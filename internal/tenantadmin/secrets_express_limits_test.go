package tenantadmin

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestSecretSettingsExpressLowerOnly (threat model T-418): a delegated
// admin only lowers the express limits. A limit above both its default
// and its stored value is ErrForbidden, stores nothing (the other members
// included) and is not audited; a lower value, the default and a value the
// super admin raised (sent back unchanged or lowered) are accepted. The
// super admin sets any value within the bounds, and the bounds are checked
// before the role.
func TestSecretSettingsExpressLowerOnly(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		base := SecretSettingsOf(tenant.DefaultSecretSettings())
		limits := func(ip, token, pending *int) SecretSettingsInput {
			in := base
			in.ExpressPerHourPerIP, in.ExpressPerHourPerToken, in.ExpressMaxPending = ip, token, pending
			return in
		}
		stored := func(tid tenant.ID) *tenant.Tenant {
			t.Helper()
			tn, err := ev.db.Tenants().Get(ctx, tid)
			mustNoErr(t, "read back", err)
			return tn
		}
		audits := func() int { return len(ev.auditEvents(t, ev.a.ID, audit.ActionSecretSettingsUpdated)) }
		update := func(what string, p adminauth.Principal, in SecretSettingsInput) tenant.ExpressSettings {
			t.Helper()
			out, err := ev.svc.UpdateSecretSettings(ctx, p, ev.a.ID, in, clientIP)
			mustNoErr(t, what, err)
			return expressOf(t, out)
		}
		refused := func(what string, in SecretSettingsInput) {
			t.Helper()
			before, n := stored(ev.a.ID), audits()
			if _, err := ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, in, clientIP); !errors.Is(err, ErrForbidden) {
				t.Errorf("%s: %v, want ErrForbidden", what, err)
			}
			after := stored(ev.a.ID)
			if after.Express != before.Express || after.Secrets.Enabled != before.Secrets.Enabled || audits() != n {
				t.Errorf("%s: stored %+v %+v (was %+v %+v), %d audit events (was %d)",
					what, after.Express, after.Secrets, before.Express, before.Secrets, audits(), n)
			}
		}

		// Above the default: refused, with the 2.1 members and the
		// anonymous mode of the same replacement.
		for name, in := range map[string]SecretSettingsInput{
			"ip":      limits(new(tenant.DefaultExpressPerHourPerIP+1), nil, nil),
			"token":   limits(nil, new(tenant.DefaultExpressPerHourPerToken+1), nil),
			"pending": limits(nil, nil, new(tenant.MaxExpressMaxPending)),
		} {
			in.Enabled, in.ExpressEnabled = false, new(true)
			refused("raise "+name, in)
		}
		if tn := stored(ev.a.ID); tn.Express != tenant.DefaultExpressSettings() || !tn.Secrets.Enabled || audits() != 0 {
			t.Fatalf("after the refusals: %+v %+v, %d audit events", tn.Express, tn.Secrets, audits())
		}

		// Lower, then back up to the defaults: accepted.
		low := tenant.ExpressSettings{PerHourPerIP: 3, PerHourPerToken: 100, MaxPending: 1}
		if x := update("lower", ev.adminA, limits(new(3), new(100), new(1))); x != low {
			t.Errorf("lowered = %+v, want %+v", x, low)
		}
		def := tenant.DefaultExpressSettings()
		if x := update("defaults", ev.adminA, limits(new(def.PerHourPerIP), new(def.PerHourPerToken), new(def.MaxPending))); x != def {
			t.Errorf("defaults = %+v", x)
		}

		// The super admin raises every limit to its bound.
		top := tenant.ExpressSettings{
			PerHourPerIP: tenant.MaxExpressPerHourPerIP, PerHourPerToken: tenant.MaxExpressPerHourPerToken,
			MaxPending: tenant.MaxExpressMaxPending,
		}
		raised := limits(new(top.PerHourPerIP), new(top.PerHourPerToken), new(top.MaxPending))
		if x := update("super admin raise", ev.super, raised); x != top {
			t.Errorf("raised = %+v, want %+v", x, top)
		}
		// The delegated admin sends the form back unchanged: accepted,
		// nothing changed.
		if x := update("re-save", ev.adminA, raised); x != top {
			t.Errorf("re-saved = %+v", x)
		}
		var d struct{ Changed []string }
		mustNoErr(t, "details", json.Unmarshal(ev.auditEvents(t, ev.a.ID, audit.ActionSecretSettingsUpdated)[0].Details, &d))
		if len(d.Changed) != 0 {
			t.Errorf("re-save changed %v", d.Changed)
		}
		// Lowered under the raised value, still above the default: accepted.
		mid := top
		mid.PerHourPerIP = 500
		if x := update("lower a raised limit", ev.adminA, limits(new(500), nil, nil)); x != mid {
			t.Errorf("lowered = %+v, want %+v", x, mid)
		}
		// Up again, even below the former value: refused; one limit raised
		// refuses the whole replacement, the lowered ones included.
		refused("raise a lowered limit", limits(new(501), nil, nil))
		refused("one of three raised", limits(new(501), new(50), new(10)))
		if tn := stored(ev.a.ID); tn.Express != mid {
			t.Errorf("after the refusals = %+v, want %+v", tn.Express, mid)
		}
		// The bounds come first, above the default included.
		_, err := ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, limits(nil, nil, new(tenant.MaxExpressMaxPending+1)), clientIP)
		if ie := invalidOf(t, "out of bounds", err, FieldExpressMaxPending); ie.Code != CodeOutOfRange {
			t.Errorf("out of bounds: code %q", ie.Code)
		}
		// A 2.1 replacement (no express member) keeps the raised limits.
		if x := update("2.1 replacement", ev.adminA, base); x != mid {
			t.Errorf("after a 2.1 replacement = %+v", x)
		}
		// The auditor never writes; B is untouched.
		auditor := principal(store.RoleAuditor, "audrey", ev.a.ID)
		if _, err := ev.svc.UpdateSecretSettings(ctx, auditor, ev.a.ID, limits(new(1), nil, nil), clientIP); !errors.Is(err, adminauth.ErrReadOnlyRole) {
			t.Errorf("auditor: %v, want ErrReadOnlyRole", err)
		}
		if tn := stored(ev.b.ID); tn.Express != tenant.DefaultExpressSettings() {
			t.Errorf("tenant B = %+v", tn.Express)
		}
	})
}

// TestExpressRaised covers the comparison alone: a zero stored limit is
// read as its default, and a member left out never raises.
func TestExpressRaised(t *testing.T) {
	t.Parallel()
	zero := tenant.ExpressSettings{}
	for name, c := range map[string]struct {
		stored tenant.ExpressSettings
		in     SecretSettingsInput
		want   bool
	}{
		"nothing set":         {zero, SecretSettingsInput{}, false},
		"default over zero":   {zero, SecretSettingsInput{ExpressPerHourPerIP: new(10)}, false},
		"above zero":          {zero, SecretSettingsInput{ExpressPerHourPerIP: new(11)}, true},
		"token at stored":     {tenant.ExpressSettings{PerHourPerToken: 900}, SecretSettingsInput{ExpressPerHourPerToken: new(900)}, false},
		"token above stored":  {tenant.ExpressSettings{PerHourPerToken: 900}, SecretSettingsInput{ExpressPerHourPerToken: new(901)}, true},
		"pending under":       {tenant.ExpressSettings{MaxPending: 5}, SecretSettingsInput{ExpressMaxPending: new(1000)}, false},
		"pending above both":  {tenant.ExpressSettings{MaxPending: 5}, SecretSettingsInput{ExpressMaxPending: new(1001)}, true},
		"last of three above": {zero, SecretSettingsInput{ExpressPerHourPerIP: new(1), ExpressPerHourPerToken: new(1), ExpressMaxPending: new(1001)}, true},
	} {
		if got := expressRaised(c.stored, c.in); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

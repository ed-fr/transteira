package tenantadmin

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// expressOf returns the express members of in as a tenant setting, every
// member required.
func expressOf(t *testing.T, in SecretSettingsInput) tenant.ExpressSettings {
	t.Helper()
	if in.ExpressEnabled == nil || in.ExpressPerHourPerIP == nil || in.ExpressPerHourPerToken == nil || in.ExpressMaxPending == nil {
		t.Fatalf("express members missing: %+v", in)
	}
	return tenant.ExpressSettings{
		Enabled: *in.ExpressEnabled, PerHourPerIP: *in.ExpressPerHourPerIP,
		PerHourPerToken: *in.ExpressPerHourPerToken, MaxPending: *in.ExpressMaxPending,
	}
}

func TestSecretSettingsExpress(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		got, err := ev.svc.GetSecretSettings(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get defaults", err)
		if x := expressOf(t, got); x != tenant.DefaultExpressSettings() {
			t.Fatalf("default express = %+v", x)
		}
		changed := func() []string {
			t.Helper()
			evs := ev.auditEvents(t, ev.a.ID, audit.ActionSecretSettingsUpdated)
			var d struct{ Changed []string }
			mustNoErr(t, "details", json.Unmarshal(evs[0].Details, &d))
			return d.Changed
		}

		// A 2.1 client: the express members are kept.
		base := SecretSettingsOf(tenant.DefaultSecretSettings())
		out, err := ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, base, clientIP)
		mustNoErr(t, "2.1 update", err)
		if x := expressOf(t, out); x != tenant.DefaultExpressSettings() || len(changed()) != 0 {
			t.Errorf("2.1 update: %+v, changed %v", x, changed())
		}

		// The delegated admin opens the anonymous mode and lowers a limit.
		in := base
		in.ExpressEnabled, in.ExpressPerHourPerIP = new(true), new(5)
		out, err = ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, in, clientIP)
		mustNoErr(t, "open", err)
		want := tenant.ExpressSettings{Enabled: true, PerHourPerIP: 5, PerHourPerToken: 100, MaxPending: 1000}
		if x := expressOf(t, out); x != want {
			t.Errorf("stored = %+v", x)
		}
		if got := changed(); !slices.Equal(got, []string{"expressEnabled", "expressPerHourPerIp"}) {
			t.Errorf("changed = %v", got)
		}
		tn, err := ev.db.Tenants().Get(ctx, ev.a.ID)
		mustNoErr(t, "read back", err)
		if tn.Express != want || !slices.Contains(ev.cache.tenants, ev.a.ID) {
			t.Errorf("tenant = %+v, cache %v", tn.Express, ev.cache.tenants)
		}

		// One member alone, by the super admin: the others are kept.
		in = base
		in.ExpressPerHourPerToken, in.ExpressMaxPending = new(tenant.MaxExpressPerHourPerToken), new(tenant.MinExpressMaxPending)
		out, err = ev.svc.UpdateSecretSettings(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "limits", err)
		want = tenant.ExpressSettings{Enabled: true, PerHourPerIP: 5, PerHourPerToken: 10000, MaxPending: 1}
		if x := expressOf(t, out); x != want {
			t.Errorf("stored = %+v", x)
		}
		if got := changed(); !slices.Equal(got, []string{"expressPerHourPerToken", "expressMaxPending"}) {
			t.Errorf("changed = %v", got)
		}

		// Every limit is bounded; nothing is stored on a refusal.
		for name, c := range map[string]struct {
			mod   func(*SecretSettingsInput)
			field string
		}{
			"ip low":       {func(s *SecretSettingsInput) { s.ExpressPerHourPerIP = new(0) }, FieldExpressPerHourPerIP},
			"ip high":      {func(s *SecretSettingsInput) { s.ExpressPerHourPerIP = new(1001) }, FieldExpressPerHourPerIP},
			"token low":    {func(s *SecretSettingsInput) { s.ExpressPerHourPerToken = new(0) }, FieldExpressPerHourPerToken},
			"token high":   {func(s *SecretSettingsInput) { s.ExpressPerHourPerToken = new(10001) }, FieldExpressPerHourPerToken},
			"pending low":  {func(s *SecretSettingsInput) { s.ExpressMaxPending = new(-1) }, FieldExpressMaxPending},
			"pending high": {func(s *SecretSettingsInput) { s.ExpressMaxPending = new(100001) }, FieldExpressMaxPending},
		} {
			in := base
			in.ExpressEnabled = new(false)
			c.mod(&in)
			_, err := ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, in, clientIP)
			if ie := invalidOf(t, name, err, c.field); ie.Code != CodeOutOfRange {
				t.Errorf("%s: code %q", name, ie.Code)
			}
		}
		tn, err = ev.db.Tenants().Get(ctx, ev.a.ID)
		mustNoErr(t, "read back", err)
		if tn.Express != want {
			t.Errorf("after refusals = %+v", tn.Express)
		}
		// B is untouched.
		other, err := ev.svc.GetSecretSettings(ctx, ev.super, ev.b.ID)
		mustNoErr(t, "B", err)
		if x := expressOf(t, other); x != tenant.DefaultExpressSettings() {
			t.Errorf("tenant B = %+v", x)
		}
	})
}

// racingRepo runs before ahead of each write of the secret settings: an
// update committed between the read and the write of another.
type racingRepo struct {
	repo
	before func()
}

func (r *racingRepo) setSecretSettings(ctx context.Context, tid tenant.ID, s tenant.SecretSettings, e store.ExpressPatch) (*tenant.Tenant, error) {
	r.before()
	return r.repo.setSecretSettings(ctx, tid, s, e)
}

// TestSecretSettingsExpressConcurrent checks that an express member left
// out of an update keeps the value stored at the time of the write: a 2.1
// client never writes back an anonymous mode closed meanwhile, and two
// updates of different members both stay.
func TestSecretSettingsExpressConcurrent(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		base := SecretSettingsOf(tenant.DefaultSecretSettings())
		open := base
		open.ExpressEnabled = new(true)
		_, err := ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, open, clientIP)
		mustNoErr(t, "open", err)

		// The super admin closes the anonymous service while a 2.1 client
		// turns the 2.1 module off.
		closed := tenant.ExpressSettings{PerHourPerIP: 10, PerHourPerToken: 100, MaxPending: 7}
		ev.svc.repo = &racingRepo{repo: ev.svc.repo, before: func() {
			if _, err := ev.db.Tenants().SetExpressSettings(ctx, ev.a.ID, closed); err != nil {
				t.Error(err)
			}
		}}
		v21 := base
		v21.Enabled = false
		out, err := ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, v21, clientIP)
		mustNoErr(t, "2.1 update", err)
		if x := expressOf(t, out); x != closed || out.Enabled {
			t.Errorf("answered %+v, express %+v, want %+v", out, x, closed)
		}
		tn, err := ev.db.Tenants().Get(ctx, ev.a.ID)
		mustNoErr(t, "read back", err)
		if tn.Express != closed || tn.Secrets.Enabled {
			t.Errorf("stored %+v, express %+v: a stale member was written back", tn.Secrets, tn.Express)
		}

		// Another member changed meanwhile: both changes stay.
		ev.svc.repo.(*racingRepo).before = func() {
			if _, err := ev.db.Tenants().SetExpressSettings(ctx, ev.a.ID, tenant.ExpressSettings{
				Enabled: true, PerHourPerIP: 10, PerHourPerToken: 100, MaxPending: 8,
			}); err != nil {
				t.Error(err)
			}
		}
		limit := base
		limit.ExpressPerHourPerIP = new(4)
		out, err = ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, limit, clientIP)
		mustNoErr(t, "limit", err)
		if x, want := expressOf(t, out), (tenant.ExpressSettings{Enabled: true, PerHourPerIP: 4, PerHourPerToken: 100, MaxPending: 8}); x != want {
			t.Errorf("express %+v, want %+v", x, want)
		}
	})
}

// TestExpressSettingsMerge covers the merge of a zero stored value: a
// limit read as zero takes its default.
func TestExpressSettingsMerge(t *testing.T) {
	t.Parallel()
	got, err := expressSettings(tenant.ExpressSettings{Enabled: true}, SecretSettingsInput{ExpressPerHourPerIP: new(3)})
	if err != nil || got != (tenant.ExpressSettings{Enabled: true, PerHourPerIP: 3, PerHourPerToken: 100, MaxPending: 1000}) {
		t.Errorf("merge = %+v, %v", got, err)
	}
	if !samePtr[int](nil, nil) || samePtr(new(1), nil) || samePtr(nil, new(1)) || samePtr(new(1), new(2)) || !samePtr(new(2), new(2)) {
		t.Error("samePtr")
	}
}

// The express settings are exported as stored; an import keeps the limits
// and never the anonymous mode (P92), takes the defaults of a 2.1 or 2.2
// export, and refuses a limit out of bounds.
func TestExpressSettingsExportImport(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		in := SecretSettingsOf(tenant.DefaultSecretSettings())
		in.ExpressEnabled, in.ExpressPerHourPerIP, in.ExpressPerHourPerToken, in.ExpressMaxPending = new(true), new(3), new(30), new(300)
		_, err := ev.svc.UpdateSecretSettings(ctx, ev.adminA, ev.a.ID, in, clientIP)
		mustNoErr(t, "configure A", err)
		src, err := ev.svc.ExportConfig(ctx, ev.adminA, ev.a.ID, false, clientIP)
		mustNoErr(t, "export", err)
		ss := src.SecretSettings
		if ss == nil || ss.ExpressEnabled == nil || !*ss.ExpressEnabled || *ss.ExpressPerHourPerIP != 3 ||
			*ss.ExpressPerHourPerToken != 30 || *ss.ExpressMaxPending != 300 {
			t.Fatalf("exported = %+v", ss)
		}

		imp := minimalImport("transfer.entity-c.example.com")
		imp.Config.SecretSettings = ss
		got, err := ev.svc.ImportTenant(ctx, ev.super, imp, clientIP)
		mustNoErr(t, "import", err)
		tn, err := ev.db.Tenants().Get(ctx, got.ID)
		mustNoErr(t, "read imported", err)
		if want := (tenant.ExpressSettings{PerHourPerIP: 3, PerHourPerToken: 30, MaxPending: 300}); tn.Express != want {
			t.Errorf("imported express = %+v, want %+v", tn.Express, want)
		}

		// A 2.1 export: the defaults.
		old := *ss
		old.ExpressEnabled, old.ExpressPerHourPerIP, old.ExpressPerHourPerToken, old.ExpressMaxPending = nil, nil, nil, nil
		imp = minimalImport("transfer.entity-d.example.com")
		imp.Config.SecretSettings = &old
		got, err = ev.svc.ImportTenant(ctx, ev.super, imp, clientIP)
		mustNoErr(t, "import 2.1", err)
		tn, err = ev.db.Tenants().Get(ctx, got.ID)
		mustNoErr(t, "read imported 2.1", err)
		if tn.Express != tenant.DefaultExpressSettings() {
			t.Errorf("imported 2.1 express = %+v", tn.Express)
		}

		// A limit out of bounds is refused at its pointer.
		bad := old
		bad.ExpressMaxPending = new(0)
		imp = minimalImport("transfer.entity-e.example.com")
		imp.Config.SecretSettings = &bad
		_, err = ev.svc.ImportTenant(ctx, ev.super, imp, clientIP)
		if ie := importErrorAt(t, "out of range", err, "/config/secretSettings/expressMaxPending"); ie.Code != CodeOutOfRange {
			t.Errorf("code %q", ie.Code)
		}
	})
}

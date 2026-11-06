package tenantadmin

import (
	"context"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestUpdateTenantLinkOnly lets the super admin alone switch the link-only
// transfers of a tenant, audited as tenant.updated with the member name.
func TestUpdateTenantLinkOnly(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		v, err := ev.svc.GetTenant(ctx, ev.super, ev.a.ID)
		mustNoErr(t, "get", err)
		if v.LinkOnlyAllowed {
			t.Fatal("link-only allowed by default")
		}
		_, err = ev.svc.UpdateTenant(ctx, ev.adminA, ev.a.ID, TenantUpdate{LinkOnlyAllowed: ptr(true)}, clientIP)
		wantErr(t, "delegated", err, ErrForbidden)

		// Alone: only the switch is written.
		ev.cache.hosts = nil
		v, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{LinkOnlyAllowed: ptr(true)}, clientIP)
		mustNoErr(t, "on", err)
		if got, err := ev.db.Tenants().Get(ctx, ev.a.ID); err != nil || !v.LinkOnlyAllowed || !got.LinkOnlyAllowed {
			t.Fatalf("on: %+v, stored %+v %v", v, got, err)
		}
		if !ev.cache.sawHost(hostA) {
			t.Error("cache not invalidated")
		}
		if f := ssoAuditFields(t, ev, ev.a.ID, ActionTenantUpdated); !slices.Equal(f, []string{"linkOnlyAllowed"}) {
			t.Errorf("audit fields %v", f)
		}
		// With another field: both are written.
		v, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{LinkOnlyAllowed: ptr(false), DefaultLanguage: ptr("fr")}, clientIP)
		mustNoErr(t, "off", err)
		if got, _ := ev.db.Tenants().Get(ctx, ev.a.ID); v.LinkOnlyAllowed || got.LinkOnlyAllowed || got.DefaultLanguage != "fr" {
			t.Fatalf("off: %+v stored %+v", v, got)
		}
		if b, _ := ev.db.Tenants().Get(ctx, ev.b.ID); b.LinkOnlyAllowed {
			t.Error("tenant B changed")
		}
		// The delegated admin may set the current value.
		_, err = ev.svc.UpdateTenant(ctx, ev.adminA, ev.a.ID, TenantUpdate{LinkOnlyAllowed: ptr(false)}, clientIP)
		mustNoErr(t, "delegated, unchanged", err)
	})
}

// TestLevelLinkOnlyAndDropLinks stores the link-only switch of a level and
// refuses to remove a level a drop link uses.
func TestLevelLinkOnlyAndDropLinks(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		off := goodLevel("closed", false)
		off.Rules.LinkOnlyForbidden = true
		out, err := ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, []ConfidentialityLevel{goodLevel("open", true), off}, clientIP)
		mustNoErr(t, "update", err)
		if out[0].Rules.LinkOnlyForbidden || !out[1].Rules.LinkOnlyForbidden {
			t.Fatalf("levels %+v", out)
		}
		stored, err := ev.db.ConfidentialityLevels().List(ctx, ev.a.ID)
		if err != nil || !stored[0].LinkOnlyAllowed || stored[1].LinkOnlyAllowed {
			t.Fatalf("stored %+v %v", stored, err)
		}
		tok, err := id.NewDropToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ev.db.DropLinks().Create(ctx, ev.a.ID, store.DropLink{
			ID: id.New(id.DropLink), TokenHash: id.HashToken(tok), Label: "In", Recipients: []string{"a@entity-a.example.com"},
			ValidityDays: 7, ConfidentialityLevel: "closed", Enabled: true, CreatedBy: "adm_1",
		}); err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, []ConfidentialityLevel{goodLevel("open", true)}, clientIP)
		wantErr(t, "level in use", err, ErrLevelInUse)
	})
}

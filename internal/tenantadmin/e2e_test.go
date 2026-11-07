package tenantadmin

import (
	"context"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestUpdateTenantE2EPolicy lets the super admin alone change the
// end-to-end encryption policy of a tenant, audited as tenant.updated.
func TestUpdateTenantE2EPolicy(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		v, err := ev.svc.GetTenant(ctx, ev.super, ev.a.ID)
		mustNoErr(t, "get", err)
		if v.E2EPolicy != tenant.E2EForbidden {
			t.Fatalf("default policy %q", v.E2EPolicy)
		}
		// A delegated admin of the tenant is refused, nothing applied, even
		// next to an allowed field.
		_, err = ev.svc.UpdateTenant(ctx, ev.adminA, ev.a.ID, TenantUpdate{E2EPolicy: ptr("allowed"), DefaultLanguage: ptr("fr")}, clientIP)
		wantErr(t, "delegated", err, ErrForbidden)
		if got, _ := ev.db.Tenants().Get(ctx, ev.a.ID); got.E2EPolicy != tenant.E2EForbidden || got.DefaultLanguage == "fr" {
			t.Fatalf("delegated change applied: %+v", got)
		}
		// Outside its scope: not found, before anything else.
		_, err = ev.svc.UpdateTenant(ctx, ev.adminA, ev.b.ID, TenantUpdate{E2EPolicy: ptr("allowed")}, clientIP)
		wantErr(t, "out of scope", err, ErrNotFound)
		// An unknown value is refused.
		_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{E2EPolicy: ptr("sometimes")}, clientIP)
		_ = invalidOf(t, "unknown policy", err, FieldE2EPolicy)

		ev.cache.hosts = nil
		v, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{E2EPolicy: ptr("required")}, clientIP)
		mustNoErr(t, "required", err)
		if got, err := ev.db.Tenants().Get(ctx, ev.a.ID); err != nil || v.E2EPolicy != tenant.E2ERequired || got.E2EPolicy != tenant.E2ERequired {
			t.Fatalf("required: %+v, stored %+v %v", v, got, err)
		}
		if !ev.cache.sawHost(hostA) {
			t.Error("cache not invalidated")
		}
		if f := ssoAuditFields(t, ev, ev.a.ID, ActionTenantUpdated); !slices.Equal(f, []string{"e2ePolicy"}) {
			t.Errorf("audit fields %v", f)
		}
		// With other fields (and the link-only switch): all are written.
		v, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID,
			TenantUpdate{E2EPolicy: ptr("allowed"), DefaultLanguage: ptr("fr"), LinkOnlyAllowed: ptr(true)}, clientIP)
		mustNoErr(t, "allowed", err)
		if got, _ := ev.db.Tenants().Get(ctx, ev.a.ID); v.E2EPolicy != tenant.E2EAllowed || got.E2EPolicy != tenant.E2EAllowed ||
			got.DefaultLanguage != "fr" || !got.LinkOnlyAllowed {
			t.Fatalf("allowed: %+v stored %+v", v, got)
		}
		if b, _ := ev.db.Tenants().Get(ctx, ev.b.ID); b.E2EPolicy != tenant.E2EForbidden {
			t.Error("tenant B changed")
		}
		// The delegated admin may send the current value.
		_, err = ev.svc.UpdateTenant(ctx, ev.adminA, ev.a.ID, TenantUpdate{E2EPolicy: ptr("allowed")}, clientIP)
		mustNoErr(t, "delegated, unchanged", err)
	})
}

// TestLevelE2EPolicy stores, returns and clears the policy of a level, for
// a delegated admin.
func TestLevelE2EPolicy(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		req := goodLevel("required", false)
		req.Rules.E2EPolicy = new(tenant.E2ERequired)
		out, err := ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, []ConfidentialityLevel{goodLevel("open", true), req}, clientIP)
		mustNoErr(t, "update", err)
		if out[0].Rules.E2EPolicy != nil || out[1].Rules.E2EPolicy == nil || *out[1].Rules.E2EPolicy != tenant.E2ERequired {
			t.Fatalf("levels %+v", out)
		}
		got, err := ev.svc.GetConfidentialityLevels(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if got[0].Rules.E2EPolicy != nil || got[1].Rules.E2EPolicy == nil || *got[1].Rules.E2EPolicy != tenant.E2ERequired {
			t.Fatalf("round trip %+v", got)
		}
		pub, err := ev.svc.PublicConfidentialityLevels(ctx, ev.a, "en")
		mustNoErr(t, "public", err)
		if pub[1].Rules.E2EPolicy == nil || *pub[1].Rules.E2EPolicy != tenant.E2ERequired {
			t.Fatalf("public %+v", pub)
		}
		// The slice is cloned: changing the input later changes nothing.
		*req.Rules.E2EPolicy = tenant.E2EForbidden
		if again, _ := ev.svc.GetConfidentialityLevels(ctx, ev.adminA, ev.a.ID); *again[1].Rules.E2EPolicy != tenant.E2ERequired {
			t.Error("stored policy shares memory with the input")
		}
		// Unknown value.
		bad := goodLevel("bad", true)
		bad.Rules.E2EPolicy = new(tenant.E2EPolicy("sometimes"))
		_, err = ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, []ConfidentialityLevel{bad}, clientIP)
		_ = invalidOf(t, "unknown", err, FieldLevels+"/0/rules/e2ePolicy")
		// Clearing.
		_, err = ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, []ConfidentialityLevel{goodLevel("open", true)}, clientIP)
		mustNoErr(t, "clear", err)
	})
}

// TestImportExportE2E carries the tenant and level policies through an
// export and an import.
func TestImportExportE2E(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		_, err := ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{E2EPolicy: ptr("allowed")}, clientIP)
		mustNoErr(t, "tenant policy", err)
		lvl := goodLevel("closed", true)
		lvl.Rules.E2EPolicy = new(tenant.E2ERequired)
		_, err = ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, []ConfidentialityLevel{lvl, goodLevel("open", false)}, clientIP)
		mustNoErr(t, "levels", err)

		out, err := ev.svc.ExportConfig(ctx, ev.adminA, ev.a.ID, false, clientIP)
		mustNoErr(t, "export", err)
		if out.Settings.E2EPolicy == nil || *out.Settings.E2EPolicy != "allowed" {
			t.Fatalf("exported tenant policy %v", out.Settings.E2EPolicy)
		}
		items := out.ConfidentialityLevels.Items
		if items[0].Rules.E2EPolicy == nil || *items[0].Rules.E2EPolicy != "required" || items[1].Rules.E2EPolicy != nil {
			t.Fatalf("exported level policies %+v", items)
		}

		in := minimalImport("c3.example.com")
		in.Config = out
		got, err := ev.svc.ImportTenant(ctx, ev.super, in, clientIP)
		mustNoErr(t, "import", err)
		if got.E2EPolicy != tenant.E2EAllowed {
			t.Errorf("imported tenant policy %q", got.E2EPolicy)
		}
		lv, err := ev.svc.GetConfidentialityLevels(ctx, ev.super, got.ID)
		mustNoErr(t, "levels", err)
		if lv[0].Rules.E2EPolicy == nil || *lv[0].Rules.E2EPolicy != tenant.E2ERequired || lv[1].Rules.E2EPolicy != nil {
			t.Errorf("imported levels %+v", lv)
		}
	})
}

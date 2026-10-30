package tenantadmin

import (
	"context"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestUpdateTenantAntivirus(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		v, err := ev.svc.GetTenant(ctx, ev.super, ev.a.ID)
		mustNoErr(t, "get", err)
		if !v.AntivirusEnabled || !v.AntivirusEffective || !ev.svc.AntivirusEffective(ev.a) {
			t.Fatalf("new tenant: %+v", v)
		}

		// A delegated admin may neither turn it off nor on: nothing changes.
		_, err = ev.svc.UpdateTenant(ctx, ev.adminA, ev.a.ID, TenantUpdate{
			AntivirusEnabled: ptr(false), DefaultLanguage: ptr("fr"),
		}, clientIP)
		wantErr(t, "delegated", err, ErrForbidden)
		if got, err := ev.db.Tenants().Get(ctx, ev.a.ID); err != nil || !got.AntivirusEnabled || got.DefaultLanguage != "en" {
			t.Fatalf("after a refused update: %+v, %v", got, err)
		}
		// Setting it to its current value is not a change.
		_, err = ev.svc.UpdateTenant(ctx, ev.adminA, ev.a.ID, TenantUpdate{AntivirusEnabled: ptr(true)}, clientIP)
		mustNoErr(t, "delegated, unchanged", err)

		// The super admin turns it off, together with another field.
		ev.cache.hosts = nil
		v, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{
			AntivirusEnabled: ptr(false), DefaultLanguage: ptr("fr"),
		}, clientIP)
		mustNoErr(t, "off", err)
		if v.AntivirusEnabled || v.AntivirusEffective || v.DefaultLanguage != "fr" {
			t.Fatalf("off: %+v", v)
		}
		if !ev.cache.sawHost(hostA) {
			t.Fatalf("cache not invalidated: %+v", ev.cache.hosts)
		}
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantAntivirusDisabled)); n != 1 {
			t.Fatalf("%d disabled events", n)
		}
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantUpdated)); n != 1 {
			t.Fatalf("%d update events", n)
		}
		// Tenant B is untouched.
		if b, err := ev.db.Tenants().Get(ctx, ev.b.ID); err != nil || !b.AntivirusEnabled {
			t.Fatalf("tenant B: %+v, %v", b, err)
		}
		// The delegated admin reads it.
		if got, err := ev.svc.GetTenant(ctx, ev.adminA, ev.a.ID); err != nil || got.AntivirusEnabled {
			t.Fatalf("delegated read: %+v, %v", got, err)
		}

		// No change: no event.
		_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{AntivirusEnabled: ptr(false)}, clientIP)
		mustNoErr(t, "no-op", err)
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantAntivirusDisabled)); n != 1 {
			t.Fatalf("%d disabled events after a no-op", n)
		}

		// Back on, alone: only the enabled event.
		v, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{AntivirusEnabled: ptr(true)}, clientIP)
		mustNoErr(t, "on", err)
		if !v.AntivirusEnabled || !v.AntivirusEffective {
			t.Fatalf("on: %+v", v)
		}
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantAntivirusEnabled)); n != 1 {
			t.Fatalf("%d enabled events", n)
		}
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantUpdated)); n != 1 {
			t.Fatalf("%d update events", n)
		}

		// A store failure is reported.
		ev.faults("updateTenantWithAntivirus")
		_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{AntivirusEnabled: ptr(false)}, clientIP)
		wantErr(t, "store failure", err, errBoom)
	})
}

func TestAntivirusEffectiveEngineNone(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t), func(o *Options) { o.AntivirusDisabled = true })
	v, err := ev.svc.GetTenant(ctx, ev.super, ev.a.ID)
	mustNoErr(t, "get", err)
	if !v.AntivirusEnabled || v.AntivirusEffective || ev.svc.AntivirusEffective(ev.a) {
		t.Fatalf("engine none: %+v", v)
	}
}

func TestUpdateErrorMapping(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err, want error
	}{
		{store.ErrNotFound, ErrNotFound},
		{store.ErrConflict, ErrAlreadyExists},
	} {
		if err := updateError("op", tc.err); !errors.Is(err, tc.want) {
			t.Errorf("updateError(%v) = %v, want %v", tc.err, err, tc.want)
		}
	}
}

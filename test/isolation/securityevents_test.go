package isolation_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/securityevents"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// sessionOf returns an authenticated session of an administrator of role
// attached to tids.
func sessionOf(role store.AdminRole, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: "as_x", State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: "adm_x", Role: role, TenantIDs: tids},
	}
}

// TestSecurityEventsIsolation writes the security events of A, of B and
// without tenant through the recorder, and checks what each administrator
// reads back through the service (threat model T-283): the events of its
// own tenant only, never those of another tenant nor those without tenant;
// the instance-wide listing for the super admin only.
func TestSecurityEventsIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		rec, err := securityevents.New(securityevents.Options{Store: f.db.SecurityEvents()})
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC()
		for i, tid := range []tenant.ID{f.a.ID, f.a.ID, f.b.ID, ""} {
			rec.Add(ctx, events.LogRecord{
				Stream: events.StreamSecurity, Time: at, Action: "verification_code_invalid", TenantID: string(tid),
				IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}),
			})
		}
		if err := rec.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		svc, err := securityevents.NewService(f.db.SecurityEvents(), f.db.Tenants())
		if err != nil {
			t.Fatal(err)
		}

		onlyOf := func(name string, page store.Page[store.SecurityEvent], tid tenant.ID, n int) {
			t.Helper()
			if len(page.Items) != n {
				t.Errorf("%s: %d events, want %d", name, len(page.Items), n)
			}
			for _, ev := range page.Items {
				if ev.TenantID != tid {
					t.Errorf("%s: listed an event of %q", name, ev.TenantID)
				}
			}
		}
		for name, p := range map[string]adminauth.Principal{
			"delegated of A": sessionOf(store.RoleDelegatedAdmin, f.a.ID),
			"auditor of A":   sessionOf(store.RoleAuditor, f.a.ID),
			"super admin":    sessionOf(store.RoleSuperAdmin),
		} {
			page, err := svc.ListTenant(ctx, p, f.a.ID, securityevents.Filter{})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			onlyOf(name, page, f.a.ID, 2)
			// Paging keeps to the tenant.
			first, err := svc.ListTenant(ctx, p, f.a.ID, securityevents.Filter{Limit: 1})
			if err != nil || first.NextCursor == "" {
				t.Fatalf("%s: first page %+v, %v", name, first, err)
			}
			next, err := svc.ListTenant(ctx, p, f.a.ID, securityevents.Filter{Limit: 1, Cursor: first.NextCursor})
			if err != nil {
				t.Fatal(err)
			}
			onlyOf(name+" page 2", next, f.a.ID, 1)
		}
		for name, p := range map[string]adminauth.Principal{
			"delegated of A": sessionOf(store.RoleDelegatedAdmin, f.a.ID),
			"auditor of A":   sessionOf(store.RoleAuditor, f.a.ID),
		} {
			if _, err := svc.ListTenant(ctx, p, f.b.ID, securityevents.Filter{}); !errors.Is(err, adminauth.ErrNotFound) {
				t.Errorf("%s reading B: %v", name, err)
			}
			if _, err := svc.ListGlobal(ctx, p, "", securityevents.Filter{}); !errors.Is(err, adminauth.ErrForbidden) {
				t.Errorf("%s reading the instance: %v", name, err)
			}
			// A cursor of B's listing gives nothing of B.
			pageB, _ := svc.ListTenant(ctx, sessionOf(store.RoleSuperAdmin), f.b.ID, securityevents.Filter{})
			if len(pageB.Items) == 1 {
				page, err := svc.ListTenant(ctx, p, f.a.ID, securityevents.Filter{Cursor: "9999999999999:" + pageB.Items[0].ID})
				if err != nil {
					t.Fatal(err)
				}
				onlyOf(name+" with a cursor of B", page, f.a.ID, 2)
			}
		}
		super := sessionOf(store.RoleSuperAdmin)
		all, err := svc.ListGlobal(ctx, super, "", securityevents.Filter{})
		if err != nil || len(all.Items) != 4 {
			t.Fatalf("instance: %d events, %v", len(all.Items), err)
		}
		withoutTenant := 0
		for _, ev := range all.Items {
			if ev.TenantID == "" {
				withoutTenant++
			}
		}
		if withoutTenant != 1 {
			t.Errorf("instance: %d events without tenant, want 1", withoutTenant)
		}
		pageB, err := svc.ListGlobal(ctx, super, f.b.ID, securityevents.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		onlyOf("instance filtered on B", pageB, f.b.ID, 1)
	})
}

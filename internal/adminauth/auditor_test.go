package adminauth

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestAuditorAccount checks the life of an auditor account (since 2.0):
// created by the super admin only, attached to tenants, TOTP required by
// default, activated and invited like a delegated admin, promoted and
// demoted by Update; on its side, it manages its own password and TOTP but
// no account, nor its own role or tenants.
func TestAuditorAccount(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)

		// Creation: tenants required, TOTP required by default.
		_, _, err := ev.svc.Create(ctx, r.p, AdminCreate{
			Username: "audit.none", Email: "audit@entity-a.example.com", Role: store.RoleAuditor,
		}, ipA)
		wantInvalid(t, "Create(auditor without tenant)", err, FieldTenantIDs)
		acc, link, err := ev.svc.Create(ctx, r.p, AdminCreate{
			Username: "Audit.A", Email: "audit@entity-a.example.com", Role: store.RoleAuditor, TenantIDs: []tenant.ID{ev.a.ID},
		}, ipA)
		if err != nil || acc.Role != store.RoleAuditor || !acc.RequireTOTP || !slices.Equal(acc.TenantIDs, []tenant.ID{ev.a.ID}) || acc.Activated {
			t.Fatalf("Create(auditor) = %+v, %v", acc, err)
		}
		if got := ev.auditDetails(t, "admin.created"); !slices.ContainsFunc(got, func(d string) bool {
			return strings.Contains(d, `"role":"auditor"`)
		}) {
			t.Errorf("admin.created details %v: no auditor role", got)
		}

		// A delegated admin may not create one.
		d := ev.mustDelegated(t, r, "deleg.a", false, ev.a.ID)
		_, _, err = ev.svc.Create(ctx, d.p, AdminCreate{
			Username: "audit.b", Email: "audit-b@entity-a.example.com", Role: store.RoleAuditor, TenantIDs: []tenant.ID{ev.a.ID},
		}, ipB)
		wantErr(t, "Create(auditor by delegated)", err, ErrForbidden)

		// Invitation again (copied link) while not activated, then
		// activation and the mandatory enrollment.
		_, link2, err := ev.svc.Invite(ctx, r.p, acc.ID, Invitation{}, ipA)
		if err != nil {
			t.Fatalf("Invite(auditor) = %v", err)
		}
		ev.tokenOf(t, link)
		sess, err := ev.svc.Activate(ctx, ev.tokenOf(t, link2), rootPassword, ipB)
		if err != nil || sess.State != store.SessionTOTPEnrollmentRequired {
			t.Fatalf("Activate(auditor) = %+v, %v", sess, err)
		}
		_, conf := ev.mustEnroll(t, ev.mustResolve(t, sess.Token))
		if conf.Session == nil {
			t.Fatal("ConfirmEnrollment(auditor): no session")
		}
		p := ev.mustResolve(t, conf.Session.Token)
		if p.Admin.Role != store.RoleAuditor || RequireAuthenticated(p) != nil {
			t.Fatalf("auditor principal = %+v", p)
		}

		// Its tenants: audit reads only; every other tenant is missing.
		if err := RequireTenantAuditRead(p.Admin, ev.a.ID); err != nil {
			t.Errorf("RequireTenantAuditRead(A) = %v", err)
		}
		wantErr(t, "RequireTenantAccess(A)", RequireTenantAccess(p.Admin, ev.a.ID), ErrReadOnlyRole)
		wantErr(t, "RequireTenantWrite(A)", RequireTenantWrite(p.Admin, ev.a.ID), ErrReadOnlyRole)
		wantErr(t, "RequireTenantAuditRead(B)", RequireTenantAuditRead(p.Admin, ev.b.ID), ErrNotFound)

		// No account management, its own account included.
		_, err = ev.svc.List(ctx, p, "", 0)
		wantErr(t, "List(auditor)", err, ErrForbidden)
		_, err = ev.svc.Update(ctx, p, acc.ID, AdminUpdate{Role: ptr(store.RoleDelegatedAdmin)}, ipB)
		wantErr(t, "Update(own role)", err, ErrForbidden)
		_, err = ev.svc.Update(ctx, p, acc.ID, AdminUpdate{TenantIDs: &[]tenant.ID{ev.a.ID, ev.b.ID}}, ipB)
		wantErr(t, "Update(own tenants)", err, ErrForbidden)
		_, _, err = ev.svc.Invite(ctx, p, d.account.ID, Invitation{}, ipB)
		wantErr(t, "Invite(by auditor)", err, ErrForbidden)
		_, _, err = ev.svc.ResetCredentials(ctx, p, d.account.ID, ipB)
		wantErr(t, "ResetCredentials(by auditor)", err, ErrForbidden)
		wantErr(t, "Delete(by auditor)", ev.svc.Delete(ctx, p, d.account.ID, ipB), ErrForbidden)

		// Its own password: allowed.
		if err := ev.svc.ChangePassword(ctx, p, rootPassword, newPassword, ipB); err != nil {
			t.Errorf("ChangePassword(auditor) = %v", err)
		}

		// The session of the auditor still works after its password change.
		if _, err := ev.svc.Resolve(ctx, conf.Session.Token); err != nil {
			t.Fatalf("Resolve(auditor after password change) = %v", err)
		}

		// The super admin: auditor to delegated admin and back, tenants
		// kept; an auditor without tenant is refused; promotion of the
		// activated auditor with TOTP to super admin, then demotion to
		// auditor with tenants.
		up, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Role: ptr(store.RoleAuditor)}, ipA)
		if err != nil || up.Role != store.RoleAuditor || !slices.Equal(up.TenantIDs, []tenant.ID{ev.a.ID}) {
			t.Errorf("Update(delegated to auditor) = %+v, %v", up, err)
		}
		up, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Role: ptr(store.RoleDelegatedAdmin)}, ipA)
		if err != nil || up.Role != store.RoleDelegatedAdmin {
			t.Errorf("Update(auditor to delegated) = %+v, %v", up, err)
		}
		_, err = ev.svc.Update(ctx, r.p, acc.ID, AdminUpdate{TenantIDs: &[]tenant.ID{}}, ipA)
		wantInvalid(t, "Update(auditor without tenant)", err, FieldTenantIDs)
		up, err = ev.svc.Update(ctx, r.p, acc.ID, AdminUpdate{Role: ptr(store.RoleSuperAdmin)}, ipA)
		if err != nil || up.Role != store.RoleSuperAdmin || len(up.TenantIDs) != 0 {
			t.Fatalf("Update(auditor to super) = %+v, %v", up, err)
		}
		_, err = ev.svc.Update(ctx, r.p, acc.ID, AdminUpdate{Role: ptr(store.RoleAuditor)}, ipA)
		wantInvalid(t, "Update(super to auditor without tenant)", err, FieldTenantIDs)
		up, err = ev.svc.Update(ctx, r.p, acc.ID, AdminUpdate{Role: ptr(store.RoleAuditor), TenantIDs: &[]tenant.ID{ev.b.ID}}, ipA)
		if err != nil || up.Role != store.RoleAuditor || !slices.Equal(up.TenantIDs, []tenant.ID{ev.b.ID}) {
			t.Errorf("Update(super to auditor) = %+v, %v", up, err)
		}
		// The role change revoked the sessions of the auditor.
		if _, err := ev.svc.Resolve(ctx, conf.Session.Token); err == nil {
			t.Error("the auditor session survived its role change")
		}
	})
}

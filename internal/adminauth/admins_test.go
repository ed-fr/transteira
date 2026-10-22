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

// TestDelegatedAdmin checks the creation, activation and mandatory
// enrollment of a delegated admin, and what it may access.
func TestDelegatedAdmin(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)

		acc, link, err := ev.svc.Create(ctx, r.p, AdminCreate{
			Username: "Admin.B", Email: "admin@entity-b.example.com", Role: store.RoleDelegatedAdmin,
			TenantIDs: []tenant.ID{ev.b.ID, ev.a.ID},
		}, ipA)
		if err != nil {
			t.Fatalf("Create = %v", err)
		}
		if acc.Username != "admin.b" || acc.Role != store.RoleDelegatedAdmin || !acc.RequireTOTP || acc.TOTPEnabled ||
			acc.Activated || acc.Disabled || len(acc.TenantIDs) != 2 || !acc.LastLoginAt.IsZero() || acc.CreatedAt.IsZero() {
			t.Errorf("Create = %+v", acc)
		}
		// The link is returned, never mailed: only its hash is stored.
		token := ev.tokenOf(t, link)

		_, _, err = ev.svc.Create(ctx, r.p, AdminCreate{
			Username: "admin.b", Email: "x@entity-b.example.com", Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{ev.b.ID},
		}, ipA)
		wantErr(t, "Create(duplicate)", err, ErrAlreadyExists)

		// Not activated: no login.
		_, err = ev.svc.Login(ctx, "admin.b", rootPassword, ipB)
		wantErr(t, "Login before activation", err, ErrInvalidCredentials)

		// Activation.
		_, err = ev.svc.Activate(ctx, token, "short", ipB)
		wantInvalid(t, "Activate(short)", err, FieldPassword)
		_, err = ev.svc.Activate(ctx, "act_bad", rootPassword, ipB)
		wantErr(t, "Activate(malformed)", err, ErrNotFound)
		_, err = ev.svc.Activate(ctx, "act_"+strings.Repeat("a", 43), rootPassword, ipB)
		wantErr(t, "Activate(unknown)", err, ErrNotFound)
		sess, err := ev.svc.Activate(ctx, token, newPassword, ipB)
		if err != nil || sess.State != store.SessionTOTPEnrollmentRequired ||
			!sess.StateExpiresAt.Equal(ev.svc.now().Add(DefaultStateTTL)) {
			t.Fatalf("Activate = %+v, %v", sess, err)
		}
		_, err = ev.svc.Activate(ctx, token, newPassword, ipB)
		wantErr(t, "Activate(used)", err, ErrNotFound)

		// Mandatory enrollment: nothing else works until confirmed.
		p := ev.mustResolve(t, sess.Token)
		wantErr(t, "RequireAuthenticated(activation)", RequireAuthenticated(p), ErrUnauthenticated)
		_, conf := ev.mustEnroll(t, p)
		if conf.Session == nil || !conf.Session.StateExpiresAt.IsZero() {
			t.Fatalf("ConfirmEnrollment = %+v", conf)
		}
		p = ev.mustResolve(t, conf.Session.Token)

		// Authorization: the tenants of the admin only (another tenant is
		// answered as missing), no account management.
		if err := RequireTenantAccess(p.Admin, ev.a.ID); err != nil {
			t.Errorf("RequireTenantAccess(A) = %v", err)
		}
		wantErr(t, "RequireTenantAccess(C)", RequireTenantAccess(p.Admin, ev.c.ID), ErrNotFound)
		_, err = ev.svc.List(ctx, p, "", 0)
		wantErr(t, "List(delegated)", err, ErrForbidden)
		_, err = ev.svc.Get(ctx, p, r.p.Admin.ID)
		wantErr(t, "Get(delegated)", err, ErrForbidden)
		_, _, err = ev.svc.Create(ctx, p, AdminCreate{}, ipB)
		wantErr(t, "Create(delegated)", err, ErrForbidden)
		_, err = ev.svc.Update(ctx, p, r.p.Admin.ID, AdminUpdate{Disabled: ptr(true)}, ipB)
		wantErr(t, "Update(delegated)", err, ErrForbidden)
		wantErr(t, "Delete(delegated)", ev.svc.Delete(ctx, p, r.p.Admin.ID, ipB), ErrForbidden)
		_, _, err = ev.svc.ResetCredentials(ctx, p, r.p.Admin.ID, ipB)
		wantErr(t, "ResetCredentials(delegated)", err, ErrForbidden)
		wantErr(t, "DisableTOTP(required)", ev.svc.DisableTOTP(ctx, p, newPassword, ipB), ErrForbidden)

		// List and Get for the super admin.
		page, err := ev.svc.List(ctx, r.p, "", 1)
		if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
			t.Fatalf("List(limit 1) = %+v, %v", page, err)
		}
		page, err = ev.svc.List(ctx, r.p, page.NextCursor, 0)
		if err != nil || len(page.Items) != 1 || page.NextCursor != "" {
			t.Fatalf("List(page 2) = %+v, %v", page, err)
		}
		_, err = ev.svc.List(ctx, r.p, "bad cursor", 0)
		wantInvalid(t, "List(bad cursor)", err, FieldCursor)
		got, err := ev.svc.Get(ctx, r.p, acc.ID)
		if err != nil || !got.TOTPEnabled || !got.Activated || got.LastLoginAt.IsZero() {
			t.Errorf("Get = %+v, %v", got, err)
		}
		_, err = ev.svc.Get(ctx, r.p, "adm_unknown")
		wantErr(t, "Get(unknown)", err, ErrNotFound)
		all, err := ev.svc.ListAccounts(ctx)
		if err != nil || len(all) != 2 {
			t.Errorf("ListAccounts = %d, %v", len(all), err)
		}
		for _, action := range []string{"admin.created", "admin.activated", "admin.totp_enrolled"} {
			if ev.countAction(t, action) < 1 {
				t.Errorf("no audit %s", action)
			}
		}
		ev.assertNoSecretLogged(t, token, link.URL, newPassword)
	})
}

// TestCreateValidation checks the refusals of Create.
func TestCreateValidation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		valid := func() AdminCreate {
			return AdminCreate{Username: "admin.x", Email: "x@entity-a.example.com", Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{ev.a.ID}}
		}
		unknown := tenant.ID("ten_01JAB00000000000000ENT1TYZ")
		cases := map[string]struct {
			mutate func(*AdminCreate)
			field  string
		}{
			"username":       {func(c *AdminCreate) { c.Username = "-" }, FieldUsername},
			"email":          {func(c *AdminCreate) { c.Email = "nope" }, FieldEmail},
			"super admin":    {func(c *AdminCreate) { c.Role = store.RoleSuperAdmin }, FieldRole},
			"no tenant":      {func(c *AdminCreate) { c.TenantIDs = nil }, FieldTenantIDs},
			"bad tenant":     {func(c *AdminCreate) { c.TenantIDs = []tenant.ID{"x"} }, FieldTenantIDs},
			"too many":       {func(c *AdminCreate) { c.TenantIDs = make([]tenant.ID, store.MaxAdminTenants+1) }, FieldTenantIDs},
			"unknown first":  {func(c *AdminCreate) { c.TenantIDs = []tenant.ID{unknown} }, FieldTenantIDs},
			"unknown second": {func(c *AdminCreate) { c.TenantIDs = []tenant.ID{ev.a.ID, unknown} }, FieldTenantIDs},
		}
		for name, tc := range cases {
			req := valid()
			tc.mutate(&req)
			_, _, err := ev.svc.Create(ctx, r.p, req, ipA)
			wantInvalid(t, "Create("+name+")", err, tc.field)
		}
		if all, _ := ev.svc.ListAccounts(ctx); len(all) != 1 {
			t.Errorf("accounts after refusals = %d, want 1", len(all))
		}
		// Any tenant works: no tenant SMTP is involved any more.
		req := valid()
		req.TenantIDs = []tenant.ID{ev.c.ID}
		if _, _, err := ev.svc.Create(ctx, r.p, req, ipA); err != nil {
			t.Errorf("Create(tenant without smtp) = %v", err)
		}
	})
}

// TestUpdateAndRevocation checks Update, the session and activation link
// revocations, and the promotion rule.
func TestUpdateAndRevocation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		d := ev.mustDelegated(t, r, "admin.a", false, ev.a.ID)

		// Changing the mail address keeps the sessions.
		acc, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Email: ptr("new@entity-a.example.com")}, ipA)
		if err != nil || acc.Email != "new@entity-a.example.com" {
			t.Fatalf("Update(email) = %+v, %v", acc, err)
		}
		ev.mustResolve(t, mustToken(t, ev, "admin.a"))
		// Changing the tenants revokes them.
		tok := mustToken(t, ev, "admin.a")
		acc, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{TenantIDs: &[]tenant.ID{ev.a.ID, ev.b.ID}}, ipA)
		if err != nil || len(acc.TenantIDs) != 2 {
			t.Fatalf("Update(tenants) = %+v, %v", acc, err)
		}
		_, err = ev.svc.Resolve(ctx, tok)
		wantErr(t, "session after a tenant change", err, ErrUnauthenticated)
		// Disabling revokes them and blocks the login; enabling again does
		// not revoke.
		tok = mustToken(t, ev, "admin.a")
		if _, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Disabled: ptr(true)}, ipA); err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.Resolve(ctx, tok)
		wantErr(t, "session after disabling", err, ErrUnauthenticated)
		_, err = ev.svc.Login(ctx, "admin.a", rootPassword, ipB)
		wantErr(t, "login of a disabled account", err, ErrInvalidCredentials)
		if _, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Disabled: ptr(false)}, ipA); err != nil {
			t.Fatal(err)
		}
		tok = mustToken(t, ev, "admin.a")
		// Requiring TOTP while not enrolled revokes; relaxing it does not.
		if _, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{RequireTOTP: ptr(true)}, ipA); err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.Resolve(ctx, tok)
		wantErr(t, "session after requiring totp", err, ErrUnauthenticated)
		if _, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{RequireTOTP: ptr(false)}, ipA); err != nil {
			t.Fatal(err)
		}

		// Promotion needs TOTP enabled (and an activated account, see
		// TestActivationLinkRevocation).
		_, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Role: ptr(store.RoleSuperAdmin)}, ipA)
		wantErr(t, "promote without totp", err, ErrNotPromotable)
		wantErr(t, "promote without totp is a conflict", err, ErrStateConflict)
		ev.mustEnroll(t, ev.mustResolve(t, mustToken(t, ev, "admin.a")))
		acc, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Role: ptr(store.RoleSuperAdmin)}, ipA)
		if err != nil || acc.Role != store.RoleSuperAdmin || len(acc.TenantIDs) != 0 || !acc.RequireTOTP {
			t.Fatalf("Update(promote) = %+v, %v", acc, err)
		}
		// Demotion needs tenants.
		_, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Role: ptr(store.RoleDelegatedAdmin)}, ipA)
		wantInvalid(t, "demote without tenants", err, FieldTenantIDs)
		_, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{
			Role:      ptr(store.RoleDelegatedAdmin),
			TenantIDs: &[]tenant.ID{"ten_01JAB00000000000000ENT1TYZ"},
		}, ipA)
		wantInvalid(t, "demote to an unknown tenant", err, FieldTenantIDs)
		acc, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{
			Role:      ptr(store.RoleDelegatedAdmin),
			TenantIDs: &[]tenant.ID{ev.c.ID},
		}, ipA)
		if err != nil || acc.Role != store.RoleDelegatedAdmin || !slices.Equal(acc.TenantIDs, []tenant.ID{ev.c.ID}) {
			t.Fatalf("Update(demote) = %+v, %v", acc, err)
		}

		// Input checks and self-protection.
		_, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Email: ptr("bad")}, ipA)
		wantInvalid(t, "Update(email)", err, FieldEmail)
		_, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Role: ptr(store.AdminRole("auditor"))}, ipA)
		wantInvalid(t, "Update(role)", err, FieldRole)
		_, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{TenantIDs: &[]tenant.ID{"x"}}, ipA)
		wantInvalid(t, "Update(tenants)", err, FieldTenantIDs)
		_, err = ev.svc.Update(ctx, r.p, "adm_unknown", AdminUpdate{Disabled: ptr(true)}, ipA)
		wantErr(t, "Update(unknown)", err, ErrNotFound)
		_, err = ev.svc.Update(ctx, r.p, r.p.Admin.ID, AdminUpdate{Disabled: ptr(true)}, ipA)
		wantErr(t, "disable self", err, ErrSelfAction)
		_, err = ev.svc.Update(ctx, r.p, r.p.Admin.ID, AdminUpdate{Role: ptr(store.RoleDelegatedAdmin)}, ipA)
		wantErr(t, "demote self", err, ErrSelfAction)
		if _, err := ev.svc.Update(ctx, r.p, r.p.Admin.ID, AdminUpdate{Email: ptr("root@example.com")}, ipA); err != nil {
			t.Errorf("Update(own email) = %v", err)
		}
		wantErr(t, "delete self", ev.svc.Delete(ctx, r.p, r.p.Admin.ID, ipA), ErrSelfAction)

		// While two usable super admins exist, one can delete the other;
		// the last one is then protected by the store as well.
		acc, err = ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Role: ptr(store.RoleSuperAdmin)}, ipA)
		if err != nil {
			t.Fatal(err)
		}
		if err := ev.svc.Delete(ctx, r.p, acc.ID, ipA); err != nil {
			t.Fatalf("Delete(second super admin) = %v", err)
		}
		wantErr(t, "store Delete(last)", ev.db.Admins().Delete(ctx, r.p.Admin.ID), store.ErrLastSuperAdmin)
		if n := ev.countAction(t, "admin.updated"); n < 8 {
			t.Errorf("audit admin.updated = %d", n)
		}
		if n := ev.countAction(t, "admin.deleted"); n != 1 {
			t.Errorf("audit admin.deleted = %d", n)
		}
	})
}

// TestActivationLinkRevocation checks that a change of role, tenants or
// mail address revokes the pending activation links, and that an account
// not activated cannot be promoted.
func TestActivationLinkRevocation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		create := func(username string) (Account, string) {
			t.Helper()
			acc, link, err := ev.svc.Create(ctx, r.p, AdminCreate{
				Username: username, Email: username + "@entity-a.example.com", Role: store.RoleDelegatedAdmin,
				TenantIDs: []tenant.ID{ev.a.ID},
			}, ipA)
			if err != nil {
				t.Fatal(err)
			}
			return acc, ev.tokenOf(t, link)
		}
		for name, u := range map[string]AdminUpdate{
			"email":   {Email: ptr("moved@entity-b.example.com")},
			"tenants": {TenantIDs: &[]tenant.ID{ev.b.ID}},
		} {
			acc, token := create("pending." + name)
			if _, err := ev.svc.Update(ctx, r.p, acc.ID, u, ipA); err != nil {
				t.Fatalf("Update(%s) = %v", name, err)
			}
			_, err := ev.svc.Activate(ctx, token, newPassword, ipB)
			wantErr(t, "Activate after a change of "+name, err, ErrNotFound)
		}
		// Other changes keep the link.
		acc, token := create("pending.kept")
		if _, err := ev.svc.Update(ctx, r.p, acc.ID, AdminUpdate{RequireTOTP: ptr(false)}, ipA); err != nil {
			t.Fatal(err)
		}
		// Not activated: no promotion (the link stays usable).
		_, err := ev.svc.Update(ctx, r.p, acc.ID, AdminUpdate{Role: ptr(store.RoleSuperAdmin)}, ipA)
		wantErr(t, "promote a pending account", err, ErrNotPromotable)
		if _, err := ev.svc.Activate(ctx, token, newPassword, ipB); err != nil {
			t.Errorf("Activate after an unrelated change = %v", err)
		}
	})
}

// TestLastSuperAdmin checks that the last usable super admin can be
// neither disabled, nor demoted, nor deleted, nor reset through the
// service, even while unusable super admins exist.
func TestLastSuperAdmin(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		second, secret := ev.mustSuper(t, r, "second")
		other := ev.login(t, "second", secret)
		// An unusable super admin: activated and enrolled, promoted, then
		// its TOTP cleared by the local command.
		third, _ := ev.mustSuper(t, r, "third")
		if err := ev.svc.ResetTOTPLocal(ctx, "third"); err != nil {
			t.Fatal(err)
		}
		// Disabling second leaves root the last usable super admin; second
		// still acts with its principal (stale: the service relies on the
		// store rule).
		if _, err := ev.svc.Update(ctx, r.p, second.ID, AdminUpdate{Disabled: ptr(true)}, ipA); err != nil {
			t.Fatal(err)
		}
		_, err := ev.svc.Update(ctx, other, r.p.Admin.ID, AdminUpdate{Disabled: ptr(true)}, ipA)
		wantErr(t, "disable the last usable super admin", err, ErrLastSuperAdmin)
		wantErr(t, "conflict", err, ErrStateConflict)
		_, err = ev.svc.Update(ctx, other, r.p.Admin.ID, AdminUpdate{Role: ptr(store.RoleDelegatedAdmin), TenantIDs: &[]tenant.ID{ev.a.ID}}, ipA)
		wantErr(t, "demote the last usable super admin", err, ErrLastSuperAdmin)
		wantErr(t, "delete the last usable super admin", ev.svc.Delete(ctx, other, r.p.Admin.ID, ipA), ErrLastSuperAdmin)
		_, _, err = ev.svc.ResetCredentials(ctx, other, r.p.Admin.ID, ipA)
		wantErr(t, "reset the last usable super admin", err, ErrLastSuperAdmin)
		wantErr(t, "delete unknown", ev.svc.Delete(ctx, other, "adm_unknown", ipA), ErrNotFound)
		// The unusable super admins do not count, and can be removed.
		if err := ev.svc.Delete(ctx, r.p, third.ID, ipA); err != nil {
			t.Errorf("Delete(unusable super admin) = %v", err)
		}
		if err := ev.svc.Delete(ctx, r.p, second.ID, ipA); err != nil {
			t.Errorf("Delete(disabled super admin) = %v", err)
		}
		// A disabled caller is refused by the authorization helpers.
		other.Admin.Disabled = true
		_, err = ev.svc.List(ctx, other, "", 0)
		wantErr(t, "List(disabled)", err, ErrForbidden)
	})
}

// TestResetCredentials checks the credentials reset by a super admin.
func TestResetCredentials(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		d := ev.mustDelegated(t, r, "admin.a", true, ev.a.ID)
		_, enrolled := ev.mustEnroll(t, d.p)

		_, _, err := ev.svc.ResetCredentials(ctx, r.p, r.p.Admin.ID, ipA)
		wantErr(t, "reset self", err, ErrSelfAction)
		_, _, err = ev.svc.ResetCredentials(ctx, r.p, "adm_unknown", ipA)
		wantErr(t, "reset unknown", err, ErrNotFound)
		acc, link, err := ev.svc.ResetCredentials(ctx, r.p, d.account.ID, ipA)
		if err != nil || acc.Activated || acc.TOTPEnabled || acc.ID != d.account.ID {
			t.Fatalf("ResetCredentials = %+v, %v", acc, err)
		}
		token := ev.tokenOf(t, link)
		if got, err := ev.svc.Get(ctx, r.p, d.account.ID); err != nil || got.Activated || got.TOTPEnabled {
			t.Errorf("after reset = %+v, %v", got, err)
		}
		_, err = ev.svc.Resolve(ctx, enrolled.Session.Token)
		wantErr(t, "session after reset", err, ErrUnauthenticated)
		_, err = ev.svc.Login(ctx, "admin.a", rootPassword, ipB)
		wantErr(t, "login after reset", err, ErrInvalidCredentials)
		sess, err := ev.svc.Activate(ctx, token, newPassword, ipB)
		if err != nil || sess.State != store.SessionTOTPEnrollmentRequired {
			t.Fatalf("Activate after reset = %+v, %v", sess, err)
		}

		// A super admin can be reset by another one.
		second, _ := ev.mustSuper(t, r, "second")
		acc, link, err = ev.svc.ResetCredentials(ctx, r.p, second.ID, ipA)
		if err != nil || acc.Role != store.RoleSuperAdmin || acc.Activated {
			t.Fatalf("reset a super admin = %+v, %v", acc, err)
		}
		sess, err = ev.svc.Activate(ctx, ev.tokenOf(t, link), newPassword, ipB)
		if err != nil || sess.State != store.SessionTOTPEnrollmentRequired {
			t.Errorf("Activate(super admin) = %+v, %v", sess, err)
		}

		// A disabled account is refused; a new reset revokes the previous
		// link; an expired link is refused.
		_, link, err = ev.svc.ResetCredentials(ctx, r.p, d.account.ID, ipA)
		if err != nil {
			t.Fatal(err)
		}
		old := ev.tokenOf(t, link)
		if _, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Disabled: ptr(true)}, ipA); err != nil {
			t.Fatal(err)
		}
		_, _, err = ev.svc.ResetCredentials(ctx, r.p, d.account.ID, ipA)
		wantErr(t, "reset a disabled account", err, ErrAccountDisabled)
		wantErr(t, "disabled is a conflict", err, ErrStateConflict)
		_, err = ev.svc.Activate(ctx, old, newPassword, ipB)
		wantErr(t, "Activate(disabled)", err, ErrNotFound)
		if _, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Disabled: ptr(false)}, ipA); err != nil {
			t.Fatal(err)
		}
		_, link, err = ev.svc.ResetCredentials(ctx, r.p, d.account.ID, ipA)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.Activate(ctx, old, newPassword, ipB)
		wantErr(t, "Activate(previous link)", err, ErrNotFound)
		token = ev.tokenOf(t, link)
		ev.clock.Advance(ActivationTTL)
		_, err = ev.svc.Activate(ctx, token, newPassword, ipB)
		wantErr(t, "Activate(expired)", err, ErrNotFound)
		if n := ev.countAction(t, "admin.credentials_reset"); n != 4 {
			t.Errorf("audit admin.credentials_reset = %d", n)
		}
	})
}

// TestLocalResets checks the local commands: TOTP reset and password
// reset, the last super admin included.
func TestLocalResets(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)

		// Local TOTP reset of the super admin: sessions revoked, a new
		// enrollment at the next login.
		wantErr(t, "ResetTOTPLocal(unknown)", ev.svc.ResetTOTPLocal(ctx, "nobody"), ErrNotFound)
		tok := r.sess.Token
		if err := ev.svc.ResetTOTPLocal(ctx, "ROOT"); err != nil {
			t.Fatalf("ResetTOTPLocal = %v", err)
		}
		_, err := ev.svc.Resolve(ctx, tok)
		wantErr(t, "session after ResetTOTPLocal", err, ErrUnauthenticated)
		sess, err := ev.svc.Login(ctx, rootName, rootPassword, ipA)
		if err != nil || sess.State != store.SessionTOTPEnrollmentRequired {
			t.Fatalf("Login after ResetTOTPLocal = %+v, %v", sess, err)
		}
		_, conf := ev.mustEnroll(t, ev.mustResolve(t, sess.Token))
		r.p = ev.mustResolve(t, conf.Session.Token)
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{Action: "admin.totp_reset_local"})
		if err != nil || len(page.Items) != 1 || page.Items[0].ActorKind != store.ActorSystem || page.Items[0].Actor != "cli" {
			t.Errorf("audit admin.totp_reset_local = %+v, %v", page.Items, err)
		}

		// Local password reset of the last super admin: everything is
		// cleared and a link is returned.
		_, err = ev.svc.ResetPasswordLocal(ctx, "nobody")
		wantErr(t, "ResetPasswordLocal(unknown)", err, ErrNotFound)
		link, err := ev.svc.ResetPasswordLocal(ctx, "Root")
		if err != nil {
			t.Fatalf("ResetPasswordLocal = %v", err)
		}
		token := ev.tokenOf(t, link)
		_, err = ev.svc.Resolve(ctx, conf.Session.Token)
		wantErr(t, "session after ResetPasswordLocal", err, ErrUnauthenticated)
		a, err := ev.db.Admins().GetByUsername(ctx, rootName)
		if err != nil || a.PasswordHash != "" || a.TOTPEnabled || a.TOTPSecretID != "" {
			t.Errorf("after ResetPasswordLocal = %+v, %v", a, err)
		}
		if n, _ := ev.db.AdminRecoveryCodes().CountUnused(ctx, a.ID); n != 0 {
			t.Errorf("recovery codes after ResetPasswordLocal = %d", n)
		}
		_, err = ev.svc.Login(ctx, rootName, rootPassword, ipA)
		wantErr(t, "login after ResetPasswordLocal", err, ErrInvalidCredentials)
		sess, err = ev.svc.Activate(ctx, token, newPassword, ipA)
		if err != nil || sess.State != store.SessionTOTPEnrollmentRequired {
			t.Fatalf("Activate after ResetPasswordLocal = %+v, %v", sess, err)
		}
		page, err = ev.db.AuditEvents().List(ctx, store.AuditFilter{Action: "admin.password_reset_local"})
		if err != nil || len(page.Items) != 1 || page.Items[0].ActorKind != store.ActorSystem || page.Items[0].Actor != "cli" ||
			page.Items[0].ObjectID != a.ID {
			t.Errorf("audit admin.password_reset_local = %+v, %v", page.Items, err)
		}
		// A disabled account is refused.
		d := ev.mustDelegated(t, r, "admin.a", false, ev.a.ID)
		_, conf = ev.mustEnroll(t, ev.mustResolve(t, sess.Token))
		r.p = ev.mustResolve(t, conf.Session.Token)
		if _, err := ev.svc.Update(ctx, r.p, d.account.ID, AdminUpdate{Disabled: ptr(true)}, ipA); err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.ResetPasswordLocal(ctx, "admin.a")
		wantErr(t, "ResetPasswordLocal(disabled)", err, ErrAccountDisabled)
		ev.assertNoSecretLogged(t, token, link.URL)
	})
}

// mustToken logs username in (no TOTP) and returns the session token.
func mustToken(t *testing.T, ev *env, username string) string {
	t.Helper()
	sess, err := ev.svc.Login(context.Background(), username, rootPassword, ipB)
	if err != nil || sess.State != store.SessionAuthenticated {
		t.Fatalf("Login(%s) = %+v, %v", username, sess, err)
	}
	return sess.Token
}

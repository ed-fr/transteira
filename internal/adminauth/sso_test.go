package adminauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/oidc"
	"github.com/ed-fr/transteira/internal/oidc/oidctest"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Single sign-on domains of the tests.
const (
	ssoDomainA = "entity-a.example.com"
	ssoDomainB = "entity-b.example.com"
)

// ssoEnv is an env whose service runs the single sign-on against a fake
// provider, with a completed setup.
type ssoEnv struct {
	*env
	idp   *oidctest.Provider
	vault *masterkey.Vault
	r     root
}

// newSSOEnv builds an ssoEnv on engine e. The client trusts the fake
// provider on 127.0.0.1 and shares the clock of the service.
func newSSOEnv(t *testing.T, e storetest.Engine) *ssoEnv {
	t.Helper()
	ev := newEnv(t, e)
	idp := oidctest.New(t)
	idp.SetNow(ev.clock.Now)
	c := oidc.NewClient(oidc.Options{
		Guard: netpolicy.NewDialGuardPolicy("sso", netpolicy.Policy{}, nil), RootCAs: idp.CertPool(),
		Now: ev.clock.Now, Timeout: 5 * time.Second,
	})
	vault := masterkey.NewVault(ev.db, ev.kr, nil)
	ev.svc.flows, ev.svc.secrets = oidc.NewFlows(c, ev.kr), vault
	se := &ssoEnv{env: ev, idp: idp, vault: vault}
	se.r = ev.mustSetup(t)
	se.claims("subject-1", "sso.a@"+ssoDomainA, true)
	return se
}

// configure writes the single sign-on configuration of tid (enabled, the
// fake provider, a new sealed client secret, MFA required), changed by
// edit when not nil.
func (se *ssoEnv) configure(t *testing.T, tid tenant.ID, edit func(*store.TenantSSO), domains ...string) {
	t.Helper()
	ctx := context.Background()
	keyID, err := se.vault.Seal(ctx, tid, crypto.PurposeSecret, []byte(se.idp.ClientSecret()))
	if err != nil {
		t.Fatal(err)
	}
	c := store.TenantSSO{
		Enabled: true, Issuer: se.idp.Issuer(), ClientID: oidctest.ClientID, ClientSecretKeyID: keyID,
		EmailDomains: domains, RequireMFA: true,
	}
	if edit != nil {
		edit(&c)
	}
	if _, _, err := se.db.SSOSettings().Put(ctx, tid, c); err != nil {
		t.Fatalf("Put sso settings: %v", err)
	}
}

// claims sets the claims of the next ID tokens.
func (se *ssoEnv) claims(subject, email string, mfa bool) {
	verified := true
	c := oidctest.Claims{Subject: subject, Email: email, EmailVerified: &verified}
	if mfa {
		c.AMR = []string{"pwd", "mfa"}
	}
	se.idp.SetClaims(c)
}

// begin starts a login for email and plays the browser at the provider; it
// returns the callback the browser brings back.
func (se *ssoEnv) begin(t *testing.T, email string) SSOCallback {
	t.Helper()
	st, err := se.svc.StartSSO(context.Background(), email, ipB)
	if err != nil {
		t.Fatalf("StartSSO(%s): %v", email, err)
	}
	if !strings.HasPrefix(st.RedirectURL, se.idp.Server.URL+oidctest.AuthorizePath+"?") || st.Cookie == "" {
		t.Fatalf("StartSSO = %+v", st)
	}
	u, err := se.idp.Authorize(st.RedirectURL)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	q := u.Query()
	if got := u.Scheme + "://" + u.Host + u.Path; got != baseURL+SSOCallbackPath {
		t.Fatalf("redirect uri = %s", got)
	}
	return SSOCallback{Cookie: st.Cookie, Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss"), Error: q.Get("error")}
}

// login runs a whole single sign-on login for email.
func (se *ssoEnv) login(t *testing.T, email string) (Session, error) {
	t.Helper()
	return se.svc.CompleteSSO(context.Background(), se.begin(t, email), ipB)
}

// mustLogin runs a successful login for email and returns its session.
func (se *ssoEnv) mustLogin(t *testing.T, email string) Principal {
	t.Helper()
	sess, err := se.login(t, email)
	if err != nil {
		t.Fatalf("CompleteSSO(%s): %v", email, err)
	}
	if sess.State != store.SessionAuthenticated || sess.StateExpiresAt != (time.Time{}) || sess.CSRFToken == "" {
		t.Fatalf("CompleteSSO(%s) = %+v", email, sess)
	}
	return se.mustResolve(t, sess.Token)
}

// ssoOnly creates a single sign-on only account username@domain on tids.
func (se *ssoEnv) ssoOnly(t *testing.T, username, domain string, role store.AdminRole, tids ...tenant.ID) Account {
	t.Helper()
	acc, link, err := se.svc.Create(context.Background(), se.r.p, AdminCreate{
		Username: username, Email: username + "@" + domain, Role: role, TenantIDs: tids,
		Invitation: Invitation{Delivery: DeliveryNone},
	}, ipA)
	if err != nil {
		t.Fatalf("Create(%s, none): %v", username, err)
	}
	if !acc.SSOOnly || acc.Activated || acc.RequireTOTP || link.URL != "" || link.Delivery != DeliveryNone ||
		!link.ExpiresAt.Equal(acc.CreatedAt) {
		t.Fatalf("Create(%s, none) = %+v, %+v", username, acc, link)
	}
	return acc
}

// wantSSOFail fails unless err is an *SSOError of reason.
func wantSSOFail(t *testing.T, what string, err error, reason string) {
	t.Helper()
	var se *SSOError
	if !errors.As(err, &se) || se.Reason != reason || !errors.Is(err, ErrSSOFailed) {
		t.Errorf("%s: err = %v, want sso failure %s", what, err, reason)
	}
}

// lastAudit returns the newest audit event of action, with its details.
func (ev *env) lastAudit(t *testing.T, action audit.Action) (store.AuditEvent, map[string]any) {
	t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{Action: string(action), Limit: 1})
	if err != nil || len(page.Items) == 0 {
		t.Fatalf("no %s audit event (%v)", action, err)
	}
	var details map[string]any
	if len(page.Items[0].Details) > 0 {
		if err := json.Unmarshal(page.Items[0].Details, &details); err != nil {
			t.Fatal(err)
		}
	}
	return page.Items[0], details
}

// TestSSOFirstLoginAndPinning walks the life of a single sign-on account:
// creation without activation link, first login by the verified address
// (identity pinned), later logins by the pinned identity only, another
// subject refused, unpinning and pinning again.
func TestSSOFirstLoginAndPinning(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		se := newSSOEnv(t, e)

		m, err := se.svc.Methods(ctx)
		if err != nil || m != (AuthMethods{Password: true}) {
			t.Fatalf("Methods (no configuration) = %+v, %v", m, err)
		}
		se.configure(t, se.a.ID, nil, ssoDomainA)
		if m, err = se.svc.Methods(ctx); err != nil || m != (AuthMethods{Password: true, SSO: true}) {
			t.Fatalf("Methods = %+v, %v", m, err)
		}
		acc := se.ssoOnly(t, "sso.a", ssoDomainA, store.RoleDelegatedAdmin, se.a.ID)
		if _, d := se.lastAudit(t, audit.ActionAdminCreated); d["sso_only"] != true {
			t.Errorf("admin.created details = %v", d)
		}
		if se.countAction(t, string(audit.ActionAdminInvited)) != 0 {
			t.Error("an account without link was audited as invited")
		}

		// First login: matched by the verified address, case-insensitively.
		p := se.mustLogin(t, "SSO.A@Entity-A.example.com")
		if p.Admin.ID != acc.ID || p.AuthMethod != store.AuthOIDC || !slices.Equal(p.Admin.TenantIDs, []tenant.ID{se.a.ID}) {
			t.Fatalf("session = %+v", p)
		}
		ev, d := se.lastAudit(t, audit.ActionAdminIdentityLinked)
		if ev.ObjectID != acc.ID || ev.Actor != "sso.a" || d["issuer"] != se.idp.Issuer() || d["client_id"] != oidctest.ClientID ||
			d["tenant_id"] != string(se.a.ID) || d["identity_id"] == "" || strings.Contains(string(ev.Details), "subject-1") {
			t.Errorf("admin.identity_linked = %+v %v", ev, d)
		}
		if _, d = se.lastAudit(t, audit.ActionAdminLogin); d["method"] != "oidc" || d["issuer"] != se.idp.Issuer() || d["mfa"] != true {
			t.Errorf("admin.login details = %v", d)
		}
		got, err := se.svc.Get(ctx, se.r.p, acc.ID)
		if err != nil || len(got.Identities) != 1 || got.Identities[0].Issuer != se.idp.Issuer() ||
			got.Identities[0].ClientID != oidctest.ClientID || !got.Identities[0].LastUsedAt.Equal(se.svc.now()) ||
			got.LastLoginAt.IsZero() || !got.SSOOnly {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		row, err := se.db.AdminSessions().GetByTokenHash(ctx, p.tokenHash, se.svc.now(), time.Hour)
		if err != nil || row.SSOIssuer != se.idp.Issuer() || row.SSOClientID != oidctest.ClientID || !row.SSOMFA {
			t.Errorf("stored session = %+v, %v", row, err)
		}

		// Later logins: the pinned identity only, whatever the address.
		se.claims("subject-1", "renamed@"+ssoDomainA, true)
		if p := se.mustLogin(t, "sso.a@"+ssoDomainA); p.Admin.ID != acc.ID {
			t.Errorf("second login = %+v", p)
		}
		if n := se.countAction(t, string(audit.ActionAdminIdentityLinked)); n != 1 {
			t.Errorf("%d identity_linked events, want 1", n)
		}
		// Another subject presenting the address of the pinned account.
		se.claims("subject-2", "sso.a@"+ssoDomainA, true)
		_, err = se.login(t, "sso.a@"+ssoDomainA)
		wantSSOFail(t, "other subject", err, securitylog.ReasonIdentityMismatch)
		if lines := se.logLines("sso_failed"); len(lines) != 1 || !strings.Contains(lines[0], `reason="identity_mismatch"`) ||
			!strings.Contains(lines[0], "tenant="+hostA) || !strings.Contains(lines[0], "ip=198.51.100.20") {
			t.Errorf("security log = %q", lines)
		}
		if ev, d := se.lastAudit(t, audit.ActionAdminLoginFailed); ev.ObjectID != acc.ID || d["reason"] != "identity_mismatch" ||
			d["method"] != "oidc" || d["tenant_id"] != string(se.a.ID) {
			t.Errorf("admin.login_failed = %+v %v", ev, d)
		}

		// Unpinned by the super admin: the sessions it opened are revoked,
		// the next login pins the new subject.
		err = se.svc.DeleteIdentity(ctx, se.r.p, acc.ID, got.Identities[0].ID, ipA)
		if err != nil {
			t.Fatalf("DeleteIdentity: %v", err)
		}
		if _, err := se.db.AdminSessions().GetByTokenHash(ctx, p.tokenHash, se.svc.now(), time.Hour); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("session of the unpinned identity = %v, want revoked", err)
		}
		if ev, d := se.lastAudit(t, audit.ActionAdminIdentityUnlinked); ev.ObjectID != acc.ID || ev.Actor != "root" ||
			d["reason"] != "unpinned" || d["issuer"] != se.idp.Issuer() {
			t.Errorf("admin.identity_unlinked = %+v %v", ev, d)
		}
		wantErr(t, "DeleteIdentity again", se.svc.DeleteIdentity(ctx, se.r.p, acc.ID, got.Identities[0].ID, ipA), ErrNotFound)
		if p := se.mustLogin(t, "sso.a@"+ssoDomainA); p.Admin.ID != acc.ID {
			t.Errorf("login after unpinning = %+v", p)
		}
		if got, _ := se.svc.Get(ctx, se.r.p, acc.ID); len(got.Identities) != 1 || got.Identities[0].ID == "" {
			t.Errorf("identities after pinning again = %+v", got.Identities)
		}

		// A new mail address unpins the identities and revokes the single
		// sign-on sessions they opened.
		p = se.mustLogin(t, "sso.a@"+ssoDomainA)
		changed, err := se.svc.Update(ctx, se.r.p, acc.ID, AdminUpdate{Email: ptr("sso.renamed@" + ssoDomainA)}, ipA)
		if err != nil || changed.Identities == nil || len(changed.Identities) != 0 {
			t.Fatalf("Update(email) = %+v, %v", changed, err)
		}
		if ev, d := se.lastAudit(t, audit.ActionAdminIdentityUnlinked); ev.ObjectID != acc.ID || d["reason"] != "email_changed" ||
			d["identity_id"] == nil || d["client_id"] != oidctest.ClientID {
			t.Errorf("admin.identity_unlinked = %+v %v", ev, d)
		}
		if _, err := se.db.AdminSessions().GetByTokenHash(ctx, p.tokenHash, se.svc.now(), time.Hour); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("session after the address change = %v, want revoked", err)
		}
		// The same address again changes nothing.
		before := se.countAction(t, string(audit.ActionAdminIdentityUnlinked))
		if _, err := se.svc.Update(ctx, se.r.p, acc.ID, AdminUpdate{Email: ptr("sso.renamed@" + ssoDomainA)}, ipA); err != nil {
			t.Fatal(err)
		}
		if se.countAction(t, string(audit.ActionAdminIdentityUnlinked)) != before {
			t.Error("an unchanged address unpinned identities")
		}

		// Only the super admin unpins.
		d2 := se.mustDelegated(t, se.r, "deleg", false, se.a.ID)
		wantErr(t, "DeleteIdentity by a delegated admin", se.svc.DeleteIdentity(ctx, d2.p, acc.ID, "aid_x", ipA), ErrForbidden)
	})
}

// TestSSOAccountMatching checks the accounts a login may not open (T-286,
// T-293): unknown, outside the routed domains, of another tenant,
// disabled, super admin, without verified address, ambiguous; and that an
// account whose MFA is not proven is refused when the tenant requires it.
func TestSSOAccountMatching(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		se := newSSOEnv(t, e)
		se.configure(t, se.a.ID, nil, ssoDomainA, "example.com")
		se.configure(t, se.b.ID, nil, ssoDomainB)
		fail := func(name, subject, email string, mfa bool, reason string) {
			t.Helper()
			se.claims(subject, email, mfa)
			_, err := se.login(t, "anyone@"+ssoDomainA)
			wantSSOFail(t, name, err, reason)
		}
		fail("unknown account", "s-unknown", "nobody@"+ssoDomainA, true, securitylog.ReasonAccountUnknown)
		// A delegated admin of tenant B with an address of A's domain.
		se.ssoOnly(t, "other", ssoDomainA, store.RoleDelegatedAdmin, se.b.ID)
		fail("account of another tenant", "s-other", "other@"+ssoDomainA, true, securitylog.ReasonAccountUnknown)
		// An account of A whose address is outside the routed domains.
		se.ssoOnly(t, "outside", "elsewhere.example.org", store.RoleAuditor, se.a.ID)
		fail("domain not routed", "s-outside", "outside@elsewhere.example.org", true, securitylog.ReasonAccountUnknown)
		fail("single label domain", "s-x", "x@localhost", true, securitylog.ReasonAccountUnknown)
		// No verified address in the token.
		se.idp.SetClaims(oidctest.Claims{Subject: "s-unverified", Email: "sso.a@" + ssoDomainA, AMR: []string{"mfa"}})
		_, err := se.login(t, "sso.a@"+ssoDomainA)
		wantSSOFail(t, "unverified address", err, securitylog.ReasonAccountUnknown)
		// The super admin (it-admin@example.com, a routed domain).
		fail("super admin", "s-root", "it-admin@example.com", true, securitylog.ReasonAccountUnknown)
		// A disabled account.
		dis := se.ssoOnly(t, "disabled", ssoDomainA, store.RoleDelegatedAdmin, se.a.ID)
		if _, err := se.svc.Update(ctx, se.r.p, dis.ID, AdminUpdate{Disabled: ptr(true)}, ipA); err != nil {
			t.Fatal(err)
		}
		fail("disabled account", "s-disabled", "disabled@"+ssoDomainA, true, securitylog.ReasonAccountUnknown)
		if ev, d := se.lastAudit(t, audit.ActionAdminLoginFailed); ev.ObjectID != dis.ID || d["reason"] != "account_unknown" {
			t.Errorf("admin.login_failed = %+v %v", ev, d)
		}
		// Two accounts sharing an address.
		se.ssoOnly(t, "twin1", ssoDomainA, store.RoleDelegatedAdmin, se.a.ID)
		twin2 := se.ssoOnly(t, "twin2", ssoDomainA, store.RoleDelegatedAdmin, se.a.ID)
		if _, err := se.svc.Update(ctx, se.r.p, twin2.ID, AdminUpdate{Email: ptr("twin1@" + ssoDomainA)}, ipA); err != nil {
			t.Fatal(err)
		}
		fail("ambiguous address", "s-twin", "twin1@"+ssoDomainA, true, securitylog.ReasonAccountUnknown)

		// MFA required by the tenant, not proven: refused before any
		// account is matched or pinned.
		acc := se.ssoOnly(t, "auditor", ssoDomainA, store.RoleAuditor, se.a.ID)
		fail("mfa missing", "s-auditor", "auditor@"+ssoDomainA, false, securitylog.ReasonMFAMissing)
		if got, _ := se.svc.Get(ctx, se.r.p, acc.ID); len(got.Identities) != 0 {
			t.Errorf("an identity was pinned without mfa: %+v", got.Identities)
		}
		// Not required: the session records that MFA was not proven.
		se.configure(t, se.a.ID, func(c *store.TenantSSO) { c.RequireMFA = false }, ssoDomainA, "example.com")
		se.claims("s-auditor", "auditor@"+ssoDomainA, false)
		p := se.mustLogin(t, "auditor@"+ssoDomainA)
		if p.Admin.ID != acc.ID || p.Admin.Role != store.RoleAuditor {
			t.Errorf("auditor session = %+v", p)
		}

		// A pinned account disabled later is refused at its next login.
		if _, err := se.svc.Update(ctx, se.r.p, acc.ID, AdminUpdate{Disabled: ptr(true)}, ipA); err != nil {
			t.Fatal(err)
		}
		_, err = se.login(t, "auditor@"+ssoDomainA)
		wantSSOFail(t, "pinned account disabled", err, securitylog.ReasonAccountUnknown)

		// Every failure was written to the security log with the tenant.
		lines := se.logLines("sso_failed")
		if len(lines) != 10 {
			t.Errorf("%d sso_failed lines, want 10: %q", len(lines), lines)
		}
		for _, l := range lines {
			if !strings.Contains(l, "tenant="+hostA) {
				t.Errorf("line without tenant: %s", l)
			}
		}
	})
}

// TestSSOPromotion checks that a promotion to super admin unpins the
// identities (audited) and that the promoted account can no longer sign in
// through single sign-on (T-293); and that a single sign-on only account
// cannot be promoted.
func TestSSOPromotion(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		se := newSSOEnv(t, e)
		se.configure(t, se.a.ID, nil, ssoDomainA)
		d := se.mustDelegated(t, se.r, "pinned", true, se.a.ID)
		se.mustEnroll(t, d.p)
		se.claims("s-pinned", "pinned@"+ssoDomainA, true)
		se.mustLogin(t, "pinned@"+ssoDomainA)
		promoted, err := se.svc.Update(ctx, se.r.p, d.account.ID, AdminUpdate{Role: ptr(store.RoleSuperAdmin)}, ipA)
		if err != nil || promoted.Role != store.RoleSuperAdmin || promoted.Identities == nil || len(promoted.Identities) != 0 {
			t.Fatalf("promote = %+v, %v", promoted, err)
		}
		if ev, dd := se.lastAudit(t, audit.ActionAdminIdentityUnlinked); ev.ObjectID != d.account.ID || dd["reason"] != "promoted" {
			t.Errorf("admin.identity_unlinked = %+v %v", ev, dd)
		}
		_, err = se.login(t, "pinned@"+ssoDomainA)
		wantSSOFail(t, "promoted account", err, securitylog.ReasonAccountUnknown)

		acc := se.ssoOnly(t, "only", ssoDomainA, store.RoleDelegatedAdmin, se.a.ID)
		_, err = se.svc.Update(ctx, se.r.p, acc.ID, AdminUpdate{Role: ptr(store.RoleSuperAdmin)}, ipA)
		wantErr(t, "promote a single sign-on only account", err, ErrNotPromotable)

		// A super admin session opened through single sign-on (never made
		// by the service) is refused.
		token, err := id.NewToken(SessionTokenPrefix, tokenBytes)
		if err != nil {
			t.Fatal(err)
		}
		now := se.svc.now()
		if err := se.db.AdminSessions().Create(ctx, store.AdminSession{
			ID: id.New(id.AdminSession), TokenHash: tokenHash(token), AdminID: se.r.p.Admin.ID,
			State: store.SessionAuthenticated, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
			AuthMethod: store.AuthOIDC, SSOIssuer: se.idp.Issuer(), SSOClientID: oidctest.ClientID,
		}); err != nil {
			t.Fatal(err)
		}
		_, err = se.svc.Resolve(ctx, token)
		wantErr(t, "super admin single sign-on session", err, ErrUnauthenticated)
	})
}

// TestSSOSessionScope checks that a single sign-on session reaches only the
// tenants whose current configuration admits it (T-287, T-291): enabled,
// same issuer and client ID, MFA requirement met.
func TestSSOSessionScope(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		se := newSSOEnv(t, e)
		se.configure(t, se.a.ID, func(c *store.TenantSSO) { c.RequireMFA = false }, ssoDomainA)
		se.configure(t, se.b.ID, nil, ssoDomainB)
		acc := se.ssoOnly(t, "multi", ssoDomainA, store.RoleDelegatedAdmin, se.a.ID, se.b.ID)
		all := []tenant.ID{se.a.ID, se.b.ID, se.c.ID}
		if _, err := se.svc.Update(ctx, se.r.p, acc.ID, AdminUpdate{TenantIDs: &all}, ipA); err != nil {
			t.Fatal(err)
		}
		se.claims("s-multi", "multi@"+ssoDomainA, true)
		sess, err := se.login(t, "multi@"+ssoDomainA)
		if err != nil {
			t.Fatal(err)
		}
		scope := func(want ...tenant.ID) {
			t.Helper()
			p, err := se.svc.Resolve(ctx, sess.Token)
			slices.Sort(want)
			if err != nil || !slices.Equal(p.Admin.TenantIDs, want) || p.Admin.ID != acc.ID {
				t.Errorf("scope = %v, %v, want %v", p.Admin.TenantIDs, err, want)
			}
		}
		// C has no configuration: out of the scope.
		scope(se.a.ID, se.b.ID)
		// B now requires another client ID.
		se.configure(t, se.b.ID, func(c *store.TenantSSO) { c.ClientID = "another-client" }, ssoDomainB)
		scope(se.a.ID)
		// B back, but disabled.
		se.configure(t, se.b.ID, func(c *store.TenantSSO) { c.Enabled = false }, ssoDomainB)
		scope(se.a.ID)
		se.configure(t, se.b.ID, nil, ssoDomainB)
		scope(se.a.ID, se.b.ID)
		// Another issuer for B.
		se.configure(t, se.b.ID, func(c *store.TenantSSO) { c.Issuer = "https://login.example.com/other/v2.0" }, ssoDomainB)
		scope(se.a.ID)

		// A login without MFA does not reach a tenant requiring it.
		se.configure(t, se.b.ID, nil, ssoDomainB)
		se.claims("s-multi", "multi@"+ssoDomainA, false)
		sess, err = se.login(t, "multi@"+ssoDomainA)
		if err != nil {
			t.Fatal(err)
		}
		scope(se.a.ID)
		// No tenant left: the session stays valid and reaches nothing.
		se.configure(t, se.a.ID, func(c *store.TenantSSO) { c.Enabled = false }, ssoDomainA)
		scope()

		// A password session keeps every tenant.
		se.mustDelegated(t, se.r, "local", false, se.a.ID, se.b.ID)
		if p := se.mustResolve(t, mustToken(t, se.env, "local")); len(p.Admin.TenantIDs) != 2 || p.AuthMethod != store.AuthPassword {
			t.Errorf("password session = %+v", p)
		}

		// The scope cannot be read: the request fails.
		restore := se.withFaults("ssoForAdmin")
		_, err = se.svc.Resolve(ctx, sess.Token)
		restore()
		wantErr(t, "scope fault", err, errFault)
	})
}

// TestSSOFlowFailures checks the refusals of the callback: replayed,
// missing or tampered flow, issuer mismatch, provider error, configuration
// changed or removed since the start, code refused, and the per-IP limit.
func TestSSOFlowFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		se := newSSOEnv(t, e)
		se.configure(t, se.a.ID, nil, ssoDomainA)
		se.ssoOnly(t, "sso.a", ssoDomainA, store.RoleDelegatedAdmin, se.a.ID)
		// recorded counts the attempts reserved on the per-IP limit.
		var recorded int
		se.svc.repo = countingRepo{repo: se.svc.repo, n: &recorded}
		complete := func(cb SSOCallback) error {
			_, err := se.svc.CompleteSSO(ctx, cb, ipB)
			return err
		}

		cb := se.begin(t, "sso.a@"+ssoDomainA)
		if err := complete(cb); err != nil {
			t.Fatal(err)
		}
		// A replay: the cookie is genuine and bound to the state, the flow
		// is gone; counted and logged.
		replay := cb
		failures := recorded
		wantSSOFail(t, "replayed state", complete(replay), securitylog.ReasonStateInvalid)
		if lines := se.logLines("sso_failed"); len(lines) != 1 || !strings.Contains(lines[0], `reason="state_invalid"`) {
			t.Errorf("security log after a replay = %q", lines)
		}
		if got := recorded; got != failures+1 {
			t.Errorf("per-IP attempts after a replay = %d, want %d", got, failures+1)
		}

		// No flow binding (no cookie, a forged one, or a state the cookie
		// is not bound to): what a cross-site page can produce. Refused
		// alike, neither counted nor logged, and the flow stays usable.
		cb = se.begin(t, "sso.a@"+ssoDomainA)
		missing := cb
		missing.Cookie = ""
		forged := cb
		forged.Cookie = "of_" + strings.Repeat("A", 43) + "." + strings.Repeat("A", 43)
		tampered := cb
		tampered.State = "other-state"
		failures = recorded
		for range LoginIPMaxFailures + 1 {
			wantSSOFail(t, "no cookie", complete(missing), securitylog.ReasonStateInvalid)
			wantSSOFail(t, "forged cookie", complete(forged), securitylog.ReasonStateInvalid)
			wantSSOFail(t, "tampered state", complete(tampered), securitylog.ReasonStateInvalid)
			wantSSOFail(t, "no state", complete(SSOCallback{Cookie: cb.Cookie}), securitylog.ReasonStateInvalid)
		}
		if got := recorded; got != failures {
			t.Errorf("per-IP attempts after unbound callbacks = %d, want %d", got, failures)
		}
		if lines := se.logLines("sso_failed"); len(lines) != 1 {
			t.Errorf("unbound callbacks logged: %q", lines)
		}
		if err := complete(cb); err != nil {
			t.Errorf("flow after unbound callbacks: %v", err)
		}

		cb = se.begin(t, "sso.a@"+ssoDomainA)
		cb.Iss = "https://login.example.com/other/v2.0"
		wantSSOFail(t, "iss mismatch", complete(cb), securitylog.ReasonIssuerError)

		se.idp.SetBehavior(oidctest.Behavior{AuthorizeError: "access_denied"})
		cb = se.begin(t, "sso.a@"+ssoDomainA)
		se.idp.SetBehavior(oidctest.Behavior{})
		if cb.Error != "access_denied" {
			t.Fatalf("callback = %+v", cb)
		}
		wantSSOFail(t, "provider error", complete(cb), securitylog.ReasonIssuerError)
		// The provider error burnt the flow.
		cb.Error = ""
		wantSSOFail(t, "flow after a provider error", complete(cb), securitylog.ReasonStateInvalid)

		se.idp.SetBehavior(oidctest.Behavior{Status: map[string]int{oidctest.TokenPath: 400}})
		wantSSOFail(t, "code refused", complete(se.begin(t, "sso.a@"+ssoDomainA)), securitylog.ReasonTokenInvalid)
		se.idp.SetBehavior(oidctest.Behavior{})

		// Configuration disabled, then deleted, between start and callback.
		cb = se.begin(t, "sso.a@"+ssoDomainA)
		se.configure(t, se.a.ID, func(c *store.TenantSSO) { c.Enabled = false }, ssoDomainA)
		wantSSOFail(t, "disabled since the start", complete(cb), securitylog.ReasonIssuerError)
		se.configure(t, se.a.ID, nil, ssoDomainA)
		cb = se.begin(t, "sso.a@"+ssoDomainA)
		if _, err := se.db.SSOSettings().Delete(ctx, se.a.ID); err != nil {
			t.Fatal(err)
		}
		wantSSOFail(t, "deleted since the start", complete(cb), securitylog.ReasonIssuerError)
		se.configure(t, se.a.ID, nil, ssoDomainA)

		// The tenant of the flow is gone.
		cb = se.begin(t, "sso.a@"+ssoDomainA)
		restore := se.withRepo(func(r repo) faultRepo {
			return faultRepo{repo: r, fails: map[string]error{"tenant": store.ErrNotFound}}
		})
		wantSSOFail(t, "tenant deleted", complete(cb), securitylog.ReasonIssuerError)
		restore()
		if lines := se.logLines("sso_failed"); !strings.Contains(lines[len(lines)-1], "tenant=-") {
			t.Errorf("failure without tenant = %s", lines[len(lines)-1])
		}

		// The secret cannot be unsealed at the callback.
		cb = se.begin(t, "sso.a@"+ssoDomainA)
		restoreSecrets := with[SecretOpener](&se.svc.secrets, failOpener{})
		wantSSOFail(t, "secret not unsealed", complete(cb), securitylog.ReasonIssuerError)
		restoreSecrets()

		// Every failure is counted on the per-IP limit: the 20th locks.
		for i := len(se.logLines("sso_failed")); i < LoginIPMaxFailures-1; i++ {
			wantSSOFail(t, "flood", complete(replay), securitylog.ReasonStateInvalid)
		}
		_ = wantLimited(t, "flood lock", complete(replay))
		_ = wantLimited(t, "while locked", complete(replay))
		_, err := se.svc.StartSSO(ctx, "sso.a@"+ssoDomainA, ipB)
		_ = wantLimited(t, "start while locked", err)
		_, err = se.svc.Login(ctx, "root", rootPassword, ipB)
		_ = wantLimited(t, "password login while locked", err)
		if lines := se.logLines("rate_limited"); len(lines) < 1 || !strings.Contains(lines[0], `scope="admin_login"`) {
			t.Errorf("rate_limited lines = %q", lines)
		}
	})
}

// countingRepo counts the attempts reserved on the login limits.
type countingRepo struct {
	repo
	n *int
}

func (c countingRepo) recordLogin(ctx context.Context, rules []store.AdminLoginRule, now time.Time) (store.FailureOutcome, error) {
	*c.n++
	return c.repo.recordLogin(ctx, rules, now)
}

// failOpener fails every unsealing.
type failOpener struct{}

func (failOpener) Open(context.Context, tenant.ID, crypto.Purpose, string) ([]byte, error) {
	return nil, errFault
}

// TestSSOStart checks the start of a login: malformed address, unknown or
// disabled domain alike, configuration that cannot be used, the per-IP
// limit, and a service without single sign-on.
func TestSSOStart(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		se := newSSOEnv(t, e)
		_, err := se.svc.StartSSO(ctx, "not an address", ipB)
		wantInvalid(t, "malformed address", err, FieldEmail)
		_, err = se.svc.StartSSO(ctx, "a@"+ssoDomainA, netip.Addr{})
		wantErr(t, "no client ip", err, ErrNoClientIP)
		_, err = se.svc.StartSSO(ctx, "a@"+ssoDomainA, ipB)
		wantErr(t, "unknown domain", err, ErrSSONotAvailable)
		se.configure(t, se.a.ID, func(c *store.TenantSSO) { c.Enabled = false }, ssoDomainA)
		_, err = se.svc.StartSSO(ctx, "a@"+ssoDomainA, ipB)
		wantErr(t, "disabled", err, ErrSSONotAvailable)

		// The provider cannot be reached: same answer, logged by tenant.
		se.configure(t, se.a.ID, nil, ssoDomainA)
		se.idp.SetBehavior(oidctest.Behavior{Status: map[string]int{oidctest.DiscoveryPath: 500}})
		_, err = se.svc.StartSSO(ctx, "a@"+ssoDomainA, ipB)
		wantErr(t, "discovery failure", err, ErrSSONotAvailable)
		se.idp.SetBehavior(oidctest.Behavior{})
		if log := se.applog.String(); !strings.Contains(log, "single sign-on start failed") || !strings.Contains(log, string(se.a.ID)) ||
			strings.Contains(log, se.idp.ClientSecret()) {
			t.Errorf("application log = %s", log)
		}
		// The secret cannot be unsealed.
		restore := with[SecretOpener](&se.svc.secrets, failOpener{})
		_, err = se.svc.StartSSO(ctx, "a@"+ssoDomainA, ipB)
		wantErr(t, "secret not unsealed", err, ErrSSONotAvailable)
		restore()
		if !strings.Contains(se.applog.String(), "single sign-on client secret not unsealed") {
			t.Error("unsealing failure not logged")
		}
		// No sso_failed event at the start: nothing was presented.
		if lines := se.logLines("sso_failed"); len(lines) != 0 {
			t.Errorf("sso_failed at the start: %q", lines)
		}
		// A success does not count: many starts in a row.
		for range LoginIPMaxFailures + 1 {
			if _, err := se.svc.StartSSO(ctx, "a@"+ssoDomainA, ipB); err != nil {
				t.Fatalf("StartSSO: %v", err)
			}
		}
		// Unknown domains count: the 20th failure locks (4 so far).
		for range LoginIPMaxFailures - 5 {
			_, err = se.svc.StartSSO(ctx, "a@unknown.example.com", ipB)
			wantErr(t, "unknown domain", err, ErrSSONotAvailable)
		}
		_, err = se.svc.StartSSO(ctx, "a@unknown.example.com", ipB)
		_ = wantLimited(t, "probing locked", err)

		// Without flows, no single sign-on at all.
		se.svc.flows = nil
		if m, err := se.svc.Methods(ctx); err != nil || m.SSO {
			t.Errorf("Methods without flows = %+v, %v", m, err)
		}
		_, err = se.svc.StartSSO(ctx, "a@"+ssoDomainA, ipA)
		wantErr(t, "start without flows", err, ErrSSONotAvailable)
		_, err = se.svc.CompleteSSO(ctx, SSOCallback{}, ipA)
		wantErr(t, "callback without flows", err, ErrSSONotAvailable)
		_, err = se.svc.CompleteSSO(ctx, SSOCallback{}, netip.Addr{})
		wantErr(t, "callback without ip", err, ErrNoClientIP)

		if _, err := New(se.db, se.kr, se.vault, se.hasher, securitylog.New(se.seclog), Options{
			AdminBaseURL: baseURL, SSOFlows: oidc.NewFlows(oidc.NewClient(oidc.Options{}), se.kr),
		}); err == nil {
			t.Error("New accepted flows without a secret opener")
		}
	})
}

// TestSSOEnforced checks the enforced single sign-on (T-292): the right
// password of an account attached to an enforcing tenant is refused after
// the check, a wrong one stays a wrong password, and no activation link is
// issued for a single sign-on only account.
func TestSSOEnforced(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		se := newSSOEnv(t, e)
		se.configure(t, se.a.ID, nil, ssoDomainA)
		se.mustDelegated(t, se.r, "local", false, se.a.ID, se.b.ID)
		only := se.ssoOnly(t, "only", ssoDomainA, store.RoleDelegatedAdmin, se.a.ID)
		// Not enforced yet: both ways work.
		early := mustToken(t, se.env, "local")
		if p := se.mustResolve(t, early); len(p.Admin.TenantIDs) != 2 {
			t.Fatalf("password session before enforcement = %v", p.Admin.TenantIDs)
		}
		se.configure(t, se.a.ID, func(c *store.TenantSSO) { c.Enforced = true }, ssoDomainA)
		// A password session opened before the enforcement no longer
		// reaches the enforcing tenant (T-292); the others stay.
		if p := se.mustResolve(t, early); !slices.Equal(p.Admin.TenantIDs, []tenant.ID{se.b.ID}) {
			t.Errorf("password session after enforcement = %v", p.Admin.TenantIDs)
		}
		// An enforced configuration that cannot be used (disabled) does not
		// count.
		se.configure(t, se.a.ID, func(c *store.TenantSSO) { c.Enforced, c.Enabled = true, false }, ssoDomainA)
		if p := se.mustResolve(t, early); len(p.Admin.TenantIDs) != 2 {
			t.Errorf("password session with a disabled enforcement = %v", p.Admin.TenantIDs)
		}
		se.configure(t, se.a.ID, func(c *store.TenantSSO) { c.Enforced = true }, ssoDomainA)
		// An account activated by link while enforced: the session opens
		// (Activate unchanged) but reaches no enforcing tenant.
		if act := se.mustDelegated(t, se.r, "activated", false, se.a.ID); len(act.p.Admin.TenantIDs) != 0 {
			t.Errorf("activation session under enforcement = %v", act.p.Admin.TenantIDs)
		}
		// The enforcement cannot be read: the request fails; the super
		// admin, whose local login is always available, reads nothing.
		restoreScope := se.withFaults("ssoForAdmin")
		_, err := se.svc.Resolve(ctx, early)
		if _, err := se.svc.Resolve(ctx, se.r.sess.Token); err != nil {
			t.Errorf("super admin session: %v", err)
		}
		restoreScope()
		wantErr(t, "password scope fault", err, errFault)
		hash := fakeHash(rootPassword)
		before := se.hasher.count(hash)
		_, err = se.svc.Login(ctx, "local", rootPassword, ipB)
		wantErr(t, "enforced", err, ErrSSORequired)
		if se.hasher.count(hash) != before+1 {
			t.Error("the password was not verified before the refusal")
		}
		if _, d := se.lastAudit(t, audit.ActionAdminLoginFailed); d["reason"] != "sso_required" {
			t.Errorf("admin.login_failed details = %v", d)
		}
		if lines := se.logLines("admin_login_failed"); len(lines) != 0 {
			t.Errorf("a right password was logged as a failure: %q", lines)
		}
		_, err = se.svc.Login(ctx, "local", "a wrong password!", ipB)
		wantErr(t, "wrong password", err, ErrInvalidCredentials)
		// The single sign-on only account has no password at all.
		_, err = se.svc.Login(ctx, "only", "", ipB)
		wantErr(t, "single sign-on only account", err, ErrInvalidCredentials)
		// The super admin is never refused.
		if _, err := se.svc.Login(ctx, "root", rootPassword, ipB); err != nil {
			t.Errorf("super admin login: %v", err)
		}
		// No link for the single sign-on only account while enforced.
		_, _, err = se.svc.ResetCredentials(ctx, se.r.p, only.ID, ipA)
		wantErr(t, "reset", err, ErrSSOOnlyEnforced)
		wantErr(t, "reset is a state conflict", err, ErrStateConflict)
		_, _, err = se.svc.Invite(ctx, se.r.p, only.ID, Invitation{}, ipA)
		wantErr(t, "invite", err, ErrSSOOnlyEnforced)
		// Unknown account: the usual answer.
		_, _, err = se.svc.ResetCredentials(ctx, se.r.p, id.New(id.Admin), ipA)
		wantErr(t, "reset unknown", err, ErrNotFound)
		// The enforcement cannot be read: the login fails.
		restore := se.withFaults("ssoForAdmin")
		_, err = se.svc.Login(ctx, "local", rootPassword, ipB)
		wantErr(t, "enforcement fault", err, errFault)
		_, _, err = se.svc.ResetCredentials(ctx, se.r.p, only.ID, ipA)
		wantErr(t, "reset enforcement fault", err, errFault)
		restore()
		restore = se.withFaults("admin")
		_, _, err = se.svc.ResetCredentials(ctx, se.r.p, only.ID, ipA)
		wantErr(t, "reset read fault", err, errFault)
		restore()

		// Not enforced any more: the link is issued, and using it ends the
		// single sign-on only state.
		se.configure(t, se.a.ID, nil, ssoDomainA)
		acc, link, err := se.svc.ResetCredentials(ctx, se.r.p, only.ID, ipA)
		if err != nil || !acc.SSOOnly || link.URL == "" {
			t.Fatalf("reset = %+v, %+v, %v", acc, link, err)
		}
		if _, err := se.svc.Activate(ctx, se.tokenOf(t, link), rootPassword, ipB); err != nil {
			t.Fatal(err)
		}
		if got, _ := se.svc.Get(ctx, se.r.p, only.ID); got.SSOOnly || !got.Activated {
			t.Errorf("after activation = %+v", got)
		}
	})
}

// TestSSOCreateNone checks the creation without activation link: every
// tenant of the account needs a usable single sign-on.
func TestSSOCreateNone(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		se := newSSOEnv(t, e)
		create := func(tids ...tenant.ID) error {
			_, _, err := se.svc.Create(ctx, se.r.p, AdminCreate{
				Username: "none", Email: "none@" + ssoDomainA, Role: store.RoleAuditor, TenantIDs: tids,
				Invitation: Invitation{Delivery: DeliveryNone},
			}, ipA)
			return err
		}
		wantErr(t, "no configuration", create(se.a.ID), ErrSSONotConfigured)
		se.configure(t, se.a.ID, nil, ssoDomainA)
		se.configure(t, se.b.ID, func(c *store.TenantSSO) { c.Enabled = false }, ssoDomainB)
		wantErr(t, "disabled configuration", create(se.a.ID, se.b.ID), ErrSSONotConfigured)
		wantInvalid(t, "unknown tenant", create(se.a.ID, tenant.ID(id.New(id.Tenant))), FieldTenantIDs)
		_, _, err := se.svc.Create(ctx, se.r.p, AdminCreate{
			Username: "none", Email: "none@" + ssoDomainA, Role: store.RoleAuditor, TenantIDs: []tenant.ID{se.a.ID},
			Invitation: Invitation{Delivery: DeliveryNone, Language: "de"},
		}, ipA)
		wantInvalid(t, "language", err, FieldInvitation+FieldLanguage)
		restore := se.withFaults("ssoGet")
		wantErr(t, "configuration fault", create(se.a.ID), errFault)
		restore()
		if err := create(se.a.ID); err != nil {
			t.Fatal(err)
		}
		if se.countAction(t, string(audit.ActionAdminCreated)) != 1 {
			t.Error("admin.created not audited once")
		}
	})
}

// TestSSOFaults checks that every failure of the store, the keys or the
// random sources during a login is an internal error (or only logged when
// the session is already open), and that a security log failure never
// changes the answer.
func TestSSOFaults(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		se := newSSOEnv(t, e)
		se.configure(t, se.a.ID, nil, ssoDomainA)
		acc := se.ssoOnly(t, "sso.a", ssoDomainA, store.RoleDelegatedAdmin, se.a.ID)
		email := "sso.a@" + ssoDomainA

		restore := se.withFaults("ssoAnyEnabled")
		_, err := se.svc.Methods(ctx)
		wantErr(t, "methods", err, errFault)
		restore()
		for _, op := range []string{"ssoRoute", "checkLogin"} {
			restore = se.withFaults(op)
			_, err = se.svc.StartSSO(ctx, email, ipB)
			wantErr(t, "start "+op, err, errFault)
			restore()
		}

		// Failures before the account is pinned.
		for _, op := range []string{
			"checkLogin", "tenant", "ssoGet", "findIdentity", "adminsByEmail", "identityForAdmin",
			"tx.linkIdentity", "tx.audit." + string(audit.ActionAdminIdentityLinked), "tx.createSession",
		} {
			cb := se.begin(t, email)
			restore = se.withFaults(op)
			_, err = se.svc.CompleteSSO(ctx, cb, ipB)
			restore()
			wantErr(t, "callback "+op, err, errFault)
		}
		restore = with(&se.svc.newToken, failToken)
		_, err = se.svc.CompleteSSO(ctx, se.begin(t, email), ipB)
		restore()
		wantErr(t, "session token", err, errFault)
		// A concurrent pinning, or a promotion since the match.
		for want, injected := range map[string]error{
			securitylog.ReasonIdentityMismatch: store.ErrIdentityConflict,
			securitylog.ReasonAccountUnknown:   store.ErrInvalid,
		} {
			cb := se.begin(t, email)
			restore = se.withRepo(func(r repo) faultRepo {
				return faultRepo{repo: r, fails: map[string]error{"tx.linkIdentity": injected}}
			})
			_, err = se.svc.CompleteSSO(ctx, cb, ipB)
			restore()
			wantSSOFail(t, "link "+want, err, want)
		}
		if got, _ := se.svc.Get(ctx, se.r.p, acc.ID); len(got.Identities) != 0 {
			t.Fatalf("identity pinned by a failed login: %+v", got.Identities)
		}

		// Recording the use and the login only logs.
		restore = se.withFaults("touchIdentity", "touchLogin")
		se.mustLogin(t, email)
		restore()
		if log := se.applog.String(); !strings.Contains(log, "single sign-on identity use not recorded") ||
			!strings.Contains(log, "admin last login not recorded") {
			t.Errorf("application log = %s", log)
		}
		// Pinned now: the reads of the pinned path.
		cb := se.begin(t, email)
		restore = se.withFaults("admin")
		_, err = se.svc.CompleteSSO(ctx, cb, ipB)
		restore()
		wantErr(t, "pinned admin", err, errFault)
		cb = se.begin(t, email)
		restore = se.withRepo(func(r repo) faultRepo {
			return faultRepo{repo: r, fails: map[string]error{"admin": store.ErrNotFound}}
		})
		_, err = se.svc.CompleteSSO(ctx, cb, ipB)
		restore()
		wantSSOFail(t, "pinned admin deleted", err, securitylog.ReasonAccountUnknown)

		// A security log failure is reported on the application log only.
		se.seclog.mu.Lock()
		se.seclog.err = errFault
		se.seclog.mu.Unlock()
		cb = se.begin(t, email)
		cb.Iss = "https://login.example.com/other/v2.0"
		_, err = se.svc.CompleteSSO(ctx, cb, ipB)
		wantSSOFail(t, "security log down", err, securitylog.ReasonIssuerError)
		if !strings.Contains(se.applog.String(), "security log write failed") {
			t.Error("security log failure not reported")
		}
		se.seclog.mu.Lock()
		se.seclog.err = nil
		se.seclog.mu.Unlock()

		// Account views and changes.
		restore = se.withFaults("identities")
		_, err = se.svc.Get(ctx, se.r.p, acc.ID)
		wantErr(t, "get identities", err, errFault)
		_, err = se.svc.Update(ctx, se.r.p, acc.ID, AdminUpdate{Disabled: ptr(false)}, ipA)
		wantErr(t, "update identities", err, errFault)
		restore()
		d := se.mustDelegated(t, se.r, "promo", true, se.a.ID)
		se.mustEnroll(t, d.p)
		se.claims("s-promo", "promo@"+ssoDomainA, true)
		se.mustLogin(t, "promo@"+ssoDomainA)
		for _, op := range []string{"tx.listIdentities", "tx.audit." + string(audit.ActionAdminIdentityUnlinked)} {
			restore = se.withFaults(op)
			_, err = se.svc.Update(ctx, se.r.p, d.account.ID, AdminUpdate{Role: ptr(store.RoleSuperAdmin)}, ipA)
			restore()
			wantErr(t, "promote "+op, err, errFault)
		}
		got, err := se.svc.Get(ctx, se.r.p, d.account.ID)
		if err != nil || len(got.Identities) != 1 || got.Role != store.RoleDelegatedAdmin {
			t.Fatalf("after failed promotions = %+v, %v", got, err)
		}
		for _, op := range []string{"tx.listIdentities", "tx.deleteIdentity", "tx.deleteSSOSessions"} {
			restore = se.withFaults(op)
			_, err = se.svc.Update(ctx, se.r.p, d.account.ID, AdminUpdate{Email: ptr("moved@" + ssoDomainA)}, ipA)
			restore()
			wantErr(t, "email change "+op, err, errFault)
		}
		for _, op := range []string{"tx.deleteIdentity", "tx.deleteSSOSessions", "tx.audit"} {
			restore = se.withFaults(op)
			err = se.svc.DeleteIdentity(ctx, se.r.p, d.account.ID, got.Identities[0].ID, ipA)
			restore()
			wantErr(t, "delete identity "+op, err, errFault)
		}
		// The invitation of a single sign-on only account reads the
		// enforcement.
		restore = se.withFaults("ssoForAdmin")
		_, _, err = se.svc.Invite(ctx, se.r.p, acc.ID, Invitation{}, ipA)
		restore()
		wantErr(t, "invite enforcement", err, errFault)
	})
}

// TestSSOErrorAndRules checks the small helpers of the single sign-on.
func TestSSOErrorAndRules(t *testing.T) {
	err := error(&SSOError{Reason: securitylog.ReasonTokenInvalid})
	if !errors.Is(err, ErrSSOFailed) || errors.Is(err, ErrInvalidCredentials) || !strings.Contains(err.Error(), "token_invalid") {
		t.Errorf("SSOError = %v", err)
	}
	if f := (&ssoRefusalError{reason: "x"}); !strings.Contains(f.Error(), "x") {
		t.Error(f.Error())
	}
	if !usable(store.TenantSSO{Enabled: true, ClientSecretKeyID: "wk_x"}) || usable(store.TenantSSO{Enabled: true}) {
		t.Error("usable")
	}
	tid := tenant.ID("ten_a")
	for _, tc := range []struct {
		a    store.Admin
		want bool
	}{
		{store.Admin{Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{tid}}, true},
		{store.Admin{Role: store.RoleAuditor, TenantIDs: []tenant.ID{tid}}, true},
		{store.Admin{Role: store.RoleSuperAdmin}, false},
		{store.Admin{Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{tid}, Disabled: true}, false},
		{store.Admin{Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{"ten_b"}}, false},
	} {
		if got := eligible(tc.a, tid); got != tc.want {
			t.Errorf("eligible(%+v) = %v", tc.a, got)
		}
	}
	if u, _ := url.Parse(baseURL + SSOCallbackPath); u.Path != "/api/v1/admin/auth/oidc/callback" {
		t.Error(u)
	}
}

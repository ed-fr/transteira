package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/oidc/oidctest"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// verified is the address of the email_verified claim.
func verified() *bool { v := true; return &v }

// ssoAuditActions returns the actions of every audit event of the instance
// (any tenant), with their count.
func ssoAuditActions(t *testing.T, a *adminEnv) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, r := range sysQuery(t, a.e, `SELECT action FROM audit_events`) {
		out[r[0]]++
	}
	return out
}

// TestSSOLogin runs the single sign-on login of a delegated admin through
// the real HTTP server and a fake provider: the configuration by the super
// admin, the first login pinning the identity (never an unknown account, a
// wrong subject or an unverified address), the second login by the
// (issuer, client ID, subject) triple, and the session reaching its tenant
// only.
func TestSSOLogin(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startSSO(t, e, serverOptions{})
		tidA, tidB := string(s.tenantA.ID), string(s.tenantB.ID)

		// Nothing is offered before a configuration exists.
		if resp := mustStatus(t, "methods", s.client(nil, adminIP(30)).send(t, http.MethodGet, pathSSOMethods, nil, nil), http.StatusOK); string(resp.body) != "{\"password\":true,\"sso\":false}\n" {
			t.Errorf("methods = %s", resp.body)
		}
		expectProblem(t, s.client(nil, adminIP(31)).send(t, http.MethodPost, pathSSOStart, map[string]string{"email": "who@" + domainA}, nil),
			http.StatusNotFound, "sso-not-available")
		expectProblem(t, s.sa.call(t, http.MethodGet, tenantPath(tidA, "/sso"), nil), http.StatusNotFound, "not-found")

		resp := mustStatus(t, "putTenantSso", s.putSSO(t, tidA, s.ssoBody([]string{domainA}, nil)), http.StatusOK)
		if strings.Contains(string(resp.body), s.idp.ClientSecret()) {
			t.Errorf("the client secret is returned: %s", resp.body)
		}
		var cfg struct {
			Enabled         bool     `json:"enabled"`
			HasClientSecret bool     `json:"hasClientSecret"`
			EmailDomains    []string `json:"emailDomains"`
		}
		mustJSON(t, resp.body, &cfg)
		if !cfg.Enabled || !cfg.HasClientSecret || len(cfg.EmailDomains) != 1 {
			t.Errorf("putTenantSso = %s", resp.body)
		}
		if resp := mustStatus(t, "methods", s.client(nil, adminIP(30)).send(t, http.MethodGet, pathSSOMethods, nil, nil), http.StatusOK); string(resp.body) != "{\"password\":true,\"sso\":true}\n" {
			t.Errorf("methods after the configuration = %s", resp.body)
		}
		// The test of the discovery reaches the fake provider.
		tr := mustStatus(t, "testTenantSso", s.sa.call(t, http.MethodPost, tenantPath(tidA, "/sso/test"), nil), http.StatusOK)
		if !strings.Contains(string(tr.body), `"success":true`) {
			t.Fatalf("testTenantSso = %s (the guard or the roots refuse the provider)", tr.body)
		}

		email := uniqueEmail(t, "sso-user", domainA)
		id := s.createSSOOnly(t, "sso.user", "delegated_admin", email, tidA)
		if ids := s.identitiesOf(t, id); len(ids) != 0 {
			t.Fatalf("a new account has identities: %v", ids)
		}

		// Refused logins pin nothing: unknown account, unverified address,
		// provider error.
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-stranger", Email: uniqueEmail(t, "stranger", domainA), EmailVerified: verified()})
		_, resp = s.ssoLogin(t, "x@"+domainA, adminIP(40))
		expectSSOFailure(t, resp, "invalid-credentials")
		unverified := false
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-1", Email: email, EmailVerified: &unverified})
		_, resp = s.ssoLogin(t, email, adminIP(40))
		expectSSOFailure(t, resp, "invalid-credentials")
		s.idp.SetClaims(oidctest.Claims{})
		s.idp.SetBehavior(oidctest.Behavior{AuthorizeError: "access_denied"})
		_, resp = s.ssoLogin(t, email, adminIP(40))
		expectSSOFailure(t, resp, "invalid-credentials")
		s.idp.SetBehavior(oidctest.Behavior{})
		if ids := s.identitiesOf(t, id); len(ids) != 0 {
			t.Fatalf("a refused login pinned %v", ids)
		}

		// First login: the identity is pinned and the session is open
		// without any second factor of ours.
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-1", Email: email, EmailVerified: verified()})
		c, resp := s.ssoLogin(t, email, adminIP(41))
		c.adoptSSO(t, resp)
		me := c.me(t)
		if me.Role != "delegated_admin" || me.Email != email || len(me.Tenants) != 1 || me.Tenants[0].ID != tidA {
			t.Errorf("me = %+v, want the delegated admin of tenant A only", me)
		}
		mustStatus(t, "own tenant", c.call(t, http.MethodGet, tenantPath(tidA, ""), nil), http.StatusOK)
		expectProblem(t, c.call(t, http.MethodGet, tenantPath(tidB, ""), nil), http.StatusNotFound, "not-found")
		// Read-only access to its own SSO configuration, never a write.
		mustStatus(t, "getTenantSso by the delegated admin", c.call(t, http.MethodGet, tenantPath(tidA, "/sso"), nil), http.StatusOK)
		expectProblem(t, c.call(t, http.MethodPut, tenantPath(tidA, "/sso"), s.ssoBody([]string{domainA}, nil)), http.StatusForbidden, "forbidden")
		ids := s.identitiesOf(t, id)
		if len(ids) != 1 || ids[0].Issuer != s.idp.Issuer() || ids[0].ClientID != oidctest.ClientID {
			t.Fatalf("identities after the first login = %+v", ids)
		}
		acts := ssoAuditActions(t, s.adminEnv)
		for _, act := range []string{"admin.login", "admin.identity_linked", "tenant.sso_updated"} {
			if acts[act] == 0 {
				t.Errorf("no %s audit event; actions: %v", act, acts)
			}
		}

		// Second login: matched by the triple, whatever the address says.
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-1", Email: uniqueEmail(t, "renamed", domainA), EmailVerified: verified()})
		c2, resp := s.ssoLogin(t, email, adminIP(42))
		c2.adoptSSO(t, resp)
		if me := c2.me(t); me.ID != id {
			t.Errorf("second login = account %s, want %s", me.ID, id)
		}
		if ids := s.identitiesOf(t, id); len(ids) != 1 {
			t.Errorf("a second login pinned another identity: %+v", ids)
		}
		// Another subject presenting the account's address is refused:
		// the account is already pinned.
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-2", Email: email, EmailVerified: verified()})
		_, resp = s.ssoLogin(t, email, adminIP(43))
		expectSSOFailure(t, resp, "invalid-credentials")
		// A super admin never signs in through SSO.
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-root", Email: s.sa.acct.email, EmailVerified: verified()})
		_, resp = s.ssoLogin(t, s.sa.acct.email, adminIP(44))
		expectSSOFailure(t, resp, "invalid-credentials")

		// The identity can be unpinned by the super admin only.
		expectProblem(t, c.call(t, http.MethodDelete, pathAdmins+"/"+id+"/identities/"+ids[0].ID, nil), http.StatusForbidden, "forbidden")
		mustStatus(t, "deleteAdminIdentity", s.sa.call(t, http.MethodDelete, pathAdmins+"/"+id+"/identities/"+ids[0].ID, nil), http.StatusNoContent)
		if got := s.identitiesOf(t, id); len(got) != 0 {
			t.Errorf("identities after the unpinning = %+v", got)
		}
		expectProblem(t, s.sa.call(t, http.MethodDelete, pathAdmins+"/"+id+"/identities/"+ids[0].ID, nil), http.StatusNotFound, "not-found")

		// Tenant B has no configuration: its domain is not routed.
		expectProblem(t, s.client(nil, adminIP(45)).send(t, http.MethodPost, pathSSOStart, map[string]string{"email": "x@" + domainB}, nil),
			http.StatusNotFound, "sso-not-available")
		// Removing the configuration closes the way in.
		mustStatus(t, "deleteTenantSso", s.sa.call(t, http.MethodDelete, tenantPath(tidA, "/sso"), nil), http.StatusNoContent)
		expectProblem(t, s.client(nil, adminIP(46)).send(t, http.MethodPost, pathSSOStart, map[string]string{"email": email}, nil),
			http.StatusNotFound, "sso-not-available")
		s.expectNoSecrets(t, s.auditRows(t))
	})
}

// TestSSOSessionScope checks that an SSO session reaches only the tenants
// whose configuration has the issuer and the client ID of the login (tenant
// A trusts one provider, tenant B another), and that changing the client ID
// of the configuration the session was opened through revokes the session.
func TestSSOSessionScope(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startSSO(t, e, serverOptions{})
		other := oidctest.New(t)
		tidA, tidB := string(s.tenantA.ID), string(s.tenantB.ID)
		mustStatus(t, "put A", s.putSSO(t, tidA, s.ssoBody([]string{domainA}, nil)), http.StatusOK)
		mustStatus(t, "put B", s.putSSO(t, tidB, s.ssoBody([]string{domainB}, map[string]any{
			"issuer": other.Issuer(), "clientSecret": other.ClientSecret(),
		})), http.StatusOK)
		// A domain of another tenant cannot be routed to this one (the
		// 409 sso-domain-conflict needs a domain shared by two tenants,
		// which the internal domains of a tenant exclude).
		expectProblem(t, s.putSSO(t, tidB, s.ssoBody([]string{domainB, domainA}, nil)), http.StatusBadRequest, "validation-failed")

		email := uniqueEmail(t, "two-tenants", domainA)
		s.createSSOOnly(t, "two.tenants", "delegated_admin", email, tidA, tidB)
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-two", Email: email, EmailVerified: verified()})
		c, resp := s.ssoLogin(t, email, adminIP(50))
		c.adoptSSO(t, resp)
		mustStatus(t, "tenant A, the provider of the login", c.call(t, http.MethodGet, tenantPath(tidA, ""), nil), http.StatusOK)
		expectProblem(t, c.call(t, http.MethodGet, tenantPath(tidB, ""), nil), http.StatusNotFound, "not-found")
		expectProblem(t, c.call(t, http.MethodGet, tenantPath(tidB, "/sso"), nil), http.StatusNotFound, "not-found")
		// An unrelated change of tenant B does not touch the session.
		mustStatus(t, "disable B", s.putSSO(t, tidB, s.ssoBody([]string{domainB}, map[string]any{
			"issuer": other.Issuer(), "clientSecret": other.ClientSecret(), "enabled": false,
		})), http.StatusOK)
		mustStatus(t, "tenant A after B changed", c.call(t, http.MethodGet, tenantPath(tidA, ""), nil), http.StatusOK)

		// Another application at tenant A: the session is revoked.
		a := s.ssoBody([]string{domainA}, map[string]any{"clientId": "another-app", "clientSecret": "another-secret-value"})
		mustStatus(t, "change client ID of A", s.sa.call(t, http.MethodPut, tenantPath(tidA, "/sso"), a), http.StatusOK)
		expectProblem(t, c.call(t, http.MethodGet, tenantPath(tidA, ""), nil), http.StatusUnauthorized, "unauthenticated")
		expectProblem(t, c.send(t, http.MethodGet, pathAdminMe, nil, nil), http.StatusUnauthorized, "unauthenticated")
		// Changing the client ID without a new secret is refused.
		noSecret := s.ssoBody([]string{domainA}, map[string]any{"clientId": "third-app"})
		delete(noSecret, "clientSecret")
		expectProblem(t, s.sa.call(t, http.MethodPut, tenantPath(tidA, "/sso"), noSecret), http.StatusBadRequest, "validation-failed")
	})
}

// TestSSOEnforced checks that the enforced option refuses the local
// password login (403 sso-required, only for the right password) of the
// accounts of the tenant.
func TestSSOEnforced(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startSSO(t, e, serverOptions{})
		tidA := string(s.tenantA.ID)
		d := s.sa.createDelegatedOf(t, "pwd.user", tidA, domainA, adminIP(60))
		mustStatus(t, "put", s.putSSO(t, tidA, s.ssoBody([]string{domainA}, nil)), http.StatusOK)
		// Not enforced: the password still works.
		d2 := s.client(d.acct, adminIP(61))
		d2.signIn(t)
		mustStatus(t, "enforce", s.putSSO(t, tidA, s.ssoBody([]string{domainA}, map[string]any{"enforced": true})), http.StatusOK)
		d3 := s.client(d.acct, adminIP(62))
		expectProblem(t, d3.login(t, d.acct.username, d.acct.password), http.StatusForbidden, "sso-required")
		expectProblem(t, d3.login(t, d.acct.username, "not the password"), http.StatusUnauthorized, "invalid-credentials")
		// The super admin keeps its password.
		s.client(s.sa.acct, adminIP(63)).signIn(t)
		// The account can still use SSO.
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-pwd", Email: d.acct.email, EmailVerified: verified()})
		c, resp := s.ssoLogin(t, d.acct.email, adminIP(64))
		c.adoptSSO(t, resp)
		if me := c.me(t); me.ID != d.acct.id {
			t.Errorf("SSO login of the enforced account = %s, want %s", me.ID, d.acct.id)
		}
	})
}

// TestSSOLoginAfterMasterKeyRotation checks threat T-294: the client secret,
// sealed with the master key like the SMTP password, is re-wrapped by the
// rotation and the SSO login still works on the new key alone (the token
// request needs the secret in clear).
func TestSSOLoginAfterMasterKeyRotation(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		k1, k2 := newKeyFile(t, "sso-rot-K1"), newKeyFile(t, "sso-rot-K2")
		s := startSSO(t, e, serverOptions{env: map[string]string{config.EnvMasterKeyFile: k1.path}})
		tidA := string(s.tenantA.ID)
		mustStatus(t, "put", s.putSSO(t, tidA, s.ssoBody([]string{domainA}, nil)), http.StatusOK)
		email := uniqueEmail(t, "rotated", domainA)
		id := s.createSSOOnly(t, "rotated.user", "delegated_admin", email, tidA)
		s.idp.SetClaims(oidctest.Claims{Subject: "sub-rot", Email: email, EmailVerified: verified()})
		c, resp := s.ssoLogin(t, email, adminIP(70))
		c.adoptSSO(t, resp)

		var logs []*watchBuffer
		cfg := *s.cfg
		cfg.MasterKeyNewFile = k2.path
		s.relaunch(t, cfg, serverOptions{}, &logs)
		rot := s.sa.mustStartRotation(t, s.sa.acct.nextCode(t), "")
		if rot.TotalKeys < 2 {
			t.Errorf("rotation = %+v, want at least the TOTP secret and the client secret", rot)
		}
		s.sa.waitRotation(t, rot.ID)
		cfg.MasterKeyFile, cfg.MasterKeyNewFile = k2.path, ""
		s.relaunch(t, cfg, serverOptions{}, &logs)
		s.sa.refreshCSRF(t)

		if st := s.sa.masterKeyStatus(t); st.ActiveKeyID != k2.id {
			t.Fatalf("active key = %s, want %s", st.ActiveKeyID, k2.id)
		}
		// The secret still unseals: the discovery test and a login by the
		// pinned identity.
		tr := mustStatus(t, "testTenantSso", s.sa.call(t, http.MethodPost, tenantPath(tidA, "/sso/test"), nil), http.StatusOK)
		if !strings.Contains(string(tr.body), `"success":true`) {
			t.Fatalf("testTenantSso after the rotation = %s", tr.body)
		}
		c2, resp := s.ssoLogin(t, email, adminIP(71))
		c2.adoptSSO(t, resp)
		if me := c2.me(t); me.ID != id {
			t.Errorf("login after the rotation = %s, want %s", me.ID, id)
		}
		if got := s.idp.LastTokenRequest().Get("client_secret"); got != s.idp.ClientSecret() {
			t.Errorf("the client secret sent after the rotation differs from the stored one")
		}
		s.expectLogsClean(t, logs, k1, k2)
	})
}

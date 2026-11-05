package httpisolation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Markers of the single sign-on configurations seeded for each tenant
// (threat model T-287, T-288, T-296): each appears in the configuration of
// its tenant only.
const (
	ssoIssuerA = "https://idp-a.example.com/isolation-a-7f2c/v2.0"
	ssoClientA = "client-a-isolation-3b9e"
	ssoDomainA = "entity-a.example.com"
	ssoIssuerB = "https://idp-b.example.org/isolation-b-91d4/v2.0"
	ssoClientB = "client-b-isolation-c5a8"
	ssoDomainB = "entity-b.example.com"
)

// leaksSSO are the values of tenant B's configuration that no answer to
// tenant A's administrators may hold.
func leaksSSO() []string { return []string{ssoIssuerB, ssoClientB} }

// seedSSO gives each tenant a disabled single sign-on configuration of its
// own (no secret: nothing is sealed by the seeding).
func seedSSO(t *testing.T, db *store.DB, a, b tenant.ID) {
	t.Helper()
	ctx := context.Background()
	for _, c := range []struct {
		tid                    tenant.ID
		issuer, client, domain string
	}{{a, ssoIssuerA, ssoClientA, ssoDomainA}, {b, ssoIssuerB, ssoClientB, ssoDomainB}} {
		if _, _, err := db.SSOSettings().Put(ctx, c.tid, store.TenantSSO{
			Issuer: c.issuer, ClientID: c.client, EmailDomains: []string{c.domain}, RequireMFA: true,
		}); err != nil {
			t.Fatalf("seed single sign-on configuration: %v", err)
		}
	}
}

// noSSOOfB asserts that resp holds no value of tenant B's configuration.
func (h *harness) noSSOOfB(t *testing.T, op operation, what string, resp response) {
	t.Helper()
	for _, s := range leaksSSO() {
		if strings.Contains(string(resp.body), s) {
			t.Errorf("%s: %s leaks %q of tenant B's single sign-on configuration: %s", op, what, s, resp.body)
		}
	}
}

// ssoLoginStep is the isolation case of the three operations of the
// single sign-on login (methods, start, callback): served on the admin host
// only, and, where a domain is routed, the answer for a domain of tenant B
// is the answer for an unknown domain, tenant A's configuration included
// (no oracle on the tenants nor on the domains, T-296).
func ssoLoginStep(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	if op.id != "startAdminOidcLogin" {
		return
	}
	start := func(domain string) response {
		return h.do(t, http.MethodPost, "http://"+h.addr+"/api/v1"+op.template, hostAdmin,
			strings.NewReader(`{"email":"someone@`+domain+`"}`), http.Header{"Content-Type": {"application/json"}})
	}
	unknown := start("unknown-domain.example.net")
	wantCode(t, op, hostAdmin, unknown, http.StatusNotFound, "sso-not-available")
	for _, domain := range []string{ssoDomainA, ssoDomainB} {
		// Both are configured but disabled: the same answer as unknown.
		got := start(domain)
		wantCode(t, op, hostAdmin, got, http.StatusNotFound, "sso-not-available")
		if string(withoutInstance(t, got)) != string(withoutInstance(t, unknown)) {
			t.Errorf("%s: domain %s answers %s, an unknown domain %s", op, domain, got.body, unknown.body)
		}
	}
}

// ssoMethods adds to ssoLoginStep nothing: the methods list names no
// tenant. It is kept apart to assert the body.
func ssoMethods(t *testing.T, h *harness, op operation) {
	t.Helper()
	ssoLoginStep(t, h, op)
	resp := h.do(t, http.MethodGet, "http://"+h.addr+"/api/v1"+op.template, hostAdmin, nil, http.Header{})
	if resp.status != http.StatusOK || strings.TrimSpace(string(resp.body)) != `{"password":true,"sso":false}` {
		t.Errorf("%s: %d %s, want only the two flags (nothing enabled in the harness)", op, resp.status, resp.body)
	}
}

// tenantSsoRead is the isolation case of getTenantSso: served on the admin
// host only; the delegated admin of A reads its own configuration and, for
// tenant B's ID, gets exactly the answer of an unknown tenant (404); the
// super admin reads each tenant's own configuration; the secret is never in
// the body.
func tenantSsoRead(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminTenantOp(t, h, op)
	deleg := h.sendAs(t, h.session(t), op, string(h.tenantA.ID))
	var got struct {
		Issuer          string   `json:"issuer"`
		ClientID        string   `json:"clientId"`
		EmailDomains    []string `json:"emailDomains"`
		HasClientSecret bool     `json:"hasClientSecret"`
	}
	if deleg.status != http.StatusOK || json.Unmarshal(deleg.body, &got) != nil || got.Issuer != ssoIssuerA ||
		got.ClientID != ssoClientA || len(got.EmailDomains) != 1 || got.EmailDomains[0] != ssoDomainA {
		t.Fatalf("%s for tenant A by its delegated admin: %d %s", op, deleg.status, deleg.body)
	}
	h.noSSOOfB(t, op, "the answer to a delegated admin of A", deleg)
	super := h.superSession(t)
	for _, c := range []struct {
		tid            tenant.ID
		issuer, client string
	}{{h.tenantA.ID, ssoIssuerA, ssoClientA}, {h.tenantB.ID, ssoIssuerB, ssoClientB}} {
		resp := h.adminCall(t, super, op.verb, tenantPath(c.tid, "/sso"), "")
		if resp.status != http.StatusOK || !strings.Contains(string(resp.body), c.issuer) || !strings.Contains(string(resp.body), c.client) {
			t.Errorf("%s by the super admin for %s: %d %s", op, c.tid, resp.status, resp.body)
		}
		if strings.Contains(string(resp.body), "clientSecret\"") {
			t.Errorf("%s returns a clientSecret member: %s", op, resp.body)
		}
	}
	// An unknown tenant, for the super admin, is a plain 404.
	wantCode(t, op, hostAdmin, h.adminCall(t, super, op.verb, tenantPath(tenant.ID(id.New(id.Tenant)), "/sso"), ""),
		http.StatusNotFound, "not-found")
}

// tenantSsoWrite is the isolation case of putTenantSso, deleteTenantSso and
// testTenantSso, reserved to the super admin (T-287): a delegated admin
// of A gets 403 forbidden for its own tenant, and for tenant B's ID the
// 404 of an unknown tenant (the access check comes first, see tenantScoped),
// even with a valid body, and nothing of any configuration changes; for the
// super admin an unknown tenant is a 404.
func tenantSsoWrite(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminTenantOp(t, h, op)
	deleg := h.session(t)
	body := validBodies[op.id]
	sub := "/sso"
	if op.id == "testTenantSso" {
		sub = "/sso/test"
	}
	resp := h.adminCall(t, deleg, op.verb, tenantPath(h.tenantA.ID, sub), body)
	wantCode(t, op, hostAdmin, resp, http.StatusForbidden, "forbidden")
	h.noSSOOfB(t, op, "the refusal of a delegated admin", resp)
	resp = h.adminCall(t, deleg, op.verb, tenantPath(h.tenantB.ID, sub), body)
	wantCode(t, op, hostAdmin, resp, http.StatusNotFound, "not-found")
	h.noSSOOfB(t, op, "the answer for tenant B", resp)
	// Nothing changed: both configurations are still the seeded ones.
	super := h.superSession(t)
	for _, c := range []struct {
		tid            tenant.ID
		issuer, client string
	}{{h.tenantA.ID, ssoIssuerA, ssoClientA}, {h.tenantB.ID, ssoIssuerB, ssoClientB}} {
		resp := h.adminCall(t, super, http.MethodGet, tenantPath(c.tid, "/sso"), "")
		if resp.status != http.StatusOK || !strings.Contains(string(resp.body), c.issuer) {
			t.Errorf("%s: configuration of %s after the refused calls: %d %s", op, c.tid, resp.status, resp.body)
		}
	}
	unknown := tenantPath(tenant.ID(id.New(id.Tenant)), sub)
	wantCode(t, op, hostAdmin, h.adminCall(t, super, op.verb, unknown, body), http.StatusNotFound, "not-found")
}

// adminIdentityOp is the isolation case of deleteAdminIdentity: served on
// the admin host only and reserved to the super admin (403 forbidden for a
// delegated admin, whatever the account or identity it names).
func adminIdentityOp(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	path := "/admin/admins/" + h.admins.delegatedID + "/identities/aid_01JABCM8Q9R0S1T2V3V4W5X6Y7"
	resp := h.adminCall(t, h.session(t), op.verb, path, "")
	wantCode(t, op, hostAdmin, resp, http.StatusForbidden, "forbidden")
	// The super admin gets a plain 404 for an identity that does not exist.
	wantCode(t, op, hostAdmin, h.adminCall(t, h.superSession(t), op.verb, path, ""), http.StatusNotFound, "not-found")
}

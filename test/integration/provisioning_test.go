package integration_test

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Provisioning API paths (since API 1.2).
const (
	pathProvisioningTokens = "/api/v1/admin/provisioning-tokens"
	pathProvisionedTenants = "/api/v1/provisioning/tenants"
	// provisioningSuffix is the FQDN suffix of the test token: it covers
	// no admin host (admin.localhost).
	provisioningSuffix = ".provisioned.localhost"
)

// Members of the OpenAPI ProvisionedTenant (all required) and
// ProvisioningToken (required ones, plus the optional dates and cap).
var (
	provisionedTenantMembers = []string{"createdAt", "delegatedAdminActivated", "fqdn", "id", "name", "setupState"}
	provisioningTokenMembers = []string{
		"allowedCidrs", "allowedFqdnSuffixes", "createdAt", "createdBy", "id", "maxStorageQuotaBytes", "maxTenants", "name",
		"prefix", "tenantsCreated",
	}
)

// provisioningJSON is the part of a ProvisionedTenant the test reads.
type provisioningJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	FQDN       string `json:"fqdn"`
	SetupState string `json:"setupState"`
}

// expectMembers checks that the JSON object raw holds exactly the members
// required, plus some of optional.
func expectMembers(t *testing.T, schema string, raw []byte, required, optional []string) {
	t.Helper()
	var members map[string]json.RawMessage
	mustJSON(t, raw, &members)
	for _, m := range required {
		if _, ok := members[m]; !ok {
			t.Errorf("%s: member %s missing in %s", schema, m, raw)
		}
	}
	for m := range maps.Keys(members) {
		if !slices.Contains(required, m) && !slices.Contains(optional, m) {
			t.Errorf("%s: unexpected member %s in %s", schema, m, raw)
		}
	}
}

// expectFieldProblem asserts that resp is a Problem with the given status
// and code naming the single field.
func expectFieldProblem(t *testing.T, resp response, status int, code, field string) {
	t.Helper()
	expectProblem(t, resp, status, code)
	var p struct {
		Errors []struct {
			Field string `json:"field"`
		} `json:"errors"`
	}
	mustJSON(t, resp.body, &p)
	if len(p.Errors) != 1 || p.Errors[0].Field != field {
		t.Errorf("errors %s, want the field %s", resp.body, field)
	}
}

// bootstrapAs is adminEnv.bootstrap with the super admin address email,
// unique to the test: the provisioning notices are mailed to the super
// admins, and the other tests expect no mail to the default address.
func (a *adminEnv) bootstrapAs(t *testing.T, ip, email string) *adminClient {
	t.Helper()
	acct := &adminAccount{username: superName, email: email, password: superPassword}
	c := a.client(acct, ip)
	resp := c.setup(t, acct.username, acct.email, acct.password, adminSetupToken)
	if resp.status != http.StatusCreated {
		t.Fatalf("setup: %d %s", resp.status, resp.body)
	}
	var enr enrollmentJSON
	mustJSON(t, resp.body, &enr)
	c.adopt(t, resp, enr.CSRFToken, stateEnrollRequired)
	acct.secret = decodeSecret(t, enr.Secret)
	a.secret(enr.Secret)
	if resp := c.confirm(t, acct.nextCode(t)); resp.status != http.StatusOK || c.state != stateAuthenticated {
		t.Fatalf("confirm the super admin enrollment: %d %s", resp.status, resp.body)
	}
	acct.id = c.me(t).ID
	return c
}

// provision sends a provisioning request with the Bearer token from ip.
func (a *adminEnv) provision(t *testing.T, method, path, token, ip string, body any) response {
	t.Helper()
	h := http.Header{hdrXFF: {ip}}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
		h.Set("Content-Type", contentJSON)
	}
	return a.do(t, request{method: method, path: path, host: adminHost, body: raw, headers: h})
}

// TestProvisioningFlow covers the provisioning API end to end through the
// real server (V1.2, decisions P48 to P50, threats T-267 to T-276): the
// super admin creates a token with a TOTP re-confirmation; the token
// creates a tenant in setup whose activation link is mailed, never
// returned; the super admins are told by mail and the instance webhooks
// get provisioning_token.created and tenant.provisioned; the token sees only its own tenants; the token
// is never a tenant API token nor the reverse; a revoked token is refused.
func TestProvisioningFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		mp := mailpitEnv(t)
		env := systemSMTPEnv(mp)
		env[config.EnvWebhookAllowNetworks] = "127.0.0.0/8"
		env[config.EnvWebhookAllowHTTPNetworks] = "127.0.0.0/8"
		a := startAdmin(t, e, serverOptions{env: env}, false)
		a.secret(webhookURLToken)
		sa := a.bootstrapAs(t, adminIP(40), uniqueEmail(t, "root", "provider.example.com"))
		rcv := newWebhookReceiver(t)
		sa.mustCreateWebhook(t, "", map[string]any{
			"name": "Provisioning watch", "kind": "generic", "url": rcv.url(), "events": []string{"tenant.provisioned", "provisioning_token.created"},
		})

		// The super admin creates the token: the body is checked before the
		// code, an unknown member is refused, a code is required.
		create := map[string]any{
			"name": "Managed service provider", "allowedCidrs": []string{"198.51.100.0/24"},
			"allowedFqdnSuffixes": []string{provisioningSuffix}, "maxStorageQuotaBytes": int64(1) << 40, "maxTenants": 5,
		}
		resp := sa.call(t, http.MethodPost, pathProvisioningTokens, create)
		expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
		create["role"] = "super_admin"
		expectFieldProblem(t, sa.call(t, http.MethodPost, pathProvisioningTokens, create), http.StatusBadRequest, "validation-failed", "/role")
		delete(create, "role")
		code := sa.acct.nextCode(t)
		a.secret(code)
		create["code"] = code
		resp = sa.call(t, http.MethodPost, pathProvisioningTokens, create)
		if resp.status != http.StatusCreated {
			t.Fatalf("createProvisioningToken: %d %s", resp.status, resp.body)
		}
		expectMembers(t, "ProvisioningTokenCreated", resp.body, append(slices.Clone(provisioningTokenMembers), "token"),
			[]string{"lastUsedAt", "expiresAt", "revokedAt", "maxTransferBytes"})
		var tok struct {
			ID     string `json:"id"`
			Token  string `json:"token"`
			Prefix string `json:"prefix"`
		}
		mustJSON(t, resp.body, &tok)
		a.secret(tok.Token)
		if !strings.HasPrefix(tok.Token, "ttp_") || len(tok.Token) != 47 || !strings.HasPrefix(tok.Token, tok.Prefix) {
			t.Fatalf("token %q prefix %q", tok.Token, tok.Prefix)
		}
		// The same code again is refused (no replay).
		expectProblem(t, sa.call(t, http.MethodPost, pathProvisioningTokens, create), http.StatusUnauthorized, "invalid-credentials")

		// The super admins are told of the new token (T-275): by mail and
		// through the instance webhooks, never with the secret.
		tokenNotice := mp.find(t, sa.acct.email, func(msg mpMessage) bool {
			return strings.Contains(msg.Subject, "Managed service provider")
		})
		if !strings.Contains(tokenNotice.Text, tok.Prefix) || !strings.Contains(tokenNotice.Text, superName) ||
			!strings.Contains(tokenNotice.Text, "https://"+adminHost+"/admin/system/provisioning-tokens") ||
			strings.Contains(tokenNotice.Text+tokenNotice.HTML, tok.Token) {
			t.Errorf("token creation notice:\n%s", tokenNotice.Text)
		}
		eventually(t, "provisioning_token.created webhook", func() bool {
			rcv.mu.Lock()
			defer rcv.mu.Unlock()
			for _, r := range rcv.got {
				if strings.Contains(string(r.body), tok.Token) {
					t.Errorf("the webhook carries the token secret: %s", r.body)
				}
				if strings.Contains(string(r.body), `"provisioning_token.created"`) &&
					strings.Contains(string(r.body), "/admin/system/provisioning-tokens") {
					return true
				}
			}
			return false
		})

		// The token creates a tenant; its body is strict and its scope checked.
		ip := adminIP(41)
		email := uniqueEmail(t, "msp-admin", "customer.example.com")
		local, _, _ := strings.Cut(email, "@")
		fqdn := local + provisioningSuffix
		name := "Entity " + local
		tenantBody := map[string]any{
			"name": name, "fqdn": fqdn, "defaultLanguage": "fr", "storageQuotaBytes": int64(1) << 30,
			"delegatedAdmin": map[string]any{"username": "admin." + local, "email": email, "language": "fr"},
		}
		tenantBody["setupState"] = "active"
		expectFieldProblem(t, a.provision(t, http.MethodPost, pathProvisionedTenants, tok.Token, ip, tenantBody),
			http.StatusBadRequest, "validation-failed", "/setupState")
		delete(tenantBody, "setupState")
		tenantBody["fqdn"] = "evil" + strings.TrimPrefix(provisioningSuffix, ".")
		expectFieldProblem(t, a.provision(t, http.MethodPost, pathProvisionedTenants, tok.Token, ip, tenantBody),
			http.StatusForbidden, "provisioning-scope-exceeded", "/fqdn")
		tenantBody["fqdn"] = fqdn
		resp = a.provision(t, http.MethodPost, pathProvisionedTenants, tok.Token, ip, tenantBody)
		if resp.status != http.StatusCreated {
			t.Fatalf("provisionTenant: %d %s", resp.status, resp.body)
		}
		expectMembers(t, "ProvisionedTenant", resp.body, provisionedTenantMembers, nil)
		if strings.Contains(string(resp.body), "act_") || strings.Contains(string(resp.body), "activation") {
			t.Errorf("the answer carries the activation link: %s", resp.body)
		}
		var created provisioningJSON
		mustJSON(t, resp.body, &created)
		if created.SetupState != "setup" || created.FQDN != fqdn || created.Name != name {
			t.Errorf("created %+v", created)
		}

		// The activation link reaches the delegated admin by mail only, and
		// the super admin is told.
		msg := mp.find(t, email, func(mpMessage) bool { return true })
		m := mailedLinkRE.FindStringSubmatch(msg.Text + msg.HTML)
		if m == nil {
			t.Fatalf("no activation link in the mail:\n%s", msg.Text)
		}
		a.secret(m[1])
		notice := mp.find(t, sa.acct.email, func(msg mpMessage) bool { return strings.Contains(msg.Subject, name) })
		if !strings.Contains(notice.Text, fqdn) || !strings.Contains(notice.Text, tok.Prefix) ||
			!strings.Contains(notice.Text, "https://"+adminHost+"/admin/tenants/"+created.ID) || strings.Contains(notice.Text, tok.Token) {
			t.Errorf("super admin notice:\n%s", notice.Text)
		}
		eventually(t, "tenant.provisioned webhook", func() bool {
			rcv.mu.Lock()
			defer rcv.mu.Unlock()
			for _, r := range rcv.got {
				if strings.Contains(string(r.body), "tenant.provisioned") && strings.Contains(string(r.body), created.ID) {
					return true
				}
			}
			return false
		})

		// The token sees its tenant only: not the tenants of the super admin.
		resp = a.provision(t, http.MethodGet, pathProvisionedTenants, tok.Token, ip, nil)
		if resp.status != http.StatusOK {
			t.Fatalf("listProvisionedTenants: %d %s", resp.status, resp.body)
		}
		var list struct {
			Items []json.RawMessage `json:"items"`
		}
		mustJSON(t, resp.body, &list)
		if len(list.Items) != 1 {
			t.Fatalf("list %s", resp.body)
		}
		expectMembers(t, "ProvisionedTenant", list.Items[0], provisionedTenantMembers, nil)
		resp = a.provision(t, http.MethodGet, pathProvisionedTenants+"/"+created.ID, tok.Token, ip, nil)
		if resp.status != http.StatusOK || !strings.Contains(string(resp.body), `"delegatedAdminActivated":false`) {
			t.Errorf("getProvisionedTenant: %d %s", resp.status, resp.body)
		}
		expectProblem(t, a.provision(t, http.MethodGet, pathProvisionedTenants+"/"+string(a.tenantA.ID), tok.Token, ip, nil),
			http.StatusNotFound, "not-found")

		// Token confusion (T-269), hosts and credentials.
		apiToken := "tt_" + strings.TrimPrefix(tok.Token, "ttp_")
		expectProblem(t, a.provision(t, http.MethodGet, pathProvisionedTenants, apiToken, ip, nil),
			http.StatusUnauthorized, "provisioning-token-invalid")
		resp = a.do(t, request{
			method: http.MethodGet, path: "/api/v1/transfers/" + exampleTransferID, host: hostA,
			headers: http.Header{"Authorization": {"Bearer " + tok.Token}, hdrXFF: {"192.0.2.50"}},
		})
		expectProblem(t, resp, http.StatusUnauthorized, "invalid-credentials")
		resp = a.do(t, request{
			method: http.MethodGet, path: pathProvisionedTenants, host: hostA,
			headers: http.Header{"Authorization": {"Bearer " + tok.Token}, hdrXFF: {ip}},
		})
		expectProblem(t, resp, http.StatusNotFound, "not-found")
		// The admin session opens nothing here.
		expectProblem(t, sa.send(t, http.MethodGet, pathProvisionedTenants, nil, nil), http.StatusUnauthorized, "unauthenticated")
		// From outside the ranges of the token: the same refusal.
		expectProblem(t, a.provision(t, http.MethodGet, pathProvisionedTenants, tok.Token, "203.0.113.9", nil),
			http.StatusUnauthorized, "provisioning-token-invalid")

		// The super admin lists then revokes the token; it is refused at once.
		resp = sa.call(t, http.MethodGet, pathProvisioningTokens, nil)
		var tokens []json.RawMessage
		mustJSON(t, resp.body, &tokens)
		if resp.status != http.StatusOK || len(tokens) != 1 || !strings.Contains(string(tokens[0]), `"tenantsCreated":1`) ||
			strings.Contains(string(resp.body), tok.Token) {
			t.Fatalf("listProvisioningTokens: %d %s", resp.status, resp.body)
		}
		expectMembers(t, "ProvisioningToken", tokens[0], provisioningTokenMembers,
			[]string{"lastUsedAt", "expiresAt", "revokedAt", "maxTransferBytes"})
		if resp := sa.call(t, http.MethodDelete, pathProvisioningTokens+"/"+tok.ID, nil); resp.status != http.StatusNoContent {
			t.Fatalf("revokeProvisioningToken: %d %s", resp.status, resp.body)
		}
		expectProblem(t, a.provision(t, http.MethodGet, pathProvisionedTenants, tok.Token, ip, nil),
			http.StatusUnauthorized, "provisioning-token-invalid")

		// Every refusal is in the security log, with the real client IP and
		// no tenant; the token never is.
		sec := strings.Join(a.securityLines(t), "\n")
		for want, n := range map[string]int{
			"ip=" + ip + " tenant=- event=provisioning_token_invalid":  2, // tt_ token, revoked
			"ip=203.0.113.9 tenant=- event=provisioning_token_invalid": 1,
			"event=provisioning_token_invalid":                         3,
		} {
			if got := strings.Count(sec, want); got != n {
				t.Errorf("%d lines with %q, want %d:\n%s", got, want, n, sec)
			}
		}
		a.expectAudit(t, "provisioning_token.created", "provisioning_token.revoked")
		a.expectLogsClean(t, nil)
	})
}

// TestProvisioningWithoutSystemSMTP: without the system SMTP, a tenant
// cannot be provisioned (its link could not be mailed) and nothing is
// created.
func TestProvisioningWithoutSystemSMTP(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrapAs(t, adminIP(42), uniqueEmail(t, "root", "provider.example.com"))
		code := sa.acct.nextCode(t)
		a.secret(code)
		resp := sa.call(t, http.MethodPost, pathProvisioningTokens, map[string]any{
			"name": "MSP", "allowedCidrs": []string{"198.51.100.0/24"}, "allowedFqdnSuffixes": []string{provisioningSuffix},
			"maxStorageQuotaBytes": 1 << 30, "maxTenants": 1, "code": code,
		})
		if resp.status != http.StatusCreated {
			t.Fatalf("createProvisioningToken: %d %s", resp.status, resp.body)
		}
		var tok struct {
			Token string `json:"token"`
		}
		mustJSON(t, resp.body, &tok)
		a.secret(tok.Token)
		ip := adminIP(43)
		resp = a.provision(t, http.MethodPost, pathProvisionedTenants, tok.Token, ip, map[string]any{
			"name": "Entity Q", "fqdn": "entity-q" + provisioningSuffix, "defaultLanguage": "en", "storageQuotaBytes": 1 << 20,
			"delegatedAdmin": map[string]any{"username": "admin.entity-q", "email": "it@entity-q.example.com", "language": "en"},
		})
		expectProblem(t, resp, http.StatusServiceUnavailable, "system-smtp-unavailable")
		resp = a.provision(t, http.MethodGet, pathProvisionedTenants, tok.Token, ip, nil)
		if resp.status != http.StatusOK || string(resp.body) != `{"items":[]}`+"\n" && string(resp.body) != `{"items":[]}` {
			t.Errorf("list after the refusal: %d %s", resp.status, resp.body)
		}
		a.expectLogsClean(t, nil)
	})
}

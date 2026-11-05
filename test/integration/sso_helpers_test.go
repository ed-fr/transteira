package integration_test

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/ed-fr/transteira/internal/api/admin"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/oidc"
	"github.com/ed-fr/transteira/internal/oidc/oidctest"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Helpers of the single sign-on tests (OpenAPI "Admin auth" oidc steps and
// getTenantSso / putTenantSso; threat model T-286 to T-296).
//
// Seam: app.Run builds its OpenID Connect client itself (newSSO) and has no
// option to inject RootCAs, so the fake provider, which serves a TLS
// certificate, is trusted through SSL_CERT_FILE, which the Go runtime reads
// when it first loads the system roots (TestMain below). The certificate
// of httptest is the same for every server, so one file serves every
// provider of the package.

// pathSSOStart, pathSSOMethods and ssoCallbackPath are the admin paths of
// the single sign-on login.
const (
	pathSSOStart    = "/api/v1/admin/auth/oidc/start"
	pathSSOMethods  = "/api/v1/admin/auth/methods"
	ssoCallbackPath = "/api/v1/admin/auth/oidc/callback"
	// ssoLoopback opens the loopback of the provider to the egress guard
	// (TT_SSO_ALLOW_NETWORKS).
	ssoLoopback = "127.0.0.0/8"
)

// TestMain makes the process trust the certificate of the fake identity
// provider (see the seam note above).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tt-sso-roots-")
	if err != nil {
		panic(err)
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	srv.Close()
	file := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(file, pemBytes, 0o600); err != nil {
		panic(err)
	}
	if err := os.Setenv("SSL_CERT_FILE", file); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// ssoEnv is an admin environment whose OpenID Connect client may reach the
// fake provider.
type ssoEnv struct {
	*adminEnv
	idp *oidctest.Provider
	sa  *adminClient
}

// startSSO starts a server allowing the loopback for the single sign-on,
// bootstraps the super admin and returns the environment.
func startSSO(t *testing.T, e storetest.Engine, o serverOptions) *ssoEnv {
	t.Helper()
	env := map[string]string{config.EnvSSOAllowNetworks: ssoLoopback}
	for k, v := range o.env {
		env[k] = v
	}
	o.env = env
	a := startAdmin(t, e, o, false)
	idp := oidctest.New(t)
	return &ssoEnv{adminEnv: a, idp: idp, sa: a.bootstrapUnique(t, adminIP(10))}
}

// ssoBody is a putTenantSso body for the provider of s.
func (s *ssoEnv) ssoBody(domains []string, extra map[string]any) map[string]any {
	b := map[string]any{
		"enabled": true, "issuer": s.idp.Issuer(), "clientId": oidctest.ClientID, "clientSecret": s.idp.ClientSecret(),
		"emailDomains": domains, "enforced": false, "requireMfa": false,
	}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

// putSSO sends putTenantSso as the super admin.
func (s *ssoEnv) putSSO(t *testing.T, tid string, body map[string]any) response {
	t.Helper()
	s.secret(s.idp.ClientSecret())
	return s.sa.call(t, http.MethodPut, tenantPath(tid, "/sso"), body)
}

// ssoLogin plays the browser of a single sign-on login of email from ip:
// start, authorization at the provider, callback. It returns the callback
// answer (a 303) and the client, holding the session when it succeeded.
func (s *ssoEnv) ssoLogin(t *testing.T, email, ip string) (*adminClient, response) {
	t.Helper()
	c := s.client(nil, ip)
	start := c.send(t, http.MethodPost, pathSSOStart, map[string]string{"email": email}, nil)
	if start.status != http.StatusOK {
		t.Fatalf("startAdminOidcLogin(%s): %d %s", email, start.status, start.body)
	}
	var red struct {
		RedirectURL string `json:"redirectUrl"`
	}
	mustJSON(t, start.body, &red)
	flow := ""
	for _, line := range start.header.Values("Set-Cookie") {
		ck, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatal(err)
		}
		if ck.Name == oidc.FlowCookieName {
			flow = ck.Name + "=" + ck.Value
			if !ck.Secure || !ck.HttpOnly || ck.Path != "/" || ck.Domain != "" || ck.MaxAge <= 0 {
				t.Errorf("flow cookie %q lacks the __Host- attributes", line)
			}
		}
	}
	if flow == "" {
		t.Fatalf("no flow cookie in %v", start.header)
	}
	back, err := s.idp.Authorize(red.RedirectURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if back.Path != ssoCallbackPath || back.Host != adminHost {
		t.Fatalf("the provider redirects to %s, want https://%s%s", back, adminHost, ssoCallbackPath)
	}
	return c, c.send(t, http.MethodGet, ssoCallbackPath+"?"+back.RawQuery, nil,
		http.Header{"Cookie": {flow}, "Sec-Fetch-Site": {"cross-site"}})
}

// expectSSOFailure asserts that resp is a 303 to the login page with code.
func expectSSOFailure(t *testing.T, resp response, code string) {
	t.Helper()
	want := admin.SSOFailureLocation + url.QueryEscape(code)
	if resp.status != http.StatusSeeOther || resp.header.Get("Location") != want {
		t.Fatalf("callback = %d Location %q, want 303 %q; body %s", resp.status, resp.header.Get("Location"), want, resp.body)
	}
	if ck, ok := sessionCookie(t, resp); ok && ck.Value != "" {
		t.Errorf("a failed login set a session cookie")
	}
}

// adoptSSO makes c hold the session of a successful callback.
func (c *adminClient) adoptSSO(t *testing.T, resp response) {
	t.Helper()
	if resp.status != http.StatusSeeOther || resp.header.Get("Location") != admin.SSOSuccessLocation {
		t.Fatalf("callback = %d Location %q, want 303 %s; body %s", resp.status, resp.header.Get("Location"), admin.SSOSuccessLocation, resp.body)
	}
	c.cookie = expectSessionCookie(t, resp)
	c.a.secret(c.cookie)
	c.refreshCSRF(t)
	c.state = stateAuthenticated
}

// createSSOOnly creates, as the super admin, an account without
// activation link (delivery none) for tenants tids.
func (s *ssoEnv) createSSOOnly(t *testing.T, username, role, email string, tids ...string) string {
	t.Helper()
	resp := mustStatus(t, "createAdmin "+username, s.sa.call(t, http.MethodPost, pathAdmins, map[string]any{
		"username": username, "email": email, "role": role, "tenantIds": tids, "invitation": map[string]any{"delivery": "none"},
	}), http.StatusCreated)
	var created adminJSON
	mustJSON(t, resp.body, &created)
	if created.ActivationURL != "" {
		t.Errorf("a delivery none account has an activation link: %s", resp.body)
	}
	return created.ID
}

// identitiesOf returns the SSO identities of the admin id (getAdmin).
func (s *ssoEnv) identitiesOf(t *testing.T, id string) []struct {
	ID       string `json:"id"`
	Issuer   string `json:"issuer"`
	ClientID string `json:"clientId"`
} {
	t.Helper()
	resp := mustStatus(t, "getAdmin", s.sa.call(t, http.MethodGet, pathAdmins+"/"+id, nil), http.StatusOK)
	var a struct {
		SSOOnly    bool `json:"ssoOnly"`
		Identities []struct {
			ID       string `json:"id"`
			Issuer   string `json:"issuer"`
			ClientID string `json:"clientId"`
		} `json:"identities"`
	}
	mustJSON(t, resp.body, &a)
	return a.Identities
}

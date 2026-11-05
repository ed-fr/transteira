package app

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/oidc"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// adminCall sends a same-origin request to the admin host with the session
// cookie and CSRF token, and returns the status, the headers and the body.
func adminCall(t *testing.T, base, method, path, cookie, csrf, body string) (int, http.Header, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = adminHost
	req.Header.Set("Origin", "https://"+adminHost)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

// sessionCookie returns the "name=value" pair of the admin session cookie
// set by h.
func sessionCookie(t *testing.T, h http.Header) string {
	t.Helper()
	for _, c := range h.Values("Set-Cookie") {
		if strings.HasPrefix(c, "__Host-tt_admin=") {
			return strings.SplitN(c, ";", 2)[0]
		}
	}
	t.Fatalf("no session cookie in %v", h)
	return ""
}

// TestRunWiresSingleSignOn checks the single sign-on wiring of the
// application: the login methods and the discovery test of a tenant configuration, which reaches
// the shared OpenID Connect client (a refused discovery is a result, never
// a 500).
func TestRunWiresSingleSignOn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := testConfig(t, storetest.SQLite(t))
	prepare(t, cfg)
	cfg.ClamAV.Address = fakeClamd(t)
	cfg.SetupToken = config.NewSecret("stp_configured_token_value")
	// A TCP listener: the login steps need a client IP.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	s := start(t, cfg, WithListener(ln))

	if code, _, body := adminCall(t, base, http.MethodGet, "/api/v1/admin/auth/methods", "", "", ""); code != http.StatusOK ||
		body != `{"password":true,"sso":false}`+"\n" {
		t.Fatalf("methods = %d %s", code, body)
	}
	// The super admin, with TOTP.
	code, h, body := adminCall(t, base, http.MethodPost, "/api/v1/admin/setup", "", "",
		`{"username":"root","email":"root@example.com","password":"a-long-passphrase-2026","setupToken":"stp_configured_token_value"}`) // gitleaks:allow (fake test credentials)
	if code != http.StatusCreated {
		t.Fatalf("setup = %d %s", code, body)
	}
	var enr struct{ Secret, CsrfToken string }
	if err = json.Unmarshal([]byte(body), &enr); err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enr.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code, h, body = adminCall(t, base, http.MethodPost, "/api/v1/admin/me/totp/confirm", sessionCookie(t, h), enr.CsrfToken,
		`{"code":"`+crypto.TOTPCode(secret, crypto.TOTPCounter(time.Now()))+`"}`)
	if code != http.StatusOK {
		t.Fatalf("confirm = %d %s", code, body)
	}
	if err := json.Unmarshal([]byte(body), &enr); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, h)

	// A configuration whose issuer cannot be resolved.
	c := *cfg
	db, err := store.Open(ctx, &c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	tn, err := db.Tenants().TenantByFQDN(ctx, tenantHost)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SSOSettings().Put(ctx, tn.ID, store.TenantSSO{
		Issuer: "https://sso.entity-a.invalid/idp", ClientID: "app", EmailDomains: []string{"entity-a.example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	code, _, body = adminCall(t, base, http.MethodPost, "/api/v1/admin/tenants/"+string(tn.ID)+"/sso/test", cookie, enr.CsrfToken, "")
	if code != http.StatusOK || !strings.Contains(body, `"success":false`) {
		t.Fatalf("sso test = %d %s", code, body)
	}
	if err := s.stop(t); err != nil {
		t.Fatal(err)
	}
}

func TestNewSSO(t *testing.T) {
	t.Parallel()
	kr, err := masterkey.New(masterkeytest.Key(t, "app"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kr.Close)
	cfg := &config.Config{SSOAllowNetworks: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/28")}, SSOUseProxy: true}
	client, flows, err := newSSO(cfg, kr)
	if err != nil || client == nil || flows == nil {
		t.Fatalf("newSSO = %v, %v, %v", client, flows, err)
	}
	cfg.SSOAllowNetworks = []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}
	if _, _, err := newSSO(cfg, kr); err == nil || !strings.Contains(err.Error(), config.EnvSSOAllowNetworks) {
		t.Errorf("newSSO(core) = %v", err)
	}
	// The purge runs until its context ends.
	ctx, cancel := context.WithCancel(context.Background())
	purgeFlows(ctx, oidc.NewFlows(client, kr), time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	cancel()
}

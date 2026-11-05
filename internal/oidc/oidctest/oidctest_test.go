package oidctest

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// authURL returns a valid authorization URL of p.
func authURL(p *Provider, edit func(url.Values)) string {
	q := url.Values{
		"client_id": {ClientID}, "response_type": {"code"}, "scope": {"openid email"},
		"redirect_uri": {"https://rp.example.com/cb"}, "state": {"st"}, "nonce": {"n"},
		"code_challenge": {"ch"}, "code_challenge_method": {"S256"},
	}
	if edit != nil {
		edit(q)
	}
	return p.Server.URL + AuthorizePath + "?" + q.Encode()
}

func TestAuthorize(t *testing.T) {
	t.Parallel()
	p := New(t)
	back, err := p.Authorize(authURL(p, nil))
	if err != nil {
		t.Fatal(err)
	}
	q := back.Query()
	if back.Host != "rp.example.com" || q.Get("state") != "st" || q.Get("code") == "" || q.Get("iss") != p.Issuer() {
		t.Fatalf("callback %s", back)
	}
	if _, err := p.Authorize(authURL(p, func(q url.Values) { q.Del("nonce") })); err == nil {
		t.Error("request without nonce accepted")
	}
	p.SetBehavior(Behavior{AuthorizeError: "access_denied", WrongIss: true})
	back, _ = p.Authorize(authURL(p, nil))
	if back.Query().Get("error") != "access_denied" || back.Query().Get("code") != "" || back.Query().Get("iss") == p.Issuer() {
		t.Errorf("error callback %s", back)
	}
	p.SetBehavior(Behavior{NoIss: true})
	back, _ = p.Authorize(authURL(p, nil))
	if back.Query().Has("iss") {
		t.Errorf("iss sent: %s", back)
	}
	if p.Requests(AuthorizePath) != 4 {
		t.Errorf("Requests = %d", p.Requests(AuthorizePath))
	}
}

func TestTokenEndpoint(t *testing.T) {
	t.Parallel()
	p := New(t)
	c := p.Client()
	post := func(form url.Values, basic bool) int {
		req, _ := http.NewRequest(http.MethodPost, p.Server.URL+TokenPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basic {
			req.SetBasicAuth(url.QueryEscape(ClientID), url.QueryEscape(p.ClientSecret()))
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	verifier := "verifier-verifier-verifier-verifier-verifier"
	code := p.Code("n", verifier, "https://rp.example.com/cb")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://rp.example.com/cb"}, "code_verifier": {verifier}}
	if s := post(form, false); s != http.StatusUnauthorized {
		t.Errorf("without client authentication: %d", s)
	}
	code = p.Code("n", verifier, "https://rp.example.com/cb")
	form.Set("code", code)
	if s := post(form, true); s != http.StatusOK {
		t.Errorf("valid request: %d", s)
	}
	if s := post(form, true); s != http.StatusBadRequest {
		t.Errorf("replayed code: %d", s)
	}
	if got := p.LastTokenRequest().Get("client_secret"); got != p.ClientSecret() {
		t.Errorf("LastTokenRequest secret %q", got)
	}
	resp, err := c.Get(p.Server.URL + TokenPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET token: %d", resp.StatusCode)
	}
	resp, err = c.Get(p.Server.URL + "/nowhere")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path: %d", resp.StatusCode)
	}
}

func TestClaimsMap(t *testing.T) {
	t.Parallel()
	p := New(t)
	at := time.Unix(1_700_000_000, 0)
	p.SetNow(func() time.Time { return at })
	if m := p.ClaimsMap("n"); m["sub"] != "subject-1" || m["aud"] != ClientID || m["iat"] != at.Unix() || m["nonce"] != "n" {
		t.Fatalf("default claims %v", m)
	}
	yes, other := true, "x"
	p.SetClaims(Claims{
		Subject: "s", Email: "e", EmailVerified: &yes, PreferredUsername: "u", AMR: []string{"mfa"},
		Audience: []string{"a", "b"}, AZP: "a", Issuer: "i", IssuedAt: at, Expiry: at, NotBefore: at, Nonce: &other,
		Extra: map[string]any{"sub": nil, "tid": "t"},
	})
	m := p.ClaimsMap("n")
	if _, ok := m["sub"]; ok || m["tid"] != "t" || m["nonce"] != "x" || m["iss"] != "i" || m["nbf"] != at.Unix() {
		t.Fatalf("claims %v", m)
	}
	p.SetClaims(Claims{Audience: []string{"only"}})
	if p.ClaimsMap("n")["aud"] != "only" {
		t.Error("single audience not a string")
	}
}

func TestIDTokenAlgorithms(t *testing.T) {
	t.Parallel()
	p := New(t)
	for _, alg := range []string{"", AlgRS256, AlgPS256, AlgES256, AlgHS256, AlgNone} {
		p.SetBehavior(Behavior{Alg: alg, KID: "k"})
		tok, err := p.IDToken("n")
		if err != nil || strings.Count(tok, ".") != 2 {
			t.Errorf("IDToken(%q) = %q, %v", alg, tok, err)
		}
	}
	p.SetBehavior(Behavior{Alg: "RS999"})
	if _, err := p.IDToken("n"); err == nil {
		t.Error("unknown algorithm accepted")
	}
}

func TestKeysAndDocument(t *testing.T) {
	t.Parallel()
	p := New(t)
	if n := len(p.JWKS().Keys); n != 2 {
		t.Fatalf("%d keys", n)
	}
	p.RotateKeys(t, true)
	if n := len(p.JWKS().Keys); n != 4 {
		t.Fatalf("%d keys after a rotation keeping the old ones", n)
	}
	p.RotateKeys(t, false)
	if n := len(p.JWKS().Keys); n != 2 {
		t.Fatalf("%d keys after a rotation", n)
	}
	p.SetBehavior(Behavior{ClientSecretPost: true})
	if m := p.Document()["token_endpoint_auth_methods_supported"].([]string); len(m) != 1 || m[0] != "client_secret_post" {
		t.Errorf("methods %v", m)
	}
	if p.CertPool() == nil || !strings.HasSuffix(p.Issuer(), IssuerPath) {
		t.Error("CertPool or Issuer")
	}
}

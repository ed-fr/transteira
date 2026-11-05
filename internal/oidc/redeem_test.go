package oidc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/ed-fr/transteira/internal/oidc/oidctest"
)

// ptr returns a pointer to v.
func ptr[T any](v T) *T { return &v }

func TestRedeemSuccess(t *testing.T) {
	t.Parallel()
	for _, alg := range []string{oidctest.AlgRS256, oidctest.AlgPS256, oidctest.AlgES256} {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.idp.SetBehavior(oidctest.Behavior{Alg: alg})
			e.idp.SetClaims(oidctest.Claims{
				Subject: "sub-42", Email: "Alice@Entity-A.example.com",
				EmailVerified: ptr(true), AMR: []string{"pwd", "mfa"},
			})
			id, err := e.login(t)
			if err != nil {
				t.Fatal(err)
			}
			want := Identity{
				Issuer: e.idp.Issuer(), ClientID: oidctest.ClientID, Subject: "sub-42",
				Email: "alice@entity-a.example.com", MFA: true,
			}
			if id != want {
				t.Fatalf("Identity = %+v", id)
			}
			form := e.idp.LastTokenRequest()
			if form.Get("client_secret") != e.cfg.ClientSecret || form.Get("code_verifier") == "" ||
				form.Get("redirect_uri") != e.cfg.RedirectURL {
				t.Errorf("token request %v", form)
			}
		})
	}
}

func TestRedeemClientSecretPost(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.idp.SetBehavior(oidctest.Behavior{ClientSecretPost: true})
	if _, err := e.login(t); err != nil {
		t.Fatal(err)
	}
}

func TestRedeemMultipleAudiences(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.idp.SetClaims(oidctest.Claims{Audience: []string{oidctest.ClientID, "other"}, AZP: oidctest.ClientID})
	if _, err := e.login(t); err != nil {
		t.Fatal(err)
	}
}

func TestRedeemInvalidTokens(t *testing.T) {
	t.Parallel()
	now := time.Now()
	for _, tc := range []struct {
		name   string
		b      oidctest.Behavior
		c      oidctest.Claims
		reason string
	}{
		{"alg none", oidctest.Behavior{Alg: oidctest.AlgNone}, oidctest.Claims{}, ReasonTokenInvalid},
		{"HS256 with the client secret", oidctest.Behavior{Alg: oidctest.AlgHS256}, oidctest.Claims{}, ReasonTokenInvalid},
		{"unknown kid", oidctest.Behavior{KID: "unknown"}, oidctest.Claims{}, ReasonTokenInvalid},
		{"garbage", oidctest.Behavior{IDToken: "a.b.c"}, oidctest.Claims{}, ReasonTokenInvalid},
		{"no id token", oidctest.Behavior{NoIDToken: true}, oidctest.Claims{}, ReasonTokenInvalid},
		{"wrong issuer", oidctest.Behavior{}, oidctest.Claims{Issuer: "https://evil.example.com"}, ReasonTokenInvalid},
		{"wrong audience", oidctest.Behavior{}, oidctest.Claims{Audience: []string{"other"}}, ReasonTokenInvalid},
		{"several audiences, no azp", oidctest.Behavior{}, oidctest.Claims{Audience: []string{oidctest.ClientID, "other"}}, ReasonTokenInvalid},
		{"wrong azp", oidctest.Behavior{}, oidctest.Claims{AZP: "other"}, ReasonTokenInvalid},
		{"expired", oidctest.Behavior{}, oidctest.Claims{Expiry: now.Add(-Leeway - time.Second)}, ReasonTokenInvalid},
		{"no exp", oidctest.Behavior{}, oidctest.Claims{Extra: map[string]any{"exp": nil}}, ReasonTokenInvalid},
		{"no iat", oidctest.Behavior{}, oidctest.Claims{Extra: map[string]any{"iat": nil}}, ReasonTokenInvalid},
		{"future iat", oidctest.Behavior{}, oidctest.Claims{IssuedAt: now.Add(Leeway + time.Minute)}, ReasonTokenInvalid},
		{"future nbf", oidctest.Behavior{}, oidctest.Claims{NotBefore: now.Add(Leeway + time.Minute)}, ReasonTokenInvalid},
		{"wrong nonce", oidctest.Behavior{}, oidctest.Claims{Nonce: ptr("other")}, ReasonTokenInvalid},
		{"no sub", oidctest.Behavior{}, oidctest.Claims{Extra: map[string]any{"sub": nil}}, ReasonTokenInvalid},
		{"long sub", oidctest.Behavior{}, oidctest.Claims{Subject: strings.Repeat("s", 256)}, ReasonTokenInvalid},
		{"amr not a list", oidctest.Behavior{}, oidctest.Claims{Extra: map[string]any{"amr": "mfa"}}, ReasonTokenInvalid},
		{"token endpoint 400", oidctest.Behavior{Status: map[string]int{oidctest.TokenPath: 400}}, oidctest.Claims{}, ReasonTokenInvalid},
		{"token endpoint 500", oidctest.Behavior{Status: map[string]int{oidctest.TokenPath: 500}}, oidctest.Claims{}, ReasonIssuerError},
		{"token endpoint redirect", oidctest.Behavior{Redirect: map[string]bool{oidctest.TokenPath: true}}, oidctest.Claims{}, ReasonIssuerError},
		{"token answer oversized", oidctest.Behavior{Oversize: map[string]bool{oidctest.TokenPath: true}}, oidctest.Claims{}, ReasonIssuerError},
		{"jwks unavailable", oidctest.Behavior{Status: map[string]int{oidctest.JWKSPath: 500}}, oidctest.Claims{}, ReasonIssuerError},
		{"jwks not json", oidctest.Behavior{JWKSBody: []byte("<html>")}, oidctest.Claims{}, ReasonIssuerError},
		{"jwks without usable key", oidctest.Behavior{JWKSBody: []byte(`{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`)}, oidctest.Claims{}, ReasonTokenInvalid},
		{"jwks oversized", oidctest.Behavior{Oversize: map[string]bool{oidctest.JWKSPath: true}}, oidctest.Claims{}, ReasonIssuerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.clk.mu.Lock()
			e.clk.t = now
			e.clk.mu.Unlock()
			e.idp.SetBehavior(tc.b)
			e.idp.SetClaims(tc.c)
			_, err := e.login(t)
			wantReason(t, err, tc.reason)
		})
	}
}

func TestRedeemLeeway(t *testing.T) {
	t.Parallel()
	now := time.Now()
	e := newEnv(t)
	e.clk.mu.Lock()
	e.clk.t = now
	e.clk.mu.Unlock()
	e.idp.SetClaims(oidctest.Claims{
		Expiry: now.Add(-Leeway + 5*time.Second), IssuedAt: now.Add(Leeway - 5*time.Second),
		NotBefore: now.Add(Leeway - 5*time.Second),
	})
	if _, err := e.login(t); err != nil {
		t.Fatalf("within the leeway: %v", err)
	}
}

func TestRedeemCodeReplay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := context.Background()
	authURL, cookie, err := e.flows.Begin(ctx, e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	back, err := e.idp.Authorize(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := back.Query()
	p, err := e.flows.Consume(cookie, q.Get("state"), q.Get("iss"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.flows.Redeem(ctx, p, e.cfg, q.Get("code")); err != nil {
		t.Fatal(err)
	}
	_, err = e.flows.Redeem(ctx, p, e.cfg, q.Get("code"))
	wantReason(t, err, ReasonTokenInvalid)
	// A code bound to another PKCE challenge is refused.
	code := e.idp.Code(p.nonce, "another-verifier-another-verifier-another-ver", p.redirectURL)
	_, err = e.flows.Redeem(ctx, p, e.cfg, code)
	wantReason(t, err, ReasonTokenInvalid)
	// With its own verifier, a code issued directly works.
	code = e.idp.Code(p.nonce, p.verifier, p.redirectURL)
	if _, err := e.flows.Redeem(ctx, p, e.cfg, code); err != nil {
		t.Fatal(err)
	}
}

func TestRedeemPreconditions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := context.Background()
	p := Pending{
		TenantID: "ten_a", Issuer: e.cfg.Issuer, ClientID: e.cfg.ClientID, redirectURL: e.cfg.RedirectURL,
		verifier: "v", nonce: "n",
	}
	_, err := e.flows.Redeem(ctx, Pending{}, e.cfg, "code")
	wantReason(t, err, ReasonStateInvalid)
	for name, edit := range map[string]func(*Config){
		"tenant": func(c *Config) { c.TenantID = "ten_b" },
		"issuer": func(c *Config) { c.Issuer = "https://other.example.com" },
		"client": func(c *Config) { c.ClientID = "other" },
	} {
		cfg := e.cfg
		edit(&cfg)
		if _, err := e.flows.Redeem(ctx, p, cfg, "code"); ReasonOf(err) != ReasonIssuerError {
			t.Errorf("%s changed: %v", name, err)
		}
	}
	for _, code := range []string{"", strings.Repeat("c", 2049)} {
		if _, err := e.flows.Redeem(ctx, p, e.cfg, code); ReasonOf(err) != ReasonTokenInvalid {
			t.Errorf("code of %d bytes: %v", len(code), err)
		}
	}
	e.idp.SetBehavior(oidctest.Behavior{Status: map[string]int{oidctest.DiscoveryPath: 500}})
	_, err = e.flows.Redeem(ctx, p, e.cfg, "code")
	wantReason(t, err, ReasonIssuerError)
}

func TestRedeemProviderGone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := context.Background()
	authURL, cookie, err := e.flows.Begin(ctx, e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	back, err := e.idp.Authorize(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := back.Query()
	p, err := e.flows.Consume(cookie, q.Get("state"), q.Get("iss"))
	if err != nil {
		t.Fatal(err)
	}
	e.idp.Server.Close()
	_, err = e.flows.Redeem(ctx, p, e.cfg, q.Get("code"))
	wantReason(t, err, ReasonIssuerError)
}

func TestKeyRotation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.login(t); err != nil {
		t.Fatal(err)
	}
	// Rotated within the minute: the new key ID is unknown and the keys
	// are not reloaded yet.
	e.idp.RotateKeys(t, false)
	_, err := e.login(t)
	wantReason(t, err, ReasonTokenInvalid)
	if n := e.idp.Requests(oidctest.JWKSPath); n != 1 {
		t.Fatalf("%d key loads within a minute", n)
	}
	// A minute later, one reload picks the new key.
	e.clk.Advance(keyReloadInterval)
	if _, err := e.login(t); err != nil {
		t.Fatal(err)
	}
	if n := e.idp.Requests(oidctest.JWKSPath); n != 2 {
		t.Fatalf("%d key loads", n)
	}
	// Repeated unknown key IDs never reload more than once a minute.
	e.idp.SetBehavior(oidctest.Behavior{KID: "unknown"})
	for range 5 {
		_, err := e.login(t)
		wantReason(t, err, ReasonTokenInvalid)
	}
	if n := e.idp.Requests(oidctest.JWKSPath); n != 2 {
		t.Fatalf("%d key loads after unknown key IDs", n)
	}
	// Old keys kept published still verify after a rotation.
	e.idp.SetBehavior(oidctest.Behavior{})
	e.idp.RotateKeys(t, true)
	e.clk.Advance(keyReloadInterval)
	if _, err := e.login(t); err != nil {
		t.Fatal(err)
	}
}

func TestValidClaims(t *testing.T) {
	t.Parallel()
	c := NewClient(Options{Now: func() time.Time { return time.Unix(1_000_000, 0) }})
	now := time.Unix(1_000_000, 0)
	p := Pending{Issuer: "https://accounts.google.com", ClientID: "c", nonce: "n"}
	tok := &gooidc.IDToken{Issuer: "https://accounts.google.com", Audience: []string{"c"}, Expiry: now.Add(time.Minute), IssuedAt: now}
	cl := &claims{Subject: "s", Nonce: "n"}
	if !c.validClaims(tok, cl, p) {
		t.Fatal("valid claims refused")
	}
	// go-oidc tolerates a Google issuer without scheme: not here.
	google := *tok
	google.Issuer = "accounts.google.com"
	if c.validClaims(&google, cl, p) {
		t.Error("issuer without scheme accepted")
	}
	// A Microsoft Entra ID tenant issuer: tid must be its tenant ID.
	const guid = "0B0C1D2E-3F40-5A6B-7C8D-9E0F1A2B3C4D"
	entra := "https://login.microsoftonline.com/" + guid + "/v2.0"
	pe := Pending{Issuer: entra, ClientID: "c", nonce: "n"}
	te := *tok
	te.Issuer = entra
	for tid, want := range map[string]bool{
		strings.ToLower(guid):                  true,
		guid:                                   true,
		"":                                     false,
		"11111111-2222-3333-4444-555555555555": false,
	} {
		ce := &claims{Subject: "s", Nonce: "n", TID: tid}
		if got := c.validClaims(&te, ce, pe); got != want {
			t.Errorf("validClaims(entra, tid %q) = %v", tid, got)
		}
	}
	// Other issuers ignore tid.
	if !c.validClaims(tok, &claims{Subject: "s", Nonce: "n", TID: "whatever"}, p) {
		t.Error("tid checked for a non-Entra issuer")
	}
}

func TestEmail(t *testing.T) {
	t.Parallel()
	entra := "https://login.microsoftonline.com/0b0c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4d/v2.0"
	other := "https://idp.example.com"
	for _, tc := range []struct {
		issuer, verified, email, upn, want string
	}{
		{other, `true`, "A@B.example.com", "", "a@b.example.com"},
		{other, `"true"`, "a@b.example.com", "", "a@b.example.com"},
		{other, `false`, "a@b.example.com", "", ""},
		{other, `"false"`, "a@b.example.com", "", ""},
		{other, `1`, "a@b.example.com", "", ""},
		{other, ``, "a@b.example.com", "u@b.example.com", ""},
		{entra, ``, "a@b.example.com", "U@B.example.com", "u@b.example.com"},
		{entra, `null`, "", "u@b.example.com", "u@b.example.com"},
		{entra, `false`, "", "u@b.example.com", ""},
		{entra, `true`, "a@b.example.com", "u@b.example.com", "a@b.example.com"},
		{other, `true`, "not-an-address", "", ""},
		{other, `true`, "@b.example.com", "", ""},
		{other, `true`, "a@", "", ""},
		{other, `true`, "a@@b", "", ""},
		{other, `true`, strings.Repeat("a", 250) + "@b.example.com", "", ""},
		{other, `true`, "", "", ""},
	} {
		cl := &claims{Email: tc.email, PreferredUsername: tc.upn, EmailVerified: json.RawMessage(tc.verified)}
		if got := email(tc.issuer, cl); got != tc.want {
			t.Errorf("email(%s, verified %s, %q, %q) = %q, want %q", tc.issuer, tc.verified, tc.email, tc.upn, got, tc.want)
		}
	}
	// The idp claim of an Entra ID token: a guest (B2B) account of another
	// directory gets no address from preferred_username.
	for idp, want := range map[string]string{
		"":    "u@b.example.com",
		entra: "u@b.example.com",
		"https://sts.windows.net/0B0C1D2E-3F40-5A6B-7C8D-9E0F1A2B3C4D/": "u@b.example.com",
		"https://sts.windows.net/11111111-2222-3333-4444-555555555555/": "",
		"live.com":   "",
		"google.com": "",
		other:        "",
	} {
		cl := &claims{PreferredUsername: "u@b.example.com", IDP: idp}
		if got := email(entra, cl); got != want {
			t.Errorf("email(entra, idp %q) = %q, want %q", idp, got, want)
		}
	}
	// A verified email claim does not depend on idp.
	verified := &claims{Email: "a@b.example.com", EmailVerified: json.RawMessage(`true`), IDP: "live.com"}
	if got := email(entra, verified); got != "a@b.example.com" {
		t.Errorf("email(verified, guest) = %q", got)
	}
}

package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/oidc/oidctest"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	good := Config{
		TenantID: "t", Issuer: "https://idp.example.com", ClientID: "c", ClientSecret: "s",
		RedirectURL: "https://admin.example.com/api/v1/admin/auth/oidc/callback",
	}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Config){
		"issuer":         func(c *Config) { c.Issuer = "http://x.example.com" },
		"tenant":         func(c *Config) { c.TenantID = "" },
		"client":         func(c *Config) { c.ClientID = "" },
		"long client":    func(c *Config) { c.ClientID = strings.Repeat("c", 256) },
		"secret":         func(c *Config) { c.ClientSecret = "" },
		"long secret":    func(c *Config) { c.ClientSecret = strings.Repeat("s", 1025) },
		"redirect parse": func(c *Config) { c.RedirectURL = "https://[::1" },
		"redirect http":  func(c *Config) { c.RedirectURL = "http://admin.example.com/cb" },
		"redirect host":  func(c *Config) { c.RedirectURL = "https:///cb" },
		"redirect user":  func(c *Config) { c.RedirectURL = "https://u@admin.example.com/cb" },
		"redirect query": func(c *Config) { c.RedirectURL = "https://admin.example.com/cb?x=1" },
		"redirect frag":  func(c *Config) { c.RedirectURL = "https://admin.example.com/cb#x" },
	} {
		c := good
		edit(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := good
	c.Issuer = "https://login.microsoftonline.com/common/v2.0"
	if err := c.validate(); !errors.Is(err, ErrIssuerNotAllowed) {
		t.Errorf("multi-tenant issuer = %v", err)
	}
}

func TestBeginAuthorizationURL(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	authURL, cookie, err := e.flows.Begin(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != e.idp.Server.URL+oidctest.AuthorizePath {
		t.Fatalf("authorization URL %q", authURL)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != oidctest.ClientID || q.Get("redirect_uri") != e.cfg.RedirectURL ||
		q.Get("scope") != "openid email profile" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("parameters %v", q)
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if b, err := base64.RawURLEncoding.DecodeString(q.Get(k)); err != nil || len(b) != 32 {
			t.Errorf("%s is not 256 bits: %q", k, q.Get(k))
		}
	}
	if q.Has("client_secret") || strings.Contains(authURL, e.cfg.ClientSecret) {
		t.Error("client secret in the authorization URL")
	}
	id, _, ok := ParseCookie(cookie)
	if !ok || e.flows.Len() != 1 || e.flows.byID[id] == nil {
		t.Fatalf("cookie %q not kept", cookie)
	}
	fl := e.flows.byID[id]
	if fl.state != q.Get("state") || fl.pending.nonce != q.Get("nonce") || len(fl.pending.verifier) != 43 {
		t.Error("flow does not hold the parameters sent")
	}
}

func TestBeginFailures(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	bad := e.cfg
	bad.ClientSecret = ""
	if _, _, err := e.flows.Begin(context.Background(), bad); !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("Begin(bad config) = %v", err)
	}
	e.idp.SetBehavior(oidctest.Behavior{Status: map[string]int{oidctest.DiscoveryPath: 404}})
	_, _, err := e.flows.Begin(context.Background(), e.cfg)
	wantReason(t, err, ReasonIssuerError)
	e.idp.SetBehavior(oidctest.Behavior{})
	f := NewFlows(e.c, fakeKeys{macErr: crypto.ErrKeyUnavailable})
	if _, _, err := f.Begin(context.Background(), e.cfg); !errors.Is(err, crypto.ErrKeyUnavailable) || f.Len() != 0 {
		t.Errorf("Begin(MAC failure) = %v", err)
	}
}

func TestFlowSingleUse(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	authURL, cookie, err := e.flows.Begin(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	state := mustQuery(t, authURL).Get("state")
	p, err := e.flows.Consume(cookie, state, e.idp.Issuer())
	if err != nil || p.TenantID != "ten_a" || p.Issuer != e.idp.Issuer() || p.ClientID != oidctest.ClientID {
		t.Fatalf("Consume = %+v, %v", p, err)
	}
	_, err = e.flows.Consume(cookie, state, e.idp.Issuer())
	wantReason(t, err, ReasonStateInvalid)
}

// mustQuery returns the query of raw.
func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestConsumeFailures(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	begin := func() (string, string) {
		authURL, cookie, err := e.flows.Begin(context.Background(), e.cfg)
		if err != nil {
			t.Fatal(err)
		}
		return cookie, mustQuery(t, authURL).Get("state")
	}
	cookie, state := begin()
	for name, tc := range map[string][2]string{
		"empty state":   {cookie, ""},
		"long state":    {cookie, strings.Repeat("s", 257)},
		"bad cookie":    {"garbage", state},
		"other state":   {cookie, state + "x"},
		"tampered id":   {"of_AAAA" + cookie[7:], state},
		"tampered mac":  {cookie[:len(cookie)-2] + "AA", state},
		"unknown flow":  {"of_" + random() + "." + strings.SplitN(cookie, ".", 2)[1], state},
		"no flow found": {"", state},
	} {
		if e.flows.Bound(tc[0], tc[1]) {
			t.Errorf("%s: Bound", name)
		}
		if _, err := e.flows.Consume(tc[0], tc[1], ""); ReasonOf(err) != ReasonStateInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Bound neither consumes nor needs the flow.
	if !e.flows.Bound(cookie, state) || e.flows.Len() != 1 {
		t.Fatalf("Bound(genuine) = false or flow consumed (%d flows)", e.flows.Len())
	}
	// A rejected MAC does not burn the flow; the real one still works.
	if _, err := e.flows.Consume(cookie, state, e.idp.Issuer()); err != nil {
		t.Fatalf("genuine Consume after attacks: %v", err)
	}

	// Expired: still bound (the cookie is genuine), refused by Consume.
	cookie, state = begin()
	e.clk.Advance(FlowTTL)
	if !e.flows.Bound(cookie, state) {
		t.Error("Bound(expired genuine cookie) = false")
	}
	_, err := e.flows.Consume(cookie, state, e.idp.Issuer())
	wantReason(t, err, ReasonStateInvalid)

	// RFC 9207: another issuer, or none while the provider announces it.
	cookie, state = begin()
	_, err = e.flows.Consume(cookie, state, e.idp.Server.URL+"/other")
	wantReason(t, err, ReasonIssuerError)
	if _, err := e.flows.Consume(cookie, state, e.idp.Issuer()); ReasonOf(err) != ReasonStateInvalid {
		t.Errorf("flow reusable after an iss failure: %v", err)
	}
	cookie, state = begin()
	_, err = e.flows.Consume(cookie, state, "")
	wantReason(t, err, ReasonIssuerError)
}

func TestConsumeIssOptional(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.idp.SetBehavior(oidctest.Behavior{Discovery: func(d map[string]any) {
		delete(d, "authorization_response_iss_parameter_supported")
	}})
	authURL, cookie, err := e.flows.Begin(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.flows.Consume(cookie, mustQuery(t, authURL).Get("state"), ""); err != nil {
		t.Fatalf("Consume without iss = %v", err)
	}
}

func TestConsumeKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, cookie, err := e.flows.Begin(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	// A MAC failure is a state failure.
	f := &Flows{client: e.c, keys: fakeKeys{verifyErr: crypto.ErrKeyUnavailable}, max: MaxFlows, byID: e.flows.byID, order: e.flows.order}
	if f.Bound(cookie, "state") {
		t.Error("Bound with a MAC failure")
	}
	_, err = f.Consume(cookie, "state", "")
	wantReason(t, err, ReasonStateInvalid)
	// With a MAC accepted anyway, the state is still compared.
	f.keys = fakeKeys{verifyOK: true}
	_, err = f.Consume(cookie, "not-the-state", "")
	wantReason(t, err, ReasonStateInvalid)
	if e.flows.Len() != 0 {
		t.Error("flow kept after a failed Consume")
	}
}

func TestFlowsEvictionAndPurge(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.flows.max = 3
	var cookies []string
	for range 5 {
		_, c, err := e.flows.Begin(context.Background(), e.cfg)
		if err != nil {
			t.Fatal(err)
		}
		cookies = append(cookies, c)
		e.clk.Advance(time.Minute)
	}
	if e.flows.Len() != 3 {
		t.Fatalf("Len = %d", e.flows.Len())
	}
	for i, c := range cookies {
		id, _, _ := ParseCookie(c)
		if kept := e.flows.byID[id] != nil; kept != (i >= 2) {
			t.Errorf("flow %d kept = %v", i, kept)
		}
	}
	// The flows started at 2, 3 and 4 minutes expire at 12, 13 and 14; the
	// clock is at 5.
	e.clk.Advance(FlowTTL - 3*time.Minute + time.Second)
	e.flows.Purge()
	if e.flows.Len() != 2 {
		t.Fatalf("Len after the first expiry = %d", e.flows.Len())
	}
	e.clk.Advance(time.Hour)
	e.flows.Purge()
	if e.flows.Len() != 0 {
		t.Fatalf("Len after purge = %d", e.flows.Len())
	}
}

func TestParseCookie(t *testing.T) {
	t.Parallel()
	mac := base64.RawURLEncoding.EncodeToString(make([]byte, crypto.MACSize))
	for in, want := range map[string]bool{
		"of_abc." + mac:                        true,
		"of_abc" + mac:                         false,
		"xx_abc." + mac:                        false,
		"of_." + mac:                           false,
		"of_a+b." + mac:                        false,
		"of_abc." + mac + "=":                  false,
		"of_abc." + mac[:10]:                   false,
		"of_" + strings.Repeat("a", 300) + mac: false,
		"of_abc." + mac + "." + mac:            false,
	} {
		if _, _, ok := ParseCookie(in); ok != want {
			t.Errorf("ParseCookie(%q) = %v", in, ok)
		}
	}
}

func TestFlowCookies(t *testing.T) {
	t.Parallel()
	c := FlowCookie("of_x.y")
	if got := c.String(); got != "__Host-tt_oidc=of_x.y; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax" {
		t.Errorf("FlowCookie = %q", got)
	}
	clear := ClearFlowCookie()
	if got := clear.String(); got != "__Host-tt_oidc=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" {
		t.Errorf("ClearFlowCookie = %q", got)
	}
	if clear.SameSite != http.SameSiteLaxMode {
		t.Error("SameSite")
	}
}

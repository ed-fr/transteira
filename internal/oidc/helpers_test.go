package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/oidc/oidctest"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

// newClock returns a clock set to now.
func newClock() *clock { return &clock{t: time.Now()} }

// Now returns the time of the clock.
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock by d.
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// loopbackGuard is a guard refusing nothing, so that the fake provider on
// 127.0.0.1 can be reached.
func loopbackGuard() *netpolicy.DialGuard {
	return netpolicy.NewDialGuardPolicy("sso", netpolicy.Policy{}, nil)
}

// testKeys returns a random master key.
func testKeys(t testing.TB) *crypto.MasterKey {
	t.Helper()
	raw := make([]byte, crypto.MasterKeySize)
	_, _ = rand.Read(raw)
	k, err := crypto.ParseMasterKey([]byte(base64.StdEncoding.EncodeToString(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// env is a fake provider with a client and flows using it.
type env struct {
	idp   *oidctest.Provider
	clk   *clock
	c     *Client
	flows *Flows
	cfg   Config
}

// newEnv starts a fake provider and returns a client trusting it.
func newEnv(t testing.TB) *env {
	t.Helper()
	idp := oidctest.New(t)
	clk := newClock()
	idp.SetNow(clk.Now)
	c := NewClient(Options{Guard: loopbackGuard(), RootCAs: idp.CertPool(), Now: clk.Now, Timeout: 5 * time.Second})
	return &env{
		idp: idp, clk: clk, c: c, flows: NewFlows(c, testKeys(t)),
		cfg: Config{
			TenantID: "ten_a", Issuer: idp.Issuer(), ClientID: oidctest.ClientID,
			ClientSecret: idp.ClientSecret(), RedirectURL: "https://admin.example.com/api/v1/admin/auth/oidc/callback",
		},
	}
}

// login runs a whole flow up to the redeem and returns its outcome.
func (e *env) login(t testing.TB) (Identity, error) {
	t.Helper()
	authURL, cookie, err := e.flows.Begin(context.Background(), e.cfg)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	back, err := e.idp.Authorize(authURL)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	q := back.Query()
	p, err := e.flows.Consume(cookie, q.Get("state"), q.Get("iss"))
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	return e.flows.Redeem(context.Background(), p, e.cfg, q.Get("code"))
}

// wantReason fails unless err is an *Error of reason r.
func wantReason(t testing.TB, err error, r string) {
	t.Helper()
	e, ok := errors.AsType[*Error](err)
	if !ok || e.Reason != r {
		t.Fatalf("error = %v, want reason %s", err, r)
	}
}

// fakeKeys is a Keys whose answers are fixed.
type fakeKeys struct {
	macErr    error
	verifyOK  bool
	verifyErr error
}

// MAC returns a fixed MAC or macErr.
func (k fakeKeys) MAC(crypto.MACPurpose, ...[]byte) ([]byte, error) {
	return make([]byte, crypto.MACSize), k.macErr
}

// VerifyMAC returns verifyOK and verifyErr.
func (k fakeKeys) VerifyMAC(crypto.MACPurpose, []byte, ...[]byte) (bool, error) {
	return k.verifyOK, k.verifyErr
}

// resolver is a netpolicy.Resolver with fixed answers.
type resolver struct {
	addrs []netip.Addr
	err   error
}

// LookupNetIP returns the fixed answer.
func (r resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addrs, r.err
}

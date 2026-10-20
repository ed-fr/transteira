package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tenant"
)

// event is a recorded security event.
type event struct {
	kind   string
	ip     netip.Addr
	host   string
	tenant string
	scope  string
}

// fakeEvents records security events.
type fakeEvents struct {
	mu     sync.Mutex
	events []event
}

func (f *fakeEvents) UnknownFQDN(_ context.Context, ip netip.Addr, host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event{kind: "unknown_fqdn", ip: ip, host: host})
}

func (f *fakeEvents) RateLimited(_ context.Context, ip netip.Addr, tenantFQDN, scope string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event{kind: "rate_limited", ip: ip, tenant: tenantFQDN, scope: scope})
}

// fakeLimiter allows the first n calls per key.
type fakeLimiter struct {
	mu    sync.Mutex
	n     int
	calls map[string]int
	retry time.Duration
}

func newFakeLimiter(n int, retry time.Duration) *fakeLimiter {
	return &fakeLimiter{n: n, calls: map[string]int{}, retry: retry}
}

func (l *fakeLimiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls[key]++
	if l.calls[key] > l.n {
		return false, l.retry
	}
	return true, 0
}

// fakeResolver resolves hosts with tenant.NormalizeHost and a fixed map, or
// returns err when set.
type fakeResolver struct {
	tenants map[string]*tenant.Tenant
	err     error
	nilBoth bool
}

func (f *fakeResolver) Resolve(_ context.Context, host string) (*tenant.Tenant, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.nilBoth {
		return nil, nil
	}
	fqdn, err := tenant.NormalizeHost(host)
	if err != nil {
		return nil, err
	}
	t, ok := f.tenants[fqdn]
	if !ok {
		return nil, tenant.ErrUnknownTenant
	}
	return t, nil
}

// okHandler answers 204.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
})

// decodeProblem decodes a problem response and checks its content type.
func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) problem.Problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != problem.ContentType {
		t.Fatalf("Content-Type = %q, want %q", ct, problem.ContentType)
	}
	var p problem.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v (body %q)", err, rec.Body.String())
	}
	return p
}

// withIP returns r carrying ip as client IP.
func withIP(r *http.Request, ip string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientIPKey, netip.MustParseAddr(ip)))
}

// withRID returns r carrying rid as request ID.
func withRID(r *http.Request, rid string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestIDKey, rid))
}

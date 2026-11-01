package httpserver

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/metrics"
	"github.com/ed-fr/transteira/internal/tenant"
)

// tlsAskPeer is the address of the reverse proxy in these tests.
const tlsAskPeer = "172.30.0.10"

// fakeTLSAskCounter records the results counted by the handler.
type fakeTLSAskCounter struct {
	mu   sync.Mutex
	seen map[string]int
}

func (c *fakeTLSAskCounter) TLSAsk(result string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]int{}
	}
	c.seen[result]++
}

func (c *fakeTLSAskCounter) count(result string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen[result]
}

// fqdnLookup is a tenant.Lookup serving a fixed set of tenants by FQDN.
type fqdnLookup struct {
	tenants map[string]*tenant.Tenant
	err     error
}

func (l fqdnLookup) TenantByFQDN(_ context.Context, fqdn string) (*tenant.Tenant, error) {
	if l.err != nil {
		return nil, l.err
	}
	if t, ok := l.tenants[fqdn]; ok {
		return t, nil
	}
	return nil, tenant.ErrUnknownTenant
}

// tlsAskEnv is a server with /tls/ask enabled for tlsAskPeer, a real
// resolver over a tenant in setup (hostA) and a lookup that would also
// answer for the admin host.
func tlsAskEnv(t *testing.T, lookupErr error, opts ...Option) (*env, *fakeTLSAskCounter) {
	t.Helper()
	counter := &fakeTLSAskCounter{}
	lookup := fqdnLookup{err: lookupErr, tenants: map[string]*tenant.Tenant{
		hostA:     {ID: "ten_a", FQDN: hostA, SetupState: tenant.SetupStateSetup},
		hostAdmin: {ID: "ten_admin", FQDN: hostAdmin, SetupState: tenant.SetupStateActive},
	}}
	e := newEnv(t, envConfig{
		resolver:      tenant.NewResolver(lookup),
		tlsAskAllowed: []netip.Prefix{netip.MustParsePrefix(tlsAskPeer + "/32")},
		tlsAsk:        counter,
		opts:          opts,
	})
	return e, counter
}

// ask sends a /tls/ask request with query from peer (host:port) with the
// given headers (name, value pairs).
func (e *env) ask(t *testing.T, method, query, peer string, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, TLSAskPath+query, nil)
	req.Host = hostUnknown
	req.RemoteAddr = peer
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

// expectEmpty checks an empty answer with status and the headers shared by
// 200 and 404.
func expectEmpty(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status || rec.Body.Len() != 0 {
		t.Fatalf("answer = %d %q, want %d with an empty body", rec.Code, rec.Body.String(), status)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "0" {
		t.Errorf("Content-Length = %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "" {
		t.Errorf("Content-Type = %q", got)
	}
	if rec.Header().Get("X-Content-Type-Options") == "" {
		t.Error("security headers missing")
	}
}

func TestTLSAskDisabled(t *testing.T) {
	t.Parallel()
	counter := &fakeTLSAskCounter{}
	e := newEnv(t, envConfig{tlsAsk: counter})
	for _, host := range []string{hostUnknown, hostA, hostAdmin} {
		rec := e.do(t, http.MethodGet, TLSAskPath+"?domain="+hostA, host, nil)
		expectEmpty(t, rec, http.StatusNotFound)
	}
	if got := counter.count(metrics.TLSAskRefused); got != 3 {
		t.Fatalf("refused = %d, want 3", got)
	}
	// A nil counter is accepted.
	e = newEnv(t, envConfig{})
	expectEmpty(t, e.do(t, http.MethodGet, TLSAskPath+"?domain="+hostA, hostA, nil), http.StatusNotFound)
}

func TestTLSAskAllowed(t *testing.T) {
	t.Parallel()
	e, counter := tlsAskEnv(t, nil)
	e.maintenance.active.Store(true) // still answered in maintenance mode
	peers := []string{tlsAskPeer + ":40000", "[::ffff:" + tlsAskPeer + "]:40000"}
	queries := []string{
		"?domain=" + hostA,
		"?domain=" + strings.ToUpper(hostA),
		"?domain=" + hostA + ".",
	}
	for _, peer := range peers {
		for _, q := range queries {
			for _, m := range []string{http.MethodGet, http.MethodHead} {
				expectEmpty(t, e.ask(t, m, q, peer), http.StatusOK)
			}
		}
	}
	if got, want := counter.count(metrics.TLSAskAllowed), len(peers)*len(queries)*2; got != want {
		t.Fatalf("allowed = %d, want %d", got, want)
	}
	if log := e.secLog.String(); log != "" {
		t.Fatalf("security log = %q", log)
	}
}

func TestTLSAskUnknown(t *testing.T) {
	t.Parallel()
	e, counter := tlsAskEnv(t, nil)
	peer := tlsAskPeer + ":40000"
	queries := []string{
		"?domain=" + hostUnknown,
		"?domain=" + hostAdmin, // admin host, even if the lookup knew it
		"?domain=" + strings.ToUpper(hostAdmin) + ".",
		"",
		"?domain=",
		"?domain=" + hostA + "&domain=" + hostA,
		"?domain=" + hostA + ":443",
		"?domain=%5B" + hostA + "%5D",
		"?domain=bad_host..example.com",
		"?domain=" + strings.Repeat("a", 254),
	}
	for _, q := range queries {
		expectEmpty(t, e.ask(t, http.MethodGet, q, peer), http.StatusNotFound)
	}
	if got := counter.count(metrics.TLSAskUnknown); got != len(queries) {
		t.Fatalf("unknown = %d, want %d", got, len(queries))
	}
	if log := e.secLog.String(); log != "" {
		t.Fatalf("security log = %q (unknown names are not logged)", log)
	}
}

func TestTLSAskRefused(t *testing.T) {
	t.Parallel()
	e, counter := tlsAskEnv(t, nil)
	q := "?domain=" + hostA
	ok := tlsAskPeer + ":40000"
	cases := []struct {
		name, method, peer string
		hdr                []string
	}{
		{"peer outside the list", http.MethodGet, "172.30.0.11:40000", nil},
		{"unparsable peer", http.MethodGet, "@", nil},
		{"X-Forwarded-For", http.MethodGet, ok, []string{"X-Forwarded-For", tlsAskPeer}},
		{"X-Real-IP", http.MethodGet, ok, []string{"X-Real-IP", tlsAskPeer}},
		{"Forwarded", http.MethodGet, ok, []string{"Forwarded", "for=" + tlsAskPeer}},
		{"X-Forwarded-Host", http.MethodGet, ok, []string{"X-Forwarded-Host", hostA}},
		{"X-Forwarded-Proto", http.MethodGet, ok, []string{"X-Forwarded-Proto", "https"}},
		{"Via", http.MethodGet, ok, []string{"Via", "1.1 caddy"}},
		{"empty relay header", http.MethodGet, ok, []string{"X-Forwarded-For", ""}},
		{"POST", http.MethodPost, ok, nil},
		{"OPTIONS", http.MethodOptions, ok, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expectEmpty(t, e.ask(t, c.method, q, c.peer, c.hdr...), http.StatusNotFound)
		})
	}
	if got := counter.count(metrics.TLSAskRefused); got != len(cases) {
		t.Fatalf("refused = %d, want %d", got, len(cases))
	}
	if counter.count(metrics.TLSAskAllowed) != 0 {
		t.Fatal("a refused request was looked up")
	}
	if log := e.secLog.String(); log != "" {
		t.Fatalf("security log = %q", log)
	}
}

// TestTLSAskSameHeaders checks that 200 and 404 cannot be told apart by
// their headers.
func TestTLSAskSameHeaders(t *testing.T) {
	t.Parallel()
	e, _ := tlsAskEnv(t, nil)
	peer := tlsAskPeer + ":40000"
	yes := e.ask(t, http.MethodGet, "?domain="+hostA, peer)
	no := e.ask(t, http.MethodGet, "?domain="+hostUnknown, peer)
	refused := e.ask(t, http.MethodGet, "?domain="+hostA, "192.0.2.1:1")
	names := func(h http.Header) []string {
		h = h.Clone()
		h.Del("X-Request-Id") // differs per request
		return slices.Sorted(maps.Keys(h))
	}
	for _, rec := range []*httptest.ResponseRecorder{no, refused} {
		if !slices.Equal(names(yes.Header()), names(rec.Header())) {
			t.Fatalf("headers differ: %v and %v", names(yes.Header()), names(rec.Header()))
		}
		for _, k := range names(yes.Header()) {
			if yes.Header().Get(k) != rec.Header().Get(k) {
				t.Errorf("%s = %q and %q", k, yes.Header().Get(k), rec.Header().Get(k))
			}
		}
	}
}

// allowLimiter allows every request.
type allowLimiter struct{}

func (allowLimiter) Allow(string) (bool, time.Duration) { return true, 0 }

// keyLimiter denies every request and records the keys it was asked for.
type keyLimiter struct {
	mu   sync.Mutex
	keys []string
}

func (l *keyLimiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, key)
	return false, 3 * time.Second
}

// TestTLSAskRateLimited checks that /tls/ask escapes the global limit and
// has its own, keyed by the direct peer and applied after the peer check,
// without a security event.
func TestTLSAskRateLimited(t *testing.T) {
	t.Parallel()
	e, _ := tlsAskEnv(t, nil, WithGlobalLimiter(denyLimiter{}))
	expectEmpty(t, e.ask(t, http.MethodGet, "?domain="+hostA, tlsAskPeer+":40000"), http.StatusOK)

	limiter := &keyLimiter{}
	e, counter := tlsAskEnv(t, nil, withTLSAskLimiter(limiter))
	expectEmpty(t, e.ask(t, http.MethodGet, "?domain="+hostA, "192.0.2.1:1"), http.StatusNotFound)
	rec := e.ask(t, http.MethodGet, "?domain="+hostA, "[::ffff:"+tlsAskPeer+"]:40000")
	decodeProblem(t, rec, http.StatusTooManyRequests, problem.CodeRateLimited)
	if rec.Header().Get("Retry-After") != "3" {
		t.Errorf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if !slices.Equal(limiter.keys, []string{"tlsask:" + tlsAskPeer}) {
		t.Fatalf("limiter keys = %v", limiter.keys)
	}
	if counter.count(metrics.TLSAskAllowed) != 0 {
		t.Fatal("a throttled request was answered")
	}
	if log := e.secLog.String(); log != "" {
		t.Fatalf("security log = %q", log)
	}
}

func TestTLSAskResolverError(t *testing.T) {
	t.Parallel()
	e, counter := tlsAskEnv(t, errors.New("database down"))
	rec := e.ask(t, http.MethodGet, "?domain="+hostA, tlsAskPeer+":40000")
	decodeProblem(t, rec, http.StatusInternalServerError, problem.CodeInternalError)
	if !strings.Contains(e.appLog.String(), "database down") {
		t.Fatalf("app log = %q", e.appLog.String())
	}
	if counter.count(metrics.TLSAskAllowed)+counter.count(metrics.TLSAskUnknown) != 0 {
		t.Fatal("a failed lookup was counted")
	}
}

// FuzzTLSAskDomain checks that any raw query gets an empty 200 or 404 (or
// the 400 of an unparsable request line, never reaching the handler), and
// 200 only for the FQDN of the tenant, whatever its case or final dot.
func FuzzTLSAskDomain(f *testing.F) {
	for _, s := range []string{hostA, hostAdmin, hostUnknown, strings.ToUpper(hostA) + ".", hostA + ":443", "", "%00", "a..b", strings.Repeat("a.", 130)} {
		f.Add(s)
	}
	e, _ := tlsAskEnv(&testing.T{}, nil, withTLSAskLimiter(allowLimiter{}))
	f.Fuzz(func(t *testing.T, domain string) {
		req := httptest.NewRequest(http.MethodGet, TLSAskPath, nil)
		req.URL.RawQuery = "domain=" + domain
		req.Host = hostUnknown
		req.RemoteAddr = tlsAskPeer + ":40000"
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		if rec.Body.Len() != 0 {
			t.Fatalf("%q: body %q", domain, rec.Body.String())
		}
		switch rec.Code {
		case http.StatusOK:
			values := req.URL.Query()["domain"]
			n, err := tenant.NormalizeHost(values[0])
			if len(values) != 1 || err != nil || n != hostA {
				t.Fatalf("%q: 200 for %v", domain, values)
			}
		case http.StatusNotFound:
		default:
			t.Fatalf("%q: status %d", domain, rec.Code)
		}
	})
}

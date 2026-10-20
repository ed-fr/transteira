package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestRateLimit(t *testing.T) {
	ev := &fakeEvents{}
	lim := newFakeLimiter(2, 1500*time.Millisecond)
	h := RateLimit(lim, ev, "global")(okHandler)

	serve := func(ip string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, withRID(withIP(httptest.NewRequest(http.MethodGet, "/", nil), ip), "req_1"))
		return rec
	}
	for range 2 {
		if rec := serve("192.0.2.1"); rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
	}
	rec := serve("192.0.2.1")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2", got)
	}
	p := decodeProblem(t, rec)
	if p.Code != problem.CodeRateLimited || p.Instance != "req_1" {
		t.Fatalf("problem = %+v", p)
	}
	if rec := serve("192.0.2.2"); rec.Code != http.StatusNoContent {
		t.Fatalf("other IP limited: %d", rec.Code)
	}
	want := event{kind: "rate_limited", ip: netip.MustParseAddr("192.0.2.1"), scope: "global"}
	if len(ev.events) != 1 || ev.events[0] != want {
		t.Fatalf("events = %+v, want [%+v]", ev.events, want)
	}
}

func TestRateLimitTenantAndNilEvents(t *testing.T) {
	lim := newFakeLimiter(0, time.Second)
	ev := &fakeEvents{}
	req := withIP(httptest.NewRequest(http.MethodGet, "/", nil), "192.0.2.1")
	req = req.WithContext(tenant.WithTenant(req.Context(), &tenant.Tenant{FQDN: "transfer.example.com"}))

	rec := httptest.NewRecorder()
	RateLimit(lim, ev, "deposit")(okHandler).ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || len(ev.events) != 1 || ev.events[0].tenant != "transfer.example.com" {
		t.Fatalf("status %d, events %+v", rec.Code, ev.events)
	}

	rec = httptest.NewRecorder()
	RateLimit(lim, nil, "deposit")(okHandler).ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRateLimitNoClientIP(t *testing.T) {
	lim := newFakeLimiter(1, time.Second)
	RateLimit(lim, nil, "global")(okHandler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if lim.calls["invalid"] != 1 {
		t.Fatalf("calls = %v", lim.calls)
	}
}

func TestRateLimitNilLimiterPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic")
		}
	}()
	RateLimit(nil, nil, "global")
}

func TestRateLimitKey(t *testing.T) {
	tests := []struct {
		ip   netip.Addr
		want string
	}{
		{netip.Addr{}, "invalid"},
		{netip.MustParseAddr("192.0.2.1"), "192.0.2.1"},
		{netip.MustParseAddr("::ffff:192.0.2.1"), "192.0.2.1"},
		{netip.MustParseAddr("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "2001:db8:1:2::/64"},
		{netip.MustParseAddr("2001:db8:1:2::1"), "2001:db8:1:2::/64"},
		{netip.MustParseAddr("fe80::1%eth0"), "fe80::/64"},
		{netip.MustParseAddr("::1"), "::/64"},
	}
	for _, tc := range tests {
		if got := RateLimitKey(tc.ip); got != tc.want {
			t.Errorf("RateLimitKey(%v) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestRateLimitIPv6SharesPrefix(t *testing.T) {
	lim := newFakeLimiter(1, time.Second)
	h := RateLimit(lim, nil, "global")(okHandler)
	codes := make([]int, 0, 3)
	for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:3::1"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, withIP(httptest.NewRequest(http.MethodGet, "/", nil), ip))
		codes = append(codes, rec.Code)
	}
	if codes[0] != 204 || codes[1] != 429 || codes[2] != 204 {
		t.Fatalf("codes = %v, want [204 429 204]", codes)
	}
}

// fakeClock is a manually advanced clock.
type fakeClock struct{ now time.Time }

func newFakeClock() *fakeClock { return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func TestRateLimitEventThrottle(t *testing.T) {
	ev := &fakeEvents{}
	clock := newFakeClock()
	h := rateLimit(newFakeLimiter(0, time.Second), ev, "global", clock.Now)(okHandler)
	serve := func(ip string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, withIP(httptest.NewRequest(http.MethodGet, "/", nil), ip))
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" {
			t.Fatalf("status = %d, Retry-After = %q: responses must not be throttled", rec.Code, rec.Header().Get("Retry-After"))
		}
	}
	for range 50 {
		serve("192.0.2.1")
	}
	if len(ev.events) != 1 {
		t.Fatalf("events after flood = %d, want 1", len(ev.events))
	}
	serve("2001:db8:1:2::1")
	serve("2001:db8:1:2::2") // same /64: same key, throttled
	if len(ev.events) != 2 {
		t.Fatalf("events = %+v, want one per key", ev.events)
	}
	clock.Advance(SecurityEventInterval - time.Millisecond)
	serve("192.0.2.1")
	if len(ev.events) != 2 {
		t.Fatalf("event written before the interval elapsed: %+v", ev.events)
	}
	clock.Advance(time.Millisecond)
	serve("192.0.2.1")
	serve("192.0.2.1")
	if len(ev.events) != 3 || ev.events[2].ip != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("events = %+v, want a new event after the interval", ev.events)
	}
	if SecurityEventInterval != 10*time.Second {
		t.Fatalf("SecurityEventInterval = %v", SecurityEventInterval)
	}
}

func TestRateLimitThrottlePerScope(t *testing.T) {
	ev := &fakeEvents{}
	clock := newFakeClock()
	throttle := newEventThrottle(clock.Now)
	lim := newFakeLimiter(0, time.Second)
	for _, scope := range []string{"global", "deposit", "global"} {
		allow(httptest.NewRecorder(), withIP(httptest.NewRequest(http.MethodGet, "/", nil), "192.0.2.1"), lim, ev, throttle, scope)
	}
	if len(ev.events) != 2 || ev.events[0].scope != "global" || ev.events[1].scope != "deposit" {
		t.Fatalf("events = %+v, want one per scope", ev.events)
	}
}

func TestRateLimitZeroAddrSharedBucket(t *testing.T) {
	ev := &fakeEvents{}
	lim := newFakeLimiter(1, time.Second)
	h := RealIP(testTrusted)(RateLimit(lim, ev, "global")(okHandler))
	codes := make([]int, 0, 3)
	for _, xff := range []string{"garbage", "", "192.0.2.60, garbage"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.2:443" // trusted proxy, no usable forwarded address
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[0] != 204 || codes[1] != 429 || codes[2] != 429 || lim.calls["invalid"] != 3 || len(lim.calls) != 1 {
		t.Fatalf("codes = %v, calls = %v", codes, lim.calls)
	}
	if len(ev.events) != 1 || ev.events[0].ip.IsValid() {
		t.Fatalf("events = %+v, want one event with the zero Addr", ev.events)
	}
}

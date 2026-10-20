package middleware

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tenant"
)

func testResolver() *fakeResolver {
	return &fakeResolver{tenants: map[string]*tenant.Tenant{
		"transfer.entity-a.example.com": {ID: "a", FQDN: "transfer.entity-a.example.com"},
	}}
}

func TestTenant(t *testing.T) {
	errDB := errors.New("database is down: secret dsn")
	tests := []struct {
		name       string
		resolver   *fakeResolver
		host       string
		cancel     bool
		wantStatus int
		wantCode   problem.Code
		wantEvent  string
		wantLog    string
	}{
		{"known", testResolver(), "transfer.entity-a.example.com", false, http.StatusNoContent, "", "", ""},
		{"known with port and case", testResolver(), "Transfer.Entity-A.example.com:443", false, http.StatusNoContent, "", "", ""},
		{"unknown", testResolver(), "transfer.entity-b.example.com", false, http.StatusMisdirectedRequest, problem.CodeUnknownTenant, "unknown_fqdn", ""},
		{"invalid", testResolver(), "bad host\r\n", false, http.StatusMisdirectedRequest, problem.CodeUnknownTenant, "unknown_fqdn", ""},
		{"empty", testResolver(), "", false, http.StatusMisdirectedRequest, problem.CodeUnknownTenant, "unknown_fqdn", ""},
		{"resolver error", &fakeResolver{err: errDB}, "transfer.entity-a.example.com", false, http.StatusInternalServerError, problem.CodeInternalError, "", "ERROR"},
		{"nil tenant nil error", &fakeResolver{nilBoth: true}, "transfer.entity-a.example.com", false, http.StatusInternalServerError, problem.CodeInternalError, "", "ERROR"},
		{"client gone", &fakeResolver{err: fmt.Errorf("lookup: %w", context.Canceled)}, "transfer.entity-a.example.com", true, http.StatusInternalServerError, problem.CodeInternalError, "", "DEBUG"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := &fakeEvents{}
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			var got *tenant.Tenant
			h := Tenant(tc.resolver, ev, nil, logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, _ = tenant.FromContext(r.Context())
				w.WriteHeader(http.StatusNoContent)
			}))
			req := withRID(withIP(httptest.NewRequest(http.MethodGet, "/", nil), "192.0.2.1"), "req_t")
			req.Host = tc.host
			req.Header.Set("X-Forwarded-Host", "transfer.entity-a.example.com")
			if tc.cancel {
				ctx, cancel := context.WithCancel(req.Context())
				cancel()
				req = req.WithContext(ctx)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantCode == "" {
				if got == nil || got.FQDN != "transfer.entity-a.example.com" {
					t.Fatalf("tenant in context = %+v", got)
				}
			} else {
				p := decodeProblem(t, rec)
				if p.Code != tc.wantCode || p.Instance != "req_t" || p.Detail != "" {
					t.Fatalf("problem = %+v", p)
				}
				if strings.Contains(rec.Body.String(), "secret") {
					t.Fatal("resolver error leaked to the client")
				}
			}
			if tc.wantEvent == "" {
				if len(ev.events) != 0 {
					t.Fatalf("unexpected events %+v", ev.events)
				}
			} else {
				want := event{kind: tc.wantEvent, ip: netip.MustParseAddr("192.0.2.1"), host: tc.host}
				if len(ev.events) != 1 || ev.events[0] != want {
					t.Fatalf("events = %+v, want [%+v]", ev.events, want)
				}
			}
			if tc.wantLog != "" && !strings.Contains(logs.String(), "level="+tc.wantLog) {
				t.Fatalf("log = %q, want level %s", logs.String(), tc.wantLog)
			}
		})
	}
}

func TestTenantUnknownHostLimiter(t *testing.T) {
	ev := &fakeEvents{}
	lim := newFakeLimiter(2, 10*time.Second)
	h := Tenant(testResolver(), ev, lim, nil)(okHandler)
	serve := func(host string) int {
		req := withIP(httptest.NewRequest(http.MethodGet, "/", nil), "192.0.2.1")
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	codes := []int{
		serve("a.example.com"), serve("b.example.com"), serve("c.example.com"),
		serve("transfer.entity-a.example.com"), // known hosts never consume the limiter
	}
	want := []int{421, 421, 429, 204}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("codes = %v, want %v", codes, want)
		}
	}
	if len(ev.events) != 3 || ev.events[2].kind != "rate_limited" || ev.events[2].scope != ScopeUnknownHost {
		t.Fatalf("events = %+v", ev.events)
	}
	if lim.calls["192.0.2.1"] != 3 {
		t.Fatalf("limiter calls = %v", lim.calls)
	}
}

func TestTenantPanicsOnNil(t *testing.T) {
	for _, tc := range []struct {
		r TenantResolver
		e SecurityEvents
	}{{nil, &fakeEvents{}}, {testResolver(), nil}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("expected a panic")
				}
			}()
			Tenant(tc.r, tc.e, nil, nil)
		}()
	}
}

func TestTruncateHost(t *testing.T) {
	short := "transfer.example.com"
	if truncateHost(short) != short {
		t.Fatal("short host changed")
	}
	long := strings.Repeat("a", maxLoggedHost+10)
	if got := truncateHost(long); len(got) != maxLoggedHost {
		t.Fatalf("len = %d", len(got))
	}
	// A multi-byte rune straddling the cut is dropped entirely.
	multi := strings.Repeat("a", maxLoggedHost-1) + "é" + "zzz"
	got := truncateHost(multi)
	if len(got) != maxLoggedHost-1 || !utf8.ValidString(got) {
		t.Fatalf("got %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
}

func FuzzTenantHost(f *testing.F) {
	for _, s := range []string{
		"transfer.entity-a.example.com", "TRANSFER.ENTITY-A.EXAMPLE.COM.:8443", "", "[::1]:80",
		"xn--bcher-kva.example", "a\r\nb", strings.Repeat("é", 200), "transfer.entity-a.example.com:99999",
	} {
		f.Add(s)
	}
	resolver := testResolver()
	f.Fuzz(func(t *testing.T, host string) {
		ev := &fakeEvents{}
		h := Tenant(resolver, ev, nil, nil)(okHandler)
		req := withIP(httptest.NewRequest(http.MethodGet, "/", nil), "192.0.2.1")
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusNoContent:
			if len(ev.events) != 0 {
				t.Fatalf("event on success: %+v", ev.events)
			}
		case http.StatusMisdirectedRequest:
			if len(ev.events) != 1 {
				t.Fatalf("events = %+v", ev.events)
			}
			logged := ev.events[0].host
			if len(logged) > maxLoggedHost || !strings.HasPrefix(host, logged) {
				t.Fatalf("logged host %q is not a bounded prefix of %q", logged, host)
			}
			if utf8.ValidString(host) && !utf8.ValidString(logged) {
				t.Fatalf("truncation broke UTF-8: %q", logged)
			}
		default:
			t.Fatalf("status = %d", rec.Code)
		}
	})
}

func TestTenantUnknownHostEventThrottle(t *testing.T) {
	ev := &fakeEvents{}
	clock := newFakeClock()
	lim := newFakeLimiter(3, 10*time.Second)
	h := tenantMiddleware(testResolver(), ev, lim, nil, clock.Now)(okHandler)
	serve := func(host string) int {
		req := withIP(httptest.NewRequest(http.MethodGet, "/", nil), "192.0.2.1")
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// Every 421 up to the limit is logged, so that scans are visible.
	for i := range 3 {
		if code := serve(fmt.Sprintf("scan-%d.example.com", i)); code != http.StatusMisdirectedRequest {
			t.Fatalf("code = %d, want 421", code)
		}
	}
	// Once refused with 429, a flood writes a single event per interval.
	for i := range 100 {
		if code := serve(fmt.Sprintf("flood-%d.example.com", i)); code != http.StatusTooManyRequests {
			t.Fatalf("code = %d, want 429", code)
		}
	}
	kinds := func() (unknown, limited int) {
		for _, e := range ev.events {
			switch e.kind {
			case "unknown_fqdn":
				unknown++
			case "rate_limited":
				limited++
			}
		}
		return unknown, limited
	}
	if u, l := kinds(); u != 3 || l != 1 {
		t.Fatalf("unknown_fqdn = %d, rate_limited = %d; want 3, 1", u, l)
	}
	clock.Advance(SecurityEventInterval)
	serve("again.example.com")
	if u, l := kinds(); u != 3 || l != 2 {
		t.Fatalf("after interval: unknown_fqdn = %d, rate_limited = %d; want 3, 2", u, l)
	}
}

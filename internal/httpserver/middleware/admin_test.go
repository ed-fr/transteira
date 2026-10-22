package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// adminEcho answers 200 with the admin session email and token from the
// context; 418 when the admin session is missing or a deposit session is
// present instead.
var adminEcho = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	s, ok := AdminSessionFrom[fakeSession](r.Context())
	tok, tokOK := AdminSessionToken(r.Context())
	_, deposit := SessionToken(r.Context())
	if !ok || !tokOK || deposit {
		w.WriteHeader(http.StatusTeapot)
		return
	}
	_, _ = w.Write([]byte(s.email + " " + tok))
})

func TestAdminSession(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		cookie string
		err    error
		status int
		code   problem.Code
		clears bool
	}{
		{name: "no cookie", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{name: "empty cookie", cookie: AdminCookie + "=", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{name: "deposit cookie only", cookie: DepositCookie + "=good", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{name: "unknown token", cookie: AdminCookie + "=bad", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated, clears: true},
		{name: "resolver failure", cookie: AdminCookie + "=good", err: errors.New("db down"), status: http.StatusInternalServerError, code: problem.CodeInternalError},
		{name: "valid", cookie: AdminCookie + "=good", status: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := AdminSession(&fakeSessions{err: tt.err}, always, nil)(adminEcho)
			req := withRID(httptest.NewRequest(http.MethodGet, "/api/v1/admin/me", nil), "req_1")
			if tt.cookie != "" {
				req.Header.Set("Cookie", tt.cookie)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.status, rec.Body)
			}
			if tt.code != "" {
				if p := decodeProblem(t, rec); p.Code != tt.code {
					t.Errorf("problem = %+v, want %s", p, tt.code)
				}
			} else if rec.Body.String() != "alice@entity-a.example.com good" {
				t.Errorf("body = %q", rec.Body)
			}
			got := rec.Header().Get("Set-Cookie")
			if want := ExpiredCookie(AdminCookie); (got == want) != tt.clears || (!tt.clears && got != "") {
				t.Errorf("Set-Cookie = %q, want cleared=%v", got, tt.clears)
			}
		})
	}
	// Not required: passes untouched.
	h := AdminSession(&fakeSessions{}, never, nil)(adminEcho)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("not required: %d", rec.Code)
	}
}

func TestExpiredCookie(t *testing.T) {
	t.Parallel()
	got := ExpiredCookie(AdminCookie)
	want := "__Host-tt_admin=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
	if got != want {
		t.Errorf("ExpiredCookie = %q, want %q", got, want)
	}
}

func TestAdminSessionAccessors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, ok := AdminSessionFrom[fakeSession](ctx); ok {
		t.Error("AdminSessionFrom on an empty context reported a session")
	}
	if tok, ok := AdminSessionToken(ctx); ok || tok != "" {
		t.Errorf("AdminSessionToken = %q, %v", tok, ok)
	}
	// A deposit session is never returned as an admin session, nor the
	// reverse.
	ctx = context.WithValue(ctx, sessionKey{}, sessionValue{session: fakeSession{}, token: "good"})
	if _, ok := AdminSessionFrom[fakeSession](ctx); ok {
		t.Error("AdminSessionFrom returned the deposit session")
	}
	ctx = context.WithValue(context.Background(), adminSessionKey{}, sessionValue{session: fakeSession{}, token: "good"})
	if _, ok := SessionFrom[fakeSession](ctx); ok {
		t.Error("SessionFrom returned the admin session")
	}
	if tok, ok := AdminSessionToken(ctx); !ok || tok != "good" {
		t.Errorf("AdminSessionToken = %q, %v", tok, ok)
	}
}

func TestAdminCSRF(t *testing.T) {
	t.Parallel()
	const host = "admin.transfer.example.com"
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	tests := []struct {
		name    string
		method  string
		cookie  string
		header  http.Header
		pass    bool
		depOnly bool
	}{
		{name: "safe method", method: http.MethodGet, cookie: "good", pass: true},
		{name: "valid", method: http.MethodPost, cookie: "good", header: http.Header{
			"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://" + host}, "Sec-Fetch-Site": {"same-origin"},
		}, pass: true},
		{name: "missing token", method: http.MethodPost, cookie: "good"},
		{name: "wrong token", method: http.MethodDelete, cookie: "good", header: http.Header{"X-Csrf-Token": {"csrf_bad"}}},
		{name: "tenant origin", method: http.MethodPost, cookie: "good", header: http.Header{
			"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://transfer.entity-a.example.com"},
		}},
		// The token of a deposit session does not satisfy the admin check.
		{name: "deposit session only", method: http.MethodPost, depOnly: true, header: http.Header{"X-Csrf-Token": {"csrf_good"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sessions := &fakeSessions{}
			h := AdminCSRF(sessions, always)(ok)
			if tt.cookie != "" {
				h = AdminSession(sessions, always, nil)(h)
			}
			req := httptest.NewRequest(tt.method, "/api/v1/admin/auth/logout", nil)
			req.Host = host
			for k, v := range tt.header {
				req.Header[k] = v
			}
			if tt.cookie != "" {
				req.Header.Set("Cookie", AdminCookie+"="+tt.cookie)
			}
			if tt.depOnly {
				req = req.WithContext(context.WithValue(req.Context(), sessionKey{}, sessionValue{session: fakeSession{}, token: "good"}))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if tt.pass != (rec.Code == http.StatusNoContent) {
				t.Fatalf("status = %d (body %s), want pass=%v", rec.Code, rec.Body, tt.pass)
			}
			if !tt.pass {
				if p := decodeProblem(t, rec); p.Code != problem.CodeCSRFInvalid {
					t.Errorf("problem %+v", p)
				}
			}
		})
	}
}

func TestRateLimitIf(t *testing.T) {
	t.Parallel()
	ev := &fakeEvents{}
	limiter := newFakeLimiter(1, 2*time.Second)
	onlyPost := func(r *http.Request) bool { return r.Method == http.MethodPost }
	h := RateLimitIf(limiter, ev, "admin_auth", onlyPost)(okHandler)
	ip := netip.MustParseAddr("192.0.2.7")
	do := func(method string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, withIP(httptest.NewRequest(method, "/api/v1/admin/auth/login", nil), ip.String()))
		return rec
	}
	if rec := do(http.MethodPost); rec.Code != http.StatusNoContent {
		t.Fatalf("first POST %d", rec.Code)
	}
	if rec := do(http.MethodPost); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("second POST %d %v", rec.Code, rec.Header())
	}
	// Requests the predicate excludes neither consume nor get refused.
	for range 3 {
		if rec := do(http.MethodGet); rec.Code != http.StatusNoContent {
			t.Fatalf("GET %d", rec.Code)
		}
	}
	if limiter.calls["192.0.2.7"] != 2 {
		t.Errorf("limiter calls %v", limiter.calls)
	}
	if len(ev.events) != 1 || ev.events[0].scope != "admin_auth" || ev.events[0].ip != ip || !strings.HasPrefix(ev.events[0].kind, "rate_limited") {
		t.Errorf("events %+v", ev.events)
	}
}

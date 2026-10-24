package middleware

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// fakeSession is the session type stored by the fake resolver.
type fakeSession struct{ email string }

// fakeSessions resolves the token "good" (and records the CSRF checks).
type fakeSessions struct {
	err       error
	csrfCalls int
}

func (f *fakeSessions) ResolveSession(_ context.Context, raw string) (any, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	if raw != "good" {
		return nil, false, nil
	}
	return fakeSession{email: "alice@entity-a.example.com"}, true, nil
}

func (f *fakeSessions) CheckCSRF(raw, header string) bool {
	f.csrfCalls++
	return raw == "good" && header == "csrf_good"
}

func always(*http.Request) bool { return true }
func never(*http.Request) bool  { return false }

// sessionEcho answers 200 with the session email and token from the
// context.
var sessionEcho = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	s, ok := SessionFrom[fakeSession](r.Context())
	tok, tokOK := SessionToken(r.Context())
	if !ok || !tokOK {
		w.WriteHeader(http.StatusTeapot)
		return
	}
	_, _ = w.Write([]byte(s.email + " " + tok))
})

func TestDepositSession(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		required func(*http.Request) bool
		cookie   string
		err      error
		status   int
		code     problem.Code
		body     string
	}{
		{name: "not required", required: never, status: http.StatusTeapot},
		{name: "no cookie", required: always, status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{name: "empty cookie", required: always, cookie: DepositCookie + "=", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{name: "unknown token", required: always, cookie: DepositCookie + "=bad", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{name: "resolver failure", required: always, cookie: DepositCookie + "=good", err: errors.New("db down"), status: http.StatusInternalServerError, code: problem.CodeInternalError},
		{name: "other cookie only", required: always, cookie: "tt_deposit=good", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{name: "valid", required: always, cookie: DepositCookie + "=good", status: http.StatusOK, body: "alice@entity-a.example.com good"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			h := DepositSession(&fakeSessions{err: tt.err}, tt.required, logger)(sessionEcho)
			req := withRID(httptest.NewRequest(http.MethodGet, "/api/v1/deposit-sessions/current", nil), "req_1")
			if tt.cookie != "" {
				req.Header.Set("Cookie", tt.cookie)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.status, rec.Body)
			}
			if tt.code != "" {
				p := decodeProblem(t, rec)
				if p.Code != tt.code || p.Instance != "req_1" {
					t.Errorf("problem = %+v, want code %s and instance req_1", p, tt.code)
				}
			}
			if tt.body != "" && rec.Body.String() != tt.body {
				t.Errorf("body = %q, want %q", rec.Body, tt.body)
			}
			if tt.err != nil {
				if !strings.Contains(logs.String(), "db down") || strings.Contains(logs.String(), "good") {
					t.Errorf("log = %q, want the error and never the token", logs.String())
				}
			}
		})
	}
}

func TestDepositSessionNilLogger(t *testing.T) {
	t.Parallel()
	h := DepositSession(&fakeSessions{err: errors.New("boom")}, always, nil)(sessionEcho)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: DepositCookie, Value: "good"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestSessionAccessorsWithoutSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, ok := SessionFrom[fakeSession](ctx); ok {
		t.Error("SessionFrom on an empty context reported a session")
	}
	if tok, ok := SessionToken(ctx); ok || tok != "" {
		t.Errorf("SessionToken = %q, %v, want \"\", false", tok, ok)
	}
	// A session of another type is not returned.
	ctx = context.WithValue(ctx, sessionKey{}, sessionValue{session: fakeSession{}, token: "good"})
	if _, ok := SessionFrom[string](ctx); ok {
		t.Error("SessionFrom returned a session of the wrong type")
	}
}

func TestCSRF(t *testing.T) {
	t.Parallel()
	const host = "transfer.entity-a.example.com"
	tests := []struct {
		name     string
		method   string
		required func(*http.Request) bool
		noToken  bool
		header   http.Header
		host     string
		pass     bool
	}{
		{name: "safe method", method: http.MethodGet, required: always, noToken: true, pass: true},
		{name: "head", method: http.MethodHead, required: always, noToken: true, pass: true},
		{name: "options", method: http.MethodOptions, required: always, noToken: true, pass: true},
		{name: "trace", method: http.MethodTrace, required: always, noToken: true, pass: true},
		{name: "not required", method: http.MethodPost, required: never, noToken: true, pass: true},
		{
			name: "valid token only", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}}, pass: true,
		},
		{
			name: "valid with origin and fetch site", method: http.MethodDelete, required: always,
			header: http.Header{
				"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://" + host}, "Sec-Fetch-Site": {"same-origin"},
			}, pass: true,
		},
		{
			name: "origin case and default port", method: http.MethodPut, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://TRANSFER.entity-a.example.com:443"}},
			host:   host + ":443", pass: true,
		},
		{
			name: "origin with port", method: http.MethodPatch, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://" + host + ":8443"}},
			host:   host + ":8443", pass: true,
		},
		{
			name: "no session in context", method: http.MethodPost, required: always, noToken: true,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}},
		},
		{name: "missing token", method: http.MethodPost, required: always},
		{
			name: "wrong token", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_bad"}},
		},
		{
			name: "cross-site fetch", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Sec-Fetch-Site": {"cross-site"}},
		},
		{
			name: "same-site fetch", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Sec-Fetch-Site": {"same-site"}},
		},
		{
			name: "several fetch site values", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Sec-Fetch-Site": {"same-origin", "same-origin"}},
		},
		{
			name: "foreign origin", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://evil.example.net"}},
		},
		{
			name: "other tenant origin", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://transfer.entity-b.example.com"}},
		},
		{
			name: "http origin", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Origin": {"http://" + host}},
		},
		{
			name: "null origin", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Origin": {"null"}},
		},
		{
			name: "empty https origin", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://"}},
		},
		{
			name: "origin with path", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://" + host + "/x"}},
		},
		{
			name: "several origins", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://" + host, "https://" + host}},
		},
		{
			name: "wrong port", method: http.MethodPost, required: always,
			header: http.Header{"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://" + host + ":8443"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			checker := &fakeSessions{}
			h := CSRF(checker, tt.required)(okHandler)
			req := httptest.NewRequest(tt.method, "/api/v1/invitations", nil)
			req.Host = host
			if tt.host != "" {
				req.Host = tt.host
			}
			for k, vs := range tt.header {
				req.Header[http.CanonicalHeaderKey(k)] = vs
			}
			if !tt.noToken {
				req = req.WithContext(context.WithValue(req.Context(), sessionKey{}, sessionValue{session: fakeSession{}, token: "good"}))
			}
			req = withRID(req, "req_2")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if tt.pass {
				if rec.Code != http.StatusNoContent {
					t.Fatalf("status = %d, want 204 (body %s)", rec.Code, rec.Body)
				}
				return
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			if p := decodeProblem(t, rec); p.Code != problem.CodeCSRFInvalid || p.Instance != "req_2" {
				t.Errorf("problem = %+v, want csrf-invalid with instance req_2", p)
			}
		})
	}
}

func TestSameOrigin(t *testing.T) {
	t.Parallel()
	const host = "transfer.entity-a.example.com"
	tests := []struct {
		name     string
		method   string
		required func(*http.Request) bool
		header   http.Header
		pass     bool
	}{
		{name: "no header", method: http.MethodPost, required: always, pass: true},
		{
			name: "same origin", method: http.MethodPost, required: always,
			header: http.Header{"Origin": {"https://" + host}, "Sec-Fetch-Site": {"same-origin"}}, pass: true,
		},
		{name: "foreign origin", method: http.MethodPost, required: always, header: http.Header{"Origin": {"https://evil.example.net"}}},
		{name: "cross-site fetch", method: http.MethodPost, required: always, header: http.Header{"Sec-Fetch-Site": {"cross-site"}}},
		{name: "not required", method: http.MethodPost, required: never, header: http.Header{"Origin": {"https://evil.example.net"}}, pass: true},
		{name: "safe method", method: http.MethodGet, required: always, header: http.Header{"Origin": {"https://evil.example.net"}}, pass: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := withRID(httptest.NewRequest(tt.method, "/api/v1/downloads/dl_x/unlock", nil), "req_3")
			req.Host = host
			for k, vs := range tt.header {
				req.Header[k] = vs
			}
			rec := httptest.NewRecorder()
			SameOrigin(tt.required)(okHandler).ServeHTTP(rec, req)
			if tt.pass {
				if rec.Code != http.StatusNoContent {
					t.Fatalf("status %d, want 204", rec.Code)
				}
				return
			}
			if p := decodeProblem(t, rec); rec.Code != http.StatusForbidden || p.Code != problem.CodeCSRFInvalid {
				t.Errorf("status %d problem %+v, want 403 csrf-invalid", rec.Code, p)
			}
		})
	}
}

// TestCookieSessionFailureLevel checks that a resolver failure is logged at
// Error level, and only at Debug level when the client canceled the
// request (a browser leaving a page), for both session cookies.
func TestCookieSessionFailureLevel(t *testing.T) {
	t.Parallel()
	type mw func(SessionResolver, func(*http.Request) bool, *slog.Logger) func(http.Handler) http.Handler
	kinds := []struct {
		name   string
		mw     mw
		cookie string
		what   string
	}{
		{"deposit", DepositSession, DepositCookie, "deposit session lookup failed"},
		{"admin", AdminSession, AdminCookie, "admin session lookup failed"},
	}
	tests := []struct {
		name   string
		err    error
		cancel bool
		level  string
	}{
		{"server failure", errors.New("db down"), false, "ERROR"},
		{"client canceled", fmt.Errorf("lookup: %w", context.Canceled), true, "DEBUG"},
		{"cancellation error without canceled request", context.Canceled, false, "ERROR"},
		{"other error after cancellation", errors.New("db down"), true, "ERROR"},
	}
	for _, k := range kinds {
		for _, tt := range tests {
			t.Run(k.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				var logs bytes.Buffer
				logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
				h := k.mw(&fakeSessions{err: tt.err}, always, logger)(sessionEcho)
				req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
				req.AddCookie(&http.Cookie{Name: k.cookie, Value: "good"})
				if tt.cancel {
					ctx, cancel := context.WithCancel(req.Context())
					cancel()
					req = req.WithContext(ctx)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusInternalServerError {
					t.Fatalf("status = %d, want 500", rec.Code)
				}
				got := logs.String()
				if !strings.Contains(got, "level="+tt.level) || !strings.Contains(got, k.what) {
					t.Errorf("log = %q, want %q at level %s", got, k.what, tt.level)
				}
			})
		}
	}
}

package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// meEcho answers 200 with the "my transfers" session email and token from
// the context; 418 when it is missing or a deposit or admin session is
// present instead.
var meEcho = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	s, ok := MyTransfersSessionFrom[fakeSession](r.Context())
	tok, tokOK := MyTransfersSessionToken(r.Context())
	_, deposit := SessionToken(r.Context())
	_, admin := AdminSessionToken(r.Context())
	if !ok || !tokOK || deposit || admin {
		w.WriteHeader(http.StatusTeapot)
		return
	}
	_, _ = w.Write([]byte(s.email + " " + tok))
})

func TestMyTransfersSession(t *testing.T) {
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
		{name: "empty cookie", cookie: MyTransfersCookie + "=", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{name: "deposit cookie only", cookie: DepositCookie + "=good", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{name: "unknown or expired token", cookie: MyTransfersCookie + "=bad", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated, clears: true},
		{name: "resolver failure", cookie: MyTransfersCookie + "=good", err: errors.New("db down"), status: http.StatusInternalServerError, code: problem.CodeInternalError},
		{name: "valid", cookie: MyTransfersCookie + "=good", status: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := MyTransfersSession(&fakeSessions{err: tt.err}, always, nil)(meEcho)
			req := withRID(httptest.NewRequest(http.MethodGet, "/api/v1/me/transfers", nil), "req_1")
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
			if want := ExpiredCookie(MyTransfersCookie); (got == want) != tt.clears || (!tt.clears && got != "") {
				t.Errorf("Set-Cookie = %q, want cleared=%v", got, tt.clears)
			}
		})
	}
	// Not required: passes untouched.
	h := MyTransfersSession(&fakeSessions{}, never, nil)(meEcho)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("not required: %d", rec.Code)
	}
}

func TestMyTransfersSessionAccessors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, ok := MyTransfersSessionFrom[fakeSession](ctx); ok {
		t.Error("MyTransfersSessionFrom on an empty context reported a session")
	}
	if tok, ok := MyTransfersSessionToken(ctx); ok || tok != "" {
		t.Errorf("MyTransfersSessionToken = %q, %v", tok, ok)
	}
	// A deposit session is never returned as a "my transfers" session, nor
	// the reverse.
	ctx = context.WithValue(ctx, sessionKey{}, sessionValue{session: fakeSession{}, token: "good"})
	if _, ok := MyTransfersSessionFrom[fakeSession](ctx); ok {
		t.Error("MyTransfersSessionFrom returned the deposit session")
	}
	ctx = context.WithValue(context.Background(), myTransfersSessionKey{}, sessionValue{session: fakeSession{}, token: "good"})
	if _, ok := SessionFrom[fakeSession](ctx); ok {
		t.Error("SessionFrom returned the my transfers session")
	}
	if tok, ok := MyTransfersSessionToken(ctx); !ok || tok != "good" {
		t.Errorf("MyTransfersSessionToken = %q, %v", tok, ok)
	}
}

func TestMyTransfersCSRF(t *testing.T) {
	t.Parallel()
	const host = "transfer.entity-a.example.com"
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
		{name: "missing token", method: http.MethodDelete, cookie: "good"},
		{name: "wrong token", method: http.MethodDelete, cookie: "good", header: http.Header{"X-Csrf-Token": {"csrf_bad"}}},
		{name: "cross site", method: http.MethodPost, cookie: "good", header: http.Header{
			"X-Csrf-Token": {"csrf_good"}, "Sec-Fetch-Site": {"cross-site"},
		}},
		{name: "other origin", method: http.MethodPost, cookie: "good", header: http.Header{
			"X-Csrf-Token": {"csrf_good"}, "Origin": {"https://transfer.entity-b.example.com"},
		}},
		// The token of a deposit session does not satisfy the check.
		{name: "deposit session only", method: http.MethodPost, depOnly: true, header: http.Header{"X-Csrf-Token": {"csrf_good"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sessions := &fakeSessions{}
			h := MyTransfersCSRF(sessions, always)(ok)
			if tt.cookie != "" {
				h = MyTransfersSession(sessions, always, nil)(h)
			}
			req := httptest.NewRequest(tt.method, "/api/v1/me/transfers/trf_x", nil)
			req.Host = host
			for k, v := range tt.header {
				req.Header[k] = v
			}
			if tt.cookie != "" {
				req.Header.Set("Cookie", MyTransfersCookie+"="+tt.cookie)
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

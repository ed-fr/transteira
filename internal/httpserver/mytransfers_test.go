package httpserver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/mytransfers"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

const (
	meToken = "ms_good"
	meCSRF  = "csrf_me"
)

// fakeMeSessions knows the "my transfers" session meToken of tenant ten_a.
type fakeMeSessions struct {
	err error
}

func (f fakeMeSessions) Session(_ context.Context, t *tenant.Tenant, raw string) (mytransfers.SessionInfo, error) {
	if f.err != nil {
		return mytransfers.SessionInfo{}, f.err
	}
	if t.ID != "ten_a" || raw != meToken {
		return mytransfers.SessionInfo{}, mytransfers.ErrUnauthenticated
	}
	return mytransfers.SessionInfo{
		ID: "mts_secret", Email: "alice@entity-a.example.com", CSRFToken: meCSRF,
		ExpiresAt: time.Date(2026, 10, 19, 20, 0, 0, 0, time.UTC),
	}, nil
}

func (fakeMeSessions) CheckCSRF(raw, header string) bool { return raw == meToken && header == meCSRF }

// fakeMyTransfers is a "my transfers" service whose operations succeed.
type fakeMyTransfers struct {
	public.MyTransfersService
}

func (fakeMyTransfers) RequestLink(context.Context, *tenant.Tenant, netip.Addr, string, string, string) error {
	return nil
}

func (fakeMyTransfers) StartSession(context.Context, *tenant.Tenant, netip.Addr, string) (mytransfers.Session, error) {
	return mytransfers.Session{Token: meToken, SessionInfo: mytransfers.SessionInfo{
		Email: "alice@entity-a.example.com", CSRFToken: meCSRF, ExpiresAt: time.Now().Add(mytransfers.SessionTTL),
	}}, nil
}

func (fakeMyTransfers) End(context.Context, *tenant.Tenant, string) error { return nil }

func (fakeMyTransfers) List(context.Context, *tenant.Tenant, mytransfers.SessionInfo, string, int) (store.Page[mytransfers.Transfer], error) {
	return store.Page[mytransfers.Transfer]{}, nil
}

func (fakeMyTransfers) Delete(context.Context, *tenant.Tenant, mytransfers.SessionInfo, netip.Addr, string) error {
	return nil
}

func newMeEnv(t *testing.T, sessions MyTransfersSessions) *env {
	t.Helper()
	return newEnv(t, envConfig{
		api:         public.NewServer(public.WithMyTransfers(fakeMyTransfers{})),
		sessions:    fakeSessions{},
		myTransfers: sessions,
	})
}

func TestMyTransfersRoutes(t *testing.T) {
	t.Parallel()
	cookie := middleware.MyTransfersCookie + "=" + meToken
	same := []string{"Origin", "https://" + hostA, "Sec-Fetch-Site", "same-origin"}
	json := []string{"Content-Type", "application/json"}
	join := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		hdr    []string
		status int
		code   problem.Code
		clears bool
	}{
		{name: "current without cookie", method: http.MethodGet, path: "/api/v1/me/sessions/current", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{
			name: "current with a deposit cookie only", method: http.MethodGet, path: "/api/v1/me/sessions/current",
			hdr: []string{"Cookie", middleware.DepositCookie + "=" + goodToken}, status: http.StatusUnauthorized, code: problem.CodeUnauthenticated,
		},
		{
			name: "current with an expired cookie", method: http.MethodGet, path: "/api/v1/me/sessions/current",
			hdr: []string{"Cookie", middleware.MyTransfersCookie + "=ms_old"}, status: http.StatusUnauthorized, code: problem.CodeUnauthenticated, clears: true,
		},
		{name: "current", method: http.MethodGet, path: "/api/v1/me/sessions/current", hdr: []string{"Cookie", cookie}, status: http.StatusOK},
		{name: "list", method: http.MethodGet, path: "/api/v1/me/transfers", hdr: []string{"Cookie", cookie}, status: http.StatusOK},
		{name: "list without cookie", method: http.MethodGet, path: "/api/v1/me/transfers", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{
			name: "end without csrf", method: http.MethodDelete, path: "/api/v1/me/sessions/current",
			hdr: []string{"Cookie", cookie}, status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "end with a wrong csrf", method: http.MethodDelete, path: "/api/v1/me/sessions/current",
			hdr: []string{"Cookie", cookie, middleware.HeaderCSRFToken, goodCSRF}, status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "end cross-site", method: http.MethodDelete, path: "/api/v1/me/sessions/current",
			hdr:    []string{"Cookie", cookie, middleware.HeaderCSRFToken, meCSRF, "Sec-Fetch-Site", "cross-site"},
			status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "end without cookie", method: http.MethodDelete, path: "/api/v1/me/sessions/current",
			hdr: []string{middleware.HeaderCSRFToken, meCSRF}, status: http.StatusUnauthorized, code: problem.CodeUnauthenticated,
		},
		{
			name: "end", method: http.MethodDelete, path: "/api/v1/me/sessions/current",
			hdr: join([]string{"Cookie", cookie, middleware.HeaderCSRFToken, meCSRF}, same), status: http.StatusNoContent, clears: true,
		},
		{
			name: "delete without csrf", method: http.MethodDelete, path: "/api/v1/me/transfers/trf_x",
			hdr: []string{"Cookie", cookie}, status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "delete", method: http.MethodDelete, path: "/api/v1/me/transfers/trf_x",
			hdr: []string{"Cookie", cookie, middleware.HeaderCSRFToken, meCSRF}, status: http.StatusNoContent,
		},
		{
			name: "extend without csrf", method: http.MethodPost, path: "/api/v1/me/transfers/trf_x/extension", body: `{"expiryDays":30}`,
			hdr: join([]string{"Cookie", cookie}, json), status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "access link cross-site", method: http.MethodPost, path: "/api/v1/me/access-links", body: `{"email":"alice@entity-a.example.com"}`,
			hdr: join(json, []string{"Sec-Fetch-Site", "cross-site"}), status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "access link foreign origin", method: http.MethodPost, path: "/api/v1/me/access-links", body: `{"email":"alice@entity-a.example.com"}`,
			hdr: join(json, []string{"Origin", "https://evil.example.net"}), status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "access link form", method: http.MethodPost, path: "/api/v1/me/access-links", body: `email=alice@entity-a.example.com`,
			hdr: []string{"Content-Type", "application/x-www-form-urlencoded"}, status: http.StatusUnsupportedMediaType, code: problem.CodeUnsupportedMediaType,
		},
		{
			name: "access link", method: http.MethodPost, path: "/api/v1/me/access-links", body: `{"email":"alice@entity-a.example.com"}`,
			hdr: join(json, same), status: http.StatusAccepted,
		},
		{
			name: "session cross-site", method: http.MethodPost, path: "/api/v1/me/sessions", body: `{"token":"mta_x"}`,
			hdr: join(json, []string{"Sec-Fetch-Site", "same-site"}), status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "session", method: http.MethodPost, path: "/api/v1/me/sessions", body: `{"token":"mta_x"}`,
			hdr: join(json, same), status: http.StatusCreated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newMeEnv(t, fakeMeSessions{})
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			rec := e.do(t, tt.method, tt.path, hostA, body, tt.hdr...)
			if tt.code != "" {
				decodeProblem(t, rec, tt.status, tt.code)
			} else if rec.Code != tt.status {
				t.Fatalf("status %d, want %d; body %s", rec.Code, tt.status, rec.Body)
			}
			if got := rec.Header().Get("Set-Cookie"); tt.clears != (got == middleware.ExpiredCookie(middleware.MyTransfersCookie)) {
				t.Errorf("Set-Cookie = %q, want cleared=%v", got, tt.clears)
			}
			if strings.Contains(rec.Body.String(), "mts_secret") {
				t.Errorf("response leaks the session record id: %s", rec.Body)
			}
		})
	}
}

// TestMyTransfersSessionCookie checks the attributes of the session cookie
// set by startMyTransfersSession, through the real strict handler.
func TestMyTransfersSessionCookie(t *testing.T) {
	t.Parallel()
	e := newMeEnv(t, fakeMeSessions{})
	rec := e.do(t, http.MethodPost, "/api/v1/me/sessions", hostA, strings.NewReader(`{"token":"mta_x"}`), "Content-Type", "application/json")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie = %q", cookies)
	}
	c := cookies[0]
	for _, part := range []string{middleware.MyTransfersCookie + "=" + meToken + ";", "Path=/", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(c, part) {
			t.Errorf("Set-Cookie %q lacks %q", c, part)
		}
	}
	if !strings.Contains(c, "Max-Age=3600") && !strings.Contains(c, "Max-Age=3599") {
		t.Errorf("Set-Cookie %q, want Max-Age of one hour", c)
	}
	if strings.Contains(c, "Domain=") {
		t.Errorf("Set-Cookie %q has a Domain", c)
	}
	assertSecurityHeaders(t, rec)
}

func TestMyTransfersSessionResolver(t *testing.T) {
	t.Parallel()
	_, ok, err := myTransfersResolver{svc: fakeMeSessions{}}.ResolveSession(context.Background(), meToken)
	if ok || err != nil {
		t.Errorf("ResolveSession without tenant = %v, %v, want false, nil", ok, err)
	}
	e := newMeEnv(t, fakeMeSessions{err: errors.New("database is locked")})
	rec := e.do(t, http.MethodGet, "/api/v1/me/transfers", hostA, nil, "Cookie", middleware.MyTransfersCookie+"="+meToken)
	decodeProblem(t, rec, http.StatusInternalServerError, problem.CodeInternalError)
	if !strings.Contains(e.appLog.String(), "database is locked") {
		t.Errorf("failure not logged: %s", e.appLog.String())
	}
	// Without a "my transfers" service, no cookie is valid.
	e = newEnv(t, envConfig{api: public.NewServer(public.WithMyTransfers(fakeMyTransfers{}))})
	rec = e.do(t, http.MethodGet, "/api/v1/me/transfers", hostA, nil, "Cookie", middleware.MyTransfersCookie+"="+meToken)
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)
}

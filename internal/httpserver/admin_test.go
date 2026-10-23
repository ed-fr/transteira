package httpserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/admin"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

const (
	adminGoodToken    = "as_good"
	adminPendingToken = "as_pending"
	adminBoomToken    = "as_boom"
	adminCSRF         = "csrf_admin"
)

// fakeAdminSessions knows the sessions adminGoodToken (authenticated
// super admin) and adminPendingToken (TOTP awaited); adminBoomToken fails.
type fakeAdminSessions struct{}

func (fakeAdminSessions) Resolve(_ context.Context, raw string) (adminauth.Principal, error) {
	p := adminauth.Principal{
		SessionID: "as_01", CSRFToken: adminCSRF, ExpiresAt: time.Now().Add(time.Hour),
		Admin: adminauth.Account{ID: "adm_01", Username: "root", Email: "root@example.com", Role: store.RoleSuperAdmin},
	}
	switch raw {
	case adminGoodToken:
		p.State = store.SessionAuthenticated
	case adminPendingToken:
		p.State = store.SessionTOTPRequired
	case adminBoomToken:
		return adminauth.Principal{}, errors.New("database down")
	default:
		return adminauth.Principal{}, adminauth.ErrUnauthenticated
	}
	return p, nil
}

func (fakeAdminSessions) CheckCSRF(raw, header string) bool {
	return (raw == adminGoodToken || raw == adminPendingToken) && header == adminCSRF
}

// adminAuth returns the headers of a same-origin request of the
// authenticated session.
func adminAuth() []string {
	return []string{
		"Cookie", middleware.AdminCookie + "=" + adminGoodToken, middleware.HeaderCSRFToken, adminCSRF,
		"Origin", "https://" + hostAdmin, "Sec-Fetch-Site", "same-origin",
	}
}

// fakeAdminService answers the setup status, the login and the logout;
// any other method panics (nil embedded interface).
type fakeAdminService struct {
	admin.Service
	loggedOut []string
}

func (*fakeAdminService) SetupRequired(context.Context) (bool, error) { return true, nil }

func (*fakeAdminService) Login(_ context.Context, username, _ string, ip netip.Addr) (adminauth.Session, error) {
	if username != "root" || !ip.IsValid() {
		return adminauth.Session{}, adminauth.ErrInvalidCredentials
	}
	return adminauth.Session{
		Token: "as_new", CSRFToken: "csrf_new", State: store.SessionTOTPRequired, ExpiresAt: time.Now().Add(time.Hour),
		// The cookie lasts until the end of the state; the margin absorbs
		// the time the request takes.
		StateExpiresAt: time.Now().Add(5*time.Minute + 500*time.Millisecond),
	}, nil
}

func (f *fakeAdminService) Logout(_ context.Context, p adminauth.Principal, _ netip.Addr) error {
	f.loggedOut = append(f.loggedOut, p.SessionID)
	return nil
}

// fakeTenantList lists one tenant.
type fakeTenantList struct{ admin.Tenants }

func (fakeTenantList) List(context.Context, store.TenantListOptions) (store.Page[*tenant.Tenant], error) {
	return store.Page[*tenant.Tenant]{Items: []*tenant.Tenant{{ID: "ten_a", Name: "Entity A", FQDN: hostA}}}, nil
}

func newAdminEnv(t *testing.T, opts ...Option) (*env, *fakeAdminService) {
	t.Helper()
	svc := &fakeAdminService{}
	return newEnv(t, envConfig{
		adminSessions: fakeAdminSessions{},
		adminAPI:      admin.NewServer(admin.WithService(svc), admin.WithTenants(fakeTenantList{})),
		opts:          opts,
	}), svc
}

func TestAdminHostRouting(t *testing.T) {
	t.Parallel()
	e, _ := newAdminEnv(t)
	tests := []struct {
		name, method, target, host string
		hdr                        []string
		status                     int
		code                       problem.Code
	}{
		{name: "setup status", method: http.MethodGet, target: "/api/v1/admin/setup", host: hostAdmin, status: http.StatusOK},
		{name: "admin host with port and case", method: http.MethodGet, target: "/api/v1/admin/setup", host: "ADMIN.transfer.example.com:443", status: http.StatusOK},
		{name: "version", method: http.MethodGet, target: "/api/v1/version", host: hostAdmin, status: http.StatusOK},
		{name: "health", method: http.MethodGet, target: "/healthz", host: hostAdmin, status: http.StatusOK},
		{name: "spec", method: http.MethodGet, target: "/api/openapi.yaml", host: hostAdmin, status: http.StatusOK},
		{name: "public operation", method: http.MethodGet, target: "/api/v1/tenant", host: hostAdmin, status: http.StatusNotFound, code: problem.CodeNotFound},
		{
			name: "public operation with session policy", method: http.MethodPost, target: "/api/v1/transfers", host: hostAdmin,
			hdr: []string{"Content-Type", "text/plain"}, status: http.StatusNotFound, code: problem.CodeNotFound,
		},
		{name: "root redirects to the admin application", method: http.MethodGet, target: "/", host: hostAdmin, status: http.StatusFound},
		{name: "unknown api prefix path", method: http.MethodGet, target: "/api/nope", host: hostAdmin, status: http.StatusNotFound, code: problem.CodeNotFound},
		{name: "bare admin prefix", method: http.MethodGet, target: "/api/v1/admin", host: hostAdmin, status: http.StatusNotFound, code: problem.CodeNotFound},
		{name: "unclean admin path", method: http.MethodGet, target: "/api/v1//admin/setup", host: hostAdmin, status: http.StatusNotFound, code: problem.CodeNotFound},
		{name: "unknown admin path", method: http.MethodGet, target: "/api/v1/admin/nope", host: hostAdmin, status: http.StatusNotFound, code: problem.CodeNotFound},
		{name: "wrong method", method: http.MethodDelete, target: "/api/v1/admin/setup", host: hostAdmin, status: http.StatusMethodNotAllowed, code: problem.CodeMethodNotAllowed},
		{name: "admin operation on a tenant host", method: http.MethodGet, target: "/api/v1/admin/setup", host: hostA, status: http.StatusNotFound, code: problem.CodeNotFound},
		{name: "bare admin prefix on a tenant host", method: http.MethodGet, target: "/api/v1/admin", host: hostA, status: http.StatusNotFound, code: problem.CodeNotFound},
		{
			name: "admin session on a tenant host", method: http.MethodGet, target: "/api/v1/admin/me", host: hostA,
			hdr: adminAuth(), status: http.StatusNotFound, code: problem.CodeNotFound,
		},
		{
			name: "forwarded host is ignored", method: http.MethodGet, target: "/api/v1/admin/setup", host: hostA,
			hdr: []string{"X-Forwarded-Host", hostAdmin, "Forwarded", "host=" + hostAdmin}, status: http.StatusNotFound, code: problem.CodeNotFound,
		},
		{name: "unknown host", method: http.MethodGet, target: "/api/v1/admin/setup", host: hostUnknown, status: http.StatusMisdirectedRequest, code: problem.CodeUnknownTenant},
		{name: "malformed host", method: http.MethodGet, target: "/api/v1/admin/setup", host: "admin@" + hostAdmin, status: http.StatusMisdirectedRequest, code: problem.CodeUnknownTenant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var body io.Reader
			if tt.method == http.MethodPost {
				body = strings.NewReader("{}")
			}
			rec := e.do(t, tt.method, tt.target, tt.host, body, tt.hdr...)
			if tt.code != "" {
				decodeProblem(t, rec, tt.status, tt.code)
			} else if rec.Code != tt.status {
				t.Fatalf("status %d, want %d; body %s", rec.Code, tt.status, rec.Body.String())
			}
			if tt.host == hostAdmin && !strings.HasPrefix(tt.target, "/healthz") && !strings.HasPrefix(tt.target, SpecPath) &&
				rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control %q on the admin host", rec.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestAdminSessionAndCSRF(t *testing.T) {
	t.Parallel()
	e, svc := newAdminEnv(t)
	cookie := func(tok string) string { return middleware.AdminCookie + "=" + tok }
	sameOrigin := []string{"Origin", "https://" + hostAdmin, "Sec-Fetch-Site", "same-origin"}
	tests := []struct {
		name, method, target, body string
		hdr                        []string
		status                     int
		code                       problem.Code
		clears                     bool
	}{
		{name: "me without cookie", method: http.MethodGet, target: "/api/v1/admin/me", status: http.StatusUnauthorized, code: problem.CodeUnauthenticated},
		{
			name: "me with an unknown cookie", method: http.MethodGet, target: "/api/v1/admin/me", hdr: []string{"Cookie", cookie("as_other")},
			status: http.StatusUnauthorized, code: problem.CodeUnauthenticated, clears: true,
		},
		{
			name: "me with a failing lookup", method: http.MethodGet, target: "/api/v1/admin/me", hdr: []string{"Cookie", cookie(adminBoomToken)},
			status: http.StatusInternalServerError, code: problem.CodeInternalError,
		},
		{
			// A valid session in an intermediate state keeps its cookie: the
			// next login step remains possible.
			name: "me in an intermediate state", method: http.MethodGet, target: "/api/v1/admin/me", hdr: []string{"Cookie", cookie(adminPendingToken)},
			status: http.StatusUnauthorized, code: problem.CodeUnauthenticated,
		},
		{name: "me", method: http.MethodGet, target: "/api/v1/admin/me", hdr: []string{"Cookie", cookie(adminGoodToken)}, status: http.StatusOK},
		{
			name: "logout without csrf", method: http.MethodPost, target: "/api/v1/admin/auth/logout", hdr: []string{"Cookie", cookie(adminGoodToken)},
			status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "logout cross-site", method: http.MethodPost, target: "/api/v1/admin/auth/logout",
			hdr:    []string{"Cookie", cookie(adminGoodToken), middleware.HeaderCSRFToken, adminCSRF, "Origin", "https://evil.example.net"},
			status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "logout without cookie", method: http.MethodPost, target: "/api/v1/admin/auth/logout",
			hdr: []string{middleware.HeaderCSRFToken, adminCSRF}, status: http.StatusUnauthorized, code: problem.CodeUnauthenticated,
		},
		{name: "logout", method: http.MethodPost, target: "/api/v1/admin/auth/logout", hdr: adminAuth(), status: http.StatusNoContent, clears: true},
		{
			name: "login cross-site", method: http.MethodPost, target: "/api/v1/admin/auth/login", body: `{"username":"root","password":"x"}`,
			hdr:    []string{"Content-Type", "application/json", "Sec-Fetch-Site", "cross-site"},
			status: http.StatusForbidden, code: problem.CodeCSRFInvalid,
		},
		{
			name: "login with a form body", method: http.MethodPost, target: "/api/v1/admin/auth/login", body: `username=root`,
			hdr:    append([]string{"Content-Type", "application/x-www-form-urlencoded"}, sameOrigin...),
			status: http.StatusUnsupportedMediaType, code: problem.CodeUnsupportedMediaType,
		},
		{
			name: "login with wrong credentials", method: http.MethodPost, target: "/api/v1/admin/auth/login", body: `{"username":"eve","password":"x"}`,
			hdr:    append([]string{"Content-Type", "application/json"}, sameOrigin...),
			status: http.StatusUnauthorized, code: problem.CodeInvalidCredentials,
		},
		{
			name: "login", method: http.MethodPost, target: "/api/v1/admin/auth/login", body: `{"username":"root","password":"x"}`,
			hdr: append([]string{"Content-Type", "application/json"}, sameOrigin...), status: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			rec := e.do(t, tt.method, tt.target, hostAdmin, body, tt.hdr...)
			if tt.code != "" {
				decodeProblem(t, rec, tt.status, tt.code)
			} else if rec.Code != tt.status {
				t.Fatalf("status %d, want %d; body %s", rec.Code, tt.status, rec.Body.String())
			}
			cleared := strings.Contains(rec.Header().Get("Set-Cookie"), middleware.AdminCookie+"=;")
			if cleared != tt.clears {
				t.Errorf("Set-Cookie %q, want cleared=%v", rec.Header().Get("Set-Cookie"), tt.clears)
			}
		})
	}
	if len(svc.loggedOut) != 1 || svc.loggedOut[0] != "as_01" {
		t.Errorf("logged out %v", svc.loggedOut)
	}
	if !strings.Contains(e.appLog.String(), "admin session lookup failed") {
		t.Errorf("app log %q", e.appLog.String())
	}
}

func TestAdminLoginSetsCookie(t *testing.T) {
	t.Parallel()
	e, _ := newAdminEnv(t)
	rec := e.do(t, http.MethodPost, "/api/v1/admin/auth/login", hostAdmin, strings.NewReader(`{"username":"root","password":"x"}`),
		"Content-Type", "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("login %d %s", rec.Code, rec.Body.String())
	}
	c := rec.Header().Get("Set-Cookie")
	for _, want := range []string{middleware.AdminCookie + "=as_new", "Path=/", "Max-Age=300", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(c, want) {
			t.Errorf("Set-Cookie %q lacks %q", c, want)
		}
	}
	if strings.Contains(c, "Domain") {
		t.Errorf("Set-Cookie %q has a Domain", c)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), `"csrfToken":"csrf_new"`) {
		t.Errorf("login answer %v %s", rec.Header(), rec.Body.String())
	}
}

func TestAdminAuthRateLimit(t *testing.T) {
	t.Parallel()
	e, _ := newAdminEnv(t, WithAdminAuthLimiter(denyLimiter{}))
	for _, target := range []string{"/api/v1/admin/auth/login", "/api/v1/admin/auth/totp", "/api/v1/admin/setup", "/api/v1/admin/activation"} {
		rec := e.do(t, http.MethodPost, target, hostAdmin, strings.NewReader("{}"), "Content-Type", "application/json")
		decodeProblem(t, rec, http.StatusTooManyRequests, problem.CodeRateLimited)
		if rec.Header().Get("Retry-After") != "3" {
			t.Errorf("%s: Retry-After %q", target, rec.Header().Get("Retry-After"))
		}
	}
	// The TOTP confirmation, a second factor check, is limited too.
	rec := e.do(t, http.MethodPost, "/api/v1/admin/me/totp/confirm", hostAdmin, strings.NewReader("{}"),
		append(adminAuth(), "Content-Type", "application/json")...)
	decodeProblem(t, rec, http.StatusTooManyRequests, problem.CodeRateLimited)
	if line := e.secLog.String(); !strings.Contains(line, `event=rate_limited scope="admin_auth"`) || !strings.Contains(line, "ip=192.0.2.10 tenant=-") {
		t.Errorf("security log %q", line)
	}
	// The other admin operations are not limited by it.
	rec = e.do(t, http.MethodGet, "/api/v1/admin/setup", hostAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Errorf("setup status %d", rec.Code)
	}
	rec = e.do(t, http.MethodPost, "/api/v1/admin/auth/logout", hostAdmin, nil, adminAuth()...)
	if rec.Code != http.StatusNoContent {
		t.Errorf("logout %d", rec.Code)
	}
}

func TestAdminDefaults(t *testing.T) {
	t.Parallel()
	// Without service nor session resolver: the open operations answer 500
	// (wiring error) and no cookie is ever valid.
	e := newEnv(t, envConfig{})
	rec := e.do(t, http.MethodGet, "/api/v1/admin/setup", hostAdmin, nil)
	decodeProblem(t, rec, http.StatusInternalServerError, problem.CodeInternalError)
	rec = e.do(t, http.MethodGet, "/api/v1/admin/me", hostAdmin, nil, "Cookie", middleware.AdminCookie+"="+adminGoodToken)
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)

	// Without admin host, the admin host is unknown.
	ok := health.CheckerFunc(func(context.Context) error { return nil })
	h := New(Deps{
		Resolver: fakeResolver{}, SecurityLog: securitylog.New(io.Discard),
		Health: &health.Service{Database: health.Check{Checker: ok}, Antivirus: health.Check{Checker: ok}, Storage: health.Check{Checker: ok}},
		Logger: slog.New(slog.DiscardHandler),
	})
	e2 := &env{handler: h}
	rec = e2.do(t, http.MethodGet, "/api/v1/admin/setup", hostAdmin, nil)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("admin host without TT_ADMIN_HOSTS: %d", rec.Code)
	}
}

func TestAdminSessionResolver(t *testing.T) {
	t.Parallel()
	r := adminSessionResolver{svc: fakeAdminSessions{}}
	ctx := context.Background()
	if s, ok, err := r.ResolveSession(ctx, adminGoodToken); err != nil || !ok || s.(adminauth.Principal).SessionID != "as_01" {
		t.Errorf("good: %v %v %v", s, ok, err)
	}
	if _, ok, err := r.ResolveSession(ctx, "as_other"); err != nil || ok {
		t.Errorf("unknown: %v %v", ok, err)
	}
	if _, ok, err := r.ResolveSession(ctx, adminBoomToken); err == nil || ok {
		t.Errorf("failure: %v %v", ok, err)
	}
	if !r.CheckCSRF(adminGoodToken, adminCSRF) || r.CheckCSRF(adminGoodToken, "csrf_other") {
		t.Error("CheckCSRF")
	}
}

func TestHostSet(t *testing.T) {
	t.Parallel()
	if (hostSet{}).match(hostAdmin) {
		t.Error("empty set matches")
	}
	s := newHostSet([]string{hostAdmin, "Admin2.Example.COM."})
	for host, want := range map[string]bool{
		hostAdmin: true, "admin2.example.com:8443": true, hostA: false, "": false, "[::1]": false, "admin@" + hostAdmin: false,
	} {
		if got := s.match(host); got != want {
			t.Errorf("match(%q) = %v, want %v", host, got, want)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("newHostSet accepted a malformed host")
		}
	}()
	newHostSet([]string{"bad host"})
}

package httpserver

import (
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

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/apitoken"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fakeToken is a token known to fakeTokens.
type fakeToken struct {
	id      string
	allowed netip.Prefix
}

// fakeTokens authenticates the tokens of tenant ten_a it knows, like
// apitoken.Service.
type fakeTokens struct {
	secrets map[string]fakeToken
	err     error
}

func (f fakeTokens) Authenticate(_ context.Context, tid tenant.ID, header string, ip netip.Addr) (apitoken.Principal, error) {
	if f.err != nil {
		return apitoken.Principal{}, f.err
	}
	secret, err := apitoken.ParseAuthorization(header)
	if err != nil {
		return apitoken.Principal{}, err
	}
	tok, ok := f.secrets[secret]
	if !ok || tid != "ten_a" {
		return apitoken.Principal{}, apitoken.ErrInvalid
	}
	p := apitoken.Principal{TokenID: tok.id, Name: "nightly export", AllowedCIDRs: []netip.Prefix{tok.allowed}}
	if !tok.allowed.Contains(ip) {
		return p, apitoken.ErrIPNotAllowed
	}
	return p, nil
}

// newSecret returns a fresh token secret (never a literal in the sources).
func newSecret(t *testing.T) string {
	t.Helper()
	g, err := apitoken.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return g.Secret
}

// tokenAPI answers the token operations with a 200 telling who
// authenticated the request: X-Test-Token is the token identifier, and
// X-Test-Session is set when a deposit session is in the context.
type tokenAPI struct {
	*public.Server
}

// whoami is the response of tokenAPI.
type whoami struct{ ctx context.Context }

func (w whoami) write(rw http.ResponseWriter) error {
	if p, ok := middleware.APITokenFrom(w.ctx); ok {
		rw.Header().Set("X-Test-Token", p.TokenID+"/"+p.Name)
	}
	if _, ok := middleware.SessionToken(w.ctx); ok {
		rw.Header().Set("X-Test-Session", "yes")
	}
	rw.WriteHeader(http.StatusOK)
	return nil
}

func (w whoami) VisitCreateTransferResponse(rw http.ResponseWriter) error   { return w.write(rw) }
func (w whoami) VisitGetTransferResponse(rw http.ResponseWriter) error      { return w.write(rw) }
func (w whoami) VisitCancelTransferResponse(rw http.ResponseWriter) error   { return w.write(rw) }
func (w whoami) VisitFinalizeTransferResponse(rw http.ResponseWriter) error { return w.write(rw) }
func (w whoami) VisitGetUploadOffsetResponse(rw http.ResponseWriter) error  { return w.write(rw) }
func (w whoami) VisitAppendUploadChunkResponse(rw http.ResponseWriter) error {
	return w.write(rw)
}
func (w whoami) VisitTerminateUploadResponse(rw http.ResponseWriter) error { return w.write(rw) }

func (tokenAPI) CreateTransfer(ctx context.Context, _ gen.CreateTransferRequestObject) (gen.CreateTransferResponseObject, error) {
	return whoami{ctx}, nil
}

func (tokenAPI) GetTransfer(ctx context.Context, _ gen.GetTransferRequestObject) (gen.GetTransferResponseObject, error) {
	return whoami{ctx}, nil
}

func (tokenAPI) CancelTransfer(ctx context.Context, _ gen.CancelTransferRequestObject) (gen.CancelTransferResponseObject, error) {
	return whoami{ctx}, nil
}

func (tokenAPI) FinalizeTransfer(ctx context.Context, _ gen.FinalizeTransferRequestObject) (gen.FinalizeTransferResponseObject, error) {
	return whoami{ctx}, nil
}

func (tokenAPI) GetUploadOffset(ctx context.Context, _ gen.GetUploadOffsetRequestObject) (gen.GetUploadOffsetResponseObject, error) {
	return whoami{ctx}, nil
}

func (tokenAPI) AppendUploadChunk(ctx context.Context, _ gen.AppendUploadChunkRequestObject) (gen.AppendUploadChunkResponseObject, error) {
	return whoami{ctx}, nil
}

func (tokenAPI) TerminateUpload(ctx context.Context, _ gen.TerminateUploadRequestObject) (gen.TerminateUploadResponseObject, error) {
	return whoami{ctx}, nil
}

// tokenEnv is an env serving tokenAPI with two tokens of ten_a: good,
// usable from the test client IP (192.0.2.10), and narrow, which is not.
type tokenEnv struct {
	*env
	good, narrow string
}

const (
	goodTokenID   = "tok_01JAAAAAAAAAAAAAAAAAAAAAAA"
	narrowTokenID = "tok_01JBBBBBBBBBBBBBBBBBBBBBBB"
)

func newTokenEnv(t *testing.T, err error, opts ...Option) *tokenEnv {
	t.Helper()
	te := &tokenEnv{good: newSecret(t), narrow: newSecret(t)}
	tokens := fakeTokens{err: err, secrets: map[string]fakeToken{
		te.good:   {id: goodTokenID, allowed: netip.MustParsePrefix("192.0.2.0/24")},
		te.narrow: {id: narrowTokenID, allowed: netip.MustParsePrefix("198.51.100.0/24")},
	}}
	te.env = newEnv(t, envConfig{
		api: tokenAPI{public.NewServer()}, sessions: fakeSessions{}, tokens: tokens, opts: opts,
	})
	return te
}

// tokenRoute is one operation accepting an API token.
type tokenRoute struct {
	name   string
	method string
	path   string
	body   string
	hdr    []string
	tus    bool
}

var tokenRoutes = []tokenRoute{
	{name: "createTransfer", method: http.MethodPost, path: "/api/v1/transfers", body: `{}`, hdr: []string{"Content-Type", "application/json"}},
	{name: "getTransfer", method: http.MethodGet, path: "/api/v1/transfers/trf_x"},
	{name: "cancelTransfer", method: http.MethodDelete, path: "/api/v1/transfers/trf_x"},
	{name: "finalizeTransfer", method: http.MethodPost, path: "/api/v1/transfers/trf_x/finalize"},
	{name: "getUploadOffset", method: http.MethodHead, path: "/api/v1/uploads/upl_x", hdr: []string{"Tus-Resumable", "1.0.0"}, tus: true},
	{
		name: "appendUploadChunk", method: http.MethodPatch, path: "/api/v1/uploads/upl_x", body: "data", tus: true,
		hdr: []string{"Tus-Resumable", "1.0.0", "Upload-Offset", "0", "Content-Type", "application/offset+octet-stream"},
	},
	{name: "terminateUpload", method: http.MethodDelete, path: "/api/v1/uploads/upl_x", hdr: []string{"Tus-Resumable", "1.0.0"}, tus: true},
}

// call sends the request of route with the extra headers hdr.
func (e *env) call(t *testing.T, route tokenRoute, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, route.method, route.path, hostA, strings.NewReader(route.body), append(append([]string{}, route.hdr...), hdr...)...)
}

// checkFailure checks a refused token request: a Problem, or a bodyless
// answer with Tus-Resumable on a tus route.
func checkFailure(t *testing.T, route tokenRoute, rec *httptest.ResponseRecorder, status int, code problem.Code) {
	t.Helper()
	if !route.tus {
		decodeProblem(t, rec, status, code)
		return
	}
	if rec.Code != status || rec.Body.Len() != 0 || rec.Header().Get(headerTusResumable) != public.TusVersion {
		t.Fatalf("%s: %d %q, Tus-Resumable %q", route.name, rec.Code, rec.Body.String(), rec.Header().Get(headerTusResumable))
	}
}

func TestAPITokenRoutes(t *testing.T) {
	t.Parallel()
	for _, route := range tokenRoutes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()
			e := newTokenEnv(t, nil)
			// A valid token: the token path only, whatever the deposit
			// cookie, the CSRF token, Origin and Sec-Fetch-Site say.
			rec := e.call(t, route, "Authorization", "Bearer "+e.good,
				"Cookie", middleware.DepositCookie+"="+goodToken,
				"Origin", "https://evil.example.net", "Sec-Fetch-Site", "cross-site")
			if rec.Code != http.StatusOK || rec.Header().Get("X-Test-Token") != goodTokenID+"/nightly export" ||
				rec.Header().Get("X-Test-Session") != "" || rec.Header().Get("Set-Cookie") != "" {
				t.Fatalf("valid token: %d %v", rec.Code, rec.Header())
			}
			// The scheme is case-insensitive.
			rec = e.call(t, route, "Authorization", "bearer "+e.good)
			if rec.Code != http.StatusOK || rec.Header().Get("X-Test-Token") == "" {
				t.Fatalf("lower-case scheme: %d", rec.Code)
			}
			// An unknown token, an empty one: 401 invalid-credentials with
			// the RFC 6750 challenge, bodyless tus answers included.
			for _, header := range []string{"Bearer " + newSecret(t), "Bearer", "Bearer ", "BEARER not-a-token"} {
				rec = e.call(t, route, "Authorization", header, "Cookie", middleware.DepositCookie+"="+goodToken)
				checkFailure(t, route, rec, http.StatusUnauthorized, problem.CodeInvalidCredentials)
				if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
					t.Errorf("%q: WWW-Authenticate %q", header, got)
				}
			}
			// A token used from outside its ranges: 403 ip-not-allowed.
			rec = e.call(t, route, "Authorization", "Bearer "+e.narrow)
			checkFailure(t, route, rec, http.StatusForbidden, problem.CodeIPNotAllowed)
			// Another scheme, or no header: the session path.
			rec = e.call(t, route, "Authorization", "Basic YWxpY2U6c2VjcmV0")
			checkFailure(t, route, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)
			if got := rec.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("session path: WWW-Authenticate %q", got)
			}
			rec = e.call(t, route)
			checkFailure(t, route, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)
			// The session path is unchanged: the cookie and the CSRF checks.
			rec = e.call(t, route, "Cookie", middleware.DepositCookie+"="+goodToken, middleware.HeaderCSRFToken, goodCSRF)
			if rec.Code != http.StatusOK || rec.Header().Get("X-Test-Session") != "yes" || rec.Header().Get("X-Test-Token") != "" {
				t.Fatalf("session path: %d %v", rec.Code, rec.Header())
			}
			sec := e.secLog.String()
			if n := strings.Count(sec, "event=api_token_invalid"); n != 4 {
				t.Errorf("%d api_token_invalid events, want 4:\n%s", n, sec)
			}
			if !strings.Contains(sec, "ip=192.0.2.10 tenant="+hostA+" event=api_token_invalid") ||
				!strings.Contains(sec, "ip=192.0.2.10 tenant="+hostA+` event=deposit_refused reason="ip"`) {
				t.Errorf("security log:\n%s", sec)
			}
			if strings.Contains(sec, e.good) || strings.Contains(sec, e.narrow) || strings.Contains(e.appLog.String(), e.narrow) {
				t.Error("a token secret was logged")
			}
			if !strings.Contains(e.appLog.String(), narrowTokenID) {
				t.Errorf("refused token not identified in the application log: %s", e.appLog.String())
			}
		})
	}
}

func TestAPITokenSeveralAuthorizationHeaders(t *testing.T) {
	t.Parallel()
	e := newTokenEnv(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/transfers/trf_x", nil)
	req.Host = hostA
	req.RemoteAddr = "192.0.2.10:4242"
	req.Header.Add("Authorization", "Bearer "+e.good)
	req.Header.Add("Authorization", "Basic YWxpY2U6c2VjcmV0")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeInvalidCredentials)
	// No single token presented: the challenge carries no error code.
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate %q", got)
	}
}

func TestAPITokenIgnoredElsewhere(t *testing.T) {
	t.Parallel()
	e := newTokenEnv(t, nil)
	bearer := "Bearer " + e.good
	// A public route without the apiToken alternative ignores the header.
	rec := e.do(t, http.MethodGet, "/api/v1/deposit-sessions/current", hostA, nil, "Authorization", bearer)
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)
	rec = e.do(t, http.MethodPost, "/api/v1/invitations", hostA, strings.NewReader(`{"email":"bob@partner.example.org"}`),
		"Authorization", bearer, "Content-Type", "application/json")
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)
	// On the admin host, a token authenticates nothing: the deposit routes
	// do not exist there, and the admin routes want their session.
	rec = e.do(t, http.MethodPost, "/api/v1/transfers", hostAdmin, strings.NewReader(`{}`),
		"Authorization", bearer, "Content-Type", "application/json")
	decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
	rec = e.do(t, http.MethodGet, "/api/v1/admin/me", hostAdmin, nil, "Authorization", bearer)
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)
	if strings.Contains(e.secLog.String(), "api_token") {
		t.Errorf("token checked off its routes:\n%s", e.secLog.String())
	}
}

func TestAPITokenLockout(t *testing.T) {
	t.Parallel()
	failures := ratelimit.NewWindow(2, time.Hour, ratelimit.WithLockout(time.Hour))
	e := newTokenEnv(t, nil, WithAPITokenFailures(failures))
	getTransfer, tusHead := tokenRoutes[1], tokenRoutes[4]
	for range 2 {
		rec := e.call(t, getTransfer, "Authorization", "Bearer "+newSecret(t))
		decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeInvalidCredentials)
	}
	// Locked out: an invalid token gets 429 without counting a failure.
	for range 3 {
		rec := e.call(t, getTransfer, "Authorization", "Bearer "+newSecret(t))
		p := decodeProblem(t, rec, http.StatusTooManyRequests, problem.CodeRateLimited)
		if p.RetryAfterSeconds == nil || rec.Header().Get("Retry-After") == "" {
			t.Errorf("429 without retry delay: %+v", p)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "" {
			t.Errorf("429 with WWW-Authenticate %q", got)
		}
	}
	rec := e.call(t, tusHead, "Authorization", "Bearer")
	checkFailure(t, tusHead, rec, http.StatusTooManyRequests, "")
	if rec.Header().Get("Retry-After") == "" {
		t.Error("tus 429 without Retry-After")
	}
	// A valid token still passes (a neighbor behind the same egress), and
	// neither lifts nor extends the lockout.
	key := middleware.RateLimitKey(netip.MustParseAddr("192.0.2.10"))
	_, before := failures.Locked(key)
	for _, route := range []tokenRoute{getTransfer, tusHead} {
		rec = e.call(t, route, "Authorization", "Bearer "+e.good)
		if rec.Code != http.StatusOK || rec.Header().Get("X-Test-Token") == "" {
			t.Errorf("%s: valid token while locked out: %d", route.name, rec.Code)
		}
	}
	if locked, after := failures.Locked(key); !locked || after > before {
		t.Errorf("lockout after a valid token: %v, %v then %v", locked, before, after)
	}
	// A valid token used from outside its ranges is still a 403.
	rec = e.call(t, getTransfer, "Authorization", "Bearer "+e.narrow)
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeIPNotAllowed)
	rec = e.call(t, getTransfer, "Authorization", "Bearer "+newSecret(t))
	decodeProblem(t, rec, http.StatusTooManyRequests, problem.CodeRateLimited)
	// The session path is not affected.
	rec = e.call(t, getTransfer, "Cookie", middleware.DepositCookie+"="+goodToken)
	if rec.Code != http.StatusOK {
		t.Errorf("session path while locked out: %d", rec.Code)
	}
	sec := e.secLog.String()
	if n := strings.Count(sec, `event=rate_limited scope="api_token"`); n != 1 {
		t.Errorf("%d rate_limited events, want 1 (throttled):\n%s", n, sec)
	}
	if n := strings.Count(sec, "event=api_token_invalid"); n != 2 {
		t.Errorf("%d api_token_invalid events, want 2", n)
	}
}

func TestAPITokenInternalError(t *testing.T) {
	t.Parallel()
	e := newTokenEnv(t, errors.New("database is locked"))
	rec := e.call(t, tokenRoutes[1], "Authorization", "Bearer "+e.good)
	decodeProblem(t, rec, http.StatusInternalServerError, problem.CodeInternalError)
	// The tus routes keep the body of a 500.
	rec = e.call(t, tokenRoutes[4], "Authorization", "Bearer "+e.good)
	if rec.Code != http.StatusInternalServerError || rec.Body.Len() == 0 {
		t.Errorf("tus 500: %d %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(e.appLog.String(), "database is locked") {
		t.Errorf("failure not logged: %s", e.appLog.String())
	}
	if strings.Contains(e.secLog.String(), "api_token") {
		t.Errorf("an internal error is not a security event:\n%s", e.secLog.String())
	}
}

func TestAPITokenWithoutService(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{api: tokenAPI{public.NewServer()}})
	rec := e.do(t, http.MethodGet, "/api/v1/transfers/trf_x", hostA, nil, "Authorization", "Bearer "+newSecret(t))
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeInvalidCredentials)
}

func TestAPITokenMaintenanceFirst(t *testing.T) {
	t.Parallel()
	e := newTokenEnv(t, nil)
	e.maintenance.Store(true)
	rec := e.call(t, tokenRoutes[0], "Authorization", "Bearer "+newSecret(t))
	decodeProblem(t, rec, http.StatusServiceUnavailable, problem.CodeMaintenance)
	if strings.Contains(e.secLog.String(), "api_token") {
		t.Error("token checked during maintenance")
	}
}

// TestTokenAuthMiddleware drives the middleware directly: the Cookie
// header is dropped on the token path, and a request without tenant (a
// wiring error) is an internal error.
func TestTokenAuthMiddleware(t *testing.T) {
	t.Parallel()
	secret := newSecret(t)
	tokens := fakeTokens{secrets: map[string]fakeToken{secret: {id: goodTokenID, allowed: netip.MustParsePrefix("0.0.0.0/0")}}}
	var buf lockedBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	a := newTokenAuth(tokens, newTokenFailures(), NewSecurityEvents(securitylog.New(&lockedBuffer{}), logger), logger)
	var seen *http.Request
	h := middleware.RealIP(func(netip.Addr) bool { return false })(
		a.middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = r })))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/transfers/trf_x", nil)
	req.Pattern = http.MethodGet + " " + APIBaseURL + "/transfers/{transferId}"
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Cookie", middleware.DepositCookie+"="+goodToken)
	tenantReq := req.WithContext(tenant.WithTenant(req.Context(), &tenant.Tenant{ID: "ten_a", FQDN: hostA}))
	h.ServeHTTP(httptest.NewRecorder(), tenantReq)
	if seen == nil || seen.Header.Get("Cookie") != "" || !tokenAuthenticated(seen) {
		t.Fatalf("token path: %+v", seen)
	}
	if tenantReq.Header.Get("Cookie") == "" {
		t.Error("the caller's request was mutated")
	}

	seen = nil
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if seen != nil || rec.Code != http.StatusInternalServerError || !strings.Contains(buf.String(), "without tenant") {
		t.Errorf("without tenant: %d, %s", rec.Code, buf.String())
	}
}

// TestTokenAuthFailureLevel checks that a token lookup failure is logged
// at Error level, and only at Debug level when the client canceled the
// request.
func TestTokenAuthFailureLevel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		err    error
		cancel bool
		level  string
	}{
		{"server failure", errors.New("database is locked"), false, "ERROR"},
		{"client canceled", fmt.Errorf("lookup: %w", context.Canceled), true, "DEBUG"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf lockedBuffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			a := newTokenAuth(fakeTokens{err: tt.err}, newTokenFailures(), NewSecurityEvents(securitylog.New(&lockedBuffer{}), logger), logger)
			h := middleware.RealIP(func(netip.Addr) bool { return false })(
				a.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("handler reached") })))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/transfers/trf_x", nil)
			req.Pattern = http.MethodGet + " " + APIBaseURL + "/transfers/{transferId}"
			req.Header.Set("Authorization", "Bearer "+newSecret(t))
			ctx := tenant.WithTenant(req.Context(), &tenant.Tenant{ID: "ten_a", FQDN: hostA})
			if tt.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req.WithContext(ctx))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status %d, want 500", rec.Code)
			}
			if got := buf.String(); !strings.Contains(got, `"level":"`+tt.level+`"`) || !strings.Contains(got, "api token lookup failed") {
				t.Errorf("log %s, want the failure at level %s", got, tt.level)
			}
		})
	}
}

func TestHasBearer(t *testing.T) {
	t.Parallel()
	for header, want := range map[string]bool{
		"":                 false,
		"Bearer":           true,
		"bearer x":         true,
		"Basic x":          false,
		"Bearerx y":        false,
		"Bearer\tx":        false,
		"Token tt_example": false,
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		if got := hasBearer(r); got != want {
			t.Errorf("hasBearer(%q) = %v, want %v", header, got, want)
		}
	}
}

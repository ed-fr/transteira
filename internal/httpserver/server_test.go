package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/tenant"
)

const (
	hostA       = "transfer.entity-a.example.com"
	hostUnknown = "transfer.unknown.example.com"
)

// fakeResolver serves hostA only.
type fakeResolver struct{ err error }

func (f fakeResolver) Resolve(_ context.Context, host string) (*tenant.Tenant, error) {
	if f.err != nil {
		return nil, f.err
	}
	if host == hostA {
		return &tenant.Tenant{ID: "ten_a", FQDN: hostA}, nil
	}
	return nil, tenant.ErrUnknownTenant
}

// fakeAPI overrides a few operations to exercise the error paths.
type fakeAPI struct {
	*public.Server
	tenantErr error
	panicky   bool
	visitFail bool
}

func (f fakeAPI) GetPublicTenant(_ context.Context, _ gen.GetPublicTenantRequestObject) (gen.GetPublicTenantResponseObject, error) {
	if f.panicky {
		panic("boom")
	}
	if f.visitFail {
		return midStreamFailure{}, nil
	}
	return nil, f.tenantErr
}

// midStreamFailure is a response whose rendering fails after the status and
// part of the body were written.
type midStreamFailure struct{}

func (midStreamFailure) VisitGetPublicTenantResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"partial":`))
	return errors.New("encoder exploded")
}

// lockedBuffer is a concurrency-safe bytes.Buffer.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// denyLimiter denies every request.
type denyLimiter struct{}

func (denyLimiter) Allow(string) (bool, time.Duration) { return false, 3 * time.Second }

type env struct {
	handler     http.Handler
	secLog      *lockedBuffer
	appLog      *lockedBuffer
	maintenance *atomic.Bool
}

type envConfig struct {
	api      gen.StrictServerInterface
	resolver middleware.TenantResolver
	opts     []Option
	trusted  func(netip.Addr) bool
	sessions DepositSessions
	idle     time.Duration
	// downloadIdle is Deps.DownloadIdleTimeout.
	downloadIdle time.Duration
}

func newEnv(t *testing.T, c envConfig) *env {
	t.Helper()
	e := &env{secLog: &lockedBuffer{}, appLog: &lockedBuffer{}, maintenance: new(atomic.Bool)}
	ok := health.CheckerFunc(func(context.Context) error { return nil })
	if c.resolver == nil {
		c.resolver = fakeResolver{}
	}
	e.handler = New(Deps{
		TrustedProxy: c.trusted,
		Resolver:     c.resolver,
		SecurityLog:  securitylog.New(e.secLog),
		Health: &health.Service{
			Database:  health.Check{Checker: ok},
			Antivirus: health.Check{Checker: ok},
			Storage:   health.Check{Checker: ok},
		},
		Maintenance:         e.maintenance,
		API:                 c.api,
		Sessions:            c.sessions,
		UploadIdleTimeout:   c.idle,
		DownloadIdleTimeout: c.downloadIdle,
		Spec:                []byte("openapi: 3.1.0\n"),
		Logger:              slog.New(slog.NewJSONHandler(e.appLog, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}, c.opts...)
	return e
}

func (e *env) do(t *testing.T, method, target, host string, body io.Reader, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	req.Host = host
	req.RemoteAddr = "192.0.2.10:4242"
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

// decodeProblem checks rec is a Problem with code and the request id as
// instance, and that the security headers are present.
func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, code problem.Code) problem.Problem {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d; body %s", rec.Code, status, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != problem.ContentType {
		t.Fatalf("Content-Type %q", ct)
	}
	var p problem.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("invalid problem %q: %v", rec.Body.String(), err)
	}
	if p.Code != code || p.Status != status {
		t.Fatalf("problem %+v, want %s", p, code)
	}
	id := rec.Header().Get(middleware.HeaderRequestID)
	if id == "" || p.Instance != id {
		t.Errorf("instance %q, request id %q", p.Instance, id)
	}
	assertSecurityHeaders(t, rec)
	return p
}

func assertSecurityHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Permissions-Policy"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing security header %s", h)
		}
	}
}

func TestVersionUnderTenant(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	rec := e.do(t, http.MethodGet, "/api/v1/version", hostA, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var v gen.VersionInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.ApiVersion != gen.V1 || v.Version == "" {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	assertSecurityHeaders(t, rec)
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
}

func TestUnknownHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	rec := e.do(t, http.MethodGet, "/api/v1/version", hostUnknown, nil)
	decodeProblem(t, rec, http.StatusMisdirectedRequest, problem.CodeUnknownTenant)
	line := e.secLog.String()
	if !strings.Contains(line, " ip=192.0.2.10 tenant=- event=unknown_fqdn host=\""+hostUnknown+"\"\n") {
		t.Errorf("security log %q", line)
	}
}

func TestUnknownHostThrottled(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{opts: []Option{WithUnknownHostLimiter(denyLimiter{})}})
	rec := e.do(t, http.MethodGet, "/api/v1/version", hostUnknown, nil)
	decodeProblem(t, rec, http.StatusTooManyRequests, problem.CodeRateLimited)
	if !strings.Contains(e.secLog.String(), "event=rate_limited scope=\"unknown_host\"") {
		t.Errorf("security log %q", e.secLog.String())
	}
}

func TestOutsideTenantRoutes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	// No tenant needed, even with an unknown host.
	rec := e.do(t, http.MethodGet, "/healthz", hostUnknown, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"maintenance":false`) {
		t.Fatalf("healthz %d %s", rec.Code, rec.Body.String())
	}
	assertSecurityHeaders(t, rec)
	e.maintenance.Store(true)
	rec = e.do(t, http.MethodGet, "/healthz", hostUnknown, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"maintenance":true`) {
		t.Fatalf("healthz in maintenance %d %s", rec.Code, rec.Body.String())
	}

	rec = e.do(t, http.MethodGet, "/api/openapi.yaml", hostUnknown, nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != public.SpecContentType || rec.Body.String() != "openapi: 3.1.0\n" {
		t.Fatalf("spec %d %q", rec.Code, rec.Body.String())
	}
	assertSecurityHeaders(t, rec)
	if e.secLog.String() != "" {
		t.Errorf("unexpected security events %q", e.secLog.String())
	}
}

func TestNotFound(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	tests := []struct {
		name, method, target, host string
	}{
		{"root", http.MethodGet, "/", hostA},
		{"bare api base", http.MethodGet, "/api/v1", hostA},
		{"api base with slash", http.MethodGet, "/api/v1/", hostA},
		{"bare api prefix", http.MethodGet, "/api", hostA},
		{"double slash under api", http.MethodGet, "/api/v1//version", hostA},
		{"dot segment under api", http.MethodGet, "/api/v1/x/../version", hostA},
		{"unclean spec path", http.MethodGet, "/api//openapi.yaml", hostA},
		{"trailing slash on health", http.MethodGet, "/healthz/", hostA},
		{"unknown outside api", http.MethodGet, "/nope", hostA},
		{"unknown api path", http.MethodGet, "/api/v1/nope", hostA},
		{"stub operation", http.MethodGet, "/api/v1/tenant", hostA},
		{"stub with path parameter", http.MethodGet, "/api/v1/admin/tenants/ten_x", hostA},
		{"unknown api path under known prefix", http.MethodPost, "/api/v1/version/x", hostA},
		{"stub with JSON body", http.MethodPost, "/api/v1/admin/tenants", hostA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var body io.Reader
			if tt.method == http.MethodPost {
				body = strings.NewReader(`{}`)
			}
			rec := e.do(t, tt.method, tt.target, tt.host, body, "Content-Type", "application/json")
			decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
		})
	}
}

func TestUnknownHostOnEveryPath(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, method, target string }{
		{"unknown api path", http.MethodGet, "/api/v1/nope"},
		{"root", http.MethodGet, "/"},
		{"outside api", http.MethodGet, "/wp-login.php"},
		{"bare api base", http.MethodGet, "/api/v1"},
		{"method not allowed", http.MethodDelete, "/api/v1/version"},
		{"would be a clean-path redirect", http.MethodGet, "/x/../y"},
		{"unclean health path", http.MethodGet, "//healthz"},
		{"health with trailing slash", http.MethodGet, "/healthz/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, envConfig{})
			rec := e.do(t, tt.method, tt.target, hostUnknown, nil)
			decodeProblem(t, rec, http.StatusMisdirectedRequest, problem.CodeUnknownTenant)
			if !strings.Contains(e.secLog.String(), "event=unknown_fqdn") {
				t.Errorf("security log %q", e.secLog.String())
			}
		})
	}
}

func TestIsTenantFree(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		HealthPath: true, SpecPath: true,
		"/healthz/": false, "//healthz": false, "/api/v1/healthz": false, "/": false, "": false,
	}
	for p, want := range cases {
		if got := isTenantFree(p); got != want {
			t.Errorf("isTenantFree(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestCleanPath(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"": "/", "/": "/", "a": "/a", "/a//b": "/a/b", "/a/./b/": "/a/b/", "/a/../b": "/b", "/a/b/": "/a/b/", "//": "/",
	}
	for in, want := range cases {
		if got := cleanPath(in); got != want {
			t.Errorf("cleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResponseErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		err     error
		status  int
		code    problem.Code
		logged  bool
		retryAf string
	}{
		{"problem", problem.New(problem.CodeForbidden), http.StatusForbidden, problem.CodeForbidden, false, ""},
		{"wrapped problem", fmt.Errorf("ctx: %w", problem.New(problem.CodeTransferGone)), http.StatusGone, problem.CodeTransferGone, false, ""},
		{"unknown error", errors.New("secret detail"), http.StatusInternalServerError, problem.CodeInternalError, true, ""},
		{"body too large", fmt.Errorf("read: %w", &http.MaxBytesError{Limit: 1}), http.StatusRequestEntityTooLarge, problem.CodePayloadTooLarge, false, ""},
		{"maintenance problem", problem.New(problem.CodeMaintenance, problem.WithRetryAfter(time.Minute)), http.StatusServiceUnavailable, problem.CodeMaintenance, false, "60"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, envConfig{api: fakeAPI{Server: public.NewServer(), tenantErr: tt.err}})
			rec := e.do(t, http.MethodGet, "/api/v1/tenant", hostA, nil)
			decodeProblem(t, rec, tt.status, tt.code)
			if strings.Contains(rec.Body.String(), "secret detail") {
				t.Error("internal error detail leaked to the client")
			}
			logs := e.appLog.String()
			if got := strings.Contains(logs, `"level":"ERROR"`) && strings.Contains(logs, "secret detail"); got != tt.logged {
				t.Errorf("error logged = %v, want %v; logs %s", got, tt.logged, logs)
			}
			if tt.logged && !strings.Contains(logs, rec.Header().Get(middleware.HeaderRequestID)) {
				t.Errorf("log lacks the request id: %s", logs)
			}
			if got := rec.Header().Get("Retry-After"); got != tt.retryAf {
				t.Errorf("Retry-After %q, want %q", got, tt.retryAf)
			}
		})
	}
}

func TestResponseErrorAfterStart(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{api: fakeAPI{Server: public.NewServer(), visitFail: true}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenant", nil)
	req.Host = hostA
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if v := recover(); v != http.ErrAbortHandler { //nolint:errorlint // net/http compares the sentinel the same way
				t.Errorf("recovered %v, want http.ErrAbortHandler", v)
			}
		}()
		e.handler.ServeHTTP(rec, req)
	}()
	if rec.Code != http.StatusOK || rec.Body.String() != `{"partial":` {
		t.Errorf("response altered after it started: %d %q", rec.Code, rec.Body.String())
	}
	logs := e.appLog.String()
	if !strings.Contains(logs, "response failed after it started") || !strings.Contains(logs, "encoder exploded") ||
		!strings.Contains(logs, rec.Header().Get(middleware.HeaderRequestID)) || !strings.Contains(logs, `"level":"ERROR"`) {
		t.Errorf("logs %s", logs)
	}
}

func TestResponseErrorAfterStartClientGone(t *testing.T) {
	t.Parallel()
	var logs lockedBuffer
	h := errorHandlers{logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	middleware.Recover(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		defer func() {
			if v := recover(); v != http.ErrAbortHandler { //nolint:errorlint // sentinel comparison as in net/http
				t.Errorf("recovered %v", v)
			}
		}()
		h.responseError(w, r, context.Canceled)
	})).ServeHTTP(rec, req)
	if !strings.Contains(logs.String(), `"level":"DEBUG"`) {
		t.Errorf("client disconnection not logged at debug level: %s", logs.String())
	}
}

func TestResponseErrorAfterStartIdleTimeout(t *testing.T) {
	t.Parallel()
	var logs lockedBuffer
	h := errorHandlers{logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	middleware.Recover(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		defer func() {
			if v := recover(); v != http.ErrAbortHandler { //nolint:errorlint // sentinel comparison as in net/http
				t.Errorf("recovered %v", v)
			}
		}()
		h.responseError(w, r, fmt.Errorf("write body: %w", os.ErrDeadlineExceeded))
	})).ServeHTTP(rec, req)
	if got := logs.String(); !strings.Contains(got, `"level":"INFO"`) || strings.Contains(got, `"level":"ERROR"`) {
		t.Errorf("idle-timeout cut not logged at info level: %s", got)
	}
}

func TestSharedProblemNotMutated(t *testing.T) {
	t.Parallel()
	shared := problem.New(problem.CodeForbidden)
	e := newEnv(t, envConfig{api: fakeAPI{Server: public.NewServer(), tenantErr: shared}})
	e.do(t, http.MethodGet, "/api/v1/tenant", hostA, nil)
	if shared.Instance != "" {
		t.Errorf("shared problem mutated: instance %q", shared.Instance)
	}
}

func TestPanicRecovered(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{api: fakeAPI{Server: public.NewServer(), panicky: true}})
	rec := e.do(t, http.MethodGet, "/api/v1/tenant", hostA, nil)
	decodeProblem(t, rec, http.StatusInternalServerError, problem.CodeInternalError)
}

func TestResolverFailure(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{resolver: fakeResolver{err: errors.New("db down")}})
	rec := e.do(t, http.MethodGet, "/api/v1/version", hostA, nil)
	decodeProblem(t, rec, http.StatusInternalServerError, problem.CodeInternalError)
}

func TestGlobalRateLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{opts: []Option{WithGlobalLimiter(denyLimiter{})}})
	rec := e.do(t, http.MethodGet, "/healthz", hostA, nil)
	decodeProblem(t, rec, http.StatusTooManyRequests, problem.CodeRateLimited)
	if rec.Header().Get("Retry-After") != "3" {
		t.Errorf("Retry-After %q", rec.Header().Get("Retry-After"))
	}
	if !strings.Contains(e.secLog.String(), "ip=192.0.2.10 tenant=- event=rate_limited scope=\"global\"") {
		t.Errorf("security log %q", e.secLog.String())
	}
}

func TestDefaultGlobalLimiter(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	// The bucket refills at GlobalRate per second: on a loaded machine a
	// burst of GlobalBurst+20 requests may take long enough to be refilled.
	// Keep sending (well above GlobalRate in practice) until one is refused.
	const attempts = 20 * GlobalBurst
	for range attempts {
		if e.do(t, http.MethodGet, "/api/openapi.yaml", hostA, nil).Code == http.StatusTooManyRequests {
			return
		}
	}
	t.Errorf("the default global limiter never refused any of %d requests", attempts)
}

func TestTrustedProxy(t *testing.T) {
	t.Parallel()
	trusted := func(a netip.Addr) bool { return a == netip.MustParseAddr("192.0.2.10") }
	e := newEnv(t, envConfig{trusted: trusted})
	e.do(t, http.MethodGet, "/api/v1/version", hostUnknown, nil, "X-Forwarded-For", "198.51.100.7")
	if !strings.Contains(e.secLog.String(), "ip=198.51.100.7 ") {
		t.Errorf("forwarded IP not used: %q", e.secLog.String())
	}

	// Without a trusted proxy the header is ignored.
	e = newEnv(t, envConfig{})
	e.do(t, http.MethodGet, "/api/v1/version", hostUnknown, nil, "X-Forwarded-For", "198.51.100.7")
	if !strings.Contains(e.secLog.String(), "ip=192.0.2.10 ") {
		t.Errorf("spoofed IP used: %q", e.secLog.String())
	}
}

func TestMaintenance(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	e.maintenance.Store(true)
	rec := e.do(t, http.MethodPost, "/api/v1/deposit-sessions", hostA, strings.NewReader(`{}`), "Content-Type", "application/json")
	p := decodeProblem(t, rec, http.StatusServiceUnavailable, problem.CodeMaintenance)
	if rec.Header().Get("Retry-After") != "300" || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 300 {
		t.Errorf("Retry-After %q, body %v", rec.Header().Get("Retry-After"), p.RetryAfterSeconds)
	}
	if strings.Contains(e.appLog.String(), `"level":"ERROR"`) {
		t.Errorf("maintenance refusal logged as an error: %s", e.appLog.String())
	}
	// Non-deposit operations keep working.
	if rec := e.do(t, http.MethodGet, "/api/v1/version", hostA, nil); rec.Code != http.StatusOK {
		t.Errorf("version in maintenance: %d", rec.Code)
	}
	if rec := e.do(t, http.MethodGet, "/api/v1/tenant", hostA, nil); rec.Code != http.StatusNotFound {
		t.Errorf("stub in maintenance: %d", rec.Code)
	}
	e.maintenance.Store(false)
	// The operation is reached again: its deposit session is checked.
	rec = e.do(t, http.MethodPost, "/api/v1/transfers", hostA, strings.NewReader(`{}`), "Content-Type", "application/json")
	decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)
}

func TestMaintenanceTusPatchBodyless(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	e.maintenance.Store(true)
	rec := e.do(t, http.MethodPatch, "/api/v1/uploads/upl_x", hostA, strings.NewReader("bytes"),
		"Tus-Resumable", "1.0.0", "Upload-Offset", "0", "Content-Type", "application/offset+octet-stream")
	if rec.Code != http.StatusServiceUnavailable || rec.Body.Len() != 0 {
		t.Fatalf("tus PATCH in maintenance: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") != "300" || rec.Header().Get("Tus-Resumable") != tusVersion {
		t.Errorf("headers %v", rec.Header())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "" {
		t.Errorf("Content-Type %q on a bodyless answer", ct)
	}
	assertSecurityHeaders(t, rec)
}

func TestMaintenanceOperationsExist(t *testing.T) {
	t.Parallel()
	iface := reflect.TypeFor[gen.StrictServerInterface]()
	mux := http.NewServeMux()
	gen.HandlerWithOptions(gen.NewStrictHandler(public.NewServer(), nil), gen.StdHTTPServerOptions{BaseURL: APIBaseURL, BaseRouter: mux})
	wildcard := regexp.MustCompile(`\{[A-Za-z]+\}`)
	// The operation behind each blocked pattern (Go method name of
	// gen.StrictServerInterface).
	ops := map[string]string{
		http.MethodPost + " " + APIBaseURL + "/deposit-sessions":                "StartDepositSession",
		http.MethodPost + " " + APIBaseURL + "/transfers":                       "CreateTransfer",
		http.MethodPost + " " + APIBaseURL + "/transfers/{transferId}/finalize": "FinalizeTransfer",
		http.MethodPatch + " " + APIBaseURL + "/uploads/{uploadId}":             "AppendUploadChunk",
		http.MethodPost + " " + APIBaseURL + "/invitations":                     "CreateInvitation",
	}
	if len(ops) != len(maintenanceBlocked) {
		t.Fatalf("%d blocked patterns, %d expected operations", len(maintenanceBlocked), len(ops))
	}
	for pattern := range maintenanceBlocked {
		op, known := ops[pattern]
		if !known {
			t.Errorf("unexpected maintenance-blocked pattern %q", pattern)
			continue
		}
		if _, ok := iface.MethodByName(op); !ok {
			t.Errorf("maintenance-blocked operation %q is not an operation of the API", op)
		}
		method, path, _ := strings.Cut(pattern, " ")
		req := httptest.NewRequest(method, wildcard.ReplaceAllString(path, "x"), nil)
		h, got := mux.Handler(req)
		if got != pattern {
			t.Errorf("pattern %q is not a route (matched %q)", pattern, got)
			continue
		}
		name := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
		if !strings.Contains(name, "."+op+"-") {
			t.Errorf("pattern %q routes to %s, not %s", pattern, name, op)
		}
	}
}

func TestMaintenanceBeforeBody(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	e.maintenance.Store(true)
	big := strings.Repeat(" ", int(middleware.DefaultJSONBodyLimit)+10)
	tests := []struct {
		name, body, contentType string
		reader                  io.Reader
	}{
		{"malformed", "{", "application/json", nil},
		{"oversized", big, "application/json", nil},
		{"oversized chunked", "", "application/json", io.MultiReader(strings.NewReader(big))},
		{"wrong media type", "x", "text/plain", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := tt.reader
			if body == nil {
				body = strings.NewReader(tt.body)
			}
			rec := e.do(t, http.MethodPost, "/api/v1/transfers", hostA, body, "Content-Type", tt.contentType)
			decodeProblem(t, rec, http.StatusServiceUnavailable, problem.CodeMaintenance)
		})
	}
}

func TestRequireJSON(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	rec := e.do(t, http.MethodPost, "/api/v1/deposit-sessions", hostA, strings.NewReader("{}"), "Content-Type", "text/plain")
	decodeProblem(t, rec, http.StatusUnsupportedMediaType, problem.CodeUnsupportedMediaType)

	// JSON merge patch is accepted (the stub then answers 404).
	rec = e.do(t, http.MethodPatch, "/api/v1/admin/tenants/ten_x", hostA, strings.NewReader("{}"), "Content-Type", "application/merge-patch+json")
	decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)

	// Branding image uploads are exempt.
	rec = e.do(t, http.MethodPut, "/api/v1/admin/tenants/ten_x/branding/logo", hostA, strings.NewReader("PNG-bytes"), "Content-Type", "image/png")
	if rec.Code == http.StatusUnsupportedMediaType {
		t.Errorf("branding image refused: %s", rec.Body.String())
	}
}

func TestBrandingBodyLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	const target = "/api/v1/admin/tenants/ten_x/branding/logo"
	// Above the JSON limit but within the image limit: reaches the stub.
	rec := e.do(t, http.MethodPut, target, hostA, strings.NewReader(strings.Repeat("x", int(middleware.DefaultJSONBodyLimit)+1)), "Content-Type", "image/png")
	decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
	// Above the image limit: refused upfront.
	rec = e.do(t, http.MethodPut, target, hostA, strings.NewReader(strings.Repeat("x", int(middleware.ImageBodyLimit)+1)), "Content-Type", "image/png")
	decodeProblem(t, rec, http.StatusRequestEntityTooLarge, problem.CodePayloadTooLarge)
}

func TestBodyLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	big := strings.Repeat(" ", int(middleware.DefaultJSONBodyLimit)+10) + "{}"

	// Announced Content-Length above the limit: refused upfront.
	rec := e.do(t, http.MethodPost, "/api/v1/deposit-sessions", hostA, strings.NewReader(big), "Content-Type", "application/json")
	decodeProblem(t, rec, http.StatusRequestEntityTooLarge, problem.CodePayloadTooLarge)

	// Unknown length (chunked): detected while decoding.
	rec = e.do(t, http.MethodPost, "/api/v1/deposit-sessions", hostA, io.MultiReader(strings.NewReader(big)), "Content-Type", "application/json")
	decodeProblem(t, rec, http.StatusRequestEntityTooLarge, problem.CodePayloadTooLarge)

	// Malformed JSON.
	rec = e.do(t, http.MethodPost, "/api/v1/deposit-sessions", hostA, strings.NewReader(`{`), "Content-Type", "application/json")
	decodeProblem(t, rec, http.StatusBadRequest, problem.CodeValidationFailed)

	// tus PATCH is exempt: it reaches the session check (a bodyless tus
	// 401), not 413.
	rec = e.do(t, http.MethodPatch, "/api/v1/uploads/upl_x", hostA, strings.NewReader(big),
		"Tus-Resumable", "1.0.0", "Upload-Offset", "0", "Content-Type", "application/offset+octet-stream")
	if rec.Code != http.StatusUnauthorized || rec.Body.Len() != 0 {
		t.Errorf("tus PATCH: %d %s", rec.Code, rec.Body.String())
	}
	assertSecurityHeaders(t, rec)
	if rec.Header().Get(middleware.HeaderRequestID) == "" {
		t.Error("tus 401 lacks X-Request-Id")
	}
}

func TestRoutePolicies(t *testing.T) {
	t.Parallel()
	cases := map[string]routePolicy{
		"PATCH /api/v1/uploads/{uploadId}": {
			bodyLimit: middleware.NoBodyLimit, rawBody: true, depositSession: true, csrf: true, tus: true, idleBody: true,
		},
		"HEAD /api/v1/uploads/{uploadId}":                       tusPolicy(false),
		"DELETE /api/v1/uploads/{uploadId}":                     tusPolicy(true),
		"OPTIONS /api/v1/uploads":                               defaultPolicy,
		"GET /api/v1/downloads/{linkToken}/files/{fileId}":      {bodyLimit: middleware.DefaultJSONBodyLimit, idleWrite: true},
		"GET /api/v1/downloads/{linkToken}/archive":             {bodyLimit: middleware.DefaultJSONBodyLimit, idleWrite: true},
		"PUT /api/v1/admin/tenants/{tenantId}/branding/{asset}": {bodyLimit: middleware.ImageBodyLimit, rawBody: true, deadline: ImageDeadline},
		"GET /api/v1/tenant/assets/{asset}":                     {bodyLimit: middleware.DefaultJSONBodyLimit, deadline: ImageDeadline},
		"PUT /api/v1/admin/tenants/{tenantId}/branding":         defaultPolicy,
		"GET /api/v1/downloads/{linkToken}":                     defaultPolicy,
		"POST /api/v1/transfers":                                sessionPolicy(true),
		"GET /api/v1/transfers/{transferId}":                    sessionPolicy(false),
		"":                                                      defaultPolicy,
	}
	for pattern, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Pattern = pattern
		if got := policyOf(r); got != want {
			t.Errorf("policyOf(%q) = %+v, want %+v", pattern, got, want)
		}
	}
	// Every pattern of the table is a route of the API router.
	mux := http.NewServeMux()
	gen.HandlerWithOptions(gen.NewStrictHandler(public.NewServer(), nil), gen.StdHTTPServerOptions{BaseURL: APIBaseURL, BaseRouter: mux})
	wildcard := regexp.MustCompile(`\{[A-Za-z]+\}`)
	for pattern := range routePolicies {
		method, path, _ := strings.Cut(pattern, " ")
		if _, got := mux.Handler(httptest.NewRequest(method, wildcard.ReplaceAllString(path, "x"), nil)); got != pattern {
			t.Errorf("route policy pattern %q is not a route (matched %q)", pattern, got)
		}
	}
}

// deadlineWriter records the deadlines set through http.ResponseController.
type deadlineWriter struct {
	*httptest.ResponseRecorder
	read, write time.Time
	err         error
}

func (d *deadlineWriter) SetReadDeadline(t time.Time) error  { d.read = t; return d.err }
func (d *deadlineWriter) SetWriteDeadline(t time.Time) error { d.write = t; return d.err }

func TestDeadlineMiddleware(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern string
		want    time.Duration
	}{
		{"POST /api/v1/transfers", RequestDeadline},
		{"HEAD /api/v1/uploads/{uploadId}", RequestDeadline},
		{"PUT /api/v1/admin/tenants/{tenantId}/branding/{asset}", ImageDeadline},
		{"PATCH /api/v1/uploads/{uploadId}", 0},
		{"GET /api/v1/downloads/{linkToken}/files/{fileId}", 0},
		{"GET /api/v1/downloads/{linkToken}/archive", 0},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := deadlineMiddleware(nil)(next)
	for _, tt := range tests {
		w := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Pattern = tt.pattern
		before := time.Now()
		h.ServeHTTP(w, r)
		after := time.Now()
		if w.Code != http.StatusNoContent {
			t.Errorf("%s: next not called", tt.pattern)
		}
		if tt.want == 0 {
			if !w.read.IsZero() || !w.write.IsZero() {
				t.Errorf("%s: streaming route got deadlines %v %v", tt.pattern, w.read, w.write)
			}
			continue
		}
		for name, d := range map[string]time.Time{"read": w.read, "write": w.write} {
			if d.Before(before.Add(tt.want)) || d.After(after.Add(tt.want)) {
				t.Errorf("%s: %s deadline %v, want now+%v", tt.pattern, name, d, tt.want)
			}
		}
	}

	// A writer without deadline support is accepted silently; another
	// failure is logged and the request still proceeds.
	var logs lockedBuffer
	h = deadlineMiddleware(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))(next)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Pattern = "POST /api/v1/transfers"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent || logs.String() != "" {
		t.Errorf("unsupported deadlines: %d, logs %q", rec.Code, logs.String())
	}
	w := &deadlineWriter{ResponseRecorder: httptest.NewRecorder(), err: errors.New("conn closed")}
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || !strings.Contains(logs.String(), "cannot set request deadline") {
		t.Errorf("failing deadlines: %d, logs %q", w.Code, logs.String())
	}
}

// deadlineSpy forwards to a real connection and records which routes got a
// write deadline.
type deadlineSpy struct {
	http.ResponseWriter
	set *atomic.Bool
}

func (d *deadlineSpy) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		d.set.Store(true)
	}
	return http.NewResponseController(d.ResponseWriter).SetWriteDeadline(t)
}

func (d *deadlineSpy) Unwrap() http.ResponseWriter { return d.ResponseWriter }

// TestDeadlineOnRealConnection checks, through the whole chain and a real
// connection, that every operation gets a write deadline: a fixed one for
// an ordinary operation, an idle one, moved forward by every write, for a
// download.
func TestDeadlineOnRealConnection(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	tests := []struct {
		target string
		want   bool
	}{
		{"/api/v1/version", true},
		// A download has no fixed deadline but an idle write deadline,
		// set before the operation runs (here it fails: no service).
		{"/api/v1/downloads/dl_x/archive", true},
	}
	for _, tt := range tests {
		var set atomic.Bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Host = hostA
			e.handler.ServeHTTP(&deadlineSpy{ResponseWriter: w, set: &set}, r)
		}))
		resp, err := srv.Client().Get(srv.URL + tt.target)
		if err != nil {
			srv.Close()
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		srv.Close()
		if set.Load() != tt.want {
			t.Errorf("%s: status %d, deadline set %v, want %v", tt.target, resp.StatusCode, set.Load(), tt.want)
		}
	}
}

func TestParamErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	rec := e.do(t, http.MethodGet, "/api/v1/admin/tenants?limit=abc", hostA, nil)
	p := decodeProblem(t, rec, http.StatusBadRequest, problem.CodeValidationFailed)
	if len(p.Errors) != 1 || p.Errors[0].Field != "limit" || p.Errors[0].Code != fieldInvalidFormat {
		t.Errorf("field errors %+v", p.Errors)
	}
	// tus operations answer parameter errors without body: 412 for the
	// Tus-Resumable header, 400 otherwise.
	rec = e.do(t, http.MethodPatch, "/api/v1/uploads/upl_x", hostA, strings.NewReader("x"))
	if rec.Code != http.StatusPreconditionFailed || rec.Body.Len() != 0 || rec.Header().Get("Tus-Version") != "1.0.0" ||
		rec.Header().Get("Tus-Resumable") != "1.0.0" {
		t.Errorf("tus PATCH without Tus-Resumable: %d %v %q", rec.Code, rec.Header(), rec.Body)
	}
	rec = e.do(t, http.MethodPatch, "/api/v1/uploads/upl_x", hostA, strings.NewReader("x"), "Tus-Resumable", "1.0.0")
	if rec.Code != http.StatusBadRequest || rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "" {
		t.Errorf("tus PATCH without Upload-Offset: %d %v %q", rec.Code, rec.Header(), rec.Body)
	}
}

func TestFieldErrorOf(t *testing.T) {
	t.Parallel()
	inner := errors.New("x")
	tests := []struct {
		err   error
		field string
		code  string
	}{
		{&gen.RequiredParamError{ParamName: "a"}, "a", fieldRequired},
		{&gen.RequiredHeaderError{ParamName: "b", Err: inner}, "b", fieldRequired},
		{&gen.InvalidParamFormatError{ParamName: "c", Err: inner}, "c", fieldInvalidFormat},
		{&gen.UnmarshalingParamError{ParamName: "d", Err: inner}, "d", fieldInvalidFormat},
		{&gen.UnescapedCookieParamError{ParamName: "e", Err: inner}, "e", fieldInvalidFormat},
		{&gen.TooManyValuesForParamError{ParamName: "f", Count: 2}, "f", fieldTooManyValues},
	}
	for _, tt := range tests {
		fe, ok := fieldErrorOf(fmt.Errorf("wrapped: %w", tt.err))
		if !ok || fe.Field != tt.field || fe.Code != tt.code {
			t.Errorf("fieldErrorOf(%T) = %+v, %v", tt.err, fe, ok)
		}
	}
	if _, ok := fieldErrorOf(inner); ok {
		t.Error("fieldErrorOf(plain error) = ok")
	}
	// A plain error still yields a 400 without field errors.
	rec := httptest.NewRecorder()
	errorHandlers{logger: slog.New(slog.DiscardHandler)}.paramError(rec, httptest.NewRequest(http.MethodGet, "/", nil), inner)
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), `"errors"`) {
		t.Errorf("paramError(plain) = %d %s", rec.Code, rec.Body.String())
	}
}

// failWriter fails every write.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestSecurityEventsWriteFailure(t *testing.T) {
	t.Parallel()
	var logs lockedBuffer
	ev := NewSecurityEvents(securitylog.New(failWriter{}), slog.New(slog.NewJSONHandler(&logs, nil)))
	ev.UnknownFQDN(context.Background(), netip.MustParseAddr("192.0.2.1"), "x.example.com")
	if !strings.Contains(logs.String(), "security log write failed") || !strings.Contains(logs.String(), "unknown_fqdn") {
		t.Errorf("logs %q", logs.String())
	}
	// A nil logger discards the failure report.
	NewSecurityEvents(securitylog.New(failWriter{}), nil).RateLimited(context.Background(), netip.Addr{}, "", ScopeGlobal)
}

func TestSecurityEventsRateLimitedWithTenant(t *testing.T) {
	t.Parallel()
	var buf lockedBuffer
	NewSecurityEvents(securitylog.New(&buf), nil).RateLimited(context.Background(), netip.MustParseAddr("192.0.2.1"), hostA, "codes")
	if !strings.Contains(buf.String(), "ip=192.0.2.1 tenant="+hostA+" event=rate_limited scope=\"codes\"") {
		t.Errorf("line %q", buf.String())
	}
}

func TestNewDefaultsAndPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("New without dependencies did not panic")
		}
	}()
	// Defaults: nil logger, trusted, maintenance and API are accepted.
	h := New(Deps{
		Resolver:    fakeResolver{},
		SecurityLog: securitylog.New(io.Discard),
		Health:      &health.Service{},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	req.Host = hostA
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("default handler: %d", rec.Code)
	}
	New(Deps{})
}

func TestMethodNotAllowed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	tests := []struct {
		name, method, target, host string
		allow                      []string
	}{
		{"spec", http.MethodPost, "/api/openapi.yaml", hostUnknown, []string{"GET", "HEAD"}},
		{"api version", http.MethodDelete, "/api/v1/version", hostA, []string{"GET", "HEAD"}},
		{"api transfer", http.MethodPut, "/api/v1/transfers/trf_x", hostA, []string{"DELETE", "GET"}},
		{"health", http.MethodPost, "/healthz", hostUnknown, []string{"GET", "HEAD"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := e.do(t, tt.method, tt.target, tt.host, nil)
			decodeProblem(t, rec, http.StatusMethodNotAllowed, problem.CodeMethodNotAllowed)
			allow := strings.Join(rec.Header().Values("Allow"), ",")
			for _, m := range tt.allow {
				if !strings.Contains(allow, m) {
					t.Errorf("Allow %q lacks %s", allow, m)
				}
			}
		})
	}
	// Under an unknown host, the tenant is resolved before routing.
	rec := e.do(t, http.MethodDelete, "/api/v1/version", hostUnknown, nil)
	decodeProblem(t, rec, http.StatusMisdirectedRequest, problem.CodeUnknownTenant)
}

func TestNoRedirectUnderAPI(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	for _, target := range []string{"/api/v1", "/api", "/api/v1//version", "/api/./v1/version", "/api/v1/version/", "/api/v1/x/../version"} {
		rec := e.do(t, http.MethodGet, target, hostA, nil)
		decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
	}
}

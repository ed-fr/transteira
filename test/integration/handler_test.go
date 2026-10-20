package integration_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/api"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/httpserver"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// The tests of this file drive the handler built by httpserver.New directly,
// with the real store, resolver and security log, to reach states a real
// client cannot produce over TCP: arbitrary bytes in Host (net/http refuses
// them on the wire), a failing database, a panicking operation.

// secretMarker stands for an internal detail (DSN, SQL) that must never
// reach a client (T-98).
const secretMarker = "postgres://owner:hunter2@db/secret"

// failingResolver always fails with an internal error.
type failingResolver struct{}

func (failingResolver) Resolve(context.Context, string) (*tenant.Tenant, error) {
	return nil, errors.New("resolve: dial " + secretMarker + ": connection refused")
}

// panickingAPI is the real API whose getVersion panics.
type panickingAPI struct{ *public.Server }

func (panickingAPI) GetVersion(context.Context, gen.GetVersionRequestObject) (gen.GetVersionResponseObject, error) {
	panic("boom: " + secretMarker)
}

// handlerEnv is a handler with a real security log file.
type handlerEnv struct {
	handler http.Handler
	logPath string
	log     *securitylog.Logger
}

func newHandler(t *testing.T, resolver interface {
	Resolve(context.Context, string) (*tenant.Tenant, error)
}, apiImpl gen.StrictServerInterface,
) *handlerEnv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "security.log")
	secLog, err := securitylog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secLog.Close() })
	ok := health.Check{Checker: health.CheckerFunc(func(context.Context) error { return nil })}
	h := httpserver.New(httpserver.Deps{
		Resolver:    resolver,
		SecurityLog: secLog,
		Health:      &health.Service{Database: ok, Antivirus: ok, Storage: ok},
		API:         apiImpl,
		Spec:        api.OpenAPISpec,
	})
	return &handlerEnv{handler: h, logPath: path, log: secLog}
}

func (h *handlerEnv) serve(r *http.Request) response {
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return response{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
}

func (h *handlerEnv) lines(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(h.logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSuffix(string(b), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// TestInternalErrors checks the 500 answers: resolver failure and panic in
// an operation give a 500 internal-error Problem with every security header
// and no internal detail.
func TestInternalErrors(t *testing.T) {
	t.Parallel()

	t.Run("resolver failure", func(t *testing.T) {
		h := newHandler(t, failingResolver{}, nil)
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/version", nil)
		r.Host = hostA
		resp := h.serve(r)
		expectProblem(t, resp, http.StatusInternalServerError, "internal-error")
		expectSecurityHeaders(t, "500", resp.header)
		if strings.Contains(string(resp.body), "hunter2") || strings.Contains(string(resp.body), "refused") {
			t.Errorf("500 leaks the cause: %s", resp.body)
		}
		if resp.header.Get("Cache-Control") != "no-store" {
			t.Errorf("Cache-Control = %q", resp.header.Get("Cache-Control"))
		}
		if n := len(h.lines(t)); n != 0 {
			t.Errorf("a database failure is not an unknown host: %d security lines", n)
		}
	})

	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a, _ := createTenants(t, e)
		db, err := store.Open(t.Context(), e.Config())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })

		t.Run("panic in an operation", func(t *testing.T) {
			h := newHandler(t, tenant.NewResolver(db.Tenants()), panickingAPI{public.NewServer()})
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/version", nil)
			r.Host = a.FQDN
			resp := h.serve(r)
			expectProblem(t, resp, http.StatusInternalServerError, "internal-error")
			expectSecurityHeaders(t, "panic 500", resp.header)
			if strings.Contains(string(resp.body), "boom") {
				t.Errorf("500 leaks the panic value: %s", resp.body)
			}
		})
	})
}

// TestSecurityLogInjectionThroughHandler covers T-99 with Host values that
// net/http would refuse on the wire: whatever the bytes, exactly one line
// per request, the documented grammar, and the ip token of the peer.
func TestSecurityLogInjectionThroughHandler(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		createTenants(t, e)
		db, err := store.Open(t.Context(), e.Config())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		h := newHandler(t, tenant.NewResolver(db.Tenants()), nil)

		forged := `2026-10-20T07:41:00.123Z ip=1.2.3.4 tenant=- event=unknown_fqdn host="x"`
		hosts := []string{
			"evil.example.net\n" + forged,
			"evil.example.net\r\n" + forged,
			"evil.example.net\r" + forged,
			`evil.example.net" ip=1.2.3.4 tenant=x event=y`,
			`evil.example.net\" ip=1.2.3.4`,
			"evil.example.net\x00\x1b[2J ip=1.2.3.4",
			"evil.example.net " + forged,
			"evil.example.net\u0085" + forged,
			"evil.example.net\xff\xfe ip=1.2.3.4",
			strings.Repeat("\n"+forged, 50),
			strings.Repeat("é", 300) + "\n" + forged,
			"",
		}
		for i, host := range hosts {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/version", nil)
			r.Host = host
			// One peer per request, so that the unknown-host limiter never
			// kicks in.
			r.RemoteAddr = fmt.Sprintf("192.0.2.%d:4242", i+1)
			r.Header.Set("X-Forwarded-For", "1.2.3.4") // no trusted proxy: ignored
			expectProblem(t, h.serve(r), http.StatusMisdirectedRequest, "unknown-tenant")
		}
		lines := h.lines(t)
		if len(lines) != len(hosts) {
			t.Fatalf("security lines = %d, want %d (one per request):\n%s", len(lines), len(hosts), strings.Join(lines, "\n"))
		}
		for i, l := range parseLines(t, lines) {
			if l.ip != fmt.Sprintf("192.0.2.%d", i+1) || l.tenant != "-" || l.event != "unknown_fqdn" {
				t.Errorf("forged tokens in %q", l.raw)
			}
			if !strings.HasPrefix(l.fields, ` host="`) || strings.Count(l.fields, ` host="`) < 1 {
				t.Errorf("fields = %q, want a single quoted host", l.fields)
			}
			if len(l.raw) > 80+4*256+16 {
				t.Errorf("line of %d bytes: value not truncated before escaping", len(l.raw))
			}
		}
	})
}

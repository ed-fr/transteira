package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ed-fr/transteira/api"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
)

// testToken is a made-up monitoring token of the tests.
const testToken = "example-monitoring-token-0123456789abcdef"

// fakeEvents records the security events.
type fakeEvents struct {
	mu          sync.Mutex
	invalid     []netip.Addr
	rateLimited []string
}

func (e *fakeEvents) MetricsTokenInvalid(_ context.Context, ip netip.Addr) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalid = append(e.invalid, ip)
}

func (e *fakeEvents) RateLimited(_ context.Context, ip netip.Addr, fqdn, scope string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rateLimited = append(e.rateLimited, ip.String()+"|"+fqdn+"|"+scope)
}

func (e *fakeEvents) counts() (invalid, limited int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.invalid), len(e.rateLimited)
}

// handlerEnv is a handler under test with its fakes.
type handlerEnv struct {
	h      Handlers
	events *fakeEvents
	logs   *bytes.Buffer
	ip     netip.Addr
	now    time.Time
	mu     sync.Mutex
}

func (e *handlerEnv) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *handlerEnv) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(d)
}

// newHandlerEnv returns handlers over a collected full snapshot; mutate
// adjusts the options.
func newHandlerEnv(t *testing.T, mutate func(*HandlerOptions)) *handlerEnv {
	t.Helper()
	col := newTestCollector(fullSources(&fakeState{state: fullState()}), fullCounters())
	col.collect(t.Context())
	env := &handlerEnv{events: &fakeEvents{}, logs: &bytes.Buffer{}, ip: netip.MustParseAddr("192.0.2.10"), now: testNow}
	opts := HandlerOptions{
		Token:     config.NewSecret(testToken),
		Collector: col,
		Events:    env.events,
		ClientIP:  func(*http.Request) netip.Addr { return env.ip },
		Logger:    slog.New(slog.NewTextHandler(env.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:       env.clock,
	}
	if mutate != nil {
		mutate(&opts)
	}
	env.h = NewHandler(opts)
	t.Cleanup(func() {
		if strings.Contains(env.logs.String(), testToken) {
			t.Errorf("the token appears in the logs:\n%s", env.logs.String())
		}
	})
	return env
}

// do serves one request on h with the Authorization values auth.
func do(h http.Handler, method, target string, auth ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for _, a := range auth {
		r.Header.Add("Authorization", a)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// assertProblem checks a problem answer.
func assertProblem(t *testing.T, w *httptest.ResponseRecorder, status int, code problem.Code) problem.Problem {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", w.Code, status, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != problem.ContentType {
		t.Fatalf("Content-Type = %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	var p problem.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Code != code {
		t.Fatalf("code = %q, want %q", p.Code, code)
	}
	if strings.Contains(w.Body.String(), testToken) {
		t.Fatal("token in the answer")
	}
	return p
}

func TestHandlerTokenUnset(t *testing.T) {
	t.Parallel()
	env := newHandlerEnv(t, func(o *HandlerOptions) { o.Token = config.Secret{} })
	for _, h := range []http.Handler{env.h.Metrics, env.h.Status} {
		w := do(h, http.MethodGet, "/metrics", "Bearer "+testToken)
		p := assertProblem(t, w, http.StatusNotFound, problem.CodeNotFound)
		if want := problem.New(problem.CodeNotFound); p.Title != want.Title || p.Type != want.Type {
			t.Fatalf("404 differs from the unknown path one: %+v", p)
		}
	}
	if i, l := env.events.counts(); i+l != 0 {
		t.Fatal("events without a token")
	}
}

func TestHandlerAllowlist(t *testing.T) {
	t.Parallel()
	env := newHandlerEnv(t, func(o *HandlerOptions) {
		o.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	})
	assertProblem(t, do(env.h.Metrics, http.MethodGet, "/metrics", "Bearer wrong"), http.StatusNotFound, problem.CodeNotFound)
	if i, _ := env.events.counts(); i != 0 {
		t.Fatal("token checked before the allowlist")
	}
	for _, ip := range []string{"198.51.100.7", "::ffff:198.51.100.7", "2001:db8::1"} {
		env.ip = netip.MustParseAddr(ip)
		if w := do(env.h.Status, http.MethodGet, "/status", "Bearer "+testToken); w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", ip, w.Code)
		}
	}
}

func TestHandlerMethod(t *testing.T) {
	t.Parallel()
	env := newHandlerEnv(t, nil)
	w := do(env.h.Metrics, http.MethodPost, "/metrics", "Bearer "+testToken)
	assertProblem(t, w, http.StatusMethodNotAllowed, problem.CodeMethodNotAllowed)
	if got := w.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q", got)
	}
}

func TestHandlerUnauthenticated(t *testing.T) {
	t.Parallel()
	env := newHandlerEnv(t, nil)
	for _, auth := range [][]string{nil, {"Basic dXNlcjpwYXNz"}, {"Token " + testToken}} {
		w := do(env.h.Metrics, http.MethodGet, "/metrics?token="+testToken+"&access_token="+testToken, auth...)
		assertProblem(t, w, http.StatusUnauthorized, problem.CodeUnauthenticated)
		if got := w.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
	}
	if i, l := env.events.counts(); i+l != 0 {
		t.Fatal("events for missing headers")
	}
}

func TestHandlerInvalidAndLockout(t *testing.T) {
	t.Parallel()
	env := newHandlerEnv(t, nil)
	bad := [][]string{
		{"Bearer wrong"},
		{"Bearer"},
		{"Bearer " + testToken + "x"},
		{"Bearer " + testToken, "Bearer " + testToken}, // ambiguous
	}
	for i := range TokenFailureLimit {
		w := do(env.h.Metrics, http.MethodGet, "/metrics", bad[i%len(bad)]...)
		assertProblem(t, w, http.StatusUnauthorized, problem.CodeInvalidCredentials)
		if got := w.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
	}
	if i, _ := env.events.counts(); i != TokenFailureLimit {
		t.Fatalf("%d metrics_token_invalid events, want %d", i, TokenFailureLimit)
	}

	// Locked out: wrong and missing tokens get 429, without new failure.
	w := do(env.h.Status, http.MethodGet, "/status", "Bearer wrong")
	p := assertProblem(t, w, http.StatusTooManyRequests, problem.CodeRateLimited)
	if w.Header().Get("Retry-After") != "900" || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 900 {
		t.Fatalf("Retry-After = %q, body %+v", w.Header().Get("Retry-After"), p)
	}
	assertProblem(t, do(env.h.Metrics, http.MethodGet, "/metrics"), http.StatusTooManyRequests, problem.CodeRateLimited)
	invalid, limited := env.events.counts()
	if invalid != TokenFailureLimit || limited != 1 {
		t.Fatalf("events: %d invalid, %d rate_limited (throttled), want %d and 1", invalid, limited, TokenFailureLimit)
	}
	if got := env.events.rateLimited[0]; got != "192.0.2.10||metrics_token" {
		t.Fatalf("rate_limited event = %q", got)
	}
	env.advance(middleware.SecurityEventInterval)
	assertProblem(t, do(env.h.Metrics, http.MethodGet, "/metrics"), http.StatusTooManyRequests, problem.CodeRateLimited)
	if _, limited := env.events.counts(); limited != 2 {
		t.Fatalf("rate_limited events = %d, want 2", limited)
	}

	// The valid token still passes from the locked-out IP.
	if w := do(env.h.Metrics, http.MethodGet, "/metrics", "bearer "+testToken); w.Code != http.StatusOK {
		t.Fatalf("valid token while locked out: %d", w.Code)
	}
	// Another IP is not locked out.
	env.ip = netip.MustParseAddr("192.0.2.11")
	assertProblem(t, do(env.h.Metrics, http.MethodGet, "/metrics", "Bearer wrong"), http.StatusUnauthorized, problem.CodeInvalidCredentials)
	// The lockout ends.
	env.ip = netip.MustParseAddr("192.0.2.10")
	env.advance(TokenLockout)
	assertProblem(t, do(env.h.Metrics, http.MethodGet, "/metrics", "Bearer wrong"), http.StatusUnauthorized, problem.CodeInvalidCredentials)
}

func TestHandlerNilEvents(t *testing.T) {
	t.Parallel()
	env := newHandlerEnv(t, func(o *HandlerOptions) { o.Events = nil })
	for range TokenFailureLimit + 1 {
		do(env.h.Metrics, http.MethodGet, "/metrics", "Bearer wrong")
	}
	assertProblem(t, do(env.h.Metrics, http.MethodGet, "/metrics", "Bearer wrong"), http.StatusTooManyRequests, problem.CodeRateLimited)
}

func TestHandlerMetricsOK(t *testing.T) {
	t.Parallel()
	env := newHandlerEnv(t, nil)
	w := do(env.h.Metrics, http.MethodGet, "/metrics", "Bearer  "+testToken+" ")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	h := w.Header()
	if h.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers = %v", h)
	}
	if h.Get("Content-Length") != fmt.Sprint(w.Body.Len()) {
		t.Fatalf("Content-Length = %q for %d bytes", h.Get("Content-Length"), w.Body.Len())
	}
	if w.Body.String() != goldenMetrics {
		t.Fatalf("body:\n%s", w.Body)
	}
	families := parseExposition(t, w.Body.String())
	for _, samples := range families {
		for _, s := range samples {
			for _, v := range s.labels {
				if strings.Contains(v, "@") || strings.Contains(v, "Entity") {
					t.Fatalf("personal data or tenant name in a label: %q", v)
				}
			}
		}
	}

	// HEAD: same headers, no body.
	w = do(env.h.Metrics, http.MethodHead, "/metrics", "Bearer "+testToken)
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") != fmt.Sprint(len(goldenMetrics)) {
		t.Fatalf("HEAD: %d, %d bytes, Content-Length %q", w.Code, w.Body.Len(), w.Header().Get("Content-Length"))
	}
}

func TestHandlerMaintenanceIrrelevant(t *testing.T) {
	t.Parallel()
	env := newHandlerEnv(t, nil) // the full sources are in maintenance
	if w := do(env.h.Status, http.MethodGet, "/status", "Bearer "+testToken); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"maintenance":true`) {
		t.Fatalf("status in maintenance: %d %s", w.Code, w.Body)
	}
}

func TestHandlerNoSnapshot(t *testing.T) {
	t.Parallel()
	for name, col := range map[string]*Collector{"nil collector": nil, "not started": NewCollector(Sources{}, nil)} {
		env := newHandlerEnv(t, func(o *HandlerOptions) { o.Collector = col })
		assertProblem(t, do(env.h.Status, http.MethodGet, "/status", "Bearer "+testToken), http.StatusInternalServerError, problem.CodeInternalError)
		if !strings.Contains(env.logs.String(), "no snapshot") {
			t.Fatalf("%s: not logged:\n%s", name, env.logs)
		}
	}
}

func TestHandlerStatusMarshalError(t *testing.T) { //nolint:paralleltest // replaces marshalJSON
	orig := marshalJSON
	t.Cleanup(func() { marshalJSON = orig })
	marshalJSON = func(any) ([]byte, error) { return nil, errors.New("boom") }
	env := newHandlerEnv(t, nil)
	assertProblem(t, do(env.h.Status, http.MethodGet, "/status", "Bearer "+testToken), http.StatusInternalServerError, problem.CodeInternalError)
	if !strings.Contains(env.logs.String(), "boom") {
		t.Fatalf("not logged:\n%s", env.logs)
	}
}

func TestHandlerDefaults(t *testing.T) {
	t.Parallel()
	col := newTestCollector(Sources{}, nil)
	col.collect(t.Context())
	h := NewHandler(HandlerOptions{
		Token:      config.NewSecret(testToken),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Collector:  col,
	})
	chain := middleware.AssignRequestID(middleware.RealIP(func(netip.Addr) bool { return false })(h.Metrics))
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.RemoteAddr = "203.0.113.5:4242"
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("default client IP: status %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.RemoteAddr = "203.0.113.5:4242"
	r.Header.Set("Authorization", "Bearer wrong")
	w = httptest.NewRecorder()
	chain.ServeHTTP(w, r)
	p := assertProblem(t, w, http.StatusUnauthorized, problem.CodeInvalidCredentials)
	if p.Instance == "" || p.Instance != w.Header().Get(middleware.HeaderRequestID) {
		t.Fatalf("instance = %q, request id %q", p.Instance, w.Header().Get(middleware.HeaderRequestID))
	}
}

func TestHandlerStatusContent(t *testing.T) {
	t.Parallel()
	env := newHandlerEnv(t, nil)
	w := do(env.h.Status, http.MethodGet, "/status", "Bearer "+testToken)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d, headers %v", w.Code, w.Header())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	validateSchema(t, "InstanceStatus", got)
	want := `{"status":"ok","version":"1.1.0","checkedAt":"2026-10-27T09:00:00Z","uptimeSeconds":864000,"maintenance":true,` +
		`"checks":{"database":"ok","antivirus":"ok","storage":"ok"},` +
		`"disk":{"totalBytes":1000,"usedBytes":300,"usedRatio":0.3,"alertThreshold":0.85,"alertActive":false},` +
		`"antivirus":{"engine":"clamd","queuedFiles":2,"alertActive":false,"selfTestPassed":true},` +
		`"lifecycle":{"expire":"2026-10-27T08:59:30.5Z"},` +
		`"tenants":[{"id":"ten_A","name":"Entity A","storageUsedBytes":250,"storageQuotaBytes":1000,"storageUsedRatio":0.25,"activeTransfers":3,"transfersLast24h":2},` +
		`{"id":"ten_B","name":"Entity \"B\"","storageUsedBytes":0,"storageQuotaBytes":0,"storageUsedRatio":0,"activeTransfers":0,"transfersLast24h":0}]}`
	if strings.TrimSpace(w.Body.String()) != want {
		t.Fatalf("body:\n%s\nwant:\n%s", w.Body, want)
	}
}

func TestBuildStatusDegradedAndMinimal(t *testing.T) {
	t.Parallel()
	// No source at all: every component unavailable, empty tenants.
	col := newTestCollector(Sources{}, nil)
	col.collect(t.Context())
	st := buildStatus(col.snapshot())
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	validateSchema(t, "InstanceStatus", got)
	if st.Status != statusDegraded || st.Checks.Database != health.StatusUnavailable || st.Tenants == nil || st.Lifecycle != nil {
		t.Fatalf("minimal status = %+v", st)
	}
	if strings.Contains(string(b), `"engine"`) || strings.Contains(string(b), `"lifecycle"`) ||
		strings.Contains(string(b), `"selfTestPassed"`) {
		t.Fatalf("optional fields present: %s", b)
	}

	// A failing component, an over-quota and a negative tenant.
	src := Sources{
		State: &fakeState{state: InstanceState{
			DiskTotalBytes: 10, DiskUsedBytes: 20, ScanQueueFiles: -1,
			Tenants: []TenantState{
				{ID: "ten_x", StorageUsedBytes: 30, StorageQuotaBytes: 10},
				{ID: "ten_y", StorageUsedBytes: -5, StorageQuotaBytes: 10, ActiveTransfers: -1, TransfersLast24h: -1},
			},
		}},
		Health: func(context.Context) health.Report {
			return health.Report{Database: health.StatusOK, Antivirus: "", Storage: health.StatusOK}
		},
		AVAlert: flag(true),
	}
	col = newTestCollector(src, nil)
	col.collect(t.Context())
	st = buildStatus(col.snapshot())
	b, _ = json.Marshal(st)
	got = nil
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	validateSchema(t, "InstanceStatus", got)
	if st.Status != statusDegraded || st.Checks.Antivirus != health.StatusUnavailable || st.Disk.UsedRatio != 1 ||
		st.Tenants[0].StorageUsedRatio != 3 || st.Tenants[1].StorageUsedRatio != 0 || st.Tenants[1].StorageUsedBytes != 0 ||
		st.Antivirus.QueuedFiles != 0 || !st.Antivirus.AlertActive {
		t.Fatalf("status = %+v", st)
	}
}

// specSchemas returns the components.schemas of the OpenAPI document.
func specSchemas(t *testing.T) map[string]any {
	t.Helper()
	var doc struct {
		Components struct {
			Schemas map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPISpec, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Components.Schemas
}

// validateSchema validates v (decoded JSON) against the named schema of
// the specification: the subset of JSON Schema used by InstanceStatus
// ($ref, type, required, properties, additionalProperties, enum, minimum,
// maximum, format date-time). Undeclared properties are refused when the
// schema declares properties without additionalProperties, to catch
// misspelled fields.
func validateSchema(t *testing.T, name string, v any) {
	t.Helper()
	schemas := specSchemas(t)
	var check func(path string, schema map[string]any, v any)
	check = func(path string, schema map[string]any, v any) {
		if ref, ok := schema["$ref"].(string); ok {
			target, _ := schemas[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any)
			if target == nil {
				t.Fatalf("%s: unresolved %s", path, ref)
			}
			check(path, target, v)
			return
		}
		if enum, ok := schema["enum"].([]any); ok {
			found := false
			for _, e := range enum {
				found = found || fmt.Sprint(e) == fmt.Sprint(v)
			}
			if !found {
				t.Errorf("%s: %v not in %v", path, v, enum)
			}
		}
		switch schema["type"] {
		case "object":
			obj, ok := v.(map[string]any)
			if !ok {
				t.Errorf("%s: %T is not an object", path, v)
				return
			}
			for _, r := range asSlice(schema["required"]) {
				if _, ok := obj[fmt.Sprint(r)]; !ok {
					t.Errorf("%s: missing required %v", path, r)
				}
			}
			props, _ := schema["properties"].(map[string]any)
			extra, hasExtra := schema["additionalProperties"].(map[string]any)
			for k, val := range obj {
				switch p, ok := props[k].(map[string]any); {
				case ok:
					check(path+"."+k, p, val)
				case hasExtra:
					check(path+"."+k, extra, val)
				default:
					t.Errorf("%s: undeclared property %q", path, k)
				}
			}
		case "array":
			arr, ok := v.([]any)
			if !ok {
				t.Errorf("%s: %T is not an array", path, v)
				return
			}
			items, _ := schema["items"].(map[string]any)
			for i, it := range arr {
				check(fmt.Sprintf("%s[%d]", path, i), items, it)
			}
		case "string":
			s, ok := v.(string)
			if !ok {
				t.Errorf("%s: %T is not a string", path, v)
				return
			}
			if schema["format"] == "date-time" {
				if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
					t.Errorf("%s: %q is not a date-time", path, s)
				}
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				t.Errorf("%s: %T is not a boolean", path, v)
			}
		case "integer", "number":
			n, ok := v.(float64)
			if !ok {
				t.Errorf("%s: %T is not a number", path, v)
				return
			}
			if schema["type"] == "integer" && n != float64(int64(n)) {
				t.Errorf("%s: %v is not an integer", path, n)
			}
			if lo, ok := toFloat(schema["minimum"]); ok && n < lo {
				t.Errorf("%s: %v below %v", path, n, lo)
			}
			if hi, ok := toFloat(schema["maximum"]); ok && n > hi {
				t.Errorf("%s: %v above %v", path, n, hi)
			}
		}
	}
	root, _ := schemas[name].(map[string]any)
	if root == nil {
		t.Fatalf("schema %s not found", name)
	}
	check(name, root, v)
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// Package integration_test exercises the TransTeira HTTP server end to end:
// a real app.Run serving on a random loopback port, a real database (SQLite
// always, PostgreSQL when the test environment is up, see
// storetest.Engines), a real security log file and two tenants,
// transfer.entity-a.localhost and transfer.entity-b.localhost, created
// through the store before the server starts.
//
// The tests are written black-box against CLAUDE.md sections 4, 8.1, 16.2,
// 16.3 and 19 and the threat model (T-01 to T-08, T-98 to T-103). They only
// use exported APIs and talk to the server over TCP, raw when the Go HTTP
// client would refuse to send the malformed input under test.
package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Fictitious tenant host names (CLAUDE.md section 24.2: *.localhost).
const (
	hostA = "transfer.entity-a.localhost"
	hostB = "transfer.entity-b.localhost"
	// nameA and nameB are the display names of the tenants; they must never
	// appear in a response that is not about the tenant itself.
	nameA = "Entity A Integration"
	nameB = "Entity B Integration"
)

// Header names used throughout the tests.
const (
	hdrRequestID  = "X-Request-Id"
	hdrRetryAfter = "Retry-After"
	contentJSON   = "application/json"
	contentProb   = "application/problem+json"
)

// waitTimeout bounds every wait on the server (start-up, shutdown).
const waitTimeout = 60 * time.Second

// securityHeaders lists the headers that every response must carry
// (CLAUDE.md section 16.2), with their exact expected values.
var securityHeaders = map[string]string{
	"Content-Security-Policy":      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
	"X-Content-Type-Options":       "nosniff",
	"Referrer-Policy":              "no-referrer",
	"X-Frame-Options":              "DENY",
	"Permissions-Policy":           "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=(), browsing-topics=()",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
}

// serverOptions customizes startServer.
type serverOptions struct {
	// trustedProxies is TT_TRUSTED_PROXIES ("" leaves it unset).
	trustedProxies string
	// maintenance is TT_MAINTENANCE=true.
	maintenance bool
	// clamd is TT_CLAMAV_ADDR; "" starts a fake clamd answering PONG.
	clamd string
	// flag, when set, is passed with app.WithMaintenance.
	flag *atomic.Bool
	// shutdownTimeout, when set, is passed with app.WithShutdownTimeout.
	shutdownTimeout time.Duration
	// env holds extra environment variables of the server (for example
	// TT_UPLOAD_IDLE_TIMEOUT); they override the defaults of testEnv.
	env map[string]string
}

// server is a running app.Run instance.
type server struct {
	addr    string // host:port of the listener
	logDir  string
	appLog  *watchBuffer
	cancel  context.CancelFunc
	done    chan error
	stopped atomic.Bool
	result  error
	client  *http.Client
	// cfg is the configuration the server runs with (data directory,
	// master key file), for the tests that inspect the files on disk.
	cfg     *config.Config
	tenantA *tenant.Tenant
	tenantB *tenant.Tenant
}

// env builds the environment of the server, as an operator would.
func testEnv(t *testing.T, e storetest.Engine, o serverOptions) map[string]string {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir() // outside every data volume (CLAUDE.md section 16.1)
	env := map[string]string{
		config.EnvDBDriver:      e.Driver,
		config.EnvDBDSN:         e.DSN,
		config.EnvDataDir:       filepath.Join(root, "data"),
		config.EnvBackupDir:     filepath.Join(root, "backups"),
		config.EnvLogDir:        filepath.Join(root, "logs"),
		config.EnvMasterKeyFile: writeMasterKey(t, keyDir),
		config.EnvListenAddr:    "127.0.0.1:8080", // unused: tests pass app.WithListener
		config.EnvLogLevel:      "debug",
		config.EnvClamAVAddr:    o.clamd,
	}
	if e.MigrateDSN != "" {
		env[config.EnvDBMigrateDSN] = e.MigrateDSN
	}
	if o.trustedProxies != "" {
		env[config.EnvTrustedProxies] = o.trustedProxies
	}
	if o.maintenance {
		env[config.EnvMaintenance] = "true"
	}
	for k, v := range o.env {
		env[k] = v
	}
	return env
}

// writeMasterKey writes a new random master key to dir and returns its
// path.
func writeMasterKey(t *testing.T, dir string) string {
	t.Helper()
	path, _ := masterkeytest.WriteKeyFile(t, dir)
	return path
}

// loadConfig turns env into a validated configuration.
func loadConfig(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// createTenants migrates the engine's database and creates tenants A and B
// through the store, as the super admin will.
func createTenants(t *testing.T, e storetest.Engine) (a, b *tenant.Tenant) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config())
	if err != nil {
		t.Fatalf("store.Open(%s): %v", e.Name, err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate(%s): %v", e.Name, err)
	}
	mk := func(name, fqdn string) *tenant.Tenant {
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
			Name: name, FQDN: fqdn, DefaultLanguage: "en",
			MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
		})
		if err != nil {
			t.Fatalf("create tenant %s: %v", fqdn, err)
		}
		return tn
	}
	return mk(nameA, hostA), mk(nameB, hostB)
}

// startServer creates the two tenants and runs app.Run on a random loopback
// port. The server is stopped, and its clean shutdown asserted, when the
// test ends (unless the test stopped it itself).
func startServer(t *testing.T, e storetest.Engine, o serverOptions) *server {
	t.Helper()
	if o.clamd == "" {
		o.clamd = fakeClamd(t)
	}
	a, b := createTenants(t, e)
	cfg := loadConfig(t, testEnv(t, e, o))

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &server{
		addr:    ln.Addr().String(),
		logDir:  cfg.LogDir,
		appLog:  newWatchBuffer(),
		done:    make(chan error, 1),
		cfg:     cfg,
		tenantA: a,
		tenantB: b,
		client: &http.Client{
			Timeout: waitTimeout,
			// Never follow redirects nor use an environment proxy.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		},
	}
	opts := []app.Option{app.WithListener(ln), app.WithLogOutput(s.appLog)}
	if o.flag != nil {
		opts = append(opts, app.WithMaintenance(o.flag))
	}
	if o.shutdownTimeout > 0 {
		opts = append(opts, app.WithShutdownTimeout(o.shutdownTimeout))
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go func() { s.done <- app.Run(ctx, cfg, opts...) }()
	// The listener is already bound: requests queue in the backlog until
	// Serve accepts them, so no readiness polling is needed. Waiting for the
	// "listening" log line makes start-up failures fail fast instead.
	select {
	case <-s.appLog.wait("HTTP server listening"):
	case err := <-s.done:
		s.stopped.Store(true)
		t.Fatalf("app.Run failed at start-up: %v\napp log:\n%s", err, s.appLog)
	case <-time.After(waitTimeout):
		t.Fatalf("server did not start within %s\napp log:\n%s", waitTimeout, s.appLog)
	}
	t.Cleanup(func() {
		if err := s.stop(); err != nil {
			t.Errorf("app.Run returned %v after shutdown, want nil\napp log:\n%s", err, s.appLog)
		}
	})
	return s
}

// stop cancels the server context and returns the result of app.Run.
func (s *server) stop() error {
	if s.stopped.Swap(true) {
		return s.result
	}
	s.cancel()
	select {
	case s.result = <-s.done:
	case <-time.After(waitTimeout):
		s.result = errors.New("app.Run did not return within the wait timeout")
	}
	return s.result
}

// url returns the absolute URL of path on the server.
func (s *server) url(path string) string { return "http://" + s.addr + path }

// request describes one HTTP request sent by do.
type request struct {
	method  string
	path    string
	host    string
	body    []byte
	headers http.Header
}

// response is a fully read HTTP response.
type response struct {
	status int
	header http.Header
	body   []byte
}

// do sends r with the Go HTTP client and reads the whole response.
func (s *server) do(t *testing.T, r request) response {
	t.Helper()
	resp, err := s.tryDo(t, r)
	if err != nil {
		t.Fatalf("%s %s (Host %q): %v", r.method, r.path, r.host, err)
	}
	return resp
}

// tryDo is do returning transport errors instead of failing the test.
func (s *server) tryDo(t *testing.T, r request) (response, error) {
	t.Helper()
	if r.method == "" {
		r.method = http.MethodGet
	}
	var body io.Reader
	if r.body != nil {
		body = bytes.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(context.Background(), r.method, s.url(r.path), body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if r.host != "" {
		req.Host = r.host
	}
	for k, vs := range r.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if r.body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentJSON)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return response{}, fmt.Errorf("read body: %w", err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

// get sends a GET for path with the given Host.
func (s *server) get(t *testing.T, host, path string) response {
	t.Helper()
	return s.do(t, request{host: host, path: path})
}

// raw writes head (the request line and headers, CRLF-terminated, without
// the final empty line) and then body, which may stream; it returns the
// parsed response. It is used for inputs the Go client refuses to send.
func (s *server) raw(t *testing.T, head string, body func(w io.Writer)) response {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: waitTimeout}).DialContext(context.Background(), "tcp", s.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(waitTimeout))
	if _, err := io.WriteString(conn, head+"\r\n"); err != nil {
		t.Fatalf("write head: %v", err)
	}
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		if body != nil {
			body(conn) // write errors are expected once the server answered early
		}
	}()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response to %q: %v", firstLine(head), err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	_ = conn.Close() // unblocks the writer
	<-writeDone
	return response{status: resp.StatusCode, header: resp.Header, body: b}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\r\n")
	return line
}

// problemBody is the subset of RFC 9457 members the tests check.
type problemBody struct {
	Type              string `json:"type"`
	Title             string `json:"title"`
	Status            int    `json:"status"`
	Detail            string `json:"detail"`
	Instance          string `json:"instance"`
	Code              string `json:"code"`
	RetryAfterSeconds *int   `json:"retryAfterSeconds"`
}

// expectProblem asserts that resp is a Problem with the given status and
// code whose instance is the X-Request-Id of the response.
func expectProblem(t *testing.T, resp response, status int, code string) problemBody {
	t.Helper()
	if resp.status != status {
		t.Fatalf("status = %d, want %d; body: %s", resp.status, status, resp.body)
	}
	if ct := resp.header.Get("Content-Type"); ct != contentProb {
		t.Errorf("Content-Type = %q, want %q", ct, contentProb)
	}
	var p problemBody
	if err := json.Unmarshal(resp.body, &p); err != nil {
		t.Fatalf("body is not a Problem: %v; body: %s", err, resp.body)
	}
	if p.Code != code || p.Status != status {
		t.Errorf("problem code/status = %q/%d, want %q/%d", p.Code, p.Status, code, status)
	}
	rid := resp.header.Get(hdrRequestID)
	if rid == "" || !strings.HasPrefix(rid, "req_") {
		t.Errorf("X-Request-Id = %q, want a req_ identifier", rid)
	}
	if p.Instance != rid {
		t.Errorf("problem instance = %q, want X-Request-Id %q", p.Instance, rid)
	}
	return p
}

// expectSecurityHeaders asserts every header of securityHeaders.
func expectSecurityHeaders(t *testing.T, label string, h http.Header) {
	t.Helper()
	for k, want := range securityHeaders {
		if got := h.Get(k); got != want {
			t.Errorf("%s: %s = %q, want %q", label, k, got, want)
		}
	}
	if h.Get("Strict-Transport-Security") != "" {
		t.Errorf("%s: Strict-Transport-Security is set; HSTS belongs to the reverse proxy", label)
	}
}

// securityLines returns the lines of the security log.
func (s *server) securityLines(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.logDir, app.SecurityLogName))
	if err != nil {
		t.Fatalf("read security log: %v", err)
	}
	text := string(b)
	if text != "" && !strings.HasSuffix(text, "\n") {
		t.Errorf("security log does not end with a newline: %q", text)
	}
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// lineRE is the fixed prefix of every security log line
// (docs/operations/security-log.md).
var lineRE = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z) ip=(\S+) tenant=(\S+) event=([a-z][a-z0-9_]*)((?: [a-z_]+="(?:[^"\\]|\\.)*")*)$`)

// logLine is a parsed security log line.
type logLine struct {
	raw, ip, tenant, event, fields string
}

// parseLines parses every line, failing the test on any line that does not
// follow the documented grammar.
func parseLines(t *testing.T, lines []string) []logLine {
	t.Helper()
	out := make([]logLine, 0, len(lines))
	for _, l := range lines {
		m := lineRE.FindStringSubmatch(l)
		if m == nil {
			t.Fatalf("security log line does not match the documented format: %q", l)
		}
		out = append(out, logLine{raw: l, ip: m[2], tenant: m[3], event: m[4], fields: m[5]})
	}
	return out
}

// eventsOf returns the parsed lines of the given event type.
func eventsOf(t *testing.T, lines []string, event string) []logLine {
	t.Helper()
	var out []logLine
	for _, l := range parseLines(t, lines) {
		if l.event == event {
			out = append(out, l)
		}
	}
	return out
}

// withHost returns the unknown_fqdn lines whose host field is exactly the
// quoted (escaped) value.
func withHost(lines []logLine, quoted string) []logLine {
	var out []logLine
	for _, l := range lines {
		if strings.Contains(l.fields, ` host=`+quoted) {
			out = append(out, l)
		}
	}
	return out
}

// fakeClamd answers PONG to every PING and returns its address.
func fakeClamd(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if _, err := bufio.NewReader(c).ReadBytes(0); err == nil {
					_, _ = c.Write([]byte("PONG\x00"))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// closedPort returns a loopback address on which nothing listens.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// watchBuffer is a concurrency-safe buffer that signals when a substring
// first appears, so that tests synchronize on log lines instead of sleeping.
type watchBuffer struct {
	mu       sync.Mutex
	b        bytes.Buffer
	watchers map[string]chan struct{}
}

func newWatchBuffer() *watchBuffer {
	return &watchBuffer{watchers: map[string]chan struct{}{}}
}

func (w *watchBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.b.Write(p)
	w.notifyLocked()
	return n, err
}

func (w *watchBuffer) notifyLocked() {
	for s, ch := range w.watchers {
		if strings.Contains(w.b.String(), s) {
			close(ch)
			delete(w.watchers, s)
		}
	}
}

// wait returns a channel closed once s has been written.
func (w *watchBuffer) wait(s string) <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch := make(chan struct{})
	if strings.Contains(w.b.String(), s) {
		close(ch)
		return ch
	}
	w.watchers[s] = ch
	return ch
}

func (w *watchBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// forEngine runs fn on every engine (SQLite, and PostgreSQL when available).
func forEngine(t *testing.T, fn func(t *testing.T, e storetest.Engine)) {
	t.Helper()
	storetest.Run(t, fn)
}

// quote mimics the escaping of the security log for plain ASCII input
// without control characters.
func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// mustJSON unmarshals b into v.
func mustJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("invalid JSON %s: %v", b, err)
	}
}

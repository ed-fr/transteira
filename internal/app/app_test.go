package app

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/maintenance"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

const (
	tenantHost = "transfer.entity-a.localhost"
	adminHost  = "admin.localhost"
)

// memListener is an in-memory net.Listener whose connections are net.Pipe
// pairs.
type memListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newMemListener() *memListener {
	return &memListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *memListener) Addr() net.Addr { return memAddr{} }

func (l *memListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *memListener) client() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: l.dial}}
}

type memAddr struct{}

func (memAddr) Network() string { return "memory" }
func (memAddr) String() string  { return "memory" }

// syncBuffer is a concurrency-safe bytes.Buffer.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
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

// testConfig completes the engine configuration with temporary directories.
func testConfig(t *testing.T, e storetest.Engine) *config.Config {
	t.Helper()
	cfg := e.Config()
	root := t.TempDir()
	cfg.DataDir = filepath.Join(root, "data")
	cfg.LogDir = filepath.Join(root, "logs")
	cfg.BackupDir = filepath.Join(root, "backups")
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.ClamAV = config.ClamAVAddr{Network: "tcp", Address: "127.0.0.1:1"}
	cfg.MasterKeyFile = writeMasterKey(t)
	cfg.AdminHosts = []string{adminHost}
	return cfg
}

// writeMasterKey writes a new random master key to a file outside every data
// directory and returns its path.
func writeMasterKey(t *testing.T) string {
	t.Helper()
	path, _ := masterkeytest.WriteKeyFile(t, t.TempDir())
	return path
}

// prepare migrates the database of cfg and creates the test tenant.
func prepare(t *testing.T, cfg *config.Config) {
	t.Helper()
	ctx := context.Background()
	c := *cfg
	db, err := store.Open(ctx, &c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Tenants().Create(ctx, &tenant.Tenant{
		Name: "Entity A", FQDN: tenantHost, DefaultLanguage: "fr",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 10 << 30,
	}); err != nil {
		t.Fatal(err)
	}
}

// started is a running server.
type started struct {
	ln     *memListener
	cancel context.CancelFunc
	done   chan error
	logs   *syncBuffer
}

func start(t *testing.T, cfg *config.Config, opts ...Option) *started {
	t.Helper()
	s := &started{ln: newMemListener(), done: make(chan error, 1), logs: &syncBuffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	opts = append([]Option{WithListener(s.ln), WithLogOutput(s.logs)}, opts...)
	go func() { s.done <- Run(ctx, cfg, opts...) }()
	t.Cleanup(func() {
		cancel()
		if err := <-s.done; err != nil {
			t.Logf("Run: %v", err)
		}
	})
	return s
}

func (s *started) stop(t *testing.T) error {
	t.Helper()
	s.cancel()
	select {
	case err := <-s.done:
		s.done <- err // for the cleanup
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after cancel")
		return nil
	}
}

func (s *started) get(t *testing.T, path, host string) (int, string) {
	t.Helper()
	return s.do(t, http.MethodGet, path, host, nil)
}

func (s *started) do(t *testing.T, method, path, host string, body io.Reader) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, "http://memory"+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.ln.client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v (logs: %s)", method, path, err, s.logs.String())
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRunServes(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		cfg := testConfig(t, e)
		prepare(t, cfg)
		if e.Driver == config.DriverPostgres {
			cfg.DBMigrateDSN = config.Secret{} // migrations already applied
		}
		cfg.ClamAV.Address = fakeClamd(t)
		s := start(t, cfg)

		if code, body := s.get(t, "/healthz", "anything"); code != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
			t.Fatalf("healthz = %d %s", code, body)
		}
		if code, body := s.get(t, "/api/v1/version", tenantHost); code != http.StatusOK || !strings.Contains(body, `"apiVersion":"v1"`) {
			t.Fatalf("version = %d %s", code, body)
		}
		if code, body := s.get(t, "/api/openapi.yaml", "anything"); code != http.StatusOK || !strings.HasPrefix(body, "openapi:") {
			t.Fatalf("spec = %d", code)
		}
		if code, _ := s.get(t, "/api/v1/version", "transfer.unknown.localhost"); code != http.StatusMisdirectedRequest {
			t.Fatalf("unknown host = %d", code)
		}
		if err := s.stop(t); err != nil {
			t.Fatalf("Run = %v", err)
		}
		logs := s.logs.String()
		for _, want := range []string{"HTTP server listening", "stopped"} {
			if !strings.Contains(logs, want) {
				t.Errorf("logs lack %q: %s", want, logs)
			}
		}
		wantMigration := "migrations applied"
		if e.Driver == config.DriverPostgres {
			wantMigration = "start-up migrations skipped"
		}
		if !strings.Contains(logs, wantMigration) {
			t.Errorf("logs lack %q: %s", wantMigration, logs)
		}
		sec, err := os.ReadFile(filepath.Join(cfg.LogDir, SecurityLogName))
		if err != nil || !strings.Contains(string(sec), `event=unknown_fqdn host="transfer.unknown.localhost"`) {
			t.Errorf("security log %q, %v", sec, err)
		}
	})
}

func TestRunMigratesAtStartup(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		cfg := testConfig(t, e)
		s := start(t, cfg)
		// Tables exist (the resolver answers 421, not 500); ClamAV is absent.
		if code, body := s.get(t, "/api/v1/version", tenantHost); code != http.StatusMisdirectedRequest {
			t.Fatalf("version = %d %s", code, body)
		}
		if code, body := s.get(t, "/healthz", "x"); code != http.StatusServiceUnavailable || !strings.Contains(body, `"antivirus":"unavailable"`) {
			t.Fatalf("healthz = %d %s", code, body)
		}
		if cfg.DBMigrateDSN.IsSet() {
			t.Error("the owner DSN was not dropped from the configuration")
		}
		if err := s.stop(t); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRunMaintenance(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, storetest.SQLite(t))
	prepare(t, cfg)
	cfg.Maintenance = true
	var mode *maintenance.Mode
	s := start(t, cfg, WithMaintenanceMode(func(m *maintenance.Mode) { mode = m }))
	code, body := s.do(t, http.MethodPost, "/api/v1/deposit-sessions", tenantHost, strings.NewReader(`{}`))
	if code != http.StatusServiceUnavailable || !strings.Contains(body, `"maintenance"`) {
		t.Fatalf("deposit in maintenance = %d %s", code, body)
	}
	if st := mode.State(); !st.Enabled || st.Source != maintenance.SourceEnvironment {
		t.Errorf("maintenance mode not initialized from the configuration: %+v", st)
	}
	mode.Force(false)
	// The handler is reached again: the empty body lacks the address.
	if code, body := s.do(t, http.MethodPost, "/api/v1/deposit-sessions", tenantHost, strings.NewReader(`{}`)); code != http.StatusBadRequest {
		t.Errorf("deposit after maintenance = %d %s, want 400 from the handler", code, body)
	}
	if !strings.Contains(s.logs.String(), "maintenance mode is active") {
		t.Errorf("logs %s", s.logs.String())
	}
}

func TestRunRealListener(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, storetest.SQLite(t))
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, WithLogOutput(logs)) }()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(logs.String(), "HTTP server listening") {
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunRefusesUniversalTrustedProxy(t *testing.T) {
	t.Parallel()
	for _, list := range [][]string{
		{"10.0.0.0/8", "0.0.0.0/0"},
		{"10.0.0.0/8", "::/0"},
		{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"},
	} {
		prefix := strings.Join(list, ",")
		cfg := testConfig(t, storetest.SQLite(t))
		cfg.TrustedProxies = nil
		for _, p := range list {
			cfg.TrustedProxies = append(cfg.TrustedProxies, netip.MustParsePrefix(p))
		}
		ln := newMemListener()
		err := Run(context.Background(), cfg, WithListener(ln), WithLogOutput(io.Discard))
		if !errors.Is(err, config.ErrTrustedProxiesTooBroad) {
			t.Errorf("Run with %s = %v, want config.ErrTrustedProxiesTooBroad", prefix, err)
		}
		if _, err := os.Stat(cfg.DBDSN.Reveal()); !os.IsNotExist(err) {
			t.Errorf("the database was opened before the refusal: %v", err)
		}
		select {
		case <-ln.closed:
		default:
			t.Error("the injected listener was not closed")
		}
	}
}

func TestRunStartupErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(t *testing.T, cfg *config.Config)
		want   string
	}{
		{"database", func(t *testing.T, cfg *config.Config) {
			cfg.DBDSN = config.NewSecret(filepath.Join(t.TempDir(), "missing", "db.sqlite"))
		}, "opening sqlite database"},
		{"migration", func(t *testing.T, cfg *config.Config) {
			prepare(t, cfg)
			raw, err := sql.Open("sqlite", cfg.DBDSN.Reveal())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = raw.Close() }()
			if _, err := raw.ExecContext(context.Background(), `INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (9999, 'future', 'x', 0)`); err != nil {
				t.Fatal(err)
			}
		}, "migrate"},
		{"log directory", func(t *testing.T, cfg *config.Config) {
			file := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg.LogDir = filepath.Join(file, "logs")
		}, "create directory"},
		{"security log", func(t *testing.T, cfg *config.Config) {
			if err := os.MkdirAll(filepath.Join(cfg.LogDir, SecurityLogName), 0o750); err != nil {
				t.Fatal(err)
			}
		}, "securitylog"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(t, storetest.SQLite(t))
			tt.mutate(t, cfg)
			err := Run(context.Background(), cfg, WithListener(newMemListener()), WithLogOutput(io.Discard))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Run = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

func TestRunMasterKeyFileErrors(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(cfg *config.Config){
		"missing": func(cfg *config.Config) { cfg.MasterKeyFile = filepath.Join(t.TempDir(), "absent.key") },
		"unset":   func(cfg *config.Config) { cfg.MasterKeyFile = "" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(t, storetest.SQLite(t))
			mutate(cfg)
			err := Run(context.Background(), cfg, WithListener(newMemListener()), WithLogOutput(io.Discard))
			if err == nil || !strings.Contains(err.Error(), config.EnvMasterKeyFile) {
				t.Errorf("Run = %v", err)
			}
			if _, err := os.Stat(cfg.DBDSN.Reveal()); !os.IsNotExist(err) {
				t.Errorf("the database was opened before the key was loaded: %v", err)
			}
		})
	}
}

func TestRunMasterKeyCheck(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		cfg := testConfig(t, e)
		prepare(t, cfg)

		// First start: the key is registered; a wrapped key is stored.
		first := *cfg
		s := start(t, &first)
		if code, _ := s.get(t, "/healthz", "x"); code == 0 {
			t.Fatal("no answer")
		}
		if err := s.stop(t); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(s.logs.String(), "master key registered as active") {
			t.Errorf("logs = %s", s.logs)
		}
		ctx := context.Background()
		c := *cfg
		db, err := store.Open(ctx, &c)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		kr, err := masterkey.Load(cfg)
		if err != nil {
			t.Fatal(err)
		}
		tn, err := db.Tenants().TenantByFQDN(ctx, tenantHost)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := masterkey.NewVault(db, kr, nil).Seal(ctx, tn.ID, crypto.PurposeSecret, []byte("smtp password")); err != nil {
			t.Fatal(err)
		}
		kr.Close()

		// Same key with a new key configured: the start goes on.
		withNew := *cfg
		withNew.MasterKeyNewFile = writeMasterKey(t)
		s = start(t, &withNew)
		if code, _ := s.get(t, "/healthz", "x"); code == 0 {
			t.Fatal("no answer")
		}
		if err := s.stop(t); err != nil {
			t.Fatal(err)
		}
		if logs := s.logs.String(); !strings.Contains(logs, "master key check passed") || !strings.Contains(logs, `"new":"mk_`) {
			t.Errorf("logs = %s", logs)
		}

		// Another key: the start is refused with the typed error.
		wrong := *cfg
		wrong.MasterKeyFile = writeMasterKey(t)
		err = Run(ctx, &wrong, WithListener(newMemListener()), WithLogOutput(io.Discard))
		ce, ok := errors.AsType[*masterkey.CheckError](err)
		if !ok || ce.Reason != masterkey.ReasonMissingKey || !errors.Is(err, masterkey.ErrKeyCheck) {
			t.Fatalf("Run(wrong key) = %v", err)
		}
	})
}

func TestRunListenError(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, storetest.SQLite(t))
	cfg.ListenAddr = "127.0.0.1:99999"
	err := Run(context.Background(), cfg, WithLogOutput(io.Discard))
	if err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Errorf("Run = %v", err)
	}
}

func TestRunServerStopsOnItsOwn(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, storetest.SQLite(t))
	s := start(t, cfg)
	if code, _ := s.get(t, "/healthz", "x"); code == 0 {
		t.Fatal("no answer")
	}
	_ = s.ln.Close()
	select {
	case err := <-s.done:
		s.done <- err
		if err == nil || !strings.Contains(err.Error(), "HTTP server stopped") {
			t.Errorf("Run = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after the listener closed")
	}
}

func TestRunShutdownTimeout(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, storetest.SQLite(t))
	s := start(t, cfg, WithShutdownTimeout(50*time.Millisecond))
	if code, _ := s.get(t, "/healthz", "x"); code == 0 {
		t.Fatal("no answer")
	}
	// A new connection that never sends its request keeps Shutdown waiting.
	conn, err := s.ln.dial(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	time.Sleep(50 * time.Millisecond)
	if err := s.stop(t); err != nil {
		t.Errorf("Run = %v, want nil after a forced close", err)
	}
	if logs := s.logs.String(); !strings.Contains(logs, "forcing close of active connections") ||
		!strings.Contains(logs, `"connections":`) {
		t.Errorf("no forced close warning in logs: %s", logs)
	}
}

func TestRunWarnsBroadTrustedProxies(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, storetest.SQLite(t))
	cfg.TrustedProxies = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.0.0/16"),
		netip.MustParsePrefix("2001:db8::/48"), netip.MustParsePrefix("2001:db8:1::/64"),
	}
	s := start(t, cfg)
	if code, _ := s.get(t, "/healthz", "x"); code == 0 {
		t.Fatal("no answer")
	}
	if err := s.stop(t); err != nil {
		t.Fatal(err)
	}
	logs := s.logs.String()
	if n := strings.Count(logs, "broad trusted proxy prefix"); n != 2 {
		t.Errorf("%d broad prefix warnings, want 2: %s", n, logs)
	}
	for _, p := range []string{"198.51.0.0/16", "2001:db8::/48"} {
		if !strings.Contains(logs, `"prefix":"`+p+`"`) {
			t.Errorf("no warning for %s: %s", p, logs)
		}
	}
}

// serveWith runs serve with handler on a memory listener and returns the
// listener, the logs, a cancel function and the result channel.
func serveWith(t *testing.T, handler http.Handler, timeout time.Duration) (*memListener, *syncBuffer, context.CancelFunc, chan error) {
	t.Helper()
	ln := newMemListener()
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	o := &runOptions{listener: ln, shutdownTimeout: timeout}
	go func() { done <- serve(ctx, &config.Config{}, o, handler, logger) }()
	return ln, logs, cancel, done
}

func TestServeCancelsRequestContextsOnShutdown(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	finished := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done() // a streaming handler stops when its context ends
		close(finished)
	})
	ln, logs, cancel, done := serveWith(t, handler, 20*time.Second)
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://memory/stream", nil)
		if resp, err := ln.client().Do(req); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	<-entered
	began := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("serve did not return: the request context was not canceled (logs: %s)", logs.String())
	}
	select {
	case <-finished:
	default:
		t.Error("serve returned before the handler")
	}
	if d := time.Since(began); d > 5*time.Second {
		t.Errorf("shutdown took %s", d)
	}
}

func TestServeHandlerIgnoringShutdown(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(entered)
		<-release // ignores both its context and the closing of its connection
	})
	defer close(release)
	ln, logs, cancel, done := serveWith(t, handler, 50*time.Millisecond)
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://memory/stuck", nil)
		if resp, err := ln.client().Do(req); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
	if l := logs.String(); !strings.Contains(l, "forcing close") || !strings.Contains(l, "handlers still running") {
		t.Errorf("missing warnings: %s", l)
	}
}

func TestDrain(t *testing.T) {
	t.Parallel()
	var n atomic.Int64
	if !drain(&n, 0) {
		t.Error("drain(0) = false")
	}
	n.Store(1)
	if drain(&n, 2*drainPoll) {
		t.Error("drain with a running handler = true")
	}
	go func() {
		time.Sleep(drainPoll)
		n.Store(0)
	}()
	if !drain(&n, 5*time.Second) {
		t.Error("drain did not see the counter drop")
	}
}

func TestCloseWith(t *testing.T) {
	t.Parallel()
	if err := closeWith(func() error { return nil }, "x"); err != nil {
		t.Error(err)
	}
	if err := closeWith(func() error { return io.ErrClosedPipe }, "thing"); !errors.Is(err, io.ErrClosedPipe) || !strings.Contains(err.Error(), "close thing") {
		t.Errorf("closeWith = %v", err)
	}
}

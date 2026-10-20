// Package app wires the TransTeira server together and runs it: logging,
// database, migrations, tenant resolution, security log, health checks and
// the HTTP server, with a graceful shutdown.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ed-fr/transteira/api"
	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/httpserver"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/version"
)

// HTTP server settings. There is deliberately no global read or write
// timeout: uploads and downloads of tens of gigabytes may last hours.
const (
	// ReadHeaderTimeout bounds the reading of request headers (slowloris).
	ReadHeaderTimeout = 10 * time.Second
	// IdleTimeout closes idle keep-alive connections.
	IdleTimeout = 120 * time.Second
	// MaxHeaderBytes bounds the size of request headers.
	MaxHeaderBytes = 64 << 10
	// ShutdownTimeout bounds the graceful shutdown. It stays below Docker's
	// default 10 s stop grace period (stop_grace_period in docker-compose) so
	// that connections still open are closed by TransTeira itself, with a
	// warning, before Docker sends SIGKILL. Raise stop_grace_period before
	// raising this value.
	ShutdownTimeout = 8 * time.Second
	// HandlerDrainTimeout bounds the wait for handlers to return once the
	// connections have been forcibly closed, before the database and the
	// security log are closed.
	HandlerDrainTimeout = time.Second
	// SecurityLogName is the file name of the security log in the log
	// directory.
	SecurityLogName = "security.log"
	// dirMode is the permission of the data and log directories created at
	// start-up when missing.
	dirMode = 0o750
)

// Option customizes Run.
type Option func(*runOptions)

type runOptions struct {
	listener        net.Listener
	logOutput       io.Writer
	shutdownTimeout time.Duration
	maintenance     *atomic.Bool
}

// WithListener serves on l instead of listening on cfg.ListenAddr (tests).
// Run closes it.
func WithListener(l net.Listener) Option {
	return func(o *runOptions) { o.listener = l }
}

// WithLogOutput writes the application log to w instead of stdout.
func WithLogOutput(w io.Writer) Option {
	return func(o *runOptions) { o.logOutput = w }
}

// WithShutdownTimeout replaces ShutdownTimeout.
func WithShutdownTimeout(d time.Duration) Option {
	return func(o *runOptions) { o.shutdownTimeout = d }
}

// WithMaintenance uses flag as the maintenance flag instead of a new one,
// so that the caller can toggle it; Run sets it to cfg.Maintenance at
// start-up.
func WithMaintenance(flag *atomic.Bool) Option {
	return func(o *runOptions) { o.maintenance = flag }
}

// Run starts the server described by cfg and blocks until ctx is canceled,
// then shuts down gracefully and releases every resource. It returns nil
// after a shutdown, including one where connections still open after
// ShutdownTimeout were forcibly closed, and an error when start-up fails or
// the server stops on its own.
//
// Run modifies cfg: once the start-up migrations are done it clears
// cfg.DBMigrateDSN, so that the owner credentials of PostgreSQL do not stay
// in memory (in the caller's copy included) for the life of the server.
//
// Start-up sequence: refuse a too broad trusted proxy list (and warn about
// broad prefixes), logger,
// database, migrations (always with SQLite; with PostgreSQL only when
// cfg.DBMigrateDSN is set, otherwise they are expected to be applied by
// "transteira migrate"), drop of the owner credentials and role
// verification, tenant resolver, security log, health checks, HTTP server.
func Run(ctx context.Context, cfg *config.Config, opts ...Option) (err error) {
	o := runOptions{logOutput: os.Stdout, shutdownTimeout: ShutdownTimeout}
	for _, opt := range opts {
		opt(&o)
	}
	if o.listener != nil {
		defer func() { _ = o.listener.Close() }() // no-op once the server closed it
	}
	// config.Load already refuses a TT_TRUSTED_PROXIES list that is too broad
	// (threat model T-08); check again for configurations built by hand. The
	// error wraps config.ErrTrustedProxiesTooBroad.
	if err := config.ValidateTrustedProxies(cfg.TrustedProxies); err != nil {
		return fmt.Errorf("app: %s: %w", config.EnvTrustedProxies, err)
	}
	logger := slog.New(slog.NewJSONHandler(o.logOutput, &slog.HandlerOptions{Level: cfg.LogLevel}))
	info := version.Get()
	logger.InfoContext(ctx, "starting TransTeira",
		slog.String("version", info.Version), slog.String("commit", info.Commit),
		slog.String("db_driver", cfg.DBDriver))
	for _, p := range cfg.BroadTrustedProxies() {
		logger.WarnContext(ctx, "broad trusted proxy prefix: every host inside it may forge the client IP; "+
			"list the reverse proxies by their exact IP address in "+config.EnvTrustedProxies,
			slog.String("prefix", p.String()))
	}

	db, err := openDatabase(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeWith(db.Close, "database")) }()

	for _, dir := range []string{cfg.DataDir, cfg.LogDir} {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("app: create directory %s: %w", dir, err)
		}
	}
	secLog, err := securitylog.Open(filepath.Join(cfg.LogDir, SecurityLogName),
		securitylog.WithErrorHandler(func(err error) {
			logger.Error("security log reopen failed", slog.String("error", err.Error()))
		}))
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	defer func() { err = errors.Join(err, closeWith(secLog.Close, "security log")) }()
	// Deferred after secLog.Close, so it runs before it: no reopening can
	// race with the close.
	stopSIGHUP := secLog.HandleSIGHUP(ctx)
	defer stopSIGHUP()

	maintenance := o.maintenance
	if maintenance == nil {
		maintenance = new(atomic.Bool)
	}
	maintenance.Store(cfg.Maintenance)
	if cfg.Maintenance {
		logger.WarnContext(ctx, "maintenance mode is active: deposits are refused")
	}

	clamd := antivirus.NewClient(cfg.ClamAV.Network, cfg.ClamAV.Address)
	handler := httpserver.New(httpserver.Deps{
		TrustedProxy: cfg.IsTrustedProxy,
		Resolver:     tenant.NewResolver(db.Tenants()),
		SecurityLog:  secLog,
		Health: &health.Service{
			Database:  health.Check{Checker: health.CheckerFunc(db.Ping)},
			Antivirus: health.Check{Checker: health.CheckerFunc(clamd.Ping)},
			Storage:   health.Check{Checker: health.StorageCheck(cfg.DataDir)},
			Logger:    logger,
		},
		Maintenance: maintenance,
		Spec:        api.OpenAPISpec,
		Logger:      logger,
	})
	return serve(ctx, cfg, &o, handler, logger)
}

// openDatabase opens the database, applies the migrations when this
// process may, forgets the owner credentials and verifies the runtime role.
func openDatabase(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*store.DB, error) {
	db, err := store.Open(ctx, cfg, store.WithLogger(logger))
	if err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}
	if err := migrate(ctx, cfg, db, logger); err != nil {
		return nil, errors.Join(err, closeWith(db.Close, "database"))
	}
	return db, nil
}

// migrate applies the start-up migrations, then drops the owner
// credentials (from db and from cfg) and verifies the runtime role.
func migrate(ctx context.Context, cfg *config.Config, db *store.DB, logger *slog.Logger) error {
	switch {
	case cfg.DBDriver == config.DriverSQLite || cfg.DBMigrateDSN.IsSet():
		n, err := db.Migrate(ctx)
		if err != nil {
			return fmt.Errorf("app: migrate: %w", err)
		}
		logger.InfoContext(ctx, "database migrations applied at start-up", slog.Int("applied", n))
	default:
		logger.InfoContext(ctx, "TT_DB_MIGRATE_DSN not set: start-up migrations skipped (run \"transteira migrate\")")
	}
	db.DropMigrationCredentials()
	cfg.DBMigrateDSN = config.Secret{}
	if err := db.Verify(ctx); err != nil {
		return fmt.Errorf("app: %w", err)
	}
	return nil
}

// serve runs the HTTP server until ctx is canceled or the server fails.
//
// On shutdown, the base context of every request is canceled so that
// long-running (streaming) handlers stop, then the server waits for the
// connections to go idle for at most o.shutdownTimeout. Connections still
// open then are forcibly closed with a warning, which is not an error. serve
// finally waits up to HandlerDrainTimeout for the handlers to return, so that
// the database and the security log, closed by Run afterwards, are not
// closed under a running handler. Residual risk: a handler that ignores both
// its context and the closing of its connection may still run after serve
// returns; it then gets "closed" errors from those resources.
func serve(ctx context.Context, cfg *config.Config, o *runOptions, handler http.Handler, logger *slog.Logger) error {
	ln := o.listener
	if ln == nil {
		var err error
		ln, err = (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("app: listen on %s: %w", cfg.ListenAddr, err)
		}
	}
	baseCtx, cancelBase := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelBase()
	var conns, handlers atomic.Int64
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlers.Add(1)
			defer handlers.Add(-1)
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		// "OPTIONS *" must go through the middlewares (tenant check, headers,
		// rate limit) like any other request instead of net/http's built-in
		// 200 answer.
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		BaseContext:                  func(net.Listener) context.Context { return baseCtx },
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				conns.Add(1)
			case http.StateHijacked, http.StateClosed:
				conns.Add(-1)
			case http.StateActive, http.StateIdle:
			}
		},
	}
	srv.RegisterOnShutdown(cancelBase)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	logger.InfoContext(ctx, "HTTP server listening", slog.String("addr", ln.Addr().String()))

	select {
	case err := <-served:
		return fmt.Errorf("app: HTTP server stopped: %w", err)
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), o.shutdownTimeout)
	defer cancel()
	err := srv.Shutdown(shutdownCtx)
	if errors.Is(err, context.DeadlineExceeded) {
		logger.Warn("graceful shutdown timed out: forcing close of active connections",
			slog.Int64("connections", conns.Load()), slog.Duration("timeout", o.shutdownTimeout))
		err = srv.Close()
	}
	if serveErr := <-served; !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	if !drain(&handlers, HandlerDrainTimeout) {
		logger.Warn("handlers still running after shutdown", slog.Int64("handlers", handlers.Load()))
	}
	if err != nil {
		_ = srv.Close()
		return fmt.Errorf("app: shutdown: %w", err)
	}
	logger.Info("stopped")
	return nil
}

// drainPoll is the polling interval of drain.
const drainPoll = 10 * time.Millisecond

// drain waits until counter drops to zero or timeout elapses, and reports
// whether it reached zero. Polling keeps it free of the WaitGroup rule that
// forbids Add during Wait, since a request read just before the connections
// were closed may still start its handler.
func drain(counter *atomic.Int64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for counter.Load() > 0 {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(drainPoll)
	}
	return true
}

// closeWith calls closeFn and labels its error.
func closeWith(closeFn func() error, what string) error {
	if err := closeFn(); err != nil {
		return fmt.Errorf("app: close %s: %w", what, err)
	}
	return nil
}

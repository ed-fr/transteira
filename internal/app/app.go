// Package app wires the TransTeira server together and runs it: logging,
// master keys, database, migrations, master key check, tenant resolution,
// security log, health checks, mail queue, depositor identification,
// transfers and tus uploads, administrator authentication, tenant
// configuration, and the HTTP server, with a graceful shutdown.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ed-fr/transteira/api"
	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/api/admin"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/apitoken"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/avalert"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/datasubject"
	"github.com/ed-fr/transteira/internal/deposit"
	"github.com/ed-fr/transteira/internal/diskalert"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/httpserver"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/keyrotation"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/maintenance"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/quota"
	"github.com/ed-fr/transteira/internal/scan"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/stats"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/systemsettings"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
	"github.com/ed-fr/transteira/internal/tenantops"
	"github.com/ed-fr/transteira/internal/transfer"
	"github.com/ed-fr/transteira/internal/upload"
	"github.com/ed-fr/transteira/internal/usage"
	"github.com/ed-fr/transteira/internal/version"
	"github.com/ed-fr/transteira/web"
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
	// ShutdownTimeout bounds the graceful shutdown of the HTTP server. With
	// HandlerDrainTimeout, BackgroundCloseTimeout, FinalCloseTimeout and
	// MailDrainTimeout it makes a worst-case shutdown of 9 s, strictly below
	// Docker's default 10 s stop grace period (stop_grace_period in
	// docker-compose), so that connections still open are closed by
	// TransTeira itself, with a warning, and the database is closed cleanly
	// before Docker sends SIGKILL. Raise stop_grace_period before raising
	// any of the five values.
	ShutdownTimeout = 5 * time.Second
	// HandlerDrainTimeout bounds the wait for handlers to return once the
	// connections have been forcibly closed, before the database and the
	// security log are closed.
	HandlerDrainTimeout = time.Second
	// BackgroundCloseTimeout bounds the wait for the background workers to
	// stop at shutdown (first stage of closeStages), after the HTTP server
	// and before the mail queue and the database. They are closed at once,
	// under this one deadline:
	//   - the antivirus workers: an analysis in progress is abandoned
	//     without counting an attempt, and resumed by the sweep of the next
	//     start;
	//   - the download service: its pending first-download mail retries are
	//     dropped (logged);
	//   - the lifecycle sweeper: an erasure in progress stops before its next
	//     transfer and is completed by a later run; a SQLite copy in progress
	//     is interrupted (VACUUM INTO under a canceled context) and its
	//     temporary file removed, the next night writes a new one;
	//   - the quota monitor: pending evaluations are dropped (the next start
	//     sweeps every tenant), an alert already decided is still sent;
	//   - the master key rotation worker: the rotation stops at its current
	//     batch and stays running, resumable (never recorded as failed); Run
	//     waits for it, beyond this deadline if needed, before destroying
	//     the master keys.
	// It takes one second from the former 7 s of ShutdownTimeout.
	BackgroundCloseTimeout = time.Second
	// FinalCloseTimeout bounds the second stage of closeStages, which has
	// its own deadline so that an exhausted first stage never deprives it:
	// the retrier of the admin mails hands its jobs to the mail queue, and
	// the usage recorder makes the final flush of the counters recorded
	// until then (shutdown included), while the database is still open.
	// It takes one second from the former 6 s of ShutdownTimeout.
	FinalCloseTimeout = time.Second
	// MailDrainTimeout bounds the delivery of the mails still queued at
	// shutdown, once the HTTP server has stopped. Jobs left after it are
	// dropped (a code or an invitation can be requested again). See
	// ShutdownTimeout for the overall budget.
	MailDrainTimeout = time.Second
	// SecurityLogName is the file name of the security log in the log
	// directory.
	SecurityLogName = "security.log"
	// dirMode is the permission of the data and log directories created at
	// start-up when missing.
	dirMode = 0o750
	// SetupTokenPrefix starts the setup token generated while no
	// administrator exists and TT_SETUP_TOKEN is not set.
	SetupTokenPrefix = "stp"
	// setupTokenBytes is the entropy of a generated setup token (192 bits).
	setupTokenBytes = 24
)

// Option customizes Run.
type Option func(*runOptions)

type runOptions struct {
	listener        net.Listener
	logOutput       io.Writer
	shutdownTimeout time.Duration
	maintenanceHook func(*maintenance.Mode)
	scanOptions     func(*scan.Options)
	lifecycleOpts   func(*lifecycle.Options)
	diskAlertOpts   func(*diskalert.Options)
	avAlertOpts     func(*avalert.Options)
	rotationOpts    func(*keyrotation.Options)
	webUI           fs.FS
}

// WithWebUI serves the web interface from fsys instead of the build
// embedded in the binary (web.Dist), for tests.
func WithWebUI(fsys fs.FS) Option {
	return func(o *runOptions) { o.webUI = fsys }
}

// WithRotationOptions lets edit change the options of the master key
// rotation service before it is created (tests: a small batch size, a
// progress hook).
func WithRotationOptions(edit func(*keyrotation.Options)) Option {
	return func(o *runOptions) { o.rotationOpts = edit }
}

// WithScanOptions lets edit change the options of the antivirus worker
// before it is created (tests: shorter retry delays). The configured
// values are already set when edit runs.
func WithScanOptions(edit func(*scan.Options)) Option {
	return func(o *runOptions) { o.scanOptions = edit }
}

// WithLifecycleOptions lets edit change the options of the lifecycle
// sweeper before it is created (tests: a short sweep interval).
func WithLifecycleOptions(edit func(*lifecycle.Options)) Option {
	return func(o *runOptions) { o.lifecycleOpts = edit }
}

// WithDiskAlertOptions lets edit change the options of the disk alert
// monitor before it is created (tests: a fake Measure, a short Interval).
func WithDiskAlertOptions(edit func(*diskalert.Options)) Option {
	return func(o *runOptions) { o.diskAlertOpts = edit }
}

// WithAntivirusAlertOptions lets edit change the options of the antivirus
// alert monitor before it is created (tests: a short Grace).
func WithAntivirusAlertOptions(edit func(*avalert.Options)) Option {
	return func(o *runOptions) { o.avAlertOpts = edit }
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

// WithMaintenanceMode calls hook with the maintenance mode once it is
// loaded, before the server starts (tests: toggle the mode with
// maintenance.Mode.Force, read it with Active).
func WithMaintenanceMode(hook func(*maintenance.Mode)) Option {
	return func(o *runOptions) { o.maintenanceHook = hook }
}

// processStart is the start of the process, the start of a maintenance
// forced by TT_MAINTENANCE.
var processStart = time.Now()

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
// broad prefixes), logger, master keys (TT_MASTER_KEY_FILE and, during a
// rotation, TT_MASTER_KEY_NEW_FILE), database, migrations (always with
// SQLite; with PostgreSQL only when cfg.DBMigrateDSN is set, otherwise they
// are expected to be applied by "transteira migrate"), drop of the owner
// credentials and role verification, master key check (masterkey.Check),
// refusal of an admin host that is also a tenant FQDN, tenant resolver,
// security log, maintenance mode (TT_MAINTENANCE or the choice stored by
// the super admin), mail queue and depositor identification service,
// administrator authentication (with the setup token generated and logged
// while no administrator exists, see newAdminService), tenant configuration
// service (sharing the tenant resolver, which it invalidates, and the
// guarded SMTP sender), health checks, HTTP server. At shutdown, once the
// HTTP server has stopped, the background workers stop (at most
// BackgroundCloseTimeout), then the retrier of the admin mails and the
// usage recorder with its final flush (at most FinalCloseTimeout), then the
// mail queue is drained (at most MailDrainTimeout), before the database is
// closed.
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

	// The master keys are read before the database is touched: a missing,
	// unreadable or malformed key file refuses the start right away.
	keys, err := masterkey.Load(cfg)
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	// Deferred first, so it runs last: the keys are destroyed once the
	// handlers have drained and the database is closed.
	defer keys.Close()

	db, err := OpenDatabase(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeWith(db.Close, "database")) }()

	if err := checkKeys(ctx, db, keys, logger); err != nil {
		return err
	}
	if err := checkAdminHosts(ctx, db.Tenants(), cfg.AdminHosts); err != nil {
		return err
	}

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

	// One writer records the audit events of the whole application: the
	// maintenance mode, deposits, transfers, antivirus, quota and disk
	// alerts, settings and key rotation.
	auditLog := audit.New(db)

	// The maintenance mode: TT_MAINTENANCE forces it, otherwise the choice
	// stored by the super admin applies.
	maint, err := maintenance.New(ctx, db.SystemSettings(), auditLog,
		maintenance.Options{Forced: cfg.Maintenance, Start: processStart})
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	if st := maint.State(); st.Enabled {
		logger.WarnContext(ctx, "maintenance mode is active: deposits are refused",
			slog.String("source", string(st.Source)))
	}
	if o.maintenanceHook != nil {
		o.maintenanceHook(maint)
	}

	// The queue owns the context of its deliveries, canceled by Close. Its
	// close is deferred after db.Close, so it runs before it, and after
	// serve has returned, so that no handler can enqueue a mail any more.
	// One sender serves the queue and the SMTP test of the administration:
	// every tenant SMTP connection dials through the guard refusing the
	// denied networks (TT_SMTP_DENY_NETWORKS, threat model P21).
	smtpSender := newSMTPSender(cfg)
	mailQueue := mail.NewQueue(smtpSender, cfg.MailQueueSize, logger, mailQueueOptions(cfg)) //nolint:contextcheck // see above
	// The instance mails (disk alert) have their own small queue and SMTP
	// sender (TT_SYSTEM_SMTP_*, see systemMail), drained in parallel with
	// the tenant queue.
	sysMail, err := newSystemMail(cfg, logger) //nolint:contextcheck // the queue owns its context, see above
	if err != nil {
		return err
	}
	defer closeMailQueues(ctx, logger, mailQueue, sysMail.queue)
	vault := masterkey.NewVault(db, keys, logger)
	// The mails of a tenant use its customized templates when it has some.
	overrides := notify.StoreOverrides(db.TenantEmailTemplates())
	// One recorder counts the usage statistics.
	usageCounts := usage.New(db, usage.Options{Logger: logger})
	deposits := deposit.New(db, keys, vault, mailQueue, secLog, deposit.Options{
		SessionTTL: cfg.DepositSessionTTL, Logger: logger, Overrides: overrides, Audit: auditLog,
	})
	files, err := storage.New(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	// Deferred after db.Close, so it runs before it, once the handlers
	// have drained.
	defer func() { err = errors.Join(err, closeWith(files.Close, "data directory")) }()
	clamd := antivirus.NewClient(cfg.ClamAV.Network, cfg.ClamAV.Address,
		antivirus.WithMaxScanBytes(cfg.ClamAVMaxScanBytes), antivirus.WithScanTimeout(cfg.ClamAVTimeout))
	uploads := upload.New(db, vault, files, upload.Options{UploadTTL: cfg.UploadTTL, MaxAge: cfg.UploadMaxAge, Logger: logger})
	notifier := notify.New(vault, db.SMTPSettings(), nil, notify.Options{Logger: logger, Overrides: overrides})
	// One hasher bounds the argon2id computations of the transfer passwords,
	// at creation (transfer) and at unlock (download), and of the admin
	// passwords (login, setup, activation, change).
	passwords := crypto.NewPasswordHasher(transfer.DefaultHashConcurrency)
	// The quota alerts, the antivirus alerts of the tenants and the resent
	// notifications are queued through one retrier, so that a full queue
	// delays them instead of dropping them.
	opsMails := mail.NewRetrier(mailQueue, mail.RetryOptions{Logger: logger})
	// The antivirus alert follows the outages the worker reports (decision
	// P10): the super admins by system mail, the administrators of the
	// tenants with transfers waiting through the tenant queue.
	avAlerts, err := avalert.New(db, auditLog, antivirusAlertOptions(cfg, &o, sysMail, avalert.Options{
		Notifier: notifier, TenantMailer: opsMails, Pinger: clamd, Logger: logger,
	}))
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	worker := scan.New(scan.Deps{
		DB: db, Vault: vault, Files: files, Scanner: clamd, Remover: uploads, Notifier: notifier, Mail: mailQueue,
		Audit: auditLog, Usage: usageCounts, Outage: avAlerts,
	}, scanOptions(cfg, &o, logger))
	downloads := download.New(download.Deps{
		DB: db, Vault: vault, Files: files, Keys: keys, Passwords: passwords, Notifier: notifier, Mail: mailQueue,
		SecurityLog: secLog, Usage: usageCounts,
	}, download.Options{Grace: cfg.DeleteAfterDownloadGrace, Logger: logger})
	// The sweeper holds the antivirus worker before erasing a transfer, so
	// that a transfer deleted while it is scanned is never made available.
	sweeper := lifecycle.New(lifecycle.Deps{DB: db, Vault: vault, Remover: uploads, Files: files, Holder: worker},
		lifecycleOptions(cfg, &o, logger))
	admins, err := newAdminService(ctx, cfg, db, adminDeps{
		keys: keys, vault: vault, hasher: passwords, seclog: secLog,
	}, logger)
	if err != nil {
		return err
	}
	// The master key rotations of the administration run in a worker of
	// their own, stopped in the first close stage. Deferred before
	// closeStages, so it runs after it but before the database and the keys
	// are closed: the worker re-wraps keys with the keyring, so the keys are
	// never destroyed under it, even past the stage budget.
	rotations := keyrotation.New(db, keys, admins, auditLog, rotationOptions(&o, logger))
	defer waitRotation(ctx, rotations, logger)
	if err := rotations.WarnInterrupted(ctx); err != nil {
		return fmt.Errorf("app: %w", err)
	}
	quotas, err := quota.New(db, notifier, opsMails, auditLog, quota.Options{
		AdminLink: adminBaseURL(cfg) + "/admin", Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	diskAlerts, err := diskalert.New(db, auditLog, diskAlertOptions(cfg, &o, sysMail, logger))
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	// Deferred after closeMailQueues, the data directory and the database, so
	// it runs before them: the workers stop enqueueing mails, touching the
	// files and counting usage before the queue drains, then the retrier of
	// the admin mails stops and the usage counters get their final flush,
	// while the database is still open.
	defer closeStages(ctx, logger,
		closeStage{timeout: BackgroundCloseTimeout, closers: []closer{worker, downloads, sweeper, quotas, diskAlerts, avAlerts, rotations}},
		closeStage{timeout: FinalCloseTimeout, closers: []closer{opsMails, sysMail, usageCounts}})
	transfers := newTransferService(cfg, db, transferDeps{
		vault: vault, uploads: uploads, secLog: secLog, passwords: passwords, onFinalized: worker.Enqueue,
		onQuota: quotas.Check, audit: auditLog, usage: usageCounts,
	}, logger)
	// The resolver of the HTTP tenant middleware is invalidated by the
	// tenant configuration after every change of a tenant row.
	resolver := tenant.NewResolver(db.Tenants())
	tenants, err := tenantadmin.New(db, tenantadmin.Options{
		AdminHosts: cfg.AdminHosts, SMTPDenyNetworks: cfg.SMTPDenyNetworks,
		Vault: vault, Assets: assetStore{files: files}, Eraser: sweeper, Mailer: smtpSender, Cache: resolver,
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	// Started before the worker, so that the outage its start-up sweep may
	// find is followed at once (a report made earlier is kept anyway).
	if err := avAlerts.Start(ctx); err != nil {
		return fmt.Errorf("app: start the antivirus alert monitor: %w", err)
	}
	if err := worker.Start(ctx); err != nil {
		return fmt.Errorf("app: start the antivirus workers: %w", err)
	}
	if err := sweeper.Start(ctx); err != nil {
		return fmt.Errorf("app: start the lifecycle sweeper: %w", err)
	}
	if err := usageCounts.Start(ctx); err != nil {
		return fmt.Errorf("app: start the usage recorder: %w", err)
	}
	if err := quotas.Start(ctx); err != nil {
		return fmt.Errorf("app: start the quota monitor: %w", err)
	}
	if err := diskAlerts.Start(ctx); err != nil {
		return fmt.Errorf("app: start the disk alert monitor: %w", err)
	}
	// A change of the system settings, served by the admin API,
	// re-evaluates the disk alert at once.
	systemSettings, err := systemsettings.New(db, auditLog, systemsettings.Options{OnChange: diskAlerts.Check})
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	operations, err := tenantops.New(db, tenantops.Options{
		Vault: vault, Eraser: sweeper, Notifier: notifier, Mailer: opsMails, Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	subjects, err := datasubject.New(db, datasubject.Options{Eraser: sweeper, Holder: worker, Logger: logger})
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	statistics, err := stats.New(db, stats.Options{
		DataDir: cfg.DataDir, Settings: db.SystemSettings(), AlertMailConfigured: cfg.SystemSMTP.Enabled(), Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}

	// apiTokens authenticates the API tokens of the deposit operations
	// (httpserver.Deps.APITokens) and serves their administration.
	apiTokens, err := apitoken.New(db, apitoken.Options{Logger: logger})
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}

	handler := httpserver.New(httpserver.Deps{
		TrustedProxy: cfg.IsTrustedProxy,
		Resolver:     resolver,
		SecurityLog:  secLog,
		Health: &health.Service{
			Database:  health.Check{Checker: health.CheckerFunc(db.Ping)},
			Antivirus: health.Check{Checker: health.CheckerFunc(clamd.Ping)},
			Storage:   health.Check{Checker: health.StorageCheck(cfg.DataDir)},
			Logger:    logger,
		},
		Maintenance: maint,
		API: public.NewServer(public.WithDeposit(deposits), public.WithTransfers(transfers),
			public.WithUploads(uploads), public.WithDownloads(downloadAdapter{svc: downloads}),
			public.WithTenantService(tenants), public.WithMaintenance(maint)),
		Sessions:   deposits,
		APITokens:  apiTokens,
		AdminHosts: cfg.AdminHosts,
		AdminAPI: admin.NewServer(admin.WithService(admins), admin.WithTenants(db.Tenants()),
			admin.WithTenantService(tenants), admin.WithOperationsService(operations),
			admin.WithDataSubjectService(subjects), admin.WithStatsService(statistics),
			admin.WithAPITokenService(apiTokens), admin.WithMaintenance(maint),
			admin.WithSystemSettings(systemSettings), admin.WithKeyRotation(rotations)),
		AdminSessions:       admins,
		UploadIdleTimeout:   cfg.UploadIdleTimeout,
		DownloadIdleTimeout: cfg.DownloadIdleTimeout,
		Spec:                api.OpenAPISpec,
		APIDocsPublic:       cfg.APIDocsPublic,
		WebUI:               webUI(&o),
		Logger:              logger,
	})
	return serve(ctx, cfg, &o, handler, logger)
}

// webUI returns the build of the web interface to serve: the one embedded
// in the binary unless WithWebUI replaced it. httpserver.New logs a warning
// when an entry page is missing (binary built without make web-build).
func webUI(o *runOptions) fs.FS {
	if o.webUI != nil {
		return o.webUI
	}
	return web.Dist()
}

// OpenDatabase opens the database as the server does: it applies the
// migrations when this process may (always with SQLite; with PostgreSQL only
// when cfg.DBMigrateDSN is set), forgets the owner credentials (in db and in
// cfg) and verifies the runtime role. Commands that work on a live database,
// such as rotate-master-key, use it to follow the same policy.
func OpenDatabase(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*store.DB, error) {
	db, err := store.Open(ctx, cfg, store.WithLogger(logger))
	if err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}
	if err := migrate(ctx, cfg, db, logger); err != nil {
		return nil, errors.Join(err, closeWith(db.Close, "database"))
	}
	return db, nil
}

// checkKeys runs the startup master key check (threat model T-36) and logs
// the keys in use. The keyring then serves the later steps (wrapped keys of
// files and secrets) through masterkey.NewVault.
func checkKeys(ctx context.Context, db *store.DB, keys *masterkey.Keyring, logger *slog.Logger) error {
	rep, err := masterkey.Check(ctx, db, keys, logger, time.Now())
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	attrs := []any{slog.String("active", rep.ActiveID), slog.String("current", rep.CurrentID)}
	if rep.NewID != "" {
		attrs = append(attrs, slog.String("new", rep.NewID))
	}
	if rep.Registered {
		logger.InfoContext(ctx, "master key registered as active on a new database", attrs...)
	} else {
		logger.InfoContext(ctx, "master key check passed", attrs...)
	}
	return nil
}

// tenantLookup finds the tenant served by a host. *store.Tenants
// implements it.
type tenantLookup interface {
	TenantByFQDN(ctx context.Context, fqdn string) (*tenant.Tenant, error)
}

// checkAdminHosts refuses an admin host that is also the FQDN of a tenant:
// the admin router would shadow the tenant, and the admin session cookie
// would share its origin. The tenant creation refuses an admin host too.
func checkAdminHosts(ctx context.Context, tenants tenantLookup, hosts []string) error {
	for _, h := range hosts {
		fqdn, err := tenant.NormalizeHost(h)
		if err != nil {
			return fmt.Errorf("app: %s: %w", config.EnvAdminHosts, err)
		}
		t, err := tenants.TenantByFQDN(ctx, fqdn)
		switch {
		case errors.Is(err, tenant.ErrUnknownTenant):
			continue
		case err != nil:
			return fmt.Errorf("app: check %s: %w", config.EnvAdminHosts, err)
		}
		return fmt.Errorf("app: %s: %s is also the FQDN of tenant %s: an admin host must not serve a tenant",
			config.EnvAdminHosts, fqdn, t.ID)
	}
	return nil
}

// adminDeps are the dependencies of the administrator authentication
// service.
type adminDeps struct {
	keys   adminauth.Keys
	vault  adminauth.Vault
	hasher adminauth.PasswordHasher
	seclog adminauth.SecurityLog
}

// newAdminService builds the administrator authentication service, with
// the session lifetimes of cfg and the activation links pointing at the
// first admin host.
//
// The first-run setup always needs a setup token: TT_SETUP_TOKEN when set;
// otherwise, while no administrator exists, a random token generated at
// each start and written ONCE to the application log, at WARN level, with
// the setup address. Once an administrator exists, no token is generated
// and nothing is logged (the setup is refused anyway).
func newAdminService(ctx context.Context, cfg *config.Config, db *store.DB, d adminDeps, logger *slog.Logger) (*adminauth.Service, error) {
	if len(cfg.AdminHosts) == 0 {
		return nil, fmt.Errorf("app: %s is required", config.EnvAdminHosts)
	}
	baseURL := adminBaseURL(cfg)
	setupToken := cfg.SetupToken.Reveal()
	if setupToken == "" {
		n, err := db.Admins().CountAll(ctx)
		if err != nil {
			return nil, fmt.Errorf("app: count admins: %w", err)
		}
		if n == 0 {
			if setupToken, err = id.NewToken(SetupTokenPrefix, setupTokenBytes); err != nil {
				return nil, fmt.Errorf("app: generate the setup token: %w", err)
			}
			// SECURITY (decision P11): this is the only place where a secret
			// is written to a log. The token only allows the creation of the
			// first super admin, only while no administrator exists, and only
			// until the next restart, which generates a new one; the operator
			// reads it from the container logs, which are as trusted as the
			// TT_SETUP_TOKEN it replaces. Set TT_SETUP_TOKEN to avoid it.
			logger.WarnContext(ctx, "No admin exists yet. Setup token: "+setupToken+
				" (valid until restart). Open "+baseURL+"/admin/setup")
		}
	}
	svc, err := adminauth.New(db, d.keys, d.vault, d.hasher, d.seclog, adminauth.Options{
		IdleTimeout: cfg.AdminSessionIdleTimeout, MaxAge: cfg.AdminSessionMaxAge,
		SetupToken: setupToken, AdminBaseURL: baseURL, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}
	return svc, nil
}

// adminBaseURL returns the absolute URL of the first admin host, the base
// of the links put in the activation and quota alert mails (never derived
// from a request). cfg.AdminHosts must not be empty.
func adminBaseURL(cfg *config.Config) string {
	return "https://" + cfg.AdminHosts[0]
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

// transferDeps are the dependencies of the transfer service.
type transferDeps struct {
	vault     *masterkey.Vault
	uploads   *upload.Engine
	secLog    *securitylog.Logger
	passwords *crypto.PasswordHasher
	// onFinalized (the antivirus worker's Enqueue) is called after each
	// finalization.
	onFinalized func(tenant.ID, string)
	// onQuota (the quota monitor's Check) is called after each creation
	// and each refusal for quota.
	onQuota func(tenant.ID, bool)
	audit   transfer.AuditRecorder
	usage   transfer.UsageRecorder
}

// newTransferService builds the transfer service over the tus upload
// engine of d. The uploads in flight at shutdown stop with the base
// context of their request (canceled by serve): the engine saves a
// checkpoint, and the client resumes after a HEAD.
func newTransferService(cfg *config.Config, db *store.DB, d transferDeps, logger *slog.Logger) *transfer.Service {
	return transfer.New(db, d.vault, d.uploads, d.secLog, transfer.Options{
		MaxRecipients: cfg.MaxRecipients, MaxOpenTransfers: cfg.MaxOpenTransfers, UploadMaxAge: cfg.UploadMaxAge,
		Hasher: d.passwords, OnFinalized: d.onFinalized, OnQuota: d.onQuota, Audit: d.audit, Usage: d.usage,
		Logger: logger,
	})
}

// downloadBackend is the part of *download.Service the HTTP layer uses.
type downloadBackend interface {
	Resolve(ctx context.Context, t *tenant.Tenant, rawToken, grantCookie string) (download.View, error)
	Unlock(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, password, grantCookie string) (string, error)
	OpenFile(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, grantCookie, fileID string) (*download.File, error)
	PrepareArchive(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, grantCookie string) (*download.Archive, error)
}

// downloadAdapter adapts the download service to public.DownloadService:
// the opened file and the archive are handed over as the narrow views the
// handlers use.
type downloadAdapter struct {
	svc downloadBackend
}

// Resolve implements public.DownloadService.
func (a downloadAdapter) Resolve(ctx context.Context, t *tenant.Tenant, rawToken, grantCookie string) (download.View, error) {
	return a.svc.Resolve(ctx, t, rawToken, grantCookie)
}

// Unlock implements public.DownloadService.
func (a downloadAdapter) Unlock(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, password, grantCookie string) (string, error) {
	return a.svc.Unlock(ctx, t, rawToken, clientIP, password, grantCookie)
}

// OpenFile implements public.DownloadService.
func (a downloadAdapter) OpenFile(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, grantCookie, fileID string) (public.DownloadFile, error) {
	f, err := a.svc.OpenFile(ctx, t, rawToken, clientIP, grantCookie, fileID)
	if err != nil {
		return public.DownloadFile{}, err
	}
	return public.DownloadFile{Name: f.Name, SHA256: f.SHA256, Content: f.Content}, nil
}

// PrepareArchive implements public.DownloadService.
func (a downloadAdapter) PrepareArchive(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, grantCookie string) (public.DownloadArchive, error) {
	archive, err := a.svc.PrepareArchive(ctx, t, rawToken, clientIP, grantCookie)
	if err != nil {
		return nil, err
	}
	return archive, nil
}

// lifecycleOptions returns the options of the lifecycle sweeper (the
// nightly copy settings, and the shortest life of an upload, which bounds
// the abandoned upload candidates), edited by WithLifecycleOptions when
// given.
func lifecycleOptions(cfg *config.Config, o *runOptions, logger *slog.Logger) lifecycle.Options {
	opts := lifecycle.Options{
		UploadTTL:               min(cfg.UploadTTL, cfg.UploadMaxAge),
		AdminSessionIdleTimeout: cfg.AdminSessionIdleTimeout,
		BackupDir:               cfg.BackupDir, BackupTime: cfg.BackupTime, BackupKeep: cfg.BackupKeep,
		Logger: logger,
	}
	if o.lifecycleOpts != nil {
		o.lifecycleOpts(&opts)
	}
	return opts
}

// scanOptions returns the options of the antivirus worker: the configured
// number of workers, edited by WithScanOptions when given.
func scanOptions(cfg *config.Config, o *runOptions, logger *slog.Logger) scan.Options {
	opts := scan.Options{Workers: cfg.ScanWorkers, Logger: logger}
	if o.scanOptions != nil {
		o.scanOptions(&opts)
	}
	return opts
}

// rotationOptions returns the options of the master key rotation service,
// edited by WithRotationOptions when given.
func rotationOptions(o *runOptions, logger *slog.Logger) keyrotation.Options {
	opts := keyrotation.Options{Logger: logger}
	if o.rotationOpts != nil {
		o.rotationOpts(&opts)
	}
	return opts
}

// rotationWaiter is the part of *keyrotation.Service waitRotation uses.
type rotationWaiter interface {
	Done() <-chan struct{}
}

// waitRotation waits, at shutdown, for the master key rotation worker
// (canceled by its Close in the first close stage) to stop, without any
// time limit: the keys it re-wraps with are destroyed right after, and a
// rotation must never see them destroyed. A canceled rotation stops at its
// current batch, so the wait is short; a warning tells when it exceeds the
// stage budget.
func waitRotation(ctx context.Context, r rotationWaiter, logger *slog.Logger) {
	select {
	case <-r.Done():
		return
	default:
	}
	logger.WarnContext(ctx, "waiting for the master key rotation to stop before destroying the master keys")
	<-r.Done()
}

// closer is a background component stopped at shutdown.
type closer interface {
	Close(ctx context.Context) error
}

// closeStage is a set of background components stopped at once, within
// timeout.
type closeStage struct {
	timeout time.Duration
	closers []closer
}

// closeStages stops the background components stage after stage, the
// components of one stage at once, each stage within its own timeout
// (not canceled with ctx, already done at shutdown): a later stage holds
// the components the earlier ones feed (the retrier of the admin mails;
// the usage recorder, whose Close makes the final flush of the counters),
// and keeps its whole budget however long the earlier stages took. A stop
// cut short is logged, not returned: what was interrupted is resumed at
// the next start.
func closeStages(ctx context.Context, logger *slog.Logger, stages ...closeStage) {
	for _, st := range stages {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), st.timeout)
		closeAll(sctx, logger, st.closers)
		cancel()
	}
}

// closeAll stops closers at once, within ctx, logging a stop cut short.
func closeAll(ctx context.Context, logger *slog.Logger, closers []closer) {
	var wg sync.WaitGroup
	for _, c := range closers {
		wg.Go(func() {
			if err := c.Close(ctx); err != nil {
				logger.WarnContext(ctx, "background worker still running at shutdown",
					slog.String("worker", fmt.Sprintf("%T", c)), slog.String("error", err.Error()))
			}
		})
	}
	wg.Wait()
}

// newSMTPSender returns the SMTP sender of the mail queue and of the SMTP
// test. It dials through a netpolicy.DialGuard over
// cfg.SMTPDenyNetworks: the address of a tenant SMTP server is resolved and
// checked at each connection (threat model P21, DNS rebinding included).
// The EHLO name stays the mail package default ("localhost"): the instance
// serves several tenant FQDNs and knows no single public host name of its
// own, and the relays TransTeira targets (internal relay, Microsoft 365,
// classic authenticated SMTP) do not check it.
func newSMTPSender(cfg *config.Config) *mail.SMTPSender {
	guard := netpolicy.NewDialGuard(cfg.SMTPDenyNetworks, nil)
	return mail.NewSMTPSender(mail.SMTPOptions{Timeout: cfg.SMTPTimeout, Dial: guard.DialContext})
}

// assetStore keeps the branding images of the tenants in the data
// directory (tenantadmin.AssetStore), under the fixed asset names of
// package storage.
type assetStore struct {
	files *storage.Store
}

// errUnknownAsset reports a branding kind without asset name.
var errUnknownAsset = errors.New("app: unknown branding image kind")

// assetName maps a branding kind to its storage asset name.
func assetName(kind branding.Kind) (string, error) {
	switch kind {
	case branding.KindLogo:
		return storage.AssetLogo, nil
	case branding.KindBackground:
		return storage.AssetBackground, nil
	default:
		return "", errUnknownAsset
	}
}

// Put implements tenantadmin.AssetStore.
func (a assetStore) Put(tid tenant.ID, kind branding.Kind, data []byte) error {
	name, err := assetName(kind)
	if err != nil {
		return err
	}
	return a.files.WriteAsset(tid, name, data)
}

// Get implements tenantadmin.AssetStore; a missing image matches
// fs.ErrNotExist.
func (a assetStore) Get(tid tenant.ID, kind branding.Kind) ([]byte, error) {
	name, err := assetName(kind)
	if err != nil {
		return nil, err
	}
	return a.files.ReadAsset(tid, name)
}

// Delete implements tenantadmin.AssetStore.
func (a assetStore) Delete(tid tenant.ID, kind branding.Kind) error {
	name, err := assetName(kind)
	if err != nil {
		return err
	}
	return a.files.RemoveAsset(tid, name)
}

// mailQueueOptions returns the explicit tuning of the mail queue: the mail
// package defaults (4 workers, one delivery in flight per tenant, circuit
// opened after 3 consecutive failures for 1 minute), and a per-tenant
// backlog of a quarter of TT_MAIL_QUEUE_SIZE (at least 1), so that one
// tenant cannot fill the whole queue.
func mailQueueOptions(cfg *config.Config) mail.QueueOptions {
	return mail.QueueOptions{
		Workers:           mail.DefaultWorkers,
		TenantConcurrency: mail.DefaultTenantConcurrency,
		TenantQueued:      max(cfg.MailQueueSize/4, 1),
		RetryDelay:        mail.DefaultRetryDelay,
		BreakerThreshold:  mail.DefaultBreakerThreshold,
		BreakerCooldown:   mail.DefaultBreakerCooldown,
	}
}

// closeMailQueue drains the mail queue for at most MailDrainTimeout. A
// drain cut short is logged, not returned: the lost mails can be requested
// again and the shutdown must go on.
// The drain is not canceled with ctx, which is already done at shutdown.
func closeMailQueue(ctx context.Context, q *mail.Queue, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), MailDrainTimeout)
	defer cancel()
	if err := q.Close(ctx); err != nil {
		logger.WarnContext(ctx, "mail queue not drained at shutdown: queued mails dropped", slog.String("error", err.Error()))
	}
}

// closeWith calls closeFn and labels its error.
func closeWith(closeFn func() error, what string) error {
	if err := closeFn(); err != nil {
		return fmt.Errorf("app: close %s: %w", what, err)
	}
	return nil
}

package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Task names one periodic task of the [Sweeper]. The names appear in the
// logs and in [Sweeper.LastRun].
type Task string

// The tasks, in the order of their first run at [Sweeper.Start].
const (
	// TaskDeleteAfterDownload erases the transfers sent with "delete after
	// the first download" once their grace period is over.
	TaskDeleteAfterDownload Task = "delete-after-download"
	// TaskExpire erases the transfers past their expiry, and the files left
	// by a rejected transfer.
	TaskExpire Task = "expire"
	// TaskAbandonedUploads erases the transfers whose uploads expired before
	// their finalization, which releases their quota reservation.
	TaskAbandonedUploads Task = "abandoned-uploads"
	// TaskTenantDeletions completes the deletions of the tenants left in
	// tenant.StatusDeleting (an interrupted [Sweeper.EraseTenant]).
	TaskTenantDeletions Task = "tenant-deletions"
	// TaskPurgeRows deletes the rows that are no longer needed.
	TaskPurgeRows Task = "purge-rows"
	// TaskOrphans removes the files of the tenant directories that the
	// database proves orphaned.
	TaskOrphans Task = "orphans"
	// TaskExpiryReminder mails the recipients who have not downloaded a
	// per-recipient transfer that is about to expire (CLAUDE.md section 12.2, V1.1).
	TaskExpiryReminder Task = "expiry-reminder"
	// TaskBackup writes the nightly copy of a SQLite database.
	TaskBackup Task = "backup"
)

// Default intervals and retention periods.
const (
	// DefaultInterval is the default delay between two runs of
	// TaskDeleteAfterDownload and of TaskExpire.
	DefaultInterval = time.Minute
	// DefaultAbandonedInterval is the default delay between two runs of
	// TaskAbandonedUploads.
	DefaultAbandonedInterval = 15 * time.Minute
	// DefaultTenantDeletionsInterval is the default delay between two runs
	// of TaskTenantDeletions.
	DefaultTenantDeletionsInterval = time.Hour
	// DefaultPurgeInterval is the default delay between two runs of
	// TaskPurgeRows.
	DefaultPurgeInterval = time.Hour
	// DefaultOrphansInterval is the default delay between two runs of
	// TaskOrphans.
	DefaultOrphansInterval = 24 * time.Hour
	// EndedRetention is how long the row of a transfer that reached a
	// terminal status (rejected, expired or deleted) is kept, so that its
	// link answers "gone" (410) rather than "not found" (404).
	EndedRetention = 30 * 24 * time.Hour
	// OrphanGrace is the age (modification time) below which TaskOrphans
	// never touches a file, so that an upload or a download that is starting
	// is never disturbed.
	OrphanGrace = 24 * time.Hour
	// DefaultBackupKeep is the default number of database copies kept.
	DefaultBackupKeep = 7
	// DefaultAdminSessionIdleTimeout is the default idle timeout of the
	// administrator sessions (TT_ADMIN_SESSION_IDLE_TIMEOUT): TaskPurgeRows
	// deletes a session idle for that long, or past its absolute expiry.
	DefaultAdminSessionIdleTimeout = 30 * time.Minute
	// AdminLoginFailureWindow is the longest window of the administrator
	// login failure rules: TaskPurgeRows deletes a counter whose latest
	// failure is that old and whose lock is over.
	AdminLoginFailureWindow = 15 * time.Minute
	// AuditRetentionMonths is how long, in calendar months, the audit
	// events are kept (CLAUDE.md sections 20 and 21.1).
	AuditRetentionMonths = 12
	// UsageRetentionMonths is how long, in calendar months, the daily usage
	// counters of the statistics are kept: the 12-month series plus the
	// current month.
	UsageRetentionMonths = 13
)

// Errors of the [Sweeper].
var (
	// ErrStarted is returned when the sweeper was already started.
	ErrStarted = errors.New("lifecycle: sweeper already started")
	// ErrClosed is returned when the sweeper was closed.
	ErrClosed = errors.New("lifecycle: sweeper closed")
	// ErrUnknownTask is returned by [Sweeper.RunTask] for a name that is not
	// a task.
	ErrUnknownTask = errors.New("lifecycle: unknown task")
	// ErrBackupDisabled is returned by [Sweeper.RunTask] for TaskBackup
	// when Options.BackupDir is empty.
	ErrBackupDisabled = errors.New("lifecycle: database backup disabled")
	// ErrTenantNotDeleting is returned by [Sweeper.EraseTenant] for a tenant
	// that exists and is not in tenant.StatusDeleting: a tenant is only
	// erased once its deletion has been started.
	ErrTenantNotDeleting = errors.New("lifecycle: tenant deletion not started")
)

// Vault destroys wrapped keys inside a transaction. *masterkey.Vault
// implements it.
type Vault interface {
	DestroyTx(ctx context.Context, tx *store.ScopedTx, wkID string) error
}

// Remover erases the files of a transfer and reports its upload activity.
// *upload.Engine implements it.
type Remover interface {
	// LockFiles takes the upload lock of every file, or none.
	LockFiles(fileIDs []string) (unlock func(), err error)
	// RemoveFiles destroys the data keys of the files in one transaction
	// (a file without key is skipped), then removes the files and their
	// checkpoints from disk, keeping the rows, then scrubs once.
	RemoveFiles(ctx context.Context, tid tenant.ID, files []store.TransferFile) error
	// TransferActivity returns the last upload activity of a transfer and
	// when its incomplete uploads expire.
	TransferActivity(ctx context.Context, tid tenant.ID, files []store.TransferFile, createdAt time.Time) (lastActivity, expiresAt time.Time, err error)
}

// Files is the part of the file storage the sweeper uses. *storage.Store
// implements it.
type Files interface {
	TenantDirs() ([]tenant.ID, error)
	List(tid tenant.ID) ([]storage.Entry, error)
	Remove(tid tenant.ID, name string) error
	RemoveCheckpoint(tid tenant.ID, name string) error
	RemoveState(tid tenant.ID, name string) error
	RemoveTemp(tid tenant.ID, file string) error
	RemoveTenantDir(tid tenant.ID) error
}

// HoldIntent tells the antivirus worker why a transfer is held, which
// decides the fate of the mails of a conclusion that committed meanwhile.
type HoldIntent int

const (
	// HoldForErase holds a transfer about to be erased
	// ([Sweeper.EraseTransfer]): the mails of a conclusion committed
	// meanwhile are dropped, nobody is told about the transfer.
	HoldForErase HoldIntent = iota
	// HoldForEdit holds a transfer being edited (a recipient removed by a
	// GDPR erasure): the mails of a conclusion committed meanwhile are
	// deferred, and sent from the current state of the transfer once the
	// last hold is released, unless it is being erased by then.
	HoldForEdit
)

// Holder keeps a transfer away from the antivirus while it is erased
// ([Sweeper.EraseTransfer], HoldForErase) or edited (HoldForEdit): Hold
// cancels and waits for an analysis in progress, drops a queued one, and
// release lets the worker queue the transfer again if it is still
// scanning. *scan.Worker implements it.
type Holder interface {
	Hold(ctx context.Context, tid tenant.ID, trfID string, intent HoldIntent) (release func(), err error)
}

// Deps are the components the sweeper relies on. Every field is required,
// except Holder.
type Deps struct {
	// DB stores the transfers and the other rows.
	DB *store.DB
	// Vault destroys the sealed download tokens.
	Vault Vault
	// Remover erases the files and reports the upload activity.
	Remover Remover
	// Files is the file storage of the tenants.
	Files Files
	// Holder is the antivirus worker, held by [Sweeper.EraseTransfer]; nil
	// when there is none (tests, tools): nothing is held.
	Holder Holder
	// Notifier builds the expiry reminder mails; nil, like Mail and
	// Opener, disables TaskExpiryReminder (tests, tools).
	Notifier ReminderNotifier
	// Mail queues the reminder mails.
	Mail MailQueue
	// Opener unseals the download tokens of the recipient links.
	Opener Opener
	// Audit is the shared audit writer of the application, which publishes
	// the events it writes; nil means a writer of its own over the
	// database, publishing nothing.
	Audit *audit.Writer
}

// Options tunes a [Sweeper]. Zero values select the defaults.
type Options struct {
	// Interval is the delay between two runs of TaskDeleteAfterDownload
	// and of TaskExpire (DefaultInterval).
	Interval time.Duration
	// AbandonedInterval is the delay between two runs of
	// TaskAbandonedUploads (DefaultAbandonedInterval).
	AbandonedInterval time.Duration
	// TenantDeletionsInterval is the delay between two runs of
	// TaskTenantDeletions (DefaultTenantDeletionsInterval).
	TenantDeletionsInterval time.Duration
	// PurgeInterval is the delay between two runs of TaskPurgeRows
	// (DefaultPurgeInterval).
	PurgeInterval time.Duration
	// OrphansInterval is the delay between two runs of TaskOrphans
	// (DefaultOrphansInterval).
	OrphansInterval time.Duration
	// ReminderInterval is the delay between two runs of TaskExpiryReminder
	// (DefaultReminderInterval).
	ReminderInterval time.Duration
	// EndedRetention replaces the constant EndedRetention (tests).
	EndedRetention time.Duration
	// OrphanGrace replaces the constant OrphanGrace (tests).
	OrphanGrace time.Duration
	// ScanningMaxAge replaces the constant store.ScanningMaxAge (tests).
	ScanningMaxAge time.Duration
	// AdminSessionIdleTimeout is the idle timeout of the administrator
	// sessions (TT_ADMIN_SESSION_IDLE_TIMEOUT,
	// DefaultAdminSessionIdleTimeout).
	AdminSessionIdleTimeout time.Duration
	// AuditRetentionMonths replaces the constant AuditRetentionMonths
	// (tests).
	AuditRetentionMonths int
	// UploadTTL is the shortest time after its creation at which the
	// uploads of a transfer can expire, min(TT_UPLOAD_TTL,
	// TT_UPLOAD_MAX_AGE): TaskAbandonedUploads only examines the uploading
	// transfers older than it (all of them when zero).
	UploadTTL time.Duration
	// BackupDir receives the copies of a SQLite database (TT_BACKUP_DIR),
	// an absolute path; TaskBackup is disabled when empty.
	BackupDir string
	// BackupTime is the UTC time of day of TaskBackup, as an offset since
	// midnight (TT_BACKUP_TIME).
	BackupTime time.Duration
	// BackupKeep is the number of copies kept (TT_BACKUP_KEEP,
	// DefaultBackupKeep).
	BackupKeep int
	// Now is the clock of the decisions and of the backup schedule
	// (time.Now when nil).
	Now func() time.Time
	// Logger receives the operational logs, identifiers and counts only
	// (nil discards).
	Logger *slog.Logger
}

// task is a periodic task of the sweeper.
type task struct {
	name Task
	// interval is the delay between the end of a run and the next one;
	// zero for TaskBackup, which runs daily at Options.BackupTime.
	interval time.Duration
	// atStart tells whether the task runs at Start.
	atStart bool
	run     func(ctx context.Context) error
}

// Sweeper is the single periodic cleanup task of the instance. Create it
// with [New], start it with [Sweeper.Start] and stop it with
// [Sweeper.Close]. It is safe for concurrent use.
type Sweeper struct {
	repo    repo
	remover Remover
	files   Files
	holder  Holder
	// notifier, mailer and opener send the expiry reminders; nil disables
	// them.
	notifier ReminderNotifier
	mailer   MailQueue
	opener   Opener
	fs       backupFS
	now      func() time.Time
	logger   *slog.Logger

	endedRetention time.Duration
	orphanGrace    time.Duration
	scanningMaxAge time.Duration
	uploadTTL      time.Duration
	// adminIdleTimeout is the idle timeout of the administrator sessions.
	adminIdleTimeout time.Duration
	// auditRetentionMonths is the retention of the audit events, in
	// calendar months.
	auditRetentionMonths int
	// sysPurges are the global purges of TaskPurgeRows.
	sysPurges  []systemPurge
	backupDir  string
	backupTime time.Duration
	backupKeep int

	// pageSizes are the page sizes of the store's listings, per erasure
	// kind: a page this long means more transfers may be due after it.
	pageSizes [kindCount]int
	// purgeBatch is the page size of the listing of the ended transfers.
	purgeBatch int
	// keyBatch is the page size of the listing of a tenant's wrapped keys,
	// destroyed one transaction per page.
	keyBatch int
	// reminderPage is the page size of the listing of the transfers due
	// for their expiry reminder.
	reminderPage int

	tasks []*task
	// newTimer returns a channel receiving once after d, for the next run
	// of the task, and the function stopping it; the tests replace it.
	newTimer func(t Task, d time.Duration) (<-chan time.Time, func())
	// afterRun, when set, is called at the end of each scheduled run
	// (tests).
	afterRun func(Task, error)

	// runMu serializes the runs of the tasks.
	runMu sync.Mutex

	lastMu sync.Mutex
	last   map[Task]time.Time

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// orDefault returns v, or def when v is not positive.
func orDefault[T time.Duration | int](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}

// New returns a stopped sweeper over deps.
func New(deps Deps, opts Options) *Sweeper {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	holder := deps.Holder
	if holder == nil {
		holder = noHolder{}
	}
	s := &Sweeper{
		repo:    storeRepo{db: deps.DB, vault: deps.Vault, writer: deps.Audit},
		remover: deps.Remover, files: deps.Files, holder: holder, fs: osFS(),
		notifier: deps.Notifier, mailer: deps.Mail, opener: deps.Opener,
		now: opts.Now, logger: opts.Logger,
		endedRetention:       orDefault(opts.EndedRetention, EndedRetention),
		orphanGrace:          orDefault(opts.OrphanGrace, OrphanGrace),
		scanningMaxAge:       orDefault(opts.ScanningMaxAge, store.ScanningMaxAge),
		uploadTTL:            max(opts.UploadTTL, 0),
		adminIdleTimeout:     orDefault(opts.AdminSessionIdleTimeout, DefaultAdminSessionIdleTimeout),
		auditRetentionMonths: orDefault(opts.AuditRetentionMonths, AuditRetentionMonths),
		backupDir:            opts.BackupDir,
		backupTime:           opts.BackupTime,
		backupKeep:           orDefault(opts.BackupKeep, DefaultBackupKeep),
		pageSizes:            [kindCount]int{store.DeletionSweepLimit, store.ExpirySweepLimit, store.AbandonedSweepLimit},
		purgeBatch:           store.PurgeBatchSize,
		keyBatch:             store.MaxPageSize,
		reminderPage:         store.ReminderSweepLimit,
		newTimer:             realTimer,
		last:                 make(map[Task]time.Time),
	}
	s.sysPurges = s.systemPurges()
	interval := orDefault(opts.Interval, DefaultInterval)
	s.tasks = []*task{
		{TaskDeleteAfterDownload, interval, true, s.erasureTask(kindDelete)},
		{TaskExpire, interval, true, s.erasureTask(kindExpire)},
		{TaskAbandonedUploads, orDefault(opts.AbandonedInterval, DefaultAbandonedInterval), true, s.erasureTask(kindAbandoned)},
		{TaskTenantDeletions, orDefault(opts.TenantDeletionsInterval, DefaultTenantDeletionsInterval), true, s.tenantDeletions},
		{TaskPurgeRows, orDefault(opts.PurgeInterval, DefaultPurgeInterval), true, s.purgeRows},
		{TaskOrphans, orDefault(opts.OrphansInterval, DefaultOrphansInterval), true, s.orphans},
		{TaskExpiryReminder, orDefault(opts.ReminderInterval, DefaultReminderInterval), true, s.expiryReminders},
		{TaskBackup, 0, false, s.backup},
	}
	return s
}

// realTimer is the default newTimer, over a time.Timer.
func realTimer(_ Task, d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTimer(d)
	return t.C, func() { t.Stop() }
}

// Start runs, in the background, every task but TaskBackup at once, in the
// order of the Task constants, then each task again after its interval
// (TaskBackup daily at Options.BackupTime UTC), until ctx is done or
// [Sweeper.Close] is called. Tasks never overlap; the failure of one is
// logged and does not stop the others. TaskBackup is not scheduled when
// Options.BackupDir is empty, nor on PostgreSQL, whose copies are made by
// a dedicated container (logged once). Start returns ErrStarted when
// called twice and ErrClosed after Close.
func (s *Sweeper) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return ErrClosed
	case s.started:
		return ErrStarted
	}
	s.started = true
	ctx, s.cancel = context.WithCancel(ctx)
	if !s.repo.backupSupported() {
		s.logger.InfoContext(ctx, "lifecycle: database backups are made by the dedicated PostgreSQL container, not by TransTeira")
	}
	s.wg.Go(func() {
		for _, t := range s.tasks {
			if t.atStart {
				s.scheduled(ctx, t)
			}
		}
		for _, t := range s.tasks {
			if t.name == TaskBackup && (s.backupDir == "" || !s.repo.backupSupported()) {
				continue
			}
			s.wg.Go(func() { s.loop(ctx, t) })
		}
	})
	return nil
}

// loop runs t after each delay until ctx is done.
func (s *Sweeper) loop(ctx context.Context, t *task) {
	for {
		d := t.interval
		if t.name == TaskBackup {
			d = s.nextBackupDelay()
		}
		c, stop := s.newTimer(t.name, d)
		select {
		case <-ctx.Done():
			stop()
			return
		case <-c:
			stop()
		}
		s.scheduled(ctx, t)
	}
}

// nextBackup returns the first time strictly after now that is at UTC
// midnight plus at.
func nextBackup(now time.Time, at time.Duration) time.Time {
	u := now.UTC()
	next := time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).Add(at)
	if !next.After(u) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// scheduled runs t for the background loop and logs its error.
func (s *Sweeper) scheduled(ctx context.Context, t *task) {
	err := s.run(ctx, t.name, t.run)
	if err != nil && ctx.Err() == nil {
		s.logger.ErrorContext(ctx, "lifecycle: task failed", slog.String("task", string(t.name)), slog.Any("error", err))
	}
	if s.afterRun != nil {
		s.afterRun(t.name, err)
	}
}

// run runs fn as the task name, after the run in progress, and records
// the time of its success.
func (s *Sweeper) run(ctx context.Context, name Task, fn func(context.Context) error) error {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := fn(ctx); err != nil {
		return err
	}
	s.lastMu.Lock()
	s.last[name] = s.now()
	s.lastMu.Unlock()
	return nil
}

// RunTask runs the task name once, now, after the run in progress, and
// returns its error: ErrUnknownTask for an unknown name, ErrBackupDisabled
// or store.ErrBackupUnsupported (PostgreSQL) for TaskBackup when it is not
// available, or ctx.Err() when ctx is done.
func (s *Sweeper) RunTask(ctx context.Context, name Task) error {
	for _, t := range s.tasks {
		if t.name == name {
			return s.run(ctx, name, t.run)
		}
	}
	return fmt.Errorf("%w %q", ErrUnknownTask, name)
}

// LastRun returns the end of the last successful run of the task name
// (Options.Now), zero when it never succeeded, for the supervision. A run
// succeeds when it did everything it found due (see the package
// documentation): a run that left any transfer, row or file for the next
// run after a failure does not move it.
func (s *Sweeper) LastRun(name Task) time.Time {
	s.lastMu.Lock()
	defer s.lastMu.Unlock()
	return s.last[name]
}

// Close stops the tasks: a run in progress stops at its next step (an
// interrupted erasure is completed by a later run, a canceled backup leaves
// no copy). Close waits for the background loops to return, at most until
// ctx is done, and returns ctx.Err() then. Calling it more than once, or
// before Start, is harmless.
func (s *Sweeper) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// scrub purges the destroyed keys and the deleted rows from the database
// files; an incomplete checkpoint is only a warning.
func (s *Sweeper) scrub(ctx context.Context) {
	err := s.repo.scrub(ctx)
	switch {
	case errors.Is(err, store.ErrScrubBusy):
		s.logger.WarnContext(ctx, "lifecycle: deleted data may remain in the database WAL until the next checkpoint",
			slog.Any("error", err))
	case err != nil:
		s.logger.ErrorContext(ctx, "lifecycle: scrub of the deleted data failed", slog.Any("error", err))
	}
}

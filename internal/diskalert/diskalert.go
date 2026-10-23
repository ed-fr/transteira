// Package diskalert watches the filesystem holding the data directory and
// alerts the super admins when it fills up (CLAUDE.md sections 12.2 and
// 19): the alert is raised when the share of the disk used reaches the
// threshold of the system settings (85 % by default), and cleared once the
// usage falls 5 points below it.
//
// # Levels
//
// The alert level (normal or raised) is stored in the system settings
// ([store.SystemSettings]). An evaluation measures the disk, computes the
// next level with [Next] and moves the stored level with a compare and
// swap: of concurrent evaluations seeing the same crossing, only the one
// that moved the level acts, so that an alert is sent once per crossing,
// and a restart sends nothing again while the level stays raised.
//
// # Effects
//
// A rise always logs a warning and records the audit event
// disk.alert_raised (system actor "disk", details usedPercent and
// thresholdPercent), even without system mail; when the system SMTP server
// is configured (Options.Mailer), it also mails the disk_alert template
// to every super admin that can sign in, in their language, and to the
// alert address of the settings, in the language recorded with it,
// duplicates removed ignoring case. A fall records disk.alert_cleared and
// sends no mail.
//
// The alert mails are at least MailInterval (an hour) apart, whatever the
// number of crossings: a rise within the hour of the last mail is logged
// and audited but not mailed, so that a super admin toggling the threshold
// cannot flood the recipients. The time of the last mail is persisted
// ([store.SystemSettings.ClaimDiskAlertMail]), so a restart keeps the
// interval. A template that fails to render in one language skips the
// recipients of that language only.
//
// A measure failure is logged once when it starts, or when its message
// changes, and once when the measures recover; the level is left as is.
//
// # Triggers
//
// The monitor evaluates when it starts, every Options.Interval (5 minutes
// by default) and after [Monitor.Check] (the application calls it after a
// change of the system settings). Check never blocks; its requests are
// coalesced.
//
// # Shutdown
//
// [Monitor.Close] stops the loop and drops a pending Check. Once an
// evaluation has moved the level in the database, its audit event and
// mails no longer depend on the cancellation by Close (no later evaluation
// would send them again); Close waits for them within its own budget only,
// so they are best effort at shutdown: when the shutdown outruns them,
// their failures are logged.
package diskalert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/diskusage"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
)

// Defaults and constants.
const (
	// DefaultInterval is the default delay between two measures.
	DefaultInterval = 5 * time.Minute
	// ClearMargin is the drop below the threshold, as a ratio, under which
	// a raised alert clears.
	ClearMargin = 0.05
	// MailTenantID is the mail.Job TenantID of the system mails: their
	// fairness share and circuit breaker in the system queue.
	MailTenantID = "system"
	// MailInterval is the minimum delay between two alert mails, whatever
	// the number of crossings (security review L2: threshold toggling).
	MailInterval = time.Hour
)

// actor is the audit actor of the alerts (actor kind system); objectID is
// their audit object ID (object kind system).
const (
	actor    = "disk"
	objectID = "disk"
)

// basisPoints is the number of basis points in a ratio of 1.
const basisPoints = 10000

var (
	// ErrStarted is returned when the monitor was already started.
	ErrStarted = errors.New("diskalert: monitor already started")
	// ErrClosed is returned when the monitor was closed.
	ErrClosed = errors.New("diskalert: monitor closed")
	// ErrInvalidOptions is returned by [New] for a missing dependency, an
	// invalid administration link or invalid SMTP settings.
	ErrInvalidOptions = errors.New("diskalert: invalid options")
	// errEmptyFilesystem reports a measure of a filesystem of size 0.
	errEmptyFilesystem = errors.New("diskalert: the filesystem reports a size of 0")
)

// Mailer enqueues mails without blocking, retrying those the queue
// refuses. *mail.Retrier implements it.
type Mailer interface {
	Send(ctx context.Context, jobs []mail.Job, attrs ...slog.Attr)
}

// Auditor records a global audit event. *audit.Writer implements it.
type Auditor interface {
	Record(ctx context.Context, ev audit.Event) error
}

// repo is the data the monitor reads and writes. storeRepo implements it.
type repo interface {
	// settings returns the system settings.
	settings(ctx context.Context) (store.SystemSettingsRow, error)
	// compareAndSet moves the disk alert level from old to level.
	compareAndSet(ctx context.Context, old, level int, now time.Time) (bool, error)
	// superAdminContacts returns the super admins to notify.
	superAdminContacts(ctx context.Context) ([]store.AdminContact, error)
	// claimMail takes the alert mail slot at now, unless an alert was
	// mailed less than MailInterval before.
	claimMail(ctx context.Context, now time.Time) (bool, error)
}

// Options configure a Monitor.
type Options struct {
	// DataDir is the data directory, whose filesystem is measured
	// (required).
	DataDir string
	// AdminLink is the absolute http or https URL of the administration
	// console put in the mails, built from the configured admin host,
	// never from a request (required).
	AdminLink string
	// Mailer sends the alert mails through the system mail queue; nil when
	// the system SMTP server is not configured (audit and log only).
	Mailer Mailer
	// SMTP is the system SMTP server of the mails, validated by [New] when
	// Mailer is set.
	SMTP mail.Settings
	// Interval is the delay between two measures (DefaultInterval).
	Interval time.Duration
	// Measure returns the size and free space of the filesystem holding a
	// path (diskusage.Measure).
	Measure func(path string) (total, free uint64, err error)
	// Now is the clock (time.Now).
	Now func() time.Time
	// Logger receives the alerts and the failures (discarded when nil).
	Logger *slog.Logger
}

// Monitor evaluates the disk alert. Its [Monitor.Check] method never
// blocks and is safe for concurrent use.
type Monitor struct {
	repo      repo
	auditor   Auditor
	mailer    Mailer
	smtp      mail.Settings
	dataDir   string
	adminLink string
	interval  time.Duration
	measure   func(path string) (total, free uint64, err error)
	now       func() time.Time
	logger    *slog.Logger
	// render renders a mail template (mail.Render; a field for the tests).
	render func(name, lang string, data any) (mail.Message, error)

	// wake (capacity 1) signals a pending Check.
	wake chan struct{}

	// failMu guards failure, the message of the last measure failure ("" when
	// the measures succeed).
	failMu  sync.Mutex
	failure string

	runMu   sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// New returns a Monitor over db, recording the alerts with auditor. It
// returns ErrInvalidOptions when a dependency is missing, Options.DataDir
// is empty, Options.AdminLink is not an absolute http or https URL, or
// Options.SMTP is invalid while Options.Mailer is set.
func New(db *store.DB, auditor Auditor, opts Options) (*Monitor, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: database required", ErrInvalidOptions)
	}
	return newMonitor(storeRepo{db: db}, auditor, opts)
}

// newMonitor returns a Monitor over r.
func newMonitor(r repo, auditor Auditor, opts Options) (*Monitor, error) {
	if auditor == nil || opts.DataDir == "" {
		return nil, fmt.Errorf("%w: auditor and data directory required", ErrInvalidOptions)
	}
	if u, err := url.Parse(opts.AdminLink); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("%w: the admin link must be an absolute http or https URL", ErrInvalidOptions)
	}
	if opts.Mailer != nil {
		if err := opts.SMTP.Validate(); err != nil {
			return nil, fmt.Errorf("%w: system SMTP settings: %w", ErrInvalidOptions, err)
		}
	}
	m := &Monitor{
		repo: r, auditor: auditor, mailer: opts.Mailer, smtp: opts.SMTP, dataDir: opts.DataDir,
		adminLink: opts.AdminLink, interval: opts.Interval, measure: opts.Measure, now: opts.Now,
		logger: opts.Logger, render: mail.Render, wake: make(chan struct{}, 1),
	}
	if m.interval <= 0 {
		m.interval = DefaultInterval
	}
	if m.measure == nil {
		m.measure = diskusage.Measure
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.logger == nil {
		m.logger = slog.New(slog.DiscardHandler)
	}
	return m, nil
}

// Next returns the alert level following level (store.DiskAlertLevelRaised,
// any other value counting as store.DiskAlertLevelNormal) for a disk used
// at ratio, with the alert threshold threshold: raised at or above the
// threshold, kept raised down to ClearMargin below it, normal under that.
func Next(level int, ratio, threshold float64) int {
	switch {
	case ratio >= threshold:
		return store.DiskAlertLevelRaised
	case level == store.DiskAlertLevelRaised && ratio >= threshold-ClearMargin:
		return store.DiskAlertLevelRaised
	default:
		return store.DiskAlertLevelNormal
	}
}

// Check asks for an evaluation. It never blocks: requests made while one
// is pending are coalesced. It is a no-op on a nil or closed monitor. Its
// signature matches systemsettings.Options.OnChange.
func (m *Monitor) Check() {
	if m == nil {
		return
	}
	m.runMu.Lock()
	closed := m.closed
	m.runMu.Unlock()
	if closed {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default: // a request is already pending
	}
}

// Evaluate measures the disk once and moves the alert level, alerting on a
// change. [Monitor.Run] calls it; it is exported for the tests and the
// callers that drive the monitor themselves. Failures are logged. It does
// nothing once ctx is done (a Check pending at Close is dropped).
func (m *Monitor) Evaluate(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	total, free, err := m.measure(m.dataDir)
	if err == nil && total == 0 {
		err = errEmptyFilesystem
	}
	if !m.measured(ctx, err) {
		return
	}
	free = min(free, total)
	used := total - free
	ratio := float64(used) / float64(total)
	row, err := m.repo.settings(ctx)
	if err != nil {
		m.fail(ctx, "read the system settings", err)
		return
	}
	cur := row.DiskAlertLevel
	next := Next(cur, ratio, float64(row.DiskAlertThresholdBP)/basisPoints)
	if next == cur {
		return
	}
	ok, err := m.repo.compareAndSet(ctx, cur, next, m.now())
	switch {
	case err != nil:
		m.fail(ctx, "store the disk alert level", err)
		return
	case !ok:
		return // another evaluation moved it first, and alerted
	}
	// The level has moved in the database: no later evaluation would act
	// again, so a Close arriving now does not cancel the audit event nor
	// the mails. Close still waits for them within its budget only: at
	// shutdown they are best effort, and their failures are logged.
	ctx = context.WithoutCancel(ctx)
	f := figures{used: used, total: total, ratio: ratio, thresholdBP: row.DiskAlertThresholdBP}
	if next == store.DiskAlertLevelRaised {
		m.raise(ctx, f, row)
		return
	}
	m.logger.InfoContext(ctx, "disk alert cleared: the disk usage fell below the threshold",
		slog.Float64("used_percent", f.usedPercent()), slog.Float64("threshold_percent", f.thresholdPercent()))
	m.record(ctx, audit.ActionDiskAlertCleared, f)
}

// measured logs the measure failures once per change and reports whether
// err is nil.
func (m *Monitor) measured(ctx context.Context, err error) bool {
	m.failMu.Lock()
	defer m.failMu.Unlock()
	if err != nil {
		if msg := err.Error(); msg != m.failure {
			m.failure = msg
			m.logger.ErrorContext(ctx, "diskalert: disk usage unavailable, the disk alert is not evaluated",
				slog.String("error", msg))
		}
		return false
	}
	if m.failure != "" {
		m.failure = ""
		m.logger.InfoContext(ctx, "diskalert: disk usage available again")
	}
	return true
}

// figures are the measures of an alert.
type figures struct {
	used, total uint64
	ratio       float64
	thresholdBP int
}

// usedPercent is the share of the disk used, in percent, rounded down to
// two decimals.
func (f figures) usedPercent() float64 { return math.Floor(f.ratio*basisPoints) / 100 }

// thresholdPercent is the threshold in percent.
func (f figures) thresholdPercent() float64 { return float64(f.thresholdBP) / 100 }

// record writes the audit event action of figures f.
func (m *Monitor) record(ctx context.Context, action audit.Action, f figures) {
	ev := audit.Event{
		ActorKind: store.ActorSystem, Actor: actor, Action: action, ObjectKind: audit.ObjectSystem, ObjectID: objectID,
		Details: map[string]any{"usedPercent": f.usedPercent(), "thresholdPercent": f.thresholdPercent()},
	}
	if err := m.auditor.Record(ctx, ev); err != nil {
		m.fail(ctx, "record the audit event", err)
	}
}

// raise logs, records and mails a raised alert.
func (m *Monitor) raise(ctx context.Context, f figures, row store.SystemSettingsRow) {
	m.logger.WarnContext(ctx, "disk alert: the disk holding the data directory reached the alert threshold",
		slog.Float64("used_percent", f.usedPercent()), slog.Float64("threshold_percent", f.thresholdPercent()),
		slog.Uint64("used_bytes", f.used), slog.Uint64("total_bytes", f.total))
	m.record(ctx, audit.ActionDiskAlertRaised, f)
	if m.mailer == nil {
		m.logger.WarnContext(ctx, "disk alert not mailed: the system SMTP server (TT_SYSTEM_SMTP_HOST) is not configured")
		return
	}
	contacts, err := m.repo.superAdminContacts(ctx)
	if err != nil {
		// The alert address may still be reached.
		m.fail(ctx, "list the super admins to notify", err)
	}
	if row.AlertEmail != "" {
		contacts = append(contacts, store.AdminContact{Email: row.AlertEmail, Language: row.AlertEmailLanguage})
	}
	contacts = dedup(contacts)
	if len(contacts) == 0 {
		m.logger.WarnContext(ctx, "disk alert not mailed: no recipient")
		return
	}
	data := mail.DiskAlertData{
		UsedBytes: clamp(f.used), TotalBytes: clamp(f.total), ThresholdPercent: f.thresholdPercent(), AdminLink: m.adminLink,
	}
	// byLang holds the message of each language, nil when it failed to
	// render: its recipients are skipped, the others still mailed.
	byLang := make(map[string]*mail.Message, 2)
	jobs := make([]mail.Job, 0, len(contacts))
	for _, c := range contacts {
		lang := c.Language
		if !i18n.IsSupported(lang) {
			lang = i18n.Default
		}
		rendered, ok := byLang[lang]
		if !ok {
			msg, err := m.render(mail.TemplateDiskAlert, lang, data)
			if err != nil {
				m.fail(ctx, "render the alert mail", err, slog.String("language", lang))
			} else {
				rendered = &msg
			}
			byLang[lang] = rendered
		}
		if rendered == nil {
			continue
		}
		msg := *rendered
		msg.To = []string{c.Email}
		jobs = append(jobs, mail.Job{TenantID: MailTenantID, Template: mail.TemplateDiskAlert, Settings: m.smtp, Message: msg})
	}
	if len(jobs) == 0 {
		return
	}
	won, err := m.repo.claimMail(ctx, m.now())
	switch {
	case err != nil:
		// The alert matters more than the interval: mail it anyway.
		m.fail(ctx, "record the time of the alert mail", err)
	case !won:
		m.logger.WarnContext(ctx, "disk alert not mailed: an alert mail was sent less than an hour ago",
			slog.Duration("min_interval", MailInterval))
		return
	}
	m.mailer.Send(ctx, jobs, slog.String("template", mail.TemplateDiskAlert), slog.Int("count", len(jobs)))
}

// dedup drops the contacts whose address was already listed, ignoring
// case; the first occurrence keeps its language.
func dedup(in []store.AdminContact) []store.AdminContact {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, c := range in {
		key := strings.ToLower(c.Email)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

// clamp converts a byte count to int64, saturating.
func clamp(n uint64) int64 {
	return int64(min(n, math.MaxInt64))
}

// fail logs a failure, with the extra attributes attrs.
func (m *Monitor) fail(ctx context.Context, what string, err error, attrs ...any) {
	m.logger.ErrorContext(ctx, "diskalert: failed to "+what, append([]any{slog.String("error", err.Error())}, attrs...)...)
}

// Run evaluates at once, every Options.Interval and after every
// [Monitor.Check], until ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	m.Evaluate(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-t.C:
		}
		m.Evaluate(ctx)
	}
}

// Start runs [Monitor.Run] in the background until [Monitor.Close]. The
// cancellation of ctx does not stop it (only its values are kept), so that
// the shutdown order stays under the control of Close. It returns
// ErrStarted when already started and ErrClosed once closed.
func (m *Monitor) Start(ctx context.Context) error {
	m.runMu.Lock()
	defer m.runMu.Unlock()
	switch {
	case m.closed:
		return ErrClosed
	case m.started:
		return ErrStarted
	}
	m.started = true
	ctx, m.cancel = context.WithCancel(context.WithoutCancel(ctx))
	m.done = make(chan struct{})
	go func() {
		defer close(m.done)
		m.Run(ctx)
	}()
	return nil
}

// Close stops the monitor: later [Monitor.Check] calls are ignored and a
// pending one is dropped. When started, it waits for [Monitor.Run] to
// return, at most until ctx is done, and returns ctx.Err() then. Calling it
// more than once is harmless.
func (m *Monitor) Close(ctx context.Context) error {
	m.runMu.Lock()
	m.closed = true
	started, done := m.started, m.done
	if m.cancel != nil {
		m.cancel()
	}
	m.runMu.Unlock()
	if !started {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

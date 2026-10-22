// Package quota watches the storage quota of the tenants and alerts their
// administrators (CLAUDE.md section 8.5): a preventive alert when a tenant
// uses 80 % of its quota, and an alert when the quota is reached and new
// deposits are refused.
//
// # Levels
//
// The alert level of a tenant is 0, 80 or 100, stored in the database
// ([store.QuotaAlerts]). It is computed from the storage used (the
// declared sizes of the transfers uploading, scanning or available) and
// the quota of the tenant:
//
//   - 100 when the storage used reaches the quota, or when a creation was
//     refused for quota while the tenant uses at least 95 % of it;
//   - 80 when the tenant uses at least 80 % of its quota;
//   - 0 otherwise.
//
// A hysteresis avoids an alert at every small change around a threshold:
// level 80 re-arms (goes back to 0) only below 75 %, and level 100 goes
// back to 80 only below 95 %.
//
// A mail is sent only when the level rises, and only by the process that
// moved it in the database ([store.QuotaAlerts.CompareAndSet]), so that two
// concurrent evaluations never send the same alert twice. A level that goes
// down is stored silently. Every rise is recorded in the audit log
// (quota.warning, quota.reached), even when the tenant has no SMTP
// settings: the audit log is the durable trace of the alerts.
//
// # Triggers
//
// The transfer service calls [Monitor.Check] after every creation and
// every refusal for quota; the call never blocks and is coalesced per
// tenant. A sweep of every active tenant runs when the monitor starts and
// every Options.SweepInterval (15 minutes by default): it catches the
// storage freed by expirations and deletions and the quota changes.
//
// # Recipients
//
// The alert goes to the delegated admins attached to the tenant (enabled
// and activated), in their language, else to the super admins, and is
// sent through the SMTP settings of the tenant.
//
// The fallback to the super admins is deliberate (the super admin must
// learn that the quota is full and deposits are refused) but carries a
// known residual risk: the SMTP settings of the tenant may have been set
// by a delegated admin since disabled or detached, pointing at a relay
// they control, which then receives the addresses of the super admins and
// the storage figures of the tenant. The mail holds
// no secret and no link token (only the administration console URL), and
// the SMTP egress guard (TT_SMTP_DENY_NETWORKS) still applies; a super
// admin taking over a tenant whose delegated admins left should review its
// SMTP settings.
//
// # Shutdown
//
// The background loop started by [Monitor.Start] stops only with
// [Monitor.Close], never with the context given to Start (the signal
// context of the server), so that the quota checks requested while the
// HTTP server drains are still evaluated. An alert whose level was moved
// in the database is recorded and mailed even when Close interrupts it:
// once the level has risen, no later evaluation would send it again.
package quota

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/bits"
	"net/url"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Defaults of the Options.
const (
	// DefaultSweepInterval is the default delay between two sweeps.
	DefaultSweepInterval = 15 * time.Minute
	// DefaultMaxPending is the default bound of the tenants waiting for an
	// evaluation requested by [Monitor.Check].
	DefaultMaxPending = 10000
)

// Thresholds, in percent of the quota.
const (
	// warnPercent raises the level to 80; the warning mail shows it.
	warnPercent = mail.QuotaWarningPercent
	// rearmPercent is the usage under which level 80 goes back to 0.
	rearmPercent = 75
	// refusedPercent is the usage from which a refused creation raises the
	// level to 100, and under which level 100 goes back to 80.
	refusedPercent = 95
	// fullPercent raises the level to 100; the reached mail shows it.
	fullPercent = mail.QuotaReachedPercent
)

// actor is the audit actor of the alerts (actor kind system).
const actor = "quota"

var (
	// ErrStarted is returned when the monitor was already started.
	ErrStarted = errors.New("quota: monitor already started")
	// ErrClosed is returned when the monitor was closed.
	ErrClosed = errors.New("quota: monitor closed")
	// ErrInvalidOptions is returned by [New] for a missing dependency or an
	// invalid administration link.
	ErrInvalidOptions = errors.New("quota: invalid options")
)

// Notifier builds the quota alert mails. *notify.Notifier implements it.
type Notifier interface {
	QuotaAlert(ctx context.Context, t *tenant.Tenant, data mail.QuotaAlertData, level notify.QuotaLevel,
		recipients []notify.Contact) ([]mail.Job, error)
}

// Mailer enqueues mails without blocking, retrying those the queue
// refuses. *mail.Retrier implements it.
type Mailer interface {
	Send(ctx context.Context, jobs []mail.Job, attrs ...slog.Attr)
}

// Auditor records an audit event in the scope of a tenant. *audit.Writer
// implements it.
type Auditor interface {
	RecordScoped(ctx context.Context, tid tenant.ID, ev audit.Event) error
}

// repo is the data the monitor reads and writes. storeRepo implements it
// over the store.
type repo interface {
	// tenant returns the tenant tid, whatever its status (store.ErrNotFound
	// when it does not exist).
	tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	// activeTenants returns every active tenant.
	activeTenants(ctx context.Context) ([]*tenant.Tenant, error)
	// usedBytes returns the storage used by tenant tid.
	usedBytes(ctx context.Context, tid tenant.ID) (int64, error)
	// usedBytesAll returns the storage used by every tenant using some.
	usedBytesAll(ctx context.Context) (map[tenant.ID]int64, error)
	// level returns the stored alert level of tenant tid.
	level(ctx context.Context, tid tenant.ID) (int, error)
	// compareAndSet moves the level of tenant tid from old to level.
	compareAndSet(ctx context.Context, tid tenant.ID, old, level int, now time.Time) (bool, error)
	// tenantContacts returns the delegated admins of tenant tid to notify.
	tenantContacts(ctx context.Context, tid tenant.ID) ([]store.AdminContact, error)
	// superAdminContacts returns the super admins to notify.
	superAdminContacts(ctx context.Context) ([]store.AdminContact, error)
}

// Options configure a Monitor.
type Options struct {
	// AdminLink is the absolute http or https URL of the administration
	// console put in the mails, built from the configured admin host (for
	// example "https://admin.example.com/admin"), never from a request
	// (required).
	AdminLink string
	// SweepInterval is the delay between two sweeps of every active tenant
	// (DefaultSweepInterval).
	SweepInterval time.Duration
	// MaxPending bounds the tenants waiting for an evaluation requested by
	// [Monitor.Check] (DefaultMaxPending); beyond it, requests for new
	// tenants are dropped with a warning, the next sweep catching up.
	MaxPending int
	// Now is the clock (time.Now).
	Now func() time.Time
	// Logger receives the failures (discarded when nil).
	Logger *slog.Logger
}

// Monitor evaluates the quota alert level of the tenants and sends the
// alerts. Its [Monitor.Check] method never blocks and is safe for
// concurrent use.
type Monitor struct {
	repo          repo
	notifier      Notifier
	mailer        Mailer
	auditor       Auditor
	adminLink     string
	sweepInterval time.Duration
	maxPending    int
	now           func() time.Time
	logger        *slog.Logger

	// mu guards pending; wake (capacity 1) signals that it is not empty.
	mu      sync.Mutex
	pending map[tenant.ID]bool
	wake    chan struct{}

	runMu   sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// New returns a Monitor over db, sending its alerts with notifier and
// mailer and recording them with auditor. It returns ErrInvalidOptions
// when a dependency is missing or Options.AdminLink is not an absolute http
// or https URL.
func New(db *store.DB, notifier Notifier, mailer Mailer, auditor Auditor, opts Options) (*Monitor, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: database required", ErrInvalidOptions)
	}
	return newMonitor(storeRepo{db: db}, notifier, mailer, auditor, opts)
}

// newMonitor returns a Monitor over r.
func newMonitor(r repo, notifier Notifier, mailer Mailer, auditor Auditor, opts Options) (*Monitor, error) {
	if notifier == nil || mailer == nil || auditor == nil {
		return nil, fmt.Errorf("%w: notifier, mailer and auditor required", ErrInvalidOptions)
	}
	if u, err := url.Parse(opts.AdminLink); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("%w: the admin link must be an absolute http or https URL", ErrInvalidOptions)
	}
	m := &Monitor{
		repo: r, notifier: notifier, mailer: mailer, auditor: auditor, adminLink: opts.AdminLink,
		sweepInterval: opts.SweepInterval, maxPending: opts.MaxPending, now: opts.Now, logger: opts.Logger,
		pending: map[tenant.ID]bool{}, wake: make(chan struct{}, 1),
	}
	if m.sweepInterval <= 0 {
		m.sweepInterval = DefaultSweepInterval
	}
	if m.maxPending <= 0 {
		m.maxPending = DefaultMaxPending
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.logger == nil {
		m.logger = slog.New(slog.DiscardHandler)
	}
	return m, nil
}

// Check asks for an evaluation of tenant tid, after a transfer creation
// (refused false) or a creation refused because of the quota (refused
// true). It never blocks: the requests of a tenant waiting for the
// evaluation are coalesced (a refusal is kept), and a request beyond
// Options.MaxPending tenants is dropped with a warning. It is a no-op on a
// nil or closed monitor and for an empty tid. Its signature matches
// transfer.Options.OnQuota.
func (m *Monitor) Check(tid tenant.ID, refused bool) {
	if m == nil || tid == "" {
		return
	}
	m.runMu.Lock()
	closed := m.closed
	m.runMu.Unlock()
	if closed {
		return
	}
	m.mu.Lock()
	prev, exists := m.pending[tid]
	if !exists && len(m.pending) >= m.maxPending {
		m.mu.Unlock()
		m.logger.Warn("quota: evaluation request dropped, too many tenants waiting",
			slog.String("tenant", string(tid)), slog.Int("max_pending", m.maxPending))
		return
	}
	m.pending[tid] = prev || refused
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default: // a wake-up is already pending
	}
}

// ProcessPending evaluates the tenants requested by [Monitor.Check] since
// the last call. [Monitor.Run] calls it on every request; it is exported
// for the tests and the callers that drive the monitor themselves.
func (m *Monitor) ProcessPending(ctx context.Context) {
	m.mu.Lock()
	batch := m.pending
	m.pending = make(map[tenant.ID]bool, len(batch))
	m.mu.Unlock()
	for tid, refused := range batch {
		if ctx.Err() != nil {
			return
		}
		m.evaluateID(ctx, tid, refused)
	}
}

// evaluateID evaluates tenant tid, reading it and its storage used.
func (m *Monitor) evaluateID(ctx context.Context, tid tenant.ID, refused bool) {
	t, err := m.repo.tenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		m.logger.DebugContext(ctx, "quota: tenant gone, nothing to evaluate", slog.String("tenant", string(tid)))
		return
	case err != nil:
		m.fail(ctx, tid, "read the tenant", err)
		return
	}
	if t.Status != tenant.StatusActive {
		return
	}
	used, err := m.repo.usedBytes(ctx, tid)
	if err != nil {
		m.fail(ctx, tid, "read the storage used", err)
		return
	}
	m.evaluate(ctx, t, used, refused)
}

// Sweep evaluates every active tenant. [Monitor.Run] calls it when it
// starts and every Options.SweepInterval. It returns an error when the
// tenants or their storage cannot be read; the failure of one tenant is
// logged without stopping the others.
func (m *Monitor) Sweep(ctx context.Context) error {
	tenants, err := m.repo.activeTenants(ctx)
	if err != nil {
		return fmt.Errorf("quota: sweep: list tenants: %w", err)
	}
	used, err := m.repo.usedBytesAll(ctx)
	if err != nil {
		return fmt.Errorf("quota: sweep: read the storage used: %w", err)
	}
	for _, t := range tenants {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.evaluate(ctx, t, used[t.ID], false)
	}
	return nil
}

// evaluate moves the level of the active tenant t, using used bytes, and
// alerts on a rise.
func (m *Monitor) evaluate(ctx context.Context, t *tenant.Tenant, used int64, refused bool) {
	cur, err := m.repo.level(ctx, t.ID)
	if err != nil {
		m.fail(ctx, t.ID, "read the alert level", err)
		return
	}
	next := Next(cur, used, t.StorageQuotaBytes, refused)
	if next == cur {
		return
	}
	ok, err := m.repo.compareAndSet(ctx, t.ID, cur, next, m.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return // deleted meanwhile
	case err != nil:
		m.fail(ctx, t.ID, "store the alert level", err)
		return
	case !ok:
		return // another evaluation moved it first, and alerted if needed
	}
	if next < cur {
		m.logger.DebugContext(ctx, "quota: alert level lowered", slog.String("tenant", string(t.ID)),
			slog.Int("from", cur), slog.Int("to", next))
		return
	}
	// The level has risen in the database: no later evaluation would alert
	// again, so a Close arriving now must not cancel the audit event nor
	// the mails.
	m.alert(context.WithoutCancel(ctx), t, notify.QuotaLevel(next), used)
}

// alert records the audit event of the level reached by t and mails its
// administrators.
func (m *Monitor) alert(ctx context.Context, t *tenant.Tenant, level notify.QuotaLevel, used int64) {
	action := audit.ActionQuotaWarning
	if level == notify.QuotaReached {
		action = audit.ActionQuotaReached
	}
	quota := t.StorageQuotaBytes
	ev := audit.Event{
		TenantID: t.ID, ActorKind: store.ActorSystem, Actor: actor, Action: action,
		ObjectKind: audit.ObjectTenant, ObjectID: string(t.ID),
		Details: map[string]any{"usedBytes": used, "quotaBytes": quota, "percent": mail.UsagePercent(used, quota)},
	}
	if err := m.auditor.RecordScoped(ctx, t.ID, ev); err != nil {
		m.fail(ctx, t.ID, "record the audit event", err)
	}
	contacts, err := m.contacts(ctx, t.ID)
	if err != nil {
		m.fail(ctx, t.ID, "list the administrators to notify", err)
		return
	}
	if len(contacts) == 0 {
		m.logger.WarnContext(ctx, "quota: no administrator to notify", slog.String("tenant", string(t.ID)),
			slog.Int("level", int(level)))
		return
	}
	data := mail.QuotaAlertData{TenantName: t.Name, UsedBytes: used, QuotaBytes: quota, AdminLink: m.adminLink}
	jobs, err := m.notifier.QuotaAlert(ctx, t, data, level, contacts)
	switch {
	case errors.Is(err, notify.ErrNoSMTP):
		m.logger.ErrorContext(ctx, "quota: no alert sent: the tenant has no SMTP settings, an administrator must configure them",
			slog.String("tenant", string(t.ID)), slog.Int("level", int(level)))
		return
	case err != nil:
		m.fail(ctx, t.ID, "build the alert mails", err)
		return
	}
	m.mailer.Send(ctx, jobs, slog.String("tenant", string(t.ID)), slog.Int("quota_level", int(level)))
}

// contacts returns the administrators to notify for tenant tid: its
// delegated admins, else the super admins.
func (m *Monitor) contacts(ctx context.Context, tid tenant.ID) ([]notify.Contact, error) {
	cs, err := m.repo.tenantContacts(ctx, tid)
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		if cs, err = m.repo.superAdminContacts(ctx); err != nil {
			return nil, err
		}
	}
	out := make([]notify.Contact, len(cs))
	for i, c := range cs {
		out[i] = notify.Contact{Email: c.Email, Language: c.Language}
	}
	return out, nil
}

// fail logs a failure about tenant tid.
func (m *Monitor) fail(ctx context.Context, tid tenant.ID, what string, err error) {
	m.logger.ErrorContext(ctx, "quota: failed to "+what, slog.String("tenant", string(tid)),
		slog.String("error", err.Error()))
}

// Next returns the alert level following cur (0, 80 or 100; any other
// value counts as 0) for a tenant using used bytes of a quota of quota
// bytes, refused telling whether a creation was just refused for quota.
// A quota of 0 or less means no quota: the level is 0. See the package
// documentation for the thresholds and the hysteresis.
func Next(cur int, used, quota int64, refused bool) int {
	if quota <= 0 {
		return store.QuotaLevelNone
	}
	used = max(used, 0)
	if atLeast(used, quota, fullPercent) || (refused && atLeast(used, quota, refusedPercent)) {
		return store.QuotaLevelReached
	}
	switch cur {
	case store.QuotaLevelReached:
		if atLeast(used, quota, refusedPercent) {
			return store.QuotaLevelReached
		}
		fallthrough
	case store.QuotaLevelWarning:
		if atLeast(used, quota, rearmPercent) {
			return store.QuotaLevelWarning
		}
		return store.QuotaLevelNone
	}
	if atLeast(used, quota, warnPercent) {
		return store.QuotaLevelWarning
	}
	return store.QuotaLevelNone
}

// atLeast reports whether used >= quota * pct / 100, exactly (128-bit
// products). used must be >= 0 and quota > 0.
func atLeast(used, quota int64, pct uint64) bool {
	hu, lu := bits.Mul64(u64(used), 100)
	hq, lq := bits.Mul64(u64(quota), pct)
	return hu > hq || (hu == hq && lu >= lq)
}

// u64 converts x to uint64, a negative x counting as 0.
func u64(x int64) uint64 {
	return uint64(max(x, 0))
}

// Run sweeps every active tenant at once and every Options.SweepInterval,
// and evaluates the tenants requested by [Monitor.Check], until ctx is
// done. A failed sweep is logged.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.sweepInterval)
	defer t.Stop()
	m.sweepLogged(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
			m.ProcessPending(ctx)
		case <-t.C:
			m.sweepLogged(ctx)
		}
	}
}

// sweepLogged sweeps and logs a failure.
func (m *Monitor) sweepLogged(ctx context.Context) {
	if err := m.Sweep(ctx); err != nil && ctx.Err() == nil {
		m.logger.ErrorContext(ctx, "quota: sweep failed", slog.String("error", err.Error()))
	}
}

// Start runs [Monitor.Run] in the background until [Monitor.Close]. The
// cancellation of ctx does not stop it (only its values are kept): see the
// package documentation. It returns ErrStarted when already started and
// ErrClosed once closed.
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

// Close stops the monitor: later [Monitor.Check] calls are ignored and the
// pending evaluations are dropped (the next start sweeps every tenant).
// When started, it waits for [Monitor.Run] to return, at most until ctx is
// done, and returns ctx.Err() then. Calling it more than once is harmless.
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

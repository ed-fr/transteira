// Package avalert alerts the administrators when the antivirus stays
// unreachable (decision P10, threat model T-42, CLAUDE.md sections 11 and
// 12). The antivirus is fail-closed: while clamd cannot be reached, the
// transfers stay in the scanning status and nothing is delivered unscanned
// (package scan); this package makes sure somebody learns about it.
//
// # Incidents
//
// The antivirus worker reports every failure to reach clamd with
// [Monitor.ClamdDown] and the end of an outage with [Monitor.ClamdUp]
// (scan Deps.Outage); both never block. The outage is detected by the
// worker while it analyzes deposits: with no deposit waiting, only the
// health check shows that clamd is down. An incident goes through three
// phases:
//
//   - idle: clamd answers;
//   - pending: clamd has been unreachable since the first failure of the
//     incident, for less than Options.Grace (5 minutes by default), so that
//     a clamd restart or a signature reload alerts nobody. An incident that
//     ends while pending is logged, never audited nor mailed;
//   - raised: the outage outlasted the grace period.
//
// At the end of the grace period, the monitor pings clamd itself
// (Options.Pinger) and counts the transfers waiting: the worker only probes
// clamd when it retries its transfers, with a growing delay, so clamd may
// be back without the worker knowing yet. When clamd answers the ping, the
// alert is postponed by another grace period, the next scan of the worker
// normally ending the incident; after MaxPostponements postponements while
// the worker still fails (clamd answering PING but not the analyses), it
// is raised anyway. When no transfer waits any more, the worker will never
// probe clamd again: the monitor closes the outage itself instead of
// raising, and the next failure the worker reports starts a new one.
//
// A raised incident is evaluated again every grace period: when no
// transfer waits any more and clamd answers a ping, the monitor clears the
// alert itself; mails held back by the hourly interval are retried.
//
// The phases live in memory: a restart starts afresh, the grace period
// running from the first failure the new process sees when it resumes the
// transfers still scanning.
//
// # Effects
//
// Raising logs a warning and records the audit event
// antivirus.alert_raised (system actor "antivirus", object
// system/antivirus, details outageSeconds, waitingTransfers and tenants),
// even without any mail; the end of a raised incident records
// antivirus.alert_cleared (details outageSeconds) and sends no mail.
//
// Raising also mails, once per incident:
//
//   - the antivirus_alert template, through the system SMTP server
//     (Options.SystemMailer; without it the alert is logged and audited
//     only), to every super admin that can sign in, in their language, and
//     to the alert address of the system settings, in the language recorded
//     with it, duplicates removed ignoring case, exactly as the disk alert;
//   - for each active tenant with transfers waiting in the scanning status,
//     the tenant template antivirus-unavailable (customizable by the
//     tenant), through the SMTP settings and the mail queue of the tenant,
//     to its delegated admins, else to the super admins, as the quota
//     alerts. A tenant without SMTP settings is logged and skipped.
//
// The alert mails are at least MailInterval (an hour) apart, whatever the
// number of incidents: the time of the last mail is persisted
// ([store.SystemSettings.ClaimAntivirusAlertMail]) and taken by a
// conditional update, so a restart keeps the interval and a flapping clamd
// cannot flood the administrators (as T-157 for the disk alert). A raise
// within the hour of the last mail is logged and audited, but mails
// nobody, neither the super admins nor the tenants, yet: the slot is
// claimed again at each evaluation of the raised incident (every grace
// period) while transfers wait, and the alert is mailed once it frees.
// When the slot cannot be read, the alert matters more than the interval:
// it is mailed anyway. The tenant mail says whether the super admins were
// mailed too, or asks to contact the operator of the instance.
//
// The mails hold no secret, no file name and no user address: the start of
// the outage, counts of transfers (and of tenants, for the system mail),
// the name of the tenant for its own mail, and the administration link
// built from the configuration.
//
// # Shutdown
//
// [Monitor.Close] stops the loop; an evaluation closed during its ping
// decides nothing. The effects of a raise already started do not depend on
// the cancellation (best effort within the budget of Close, their failures
// being logged).
package avalert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Defaults and constants.
const (
	// DefaultGrace is the default duration an outage must last before the
	// alert is raised.
	DefaultGrace = 5 * time.Minute
	// MailInterval is the minimum delay between two alert mails, whatever
	// the number of incidents.
	MailInterval = time.Hour
	// PingTimeout bounds the ping confirming an outage before raising.
	PingTimeout = 10 * time.Second
	// MaxPostponements bounds the postponements of an alert by a ping that
	// clamd answers while the worker keeps failing (clamd answering PING
	// but not INSTREAM): the alert is raised at the next deadline.
	MaxPostponements = 3
	// MailTenantID is the mail.Job TenantID of the system mails: their
	// fairness share and circuit breaker in the system queue, shared with
	// the disk alert.
	MailTenantID = "system"
)

// actor is the audit actor of the alerts (actor kind system); objectID is
// their audit object ID (object kind system).
const (
	actor    = "antivirus"
	objectID = "antivirus"
)

var (
	// ErrStarted is returned when the monitor was already started.
	ErrStarted = errors.New("avalert: monitor already started")
	// ErrClosed is returned when the monitor was closed.
	ErrClosed = errors.New("avalert: monitor closed")
	// ErrInvalidOptions is returned by [New] for a missing dependency, an
	// invalid administration link or invalid SMTP settings.
	ErrInvalidOptions = errors.New("avalert: invalid options")
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

// Notifier builds the tenant mails of the alert. *notify.Notifier
// implements it.
type Notifier interface {
	AntivirusUnavailable(ctx context.Context, t *tenant.Tenant, data mail.AntivirusUnavailableData,
		recipients []notify.Contact) ([]mail.Job, error)
}

// Pinger checks that clamd answers. *antivirus.Client implements it.
type Pinger interface {
	Ping(ctx context.Context) error
}

// repo is the data the monitor reads and writes. storeRepo implements it.
type repo interface {
	// settings returns the system settings (the alert address).
	settings(ctx context.Context) (store.SystemSettingsRow, error)
	// superAdminContacts returns the super admins to notify.
	superAdminContacts(ctx context.Context) ([]store.AdminContact, error)
	// tenantContacts returns the delegated admins of tenant tid to notify.
	tenantContacts(ctx context.Context, tid tenant.ID) ([]store.AdminContact, error)
	// tenant returns the tenant tid (store.ErrNotFound when it is gone).
	tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	// waiting returns the number of scanning transfers of every tenant
	// that has some.
	waiting(ctx context.Context) ([]store.TenantScanning, error)
	// claimMail takes the alert mail slot at now, unless an alert was
	// mailed less than MailInterval before.
	claimMail(ctx context.Context, now time.Time) (bool, error)
}

// Options configure a Monitor.
type Options struct {
	// AdminLink is the absolute http or https URL of the administration
	// console put in the mails, built from the configured admin host,
	// never from a request (required).
	AdminLink string
	// Notifier builds the antivirus-unavailable mails of the tenants
	// (required).
	Notifier Notifier
	// TenantMailer sends them through the tenant mail queue (required).
	TenantMailer Mailer
	// SystemMailer sends the antivirus_alert mails through the system mail
	// queue; nil when the system SMTP server is not configured (the super
	// admins are then alerted by the log and the audit only).
	SystemMailer Mailer
	// SMTP is the system SMTP server of the system mails, validated by
	// [New] when SystemMailer is set.
	SMTP mail.Settings
	// Pinger confirms the outage before raising; nil raises on the reports
	// of the worker alone.
	Pinger Pinger
	// Grace is how long an outage must last before the alert is raised
	// (DefaultGrace).
	Grace time.Duration
	// Now is the clock (time.Now).
	Now func() time.Time
	// Logger receives the alerts and the failures (discarded when nil).
	Logger *slog.Logger
}

// phase is the phase of the current incident.
type phase int

// Phases of an incident.
const (
	// idle: no outage.
	idle phase = iota
	// pending: an outage shorter than the grace period.
	pending
	// raised: the alert of the outage was raised.
	raised
)

// Monitor raises the antivirus alert. Its [Monitor.ClamdDown] and
// [Monitor.ClamdUp] methods never block and are safe for concurrent use.
type Monitor struct {
	repo         repo
	auditor      Auditor
	notifier     Notifier
	tenantMailer Mailer
	systemMailer Mailer
	smtp         mail.Settings
	pinger       Pinger
	adminLink    string
	grace        time.Duration
	now          func() time.Time
	logger       *slog.Logger
	// render renders a system mail template (mail.Render; a field for the
	// tests).
	render func(name, lang string, data any) (mail.Message, error)

	// obsMu guards what the worker reported: down while clamd is
	// unreachable, gen counting the outages, since the start of the last
	// one and upAt the report of its end. dismissed is set when the
	// monitor closed an outage the worker still reports (nothing left to
	// analyze): the next ClamdDown report starts a new one. reports counts
	// every ClamdDown report, so that a report made while the monitor
	// decides to close the outage keeps it open.
	obsMu     sync.Mutex
	down      bool
	gen       uint64
	since     time.Time
	upAt      time.Time
	dismissed bool
	reports   uint64

	// wake (capacity 1) signals a report not evaluated yet.
	wake chan struct{}

	// evalMu serializes the evaluations and guards the incident: its
	// phase, the outage it follows (cur, curSince), when it is evaluated
	// again (deadline), the number of postponements by a ping, and whether
	// its mails wait for the hourly slot (mailPending).
	evalMu      sync.Mutex
	phase       phase
	cur         uint64
	curSince    time.Time
	deadline    time.Time
	postponed   int
	mailPending bool

	runMu   sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// New returns a Monitor over db, recording the alerts with auditor. It
// returns ErrInvalidOptions when a dependency is missing,
// Options.AdminLink is not an absolute http or https URL, or Options.SMTP
// is invalid while Options.SystemMailer is set.
func New(db *store.DB, auditor Auditor, opts Options) (*Monitor, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: database required", ErrInvalidOptions)
	}
	return newMonitor(storeRepo{db: db}, auditor, opts)
}

// newMonitor returns a Monitor over r.
func newMonitor(r repo, auditor Auditor, opts Options) (*Monitor, error) {
	if auditor == nil || opts.Notifier == nil || opts.TenantMailer == nil {
		return nil, fmt.Errorf("%w: auditor, notifier and tenant mailer required", ErrInvalidOptions)
	}
	if u, err := url.Parse(opts.AdminLink); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("%w: the admin link must be an absolute http or https URL", ErrInvalidOptions)
	}
	if opts.SystemMailer != nil {
		if err := opts.SMTP.Validate(); err != nil {
			return nil, fmt.Errorf("%w: system SMTP settings: %w", ErrInvalidOptions, err)
		}
	}
	m := &Monitor{
		repo: r, auditor: auditor, notifier: opts.Notifier, tenantMailer: opts.TenantMailer,
		systemMailer: opts.SystemMailer, smtp: opts.SMTP, pinger: opts.Pinger, adminLink: opts.AdminLink,
		grace: opts.Grace, now: opts.Now, logger: opts.Logger, render: mail.Render, wake: make(chan struct{}, 1),
	}
	if m.grace <= 0 {
		m.grace = DefaultGrace
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.logger == nil {
		m.logger = slog.New(slog.DiscardHandler)
	}
	return m, nil
}

// ClamdDown reports that clamd cannot be reached; the worker reports every
// failure. A report while an outage is already reported changes nothing,
// unless the monitor closed that outage because nothing was left to
// analyze: the report then starts a new one. It never blocks and is a
// no-op on a nil monitor. With [Monitor.ClamdUp], it implements
// scan.OutageObserver.
func (m *Monitor) ClamdDown() {
	if m == nil {
		return
	}
	m.obsMu.Lock()
	m.reports++
	if !m.down || m.dismissed {
		m.down, m.dismissed = true, false
		m.gen++
		m.since = m.now()
	}
	m.obsMu.Unlock()
	m.signal()
}

// ClamdUp reports that clamd answers again. It never blocks and is a no-op
// on a nil monitor.
func (m *Monitor) ClamdUp() {
	if m == nil {
		return
	}
	m.obsMu.Lock()
	if m.down {
		m.down, m.dismissed, m.upAt = false, false, m.now()
	}
	m.obsMu.Unlock()
	m.signal()
}

// signal wakes the loop, coalescing the reports.
func (m *Monitor) signal() {
	select {
	case m.wake <- struct{}{}:
	default: // a report is already pending
	}
}

// Evaluate moves the incident after the reports of the worker and the
// time elapsed, raising or clearing the alert, and returns when it must be
// evaluated again (the zero time when only a report can change it).
// [Monitor.Run] calls it; it is exported for the tests and the callers
// that drive the monitor themselves. Failures are logged. It does nothing
// once ctx is done.
func (m *Monitor) Evaluate(ctx context.Context) time.Time {
	m.evalMu.Lock()
	defer m.evalMu.Unlock()
	if ctx.Err() != nil {
		return time.Time{}
	}
	m.obsMu.Lock()
	down, gen, since, upAt, reports := m.down, m.gen, m.since, m.upAt, m.reports
	m.obsMu.Unlock()
	if m.phase != idle && (!down || gen != m.cur) {
		// The outage ended when the worker reported it (a later one may
		// already have started): the incident only changes after a
		// ClamdUp report, a closed outage leaving the incident idle.
		m.end(ctx, upAt, "clamd answers again")
	}
	if down && m.phase == idle && gen != m.cur {
		m.phase, m.cur, m.curSince, m.deadline = pending, gen, since, since.Add(m.grace)
		m.postponed, m.mailPending = 0, false
	}
	if m.phase == idle {
		return time.Time{}
	}
	now := m.now()
	if now.Before(m.deadline) {
		return m.deadline
	}
	answers := m.answers(ctx)
	if ctx.Err() != nil {
		return time.Time{} // closed during the ping: decide nothing
	}
	// A failure to count counts as transfers waiting, in an unknown
	// number: a database error never holds the alert back.
	waiting, err := m.repo.waiting(ctx)
	if ctx.Err() != nil {
		return time.Time{} // closed during the count: decide nothing
	}
	known := err == nil
	if !known {
		m.fail(ctx, "count the transfers waiting for analysis", err)
	}
	nothing := known && total(waiting) == 0
	switch {
	case nothing && (m.phase == pending || answers) && m.dismiss(reports):
		// Nothing is left to analyze: the worker will not probe clamd
		// again, so the monitor closes the outage itself (a raised alert
		// only once clamd answers).
		m.end(ctx, now, "no transfer waits for analysis any more")
		return time.Time{}
	case nothing && (m.phase == pending || answers):
		// The worker reported a failure meanwhile: a new transfer may
		// wait, the outage stays open until the next evaluation.
	case m.phase == raised:
		if m.mailPending && !nothing {
			m.mailPending = m.mail(context.WithoutCancel(ctx), now, waiting, known)
		}
	case answers && m.postponed < MaxPostponements:
		m.postponed++
		m.logger.InfoContext(ctx, "antivirus alert postponed: clamd answers a ping, waiting for the antivirus worker to confirm",
			slog.Time("outage_since", m.curSince), slog.Duration("postponed_by", m.grace),
			slog.Int("postponement", m.postponed), slog.Int("max_postponements", MaxPostponements))
	default:
		m.phase = raised
		// The raise is decided: a Close arriving now does not cancel its
		// audit event nor its mails, which it waits for within its budget
		// only.
		m.raise(context.WithoutCancel(ctx), now, waiting, known)
	}
	m.deadline = now.Add(m.grace)
	return m.deadline
}

// dismiss marks the outage of the current incident as closed by the
// monitor while the worker still reports it, so that its next failure
// report starts a new outage. It reports false, leaving the outage open,
// when the worker reported a failure since the count reports was read.
func (m *Monitor) dismiss(reports uint64) bool {
	m.obsMu.Lock()
	defer m.obsMu.Unlock()
	if m.reports != reports {
		return false
	}
	if m.down && m.gen == m.cur {
		m.dismissed = true
	}
	return true
}

// total returns the number of transfers of waiting.
func total(waiting []store.TenantScanning) int {
	n := 0
	for _, w := range waiting {
		n += w.Transfers
	}
	return n
}

// end ends the current incident at the time at, for the reason why: a
// raised alert is cleared, a pending one forgotten.
func (m *Monitor) end(ctx context.Context, at time.Time, why string) {
	outage := at.Sub(m.curSince)
	if m.phase == raised {
		m.logger.InfoContext(ctx, "antivirus alert cleared: "+why,
			slog.Time("outage_since", m.curSince), slog.Duration("outage", outage))
		m.record(ctx, audit.ActionAntivirusAlertCleared, map[string]any{"outageSeconds": seconds(outage)})
	} else {
		m.logger.InfoContext(ctx, "antivirus outage ended before the alert: "+why,
			slog.Duration("outage", outage), slog.Duration("grace", m.grace))
	}
	m.phase, m.mailPending = idle, false
}

// answers reports whether clamd answers a ping (false without a pinger).
func (m *Monitor) answers(ctx context.Context) bool {
	if m.pinger == nil {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, PingTimeout)
	defer cancel()
	return m.pinger.Ping(pctx) == nil
}

// seconds returns d in whole seconds, at least 0.
func seconds(d time.Duration) int64 {
	return int64(max(d, 0) / time.Second)
}

// record writes the audit event action with details.
func (m *Monitor) record(ctx context.Context, action audit.Action, details map[string]any) {
	ev := audit.Event{
		ActorKind: store.ActorSystem, Actor: actor, Action: action, ObjectKind: audit.ObjectSystem, ObjectID: objectID,
		Details: details,
	}
	if err := m.auditor.Record(ctx, ev); err != nil {
		m.fail(ctx, "record the audit event", err)
	}
}

// tenantBatch is the mails of the alert to the administrators of one
// tenant.
type tenantBatch struct {
	tid  tenant.ID
	jobs []mail.Job
}

// raise logs, records and mails the alert of the current incident, at
// now, with the transfers waiting; known is false when they could not be
// counted, and the counts are then left out.
func (m *Monitor) raise(ctx context.Context, now time.Time, waiting []store.TenantScanning, known bool) {
	outage := now.Sub(m.curSince)
	attrs := []any{slog.Time("outage_since", m.curSince), slog.Duration("outage", outage)}
	details := map[string]any{"outageSeconds": seconds(outage)}
	if known {
		attrs = append(attrs, slog.Int("waiting_transfers", total(waiting)), slog.Int("tenants", len(waiting)))
		details["waitingTransfers"], details["tenants"] = total(waiting), len(waiting)
	}
	m.logger.WarnContext(ctx, "antivirus alert: clamd has been unreachable beyond the grace period, deposits stay in analysis", attrs...)
	m.record(ctx, audit.ActionAntivirusAlertRaised, details)
	if m.systemMailer == nil {
		m.logger.WarnContext(ctx, "antivirus alert not mailed to the super admins: the system SMTP server (TT_SYSTEM_SMTP_HOST) is not configured")
	}
	m.mailPending = m.mail(ctx, now, waiting, known)
}

// mail sends the mails of the alert, at now, with the transfers waiting,
// (known false when they could not be counted), when the hourly mail slot
// is free. It reports whether they must be tried
// again: the slot was taken by a mail of less than MailInterval, and the
// next evaluation of the raised alert claims it again.
func (m *Monitor) mail(ctx context.Context, now time.Time, waiting []store.TenantScanning, known bool) bool {
	system := m.systemJobs(ctx, mail.AntivirusAlertData{
		Since: m.curSince, WaitingTransfers: total(waiting), Tenants: len(waiting), CountUnknown: !known,
		AdminLink: m.adminLink,
	})
	tenants := m.tenantJobs(ctx, waiting, len(system) > 0)
	if len(system) == 0 && len(tenants) == 0 {
		return false
	}
	won, err := m.repo.claimMail(ctx, now)
	switch {
	case err != nil:
		// The alert matters more than the interval: mail it anyway.
		m.fail(ctx, "record the time of the alert mail", err)
	case !won:
		m.logger.WarnContext(ctx, "antivirus alert not mailed yet: an alert mail was sent less than an hour ago, retried while the outage lasts",
			slog.Duration("min_interval", MailInterval), slog.Duration("retry_every", m.grace))
		return true
	}
	if len(system) > 0 {
		m.systemMailer.Send(ctx, system, slog.String("template", mail.TemplateAntivirusAlert), slog.Int("count", len(system)))
	}
	for _, b := range tenants {
		m.tenantMailer.Send(ctx, b.jobs, slog.String("tenant", string(b.tid)),
			slog.String("template", mail.TemplateAntivirusUnavailable), slog.Int("count", len(b.jobs)))
	}
	return false
}

// systemJobs builds the antivirus_alert mails of the super admins and of
// the alert address; none when system mail is disabled or nobody can be
// reached.
func (m *Monitor) systemJobs(ctx context.Context, data mail.AntivirusAlertData) []mail.Job {
	if m.systemMailer == nil {
		return nil // logged by raise
	}
	contacts, err := m.repo.superAdminContacts(ctx)
	if err != nil {
		// The alert address may still be reached.
		m.fail(ctx, "list the super admins to notify", err)
	}
	row, err := m.repo.settings(ctx)
	switch {
	case err != nil:
		m.fail(ctx, "read the alert address", err)
	case row.AlertEmail != "":
		contacts = append(contacts, store.AdminContact{Email: row.AlertEmail, Language: row.AlertEmailLanguage})
	}
	contacts = dedup(contacts)
	if len(contacts) == 0 {
		m.logger.WarnContext(ctx, "antivirus alert not mailed to the super admins: no recipient")
		return nil
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
			msg, err := m.render(mail.TemplateAntivirusAlert, lang, data)
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
		jobs = append(jobs, mail.Job{TenantID: MailTenantID, Template: mail.TemplateAntivirusAlert, Settings: m.smtp, Message: msg})
	}
	return jobs
}

// tenantJobs builds the antivirus-unavailable mails of every active tenant
// of waiting, telling whether the operators of the instance are mailed
// too; a tenant that cannot be notified is logged and skipped.
func (m *Monitor) tenantJobs(ctx context.Context, waiting []store.TenantScanning, operatorsMailed bool) []tenantBatch {
	var out []tenantBatch
	for _, w := range waiting {
		t, err := m.repo.tenant(ctx, w.TenantID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue // deleted meanwhile
		case err != nil:
			m.failTenant(ctx, w.TenantID, "read the tenant", err)
			continue
		case t.Status != tenant.StatusActive:
			continue
		}
		contacts, err := m.contacts(ctx, w.TenantID)
		if err != nil {
			m.failTenant(ctx, w.TenantID, "list the administrators to notify", err)
			continue
		}
		if len(contacts) == 0 {
			m.logger.WarnContext(ctx, "antivirus alert: no administrator to notify", slog.String("tenant", string(w.TenantID)))
			continue
		}
		data := mail.AntivirusUnavailableData{
			TenantName: t.Name, Since: m.curSince, WaitingTransfers: w.Transfers, AdminLink: m.adminLink,
			OperatorsMailed: operatorsMailed,
		}
		jobs, err := m.notifier.AntivirusUnavailable(ctx, t, data, contacts)
		switch {
		case errors.Is(err, notify.ErrNoSMTP):
			m.logger.ErrorContext(ctx, "antivirus alert not mailed to the tenant: it has no SMTP settings, an administrator must configure them",
				slog.String("tenant", string(w.TenantID)))
			continue
		case err != nil:
			m.failTenant(ctx, w.TenantID, "build the alert mails", err)
			continue
		}
		out = append(out, tenantBatch{tid: w.TenantID, jobs: jobs})
	}
	return out
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

// fail logs a failure, with the extra attributes attrs.
func (m *Monitor) fail(ctx context.Context, what string, err error, attrs ...any) {
	m.logger.ErrorContext(ctx, "avalert: failed to "+what, append([]any{slog.String("error", err.Error())}, attrs...)...)
}

// failTenant logs a failure about tenant tid.
func (m *Monitor) failTenant(ctx context.Context, tid tenant.ID, what string, err error) {
	m.fail(ctx, what, err, slog.String("tenant", string(tid)))
}

// Run evaluates at once, after every report of the worker and when the
// grace period of a pending incident expires, until ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C
	for {
		next := m.Evaluate(ctx)
		var expire <-chan time.Time
		if !next.IsZero() {
			timer.Reset(max(next.Sub(m.now()), 0))
			expire = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-expire:
		}
		timer.Stop()
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

// Close stops the monitor. When started, it waits for [Monitor.Run] to
// return, at most until ctx is done, and returns ctx.Err() then. Calling
// it more than once is harmless.
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

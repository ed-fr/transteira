// Package abuse detects the abuses of CLAUDE.md section 15 (threat model
// T-216 to T-218, T-221): internal data leaks (per-sender daily
// thresholds, unusual behavior) and the misuse of the tool by external
// users (external quota, invitation limit, abuse reports).
//
// # Rules
//
// Every threshold of [store.AbuseSettings] is optional: a nil threshold
// disables its rule. "Per day" is the calendar day of the time zone of the
// tenant settings (an IANA name): the [start, end) bounds of the local day
// are computed in Go, so that a day of 23 or 25 hours (daylight saving
// time) is counted whole.
//
//   - daily_bytes and daily_transfers: the volume and the number of the
//     transfers an internal sender created or extended during the local
//     day, its internal and internal_remote transfers counted together
//     (deposits by API token are internal and count under the sender
//     address). Exceeded when the value is strictly above the threshold.
//     Blocking when the tenant blocks on exceed. Internal senders only: the
//     external depositors are governed by external_quota alone.
//   - recipients: the recipients of one transfer, strictly above the
//     threshold. Blocking when the tenant blocks on exceed. Internal
//     senders only.
//   - external_quota: the volume or the number of the transfers an external
//     address deposited during the local day (kind external only: the
//     replies of section 10 will join it), strictly above the threshold.
//     Blocking when the tenant blocks on exceed.
//   - unusual_volume (alert only): the volume of the sender for the local
//     day, divided by its average daily volume over the 30 previous local
//     days, is strictly above the configured factor. The average divides
//     the total of the window by 30 (days without activity count as 0), and
//     the rule applies only to a sender active on at least
//     unusualMinHistoryDays distinct days of the window. The history is a
//     capped scan of the newest store.MaxSenderHistoryRows creations: past
//     the cap, the average is underestimated, which can only raise more
//     alerts. Internal senders only.
//   - large_external (alert only): a transfer of at least the configured
//     size with at least one recipient outside the internal mail domains of
//     the tenant. Internal senders only.
//   - off_hours (alert only): a transfer created on a day outside the
//     office weekdays, or outside [start, end) minutes of the local day.
//     Internal senders only: an invited external user is not bound by the
//     office hours of the tenant.
//   - invitations (alert only here): an internal user reached the
//     per-inviter invitation limit, refused by the deposit service.
//
// # Blocking
//
// [Detector.CheckCreateTx] runs inside the transaction creating a
// transfer, under the tenant lock, and counts the candidate transfer on top
// of the stored activity: two concurrent creations cannot both pass a
// threshold. It never writes. A refused creation is reported after the
// rollback with [Detector.Blocked]; a created one with
// [Detector.AfterCreate], which evaluates every rule (the transfer is then
// counted by the store). An extension (T-210) is counted in the daily rules
// of the day it happens, and [Detector.AfterExtend] alerts, never blocks.
//
// # Alerts
//
// An exceeded rule is recorded in the audit log (abuse.threshold_exceeded,
// or abuse.unusual_activity for the alert-only behavior rules). The sender
// is the actor of the event (actor kind depositor), never a detail: the
// audit details refuse mail addresses, and the actor column is the one a
// GDPR erasure pseudonymizes. A deduplication row
// ([store.AbuseAlerts.TryInsertTx]) lets one mail and one webhook event out
// per sender, rule, local day and kind (T-217): an alert-only finding and a
// refusal are deduplicated separately, so that an alert earlier in the day
// never masks a refusal.
//
// An alert-only finding is audited at every occurrence, each one being a
// transfer that was created. A refusal is audited only the first time of
// the day for the sender and the rule (details.blocked true); the later
// refusals of that day only increment the attempts of the deduplication
// row, so that a sender retrying cannot flood the audit log.
//
// The mails go to the delegated admins attached to the tenant, else to the
// super admins (like the quota alerts), through the SMTP settings of the
// tenant. Abuse reports ([Detector.Reported]) are mailed and published
// without deduplication: their rate is limited upstream.
//
// The detection computes everything on demand from the stored transfers:
// no behavior profile is stored (T-218).
package abuse

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// ErrInvalidOptions is returned by [New] for a missing dependency or an
// invalid administration link.
var ErrInvalidOptions = errors.New("abuse: invalid options")

// Notifier builds the abuse mails. *notify.Notifier implements it.
type Notifier interface {
	AbuseAlert(ctx context.Context, t *tenant.Tenant, data mail.AbuseAlertData, recipients []notify.Contact) ([]mail.Job, error)
	AbuseReport(ctx context.Context, t *tenant.Tenant, data mail.AbuseReportData, recipients []notify.Contact) ([]mail.Job, error)
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

// Options configure a Detector.
type Options struct {
	// AdminLink is the absolute http or https base URL of the
	// administration (for example "https://admin.example.com"), built from
	// the configured admin host, never from a request (required). The
	// administration paths of the events ("/admin/tenants/...") are
	// appended to it in the mails; a trailing "/admin" is tolerated and
	// dropped, so that the link of the quota alerts can be passed as is.
	AdminLink string
	// Events receives the abuse.* events (nothing is published when nil).
	Events events.Publisher
	// Logger receives the failures (discarded when nil).
	Logger *slog.Logger
	// Now is the clock (time.Now).
	Now func() time.Time
}

// Detector evaluates the abuse rules of the tenants and sends the alerts.
// It is safe for concurrent use.
type Detector struct {
	repo      repo
	notifier  Notifier
	mailer    Mailer
	auditor   Auditor
	adminBase string
	now       func() time.Time
	logger    *slog.Logger
	events    events.Publisher
}

// Facts describe a transfer for the abuse rules.
type Facts struct {
	// TransferID is the transfer, "" when its creation was refused.
	TransferID string
	// SenderEmail is the normalized address of the sender.
	SenderEmail string
	// Kind is how the sender was allowed to deposit.
	Kind store.DepositorKind
	// Bytes is the declared total size of the transfer.
	Bytes int64
	// Recipients are the normalized recipient addresses.
	Recipients []string
	// At is the time of the creation (or of the extension); the clock of
	// the detector when zero.
	At time.Time
	// ClientIP is the client IP of the sender, the zero Addr when unknown.
	ClientIP netip.Addr
}

// Block is a refusal decided by [Detector.CheckCreateTx]: the tenant
// blocks on exceed and a blocking rule (daily_bytes, daily_transfers,
// recipients, external_quota) is exceeded. Pass it unchanged to
// [Detector.Blocked].
type Block struct {
	// Rule is the exceeded rule.
	Rule store.AbuseRule
	// Value is the measured value, the candidate transfer included.
	Value float64
	// Threshold is the configured threshold.
	Threshold float64

	// bytes tells that Value and Threshold of external_quota are sizes.
	bytes bool
}

// New returns a Detector over db, sending its alerts with notifier and
// mailer and recording them with auditor. It returns ErrInvalidOptions
// when a dependency is missing or Options.AdminLink is not an absolute
// http or https URL.
func New(db *store.DB, notifier Notifier, mailer Mailer, auditor Auditor, opts Options) (*Detector, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: database required", ErrInvalidOptions)
	}
	return newDetector(storeRepo{db: db}, notifier, mailer, auditor, opts)
}

// newDetector returns a Detector over r.
func newDetector(r repo, notifier Notifier, mailer Mailer, auditor Auditor, opts Options) (*Detector, error) {
	if notifier == nil || mailer == nil || auditor == nil {
		return nil, fmt.Errorf("%w: notifier, mailer and auditor required", ErrInvalidOptions)
	}
	u, err := url.Parse(opts.AdminLink)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("%w: the admin link must be an absolute http or https URL", ErrInvalidOptions)
	}
	d := &Detector{
		repo: r, notifier: notifier, mailer: mailer, auditor: auditor,
		adminBase: strings.TrimSuffix(strings.TrimRight(opts.AdminLink, "/"), "/admin"),
		now:       opts.Now, logger: opts.Logger, events: events.OrDiscard(opts.Events),
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.logger == nil {
		d.logger = slog.New(slog.DiscardHandler)
	}
	return d, nil
}

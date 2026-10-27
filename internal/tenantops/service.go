package tenantops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Defaults of the [Options].
const (
	// DefaultResendLimit is the number of notification resends allowed per
	// transfer within DefaultResendWindow.
	DefaultResendLimit = 5
	// DefaultResendWindow is the period of the resend limit.
	DefaultResendWindow = time.Hour
	// DefaultBusyRetries is the number of retries of a transfer deletion
	// refused because an upload request holds one of its files.
	DefaultBusyRetries = 5
	// DefaultBusyDelay is the delay before each of these retries.
	DefaultBusyDelay = 200 * time.Millisecond
	// DefaultBusyRetryAfter is the Retry-After delay returned once the
	// retries are exhausted.
	DefaultBusyRetryAfter = 5 * time.Second
)

// Eraser erases a transfer on request (*lifecycle.Sweeper): the antivirus
// is held, the data keys are destroyed, then the files, then the transfer
// is marked deleted (lifecycle.MarkDeleted). It returns
// lifecycle.AlreadyEnded for a transfer already expired or deleted,
// lifecycle.ErrNotFound for a transfer that does not exist or belongs to
// another tenant, and lifecycle.ErrBusy when an upload request holds one
// of its files.
type Eraser interface {
	EraseTransfer(ctx context.Context, tid tenant.ID, trfID string, mode lifecycle.EraseMode) (lifecycle.EraseResult, error)
}

// Notifier builds the notification mail of each recipient of a transfer
// (*notify.Notifier). It returns notify.ErrNoSMTP when the tenant has no
// SMTP settings.
type Notifier interface {
	RecipientJobs(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, link string) ([]mail.Job, error)
}

// Mailer queues mails without blocking, retrying those the queue refuses
// (*mail.Retrier). attrs identify the jobs in the logs and never hold an
// address.
type Mailer interface {
	Send(ctx context.Context, jobs []mail.Job, attrs ...slog.Attr)
}

// Options configures a [Service].
type Options struct {
	// Vault opens the sealed download tokens (required).
	Vault Vault
	// Eraser erases the transfers deleted by an administrator (required).
	Eraser Eraser
	// Notifier builds the resent notification mails (required).
	Notifier Notifier
	// Mailer queues them (required).
	Mailer Mailer
	// Logger receives the audit write failures; nil means slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// ResendLimit and ResendWindow bound the notification resends per
	// transfer; <= 0 means the defaults.
	ResendLimit  int
	ResendWindow time.Duration
	// BusyRetries, BusyDelay and BusyRetryAfter tune the retries of a
	// deletion refused while an upload is in progress; a negative
	// BusyRetries means no retry, 0 and the other values <= 0 mean the
	// defaults.
	BusyRetries    int
	BusyDelay      time.Duration
	BusyRetryAfter time.Duration
	// Audit is the shared audit writer of the application, which publishes
	// the events it writes; nil means a writer of its own over the
	// database, publishing nothing.
	Audit *audit.Writer
}

// Service is the operation service of the tenants. It is safe for
// concurrent use.
type Service struct {
	repo           repo
	eraser         Eraser
	notifier       Notifier
	mailer         Mailer
	logger         *slog.Logger
	now            func() time.Time
	resends        *ratelimit.Window
	busyRetries    int
	busyDelay      time.Duration
	busyRetryAfter time.Duration
}

// errMissingDependency reports a [New] call without a required option.
var errMissingDependency = errors.New("tenantops: Vault, Eraser, Notifier and Mailer are required")

// New returns the service over db. It fails when a required option is
// missing.
func New(db *store.DB, opts Options) (*Service, error) {
	if db == nil || opts.Vault == nil || opts.Eraser == nil || opts.Notifier == nil || opts.Mailer == nil {
		return nil, errMissingDependency
	}
	s := &Service{
		repo:     newStoreRepo(db, opts.Vault, opts.Audit),
		eraser:   opts.Eraser,
		notifier: opts.Notifier,
		mailer:   opts.Mailer,
		logger:   opts.Logger,
		now:      opts.Now,
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	limit, window := opts.ResendLimit, opts.ResendWindow
	if limit <= 0 {
		limit = DefaultResendLimit
	}
	if window <= 0 {
		window = DefaultResendWindow
	}
	s.resends = ratelimit.NewWindow(limit, window, ratelimit.WithClock(s.now))
	s.busyRetries, s.busyDelay, s.busyRetryAfter = opts.BusyRetries, opts.BusyDelay, opts.BusyRetryAfter
	switch {
	case s.busyRetries == 0:
		s.busyRetries = DefaultBusyRetries
	case s.busyRetries < 0:
		s.busyRetries = 0
	}
	if s.busyDelay <= 0 {
		s.busyDelay = DefaultBusyDelay
	}
	if s.busyRetryAfter <= 0 {
		s.busyRetryAfter = DefaultBusyRetryAfter
	}
	return s, nil
}

// --- Authorization -----------------------------------------------------------

// readable checks that p may read tenant tid, which must be active.
func (s *Service) readable(ctx context.Context, p adminauth.Principal, tid tenant.ID) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	if err := adminauth.RequireTenantAccess(p.Admin, tid); err != nil {
		return err
	}
	_, err := s.activeTenant(ctx, tid)
	return err
}

// writable checks that p may change tenant tid and returns the tenant,
// which must be active.
func (s *Service) writable(ctx context.Context, p adminauth.Principal, tid tenant.ID) (*tenant.Tenant, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return nil, err
	}
	if err := adminauth.RequireTenantWrite(p.Admin, tid); err != nil {
		return nil, err
	}
	return s.activeTenant(ctx, tid)
}

// superAdmin checks that p is an authenticated super admin.
func superAdmin(p adminauth.Principal) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	return adminauth.RequireSuperAdmin(p.Admin)
}

// activeTenant returns the active tenant tid; a missing tenant, and a
// tenant being deleted, are ErrNotFound.
func (s *Service) activeTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	t, err := s.repo.getTenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return nil, ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("tenantops: get tenant: %w", err)
	case t.Status != tenant.StatusActive:
		return nil, ErrNotFound
	}
	return t, nil
}

// --- Audit -------------------------------------------------------------------

// record writes the audit event of a change made by p on tenant tid. The
// change is committed already: a failure is logged, never returned, and a
// canceled request does not prevent the write.
func (s *Service) record(ctx context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID,
	action audit.Action, objectKind, objectID string, details map[string]any,
) {
	ev := audit.Event{
		TenantID: tid, ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: ip,
		Action: action, ObjectKind: objectKind, ObjectID: objectID, Details: details,
	}
	if err := s.repo.audit(context.WithoutCancel(ctx), tid, ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(action)),
			slog.String("tenant", string(tid)), slog.String("error", err.Error()))
	}
}

// --- Common validation ---------------------------------------------------------

// checkLimit validates a page size: 0 for the default, else 1 to
// store.MaxPageSize.
func checkLimit(limit int) error {
	if limit < 0 || limit > store.MaxPageSize {
		return invalid(FieldLimit, "must be between 1 and %d", store.MaxPageSize)
	}
	return nil
}

// listError maps the error of a store list whose filters were validated
// before: a remaining store.ErrInvalid is a malformed cursor.
func listError(op string, err error) error {
	if errors.Is(err, store.ErrInvalid) {
		return invalid(FieldCursor, "malformed cursor")
	}
	return fmt.Errorf("tenantops: %s: %w", op, err)
}

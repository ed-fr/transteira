package mytransfers

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Rules of spec 8.7 and of the threat model (T-207, T-208, P32).
const (
	// LinkTTL is the validity of an access link.
	LinkTTL = 15 * time.Minute
	// SessionTTL is the absolute lifetime of a session.
	SessionTTL = time.Hour
	// MaxRequestsPerAddress bounds the access link requests for one
	// address per RequestWindow; beyond, they are silently dropped.
	MaxRequestsPerAddress = 5
	// MaxRequestsPerIP bounds the access link requests from one client
	// (IPv4 address or IPv6 /64) per RequestWindow; beyond, they are
	// refused (429) and not recorded.
	MaxRequestsPerIP = store.AccessRequestsPerIP
	// RequestWindow is the sliding window of the request limits.
	RequestWindow = store.AccessRateWindow
	// SessionFailureLimit is the number of invalid access links one client
	// (IPv4 address or IPv6 /64) may present within SessionFailureWindow
	// before it is locked out for SessionLockout.
	SessionFailureLimit = 10
	// SessionFailureWindow is the window of SessionFailureLimit.
	SessionFailureWindow = 15 * time.Minute
	// SessionLockout is how long a client stays locked out.
	SessionLockout = 15 * time.Minute
	// SessionTokenPrefix starts every session cookie token.
	SessionTokenPrefix = "ms"
	// SessionTokenBytes is the entropy of a session token (256 bits).
	SessionTokenBytes = 32
	// CSRFPrefix starts every CSRF token.
	CSRFPrefix = "csrf_"
	// DefaultQueueSize is the capacity of the request queue when
	// Options.QueueSize is not set.
	DefaultQueueSize = 256
	// DefaultWorkers is the number of request workers when Options.Workers
	// is not set.
	DefaultWorkers = 2
	// DefaultJobTimeout bounds the processing of one request by a worker
	// when Options.JobTimeout is not set.
	DefaultJobTimeout = 30 * time.Second
	// DefaultBusyRetries, DefaultBusyDelay and DefaultBusyRetryAfter tune
	// the retries of a deletion refused while an upload is in progress,
	// like the deletion by an administrator (tenantops).
	DefaultBusyRetries    = 5
	DefaultBusyDelay      = 200 * time.Millisecond
	DefaultBusyRetryAfter = 5 * time.Second
)

// Security log scopes of the rate limits of the service.
const (
	// ScopeRequestIP is the limit of the access link requests per client IP.
	ScopeRequestIP = "access_link_ip"
	// ScopeSessionIP is the lockout of a client presenting invalid access
	// links.
	ScopeSessionIP = "access_link"
)

// expiryDays are the transfer lifetimes of a transfer without
// confidentiality level (spec 8.2).
var expiryDays = []int{1, 7, 30}

// Keys computes and verifies the MACs keyed by the master key.
// *masterkey.Keyring implements it.
type Keys interface {
	MAC(p crypto.MACPurpose, parts ...[]byte) ([]byte, error)
	VerifyMAC(p crypto.MACPurpose, mac []byte, parts ...[]byte) (bool, error)
}

// Notifier builds the access link mail. *notify.Notifier implements it.
type Notifier interface {
	MyTransfersLinkJob(ctx context.Context, t *tenant.Tenant, lang, to, link string, validity time.Duration) (mail.Job, error)
}

// MailQueue queues mails for asynchronous delivery. *mail.Queue implements
// it; Enqueue must not block.
type MailQueue interface {
	Enqueue(job mail.Job) error
}

// SecurityLog writes security events. *securitylog.Logger implements it.
type SecurityLog interface {
	Log(ev securitylog.Event) error
}

// AuditRecorder records tenant audit events. *audit.Writer implements it
// and publishes them on the event bus once committed.
type AuditRecorder interface {
	RecordScoped(ctx context.Context, tid tenant.ID, ev audit.Event) error
}

// Failures counts the invalid access links per client and locks a client
// out. *ratelimit.Window implements it.
type Failures interface {
	Locked(key string) (locked bool, retryAfter time.Duration)
	Fail(key string) (locked bool, retryAfter time.Duration)
}

// Options tunes a [Service].
type Options struct {
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Logger receives the failures of the background work, of the audit
	// and of the security log, never with an address or a token (nil
	// discards).
	Logger *slog.Logger
	// Audit records the audit events, best effort (a failure is logged).
	// nil records nothing.
	Audit AuditRecorder
	// QueueSize is the capacity of the request queue (DefaultQueueSize
	// when <= 0); a request finding it full is dropped (logged without the
	// address).
	QueueSize int
	// Workers is the number of request workers started by Start
	// (DefaultWorkers when <= 0).
	Workers int
	// JobTimeout bounds the processing of one request (DefaultJobTimeout
	// when <= 0).
	JobTimeout time.Duration
	// Failures counts the invalid access links per client; nil uses a
	// window of SessionFailureLimit failures per SessionFailureWindow with
	// a SessionLockout lockout.
	Failures Failures
	// BusyRetries, BusyDelay and BusyRetryAfter tune the retries of a
	// deletion refused while an upload is in progress; a negative
	// BusyRetries means no retry, 0 and the other values <= 0 the
	// defaults.
	BusyRetries    int
	BusyDelay      time.Duration
	BusyRetryAfter time.Duration
}

// Deps are the required dependencies of a [Service].
type Deps struct {
	// DB is the database.
	DB *store.DB
	// Keys computes the address MACs and the CSRF tokens.
	Keys Keys
	// Notifier builds the access link mails.
	Notifier Notifier
	// Mail queues them.
	Mail MailQueue
	// SecurityLog receives rate_limited and access_link_invalid.
	SecurityLog SecurityLog
	// Eraser erases the transfers deleted by their sender
	// (*lifecycle.Sweeper).
	Eraser lifecycle.TransferEraser
}

// errMissingDependency reports a [New] call without a required dependency.
var errMissingDependency = errors.New("mytransfers: DB, Keys, Notifier, Mail, SecurityLog and Eraser are required")

// errStarted reports a second Start, or a Start after Close.
var errStarted = errors.New("mytransfers: already started or closed")

// linkJob is an access link request handed to the workers. It holds the
// address: it never leaves the process memory.
type linkJob struct {
	tenant  *tenant.Tenant
	ip      netip.Addr
	mailbox string
	email   string
	lang    string
}

// Service implements "My transfers". It is safe for concurrent use.
type Service struct {
	repo     repo
	keys     Keys
	notifier Notifier
	queue    MailQueue
	seclog   SecurityLog
	eraser   lifecycle.TransferEraser
	audit    AuditRecorder
	logger   *slog.Logger
	clock    func() time.Time
	failures Failures

	workers        int
	jobTimeout     time.Duration
	busyRetries    int
	busyDelay      time.Duration
	busyRetryAfter time.Duration

	// newToken draws the tokens (replaced by the tests).
	newToken func(prefix string, entropyBytes int) (string, error)

	// mu guards jobs, started and closed: a request never sends on the
	// closed channel.
	mu      sync.RWMutex
	jobs    chan linkJob
	started bool
	closed  bool
	// cancel stops the job in progress at Close past its deadline; done is
	// closed once every worker returned.
	cancel context.CancelFunc
	done   chan struct{}
}

// New returns a service over deps, which are all required.
func New(deps Deps, opts Options) (*Service, error) {
	if deps.DB == nil || deps.Keys == nil || deps.Notifier == nil || deps.Mail == nil || deps.SecurityLog == nil || deps.Eraser == nil {
		return nil, errMissingDependency
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = DefaultQueueSize
	}
	if opts.Workers <= 0 {
		opts.Workers = DefaultWorkers
	}
	if opts.JobTimeout <= 0 {
		opts.JobTimeout = DefaultJobTimeout
	}
	switch {
	case opts.BusyRetries == 0:
		opts.BusyRetries = DefaultBusyRetries
	case opts.BusyRetries < 0:
		opts.BusyRetries = 0
	}
	if opts.BusyDelay <= 0 {
		opts.BusyDelay = DefaultBusyDelay
	}
	if opts.BusyRetryAfter <= 0 {
		opts.BusyRetryAfter = DefaultBusyRetryAfter
	}
	s := &Service{
		repo: storeRepo{db: deps.DB}, keys: deps.Keys, notifier: deps.Notifier, queue: deps.Mail,
		seclog: deps.SecurityLog, eraser: deps.Eraser, audit: opts.Audit, logger: opts.Logger, clock: opts.Now,
		failures: opts.Failures, workers: opts.Workers, jobTimeout: opts.JobTimeout,
		busyRetries: opts.BusyRetries, busyDelay: opts.BusyDelay, busyRetryAfter: opts.BusyRetryAfter,
		newToken: id.NewToken, jobs: make(chan linkJob, opts.QueueSize), done: make(chan struct{}),
	}
	if s.failures == nil {
		s.failures = ratelimit.NewWindow(SessionFailureLimit, SessionFailureWindow,
			ratelimit.WithLockout(SessionLockout), ratelimit.WithClock(opts.Now))
	}
	return s, nil
}

// Start starts the request workers. The workers keep the values of ctx but
// not its cancellation: they run until [Service.Close]. It fails when the
// service was already started or closed.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return errStarted
	}
	s.started = true
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s.cancel = cancel
	var wg sync.WaitGroup
	for range s.workers {
		wg.Go(func() { s.work(ctx) })
	}
	go func() {
		wg.Wait()
		cancel()
		close(s.done)
	}()
	return nil
}

// Close stops accepting requests (they then answer ErrMailUnavailable) and
// waits for the workers to process the requests already queued. When ctx is
// done first, the request in progress is canceled, the remaining ones are
// dropped, and ctx.Err() is returned once the workers stopped. Close is
// idempotent; a service never started closes at once.
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.jobs)
	}
	started := s.started
	s.mu.Unlock()
	if !started {
		return nil
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		s.cancel()
		<-s.done
		return ctx.Err()
	}
}

// now returns the clock at the precision of the stored timestamps.
func (s *Service) now() time.Time {
	return s.clock().UTC().Truncate(time.Millisecond)
}

// tokenHash returns the SHA-256 of a bearer token, as the store keeps it.
func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// validToken reports whether tok has the shape of a token with prefix p
// (22 to 43 base62 characters after "p_").
func validToken(p, tok string) bool {
	return id.TokenValid(p, tok, id.MinTokenBodyLen, id.MaxTokenBodyLen)
}

// logEvent writes a security event; a write failure is only reported on
// the application log.
func (s *Service) logEvent(ctx context.Context, t *tenant.Tenant, ip netip.Addr, typ securitylog.EventType, fields ...securitylog.Field) {
	ev := securitylog.Event{Type: typ, IP: ip, Tenant: t.FQDN, Fields: fields}
	if err := s.seclog.Log(ev); err != nil {
		s.logger.ErrorContext(ctx, "security log write failed",
			slog.String("event", string(typ)), slog.String("error", err.Error()))
	}
}

// record appends a tenant audit event whose actor is the sender address
// email, best effort: a failure is only reported on the application log.
// The address goes in the actor column, never in details.
func (s *Service) record(ctx context.Context, t *tenant.Tenant, ip netip.Addr, email string,
	action audit.Action, objectKind, objectID string, details map[string]any,
) {
	if s.audit == nil {
		return
	}
	ev := audit.Event{
		ActorKind: store.ActorDepositor, Actor: email, IP: ip,
		Action: action, ObjectKind: objectKind, ObjectID: objectID, Details: details,
	}
	if err := s.audit.RecordScoped(context.WithoutCancel(ctx), t.ID, ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(action)),
			slog.String("tenant", t.FQDN), slog.String("error", err.Error()))
	}
}

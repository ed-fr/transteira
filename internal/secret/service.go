package secret

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"golang.org/x/time/rate"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
)

// Limits of the recipient side (status and reveal), per client: an IPv4
// address or an IPv6 /64.
const (
	// LinkRequestsPerMinute is the sustained number of status and reveal
	// calls per minute, which is also the burst.
	LinkRequestsPerMinute = 30
	// LinkFailureLimit is the number of failures (unknown tokens, wrong key
	// proofs, wrong passphrase proofs) within LinkFailureWindow that locks
	// the client out for LinkLockout.
	LinkFailureLimit = 10
	// LinkFailureWindow is the window of LinkFailureLimit.
	LinkFailureWindow = 15 * time.Minute
	// LinkLockout is how long a client stays locked out.
	LinkLockout = 15 * time.Minute
	// DailyLimitRetryAfter is the Retry-After announced when a creator
	// reached its daily creations (store.SecretMaxDaily in
	// store.SecretDailyWindow): the oldest creation of the window ages out
	// at an unknown time, an hour is a reasonable hint.
	DailyLimitRetryAfter = time.Hour
)

// Security log scopes of the rate_limited events of the links.
const (
	// ScopeLinkIP is the scope of the per-client request limit.
	ScopeLinkIP = "secret_link_ip"
	// ScopeLink is the scope of the lockout after repeated failures.
	ScopeLink = "secret_link"
)

// Actor of the audit events of the recipient side: like a transfer
// download link, the recipient of a link is anonymous.
const linkActor = "link"

// Repo is the secrets store. *store.Secrets (built with the key vault)
// implements it.
type Repo interface {
	Create(ctx context.Context, tid tenant.ID, c store.CreateSecret) (store.CreatedSecret, error)
	StatusByToken(ctx context.Context, tid tenant.ID, token string, now time.Time) (store.Secret, error)
	Reveal(ctx context.Context, tid tenant.ID, token string, keyProof, proof [32]byte, now time.Time) (store.RevealedSecret, error)
	DeleteByCreator(ctx context.Context, tid tenant.ID, secID string, actor store.SecretActor, now time.Time) (store.EndedSecret, error)
	ListBySender(ctx context.Context, tid tenant.ID, email string, opts store.SecretListOptions) (store.Page[store.Secret], error)
}

// Eligibility applies the deposit eligibility rules of the transfers to a
// creator and returns its normalized address. *transfer.Service implements
// it ([transfer.Service.CheckCreator]); a refusal is transfer.ErrForbidden.
type Eligibility interface {
	CheckCreator(ctx context.Context, t *tenant.Tenant, sender transfer.Sender) (string, error)
}

// Scrubber removes the destroyed keys from the database files after a
// cryptographic erasure. *masterkey.Vault implements it.
type Scrubber interface {
	Scrub(ctx context.Context) error
}

// Files removes the stored file of a secret. *storage.Store implements it.
type Files interface {
	RemoveSecretFile(tid tenant.ID, name string) error
}

// SecurityLog writes security events. *securitylog.Logger implements it.
type SecurityLog interface {
	Log(ev securitylog.Event) error
}

// AuditRecorder records tenant audit events. *audit.Writer implements it.
type AuditRecorder interface {
	RecordScoped(ctx context.Context, tid tenant.ID, ev audit.Event) error
}

// Limiter counts the calls of a client. *ratelimit.Limiter implements it.
type Limiter interface {
	Allow(key string) (ok bool, retryAfter time.Duration)
}

// Failures counts the failures of a client and locks it out.
// *ratelimit.Window implements it.
type Failures interface {
	Locked(key string) (locked bool, retryAfter time.Duration)
	Fail(key string) (locked bool, retryAfter time.Duration)
}

// Deps are the required dependencies of a [Service].
type Deps struct {
	// Secrets is the store of the secrets, with its key vault.
	Secrets Repo
	// Creators checks the eligibility of the creators.
	Creators Eligibility
	// Scrubber scrubs the database after a key destruction.
	Scrubber Scrubber
	// Files removes the files of the deleted secrets.
	Files Files
	// SecurityLog receives the security events.
	SecurityLog SecurityLog
}

// Options tunes a [Service].
type Options struct {
	// Audit records the audit events, best effort after the commit; nil
	// records nothing.
	Audit AuditRecorder
	// Requests limits the status and reveal calls per client (by default
	// LinkRequestsPerMinute per minute).
	Requests Limiter
	// Failures locks out a client after its failures (by default
	// LinkFailureLimit per LinkFailureWindow, locked for LinkLockout).
	Failures Failures
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Logger receives the failures that do not fail a request (audit,
	// security log, scrub, file removal), never with a token or a content;
	// nil discards.
	Logger *slog.Logger
}

// errMissingDeps reports a Service built without one of its Deps.
var errMissingDeps = errors.New("secret: missing dependency")

// Service creates, shows, reveals, lists and deletes one-time secrets. It
// is safe for concurrent use.
type Service struct {
	repo     Repo
	creators Eligibility
	scrubber Scrubber
	files    Files
	seclog   SecurityLog
	audit    AuditRecorder
	requests Limiter
	failures Failures
	now      func() time.Time
	logger   *slog.Logger
}

// New returns a Service. Every member of deps is required.
func New(deps Deps, opts Options) (*Service, error) {
	if deps.Secrets == nil || deps.Creators == nil || deps.Scrubber == nil || deps.Files == nil || deps.SecurityLog == nil {
		return nil, errMissingDeps
	}
	s := &Service{
		repo: deps.Secrets, creators: deps.Creators, scrubber: deps.Scrubber, files: deps.Files,
		seclog: deps.SecurityLog, audit: opts.Audit, requests: opts.Requests, failures: opts.Failures,
		now: opts.Now, logger: opts.Logger,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logger == nil {
		s.logger = slog.New(slog.DiscardHandler)
	}
	if s.requests == nil {
		s.requests = ratelimit.New(rate.Every(time.Minute/LinkRequestsPerMinute), LinkRequestsPerMinute,
			ratelimit.WithClock(s.now))
	}
	if s.failures == nil {
		s.failures = ratelimit.NewWindow(LinkFailureLimit, LinkFailureWindow,
			ratelimit.WithLockout(LinkLockout), ratelimit.WithClock(s.now))
	}
	return s, nil
}

// clientKey returns the rate limit key of ip: the IPv4 address, or the /64
// prefix of an IPv6 address; a single key for an invalid address.
func clientKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return "invalid"
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return ip.String()
	}
	p, _ := ip.Prefix(64) // cannot fail for an IPv6 address
	return p.String()
}

// logEvent writes a security event; a write failure is only reported on the
// application log.
func (s *Service) logEvent(ctx context.Context, t *tenant.Tenant, ip netip.Addr, typ securitylog.EventType, fields ...securitylog.Field) {
	ev := securitylog.Event{Type: typ, IP: ip, Tenant: t.FQDN, TenantID: string(t.ID), Fields: fields}
	if err := s.seclog.Log(ev); err != nil {
		s.logger.ErrorContext(ctx, "security log write failed",
			slog.String("event", string(typ)), slog.String("error", err.Error()))
	}
}

// record appends a tenant audit event about the secret secID, best effort:
// a failure is only reported on the application log.
func (s *Service) record(ctx context.Context, t *tenant.Tenant, ev audit.Event) {
	if s.audit == nil {
		return
	}
	if ev.ObjectKind == "" {
		ev.ObjectKind = audit.ObjectSecret
	}
	if err := s.audit.RecordScoped(context.WithoutCancel(ctx), t.ID, ev); err != nil {
		s.logger.ErrorContext(ctx, "secret: audit write failed",
			slog.String("tenant", t.FQDN), slog.String("action", string(ev.Action)), slog.String("error", err.Error()))
	}
}

// erased finishes a cryptographic erasure of tenant t: the stored file of
// the secret is removed ("" for none), then the destroyed keys are scrubbed
// from the database files. Both are best effort: a failure is logged (the
// lifecycle task removes the orphan files, and the next scrub catches up).
func (s *Service) erased(ctx context.Context, t *tenant.Tenant, file string) {
	ctx = context.WithoutCancel(ctx)
	if file != "" {
		if err := s.files.RemoveSecretFile(t.ID, file); err != nil {
			s.logger.ErrorContext(ctx, "secret: removing the file of a secret failed",
				slog.String("tenant", t.FQDN), slog.String("error", err.Error()))
		}
	}
	if err := s.scrubber.Scrub(ctx); err != nil {
		s.logger.ErrorContext(ctx, "secret: scrubbing the destroyed keys failed",
			slog.String("tenant", t.FQDN), slog.String("error", err.Error()))
	}
}

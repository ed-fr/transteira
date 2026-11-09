package secret

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"golang.org/x/time/rate"

	"github.com/ed-fr/transteira/internal/abuse"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
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
	UploadFile(ctx context.Context, tid tenant.ID, secID string, actor store.SecretActor, files store.SecretFiles,
		body io.Reader, clock func() time.Time) (store.Secret, error)
	OpenFile(ctx context.Context, tid tenant.ID, token, grant string, files store.SecretFiles, now time.Time) (*store.SecretFileDownload, error)
	CompleteFileDownload(ctx context.Context, tid tenant.ID, secID, grant string, now time.Time) (store.EndedSecret, bool, error)
	Get(ctx context.Context, tid tenant.ID, secID string) (store.Secret, error)
	ActivateForSend(ctx context.Context, tid tenant.ID, secID string, actor store.SecretActor, token string, now time.Time) (store.Secret, error)
	MarkReceiptSent(ctx context.Context, tid tenant.ID, secID string, now time.Time) (bool, error)
}

// Notifier builds the mails of the secrets. *notify.Notifier implements
// it.
type Notifier interface {
	// SecretNotification builds the mail of the link to the recipient of
	// an e-mail secret; link is never logged.
	SecretNotification(ctx context.Context, t *tenant.Tenant, v notify.SecretView, link string) (mail.Job, error)
	// SecretReceipt builds the read receipt to the creator.
	SecretReceipt(ctx context.Context, t *tenant.Tenant, v notify.SecretView, outcome string, at time.Time) (mail.Job, error)
}

// Mailer queues built mails without blocking, retrying while the queue is
// full. *mail.Retrier implements it.
type Mailer interface {
	Send(ctx context.Context, jobs []mail.Job, attrs ...slog.Attr)
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

// Files stores, opens and removes the files of the secrets.
// *storage.Store implements it.
type Files = store.SecretFiles

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

// StreamSlots bounds the concurrent file downloads (threat model T-55):
// a secret file response holds the slots a transfer response holds, until
// it ends. *download.Service implements it; a refusal is a
// *download.TooManyStreamsError.
type StreamSlots interface {
	AcquireStream(ctx context.Context, t *tenant.Tenant, objectID string, ip netip.Addr) (release func(), err error)
}

// Deps are the required dependencies of a [Service].
type Deps struct {
	// Secrets is the store of the secrets, with its key vault.
	Secrets Repo
	// Creators checks the eligibility of the creators.
	Creators Eligibility
	// Scrubber scrubs the database after a key destruction.
	Scrubber Scrubber
	// Files stores the files of the secrets and removes those of the
	// ended secrets.
	Files Files
	// SecurityLog receives the security events.
	SecurityLog SecurityLog
	// Directory reads the tenants, their recipient domain rules and their
	// blocklists.
	Directory Directory
	// Notifier builds the link and receipt mails.
	Notifier Notifier
	// Mailer queues them.
	Mailer Mailer
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
	// OnQuota is called after the creation of a secret with a file
	// (refused false) and when one is refused because the storage quota of
	// the tenant is exceeded (refused true), as transfer.Options.OnQuota,
	// so that the quota alerts are raised. Nil does nothing.
	OnQuota func(tid tenant.ID, refused bool)
	// Streams bounds the concurrent file downloads; nil bounds nothing
	// (tests only: the application always sets it).
	Streams StreamSlots
	// Abuse is told of every secret that becomes active (link: at the
	// creation without file or after the upload; e-mail: after the send),
	// alert only; nil tells nobody.
	Abuse AbuseAlerter
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Logger receives the failures that do not fail a request (audit,
	// security log, scrub, file removal), never with a token or a content;
	// nil discards.
	Logger *slog.Logger
}

// errMissingDeps reports a Service built without one of its Deps.
var errMissingDeps = errors.New("secret: missing dependency")

// Service creates, sends, shows, reveals, lists and deletes one-time
// secrets, and sends their read receipts. It is safe for concurrent use.
type Service struct {
	repo     Repo
	creators Eligibility
	scrubber Scrubber
	files    Files
	seclog   SecurityLog
	dir      Directory
	notifier Notifier
	mailer   Mailer
	audit    AuditRecorder
	abuse    AbuseAlerter
	streams  StreamSlots
	requests Limiter
	failures Failures
	onQuota  func(tid tenant.ID, refused bool)
	now      func() time.Time
	logger   *slog.Logger
}

// New returns a Service. Every member of deps is required.
func New(deps Deps, opts Options) (*Service, error) {
	if deps.Secrets == nil || deps.Creators == nil || deps.Scrubber == nil || deps.Files == nil || deps.SecurityLog == nil ||
		deps.Directory == nil || deps.Notifier == nil || deps.Mailer == nil {
		return nil, errMissingDeps
	}
	s := &Service{
		repo: deps.Secrets, creators: deps.Creators, scrubber: deps.Scrubber, files: deps.Files,
		seclog: deps.SecurityLog, dir: deps.Directory, notifier: deps.Notifier, mailer: deps.Mailer, audit: opts.Audit, requests: opts.Requests, failures: opts.Failures,
		onQuota: opts.OnQuota, abuse: opts.Abuse, streams: opts.Streams, now: opts.Now, logger: opts.Logger,
	}
	if s.onQuota == nil {
		s.onQuota = func(tenant.ID, bool) {}
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

// AbuseAlerter evaluates the abuse rules once a secret became active
// (CLAUDE.md section 15, threat model T-340): the store counts the active
// secrets of the sender in its transfer count. *abuse.Detector implements
// it. It only alerts: the creation of a secret is never blocked by the
// abuse thresholds (the creator limits of the store bound it).
type AbuseAlerter interface {
	AfterCreate(ctx context.Context, t *tenant.Tenant, f abuse.Facts)
}

// activated reports the secret sec of tenant t, just activated for the
// client of sender, to the abuse detection (best effort, alert only).
func (s *Service) activated(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, sec store.Secret) {
	if s.abuse == nil {
		return
	}
	f := abuse.Facts{
		SenderEmail: sec.SenderEmail, Kind: depositorKind(sec.CreatorKind), At: sec.ActivatedAt, ClientIP: sender.ClientIP,
	}
	if sec.RecipientEmail != "" {
		f.Recipients = []string{sec.RecipientEmail}
	}
	s.abuse.AfterCreate(context.WithoutCancel(ctx), t, f)
}

// depositorKind returns the depositor kind the abuse rules know for a
// creator kind: an API token deposits as an internal sender, as for a
// transfer.
func depositorKind(k store.SecretCreatorKind) store.DepositorKind {
	switch k {
	case store.SecretCreatorExternal:
		return store.DepositorExternal
	case store.SecretCreatorInternalRemote:
		return store.DepositorInternalRemote
	}
	return store.DepositorInternal
}

package deposit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/vcode"
)

// Rules of spec 7 (verification codes), 9 (invitations) and 8.2 (expiry).
const (
	// CodeTTL is the validity of a verification code.
	CodeTTL = vcode.TTL
	// CodeDigits is the number of digits of a verification code.
	CodeDigits = vcode.Digits
	// MaxCodesPerAddress bounds the codes sent to one address per
	// RateWindow.
	MaxCodesPerAddress = vcode.MaxPerAddress
	// MaxCodesPerIP bounds the codes requested from one client IP per
	// RateWindow, all purposes combined.
	MaxCodesPerIP = vcode.MaxPerIP
	// RateWindow is the sliding window of the code rate limits.
	RateWindow = vcode.Window
	// QueueFullRetryAfter is the Retry-After hint when the mail queue is
	// full.
	QueueFullRetryAfter = vcode.QueueFullRetryAfter
	// MaxInvitationsPerInviter bounds the invitations one internal address
	// may issue per RateWindow in a tenant (threats T-12, T-89) when the
	// service has no Options.Abuse; otherwise the tenant setting of spec
	// 15.2 applies.
	MaxInvitationsPerInviter = 20
	// VerifiedRetentionMonths is how long an unused verified address stays
	// verified (spec 7); the cleanup job purges it, and until then the
	// service ignores it.
	VerifiedRetentionMonths = store.VerifiedRetentionMonths
	// MaxMessageRunes bounds the message of an invitation (OpenAPI
	// InvitationCreate), after the removal of the control and invisible
	// characters.
	MaxMessageRunes = store.MaxInvitationMessageLen
	// DefaultSessionTTL is the session lifetime when Options.SessionTTL is
	// not set (TT_DEPOSIT_SESSION_TTL).
	DefaultSessionTTL = 4 * time.Hour
	// CSRFPrefix starts every CSRF token.
	CSRFPrefix = "csrf_"
	// InvitationPath is the path of the invitation landing page of the web
	// interface; the token follows it.
	InvitationPath = "/i/"
)

// expiryDays are the transfer lifetimes offered to depositors (spec 8.2).
var expiryDays = []int{1, 7, 30}

// Security log scopes of the rate limits.
const (
	scopeCodesPerAddress = "verification_address"
	scopeCodesPerIP      = "verification_ip"
	scopeInvitations     = "invitation"
)

// errLimited aborts the transaction of a request over a rate limit.
var errLimited = errors.New("deposit: rate limit reached")

// Keys computes and verifies the MACs keyed by the master key.
// *masterkey.Keyring implements it.
type Keys interface {
	MAC(p crypto.MACPurpose, parts ...[]byte) ([]byte, error)
	VerifyMAC(p crypto.MACPurpose, mac []byte, parts ...[]byte) (bool, error)
}

// Secrets unseals the wrapped secrets of a tenant. *masterkey.Vault
// implements it.
type Secrets interface {
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
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

// AuditRecorder records tenant audit events. *audit.Writer implements it.
type AuditRecorder interface {
	RecordScoped(ctx context.Context, tid tenant.ID, ev audit.Event) error
}

// Audit detail values of the origin of a verification.
const (
	// originInternal is a verification by an internal depositor.
	originInternal = "internal"
	// originInvitation is a verification through an invitation.
	originInvitation = "invitation"
	// originRemote is a verification by an internal depositor from outside
	// the tenant ranges (V1.1, spec 6.4).
	originRemote = "remote"
)

// AbuseDetector supplies the configurable invitation limit of spec 15.2 and
// raises its alert. *abuse.Detector implements it.
type AbuseDetector interface {
	// InvitationLimit returns the maximum number of invitations one inviter
	// may issue per RateWindow in tenant tid.
	InvitationLimit(ctx context.Context, tid tenant.ID) (int, error)
	// InvitationLimitReached alerts the administrators of t that inviter
	// reached limit. It is best effort and never fails.
	InvitationLimitReached(ctx context.Context, t *tenant.Tenant, inviter string, limit int)
}

// Options tunes a [Service].
type Options struct {
	// SessionTTL is the absolute lifetime of a deposit session
	// (DefaultSessionTTL when <= 0).
	SessionTTL time.Duration
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Logger receives the failures to write the security log and to read
	// a customized mail template, which never fail a request (nil
	// discards).
	Logger *slog.Logger
	// Overrides returns the customized mail templates of the tenants,
	// usually notify.StoreOverrides(db.TenantEmailTemplates()); nil uses
	// the default templates for every tenant. A lookup failure falls back
	// to the default template (see [Service.prepareMail]).
	Overrides mail.OverrideLookup
	// Audit records the tenant audit events (address verified, invitation
	// created and first used), best effort after the commit: a failure is
	// logged, never returned. nil records nothing.
	Audit AuditRecorder
	// Abuse supplies the per-inviter invitation limit of each tenant
	// (maxInvitationsPerInviter of its abuse settings) and alerts when it
	// is reached (V1.1, spec 15.2). nil applies MaxInvitationsPerInviter
	// everywhere, without alert.
	Abuse AbuseDetector
}

// Service identifies depositors. It is safe for concurrent use.
type Service struct {
	repo       repo
	keys       Keys
	secrets    Secrets
	queue      MailQueue
	seclog     SecurityLog
	logger     *slog.Logger
	sessionTTL time.Duration
	clock      func() time.Time
	overrides  mail.OverrideLookup
	audit      AuditRecorder
	abuse      AbuseDetector
	// Mail rendering and random sources, replaced by the tests.
	render   func(ctx context.Context, lookup mail.OverrideLookup, tenantID, name, lang string, data any) (mail.Message, error)
	rand     io.Reader
	newToken func(prefix string, entropyBytes int) (string, error)
	newID    func(p id.Prefix) (string, error)
}

// New returns a service over db, computing MACs with keys, unsealing SMTP
// passwords with secrets, sending mails through queue and writing security
// events to seclog. Every dependency is required.
func New(db *store.DB, keys Keys, secrets Secrets, queue MailQueue, seclog SecurityLog, opts Options) *Service {
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = DefaultSessionTTL
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Service{
		repo: storeRepo{db: db}, keys: keys, secrets: secrets, queue: queue, seclog: seclog,
		logger: opts.Logger, sessionTTL: opts.SessionTTL, clock: opts.Now, overrides: opts.Overrides,
		audit: opts.Audit, abuse: opts.Abuse, render: mail.DefaultTemplates().RenderFor, rand: rand.Reader, newToken: id.NewToken,
	}
	s.newID = id.NewGenerator(s.clock, nil).New
	return s
}

// now returns the clock at the precision of the stored timestamps, so that
// the values the service returns equal the stored ones.
func (s *Service) now() time.Time {
	return s.clock().UTC().Truncate(time.Millisecond)
}

// tokenHash returns the SHA-256 of a bearer token, as the store keeps it.
func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// validToken reports whether tok has the shape of a token with prefix p.
func validToken(p, tok string) bool {
	return id.TokenValid(p, tok, id.MinTokenBodyLen, id.MaxTokenBodyLen)
}

// newCode draws a verification code from the random source of the service
// (see vcode.New).
func (s *Service) newCode() (string, error) {
	code, err := vcode.New(s.rand)
	if err != nil {
		return "", fmt.Errorf("deposit: %w", err)
	}
	return code, nil
}

// validCode reports whether code is exactly CodeDigits ASCII digits.
func validCode(code string) bool { return vcode.Valid(code) }

// logEvent writes a security event; a write failure is only reported on the
// application log.
func (s *Service) logEvent(ctx context.Context, t *tenant.Tenant, ip netip.Addr, typ securitylog.EventType, fields ...securitylog.Field) {
	ev := securitylog.Event{Type: typ, IP: ip, Tenant: t.FQDN, Fields: fields}
	if err := s.seclog.Log(ev); err != nil {
		s.logger.ErrorContext(ctx, "security log write failed",
			slog.String("event", string(typ)), slog.String("error", err.Error()))
	}
}

// refuse logs a deposit_refused event with reason and returns ErrForbidden.
func (s *Service) refuse(ctx context.Context, t *tenant.Tenant, ip netip.Addr, reason string) error {
	s.logEvent(ctx, t, ip, securitylog.DepositRefused, securitylog.Field{Key: securitylog.KeyReason, Value: reason})
	return ErrForbidden
}

// record appends a tenant audit event whose actor is the depositor address
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

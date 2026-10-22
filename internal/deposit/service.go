package deposit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Rules of spec 7 (verification codes), 9 (invitations) and 8.2 (expiry).
const (
	// CodeTTL is the validity of a verification code.
	CodeTTL = 15 * time.Minute
	// CodeDigits is the number of digits of a verification code.
	CodeDigits = 6
	// MaxCodesPerAddress bounds the codes sent to one address per
	// RateWindow.
	MaxCodesPerAddress = 5
	// MaxCodesPerIP bounds the codes requested from one client IP per
	// RateWindow.
	MaxCodesPerIP = 20
	// RateWindow is the sliding window of the code rate limits.
	RateWindow = time.Hour
	// QueueFullRetryAfter is the Retry-After hint when the mail queue is
	// full.
	QueueFullRetryAfter = 30 * time.Second
	// MaxInvitationsPerInviter bounds the invitations one internal address
	// may issue per RateWindow in a tenant (threats T-12, T-89; the configurable
	// per-inviter quota of spec 15.2 comes with V1.1).
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

// Code drawing bounds.
const (
	codeSpace         = 1_000_000 // 10^CodeDigits
	codeRejectAtOrAbv = (1 << 32) - (1<<32)%codeSpace
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
		render: mail.DefaultTemplates().RenderFor, rand: rand.Reader, newToken: id.NewToken,
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

// newCode draws a verification code uniformly among the 10^6 values: a
// 32-bit random value is rejected when it falls in the incomplete last
// block, so that the reduction modulo 10^6 has no bias.
func (s *Service) newCode() (string, error) {
	var b [4]byte
	for {
		if _, err := io.ReadFull(s.rand, b[:]); err != nil {
			return "", fmt.Errorf("deposit: read random: %w", err)
		}
		if v := binary.BigEndian.Uint32(b[:]); v < codeRejectAtOrAbv {
			return fmt.Sprintf("%0*d", CodeDigits, v%codeSpace), nil
		}
	}
}

// validCode reports whether code is exactly CodeDigits ASCII digits.
func validCode(code string) bool {
	if len(code) != CodeDigits {
		return false
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

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

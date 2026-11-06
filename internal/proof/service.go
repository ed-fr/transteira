package proof

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"golang.org/x/time/rate"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Default rate limit of the proof downloads, per client (IPv4 address or
// IPv6 /64), all tenants and both operations together (T-303): a PDF is
// rendered for each request.
const (
	// DefaultRatePerMinute is the sustained number of proofs per minute.
	DefaultRatePerMinute = 10
	// DefaultBurst is the number of proofs allowed at once.
	DefaultBurst = 20
)

// ScopeProofIP is the security log scope of the rate limit of the proof
// downloads.
const ScopeProofIP = "proof_ip"

// TenantAuditor records tenant audit events. *audit.Writer implements it.
type TenantAuditor interface {
	RecordScoped(ctx context.Context, tid tenant.ID, ev audit.Event) error
}

// SecurityLog writes security events. *securitylog.Logger implements it.
type SecurityLog interface {
	Log(ev securitylog.Event) error
}

// Document is a proof ready to be served.
type Document struct {
	// FileName is the ASCII download name ([FileName]).
	FileName string
	// PDF is the document.
	PDF []byte
}

// Option configures a [Service].
type Option func(*Service)

// WithRateLimit sets the rate limit of the proof downloads per client:
// perMinute proofs per minute, up to burst at once. Values below 1 keep
// the defaults.
func WithRateLimit(perMinute, burst int) Option {
	return func(s *Service) {
		if perMinute >= 1 && burst >= 1 {
			s.perMinute, s.burst = perMinute, burst
		}
	}
}

// WithSecurityLog writes the rate limit refusals to l (event
// rate_limited, scope ScopeProofIP). Without it they are not logged.
func WithSecurityLog(l SecurityLog) Option {
	return func(s *Service) { s.seclog = l }
}

// Service serves the proofs of the transfers to their sender and to the
// administrators of their tenant, and the public keys that verify them.
// It is safe for concurrent use.
type Service struct {
	db               *store.DB
	signer           *Signer
	audit            TenantAuditor
	clock            func() time.Time
	logger           *slog.Logger
	seclog           SecurityLog
	perMinute, burst int
	limiter          *ratelimit.Limiter
}

// NewService returns the proof service over db. signer serves the public
// keys, rec records the downloads (transfer.proof_downloaded). A nil clock
// is time.Now and a nil logger discards.
func NewService(db *store.DB, signer *Signer, rec TenantAuditor, clock func() time.Time, logger *slog.Logger, opts ...Option) *Service {
	if clock == nil {
		clock = time.Now
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &Service{
		db: db, signer: signer, audit: rec, clock: clock, logger: logger,
		perMinute: DefaultRatePerMinute, burst: DefaultBurst,
	}
	for _, o := range opts {
		o(s)
	}
	s.limiter = ratelimit.New(rate.Every(time.Minute/time.Duration(s.perMinute)), s.burst, ratelimit.WithClock(clock))
	return s
}

// MyProof returns the proof of kind kind of the transfer trfID of tenant t
// for its sender, the address senderEmail of a "my transfers" session, in
// lang (the tenant default when unsupported). The transfer must be one of
// the sender's in progress, exactly as for the transfer detail
// (store.Transfers.GetBySender): any other transfer, deleted or ended
// ones included (P60: then only the administrators reach the proof), is
// ErrNotFound. With kind delivery, recipient selects the proof of that
// recipient's first download; "" selects the first download of the
// transfer.
//
// It returns ErrRateLimited (a *RateLimitError) beyond the limit of the
// client ip, ErrInvalid for a malformed kind or recipient or a recipient
// with kind deposit, ErrNotAvailable when the proof does not exist or the
// transfer was deposited through a drop link (its statement names the
// recipients of the link, never disclosed to the depositor). The download
// is audited as transfer.proof_downloaded, the sender as actor.
func (s *Service) MyProof(ctx context.Context, t *tenant.Tenant, senderEmail, trfID string, kind store.ProofKind,
	recipient, lang string, ip netip.Addr,
) (Document, error) {
	if err := s.allow(ctx, t.ID, t.FQDN, ip); err != nil {
		return Document{}, err
	}
	rcpt, err := checkRequest(kind, recipient)
	if err != nil {
		return Document{}, err
	}
	d, err := s.db.Transfers().GetBySender(ctx, t.ID, trfID, senderEmail)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return Document{}, ErrNotFound
	case err != nil:
		return Document{}, fmt.Errorf("proof: read transfer: %w", err)
	case d.DropLinkID != "":
		// The signed statement names the recipients of the drop link,
		// never disclosed to its depositor (T-311): only the
		// administrators reach these proofs.
		return Document{}, ErrNotAvailable
	}
	doc, err := s.document(ctx, t, trfID, kind, rcpt, lang)
	if err != nil {
		return Document{}, err
	}
	s.record(ctx, t.ID, store.ActorDepositor, senderEmail, ip, trfID, kind)
	return doc, nil
}

// TenantProof returns the proof of kind kind of the transfer trfID of
// tenant tid for the administrator p (delegated admin or auditor of the
// tenant, super admin), in lang (the tenant default when unsupported).
// The proof outlives the transfer: it is served as long as it is kept,
// whatever became of the transfer. recipient is as in [Service.MyProof].
//
// It returns adminauth.ErrUnauthenticated for a session that is not
// authenticated and adminauth.ErrNotFound for a tenant the administrator
// does not reach (checked first), ErrNotFound for an unknown tenant, and
// otherwise the errors of [Service.MyProof]. The download is audited as
// transfer.proof_downloaded, the administrator as actor.
func (s *Service) TenantProof(ctx context.Context, p adminauth.Principal, tid tenant.ID, trfID string, kind store.ProofKind,
	recipient, lang string, ip netip.Addr,
) (Document, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return Document{}, err
	}
	if err := adminauth.RequireTenantAuditRead(p.Admin, tid); err != nil {
		return Document{}, err
	}
	if err := s.allow(ctx, tid, "", ip); err != nil {
		return Document{}, err
	}
	rcpt, err := checkRequest(kind, recipient)
	if err != nil {
		return Document{}, err
	}
	t, err := s.db.Tenants().Get(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return Document{}, ErrNotFound
	case err != nil:
		return Document{}, fmt.Errorf("proof: read tenant: %w", err)
	}
	doc, err := s.document(ctx, t, trfID, kind, rcpt, lang)
	if err != nil {
		return Document{}, err
	}
	s.record(ctx, tid, store.ActorAdmin, p.Admin.Username, ip, trfID, kind)
	return doc, nil
}

// Keys returns every public signing key, most recent first (OpenAPI
// listProofKeys).
func (s *Service) Keys(ctx context.Context) ([]PublicKey, error) {
	return s.signer.Keys(ctx)
}

// checkRequest validates kind and recipient and returns the normalized
// recipient ("" for none).
func checkRequest(kind store.ProofKind, recipient string) (string, error) {
	if kind != store.ProofDeposit && kind != store.ProofDelivery {
		return "", &InvalidError{Param: ParamKind}
	}
	if recipient == "" {
		return "", nil
	}
	if kind != store.ProofDelivery {
		return "", &InvalidError{Param: ParamRecipient}
	}
	rcpt, err := store.NormalizeEmail(recipient)
	if err != nil {
		return "", &InvalidError{Param: ParamRecipient}
	}
	return rcpt, nil
}

// document reads the proof (kind, recipient) of the transfer trfID of
// tenant t and renders it.
func (s *Service) document(ctx context.Context, t *tenant.Tenant, trfID string, kind store.ProofKind, recipient, lang string) (Document, error) {
	proofs := s.db.TransferProofs()
	var (
		p   store.TransferProof
		err error
	)
	if recipient == "" {
		p, err = proofs.Get(ctx, t.ID, trfID, kind, "")
	} else {
		p, err = proofs.GetRecipientDelivery(ctx, t.ID, trfID, recipient)
	}
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return Document{}, ErrNotAvailable
	case err != nil:
		return Document{}, fmt.Errorf("proof: read proof: %w", err)
	case !p.ExpiresAt.After(s.clock()):
		return Document{}, ErrNotAvailable // kept beyond its retention until the next purge
	}
	st, err := ParseStatement(p.Statement)
	if err != nil {
		return Document{}, fmt.Errorf("proof: stored statement %s: %w", p.ID, err)
	}
	if st.TransferID != trfID || st.Kind != kind || st.KeyID != p.KeyID {
		return Document{}, fmt.Errorf("proof: stored statement %s does not match its row", p.ID)
	}
	if !i18n.IsSupported(lang) {
		lang = t.DefaultLanguage
	}
	data, err := Render(st, p.Statement, p.Signature, lang, KeysURL(t.FQDN))
	if err != nil {
		return Document{}, err
	}
	return Document{FileName: FileName(kind, trfID), PDF: data}, nil
}

// allow applies the rate limit of the client ip, logging a refusal.
func (s *Service) allow(ctx context.Context, tid tenant.ID, fqdn string, ip netip.Addr) error {
	ok, retry := s.limiter.Allow(clientKey(ip))
	if ok {
		return nil
	}
	if s.seclog != nil {
		ev := securitylog.Event{
			Type: securitylog.RateLimited, IP: ip, Tenant: fqdn, TenantID: string(tid),
			Fields: []securitylog.Field{{Key: securitylog.KeyScope, Value: ScopeProofIP}},
		}
		if err := s.seclog.Log(ev); err != nil {
			s.logger.ErrorContext(ctx, "security log write failed", slog.String("error", err.Error()))
		}
	}
	return &RateLimitError{RetryAfter: retry}
}

// clientKey returns the rate limit key of ip: the IPv4 address, or the
// /64 prefix of an IPv6 address; a single key for an invalid address.
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

// record writes the audit event of a proof download, best effort: the
// proof is served already, a failure is only logged. The details hold the
// kind only (no recipient address).
func (s *Service) record(ctx context.Context, tid tenant.ID, kind store.AuditActorKind, actor string, ip netip.Addr,
	trfID string, proofKind store.ProofKind,
) {
	ev := audit.Event{
		ActorKind: kind, Actor: actor, IP: ip, Action: audit.ActionTransferProofDownloaded,
		ObjectKind: audit.ObjectTransfer, ObjectID: trfID, Details: map[string]any{"kind": string(proofKind)},
	}
	if err := s.audit.RecordScoped(context.WithoutCancel(ctx), tid, ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(audit.ActionTransferProofDownloaded)),
			slog.String("tenant", string(tid)), slog.String("error", err.Error()))
	}
}

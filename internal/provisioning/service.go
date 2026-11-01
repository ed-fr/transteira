package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
	"github.com/ed-fr/transteira/internal/textsafe"
	"github.com/ed-fr/transteira/internal/touchthrottle"
)

// Defaults of the [Options].
const (
	// DefaultTouchInterval is the minimum delay between two recordings of
	// the last use of a token.
	DefaultTouchInterval = touchthrottle.DefaultInterval
	// DefaultMaxTracked bounds the number of tokens whose last recording
	// is remembered for that throttling.
	DefaultMaxTracked = touchthrottle.DefaultMaxTracked
)

// Limits of a new token, beyond those of the store.
const (
	// AttemptsPerHour bounds the tenant creation attempts of one token
	// within AttemptWindow, whatever their outcome (T-273), in memory.
	AttemptsPerHour = 30
	// AttemptWindow is the sliding window of AttemptsPerHour.
	AttemptWindow = time.Hour
	// RefusalAuditInterval is the minimum delay between two
	// tenant.provision_refused events of one token for rate-limited
	// attempts.
	RefusalAuditInterval = time.Minute
	// MaxTenantsLimit bounds the maxTenants of a token.
	MaxTenantsLimit = 1_000_000
	// maxScopeDetailBytes bounds the encoded size of the lists of ranges
	// and suffixes recorded in the audit event of a token creation; beyond
	// it, only their counts are recorded (the details hold at most
	// store.MaxAuditDetailsBytes bytes).
	maxScopeDetailBytes = 2048
)

// Audit actions of the provisioning API (OpenAPI AuditAction).
const (
	// ActionTokenCreated records the creation of a provisioning token by a
	// super admin (global, never with the secret).
	ActionTokenCreated audit.Action = "provisioning_token.created"
	// ActionTokenRevoked records the revocation of a provisioning token
	// (global).
	ActionTokenRevoked audit.Action = "provisioning_token.revoked"
	// ActionTenantProvisioned records the creation of a tenant with a
	// provisioning token (actor kind provisioning_token, actor the token
	// identifier).
	ActionTenantProvisioned audit.Action = "tenant.provisioned"
	// ActionTenantProvisionRefused records a refused tenant creation by a
	// provisioning token (global, actor kind provisioning_token, actor and
	// object the token identifier, details the reason code only).
	ActionTenantProvisionRefused audit.Action = "tenant.provision_refused"
)

// Audit object kinds.
const (
	objectToken  = "provisioning_token"
	objectTenant = "tenant"
)

// Confirmer re-confirms the second factor of an administrator, exactly as
// for a master key rotation (threat model P49). *adminauth.Service
// implements it.
type Confirmer interface {
	ConfirmTOTP(ctx context.Context, p adminauth.Principal, code, recoveryCode string, clientIP netip.Addr) (adminauth.Account, error)
}

// TenantProvisioner creates a provisioned tenant with its first delegated
// admin. *tenantadmin.Service implements it.
type TenantProvisioner interface {
	ProvisionTenant(ctx context.Context, actor adminauth.AuditActor, tokID string, in tenantadmin.TenantCreate,
		clientIP netip.Addr) (tenantadmin.TenantCreated, error)
}

// SuperAdminNotifier tells the super admins, through the system SMTP, that a
// tenant was provisioned or completed its setup (threat model P50), or that
// a provisioning token was created (T-275). It is
// [tenantadmin.ProvisioningNotifier], shared with the setup completion.
type SuperAdminNotifier = tenantadmin.ProvisioningNotifier

// Options configures a [Service].
type Options struct {
	// Confirmer checks the TOTP re-confirmation of a token creation
	// (required).
	Confirmer Confirmer
	// Tenants creates the provisioned tenants (required).
	Tenants TenantProvisioner
	// AdminHosts are the hosts of the administration (config.AdminHosts):
	// no suffix of a token may equal or cover one.
	AdminHosts []string
	// Audit is the shared audit writer of the application; nil means a
	// writer of its own over the database, publishing nothing.
	Audit *audit.Writer
	// Events receives the tenant.provisioned and
	// provisioning_token.created system events; nil publishes nothing.
	Events events.Publisher
	// Notifier tells the super admins of each provisioned tenant and of
	// each new token; nil tells nobody.
	Notifier SuperAdminNotifier
	// Logger receives the failures that do not change an answer (audit
	// after commit, last use); nil means slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// TouchInterval is the minimum delay between two recordings of the
	// last use of a token; <= 0 means DefaultTouchInterval.
	TouchInterval time.Duration
	// MaxTracked bounds the tokens remembered for that throttling; <= 0
	// means DefaultMaxTracked.
	MaxTracked int
}

// Service manages the provisioning tokens (super admin) and serves the
// provisioning API (token holders). It is safe for concurrent use.
type Service struct {
	repo       repo
	confirm    Confirmer
	tenants    TenantProvisioner
	adminHosts []string
	events     events.Publisher
	notifier   SuperAdminNotifier
	logger     *slog.Logger
	now        func() time.Time

	// touches throttles the recordings of the last use of each token.
	touches *touchthrottle.Throttle
	// attempts counts the tenant creation attempts of each token.
	attempts *ratelimit.Window
	// refusalAudits throttles the audit of the rate-limited attempts.
	refusalAudits *touchthrottle.Throttle
}

// errMissingDependency reports a [New] call without a required option.
var errMissingDependency = errors.New("provisioning: a database, Confirmer and Tenants are required")

// New returns the service over db. It fails when a required option is
// missing.
func New(db *store.DB, opts Options) (*Service, error) {
	if db == nil || opts.Confirmer == nil || opts.Tenants == nil {
		return nil, errMissingDependency
	}
	s := &Service{
		repo: &storeRepo{db: db, writer: audit.OrNew(opts.Audit, db)}, confirm: opts.Confirmer, tenants: opts.Tenants,
		events: events.OrDiscard(opts.Events), notifier: opts.Notifier, logger: opts.Logger, now: opts.Now,
		touches:       touchthrottle.New(opts.TouchInterval, opts.MaxTracked),
		attempts:      ratelimit.NewWindow(AttemptsPerHour, AttemptWindow, ratelimit.WithClock(opts.Now)),
		refusalAudits: touchthrottle.New(RefusalAuditInterval, opts.MaxTracked),
	}
	for _, h := range opts.AdminHosts {
		if n, err := tenant.NormalizeHost(h); err == nil {
			h = n
		}
		s.adminHosts = append(s.adminHosts, strings.ToLower(h))
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Token is a provisioning token as the super admin sees it (OpenAPI
// ProvisioningToken): never its secret nor its hash.
type Token struct {
	ID                   string
	Name                 string
	Prefix               string
	AllowedCIDRs         []netip.Prefix
	AllowedFQDNSuffixes  []string
	MaxStorageQuotaBytes int64
	// MaxTransferBytes is the per-transfer cap, 0 for none below 20 GiB.
	MaxTransferBytes int64
	MaxTenants       int
	// TenantsCreated is the number of live tenants the token created.
	TenantsCreated int
	// CreatedBy is the identifier of the super admin who created it.
	CreatedBy string
	CreatedAt time.Time
	// LastUsedAt, ExpiresAt and RevokedAt are zero when unset.
	LastUsedAt time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
}

// tokenOf returns the view of t.
func tokenOf(t store.ProvisioningToken) Token {
	return Token{
		ID: t.ID, Name: t.Name, Prefix: t.Prefix, AllowedCIDRs: t.AllowedCIDRs, AllowedFQDNSuffixes: t.AllowedFQDNSuffixes,
		MaxStorageQuotaBytes: t.MaxStorageQuotaBytes, MaxTransferBytes: t.MaxTransferBytes, MaxTenants: t.MaxTenants,
		TenantsCreated: t.TenantsCreated, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt,
		ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt,
	}
}

// CreatedToken is a new token with its secret, returned once (OpenAPI
// ProvisioningTokenCreated).
type CreatedToken struct {
	Token
	// Secret is the token itself; it is never stored nor logged.
	Secret string
}

// TokenCreate is the input of [Service.CreateToken] (OpenAPI
// ProvisioningTokenCreate, without the TOTP members).
type TokenCreate struct {
	Name string
	// AllowedCIDRs are the IP ranges in CIDR notation.
	AllowedCIDRs []string
	// AllowedFQDNSuffixes are the FQDN suffixes, normalized by the service
	// (see [NormalizeSuffix]).
	AllowedFQDNSuffixes  []string
	MaxStorageQuotaBytes int64
	// MaxTransferBytes is the optional per-transfer cap.
	MaxTransferBytes *int64
	MaxTenants       int
	// ExpiresAt is the optional expiry, in the future.
	ExpiresAt *time.Time
}

// superAdmin checks that p is an authenticated session of a super admin.
func superAdmin(p adminauth.Principal) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	return adminauth.RequireSuperAdmin(p.Admin)
}

// checkName validates the name of a token.
func checkName(name string) error {
	n := utf8.RuneCountInString(name)
	if n == 0 || n > store.MaxProvisioningTokenNameLen || !utf8.ValidString(name) || strings.TrimSpace(name) == "" ||
		strings.ContainsFunc(name, func(r rune) bool {
			return textsafe.IsControl(r) || textsafe.IsBidiControl(r) || textsafe.IsLineSeparator(r)
		}) {
		return invalid(FieldName, "must be 1 to 100 characters on one line")
	}
	return nil
}

// parseCIDRs validates the allowed ranges of a token: 1 to
// store.MaxProvisioningTokenCIDRs distinct CIDR ranges, never a range of
// prefix length 0 (0.0.0.0/0, ::/0) nor an IPv4-mapped IPv6 range.
func parseCIDRs(raw []string) ([]netip.Prefix, error) {
	if len(raw) == 0 || len(raw) > store.MaxProvisioningTokenCIDRs {
		return nil, invalid(FieldAllowedCIDRs, "1 to 100 ranges are required")
	}
	out := make([]netip.Prefix, 0, len(raw))
	seen := map[netip.Prefix]bool{}
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, invalid(FieldAllowedCIDRs, "malformed range")
		}
		if p.Bits() == 0 || p.Addr().Is4In6() {
			return nil, invalid(FieldAllowedCIDRs, "a range may not cover every address")
		}
		p = p.Masked()
		if seen[p] {
			return nil, invalid(FieldAllowedCIDRs, "duplicate range")
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// normalizeSuffixes validates and normalizes the suffixes of a token.
func (s *Service) normalizeSuffixes(raw []string) ([]string, error) {
	if len(raw) == 0 || len(raw) > store.MaxProvisioningTokenSuffixes {
		return nil, invalid(FieldAllowedFQDNSuffixes, "1 to 100 suffixes are required")
	}
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, r := range raw {
		suffix, err := NormalizeSuffix(r, s.adminHosts)
		if err != nil {
			return nil, invalid(FieldAllowedFQDNSuffixes, err.Error())
		}
		if seen[suffix] {
			return nil, invalid(FieldAllowedFQDNSuffixes, "duplicate suffix")
		}
		seen[suffix] = true
		out = append(out, suffix)
	}
	return out, nil
}

// checkCreate validates in and returns the token to store, without its
// identity, secret and creator.
func (s *Service) checkCreate(in TokenCreate, now time.Time) (store.ProvisioningToken, error) {
	if err := checkName(in.Name); err != nil {
		return store.ProvisioningToken{}, err
	}
	cidrs, err := parseCIDRs(in.AllowedCIDRs)
	if err != nil {
		return store.ProvisioningToken{}, err
	}
	suffixes, err := s.normalizeSuffixes(in.AllowedFQDNSuffixes)
	if err != nil {
		return store.ProvisioningToken{}, err
	}
	t := store.ProvisioningToken{
		Name: in.Name, AllowedCIDRs: cidrs, AllowedFQDNSuffixes: suffixes, MaxStorageQuotaBytes: in.MaxStorageQuotaBytes,
		MaxTenants: in.MaxTenants,
	}
	if in.MaxStorageQuotaBytes <= 0 {
		return store.ProvisioningToken{}, invalid(FieldMaxStorageQuotaBytes, "must be positive")
	}
	if in.MaxTransferBytes != nil {
		if *in.MaxTransferBytes <= 0 || *in.MaxTransferBytes > tenant.MaxTransferLimit {
			return store.ProvisioningToken{}, invalid(FieldMaxTransferBytes, "must be between 1 byte and 20 GiB")
		}
		t.MaxTransferBytes = *in.MaxTransferBytes
	}
	if in.MaxTenants <= 0 || in.MaxTenants > MaxTenantsLimit {
		return store.ProvisioningToken{}, invalid(FieldMaxTenantsCap, "must be between 1 and 1000000")
	}
	if in.ExpiresAt != nil {
		if !in.ExpiresAt.After(now) {
			return store.ProvisioningToken{}, invalid(FieldExpiresAt, "must be in the future")
		}
		t.ExpiresAt = *in.ExpiresAt
	}
	return t, nil
}

// scopeDetails returns the audit details of the scope of t: the ranges and
// suffixes when they are short enough, their counts always.
func scopeDetails(t store.ProvisioningToken) map[string]any {
	cidrs := make([]string, len(t.AllowedCIDRs))
	for i, p := range t.AllowedCIDRs {
		cidrs[i] = p.String()
	}
	d := map[string]any{
		"name": audit.RedactAddresses(t.Name), "prefix": t.Prefix,
		"cidrCount": len(cidrs), "suffixCount": len(t.AllowedFQDNSuffixes),
		"maxStorageQuotaBytes": t.MaxStorageQuotaBytes, "maxTenants": t.MaxTenants,
	}
	lists, _ := json.Marshal([][]string{cidrs, t.AllowedFQDNSuffixes}) // []string always marshals
	if len(lists) <= maxScopeDetailBytes {
		d["allowedCidrs"], d["allowedFqdnSuffixes"] = cidrs, t.AllowedFQDNSuffixes
	}
	if t.MaxTransferBytes > 0 {
		d["maxTransferBytes"] = t.MaxTransferBytes
	}
	if !t.ExpiresAt.IsZero() {
		d["expiresAt"] = t.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return d
}

// CreateToken creates a provisioning token for the super admin of p, from
// clientIP, re-confirming with a TOTP code (code) or a recovery code
// (recoveryCode), exactly one of them, as a master key rotation does
// (P49, T-275). It returns the token with its secret, shown once.
//
// Checks, in this order, so that a refused request consumes no TOTP
// attempt: an authenticated super admin (ErrUnauthenticated,
// ErrForbidden); the body (*InvalidError: name, ranges never of prefix
// length 0, suffixes normalized and never covering an admin host, caps,
// expiry in the future); then the TOTP re-confirmation, whose adminauth
// errors pass through (adminauth.ErrInvalidCredentials for a wrong or
// replayed code, a *adminauth.RateLimitError, adminauth.ErrInvalid for a
// malformed or missing code...). The token and its
// provisioning_token.created audit event (never with the secret) are
// committed together; then the provisioning_token.created system event is
// published and the super admins notified (T-275), never with the secret.
func (s *Service) CreateToken(ctx context.Context, p adminauth.Principal, in TokenCreate, code, recoveryCode string,
	clientIP netip.Addr,
) (CreatedToken, error) {
	if err := superAdmin(p); err != nil {
		return CreatedToken{}, err
	}
	t, err := s.checkCreate(in, s.now())
	if err != nil {
		return CreatedToken{}, err
	}
	acc, err := s.confirm.ConfirmTOTP(ctx, p, code, recoveryCode, clientIP)
	if err != nil {
		return CreatedToken{}, err
	}
	if err := adminauth.RequireSuperAdmin(acc); err != nil {
		return CreatedToken{}, err
	}
	gen, err := Generate()
	if err != nil {
		return CreatedToken{}, fmt.Errorf("provisioning: generate token: %w", err)
	}
	t.ID, t.Prefix, t.TokenHash, t.CreatedBy = id.New(id.ProvisioningToken), gen.Prefix, gen.Hash, acc.ID
	t.CreatedAt = s.now()
	stored, err := s.repo.createToken(ctx, t, func(tx *store.SystemTx, stored store.ProvisioningToken) error {
		return s.repo.recordTx(ctx, tx, audit.Event{
			ActorKind: store.ActorAdmin, Actor: acc.Username, IP: clientIP, Action: ActionTokenCreated,
			ObjectKind: objectToken, ObjectID: stored.ID, Details: scopeDetails(stored),
		})
	})
	if err != nil {
		return CreatedToken{}, fmt.Errorf("provisioning: create token: %w", err)
	}
	s.logger.InfoContext(ctx, "provisioning token created", slog.String("token", stored.ID),
		slog.String("admin_id", acc.ID))
	s.tokenCreated(ctx, stored, acc.Username, clientIP)
	return CreatedToken{Token: tokenOf(stored), Secret: gen.Secret}, nil
}

// tokenCreated publishes the provisioning_token.created system event and
// notifies the super admins of the committed token t, created by the super
// admin username from clientIP (threat model T-275). Neither carries the
// secret nor its hash: only the identity, prefix and scope of the token.
func (s *Service) tokenCreated(ctx context.Context, t store.ProvisioningToken, username string, clientIP netip.Addr) {
	s.events.Publish(events.Event{
		Type: events.ProvisioningTokenCreated, Severity: events.SeverityInfo, OccurredAt: t.CreatedAt,
		Counts: map[string]float64{
			"cidrCount": float64(len(t.AllowedCIDRs)), "suffixCount": float64(len(t.AllowedFQDNSuffixes)),
			"maxTenants": float64(t.MaxTenants), "maxStorageQuotaBytes": float64(t.MaxStorageQuotaBytes),
		},
		AdminPath: events.AdminPathProvisioningTokens,
	})
	if s.notifier == nil {
		return
	}
	s.notifier.TokenCreated(context.WithoutCancel(ctx), tenantadmin.ProvisioningTokenNotice{
		TokenID: t.ID, TokenName: t.Name, TokenPrefix: t.Prefix, CreatedBy: username, ClientIP: clientIP, At: t.CreatedAt,
		CIDRCount: len(t.AllowedCIDRs), SuffixCount: len(t.AllowedFQDNSuffixes), MaxTenants: t.MaxTenants,
		MaxStorageQuotaBytes: t.MaxStorageQuotaBytes, ExpiresAt: t.ExpiresAt,
	})
}

// ListTokens returns every provisioning token, revoked and expired ones
// included, newest first, for the super admin of p.
func (s *Service) ListTokens(ctx context.Context, p adminauth.Principal) ([]Token, error) {
	if err := superAdmin(p); err != nil {
		return nil, err
	}
	list, err := s.repo.listTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("provisioning: list tokens: %w", err)
	}
	out := make([]Token, len(list))
	for i, t := range list {
		out[i] = tokenOf(t)
	}
	return out, nil
}

// RevokeToken revokes the token tokID at once, for the super admin of p,
// from clientIP; the tenants it created are not affected. Revoking a token
// already revoked changes nothing and succeeds. The revocation and its
// provisioning_token.revoked audit event are committed together. It
// returns ErrNotFound for an unknown or malformed identifier.
func (s *Service) RevokeToken(ctx context.Context, p adminauth.Principal, tokID string, clientIP netip.Addr) error {
	if err := superAdmin(p); err != nil {
		return err
	}
	if !id.Valid(id.ProvisioningToken, tokID) {
		return ErrNotFound
	}
	_, _, err := s.repo.revokeToken(ctx, tokID, s.now(), func(tx *store.SystemTx, t store.ProvisioningToken, revoked bool) error {
		if !revoked {
			return nil
		}
		return s.repo.recordTx(ctx, tx, audit.Event{
			ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: clientIP, Action: ActionTokenRevoked,
			ObjectKind: objectToken, ObjectID: t.ID,
			Details: map[string]any{"name": audit.RedactAddresses(t.Name), "prefix": t.Prefix},
		})
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("provisioning: revoke token: %w", err)
	}
	s.touches.Forget(tokID)
	return nil
}

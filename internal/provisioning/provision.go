package provisioning

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// TenantRequest is the input of [Service.ProvisionTenant] (OpenAPI
// ProvisionTenantRequest). It has no setup state, role or assignment: the
// tenant always starts in setup with a new delegated admin of its own.
type TenantRequest struct {
	Name              string
	FQDN              string
	DefaultLanguage   string
	StorageQuotaBytes int64
	// MaxTransferBytes is the transfer limit; nil means the cap of the
	// token, else [tenant.MaxTransferLimit].
	MaxTransferBytes *int64
	// BackgroundPreset is the optional background preset.
	BackgroundPreset *string
	// DelegatedAdmin is the first delegated admin; its link is always
	// mailed (Delivery empty or mail).
	DelegatedAdmin adminauth.DelegatedAdmin
}

// Tenant is a tenant as a provisioning token sees it (OpenAPI
// ProvisionedTenant).
type Tenant struct {
	ID         tenant.ID
	Name       string
	FQDN       string
	SetupState tenant.SetupState
	CreatedAt  time.Time
	// DelegatedAdminActivated reports whether its delegated admin has
	// activated the account (a boolean only, T-270).
	DelegatedAdminActivated bool
}

// tenantOf returns the view of t.
func tenantOf(t store.ProvisionedTenant) Tenant {
	return Tenant{
		ID: t.ID, Name: t.Name, FQDN: t.FQDN, SetupState: t.SetupState, CreatedAt: t.CreatedAt,
		DelegatedAdminActivated: t.DelegatedAdminActivated,
	}
}

// checkPrincipal refuses a principal without a token.
func checkPrincipal(p Principal) error {
	if p.TokenID == "" {
		return refuse(ReasonUnknown, "")
	}
	return nil
}

// scope checks in against the scope of p and returns the normalized FQDN
// and the transfer limit to create.
func scope(p Principal, in TenantRequest) (fqdn string, maxTransfer int64, err error) {
	fqdn, err = NormalizeFQDN(in.FQDN)
	if err != nil {
		return "", 0, invalid(FieldFQDN, "must be a host name without port")
	}
	if !MatchSuffix(fqdn, p.AllowedFQDNSuffixes) {
		return "", 0, &ScopeError{Field: FieldFQDN}
	}
	if in.StorageQuotaBytes > p.MaxStorageQuotaBytes {
		return "", 0, &ScopeError{Field: FieldStorageQuotaBytes}
	}
	switch {
	case in.MaxTransferBytes == nil && p.MaxTransferBytes > 0:
		maxTransfer = p.MaxTransferBytes
	case in.MaxTransferBytes == nil:
		maxTransfer = tenant.MaxTransferLimit
	case *in.MaxTransferBytes <= 0:
		// Never defaulted: an explicit value must be a limit.
		return "", 0, invalid(FieldMaxTransferBytes, "must be between 1 byte and 20 GiB")
	case p.MaxTransferBytes > 0 && *in.MaxTransferBytes > p.MaxTransferBytes:
		return "", 0, &ScopeError{Field: FieldMaxTransferBytes}
	default:
		// Above 20 GiB (without a cap) is refused by the tenant validation
		// (400).
		maxTransfer = *in.MaxTransferBytes
	}
	return fqdn, maxTransfer, nil
}

// ProvisionTenant creates, for the token of p, from clientIP, a tenant in
// the setup state with its first delegated admin, whose activation link is
// mailed through the system SMTP and never returned (T-272).
//
// The scope of the token is checked first: an FQDN that is not a host name
// is an *InvalidError on FieldFQDN; an FQDN outside the suffixes of the
// token (label boundary, T-276), a storage quota above its cap or a
// transfer limit above its cap is a *ScopeError naming the field. The
// transfer limit defaults to the cap of the token, else 20 GiB. The
// creation then checks again, under a lock in the same transaction, that
// the token is usable (else ErrInvalidToken), below its maximum number of
// live tenants (else a *ScopeError on FieldMaxTenants) and below
// store.ProvisioningCreationsPerHour creations in the last hour (else a
// *RateLimitError).
//
// The errors of the tenant creation pass through: a
// *tenantadmin.InvalidError (tenantadmin.ErrInvalid; its Code is
// tenantadmin.CodeAdminHost for an admin host), an *adminauth.InvalidError
// or *adminauth.NotAllowedError (adminauth.ErrInvalid) whose field is
// relative to "/delegatedAdmin", tenantadmin.ErrAlreadyExists for an FQDN or
// a username taken, tenantadmin.ErrUnknownBackgroundPreset and
// adminauth.ErrSystemSMTPUnavailable. Nothing is created on any error.
//
// Before anything else, every attempt of the token counts against
// AttemptsPerHour attempts per token within AttemptWindow, kept in memory
// (T-273): beyond it, the attempt is refused with a *RateLimitError, so
// that the 409 answers on an FQDN or a username taken cannot be probed
// without bound (T-270). The store-side limit above only counts the
// creations, and survives a restart.
//
// Once committed, it records tenant.provisioned (actor the token, real
// client IP), publishes the tenant.provisioned system event and notifies
// the super admins (P50); a failure of these is logged, never returned.
// A refused creation is recorded as tenant.provision_refused (global,
// actor the token, real client IP) with its reason code only (see
// refusalReason), never the request; a rate-limited attempt is recorded
// at most once per RefusalAuditInterval per token. An internal failure is
// not a refusal and is not recorded.
func (s *Service) ProvisionTenant(ctx context.Context, p Principal, in TenantRequest, clientIP netip.Addr) (Tenant, error) {
	if err := checkPrincipal(p); err != nil {
		return Tenant{}, err
	}
	var (
		t   Tenant
		err error
	)
	if ok, wait := s.attempts.Allow(p.TokenID); ok {
		t, err = s.provisionTenant(ctx, p, in, clientIP)
	} else {
		err = &RateLimitError{RetryAfter: wait}
	}
	if err != nil {
		s.refused(ctx, p, err, clientIP)
	}
	return t, err
}

// Reason codes of a tenant.provision_refused audit event.
const (
	RefusalAlreadyExists           = "already_exists"
	RefusalScopeExceeded           = "scope_exceeded"
	RefusalInvalid                 = "invalid"
	RefusalRateLimited             = "rate_limited"
	RefusalSystemSMTPUnavailable   = "system_smtp_unavailable"
	RefusalUnknownBackgroundPreset = "unknown_background_preset"
	RefusalTokenUnusable           = "token_unusable"
)

// refusalReason returns the reason code of a refused creation, "" for an
// internal failure (not a refusal).
func refusalReason(err error) string {
	switch {
	case errors.Is(err, ErrRateLimited):
		return RefusalRateLimited
	case errors.Is(err, ErrScopeExceeded):
		return RefusalScopeExceeded
	case errors.Is(err, ErrInvalidToken):
		return RefusalTokenUnusable
	case errors.Is(err, tenantadmin.ErrAlreadyExists):
		return RefusalAlreadyExists
	case errors.Is(err, tenantadmin.ErrUnknownBackgroundPreset):
		return RefusalUnknownBackgroundPreset
	case errors.Is(err, adminauth.ErrSystemSMTPUnavailable):
		return RefusalSystemSMTPUnavailable
	case errors.Is(err, ErrInvalid), errors.Is(err, tenantadmin.ErrInvalid), errors.Is(err, adminauth.ErrInvalid):
		return RefusalInvalid
	default:
		return ""
	}
}

// refused records the refusal err of a creation by the token of p, from
// clientIP.
func (s *Service) refused(ctx context.Context, p Principal, err error, clientIP netip.Addr) {
	var ae *AuthError
	if errors.As(err, &ae) {
		s.logger.InfoContext(ctx, "provisioning token refused at tenant creation", slog.String("token", p.TokenID),
			slog.String("reason", ae.Reason))
	}
	reason := refusalReason(err)
	if reason == "" || (reason == RefusalRateLimited && !s.refusalAudits.Due(p.TokenID, s.now())) {
		return
	}
	if err := s.repo.record(ctx, audit.Event{
		ActorKind: store.ActorProvisioningToken, Actor: p.TokenID, IP: clientIP, Action: ActionTenantProvisionRefused,
		ObjectKind: objectToken, ObjectID: p.TokenID, Details: map[string]any{"reason": reason},
	}); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(ActionTenantProvisionRefused)),
			slog.String("token", p.TokenID), slog.String("error", err.Error()))
	}
}

// provisionTenant is ProvisionTenant once the attempt is counted.
func (s *Service) provisionTenant(ctx context.Context, p Principal, in TenantRequest, clientIP netip.Addr) (Tenant, error) {
	fqdn, maxTransfer, err := scope(p, in)
	if err != nil {
		return Tenant{}, err
	}
	admin := in.DelegatedAdmin
	created, err := s.tenants.ProvisionTenant(ctx,
		adminauth.AuditActor{Kind: store.ActorProvisioningToken, ID: p.TokenID}, p.TokenID, tenantadmin.TenantCreate{
			Name: in.Name, FQDN: fqdn, DefaultLanguage: in.DefaultLanguage, StorageQuotaBytes: in.StorageQuotaBytes,
			MaxTransferBytes: maxTransfer, BackgroundPreset: in.BackgroundPreset, DelegatedAdmin: &admin,
			SetupState: tenant.SetupStateSetup,
		}, clientIP)
	var rl *store.ProvisioningRateLimitError
	switch {
	case errors.Is(err, store.ErrProvisioningTokenUnusable):
		// Revoked or expired since the authentication of the request.
		return Tenant{}, refuse(ReasonUnusable, p.TokenID)
	case errors.Is(err, store.ErrProvisioningMaxTenants):
		return Tenant{}, &ScopeError{Field: FieldMaxTenants}
	case errors.As(err, &rl):
		return Tenant{}, &RateLimitError{RetryAfter: rl.RetryAfter}
	case err != nil:
		return Tenant{}, err
	}
	s.provisioned(ctx, p, created, clientIP)
	return Tenant{
		ID: created.ID, Name: created.Name, FQDN: created.FQDN, SetupState: created.SetupState, CreatedAt: created.CreatedAt,
	}, nil
}

// provisioned records, publishes and notifies the creation of t by the
// token of p.
func (s *Service) provisioned(ctx context.Context, p Principal, t tenantadmin.TenantCreated, clientIP netip.Addr) {
	var username string
	if t.DelegatedAdmin != nil {
		username = t.DelegatedAdmin.Account.Username
	}
	err := s.repo.record(ctx, audit.Event{
		TenantID: t.ID, ActorKind: store.ActorProvisioningToken, Actor: p.TokenID, IP: clientIP,
		Action: ActionTenantProvisioned, ObjectKind: objectTenant, ObjectID: string(t.ID),
		Details: map[string]any{
			"name": audit.RedactAddresses(t.Name), "fqdn": t.FQDN, "provisionerName": audit.RedactAddresses(p.Name),
			"provisionerPrefix": p.Prefix, "delegatedAdmin": username,
		},
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(ActionTenantProvisioned)),
			slog.String("tenant", string(t.ID)), slog.String("error", err.Error()))
	}
	now := s.now()
	s.events.Publish(events.Event{
		Type: events.TenantProvisioned, Severity: events.SeverityInfo, OccurredAt: now,
		TenantID: string(t.ID), AdminPath: tenantadmin.AdminPathTenant(t.ID),
	})
	if s.notifier == nil {
		return
	}
	s.notifier.TenantProvisioned(context.WithoutCancel(ctx), tenantadmin.ProvisioningNotice{
		TenantID: t.ID, TenantName: t.Name, FQDN: t.FQDN, TokenID: p.TokenID, TokenName: p.Name, TokenPrefix: p.Prefix,
		AdminUsername: username, ClientIP: clientIP, At: now,
	})
}

// ListTenants returns the live tenants created with the token of p, and
// only them, newest first; tenants being deleted are left out.
func (s *Service) ListTenants(ctx context.Context, p Principal) ([]Tenant, error) {
	if err := checkPrincipal(p); err != nil {
		return nil, err
	}
	list, err := s.repo.listTenants(ctx, p.TokenID)
	if err != nil {
		return nil, fmt.Errorf("provisioning: list tenants: %w", err)
	}
	out := make([]Tenant, len(list))
	for i, t := range list {
		out[i] = tenantOf(t)
	}
	return out, nil
}

// GetTenant returns tenant tid if the token of p created it. A tenant of
// another token or of a super admin, unknown, malformed or being deleted
// answers ErrNotFound alike (T-270).
func (s *Service) GetTenant(ctx context.Context, p Principal, tid tenant.ID) (Tenant, error) {
	if err := checkPrincipal(p); err != nil {
		return Tenant{}, err
	}
	if tid.Validate() != nil {
		return Tenant{}, ErrNotFound
	}
	t, err := s.repo.getTenant(ctx, p.TokenID, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Tenant{}, ErrNotFound
	case err != nil:
		return Tenant{}, fmt.Errorf("provisioning: get tenant: %w", err)
	}
	return tenantOf(t), nil
}

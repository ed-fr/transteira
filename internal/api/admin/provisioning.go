package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/provisioning"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// Provisioning operations (since API 1.2, decisions P48 to P50, threats
// T-267 to T-276): the provisioning tokens, managed by the super admin on
// the admin session, and the provisioning API itself, served on the admin
// host to the holders of a provisioning token. The token is checked by the
// provisioning middleware of internal/httpserver, which puts its
// provisioning.Principal in the request context; no session cookie nor
// CSRF token is ever read for these operations.

// ProvisioningService manages the provisioning tokens and serves the
// provisioning API (*provisioning.Service). Every method checks its
// principal itself.
type ProvisioningService interface {
	CreateToken(ctx context.Context, p adminauth.Principal, in provisioning.TokenCreate, code, recoveryCode string,
		clientIP netip.Addr) (provisioning.CreatedToken, error)
	ListTokens(ctx context.Context, p adminauth.Principal) ([]provisioning.Token, error)
	RevokeToken(ctx context.Context, p adminauth.Principal, tokID string, clientIP netip.Addr) error
	ProvisionTenant(ctx context.Context, p provisioning.Principal, in provisioning.TenantRequest, clientIP netip.Addr) (provisioning.Tenant, error)
	ListTenants(ctx context.Context, p provisioning.Principal) ([]provisioning.Tenant, error)
	GetTenant(ctx context.Context, p provisioning.Principal, tid tenant.ID) (provisioning.Tenant, error)
}

// Compile-time check that the provisioning service fits.
var _ ProvisioningService = (*provisioning.Service)(nil)

// WithProvisioningService serves the provisioning operations with svc.
// Without it they answer 500.
func WithProvisioningService(svc ProvisioningService) Option {
	return func(s *Server) { s.provisioning = svc }
}

// errNoProvisioningService reports a server built without
// WithProvisioningService: a wiring error, answered 500.
var errNoProvisioningService = errors.New("admin: no provisioning service configured")

// errNoProvisioningBody reports a provisioning creation whose raw body is
// not in the context (CaptureRawBody not installed): a wiring error,
// answered 500.
var errNoProvisioningBody = errors.New("admin: raw body of a provisioning creation missing (CaptureRawBody not installed)")

// provisioningError maps an error of the provisioning service to the error
// the strict handler renders. Server errors keep their cause, which is
// logged (the service never puts a secret in it).
func provisioningError(err error) error {
	var (
		invalid *provisioning.InvalidError
		scope   *provisioning.ScopeError
		limited *provisioning.RateLimitError
	)
	switch {
	case errors.As(err, &invalid):
		return validationFailed(invalid.Field, fieldInvalidFormat)
	case errors.As(err, &scope):
		return problem.New(problem.CodeProvisioningScopeExceeded,
			problem.WithFieldErrors(problem.FieldError{Field: scope.Field, Code: fieldNotAllowed}))
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.Is(err, provisioning.ErrInvalidToken):
		return problem.New(problem.CodeProvisioningTokenInvalid)
	case errors.Is(err, provisioning.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	default:
		return serviceError(err)
	}
}

// provisionTenantError maps an error of a tenant creation by a
// provisioning token: the errors of the delegated admin name their field
// under /delegatedAdmin, those of the tenant are mapped as for createTenant,
// and the others as by provisioningError.
func provisionTenantError(err error) error {
	var (
		invalid    *adminauth.InvalidError
		notAllowed *adminauth.NotAllowedError
	)
	switch {
	case errors.As(err, &invalid):
		return validationFailed(delegatedAdminField+invalid.Field, formatCode(invalid.Field == adminauth.FieldEmail))
	case errors.As(err, &notAllowed):
		return validationFailed(delegatedAdminField+notAllowed.Field, fieldNotAllowed)
	case errors.Is(err, tenantadmin.ErrInvalid), errors.Is(err, tenantadmin.ErrAlreadyExists),
		errors.Is(err, tenantadmin.ErrUnknownBackgroundPreset):
		return tenantError(err)
	default:
		return provisioningError(err)
	}
}

// provisioningSession returns the provisioning service and the admin
// session of the request, or the error to answer.
func (s *Server) provisioningSession(ctx context.Context) (ProvisioningService, adminauth.Principal, error) {
	if s.provisioning == nil {
		return nil, adminauth.Principal{}, errNoProvisioningService
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.provisioning, p, nil
}

// provisioningToken returns the provisioning service and the provisioning
// token of the request, or the error to answer. A request without one
// never reaches the handler (the provisioning middleware refuses it); its
// absence is refused as an invalid token.
func (s *Server) provisioningToken(ctx context.Context) (ProvisioningService, provisioning.Principal, error) {
	if s.provisioning == nil {
		return nil, provisioning.Principal{}, errNoProvisioningService
	}
	p, ok := provisioning.FromContext(ctx)
	if !ok {
		return nil, provisioning.Principal{}, problem.New(problem.CodeProvisioningTokenInvalid)
	}
	return s.provisioning, p, nil
}

// rawBody returns the raw body kept by CaptureRawBody.
func rawBody(ctx context.Context) ([]byte, error) {
	raw, ok := ctx.Value(rawBodyKey{}).([]byte)
	if !ok {
		return nil, errNoProvisioningBody
	}
	return raw, nil
}

// --- Provisioning tokens (super admin) -----------------------------------------

// ListProvisioningTokens lists the provisioning tokens, revoked ones
// included, never their secrets (super admin).
func (s *Server) ListProvisioningTokens(ctx context.Context, _ gen.ListProvisioningTokensRequestObject) (gen.ListProvisioningTokensResponseObject, error) {
	svc, p, err := s.provisioningSession(ctx)
	if err != nil {
		return nil, err
	}
	list, err := svc.ListTokens(ctx, p)
	if err != nil {
		return nil, provisioningError(err)
	}
	resp := make(gen.ListProvisioningTokens200JSONResponse, len(list))
	for i, t := range list {
		resp[i] = provisioningTokenBody(t)
	}
	return resp, nil
}

// CreateProvisioningToken creates a provisioning token (201), re-confirmed
// by a TOTP or recovery code of the super admin. The secret is in this
// answer only; the admin router marks every answer Cache-Control: no-store.
//
// The body is decoded strictly (OpenAPI ProvisioningTokenCreate,
// additionalProperties false): an unknown member, or a null code, answers
// 400 validation-failed, but only after the role check, so that it reveals
// nothing to another administrator; the service then checks the role and
// the body before the code, so that no refused request consumes a TOTP
// attempt. The codes are never logged: the service errors do not carry
// them.
func (s *Server) CreateProvisioningToken(ctx context.Context, req gen.CreateProvisioningTokenRequestObject) (gen.CreateProvisioningTokenResponseObject, error) {
	svc, p, err := s.provisioningSession(ctx)
	if err != nil {
		return nil, err
	}
	var (
		in             provisioning.TokenCreate
		code, recovery string
	)
	if b := req.Body; b != nil {
		raw, err := rawBody(ctx)
		if err != nil {
			return nil, err
		}
		if invalid := checkTokenCreateMembers(raw); invalid != nil {
			if err := requireSuperAdmin(p); err != nil {
				return nil, serviceError(err)
			}
			return nil, invalid
		}
		in = provisioning.TokenCreate{
			Name: b.Name, AllowedCIDRs: b.AllowedCidrs, AllowedFQDNSuffixes: b.AllowedFqdnSuffixes,
			MaxStorageQuotaBytes: b.MaxStorageQuotaBytes, MaxTransferBytes: b.MaxTransferBytes, MaxTenants: b.MaxTenants,
			ExpiresAt: b.ExpiresAt,
		}
		code, recovery = deref(b.Code), deref(b.RecoveryCode)
	}
	c, err := svc.CreateToken(ctx, p, in, code, recovery, middleware.ClientIP(ctx))
	if err != nil {
		return nil, provisioningError(err)
	}
	t := provisioningTokenBody(c.Token)
	return gen.CreateProvisioningToken201JSONResponse{
		Id: t.Id, Name: t.Name, Prefix: t.Prefix, AllowedCidrs: t.AllowedCidrs, AllowedFqdnSuffixes: t.AllowedFqdnSuffixes,
		MaxStorageQuotaBytes: t.MaxStorageQuotaBytes, MaxTransferBytes: t.MaxTransferBytes, MaxTenants: t.MaxTenants,
		TenantsCreated: t.TenantsCreated, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt,
		ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, Token: c.Secret,
	}, nil
}

// requireSuperAdmin checks that p is an authenticated session of a super
// admin, as the service does first.
func requireSuperAdmin(p adminauth.Principal) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	return adminauth.RequireSuperAdmin(p.Admin)
}

// RevokeProvisioningToken revokes a provisioning token (204, also when it
// was already revoked; super admin).
func (s *Server) RevokeProvisioningToken(ctx context.Context, req gen.RevokeProvisioningTokenRequestObject) (gen.RevokeProvisioningTokenResponseObject, error) {
	svc, p, err := s.provisioningSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RevokeToken(ctx, p, req.TokenId, middleware.ClientIP(ctx)); err != nil {
		return nil, provisioningError(err)
	}
	return gen.RevokeProvisioningToken204Response{}, nil
}

// provisioningTokenBody renders t as the OpenAPI ProvisioningToken: the
// ranges in CIDR notation, the optional cap and the dates never set absent.
func provisioningTokenBody(t provisioning.Token) gen.ProvisioningToken {
	cidrs := make([]string, len(t.AllowedCIDRs))
	for i, c := range t.AllowedCIDRs {
		cidrs[i] = c.String()
	}
	suffixes := t.AllowedFQDNSuffixes
	if suffixes == nil {
		suffixes = []string{}
	}
	var maxTransfer *int64
	if t.MaxTransferBytes > 0 {
		v := t.MaxTransferBytes
		maxTransfer = &v
	}
	return gen.ProvisioningToken{
		Id: t.ID, Name: t.Name, Prefix: t.Prefix, AllowedCidrs: cidrs, AllowedFqdnSuffixes: suffixes,
		MaxStorageQuotaBytes: t.MaxStorageQuotaBytes, MaxTransferBytes: maxTransfer, MaxTenants: t.MaxTenants,
		TenantsCreated: t.TenantsCreated, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt,
		LastUsedAt: optionalTime(t.LastUsedAt), ExpiresAt: optionalTime(t.ExpiresAt), RevokedAt: optionalTime(t.RevokedAt),
	}
}

// --- Provisioning API (provisioning token) ---------------------------------------

// ListProvisionedTenants lists the tenants created with the provisioning
// token of the request, and only them.
func (s *Server) ListProvisionedTenants(ctx context.Context, _ gen.ListProvisionedTenantsRequestObject) (gen.ListProvisionedTenantsResponseObject, error) {
	svc, p, err := s.provisioningToken(ctx)
	if err != nil {
		return nil, err
	}
	list, err := svc.ListTenants(ctx, p)
	if err != nil {
		return nil, provisioningError(err)
	}
	items := make([]gen.ProvisionedTenant, len(list))
	for i, t := range list {
		items[i] = provisionedTenantBody(t)
	}
	return gen.ListProvisionedTenants200JSONResponse{Items: items}, nil
}

// ProvisionTenant creates, for the provisioning token of the request, a
// tenant in the setup state with its first delegated admin (201). The
// activation link is mailed, never returned.
//
// The body is decoded strictly (OpenAPI ProvisionTenantRequest and
// NewDelegatedAdmin, additionalProperties false): an unknown member (a
// setupState, a role, an assignment...) answers 400 validation-failed
// naming it, a missing or null delegatedAdmin 400 required, and a null
// optional member 400 invalid-format, before the service is called.
func (s *Server) ProvisionTenant(ctx context.Context, req gen.ProvisionTenantRequestObject) (gen.ProvisionTenantResponseObject, error) {
	svc, p, err := s.provisioningToken(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed("", fieldRequired)
	}
	raw, err := rawBody(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkProvisionTenantMembers(raw); err != nil {
		return nil, err
	}
	b := req.Body
	d := b.DelegatedAdmin
	in := provisioning.TenantRequest{
		Name: b.Name, FQDN: b.Fqdn, DefaultLanguage: string(b.DefaultLanguage), StorageQuotaBytes: b.StorageQuotaBytes,
		MaxTransferBytes: b.MaxTransferBytes, BackgroundPreset: b.BackgroundPreset,
		DelegatedAdmin: adminauth.DelegatedAdmin{Username: d.Username, Email: string(d.Email), Language: string(d.Language)},
	}
	if d.Delivery != nil {
		in.DelegatedAdmin.Delivery = store.ActivationDelivery(*d.Delivery)
	}
	t, err := svc.ProvisionTenant(ctx, p, in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, provisionTenantError(err)
	}
	return gen.ProvisionTenant201JSONResponse(provisionedTenantBody(t)), nil
}

// GetProvisionedTenant returns a tenant created with the provisioning
// token of the request; any other tenant answers 404, like an unknown one.
func (s *Server) GetProvisionedTenant(ctx context.Context, req gen.GetProvisionedTenantRequestObject) (gen.GetProvisionedTenantResponseObject, error) {
	svc, p, err := s.provisioningToken(ctx)
	if err != nil {
		return nil, err
	}
	t, err := svc.GetTenant(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, provisioningError(err)
	}
	return gen.GetProvisionedTenant200JSONResponse(provisionedTenantBody(t)), nil
}

// provisionedTenantBody renders t as the OpenAPI ProvisionedTenant.
func provisionedTenantBody(t provisioning.Tenant) gen.ProvisionedTenant {
	return gen.ProvisionedTenant{
		Id: string(t.ID), Name: t.Name, Fqdn: t.FQDN, SetupState: gen.TenantSetupState(t.SetupState),
		CreatedAt: t.CreatedAt, DelegatedAdminActivated: t.DelegatedAdminActivated,
	}
}

// --- Strict decoding ------------------------------------------------------------

// Members of the OpenAPI ProvisioningTokenCreate, ProvisionTenantRequest
// and NewDelegatedAdmin.
var (
	tokenCreateFields = []string{
		"name", "allowedCidrs", "allowedFqdnSuffixes", "maxStorageQuotaBytes", "maxTransferBytes", "maxTenants",
		"expiresAt", memberCode, memberRecoveryCode,
	}
	// tokenCreateNotNull are the optional members that cannot be null.
	tokenCreateNotNull = []string{memberCode, memberRecoveryCode}

	provisionTenantFields = []string{
		"name", "fqdn", "defaultLanguage", "storageQuotaBytes", "maxTransferBytes", "backgroundPreset", memberDelegatedAdmin,
	}
	provisionTenantNotNull = []string{"maxTransferBytes", "backgroundPreset"}

	delegatedAdminFields  = []string{"username", "email", "language", "delivery"}
	delegatedAdminNotNull = []string{"delivery"}
)

// memberDelegatedAdmin is the delegated admin member of a
// ProvisionTenantRequest.
const memberDelegatedAdmin = "delegatedAdmin"

// objectMembers decodes raw as a JSON object; anything else answers
// invalid-format on pointer.
func objectMembers(raw []byte, pointer string) (map[string]json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, validationFailed(pointer, fieldInvalidFormat)
	}
	return members, nil
}

// rejectNulls answers invalid-format on the first of names (in order)
// whose member is null, under prefix.
func rejectNulls(members map[string]json.RawMessage, prefix string, names []string) error {
	for _, name := range names {
		if isNull(members, name) {
			return validationFailed(prefix+"/"+name, fieldInvalidFormat)
		}
	}
	return nil
}

// checkTokenCreateMembers refuses a ProvisioningTokenCreate body that is
// not an object, that has an unknown member, or a null code.
func checkTokenCreateMembers(raw []byte) error {
	members, err := objectMembers(raw, "")
	if err != nil {
		return err
	}
	if err := rejectUnknownMembers(members, tokenCreateFields); err != nil {
		return err
	}
	return rejectNulls(members, "", tokenCreateNotNull)
}

// checkProvisionTenantMembers refuses a ProvisionTenantRequest body that is
// not an object, that has an unknown member (at the top or in its
// delegatedAdmin, the pointer then under /delegatedAdmin), a null optional
// member, or no delegatedAdmin object.
func checkProvisionTenantMembers(raw []byte) error {
	members, err := objectMembers(raw, "")
	if err != nil {
		return err
	}
	if err := rejectUnknownMembers(members, provisionTenantFields); err != nil {
		return err
	}
	if err := rejectNulls(members, "", provisionTenantNotNull); err != nil {
		return err
	}
	d, ok := members[memberDelegatedAdmin]
	if !ok || isNull(members, memberDelegatedAdmin) {
		return validationFailed(delegatedAdminField, fieldRequired)
	}
	admin, err := objectMembers(d, delegatedAdminField)
	if err != nil {
		return err
	}
	if err := rejectUnknownMembersAt(delegatedAdminField, admin, delegatedAdminFields); err != nil {
		return err
	}
	return rejectNulls(admin, delegatedAdminField, delegatedAdminNotNull)
}

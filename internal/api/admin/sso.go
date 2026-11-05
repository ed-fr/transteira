package admin

import (
	"context"
	"errors"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// Defaults of the optional members of TenantSsoUpdate.
const (
	defaultSSOEnforced   = false
	defaultSSORequireMFA = true
)

// ssoError maps an error of the single sign-on configuration to the error
// the strict handler renders: the SSO problems first, then the usual
// tenant configuration mapping (tenantError).
func ssoError(err error) error {
	switch {
	case errors.Is(err, tenantadmin.ErrSSOIssuerNotAllowed):
		return problem.New(problem.CodeSSOIssuerNotAllowed, problem.WithFieldErrors(
			problem.FieldError{Field: tenantadmin.FieldSSOIssuer, Code: fieldNotAllowed}))
	case errors.Is(err, tenantadmin.ErrSSODomainConflict):
		return problem.New(problem.CodeSSODomainConflict)
	case errors.Is(err, tenantadmin.ErrSSONothingToTest):
		return problem.New(problem.CodeStateConflict)
	default:
		return tenantError(err)
	}
}

// ssoBody renders v as the OpenAPI TenantSso: the client secret is never
// part of it, only whether one is stored.
func ssoBody(v tenantadmin.SSOView) gen.TenantSso {
	return gen.TenantSso{
		Enabled: v.Enabled, Issuer: v.Issuer, ClientId: v.ClientID, HasClientSecret: v.HasClientSecret,
		EmailDomains: append([]string{}, v.EmailDomains...), Enforced: v.Enforced, RequireMfa: v.RequireMFA,
		CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
	}
}

// GetTenantSso returns the single sign-on configuration of a tenant (super
// admin, delegated admins and auditors of the tenant).
func (s *Server) GetTenantSso(ctx context.Context, req gen.GetTenantSsoRequestObject) (gen.GetTenantSsoResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	v, err := svc.GetSSO(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, ssoError(err)
	}
	return gen.GetTenantSso200JSONResponse(ssoBody(v)), nil
}

// PutTenantSso creates or replaces the single sign-on configuration of a
// tenant (super admin only). The absent optional members take their API
// defaults here: enforced false, requireMfa true.
func (s *Server) PutTenantSso(ctx context.Context, req gen.PutTenantSsoRequestObject) (gen.PutTenantSsoResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(tenantadmin.FieldSSOIssuer, fieldRequired)
	}
	b := req.Body
	in := tenantadmin.SSOUpdate{
		Enabled: b.Enabled, Issuer: b.Issuer, ClientID: b.ClientId, ClientSecret: b.ClientSecret,
		EmailDomains: b.EmailDomains, Enforced: defaultSSOEnforced, RequireMFA: defaultSSORequireMFA,
	}
	if b.Enforced != nil {
		in.Enforced = *b.Enforced
	}
	if b.RequireMfa != nil {
		in.RequireMFA = *b.RequireMfa
	}
	v, err := svc.PutSSO(ctx, p, tenant.ID(req.TenantId), in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, ssoError(err)
	}
	return gen.PutTenantSso200JSONResponse(ssoBody(v)), nil
}

// DeleteTenantSso removes the single sign-on configuration of a tenant
// (super admin only, 204).
func (s *Server) DeleteTenantSso(ctx context.Context, req gen.DeleteTenantSsoRequestObject) (gen.DeleteTenantSsoResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.DeleteSSO(ctx, p, tenant.ID(req.TenantId), middleware.ClientIP(ctx)); err != nil {
		return nil, ssoError(err)
	}
	return gen.DeleteTenantSso204Response{}, nil
}

// TestTenantSso runs the discovery test of the stored issuer of a tenant
// (super admin only) and reports how it went (200, even when the
// discovery failed); 409 state-conflict without configuration.
func (s *Server) TestTenantSso(ctx context.Context, req gen.TestTenantSsoRequestObject) (gen.TestTenantSsoResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	res, err := svc.TestSSO(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, ssoError(err)
	}
	resp := gen.TestTenantSso200JSONResponse{
		Success: res.Success, DurationMs: int(res.Duration.Milliseconds()), Stage: gen.SsoTestResultStage(res.Stage),
	}
	if res.Error != "" {
		e := gen.SsoTestResultError(res.Error)
		resp.Error = &e
	}
	return resp, nil
}

package admin

import (
	"context"
	"errors"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/secret"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// ExpressSecretService serves the administration of the express secrets
// (since 2.3, threat model T-408): the lookup of a secret of a tenant from
// its link and the purge of its live anonymous express secrets
// (*secret.Service). It audits both; the handlers check first that the
// administrator may act on the tenant.
type ExpressSecretService interface {
	Lookup(ctx context.Context, t *tenant.Tenant, actor secret.AdminActor, link string) (store.Secret, error)
	PurgeExpress(ctx context.Context, t *tenant.Tenant, actor secret.AdminActor) (int, error)
}

// Compile-time check that the secret service fits.
var _ ExpressSecretService = (*secret.Service)(nil)

// WithExpressSecretService serves lookupTenantSecret and
// purgeExpressSecrets with svc; the tenant is read with the registry of
// WithTenants. Without it they answer 500.
func WithExpressSecretService(svc ExpressSecretService) Option {
	return func(s *Server) { s.expressSvc = svc }
}

// errNoExpressSecretService reports a server built without
// WithExpressSecretService: a wiring error, answered 500.
var errNoExpressSecretService = errors.New("admin: no express secret service configured")

// LookupTenantSecret finds the secret of a tenant a pasted link (or its
// bare token) leads to, in any state, and returns its metadata (since 2.3).
// The delegated admins of the tenant, the super admin and its auditors may
// call it, a read despite the POST (the link never appears in a URL). The
// link, its token and its key are never logged nor audited.
func (s *Server) LookupTenantSecret(ctx context.Context, req gen.LookupTenantSecretRequestObject) (gen.LookupTenantSecretResponseObject, error) {
	p, t, err := s.expressTenant(ctx, tenant.ID(req.TenantId), adminauth.RequireTenantAuditRead)
	if err != nil {
		return nil, err
	}
	link := ""
	if req.Body != nil {
		link = req.Body.Link
	}
	sec, err := s.expressSvc.Lookup(ctx, t, expressActor(ctx, p), link)
	if err != nil {
		return nil, expressAdminError(err)
	}
	return gen.LookupTenantSecret200JSONResponse(adminSecretBody(sec)), nil
}

// PurgeExpressSecrets deletes every live anonymous express secret of a
// tenant at once (since 2.3) and answers how many. It changes the tenant:
// the delegated admins of the tenant and the super admin may call it, an
// auditor may not.
func (s *Server) PurgeExpressSecrets(ctx context.Context, req gen.PurgeExpressSecretsRequestObject) (gen.PurgeExpressSecretsResponseObject, error) {
	p, t, err := s.expressTenant(ctx, tenant.ID(req.TenantId), adminauth.RequireTenantWrite)
	if err != nil {
		return nil, err
	}
	n, err := s.expressSvc.PurgeExpress(ctx, t, expressActor(ctx, p))
	if err != nil {
		return nil, err
	}
	return gen.PurgeExpressSecrets200JSONResponse{Deleted: n}, nil
}

// expressTenant returns the session of the request and the active tenant
// tid once the session may act on it (require: RequireTenantAuditRead for
// a read, RequireTenantWrite for a change), or the error to answer: a
// tenant the administrator is not attached to, a missing one and one being
// deleted are all 404 not-found.
func (s *Server) expressTenant(ctx context.Context, tid tenant.ID, require func(adminauth.Account, tenant.ID) error,
) (adminauth.Principal, *tenant.Tenant, error) {
	if s.expressSvc == nil {
		return adminauth.Principal{}, nil, errNoExpressSecretService
	}
	if s.tenants == nil {
		return adminauth.Principal{}, nil, errNoTenants
	}
	p, err := principal(ctx)
	if err != nil {
		return adminauth.Principal{}, nil, err
	}
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return adminauth.Principal{}, nil, operationError(err)
	}
	if err := require(p.Admin, tid); err != nil {
		return adminauth.Principal{}, nil, operationError(err)
	}
	t, err := s.tenants.Get(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return adminauth.Principal{}, nil, problem.New(problem.CodeNotFound)
	case err != nil:
		return adminauth.Principal{}, nil, err
	case t.Status != tenant.StatusActive:
		return adminauth.Principal{}, nil, problem.New(problem.CodeNotFound)
	}
	return p, t, nil
}

// expressActor returns the administrator of the request for the audit.
func expressActor(ctx context.Context, p adminauth.Principal) secret.AdminActor {
	return secret.AdminActor{Username: p.Admin.Username, IP: middleware.ClientIP(ctx)}
}

// expressAdminError maps an error of the lookup: a link without token is
// 400 validation-failed naming /link, an unknown token 404 not-found.
func expressAdminError(err error) error {
	var invalid *secret.ValidationError
	switch {
	case errors.As(err, &invalid):
		fields := make([]problem.FieldError, len(invalid.Fields))
		for i, f := range invalid.Fields {
			fields[i] = problem.FieldError{Field: f.Pointer, Code: f.Code}
		}
		return problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(fields...))
	case errors.Is(err, secret.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	default:
		return err
	}
}

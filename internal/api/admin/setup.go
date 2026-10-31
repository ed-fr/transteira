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

// fieldNotDone is the field error code of a required setup item not done
// (409 setup-incomplete, OpenAPI completeTenantSetup).
const fieldNotDone = "not-done"

// setupError maps an error of the setup operations: the required items not
// done are listed as field errors of setup-incomplete (field: the key of the
// item, code: not-done); the others are those of tenantError.
func setupError(err error) error {
	var incomplete *tenantadmin.IncompleteError
	switch {
	case errors.As(err, &incomplete):
		fields := make([]problem.FieldError, len(incomplete.Missing))
		for i, key := range incomplete.Missing {
			fields[i] = problem.FieldError{Field: key, Code: fieldNotDone}
		}
		return problem.New(problem.CodeSetupIncomplete, problem.WithFieldErrors(fields...))
	case errors.Is(err, tenantadmin.ErrSetupIncomplete):
		return problem.New(problem.CodeSetupIncomplete)
	case errors.Is(err, tenantadmin.ErrSetupComplete):
		return problem.New(problem.CodeSetupAlreadyComplete)
	}
	return tenantError(err)
}

// setupBody renders s as the OpenAPI TenantSetup.
func setupBody(s tenantadmin.Setup) gen.TenantSetup {
	out := gen.TenantSetup{
		SetupState: gen.TenantSetupState(s.State), CanComplete: s.CanComplete,
		Items: make([]gen.TenantSetupItem, len(s.Items)),
	}
	for i, it := range s.Items {
		out.Items[i] = gen.TenantSetupItem{Key: gen.TenantSetupItemKey(it.Key), Required: it.Required, Done: it.Done}
	}
	return out
}

// GetTenantSetup returns the setup state and checklist of a tenant,
// computed by the service from its real configuration.
func (s *Server) GetTenantSetup(ctx context.Context, req gen.GetTenantSetupRequestObject) (gen.GetTenantSetupResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	st, err := svc.GetSetup(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, setupError(err)
	}
	return gen.GetTenantSetup200JSONResponse(setupBody(st)), nil
}

// CompleteTenantSetup moves a tenant from setup to active: 409
// setup-incomplete with the items not done, 409 setup-already-complete for
// an active tenant, 403 when a delegated admin forces it. The body is
// required (an empty object completes without force).
func (s *Server) CompleteTenantSetup(ctx context.Context, req gen.CompleteTenantSetupRequestObject) (gen.CompleteTenantSetupResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed("", fieldRequired)
	}
	st, err := svc.CompleteSetup(ctx, p, tenant.ID(req.TenantId), deref(req.Body.Force), deref(req.Body.MailTemplatesReviewed),
		middleware.ClientIP(ctx))
	if err != nil {
		return nil, setupError(err)
	}
	return gen.CompleteTenantSetup200JSONResponse(setupBody(st)), nil
}

// GetTextProposal returns a proposal of a legal text of a tenant, filled
// with its real configuration; nothing is saved.
func (s *Server) GetTextProposal(ctx context.Context, req gen.GetTextProposalRequestObject) (gen.GetTextProposalResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	tp, err := svc.TextProposal(ctx, p, tenant.ID(req.TenantId), string(req.Document), string(req.Language))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetTextProposal200JSONResponse{
		Document: gen.TextProposalDocument(tp.Document), Language: gen.Language(tp.Language),
		Markdown: tp.Markdown, Notice: tp.Notice,
	}, nil
}

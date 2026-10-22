package admin

import (
	"context"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// ListAdmins returns a page of administrator accounts (super admin).
func (s *Server) ListAdmins(ctx context.Context, req gen.ListAdminsRequestObject) (gen.ListAdminsResponseObject, error) {
	svc, p, err := s.authenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := svc.List(ctx, p, deref(req.Params.Cursor), deref(req.Params.Limit))
	if err != nil {
		return nil, serviceError(err)
	}
	resp := gen.ListAdmins200JSONResponse{Items: make([]gen.Admin, len(page.Items))}
	for i, a := range page.Items {
		resp.Items[i] = adminBody(a)
	}
	if page.NextCursor != "" {
		next := page.NextCursor
		resp.NextCursor = &next
	}
	return resp, nil
}

// CreateAdmin creates a delegated admin and returns it with its activation
// link, shown once and never mailed (super admin, 201).
func (s *Server) CreateAdmin(ctx context.Context, req gen.CreateAdminRequestObject) (gen.CreateAdminResponseObject, error) {
	svc, p, err := s.authenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(adminauth.FieldUsername, fieldRequired)
	}
	a, link, err := svc.Create(ctx, p, adminauth.AdminCreate{
		Username: req.Body.Username, Email: string(req.Body.Email), Role: store.AdminRole(req.Body.Role),
		TenantIDs: tenantIDs(deref(req.Body.TenantIds)), RequireTOTP: req.Body.RequireTotp,
	}, middleware.ClientIP(ctx))
	if err != nil {
		return nil, serviceError(err)
	}
	return gen.CreateAdmin201JSONResponse(withActivation(a, link)), nil
}

// GetAdmin returns one administrator account (super admin).
func (s *Server) GetAdmin(ctx context.Context, req gen.GetAdminRequestObject) (gen.GetAdminResponseObject, error) {
	svc, p, err := s.authenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	a, err := svc.Get(ctx, p, req.AdminId)
	if err != nil {
		return nil, serviceError(err)
	}
	return gen.GetAdmin200JSONResponse(adminBody(a)), nil
}

// UpdateAdmin applies a JSON merge patch to an administrator account
// (super admin): absent fields are left unchanged.
func (s *Server) UpdateAdmin(ctx context.Context, req gen.UpdateAdminRequestObject) (gen.UpdateAdminResponseObject, error) {
	svc, p, err := s.authenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed("", fieldRequired)
	}
	u := adminauth.AdminUpdate{RequireTOTP: req.Body.RequireTotp, Disabled: req.Body.Disabled}
	if req.Body.Email != nil {
		email := string(*req.Body.Email)
		u.Email = &email
	}
	if req.Body.Role != nil {
		role := store.AdminRole(*req.Body.Role)
		u.Role = &role
	}
	if req.Body.TenantIds != nil {
		tids := tenantIDs(*req.Body.TenantIds)
		u.TenantIDs = &tids
	}
	a, err := svc.Update(ctx, p, req.AdminId, u, middleware.ClientIP(ctx))
	if err != nil {
		return nil, serviceError(err)
	}
	return gen.UpdateAdmin200JSONResponse(adminBody(a)), nil
}

// DeleteAdmin deletes an administrator account (super admin, 204).
func (s *Server) DeleteAdmin(ctx context.Context, req gen.DeleteAdminRequestObject) (gen.DeleteAdminResponseObject, error) {
	svc, p, err := s.authenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.Delete(ctx, p, req.AdminId, middleware.ClientIP(ctx)); err != nil {
		return nil, serviceError(err)
	}
	return gen.DeleteAdmin204Response{}, nil
}

// ResetAdminCredentials clears the password and TOTP of an administrator
// and returns the account with a new activation link, shown once and never
// mailed (super admin, 200).
func (s *Server) ResetAdminCredentials(ctx context.Context, req gen.ResetAdminCredentialsRequestObject) (gen.ResetAdminCredentialsResponseObject, error) {
	svc, p, err := s.authenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	a, link, err := svc.ResetCredentials(ctx, p, req.AdminId, middleware.ClientIP(ctx))
	if err != nil {
		return nil, serviceError(err)
	}
	return gen.ResetAdminCredentials200JSONResponse(withActivation(a, link)), nil
}

// ActivateAdmin uses an activation link: it sets the password and answers
// 200 with the next login step and a session cookie in that state.
func (s *Server) ActivateAdmin(ctx context.Context, req gen.ActivateAdminRequestObject) (gen.ActivateAdminResponseObject, error) {
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(adminauth.FieldActivationToken, fieldRequired)
	}
	sess, err := svc.Activate(ctx, req.Body.ActivationToken, req.Body.Password, middleware.ClientIP(ctx))
	if err != nil {
		return nil, serviceError(err)
	}
	return gen.ActivateAdmin200JSONResponse{
		Body: loginState(sess), Headers: gen.ActivateAdmin200ResponseHeaders{SetCookie: s.sessionCookie(sess)},
	}, nil
}

// adminBody renders a as the OpenAPI Admin. A super admin always requires
// TOTP; a login never made is absent.
func adminBody(a adminauth.Account) gen.Admin {
	requireTOTP := a.RequireTOTP || a.Role == store.RoleSuperAdmin
	body := gen.Admin{
		Id: a.ID, Username: a.Username, Email: gen.Email(a.Email), Role: gen.AdminRole(a.Role),
		TenantIds: make([]string, len(a.TenantIDs)), TotpEnabled: a.TOTPEnabled, Activated: a.Activated,
		RequireTotp: &requireTOTP, Disabled: a.Disabled, CreatedAt: a.CreatedAt,
	}
	for i, t := range a.TenantIDs {
		body.TenantIds[i] = string(t)
	}
	if !a.LastLoginAt.IsZero() {
		last := a.LastLoginAt
		body.LastLoginAt = &last
	}
	return body
}

// withActivation renders a and its activation link as the OpenAPI
// AdminWithActivation.
func withActivation(a adminauth.Account, link adminauth.Activation) gen.AdminWithActivation {
	b := adminBody(a)
	return gen.AdminWithActivation{
		Id: b.Id, Username: b.Username, Email: b.Email, Role: b.Role, TenantIds: b.TenantIds,
		TotpEnabled: b.TotpEnabled, Activated: b.Activated, RequireTotp: b.RequireTotp, Disabled: b.Disabled,
		LastLoginAt: b.LastLoginAt, CreatedAt: b.CreatedAt,
		ActivationUrl: link.URL, ActivationExpiresAt: link.ExpiresAt,
	}
}

// tenantIDs converts the tenant IDs of a request.
func tenantIDs(ids []string) []tenant.ID {
	out := make([]tenant.ID, len(ids))
	for i, v := range ids {
		out[i] = tenant.ID(v)
	}
	return out
}

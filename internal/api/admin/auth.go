package admin

import (
	"context"
	"errors"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// GetSetupStatus tells whether the first-run setup is still to be done.
func (s *Server) GetSetupStatus(ctx context.Context, _ gen.GetSetupStatusRequestObject) (gen.GetSetupStatusResponseObject, error) {
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	required, err := svc.SetupRequired(ctx)
	if err != nil {
		return nil, serviceError(err)
	}
	return gen.GetSetupStatus200JSONResponse{SetupRequired: required}, nil
}

// CreateSuperAdmin performs the first-run setup: 201 with the TOTP secret
// to confirm and a session cookie in state totp_enrollment_required.
func (s *Server) CreateSuperAdmin(ctx context.Context, req gen.CreateSuperAdminRequestObject) (gen.CreateSuperAdminResponseObject, error) {
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(adminauth.FieldUsername, fieldRequired)
	}
	res, err := svc.CreateSuperAdmin(ctx, adminauth.SetupRequest{
		Username: req.Body.Username, Email: string(req.Body.Email), Password: req.Body.Password,
		SetupToken: deref(req.Body.SetupToken),
	}, middleware.ClientIP(ctx))
	if err != nil {
		return nil, serviceError(err)
	}
	body := enrollmentBody(res.Enrollment)
	csrf := res.Session.CSRFToken
	body.CsrfToken = &csrf
	return gen.CreateSuperAdmin201JSONResponse{
		Body: body, Headers: gen.CreateSuperAdmin201ResponseHeaders{SetCookie: s.sessionCookie(res.Session)},
	}, nil
}

// AdminLogin checks a username and password: 200 with the next login step
// and a session cookie in that state.
func (s *Server) AdminLogin(ctx context.Context, req gen.AdminLoginRequestObject) (gen.AdminLoginResponseObject, error) {
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(adminauth.FieldUsername, fieldRequired)
	}
	sess, err := svc.Login(ctx, req.Body.Username, req.Body.Password, middleware.ClientIP(ctx))
	if err != nil {
		return nil, serviceError(err)
	}
	return gen.AdminLogin200JSONResponse{
		Body: loginState(sess), Headers: gen.AdminLogin200ResponseHeaders{SetCookie: s.sessionCookie(sess)},
	}, nil
}

// AdminVerifyTotp checks the second factor of a session in state
// totp_required: 200 with the rotated, authenticated session cookie.
func (s *Server) AdminVerifyTotp(ctx context.Context, req gen.AdminVerifyTotpRequestObject) (gen.AdminVerifyTotpResponseObject, error) {
	svc, p, err := s.session(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(adminauth.FieldCode, fieldRequired)
	}
	sess, err := svc.VerifyTOTP(ctx, p, deref(req.Body.Code), deref(req.Body.RecoveryCode), middleware.ClientIP(ctx))
	if err != nil {
		return nil, serviceError(err)
	}
	return gen.AdminVerifyTotp200JSONResponse{
		Body: loginState(sess), Headers: gen.AdminVerifyTotp200ResponseHeaders{SetCookie: s.sessionCookie(sess)},
	}, nil
}

// AdminLogout ends the session, whatever its state, and clears its cookie
// (204).
func (s *Server) AdminLogout(ctx context.Context, _ gen.AdminLogoutRequestObject) (gen.AdminLogoutResponseObject, error) {
	svc, p, err := s.session(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.Logout(ctx, p, middleware.ClientIP(ctx)); err != nil {
		return nil, serviceError(err)
	}
	cookie := middleware.ExpiredCookie(middleware.AdminCookie)
	return gen.AdminLogout204Response{Headers: gen.AdminLogout204ResponseHeaders{SetCookie: &cookie}}, nil
}

// GetAdminMe returns the profile of the authenticated administrator, the
// tenants they manage (every tenant for a super admin) and the CSRF token.
func (s *Server) GetAdminMe(ctx context.Context, _ gen.GetAdminMeRequestObject) (gen.GetAdminMeResponseObject, error) {
	p, err := authenticated(ctx)
	if err != nil {
		return nil, err
	}
	if s.tenants == nil {
		return nil, errNoTenants
	}
	refs, err := s.tenantRefs(ctx, p.Admin)
	if err != nil {
		return nil, err
	}
	a := p.Admin
	resp := gen.GetAdminMe200JSONResponse{
		Id: a.ID, Username: a.Username, Email: gen.Email(a.Email), Role: gen.AdminRole(a.Role),
		TotpEnabled: a.TOTPEnabled, Tenants: refs, CsrfToken: p.CSRFToken,
	}
	if a.Language != "" {
		lang := gen.Language(a.Language)
		resp.Language = &lang
	}
	return resp, nil
}

// tenantRefs names the tenants a manages: every tenant for a super admin,
// its own tenants for a delegated admin (a tenant deleted meanwhile is
// skipped).
func (s *Server) tenantRefs(ctx context.Context, a adminauth.Account) ([]gen.TenantRef, error) {
	refs := []gen.TenantRef{}
	if a.Role == store.RoleSuperAdmin {
		cursor := ""
		for {
			page, err := s.tenants.List(ctx, store.TenantListOptions{Cursor: cursor, Limit: store.MaxPageSize})
			if err != nil {
				return nil, err
			}
			for _, t := range page.Items {
				refs = append(refs, tenantRef(t))
			}
			if page.NextCursor == "" {
				return refs, nil
			}
			cursor = page.NextCursor
		}
	}
	for _, tid := range a.TenantIDs {
		t, err := s.tenants.Get(ctx, tid)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			return nil, err
		}
		refs = append(refs, tenantRef(t))
	}
	return refs, nil
}

// tenantRef renders t as the OpenAPI TenantRef.
func tenantRef(t *tenant.Tenant) gen.TenantRef {
	return gen.TenantRef{Id: string(t.ID), Name: t.Name, Fqdn: t.FQDN}
}

// ChangeAdminPassword changes the password of the authenticated
// administrator and revokes their other sessions (204).
func (s *Server) ChangeAdminPassword(ctx context.Context, req gen.ChangeAdminPasswordRequestObject) (gen.ChangeAdminPasswordResponseObject, error) {
	svc, p, err := s.authenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(adminauth.FieldNewPassword, fieldRequired)
	}
	if err := svc.ChangePassword(ctx, p, req.Body.CurrentPassword, req.Body.NewPassword, middleware.ClientIP(ctx)); err != nil {
		return nil, serviceError(err)
	}
	return gen.ChangeAdminPassword204Response{}, nil
}

// StartTotpEnrollment generates a TOTP secret to confirm, for an
// authenticated session or one whose enrollment is mandatory. The optional
// body carries the current password, required to re-enroll.
func (s *Server) StartTotpEnrollment(ctx context.Context, req gen.StartTotpEnrollmentRequestObject) (gen.StartTotpEnrollmentResponseObject, error) {
	svc, p, err := s.session(ctx)
	if err != nil {
		return nil, err
	}
	var current string
	if req.Body != nil {
		current = deref(req.Body.CurrentPassword)
	}
	enr, err := svc.StartEnrollment(ctx, p, current, middleware.ClientIP(ctx))
	if err != nil {
		return nil, serviceError(err)
	}
	return gen.StartTotpEnrollment200JSONResponse(enrollmentBody(enr)), nil
}

// DisableTotp removes the TOTP enrollment of the authenticated
// administrator, when it is not mandatory (204).
func (s *Server) DisableTotp(ctx context.Context, req gen.DisableTotpRequestObject) (gen.DisableTotpResponseObject, error) {
	svc, p, err := s.authenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(adminauth.FieldCurrentPassword, fieldRequired)
	}
	if err := svc.DisableTOTP(ctx, p, req.Body.CurrentPassword, middleware.ClientIP(ctx)); err != nil {
		return nil, serviceError(err)
	}
	return gen.DisableTotp204Response{}, nil
}

// ConfirmTotpEnrollment confirms the pending TOTP secret: 200 with the
// recovery codes and, when the confirmation completed a login, the rotated
// session cookie and its CSRF token.
func (s *Server) ConfirmTotpEnrollment(ctx context.Context, req gen.ConfirmTotpEnrollmentRequestObject) (gen.ConfirmTotpEnrollmentResponseObject, error) {
	svc, p, err := s.session(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(adminauth.FieldCode, fieldRequired)
	}
	res, err := svc.ConfirmEnrollment(ctx, p, deref(req.Body.Code), middleware.ClientIP(ctx))
	if err != nil {
		return nil, serviceError(err)
	}
	resp := gen.ConfirmTotpEnrollment200JSONResponse{Body: gen.TotpConfirmed{RecoveryCodes: res.RecoveryCodes}}
	if res.Session != nil {
		csrf := res.Session.CSRFToken
		resp.Body.CsrfToken = &csrf
		resp.Headers.SetCookie = s.sessionCookie(*res.Session)
	}
	return resp, nil
}

// enrollmentBody renders enr as the OpenAPI TotpEnrollment (the QR code is
// encoded in base64 by the JSON encoder).
func enrollmentBody(enr adminauth.Enrollment) gen.TotpEnrollment {
	return gen.TotpEnrollment{Secret: enr.Secret, OtpauthUri: enr.URI, QrCodePng: enr.QRPNG}
}

// session returns the service and the session of the request, whatever its
// login state: the service checks that the state opens the operation.
func (s *Server) session(ctx context.Context) (Service, adminauth.Principal, error) {
	svc, err := s.service()
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return svc, p, nil
}

// authenticatedSession is session for the operations that need a fully
// authenticated session; any other state gets 401 unauthenticated.
func (s *Server) authenticatedSession(ctx context.Context) (Service, adminauth.Principal, error) {
	svc, err := s.service()
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	p, err := authenticated(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return svc, p, nil
}

// authenticated returns the session of the request when it is fully
// authenticated, or the 401 unauthenticated Problem.
func authenticated(ctx context.Context) (adminauth.Principal, error) {
	p, err := principal(ctx)
	if err != nil {
		return adminauth.Principal{}, err
	}
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return adminauth.Principal{}, problem.New(problem.CodeUnauthenticated)
	}
	return p, nil
}

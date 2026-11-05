package admin

import (
	"context"
	"errors"
	"net/url"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/oidc"
	"github.com/ed-fr/transteira/internal/securitylog"
)

// Redirects of the single sign-on callback (completeAdminOidcLogin): the
// administration interface on success, the login page with a code of a
// closed list on failure (never a free return parameter, T-296).
const (
	// SSOSuccessLocation is the administration interface.
	SSOSuccessLocation = "/admin/"
	// SSOFailureLocation is the login page; the code follows.
	SSOFailureLocation = "/admin/login?error="
)

// Codes of the error parameter of SSOFailureLocation, the closed list of
// the web interface.
const (
	ssoErrorMFARequired  = "sso-mfa-required"
	ssoErrorNotAvailable = "sso-not-available"
	ssoErrorRateLimited  = "rate-limited"
	ssoErrorGeneric      = "invalid-credentials"
)

// GetAdminAuthMethods tells the login page which methods to offer.
func (s *Server) GetAdminAuthMethods(ctx context.Context, _ gen.GetAdminAuthMethodsRequestObject) (gen.GetAdminAuthMethodsResponseObject, error) {
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	m, err := svc.Methods(ctx)
	if err != nil {
		return nil, serviceError(err)
	}
	return gen.GetAdminAuthMethods200JSONResponse{Password: m.Password, Sso: m.SSO}, nil
}

// StartAdminOidcLogin starts a single sign-on login: 200 with the URL of
// the identity provider and the flow cookie.
func (s *Server) StartAdminOidcLogin(ctx context.Context, req gen.StartAdminOidcLoginRequestObject) (gen.StartAdminOidcLoginResponseObject, error) {
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(adminauth.FieldEmail, fieldRequired)
	}
	st, err := svc.StartSSO(ctx, req.Body.Email, middleware.ClientIP(ctx))
	if err != nil {
		return nil, serviceError(err)
	}
	cookie := oidc.FlowCookie(st.Cookie).String()
	return gen.StartAdminOidcLogin200JSONResponse{
		Body: gen.OidcRedirect{RedirectUrl: st.RedirectURL}, Headers: gen.StartAdminOidcLogin200ResponseHeaders{SetCookie: &cookie},
	}, nil
}

// CompleteAdminOidcLogin is the redirect target of the identity provider:
// always a 303, to the administration interface with the session cookie
// on success, to the login page with an error code otherwise. The flow
// cookie, read and expired by middleware.FlowCookie around this handler,
// is cleared whatever the outcome. Only an internal failure answers a
// Problem (500).
func (s *Server) CompleteAdminOidcLogin(ctx context.Context, req gen.CompleteAdminOidcLoginRequestObject) (gen.CompleteAdminOidcLoginResponseObject, error) {
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	q := req.Params
	sess, err := svc.CompleteSSO(ctx, adminauth.SSOCallback{
		Cookie: middleware.FlowCookieFrom(ctx), Code: deref(q.Code), State: deref(q.State), Iss: deref(q.Iss), Error: deref(q.Error),
	}, middleware.ClientIP(ctx))
	code := ""
	var failed *adminauth.SSOError
	switch {
	case err == nil:
		location := SSOSuccessLocation
		return gen.CompleteAdminOidcLogin303Response{Headers: gen.CompleteAdminOidcLogin303ResponseHeaders{
			Location: &location, SetCookie: s.sessionCookie(sess),
		}}, nil
	case errors.As(err, &failed) && failed.Reason == securitylog.ReasonMFAMissing:
		code = ssoErrorMFARequired
	case errors.As(err, &failed):
		code = ssoErrorGeneric
	case errors.Is(err, adminauth.ErrRateLimited):
		code = ssoErrorRateLimited
	case errors.Is(err, adminauth.ErrSSONotAvailable):
		code = ssoErrorNotAvailable
	default:
		return nil, err
	}
	location := SSOFailureLocation + url.QueryEscape(code)
	return gen.CompleteAdminOidcLogin303Response{Headers: gen.CompleteAdminOidcLogin303ResponseHeaders{Location: &location}}, nil
}

// DeleteAdminIdentity unpins a single sign-on identity of an account
// (super admin, 204).
func (s *Server) DeleteAdminIdentity(ctx context.Context, req gen.DeleteAdminIdentityRequestObject) (gen.DeleteAdminIdentityResponseObject, error) {
	svc, p, err := s.authenticatedSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.DeleteIdentity(ctx, p, req.AdminId, req.IdentityId, middleware.ClientIP(ctx)); err != nil {
		return nil, serviceError(err)
	}
	return gen.DeleteAdminIdentity204Response{}, nil
}

// identitiesBody renders ids as the OpenAPI AdminIdentity list (the
// tenant is not stored: omitted), nil when not read.
func identitiesBody(ids []adminauth.Identity) *[]gen.AdminIdentity {
	if ids == nil {
		return nil
	}
	out := make([]gen.AdminIdentity, len(ids))
	for i, id := range ids {
		out[i] = gen.AdminIdentity{Id: id.ID, Issuer: id.Issuer, ClientId: id.ClientID, LinkedAt: id.LinkedAt}
	}
	return &out
}

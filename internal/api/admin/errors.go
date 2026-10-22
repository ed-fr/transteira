package admin

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
)

// Field error codes of the admin operations.
const (
	fieldInvalidFormat = "invalid-format"
	// fieldInvalidEmail is a value of a mail address field that is not a
	// bare address.
	fieldInvalidEmail = "invalid-email"
	fieldRequired     = "required"
	// fieldNotNullable is a null member of a merge patch on a field that
	// cannot be removed.
	fieldNotNullable = "not-nullable"
)

// errNoService reports a server built without WithService: a wiring error,
// answered 500.
var errNoService = errors.New("admin: no authentication service configured")

// errNoTenants reports a server built without WithTenants: a wiring error,
// answered 500.
var errNoTenants = errors.New("admin: no tenant registry configured")

// serviceError maps an error of the authentication service to the error
// the strict handler renders. Server errors keep their cause, which is
// logged (the service never puts a password, a token, a secret or a code
// in it).
func serviceError(err error) error {
	var (
		invalid *adminauth.InvalidError
		limited *adminauth.RateLimitError
	)
	switch {
	case errors.As(err, &invalid):
		return validationFailed(invalid.Field, formatCode(invalid.Field == adminauth.FieldEmail))
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.Is(err, adminauth.ErrInvalid):
		return problem.New(problem.CodeValidationFailed)
	case errors.Is(err, adminauth.ErrRateLimited):
		return problem.New(problem.CodeRateLimited)
	case errors.Is(err, adminauth.ErrInvalidCredentials):
		return problem.New(problem.CodeInvalidCredentials)
	case errors.Is(err, adminauth.ErrUnauthenticated):
		return problem.New(problem.CodeUnauthenticated)
	case errors.Is(err, adminauth.ErrForbidden):
		return problem.New(problem.CodeForbidden)
	case errors.Is(err, adminauth.ErrSetupTokenInvalid):
		return problem.New(problem.CodeSetupTokenInvalid)
	case errors.Is(err, adminauth.ErrSetupDone):
		return problem.New(problem.CodeSetupAlreadyDone)
	case errors.Is(err, adminauth.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, adminauth.ErrAlreadyExists):
		return problem.New(problem.CodeAlreadyExists)
	case errors.Is(err, adminauth.ErrStateConflict):
		return problem.New(problem.CodeStateConflict)
	default:
		return err
	}
}

// formatCode returns the field code of a malformed value: invalid-email
// for a mail address field, invalid-format otherwise.
func formatCode(address bool) string {
	if address {
		return fieldInvalidEmail
	}
	return fieldInvalidFormat
}

// validationFailed returns a 400 validation-failed Problem naming field.
func validationFailed(field, code string) *problem.Problem {
	return problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(problem.FieldError{Field: field, Code: code}))
}

// principal returns the admin session put in ctx by the session middleware.
// Its absence means the route was wired without it: the request is refused
// as unauthenticated.
func principal(ctx context.Context) (adminauth.Principal, error) {
	p, ok := middleware.AdminSessionFrom[adminauth.Principal](ctx)
	if !ok {
		return adminauth.Principal{}, problem.New(problem.CodeUnauthenticated)
	}
	return p, nil
}

// service returns the authentication service, or the error to answer.
func (s *Server) service() (Service, error) {
	if s.svc == nil {
		return nil, errNoService
	}
	return s.svc, nil
}

// sessionCookie returns the Set-Cookie value of the session cookie opening
// sess: host only (no Domain, as the __Host- prefix requires), Path=/,
// Secure, HttpOnly and SameSite=Strict. Its Max-Age is the life left to
// the session, or to its intermediate login state when that ends first
// (sess.StateExpiresAt), rounded down to the second and at least 1 (0
// would delete it).
func (s *Server) sessionCookie(sess adminauth.Session) *string {
	now := s.now()
	left := sess.ExpiresAt.Sub(now)
	if !sess.StateExpiresAt.IsZero() {
		left = min(left, sess.StateExpiresAt.Sub(now))
	}
	c := http.Cookie{
		Name: middleware.AdminCookie, Value: sess.Token, Path: "/", MaxAge: max(int(left/time.Second), 1),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
	v := c.String()
	return &v
}

// loginState renders sess as the OpenAPI LoginState.
func loginState(sess adminauth.Session) gen.LoginState {
	return gen.LoginState{Status: gen.LoginStateStatus(sess.State), CsrfToken: sess.CSRFToken}
}

// deref returns *p, or the zero value when p is nil.
func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

// optional returns a pointer to v, or nil when v is empty.
func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// optionalTime returns a pointer to t, or nil when t is zero.
func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

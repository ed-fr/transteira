package apitoken

import (
	"errors"
	"fmt"

	"github.com/ed-fr/transteira/internal/adminauth"
)

// Errors of the authentication ([Service.Authenticate]). Callers test them
// with errors.Is.
var (
	// ErrMissing reports a request without a bearer token: no
	// Authorization header, or one with another scheme (401
	// unauthenticated).
	ErrMissing = errors.New("apitoken: no bearer token")
	// ErrInvalid reports a bearer token that is malformed, unknown (on
	// this tenant), revoked or expired, without telling which (401
	// invalid-credentials, security event api_token_invalid).
	ErrInvalid = errors.New("apitoken: invalid token")
	// ErrIPNotAllowed reports a valid token presented from a client IP
	// outside its allowed ranges (403 ip-not-allowed, security event).
	ErrIPNotAllowed = errors.New("apitoken: client ip not allowed for this token")
)

// Errors of the administration. Any other error is an internal failure
// whose message never contains a secret.
var (
	// ErrInvalidInput reports a malformed input (400 validation-failed).
	// The error is an *[InvalidError] naming the field.
	ErrInvalidInput = errors.New("apitoken: invalid input")
	// ErrUnauthenticated reports a principal without an authenticated
	// session (401 unauthenticated). It is [adminauth.ErrUnauthenticated].
	ErrUnauthenticated = adminauth.ErrUnauthenticated
	// ErrForbidden reports a role that does not allow the operation (403
	// forbidden). It is [adminauth.ErrForbidden].
	ErrForbidden = adminauth.ErrForbidden
	// ErrNotFound reports a missing tenant, a tenant the caller is not
	// attached to, a tenant being deleted, or a missing token of the
	// tenant (404 not-found). A token of another tenant is answered exactly
	// like a missing one. It is [adminauth.ErrNotFound].
	ErrNotFound = adminauth.ErrNotFound
	// ErrStateConflict reports the change of a revoked token (409
	// state-conflict).
	ErrStateConflict = errors.New("apitoken: the token is revoked")
)

// Fields named by an [InvalidError]: JSON pointers (RFC 6901) of the
// request bodies. [FieldAllowedCIDRs] and [FieldAllowedSenders] are
// followed by "/<index>" for one entry.
const (
	FieldName           = "/name"
	FieldAllowedCIDRs   = "/allowedCidrs"
	FieldAllowedSenders = "/allowedSenders"
	FieldExpiresAt      = "/expiresAt"
)

// InvalidError reports a malformed input field. It matches
// [ErrInvalidInput].
type InvalidError struct {
	// Field is the JSON pointer of the field.
	Field string
	// Reason explains the problem in English; it never quotes the value.
	Reason string
}

// Error implements error.
func (e *InvalidError) Error() string {
	return "apitoken: invalid " + e.Field + ": " + e.Reason
}

// Is makes errors.Is(err, ErrInvalidInput) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalidInput }

// invalid returns an *InvalidError for field.
func invalid(field, format string, args ...any) error {
	return &InvalidError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

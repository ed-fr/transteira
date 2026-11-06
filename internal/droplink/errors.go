package droplink

import (
	"errors"
	"fmt"

	"github.com/ed-fr/transteira/internal/adminauth"
)

// Errors of the administration. Any other error is an internal failure
// whose message never contains a token.
var (
	// ErrInvalidInput reports a malformed input (400 validation-failed).
	// The error is an *[InvalidError] naming the field.
	ErrInvalidInput = errors.New("droplink: invalid input")
	// ErrUnauthenticated reports a principal without an authenticated
	// session (401 unauthenticated). It is [adminauth.ErrUnauthenticated].
	ErrUnauthenticated = adminauth.ErrUnauthenticated
	// ErrForbidden reports a role that does not allow the operation (403
	// forbidden). It is [adminauth.ErrForbidden].
	ErrForbidden = adminauth.ErrForbidden
	// ErrNotFound reports a missing tenant, a tenant the caller is not
	// attached to, a tenant being deleted, or a missing link of the tenant
	// (404 not-found). It is [adminauth.ErrNotFound].
	ErrNotFound = adminauth.ErrNotFound
	// ErrStateConflict reports the change or the rotation of a revoked
	// link (409 state-conflict).
	ErrStateConflict = errors.New("droplink: the link is revoked")
	// ErrLimitReached reports a creation over the limit of links per
	// tenant (409 drop-link-limit-reached).
	ErrLimitReached = errors.New("droplink: too many drop links")
)

// Fields named by an [InvalidError]: JSON pointers (RFC 6901) of the
// request bodies. [FieldRecipients] is followed by "/<index>" for one entry.
const (
	FieldLabel      = "/label"
	FieldRecipients = "/recipients"
	FieldValidity   = "/validityDays"
	FieldLevel      = "/confidentialityLevel"
	FieldExpiresAt  = "/expiresAt"
	FieldMaxPerHour = "/maxDepositsPerHour"
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
	return "droplink: invalid " + e.Field + ": " + e.Reason
}

// Is makes errors.Is(err, ErrInvalidInput) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalidInput }

// invalid returns an *InvalidError for field.
func invalid(field, format string, args ...any) error {
	return &InvalidError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

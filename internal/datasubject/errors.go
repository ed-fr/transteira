package datasubject

import (
	"errors"

	"github.com/ed-fr/transteira/internal/adminauth"
)

// Errors returned by the [Service]. Callers test them with errors.Is; the
// comment of each one gives the problem code it maps to. Any other error is
// an internal failure (500 internal-error) whose message never contains
// the address.
var (
	// ErrInvalid reports a malformed address (400 validation-failed). The
	// error is an *[InvalidError] naming the field.
	ErrInvalid = errors.New("datasubject: invalid input")
	// ErrUnauthenticated reports a principal without an authenticated
	// session (401 unauthenticated). It is [adminauth.ErrUnauthenticated].
	ErrUnauthenticated = adminauth.ErrUnauthenticated
	// ErrForbidden reports a role that may read the tenant but not change
	// it (403 forbidden). It is [adminauth.ErrForbidden].
	ErrForbidden = adminauth.ErrForbidden
	// ErrNotFound reports a missing tenant, a tenant the caller is not
	// attached to, or a tenant being deleted (404 not-found). It is
	// [adminauth.ErrNotFound].
	ErrNotFound = adminauth.ErrNotFound
	// ErrBusy reports an erasure stopped because an upload request still
	// holds a transfer of the address, or because a deposit started with an
	// invitation of the address meanwhile (409 conflict, Retry-After
	// [RetryAfter]). What was erased stays erased; a new call completes the
	// erasure.
	ErrBusy = errors.New("datasubject: a transfer of the address is busy, retry later")
)

// FieldEmail is the JSON pointer of the address in the request body,
// named by an [InvalidError].
const FieldEmail = "/email"

// InvalidError reports a malformed input field. It matches [ErrInvalid].
type InvalidError struct {
	// Field is the JSON pointer of the field ([FieldEmail]).
	Field string
	// Reason explains the problem in English; it never quotes the input.
	Reason string
}

// Error implements error.
func (e *InvalidError) Error() string {
	return "datasubject: invalid " + e.Field + ": " + e.Reason
}

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

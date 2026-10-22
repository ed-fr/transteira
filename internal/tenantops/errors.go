package tenantops

import (
	"errors"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
)

// Errors returned by the [Service]. Callers test them with errors.Is; the
// comment of each one gives the problem code it maps to. Any other error is
// an internal failure (500 internal-error) whose message never contains a
// secret, a download link or a mail address given by the caller.
var (
	// ErrInvalid reports a malformed input (400 validation-failed). The
	// error is an *[InvalidError] naming the field.
	ErrInvalid = errors.New("tenantops: invalid input")
	// ErrUnauthenticated reports a principal without an authenticated
	// session (401 unauthenticated). It is [adminauth.ErrUnauthenticated].
	ErrUnauthenticated = adminauth.ErrUnauthenticated
	// ErrForbidden reports a role that does not allow the operation (403
	// forbidden): the global audit log read by an administrator other than
	// a super admin. It is [adminauth.ErrForbidden].
	ErrForbidden = adminauth.ErrForbidden
	// ErrNotFound reports a missing tenant, a tenant the caller is not
	// attached to, a tenant being deleted, or a missing transfer,
	// invitation or blocklist entry of the tenant (404 not-found). An
	// object of another tenant is answered exactly like a missing one. It
	// is [adminauth.ErrNotFound].
	ErrNotFound = adminauth.ErrNotFound
	// ErrAlreadyExists reports a blocklist value already listed for the
	// same kind (409 already-exists).
	ErrAlreadyExists = errors.New("tenantops: blocklist value already listed")
	// ErrStateConflict reports an operation the current state of the
	// object does not allow (409 state-conflict). [ErrBusy] and
	// [ErrNotAvailable] match it.
	ErrStateConflict = errors.New("tenantops: not allowed in the current state")
	// ErrBusy reports a transfer deletion refused because an upload
	// request of the transfer is in progress, after the retries (409
	// state-conflict with a Retry-After header). The error is a
	// *[BusyError] carrying the delay; it matches [ErrStateConflict].
	ErrBusy = fmt.Errorf("%w: an upload of the transfer is in progress", ErrStateConflict)
	// ErrNotAvailable reports a notification resend for a transfer that is
	// not available (409 state-conflict). It matches [ErrStateConflict].
	ErrNotAvailable = fmt.Errorf("%w: the transfer is not available", ErrStateConflict)
	// ErrRateLimited reports too many notification resends of a transfer
	// (429 rate-limited). The error is a *[RateLimitError] carrying the
	// Retry-After delay.
	ErrRateLimited = errors.New("tenantops: too many resends")
	// ErrMailUnavailable reports a notification resend for a tenant
	// without SMTP settings: nothing was queued (503 mail-unavailable).
	ErrMailUnavailable = errors.New("tenantops: the tenant has no smtp settings")
)

// Fields named by an [InvalidError]: JSON pointers (RFC 6901) of the
// request bodies, or names of the query parameters. [FieldRecipients] is
// followed by "/<index>" for one recipient.
const (
	FieldStatus       = "status"
	FieldEmail        = "email"
	FieldCreatedAfter = "createdAfter"
	FieldLimit        = "limit"
	FieldCursor       = "cursor"
	FieldKindParam    = "kind"
	FieldAction       = "action"
	FieldActor        = "actor"
	FieldFrom         = "from"
	FieldTo           = "to"
	FieldTenantID     = "tenantId"
	FieldReason       = "/reason"
	FieldRecipients   = "/recipients"
	FieldKind         = "/kind"
	FieldValue        = "/value"
	FieldComment      = "/comment"
)

// InvalidError reports a malformed input field. It matches [ErrInvalid].
type InvalidError struct {
	// Field is the JSON pointer of the field, or the name of the query
	// parameter (FieldStatus...).
	Field string
	// Reason explains the problem in English; it never quotes the value.
	Reason string
	// NotAnAddress tells that the field must be a mail address and the
	// value is not one (field code invalid-email).
	NotAnAddress bool
}

// Error implements error.
func (e *InvalidError) Error() string {
	return "tenantops: invalid " + e.Field + ": " + e.Reason
}

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// invalid returns an *InvalidError for field.
func invalid(field, format string, args ...any) error {
	return &InvalidError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// invalidAddress returns an *InvalidError for a field that must be a
// mail address.
func invalidAddress(field string) error {
	return &InvalidError{Field: field, Reason: "must be a mail address", NotAnAddress: true}
}

// BusyError reports a transfer whose upload is in progress. It matches
// [ErrBusy] and [ErrStateConflict].
type BusyError struct {
	// RetryAfter is the delay before a new attempt, for the Retry-After
	// header and the retryAfterSeconds member (whole seconds, at least
	// one).
	RetryAfter time.Duration
}

// Error implements error.
func (e *BusyError) Error() string {
	return fmt.Sprintf("%v, retry after %s", ErrBusy, e.RetryAfter)
}

// Unwrap makes errors.Is(err, ErrBusy) and errors.Is(err,
// ErrStateConflict) true.
func (e *BusyError) Unwrap() error { return ErrBusy }

// RateLimitError reports a rate limit reached. It matches [ErrRateLimited].
type RateLimitError struct {
	// RetryAfter is the time left before a new attempt is allowed, for the
	// Retry-After header (whole seconds, at least one).
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%v, retry after %s", ErrRateLimited, e.RetryAfter)
}

// Unwrap makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

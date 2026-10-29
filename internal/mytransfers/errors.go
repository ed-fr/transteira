package mytransfers

import (
	"errors"
	"fmt"
	"time"
)

// Errors returned by the [Service]. Callers test them with errors.Is; the
// comment of each one gives the HTTP answer it maps to.
var (
	// ErrInvalid reports a malformed input (400 validation-failed). The
	// error is an *[InvalidError] naming the field.
	ErrInvalid = errors.New("mytransfers: invalid input")
	// ErrRateLimited reports a rate limit (429 rate-limited). The error is
	// a *[RateLimitError] carrying a Retry-After hint.
	ErrRateLimited = errors.New("mytransfers: rate limited")
	// ErrMailUnavailable reports that the tenant cannot send mail at all
	// (no SMTP settings) or that the service is shut down (503
	// mail-unavailable). It never depends on the address.
	ErrMailUnavailable = errors.New("mytransfers: mail unavailable")
	// ErrAccessLinkInvalid reports an access link token that is malformed,
	// unknown, expired, already used or of another tenant (410
	// access-link-invalid).
	ErrAccessLinkInvalid = errors.New("mytransfers: access link invalid")
	// ErrUnauthenticated reports a missing, malformed, unknown, ended or
	// expired session token (401 unauthenticated).
	ErrUnauthenticated = errors.New("mytransfers: no valid session")
	// ErrNotFound reports a transfer that is not one of the session address
	// in progress in the tenant (404 not-found), whatever the reason.
	ErrNotFound = errors.New("mytransfers: transfer not found")
	// ErrNotExtendable reports an extension of a transfer that is not
	// available, whose downloads are over, or that is due for deletion
	// after its downloads (409 state-conflict).
	ErrNotExtendable = errors.New("mytransfers: transfer cannot be extended")
	// ErrExtensionLimit reports an extension beyond 90 days after the
	// creation of the transfer (409 extension-limit-reached).
	ErrExtensionLimit = errors.New("mytransfers: transfer cannot live more than 90 days")
	// ErrNotAllowed reports an extension duration that the rules of the
	// transfer do not allow, or that would not move the expiry forward
	// (400 validation-failed, field FieldExpiryDays, code not-allowed). The
	// error is a *[NotAllowedError] listing the allowed durations.
	ErrNotAllowed = errors.New("mytransfers: duration not allowed")
	// ErrBusy reports a deletion refused because an upload of the transfer
	// is in progress (409 state-conflict with a Retry-After header). The
	// error is a *[BusyError].
	ErrBusy = errors.New("mytransfers: an upload of the transfer is in progress")
)

// Fields named by an [InvalidError]: JSON pointers of the request bodies,
// or the name of a query parameter.
const (
	FieldEmail      = "/email"
	FieldLanguage   = "/language"
	FieldToken      = "/token"
	FieldExpiryDays = "/expiryDays"
	FieldCursor     = "cursor"
)

// InvalidError reports a malformed input field. It matches [ErrInvalid].
type InvalidError struct {
	// Field is the field (FieldEmail...).
	Field string
}

// Error implements error; it never quotes the value.
func (e *InvalidError) Error() string { return "mytransfers: invalid " + e.Field }

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// invalid returns an *InvalidError for field.
func invalid(field string) error { return &InvalidError{Field: field} }

// RateLimitError reports a rate limit. It matches [ErrRateLimited].
type RateLimitError struct {
	// RetryAfter is when the client may try again, for the Retry-After
	// header (an upper bound for the request limit: its window).
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("mytransfers: rate limited, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// NotAllowedError reports an extension duration that is not allowed. It
// matches [ErrNotAllowed].
type NotAllowedError struct {
	// Allowed are the durations (in days) the rules of the transfer allow,
	// shortest first; the allowed member of the field error.
	Allowed []int
}

// Error implements error.
func (e *NotAllowedError) Error() string {
	return fmt.Sprintf("mytransfers: duration not allowed, allowed %v", e.Allowed)
}

// Is makes errors.Is(err, ErrNotAllowed) true.
func (e *NotAllowedError) Is(target error) bool { return target == ErrNotAllowed }

// BusyError reports a transfer whose upload is in progress. It matches
// [ErrBusy].
type BusyError struct {
	// RetryAfter is the delay before a new attempt, for the Retry-After
	// header.
	RetryAfter time.Duration
}

// Error implements error.
func (e *BusyError) Error() string {
	return fmt.Sprintf("%v, retry after %s", ErrBusy, e.RetryAfter)
}

// Unwrap makes errors.Is(err, ErrBusy) true.
func (e *BusyError) Unwrap() error { return ErrBusy }

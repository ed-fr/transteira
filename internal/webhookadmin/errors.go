package webhookadmin

import (
	"errors"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
)

// Errors returned by the [Service]. Callers test them with errors.Is; the
// comment of each one gives the problem code it maps to.
var (
	// ErrInvalid reports a malformed input (400 validation-failed). The
	// error is an *[InvalidError] naming the field and its code.
	ErrInvalid = errors.New("webhookadmin: invalid input")
	// ErrUnauthenticated reports a principal without an authenticated
	// session (401 unauthenticated). It is [adminauth.ErrUnauthenticated].
	ErrUnauthenticated = adminauth.ErrUnauthenticated
	// ErrForbidden reports an instance-wide webhook operation by an
	// administrator who is not a super admin (403 forbidden). It is
	// [adminauth.ErrForbidden].
	ErrForbidden = adminauth.ErrForbidden
	// ErrNotFound reports a missing tenant or webhook, a tenant the caller
	// is not attached to or being deleted, or a webhook of another tenant
	// (404 not-found). It is [adminauth.ErrNotFound].
	ErrNotFound = adminauth.ErrNotFound
	// ErrLimitReached reports a creation over the store.MaxWebhooks
	// webhooks of a tenant or of the instance (409 state-conflict).
	ErrLimitReached = errors.New("webhookadmin: too many webhooks")
	// ErrConflict reports a change of a webhook that another change
	// (another administrator) committed meanwhile (409 state-conflict):
	// the change is not applied and can be retried.
	ErrConflict = errors.New("webhookadmin: webhook changed concurrently")
	// ErrRateLimited reports too many tests, or too many creations and URL
	// changes (429 rate-limited). The error is a *[RateLimitError] carrying
	// the Retry-After delay.
	ErrRateLimited = errors.New("webhookadmin: too many requests")
)

// Fields named by an [InvalidError], as JSON pointers (RFC 6901) of the
// request bodies. An event is named by its index: "/events/2".
const (
	FieldName         = "/name"
	FieldKind         = "/kind"
	FieldURL          = "/url"
	FieldEvents       = "/events"
	FieldRotateSecret = "/rotateSecret"
)

// Codes of an [InvalidError] (OpenAPI field error codes).
const (
	// CodeInvalidFormat is a malformed value, an event type the webhook may
	// not subscribe to, or a duplicate event.
	CodeInvalidFormat = "invalid-format"
	// CodeRequired is a missing value.
	CodeRequired = "required"
	// CodeURLNotAllowed is a URL whose host does not resolve, resolves to a
	// denied network, or refuses plain http: one code for the three.
	CodeURLNotAllowed = "url-not-allowed"
)

// InvalidError reports a malformed input field. It matches [ErrInvalid].
type InvalidError struct {
	// Field is the JSON pointer of the field (FieldName...).
	Field string
	// Code is the field error code (CodeInvalidFormat...).
	Code string
}

// Error implements error.
func (e *InvalidError) Error() string {
	return "webhookadmin: invalid " + e.Field + ": " + e.Code
}

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// invalid returns an *InvalidError.
func invalid(field, code string) error { return &InvalidError{Field: field, Code: code} }

// RateLimitError reports a rate limit reached. It matches [ErrRateLimited].
type RateLimitError struct {
	// RetryAfter is the time left before a new request is allowed, for the
	// Retry-After header (at least one second).
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("webhookadmin: too many requests, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// errNotGeneric reports a secret rotation of a webhook whose kind has no
// secret.
var errNotGeneric = errors.New("webhookadmin: only a generic webhook has a secret")

// storeError maps an error of a webhook operation op to the error of the
// service.
func storeError(op string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, store.ErrLimitReached):
		return ErrLimitReached
	case errors.Is(err, store.ErrConflict):
		return ErrConflict
	case errors.Is(err, errNotGeneric):
		return invalid(FieldRotateSecret, CodeInvalidFormat)
	default:
		return fmt.Errorf("webhookadmin: %s: %w", op, err)
	}
}

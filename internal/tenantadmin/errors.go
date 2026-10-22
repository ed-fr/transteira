package tenantadmin

import (
	"errors"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/netpolicy"
)

// Errors returned by the [Service]. Callers test them with errors.Is; the
// comment of each one gives the problem code it maps to. Any other error is
// an internal failure (500 internal-error) whose message never contains a
// secret.
var (
	// ErrInvalid reports a malformed input (400 validation-failed). The
	// error is an *[InvalidError] naming the field and, for a mail
	// template, the issues found.
	ErrInvalid = errors.New("tenantadmin: invalid input")
	// ErrUnauthenticated reports a principal without an authenticated
	// session (401 unauthenticated). It is [adminauth.ErrUnauthenticated].
	ErrUnauthenticated = adminauth.ErrUnauthenticated
	// ErrForbidden reports a role that does not allow the operation (403
	// forbidden): a delegated admin creating or deleting a tenant, or
	// changing a general setting reserved to the super admin. It is
	// [adminauth.ErrForbidden].
	ErrForbidden = adminauth.ErrForbidden
	// ErrNotFound reports a missing tenant, a tenant the caller is not
	// attached to, a tenant being deleted, an unknown template, language,
	// document or image, or missing SMTP settings (404 not-found). It is
	// [adminauth.ErrNotFound].
	ErrNotFound = adminauth.ErrNotFound
	// ErrAlreadyExists reports an FQDN already used by another tenant (409
	// already-exists).
	ErrAlreadyExists = errors.New("tenantadmin: fqdn already used by another tenant")
	// ErrPayloadTooLarge reports an image above the byte or dimension
	// limits of its kind (413 payload-too-large).
	ErrPayloadTooLarge = errors.New("tenantadmin: image too large")
	// ErrUnsupportedMediaType reports an image that is not a PNG, JPEG or
	// WebP (415 unsupported-media-type).
	ErrUnsupportedMediaType = errors.New("tenantadmin: unsupported image format")
	// ErrRateLimited reports too many SMTP tests (429 rate-limited). The
	// error is a *[RateLimitError] carrying the Retry-After delay.
	ErrRateLimited = errors.New("tenantadmin: too many attempts")
	// ErrAddressDenied reports an SMTP server address inside the denied
	// networks (TT_SMTP_DENY_NETWORKS). It is [netpolicy.ErrAddressDenied],
	// returned by [netpolicy.DialGuard].
	ErrAddressDenied = netpolicy.ErrAddressDenied
)

// Fields named by an [InvalidError], as JSON pointers (RFC 6901) of the
// request bodies, or names of the query parameters. "" points at the whole
// body: [FieldImage] (the body is the image itself) and [FieldTemplate] (a
// template as a whole; its issues name their own part).
const (
	FieldName               = "/name"
	FieldFQDN               = "/fqdn"
	FieldDefaultLanguage    = "/defaultLanguage"
	FieldStorageQuotaBytes  = "/storageQuotaBytes"
	FieldMaxTransferBytes   = "/maxTransferBytes"
	FieldMaxTransferCeiling = "/maxTransferCeiling"
	FieldConfirm            = "confirm"
	FieldPrimaryColor       = "/primaryColor"
	FieldAccentColor        = "/accentColor"
	FieldImage              = ""
	FieldInternalCIDRs      = "/internalCidrs"
	FieldInternalDomains    = "/internalDomains"
	FieldHost               = "/host"
	FieldPort               = "/port"
	FieldSecurity           = "/security"
	FieldUsername           = "/username"
	FieldPassword           = "/password"
	FieldFromAddress        = "/fromAddress"
	FieldFromName           = "/fromName"
	FieldTo                 = "/to"
	FieldDKIMSelector       = "dkimSelector"
	FieldTemplate           = ""
	FieldMarkdown           = "/markdown"
)

// InvalidError reports a malformed input field. It matches [ErrInvalid].
type InvalidError struct {
	// Field is the JSON pointer of the field (FieldName...), "" for the
	// request as a whole.
	Field string
	// Reason explains the problem in English; it never quotes a secret.
	Reason string
	// Issues lists the problems of a mail template ([FieldTemplate]).
	Issues []mail.Issue
}

// Error implements error.
func (e *InvalidError) Error() string {
	return "tenantadmin: invalid " + e.Field + ": " + e.Reason
}

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// invalid returns an *InvalidError for field.
func invalid(field, format string, args ...any) error {
	return &InvalidError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// RateLimitError reports a rate limit reached. It matches [ErrRateLimited].
type RateLimitError struct {
	// RetryAfter is the time left before a new attempt is allowed, for the
	// Retry-After header (at least one second).
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("tenantadmin: too many attempts, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

package provisioning

import (
	"errors"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
)

// Errors returned by the [Service]. Callers test them with errors.Is; the
// comment of each one gives the problem it maps to. The service also passes
// through the errors of the tenant creation, documented on
// [Service.ProvisionTenant], and of the TOTP re-confirmation, documented on
// [Service.CreateToken]. Any other error is an internal failure (500
// internal-error) whose message never contains a secret.
var (
	// ErrInvalidToken reports a provisioning token that is malformed,
	// unknown, revoked, expired, or presented from outside its IP ranges
	// (401 provisioning-token-invalid). It is always the same error for
	// the client (no oracle, T-268); the error is an *[AuthError] whose
	// Reason may go to the application log only.
	ErrInvalidToken = errors.New("provisioning: invalid provisioning token")
	// ErrInvalid reports a malformed input (400 validation-failed). The
	// error is an *[InvalidError] naming the field.
	ErrInvalid = errors.New("provisioning: invalid input")
	// ErrScopeExceeded reports a request outside the scope of the token
	// (403 provisioning-scope-exceeded). The error is a *[ScopeError]
	// naming the refused field.
	ErrScopeExceeded = errors.New("provisioning: outside the scope of the provisioning token")
	// ErrRateLimited reports too many tenant creation attempts or
	// creations for the token (429 rate-limited). The error is a *[RateLimitError] carrying the
	// Retry-After delay.
	ErrRateLimited = errors.New("provisioning: too many tenant creations")
	// ErrNotFound reports an unknown provisioning token (super admin
	// operations) or a tenant that the token of the request did not create,
	// unknown, or being deleted (404 not-found).
	ErrNotFound = errors.New("provisioning: not found")
	// ErrUnauthenticated reports a principal without an authenticated
	// session (401 unauthenticated). It is [adminauth.ErrUnauthenticated].
	ErrUnauthenticated = adminauth.ErrUnauthenticated
	// ErrForbidden reports an administrator who is not a super admin (403
	// forbidden). It is [adminauth.ErrForbidden].
	ErrForbidden = adminauth.ErrForbidden
)

// Reasons of an [AuthError], for the application log only.
const (
	ReasonMalformed    = "malformed"
	ReasonUnknown      = "unknown"
	ReasonRevoked      = "revoked"
	ReasonExpired      = "expired"
	ReasonIPNotAllowed = "ip_not_allowed"
	// ReasonUnusable is a token found revoked or expired by the tenant
	// creation, after its authentication.
	ReasonUnusable = "revoked_or_expired"
)

// AuthError reports a refused provisioning token. It matches
// [ErrInvalidToken]; its message is the same whatever the reason, so that
// writing it to a response reveals nothing.
type AuthError struct {
	// Reason is one of the Reason* constants, for the application log
	// only, never for the client.
	Reason string
	// TokenID is the identifier of the token when it was found ("" for a
	// malformed or unknown one), for the application log only.
	TokenID string
}

// Error implements error.
func (e *AuthError) Error() string { return ErrInvalidToken.Error() }

// Is makes errors.Is(err, ErrInvalidToken) true.
func (e *AuthError) Is(target error) bool { return target == ErrInvalidToken }

// Fields named by an [InvalidError] or a [ScopeError], as JSON pointers of
// the request bodies. FieldMaxTenants is the empty pointer of a creation
// refused because the token reached its maximum number of tenants.
const (
	FieldName                 = "/name"
	FieldAllowedCIDRs         = "/allowedCidrs"
	FieldAllowedFQDNSuffixes  = "/allowedFqdnSuffixes"
	FieldMaxStorageQuotaBytes = "/maxStorageQuotaBytes"
	FieldMaxTransferBytes     = "/maxTransferBytes"
	FieldMaxTenantsCap        = "/maxTenants"
	FieldExpiresAt            = "/expiresAt"
	FieldFQDN                 = "/fqdn"
	FieldStorageQuotaBytes    = "/storageQuotaBytes"
	FieldMaxTenants           = ""
)

// InvalidError reports a malformed input field. It matches [ErrInvalid].
type InvalidError struct {
	// Field is the JSON pointer of the field (Field*).
	Field string
	// Reason explains the problem in English; it never quotes the value.
	Reason string
}

// Error implements error.
func (e *InvalidError) Error() string { return "provisioning: invalid " + e.Field + ": " + e.Reason }

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// invalid returns an *InvalidError for field.
func invalid(field, reason string) error { return &InvalidError{Field: field, Reason: reason} }

// ScopeError reports a request outside the scope of the token. It matches
// [ErrScopeExceeded].
type ScopeError struct {
	// Field is the JSON pointer of the refused field: FieldFQDN,
	// FieldStorageQuotaBytes, FieldMaxTransferBytes, or FieldMaxTenants
	// (the empty pointer) when the token reached its maximum number of
	// tenants.
	Field string
}

// Error implements error.
func (e *ScopeError) Error() string {
	if e.Field == FieldMaxTenants {
		return "provisioning: the provisioning token reached its maximum number of tenants"
	}
	return "provisioning: " + e.Field + " is outside the scope of the provisioning token"
}

// Is makes errors.Is(err, ErrScopeExceeded) true.
func (e *ScopeError) Is(target error) bool { return target == ErrScopeExceeded }

// RateLimitError reports the creation rate limit of a token. It matches
// [ErrRateLimited].
type RateLimitError struct {
	// RetryAfter is the time left before a creation is allowed again, for
	// the Retry-After header (at least one second).
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("provisioning: too many tenant creations, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

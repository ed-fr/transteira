package adminauth

import (
	"errors"
	"fmt"
	"time"
)

// Errors returned by the [Service]. Callers test them with errors.Is; the
// comment of each one gives the problem code it maps to. Any other error is
// an internal failure (500 internal-error) whose message never contains a
// password, a token, a TOTP secret or a code.
var (
	// ErrInvalid reports a malformed input (400 validation-failed). The
	// error is an *[InvalidError] naming the field.
	ErrInvalid = errors.New("adminauth: invalid input")
	// ErrInvalidCredentials reports a wrong username, password, TOTP code
	// or recovery code (401 invalid-credentials). It never tells which one
	// was wrong, nor whether the username exists.
	ErrInvalidCredentials = errors.New("adminauth: invalid credentials")
	// ErrUnauthenticated reports a missing, malformed, unknown, expired or
	// revoked session, a session of a disabled account, or a session whose
	// state does not open the operation (401 unauthenticated).
	ErrUnauthenticated = errors.New("adminauth: no valid admin session")
	// ErrForbidden reports an authenticated administrator whose role does
	// not allow the operation (403 forbidden). A tenant the administrator
	// is not attached to yields ErrNotFound instead (see
	// [RequireTenantAccess]).
	ErrForbidden = errors.New("adminauth: forbidden")
	// ErrReadOnlyRole reports an auditor, attached to the tenant, calling
	// an operation outside the reads open to its read-only role (403
	// read-only-role): every change, and every configuration read.
	ErrReadOnlyRole = errors.New("adminauth: read-only role")
	// ErrSetupTokenInvalid reports a missing or wrong setup token (403
	// setup-token-invalid).
	ErrSetupTokenInvalid = errors.New("adminauth: invalid setup token")
	// ErrSetupDone reports a setup attempted while an administrator exists
	// (409 setup-already-done).
	ErrSetupDone = errors.New("adminauth: setup already completed")
	// ErrNotFound reports an unknown administrator, an unknown, used or
	// expired activation link, or a tenant the caller is not attached to,
	// answered exactly like a missing tenant (404 not-found).
	ErrNotFound = errors.New("adminauth: not found")
	// ErrAlreadyExists reports a username already taken (409
	// already-exists).
	ErrAlreadyExists = errors.New("adminauth: username already taken")
	// ErrStateConflict reports an operation the current state does not
	// allow (409 state-conflict): see [ErrLastSuperAdmin], [ErrSelfAction],
	// [ErrNoPendingEnrollment], [ErrNotPromotable] and [ErrAccountDisabled],
	// which match it.
	ErrStateConflict = errors.New("adminauth: not allowed in the current state")
	// ErrRateLimited reports too many failed attempts (429 rate-limited).
	// The error is a *[RateLimitError] carrying the Retry-After delay.
	ErrRateLimited = errors.New("adminauth: too many attempts")
	// ErrNoClientIP reports a call without a valid client IP, which the
	// login limits need (500: the HTTP layer always provides one).
	ErrNoClientIP = errors.New("adminauth: no client ip")
	// ErrSSORequired reports a right password of a delegated admin or an
	// auditor attached to a tenant that enforces single sign-on (403
	// sso-required, threat T-292). It is only returned after the password
	// was verified, at the cost of any login.
	ErrSSORequired = errors.New("adminauth: single sign-on required")
	// ErrSSONotAvailable reports a single sign-on start for an e-mail
	// domain routed to no enabled configuration, unknown or disabled alike,
	// or whose provider cannot be reached (404 sso-not-available, T-296);
	// on the callback, a service without single sign-on.
	ErrSSONotAvailable = errors.New("adminauth: single sign-on not available")
	// ErrSSONotConfigured reports an account without activation link
	// (delivery none) asked for while one of its tenants has no enabled
	// single sign-on (409 sso-not-configured).
	ErrSSONotConfigured = errors.New("adminauth: single sign-on not configured")
	// ErrSSOFailed reports a failed single sign-on callback. The error is an
	// *[SSOError] carrying the reason of the sso_failed security event; the
	// HTTP layer redirects to the login page with a code of a closed list.
	ErrSSOFailed = errors.New("adminauth: single sign-on failed")
)

// Conflicts, each matching [ErrStateConflict] (409 state-conflict).
var (
	// ErrLastSuperAdmin reports an operation that would leave the instance
	// without a usable super admin (not disabled, password set, TOTP
	// enabled): deleting, disabling, demoting or resetting the last one.
	ErrLastSuperAdmin = fmt.Errorf("%w: the last usable super admin cannot be deleted, disabled, demoted or reset", ErrStateConflict)
	// ErrSelfAction reports an administrator deleting, disabling, demoting
	// or resetting their own account, which would lock them out.
	ErrSelfAction = fmt.Errorf("%w: an administrator cannot delete, disable, demote or reset their own account", ErrStateConflict)
	// ErrNoPendingEnrollment reports a TOTP confirmation without an
	// enrollment started, or whose pending secret expired (PendingTOTPTTL).
	ErrNoPendingEnrollment = fmt.Errorf("%w: no totp enrollment in progress", ErrStateConflict)
	// ErrNotPromotable reports a promotion to super admin of an account
	// that is not activated (no password) or has no TOTP enrolled: a super
	// admin must be able to sign in with both factors from the start.
	ErrNotPromotable = fmt.Errorf("%w: only an activated administrator with totp enabled can be promoted to super admin", ErrStateConflict)
	// ErrAccountDisabled reports a credentials reset of a disabled
	// account, whose activation link could not be used: enable it first.
	ErrAccountDisabled = fmt.Errorf("%w: the account is disabled", ErrStateConflict)
	// ErrSSOOnlyEnforced reports an activation link asked for a single
	// sign-on only account while one of its tenants enforces single
	// sign-on (threat T-292): such an account must never get a password.
	ErrSSOOnlyEnforced = fmt.Errorf("%w: no activation link for a single sign-on only account while single sign-on is enforced", ErrStateConflict)
)

// Fields named by an [InvalidError], as JSON pointers of the request
// bodies.
const (
	FieldUsername        = "/username"
	FieldEmail           = "/email"
	FieldPassword        = "/password"
	FieldNewPassword     = "/newPassword"
	FieldCurrentPassword = "/currentPassword"
	FieldCode            = "/code"
	FieldRecoveryCode    = "/recoveryCode"
	FieldRole            = "/role"
	FieldTenantIDs       = "/tenantIds"
	FieldActivationToken = "/activationToken"
)

// InvalidError reports a malformed input field. It matches [ErrInvalid].
type InvalidError struct {
	// Field is the JSON pointer of the field (FieldUsername...).
	Field string
}

// Error implements error; it never quotes the value.
func (e *InvalidError) Error() string { return "adminauth: invalid " + e.Field }

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// invalid returns an *InvalidError for field.
func invalid(field string) error { return &InvalidError{Field: field} }

// RateLimitError reports a lock of the login limits. It matches
// [ErrRateLimited].
type RateLimitError struct {
	// RetryAfter is the time left before the lock ends, for the
	// Retry-After header (at least one second).
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("adminauth: too many attempts, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// SSOError reports a failed single sign-on callback. It matches
// [ErrSSOFailed].
type SSOError struct {
	// Reason is the reason of the sso_failed security event, a value of a
	// closed list: securitylog.ReasonStateInvalid, ReasonTokenInvalid,
	// ReasonAccountUnknown, ReasonIdentityMismatch, ReasonMFAMissing or
	// ReasonIssuerError.
	Reason string
}

// Error implements error.
func (e *SSOError) Error() string { return "adminauth: single sign-on failed: " + e.Reason }

// Is makes errors.Is(err, ErrSSOFailed) true.
func (e *SSOError) Is(target error) bool { return target == ErrSSOFailed }

// retryAfter returns the delay until until, rounded up to the second, at
// least one second.
func retryAfter(until, now time.Time) time.Duration {
	d := (until.Sub(now) + time.Second - 1).Truncate(time.Second)
	return max(d, time.Second)
}

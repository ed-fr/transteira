package download

import (
	"errors"
	"fmt"
	"time"
)

// Errors returned by the [Service]. Callers test them with errors.Is; the
// comment of each one gives the HTTP status and problem code it maps to.
// Any other error is an internal failure (500 internal-error) whose message
// never contains a token, a password, an address or a file name.
var (
	// ErrNotFound reports a malformed or unknown download token, a token of
	// another tenant, or a file that is not a deliverable file of the
	// transfer (404 not-found).
	ErrNotFound = errors.New("download: not found")
	// ErrGone reports a known token whose transfer is expired, deleted,
	// rejected, past its deletion after the first download, or without any
	// deliverable file (410 transfer-gone).
	ErrGone = errors.New("download: transfer no longer available")
	// ErrMaxDownloads reports a transfer whose download limit
	// (store.Transfer.MaxDownloads) is reached: the download page, an
	// unlock, or a download start by a client not already counted (410
	// max-downloads-reached). A download already started by the client
	// stays served during the grace period (see the package documentation).
	ErrMaxDownloads = errors.New("download: download limit reached")
	// ErrDownloadLocked reports a password-protected transfer that this
	// browser has not unlocked: no valid grant in the cookie (401
	// download-locked).
	ErrDownloadLocked = errors.New("download: password required")
	// ErrWrongPassword reports a wrong transfer password while attempts
	// remain (401 transfer-password-invalid). The error is a
	// *[WrongPasswordError] carrying attemptsRemaining.
	ErrWrongPassword = errors.New("download: wrong transfer password")
	// ErrLocked reports a transfer or a client IP locked after too many
	// wrong passwords (429 transfer-locked). The error is a *[LockedError]
	// carrying the Retry-After delay.
	ErrLocked = errors.New("download: too many wrong passwords")
	// ErrInvalid reports a malformed password: longer than
	// MaxPasswordRunes characters or MaxPasswordBytes bytes, or not UTF-8
	// (400 validation-failed, field /password, code invalid-format).
	ErrInvalid = errors.New("download: invalid password")
	// ErrPasswordRequired reports an empty password. It also matches
	// ErrInvalid; test it first (400 validation-failed, field /password,
	// code required).
	ErrPasswordRequired = fmt.Errorf("%w: password required", ErrInvalid)
	// ErrTooManyStreams reports a file or archive request over the
	// concurrent stream limits (429 rate-limited). The error is a
	// *[TooManyStreamsError] carrying the Retry-After delay.
	ErrTooManyStreams = errors.New("download: too many concurrent downloads")
	// ErrNoClientIP reports an unlock or a download without a valid client
	// IP.
	// The HTTP layer always knows the client IP, so this is a programming
	// error; the attempt is refused (fail closed) before any password
	// check (500 internal-error).
	ErrNoClientIP = errors.New("download: client IP unknown")
	// ErrVerificationRequired reports a per-recipient link whose transfer
	// requires the recipient verification, used without a valid entry of
	// the recipient verification cookie for the link (401
	// recipient-verification-required). No password attempt is counted.
	ErrVerificationRequired = errors.New("download: recipient verification required")
	// ErrVerificationNotNeeded reports a recipient verification asked or
	// confirmed for a download on a link that needs none: a shared V1 link
	// or a transfer without the option, when no reply is possible either
	// (409 state-conflict).
	ErrVerificationNotNeeded = errors.New("download: no recipient verification for this link")
	// ErrReplyNotAllowed reports a reply (or a verification before a reply)
	// that the link does not allow: the tenant does not allow replies, the
	// link is a shared V1 link, the transfer was not sent by an internal
	// depositor (an invited external or a reply: no reply to a reply), or
	// its sender is now blocklisted or outside the internal domains of the
	// tenant (403 reply-not-allowed; threat model T-222, T-224, T-225).
	ErrReplyNotAllowed = errors.New("download: reply not allowed")
	// ErrRecipientVerificationRequired reports a reply without a valid entry
	// of the recipient verification cookie for the link, whatever the
	// options of the transfer (401 recipient-verification-required; P33).
	ErrRecipientVerificationRequired = errors.New("download: recipient verification required before a reply")
	// ErrNoChallenge reports a code submitted for a link without a pending
	// code: never requested, already used, expired, or replaced by a newer
	// one being exhausted (409 state-conflict).
	ErrNoChallenge = errors.New("download: no pending verification code")
	// ErrVerificationExhausted reports a code invalidated after too many
	// wrong attempts, including by this wrong code (410
	// verification-exhausted).
	ErrVerificationExhausted = errors.New("download: verification code exhausted")
	// ErrWrongCode reports a wrong verification code while attempts remain
	// (422 verification-code-invalid). The error is a *[WrongCodeError]
	// carrying attemptsRemaining.
	ErrWrongCode = errors.New("download: wrong verification code")
	// ErrInvalidCode reports a code that is not 6 ASCII digits (400
	// validation-failed, field /code, code invalid-format); no attempt is
	// spent.
	ErrInvalidCode = errors.New("download: malformed verification code")
	// ErrRateLimited reports a code request over a rate limit, or refused by
	// a full mail queue, or an abuse report over a rate limit (429
	// rate-limited). The error is a *[RateLimitError] carrying the
	// Retry-After delay.
	ErrRateLimited = errors.New("download: rate limit reached")
	// ErrMailUnavailable reports a code that cannot be sent: no SMTP
	// settings for the tenant, mail queue shut down or SMTP circuit open
	// (503 mail-unavailable).
	ErrMailUnavailable = errors.New("download: verification mail unavailable")
	// ErrInvalidCategory reports an abuse report whose category is not an
	// OpenAPI AbuseReportCategory (400 validation-failed, field /category,
	// code invalid-value).
	ErrInvalidCategory = errors.New("download: unknown abuse report category")
	// ErrInvalidMessage reports an abuse report whose message is not UTF-8
	// or is longer than MaxReportMessageRunes characters once sanitized
	// (400 validation-failed, field /message, code invalid-format).
	ErrInvalidMessage = errors.New("download: invalid abuse report message")
)

// WrongCodeError reports a wrong verification code. It matches
// [ErrWrongCode].
type WrongCodeError struct {
	// Remaining is the number of attempts left (at least 1), the
	// attemptsRemaining member of the problem.
	Remaining int
}

// Error implements error.
func (e *WrongCodeError) Error() string {
	return fmt.Sprintf("download: wrong verification code, %d attempt(s) remaining", e.Remaining)
}

// Is makes errors.Is(err, ErrWrongCode) true.
func (e *WrongCodeError) Is(target error) bool { return target == ErrWrongCode }

// RateLimitError reports a code request refused by a rate limit or by the
// mail queue, or an abuse report refused by a rate limit. It matches
// [ErrRateLimited].
type RateLimitError struct {
	// RetryAfter is the Retry-After hint.
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("download: rate limit reached, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// WrongPasswordError reports a wrong transfer password. It matches
// [ErrWrongPassword].
type WrongPasswordError struct {
	// Remaining is the number of attempts left before a lock (at least 1),
	// the attemptsRemaining member of the problem.
	Remaining int
}

// Error implements error.
func (e *WrongPasswordError) Error() string {
	return fmt.Sprintf("download: wrong transfer password, %d attempt(s) remaining", e.Remaining)
}

// Is makes errors.Is(err, ErrWrongPassword) true.
func (e *WrongPasswordError) Is(target error) bool { return target == ErrWrongPassword }

// LockedError reports a lock after too many wrong passwords. It matches
// [ErrLocked].
type LockedError struct {
	// RetryAfter is how long the lock still lasts, rounded up to the
	// second (at least one second), for the Retry-After header and the
	// retryAfterSeconds member of the problem.
	RetryAfter time.Duration
}

// Error implements error.
func (e *LockedError) Error() string {
	return fmt.Sprintf("download: locked after too many wrong passwords, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrLocked) true.
func (e *LockedError) Is(target error) bool { return target == ErrLocked }

// TooManyStreamsError reports a request over the concurrent stream
// limits. It matches [ErrTooManyStreams].
type TooManyStreamsError struct {
	// RetryAfter is the Retry-After hint (StreamRetryAfter).
	RetryAfter time.Duration
}

// Error implements error.
func (e *TooManyStreamsError) Error() string {
	return fmt.Sprintf("download: too many concurrent downloads, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrTooManyStreams) true.
func (e *TooManyStreamsError) Is(target error) bool { return target == ErrTooManyStreams }

// retryAfter returns the delay until until, rounded up to the second and
// at least one second.
func retryAfter(until, now time.Time) time.Duration {
	d := until.Sub(now)
	return max(((d+time.Second-1)/time.Second)*time.Second, time.Second)
}

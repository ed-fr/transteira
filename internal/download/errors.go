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
)

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

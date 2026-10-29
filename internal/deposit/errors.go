package deposit

import (
	"errors"
	"fmt"
	"time"
)

// Errors returned by the [Service]. Callers test them with errors.Is; the
// comment of each one gives the HTTP status it maps to. Any other error is
// an internal failure (500) whose message never contains an address, a
// token or a code.
var (
	// ErrInvalid reports a malformed input (400 validation-failed). The
	// error is an *[InvalidError] naming the field.
	ErrInvalid = errors.New("deposit: invalid input")
	// ErrForbidden reports a depositor who may not deposit or invite (403
	// deposit-not-allowed). It is deliberately generic: blocklist, network
	// rule and invitation mismatches look the same to the client.
	ErrForbidden = errors.New("deposit: not allowed")
	// ErrInvitationGone reports an invitation that exists but is expired or
	// revoked (410 invitation-gone).
	ErrInvitationGone = errors.New("deposit: invitation expired or revoked")
	// ErrReplyGone reports that the source transfer of a reply
	// ([Service.OpenReply]) expired, or that it or the recipient link no
	// longer exists in the tenant (410 transfer-gone).
	ErrReplyGone = errors.New("deposit: transfer replied to is gone")
	// ErrRateLimited reports a rate limit (429). The error is a
	// *[RateLimitError] carrying a Retry-After hint.
	ErrRateLimited = errors.New("deposit: rate limited")
	// ErrMailUnavailable reports that no mail can be sent for the tenant:
	// SMTP settings missing or unusable, or the mail queue shut down (503).
	ErrMailUnavailable = errors.New("deposit: mail unavailable")
	// ErrNotFound reports an unknown verification challenge or invitation
	// token, including one of another tenant (404).
	ErrNotFound = errors.New("deposit: not found")
	// ErrChallengeGone reports a verification challenge that is expired,
	// already used or invalidated after too many wrong codes (410
	// verification-exhausted).
	ErrChallengeGone = errors.New("deposit: verification challenge expired or exhausted")
	// ErrWrongCode reports a wrong verification code while attempts remain
	// (422 verification-code-invalid). The error is a *[WrongCodeError].
	ErrWrongCode = errors.New("deposit: wrong verification code")
	// ErrUnauthenticated reports a missing, malformed, unknown, ended or
	// expired session token, or the session of a revoked invitation (401).
	ErrUnauthenticated = errors.New("deposit: no valid deposit session")
)

// errDecoy reports, inside the package only, a depositor from outside who
// fails the remote rule while the tenant allows the deposit from outside
// (see [Service.checkDepositor]). [Service.Start] answers it with a decoy
// challenge and [Service.Confirm] with the wrong-code outcome; it never
// reaches the caller. It wraps ErrForbidden so that, were it ever to leak,
// it would still be answered as a refusal.
var errDecoy = fmt.Errorf("%w: decoy challenge", ErrForbidden)

// Fields named by an [InvalidError], as JSON pointers of the request
// bodies.
const (
	FieldEmail    = "/email"
	FieldCode     = "/code"
	FieldMessage  = "/message"
	FieldLanguage = "/language"
)

// InvalidError reports a malformed input field. It matches [ErrInvalid].
type InvalidError struct {
	// Field is the JSON pointer of the field (FieldEmail...).
	Field string
}

// Error implements error; it never quotes the value.
func (e *InvalidError) Error() string { return "deposit: invalid " + e.Field }

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// invalid returns an *InvalidError for field.
func invalid(field string) error { return &InvalidError{Field: field} }

// RateLimitError reports a rate limit. It matches [ErrRateLimited].
type RateLimitError struct {
	// RetryAfter is when the client may try again, for the Retry-After
	// header. For the code limits it is an upper bound (the window).
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("deposit: rate limited, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// WrongCodeError reports a wrong verification code. It matches
// [ErrWrongCode].
type WrongCodeError struct {
	// Remaining is the number of attempts left (at least 1), the
	// attemptsRemaining member of the problem.
	Remaining int
}

// Error implements error.
func (e *WrongCodeError) Error() string {
	return fmt.Sprintf("deposit: wrong verification code, %d attempt(s) remaining", e.Remaining)
}

// Is makes errors.Is(err, ErrWrongCode) true.
func (e *WrongCodeError) Is(target error) bool { return target == ErrWrongCode }

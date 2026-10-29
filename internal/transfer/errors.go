package transfer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/store"
)

// Errors returned by the [Service]. Callers test them with errors.Is; the
// comment of each one gives the HTTP status and problem code it maps to.
// Any other error is an internal failure (500) whose message never contains
// an address, a password or a file name.
var (
	// ErrInvalid reports a malformed request (400 validation-failed). The
	// error is a *[ValidationError] listing every invalid field.
	ErrInvalid = errors.New("transfer: invalid request")
	// ErrForbidden reports a sender who may no longer deposit (403
	// deposit-not-allowed): blocklisted address or domain, client IP or
	// domain outside the internal rule, or invitation no longer active. It
	// is deliberately generic; the reason goes to the security log only.
	ErrForbidden = errors.New("transfer: deposit not allowed")
	// ErrTooLarge reports a declared total above the per-transfer limit of
	// the tenant (413 transfer-too-large). The error is a *[TooLargeError]
	// carrying the limit.
	ErrTooLarge = errors.New("transfer: transfer too large")
	// ErrQuotaExceeded reports a transfer that does not fit in the storage
	// quota of the tenant (507 quota-exceeded).
	ErrQuotaExceeded = errors.New("transfer: storage quota exceeded")
	// ErrNotFound reports an unknown transfer, including a transfer of
	// another tenant or of another sender (404 not-found).
	ErrNotFound = errors.New("transfer: not found")
	// ErrConflict reports an operation not allowed in the current state of
	// the transfer (409 state-conflict): canceling or finalizing a transfer
	// that is no longer uploading, finalizing a transfer without files or
	// with a file whose key was destroyed by an interrupted cancellation,
	// or replaying an idempotency key of the same address under another
	// invitation.
	ErrConflict = errors.New("transfer: operation not allowed in the current state")
	// ErrIdempotencyMismatch reports an Idempotency-Key the sender already
	// used in the last 24 hours for a different request (409
	// state-conflict). It matches ErrConflict.
	ErrIdempotencyMismatch = fmt.Errorf("%w: idempotency key reused with a different request", ErrConflict)
	// ErrRateLimited reports a sender who already has the maximum number
	// of unfinished transfers (429 rate-limited, with Retry-After). The
	// error is a *[RateLimitError].
	ErrRateLimited = errors.New("transfer: too many unfinished transfers")
	// ErrBusy reports an upload of one of the files in progress while
	// canceling or finalizing (409 state-conflict). It matches ErrConflict.
	ErrBusy = fmt.Errorf("%w: an upload of the transfer is in progress", ErrConflict)
	// ErrIncomplete reports files whose upload is not complete at
	// finalization (409 upload-incomplete). The error is a *[FilesError]
	// listing them.
	ErrIncomplete = errors.New("transfer: upload incomplete")
	// ErrChecksumMismatch reports files whose computed SHA-256 differs from
	// the expectedSha256 declared at creation (409 checksum-mismatch). The
	// error is a *[FilesError] listing them.
	ErrChecksumMismatch = errors.New("transfer: checksum mismatch")
	// ErrBlockedFile reports a file whose SHA-256 is on the tenant blocklist
	// (403 blocked-file, threat T-27).
	ErrBlockedFile = errors.New("transfer: file refused by the blocklist")
	// ErrConfidentialityRule reports a transfer that breaks a rule of its
	// confidentiality level (422 confidentiality-rule-violated, spec 8.3).
	// The error is a *[RuleError] listing every broken rule.
	ErrConfidentialityRule = errors.New("transfer: confidentiality rule violated")
	// ErrRecipientDomainRefused reports recipients refused by the recipient
	// domain rules of the tenant (403 recipient-domain-refused, spec 8.4).
	// The error is a *[RuleError] naming every refused recipient. It is a
	// policy refusal: audited, never written to the security log.
	ErrRecipientDomainRefused = errors.New("transfer: recipient domain refused")
	// ErrAbuseBlocked reports a creation refused because it exceeds an
	// abuse detection threshold of the tenant set to block (403
	// abuse-threshold-blocked, CLAUDE.md section 15). The error is an
	// *[AbuseBlockedError] naming the rule. It is a policy refusal: audited
	// and alerted by the abuse detector, never written to the security log.
	ErrAbuseBlocked = errors.New("transfer: abuse threshold exceeded")
)

// AbuseBlockedError reports a creation refused by the abuse detection. It
// matches [ErrAbuseBlocked]. It names the rule only: the values and
// thresholds stay with the admins (audit and alerts), never in the answer.
type AbuseBlockedError struct {
	// Rule is the exceeded rule (daily_bytes, daily_transfers, recipients
	// or external_quota).
	Rule store.AbuseRule
}

// Error implements error.
func (e *AbuseBlockedError) Error() string {
	return "transfer: abuse threshold exceeded (" + string(e.Rule) + ")"
}

// Is makes errors.Is(err, ErrAbuseBlocked) true.
func (e *AbuseBlockedError) Is(target error) bool { return target == ErrAbuseBlocked }

// JSON pointers of the request fields named by a [FieldError]. The file
// fields are indexed: /files/<i>/name and so on, /recipients/<i> likewise.
// FieldIdempotencyKey names the Idempotency-Key header, not a body field.
const (
	FieldSenderEmail = "/senderEmail"
	FieldRecipients  = "/recipients"
	FieldMessage     = "/message"
	FieldExpiryDays  = "/expiryDays"
	FieldPassword    = "/password"
	FieldLanguage    = "/language"
	FieldFiles       = "/files"
	// FieldMaxDownloads, FieldConfidentialityLevel and
	// FieldRecipientVerification are the transfer options of version 1.1.
	FieldMaxDownloads          = "/maxDownloads"
	FieldConfidentialityLevel  = "/confidentialityLevel"
	FieldRecipientVerification = "/recipientVerification"
	FieldIdempotencyKey        = "Idempotency-Key"
)

// Codes of a [FieldError] (the code member of the validation-failed
// problem's errors).
const (
	// CodeRequired: the field is missing or empty.
	CodeRequired = "required"
	// CodeInvalidFormat: the value is malformed.
	CodeInvalidFormat = "invalid-format"
	// CodeInvalidEmail: the value is not an acceptable mail address.
	CodeInvalidEmail = "invalid-email"
	// CodeInvalidFileName: the file name is refused by the file name policy
	// (decision P8).
	CodeInvalidFileName = "invalid-file-name"
	// CodeNotAllowed: the value is not one of the accepted values (a
	// maxDownloads outside 1 to store.MaxDownloadsLimit included), or the
	// field is not accepted in this context (senderEmail with a session).
	CodeNotAllowed = "not-allowed"
	// CodeTooLong: the text exceeds its maximum length.
	CodeTooLong = "too-long"
	// CodeTooMany: the list exceeds its maximum number of items.
	CodeTooMany = "too-many"
	// CodeDuplicate: the item repeats an earlier one.
	CodeDuplicate = "duplicate"
	// CodeInternalOnly: the recipient is outside the internal domains of
	// the tenant, which the confidentiality level requires
	// (confidentiality-rule-violated only).
	CodeInternalOnly = "internal-only"
	// CodeMaxExceeded: maxDownloads exceeds the cap of the confidentiality
	// level (confidentiality-rule-violated only).
	CodeMaxExceeded = "max-exceeded"
	// CodeDomainDenied: the recipient domain is refused by the recipient
	// domain rules (recipient-domain-refused only).
	CodeDomainDenied = "domain-denied"
)

// FieldError is one invalid field of a request.
type FieldError struct {
	// Pointer is the JSON pointer of the field (FieldMessage,
	// "/files/0/name"...), or FieldIdempotencyKey.
	Pointer string
	// Code is the reason (CodeRequired...).
	Code string
	// Allowed optionally lists the accepted values (the validities a
	// confidentiality level allows, with CodeNotAllowed on FieldExpiryDays);
	// nil otherwise.
	Allowed []int
}

// ValidationError lists the invalid fields of a request, in the order of
// the request. It matches [ErrInvalid].
type ValidationError struct {
	// Fields are the invalid fields, at least one.
	Fields []FieldError
}

// Error implements error; it names the fields, never their values.
func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Pointer + " (" + f.Code + ")"
	}
	return "transfer: invalid request: " + strings.Join(parts, ", ")
}

// Is makes errors.Is(err, ErrInvalid) true.
func (e *ValidationError) Is(target error) bool { return target == ErrInvalid }

// TooLargeError reports a transfer above the per-transfer limit. It matches
// [ErrTooLarge].
type TooLargeError struct {
	// MaxTransferBytes is the limit of the tenant, the maxTransferBytes
	// member of the problem.
	MaxTransferBytes int64
}

// Error implements error.
func (e *TooLargeError) Error() string {
	return fmt.Sprintf("transfer: transfer too large (limit %d bytes)", e.MaxTransferBytes)
}

// Is makes errors.Is(err, ErrTooLarge) true.
func (e *TooLargeError) Is(target error) bool { return target == ErrTooLarge }

// FilesError reports the files that block a finalization. It matches its
// Kind: [ErrIncomplete] or [ErrChecksumMismatch].
type FilesError struct {
	// Kind is ErrIncomplete or ErrChecksumMismatch.
	Kind error
	// FileIDs are the identifiers of the files concerned ("fil_" + ULID),
	// by position: the files member of the problem.
	FileIDs []string
}

// Error implements error.
func (e *FilesError) Error() string {
	return fmt.Sprintf("%v: %d file(s)", e.Kind, len(e.FileIDs))
}

// Is makes errors.Is(err, e.Kind) true.
func (e *FilesError) Is(target error) bool { return target == e.Kind }

// RateLimitError reports a rate limit. It matches [ErrRateLimited].
type RateLimitError struct {
	// RetryAfter is the hint for the Retry-After header.
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("transfer: too many unfinished transfers, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// RuleError lists the fields of a creation request refused by a tenant
// policy, in the order the checks run. It matches its Kind:
// [ErrConfidentialityRule] or [ErrRecipientDomainRefused].
type RuleError struct {
	// Kind is ErrConfidentialityRule or ErrRecipientDomainRefused.
	Kind error
	// Fields are the refused fields, at least one.
	Fields []FieldError
}

// Error implements error; it names the fields, never their values.
func (e *RuleError) Error() string {
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Pointer + " (" + f.Code + ")"
	}
	return fmt.Sprintf("%v: %s", e.Kind, strings.Join(parts, ", "))
}

// Is makes errors.Is(err, e.Kind) true.
func (e *RuleError) Is(target error) bool { return target == e.Kind }

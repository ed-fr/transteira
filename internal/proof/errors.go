package proof

import (
	"errors"
	"fmt"
	"time"
)

// Errors of the [Service]. Callers test them with errors.Is; the comment of
// each one gives the HTTP answer it maps to. The administrator checks of
// [Service.TenantProof] return the errors of package adminauth unchanged
// (adminauth.ErrUnauthenticated, adminauth.ErrNotFound).
var (
	// ErrInvalid reports a malformed parameter (400 validation-failed). The
	// error is an *[InvalidError] naming the parameter.
	ErrInvalid = errors.New("proof: invalid input")
	// ErrNotFound reports a transfer the caller cannot reach (404
	// not-found): for the sender, any transfer that is not one of theirs
	// in progress in the tenant, whatever the reason; for an
	// administrator, an unknown tenant.
	ErrNotFound = errors.New("proof: transfer not found")
	// ErrNotAvailable reports a proof that does not exist: the fact did
	// not happen yet, the retention is over or the proof was erased (404
	// proof-not-available).
	ErrNotAvailable = errors.New("proof: proof not available")
	// ErrRateLimited reports too many proof requests from one client (429
	// rate-limited). The error is a *[RateLimitError].
	ErrRateLimited = errors.New("proof: rate limited")
)

// Errors of the [Signer].
var (
	// ErrNoActiveKey reports a retirement while no key is active.
	ErrNoActiveKey = errors.New("proof: no active signing key")
	// ErrKeyMismatch reports a stored private key that does not match its
	// public key (corrupted or substituted row).
	ErrKeyMismatch = errors.New("proof: signing key does not match its public key")
	// ErrNotReady reports a statement asked for a fact that is not
	// recorded in the transaction (transfer not available, no first
	// download, link not complete): a programming error of the caller.
	ErrNotReady = errors.New("proof: fact not recorded")
)

// Errors of [Verify]. Every error of Verify matches exactly one of them.
var (
	// ErrInvalidProof reports a document that is not a well-formed proof:
	// not a PDF of the writer, missing or unexpected attachments,
	// statement that is not canonical or does not follow the schema.
	ErrInvalidProof = errors.New("proof: invalid proof document")
	// ErrUnknownKey reports a statement signed by a key that is not in the
	// published list.
	ErrUnknownKey = errors.New("proof: unknown signing key")
	// ErrBadSignature reports a signature that does not verify.
	ErrBadSignature = errors.New("proof: bad signature")
	// ErrKeyRetired reports a statement whose fact is later than the
	// retirement of its signing key: it cannot have been signed while the
	// key was active (T-300).
	ErrKeyRetired = errors.New("proof: statement postdates the retirement of its key")
)

// Parameters named by an [InvalidError] (query parameters of the
// operations getMyTransferProof and getTenantTransferProof).
const (
	ParamKind      = "kind"
	ParamRecipient = "recipient"
)

// InvalidError reports a malformed parameter. It matches [ErrInvalid].
type InvalidError struct {
	// Param is the parameter (ParamKind, ParamRecipient).
	Param string
}

// Error implements error; it never quotes the value.
func (e *InvalidError) Error() string { return "proof: invalid " + e.Param }

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// RateLimitError reports a rate limit. It matches [ErrRateLimited].
type RateLimitError struct {
	// RetryAfter is when the client may try again (Retry-After header).
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("proof: rate limited, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

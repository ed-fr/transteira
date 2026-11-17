package secret

import (
	"errors"
	"time"
)

// JSON pointers of the fields of a creation and of a reveal (OpenAPI
// SecretCreate and SecretReveal), and the name of the list cursor.
const (
	FieldEncryptedText        = "/encryptedText"
	FieldVerifier             = "/verifier"
	FieldKeyVerifier          = "/keyVerifier"
	FieldPassphraseKDF        = "/passphrase/kdf" //nolint:gosec // G101: a JSON pointer, not a credential.
	FieldPassphraseIterations = "/passphrase/iterations"
	FieldPassphraseSalt       = "/passphrase/salt"
	FieldExpiresIn            = "/expiresIn"
	FieldDelivery             = "/delivery"
	FieldRecipient            = "/recipient"
	FieldFile                 = "/file"
	FieldFileSize             = "/file/size"
	FieldFileMetadata         = "/file/encryptedMetadata"
	FieldSenderEmail          = "/senderEmail"
	FieldSecretToken          = "/secretToken"
	FieldFragmentKey          = "/fragmentKey"
	FieldKeyProof             = "/keyProof"
	FieldProof                = "/proof"
	// FieldLink is the pasted link of a lookup (OpenAPI SecretLookup, since
	// 2.3).
	FieldLink = "/link"
	// FieldCategory and FieldMessage are the members of an abuse report
	// (OpenAPI AbuseReportCreate, since 2.3 on the express secrets).
	FieldCategory = "/category"
	FieldMessage  = "/message"
	// FieldGrant is the header carrying the one-time file grant of a
	// download.
	FieldGrant = "TransTeira-Secret-Grant"
	// FieldCursor is the cursor query parameter of the list.
	FieldCursor = "cursor"
)

// Field error codes.
const (
	// CodeRequired: the field is missing or empty.
	CodeRequired = "required"
	// CodeInvalidFormat: the value does not match its pattern.
	CodeInvalidFormat = "invalid-format"
	// CodeInvalidEmail: the value is not an acceptable mail address.
	CodeInvalidEmail = "invalid-email"
	// CodeTooLong: the value is longer than its limit.
	CodeTooLong = "too-long"
	// CodeNotAllowed: the value is not one of the accepted ones, or the
	// field is not accepted here.
	CodeNotAllowed = "not-allowed"
	// CodeDomainDenied: the recipient is refused by the recipient domain
	// rules or the blocklist of the tenant (as transfer.CodeDomainDenied).
	CodeDomainDenied = "domain-denied"
)

// Errors of the service. The HTTP layer maps each one to its problem code.
var (
	// ErrForbidden reports a creator that may not create a secret: not
	// eligible (the reason is in the security log), or a reply or drop link
	// session (deposit-not-allowed).
	ErrForbidden = errors.New("secret: creation not allowed")
	// ErrNotFound reports an unknown secret, link or token, one of another
	// tenant or creator, and a pending secret on the recipient side.
	ErrNotFound = errors.New("secret: not found")
	// ErrDisabled reports the module disabled for the tenant.
	ErrDisabled = errors.New("secret: secrets are disabled")
	// ErrEmailNotAllowed reports an e-mail delivery while the tenant
	// forbids it, and any creation by an invited external then.
	ErrEmailNotAllowed = errors.New("secret: e-mail delivery not allowed")
	// ErrPassphraseRequired reports an e-mail delivery without passphrase
	// while the tenant requires one.
	ErrPassphraseRequired = errors.New("secret: passphrase required for the e-mail delivery")
	// ErrFileNotAllowed reports a file while the tenant forbids them.
	ErrFileNotAllowed = errors.New("secret: file not allowed")
	// ErrQuotaExceeded reports a declared file that does not fit in the
	// storage quota of the tenant (quota-exceeded).
	ErrQuotaExceeded = errors.New("secret: storage quota exceeded")
	// ErrConflict reports a creator operation the state of the secret does
	// not allow (state-conflict): a file upload to a secret that is not
	// pending, has no declared file or has it already.
	ErrConflict = errors.New("secret: state conflict")
	// ErrRecipientRefused reports the recipient of an e-mail secret refused
	// by the recipient domain rules or the blocklist of the tenant
	// (recipient-domain-refused, field FieldRecipient CodeDomainDenied).
	ErrRecipientRefused = errors.New("secret: recipient refused")
	// ErrMailUnavailable reports a send call while the tenant has no SMTP
	// settings (mail-unavailable): the secret stays pending.
	ErrMailUnavailable = errors.New("secret: mail unavailable")
	// ErrExpressDisabled reports an express secret creation or reading
	// while the express service is closed (since 2.3, 403
	// express-secrets-disabled): the instance kill switch
	// (Options.ExpressKillSwitch) for every express secret, or the
	// anonymous mode of the tenant off (tenant.ExpressSettings.Enabled)
	// for an anonymous creation and the reading of an anonymous express
	// secret.
	ErrExpressDisabled = errors.New("secret: express secrets are disabled")
	// ErrExpressLimit reports an anonymous express secret creation while
	// the tenant holds its maximum of live express secrets
	// (tenant.ExpressSettings.MaxPending; since 2.3, 429
	// express-secret-limit-reached, without Retry-After).
	ErrExpressLimit = errors.New("secret: too many live express secrets")
	// ErrExpressTokenNotAllowed reports an express secret creation with an
	// API token that is not allowed for them (store.APIToken.ExpressAllowed;
	// since 2.3, 403 express-token-not-allowed).
	ErrExpressTokenNotAllowed = errors.New("secret: api token not allowed for express secrets")
	// ErrTokenInvalid reports an express secret creation whose API token
	// was revoked or expired between its authentication and the creation
	// transaction (since 2.3, 401 invalid-credentials, as the token
	// middleware answers such a token; written as api_token_invalid).
	ErrTokenInvalid = errors.New("secret: api token unknown, revoked or expired")
	// ErrTenantInSetup reports an express secret creation on a tenant still
	// being configured (since 2.3, 503 tenant-in-setup). The HTTP layer
	// refuses such a request first; the store checks the setup state again
	// in its creation transaction.
	ErrTenantInSetup = errors.New("secret: tenant in setup")
)

// FieldError is one invalid field of a request.
type FieldError struct {
	// Pointer is the JSON pointer of the field (or the parameter name).
	Pointer string
	// Code is the field error code.
	Code string
	// Allowed lists the accepted values, when there is a closed list.
	Allowed []string
}

// ValidationError reports a request that breaks the rules of the OpenAPI
// schema (validation-failed).
type ValidationError struct {
	// Fields are the invalid fields, in the order of the request.
	Fields []FieldError
}

// Error implements error.
func (e *ValidationError) Error() string { return "secret: invalid request" }

// FormatError reports a sealed value whose framing fails a keyless check
// the schema cannot express (secret-format-invalid).
type FormatError struct {
	// Fields are the malformed sealed values; none for an uploaded file
	// body.
	Fields []FieldError
}

// Error implements error.
func (e *FormatError) Error() string { return "secret: malformed sealed content" }

// DurationError reports a duration the tenant does not offer
// (secret-duration-not-offered).
type DurationError struct {
	// Allowed are the durations the tenant offers.
	Allowed []string
}

// Error implements error.
func (e *DurationError) Error() string { return "secret: duration not offered" }

// FileTooLargeError reports a file larger than the limit of the tenant
// (secret-file-too-large).
type FileTooLargeError struct {
	// MaxBytes is the limit of the tenant.
	MaxBytes int64
}

// Error implements error.
func (e *FileTooLargeError) Error() string { return "secret: file too large" }

// LimitError reports a creator that reached its open secrets or its daily
// creations (secret-limit-reached).
type LimitError struct {
	// RetryAfter is the delay to announce, 0 for none (the open secrets
	// free up at no predictable time).
	RetryAfter time.Duration
}

// Error implements error.
func (e *LimitError) Error() string { return "secret: creator limit reached" }

// RateLimitError reports a client over the rate limits of the links
// (rate-limited).
type RateLimitError struct {
	// RetryAfter is the delay before the next allowed call.
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimitError) Error() string { return "secret: rate limit reached" }

// GoneError reports a secret that ended (secret-gone).
type GoneError struct {
	// Reason is the API reason: ReasonRead, ReasonExpired, ReasonDeleted
	// or ReasonLocked.
	Reason string
}

// Error implements error.
func (e *GoneError) Error() string { return "secret: gone (" + e.Reason + ")" }

// ProofError reports a wrong reveal proof (secret-proof-invalid).
type ProofError struct {
	// Counted is false for a wrong key proof (not counted against the
	// secret), true for a wrong passphrase proof.
	Counted bool
	// Remaining is the number of attempts left when Counted (at least 1:
	// the fifth failure answers a *GoneError with ReasonLocked).
	Remaining int
}

// Error implements error.
func (e *ProofError) Error() string { return "secret: wrong proof" }

// API reasons of a *GoneError (the reason member of secret-gone).
const (
	ReasonRead    = "read"
	ReasonExpired = "expired"
	ReasonDeleted = "deleted"
	ReasonLocked  = "locked"
)

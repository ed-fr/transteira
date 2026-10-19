package problem

import "net/http"

// Code is a stable, machine-readable error code. Its values mirror the
// ProblemCode enumeration of api/openapi.yaml and are documented in
// docs/api/errors.md.
type Code string

// Error codes, one per value of the ProblemCode enumeration of the OpenAPI
// specification.
const (
	// CodeValidationFailed means the request is malformed or a field is invalid.
	CodeValidationFailed Code = "validation-failed"
	// CodeUnauthenticated means credentials are missing, expired or invalid.
	CodeUnauthenticated Code = "unauthenticated"
	// CodeInvalidCredentials means a wrong password, TOTP code or API token was supplied.
	CodeInvalidCredentials Code = "invalid-credentials" //nolint:gosec // G101 false positive: an error code, not a credential.
	// CodeForbidden means the caller is authenticated but not allowed.
	CodeForbidden Code = "forbidden"
	// CodeCSRFInvalid means the CSRF token is missing or invalid.
	CodeCSRFInvalid Code = "csrf-invalid"
	// CodeDepositNotAllowed is the generic refusal of a public deposit; the
	// precise reason (IP range, domain, blocklist) is only in the security log.
	CodeDepositNotAllowed Code = "deposit-not-allowed"
	// CodeIPNotAllowed means an API token was used from outside its allowed CIDRs.
	CodeIPNotAllowed Code = "ip-not-allowed"
	// CodeBlockedFile means a file hash is on the tenant blocklist.
	CodeBlockedFile Code = "blocked-file"
	// CodeInvitationNotAllowed means the caller may not issue invitations.
	CodeInvitationNotAllowed Code = "invitation-not-allowed"
	// CodeInvitationGone means the invitation expired, was revoked or already used.
	CodeInvitationGone Code = "invitation-gone"
	// CodeVerificationCodeInvalid means the email verification code is wrong.
	CodeVerificationCodeInvalid Code = "verification-code-invalid"
	// CodeVerificationExhausted means the verification code was invalidated after too many attempts.
	CodeVerificationExhausted Code = "verification-exhausted"
	// CodeNotFound means the resource does not exist or is outside the caller scope.
	CodeNotFound Code = "not-found"
	// CodeTransferGone means the transfer expired or was deleted.
	CodeTransferGone Code = "transfer-gone"
	// CodeDownloadLocked means the transfer is password protected and not unlocked.
	CodeDownloadLocked Code = "download-locked"
	// CodeTransferPasswordInvalid means the transfer password is wrong.
	CodeTransferPasswordInvalid Code = "transfer-password-invalid"
	// CodeTransferLocked means too many wrong transfer passwords were tried.
	CodeTransferLocked Code = "transfer-locked"
	// CodeStateConflict means the operation is not allowed in the current state.
	CodeStateConflict Code = "state-conflict"
	// CodeAlreadyExists means a resource with the same unique key exists.
	CodeAlreadyExists Code = "already-exists"
	// CodeUploadIncomplete means some files of the transfer are not fully uploaded.
	CodeUploadIncomplete Code = "upload-incomplete"
	// CodeChecksumMismatch means a file checksum does not match the declared one.
	CodeChecksumMismatch Code = "checksum-mismatch"
	// CodeTransferTooLarge means the transfer exceeds the per-transfer size limit.
	CodeTransferTooLarge Code = "transfer-too-large"
	// CodePayloadTooLarge means the request body is too large.
	CodePayloadTooLarge Code = "payload-too-large"
	// CodeUnsupportedMediaType means the request content type is not supported.
	CodeUnsupportedMediaType Code = "unsupported-media-type"
	// CodeQuotaExceeded means the tenant storage quota is reached.
	CodeQuotaExceeded Code = "quota-exceeded"
	// CodeRateLimited means too many requests were made.
	CodeRateLimited Code = "rate-limited"
	// CodeMaintenance means maintenance mode is active.
	CodeMaintenance Code = "maintenance"
	// CodeUnknownTenant means the Host header matches no tenant.
	CodeUnknownTenant Code = "unknown-tenant"
	// CodeSetupAlreadyDone means the first-run setup was already completed.
	CodeSetupAlreadyDone Code = "setup-already-done"
	// CodeSetupTokenInvalid means the first-run setup token is invalid.
	CodeSetupTokenInvalid Code = "setup-token-invalid"
	// CodeNewMasterKeyMissing means no new master key is configured for rotation.
	CodeNewMasterKeyMissing Code = "new-master-key-missing"
	// CodeInternalError means an unexpected server-side error occurred.
	CodeInternalError Code = "internal-error"
)

// TypeBaseURI is the prefix of every problem type URI; the code is appended
// as the fragment.
const TypeBaseURI = "https://github.com/ed-fr/transteira/blob/main/docs/api/errors.md#"

// Definition holds the default HTTP status and English title of a Code.
type Definition struct {
	// Status is the default HTTP status code.
	Status int
	// Title is the default English title.
	Title string
}

// catalog maps every known Code to its default definition.
var catalog = map[Code]Definition{
	CodeValidationFailed:        {http.StatusBadRequest, "Invalid request"},
	CodeUnauthenticated:         {http.StatusUnauthorized, "Authentication required"},
	CodeInvalidCredentials:      {http.StatusUnauthorized, "Invalid credentials"},
	CodeForbidden:               {http.StatusForbidden, "Forbidden"},
	CodeCSRFInvalid:             {http.StatusForbidden, "Invalid CSRF token"},
	CodeDepositNotAllowed:       {http.StatusForbidden, "Deposit not allowed"},
	CodeIPNotAllowed:            {http.StatusForbidden, "Address not allowed for this token"},
	CodeBlockedFile:             {http.StatusForbidden, "File refused"},
	CodeInvitationNotAllowed:    {http.StatusForbidden, "Invitations are reserved to internal users"},
	CodeInvitationGone:          {http.StatusGone, "Invitation no longer valid"},
	CodeVerificationCodeInvalid: {http.StatusUnprocessableEntity, "Invalid verification code"},
	CodeVerificationExhausted:   {http.StatusGone, "Verification code invalidated"},
	CodeNotFound:                {http.StatusNotFound, "Not found"},
	CodeTransferGone:            {http.StatusGone, "Transfer no longer available"},
	CodeDownloadLocked:          {http.StatusUnauthorized, "Password required"},
	CodeTransferPasswordInvalid: {http.StatusUnauthorized, "Wrong password"},
	CodeTransferLocked:          {http.StatusTooManyRequests, "Too many attempts"},
	CodeStateConflict:           {http.StatusConflict, "Operation not allowed in the current state"},
	CodeAlreadyExists:           {http.StatusConflict, "Already exists"},
	CodeUploadIncomplete:        {http.StatusConflict, "Upload incomplete"},
	CodeChecksumMismatch:        {http.StatusConflict, "Checksum mismatch"},
	CodeTransferTooLarge:        {http.StatusRequestEntityTooLarge, "Transfer too large"},
	CodePayloadTooLarge:         {http.StatusRequestEntityTooLarge, "Payload too large"},
	CodeUnsupportedMediaType:    {http.StatusUnsupportedMediaType, "Unsupported media type"},
	CodeQuotaExceeded:           {http.StatusInsufficientStorage, "Storage quota reached"},
	CodeRateLimited:             {http.StatusTooManyRequests, "Too many requests"},
	CodeMaintenance:             {http.StatusServiceUnavailable, "Maintenance in progress"},
	CodeUnknownTenant:           {http.StatusMisdirectedRequest, "Unknown host"},
	CodeSetupAlreadyDone:        {http.StatusConflict, "Setup already completed"},
	CodeSetupTokenInvalid:       {http.StatusForbidden, "Invalid setup token"},
	CodeNewMasterKeyMissing:     {http.StatusConflict, "New master key not configured"},
	CodeInternalError:           {http.StatusInternalServerError, "Internal error"},
}

// Lookup returns the default definition of code and whether code is known.
func Lookup(code Code) (Definition, bool) {
	d, ok := catalog[code]
	return d, ok
}

// Codes returns every known Code, in no particular order.
func Codes() []Code {
	codes := make([]Code, 0, len(catalog))
	for c := range catalog {
		codes = append(codes, c)
	}
	return codes
}

// TypeURI returns the documentation URI of the code.
func (c Code) TypeURI() string {
	return TypeBaseURI + string(c)
}

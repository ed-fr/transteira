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
	// CodeMethodNotAllowed means the path exists but not for this HTTP method.
	CodeMethodNotAllowed Code = "method-not-allowed"
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
	// CodeRangeNotSatisfiable means the requested byte range is outside the
	// file.
	CodeRangeNotSatisfiable Code = "range-not-satisfiable"
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
	// CodeMailUnavailable means the verification or invitation email cannot
	// be sent right now (no SMTP settings for the tenant, mail queue closed).
	CodeMailUnavailable Code = "mail-unavailable"
	// CodeUnknownTenant means the Host header matches no tenant.
	CodeUnknownTenant Code = "unknown-tenant"
	// CodeSetupAlreadyDone means the first-run setup was already completed.
	CodeSetupAlreadyDone Code = "setup-already-done"
	// CodeSetupTokenInvalid means the first-run setup token is invalid.
	CodeSetupTokenInvalid Code = "setup-token-invalid"
	// CodeNewMasterKeyMissing means no new master key is configured for rotation.
	CodeNewMasterKeyMissing Code = "new-master-key-missing"
	// CodeRecipientDomainRefused means a recipient is refused by the tenant's
	// recipient domain rules (since 1.1).
	CodeRecipientDomainRefused Code = "recipient-domain-refused"
	// CodeConfidentialityRuleViolated means the transfer breaks a rule of its
	// confidentiality level (since 1.1).
	CodeConfidentialityRuleViolated Code = "confidentiality-rule-violated"
	// CodeAbuseThresholdBlocked means an abuse detection threshold set to block
	// is exceeded (since 1.1).
	CodeAbuseThresholdBlocked Code = "abuse-threshold-blocked"
	// CodeRecipientVerificationRequired means the recipient of a per-recipient
	// link must prove their address by code first (since 1.1).
	CodeRecipientVerificationRequired Code = "recipient-verification-required"
	// CodeMaxDownloadsReached means the transfer reached its maximum number of
	// downloads (since 1.1).
	CodeMaxDownloadsReached Code = "max-downloads-reached"
	// CodeReplyNotAllowed means replying to the transfer is not possible
	// (since 1.1).
	CodeReplyNotAllowed Code = "reply-not-allowed"
	// CodeAccessLinkInvalid means a "My transfers" access link is unknown,
	// expired or already used (since 1.1).
	CodeAccessLinkInvalid Code = "access-link-invalid"
	// CodeExtensionLimitReached means extending the transfer would take its
	// total lifetime beyond 90 days from its creation (since 1.1).
	CodeExtensionLimitReached Code = "extension-limit-reached"
	// CodeTenantInSetup means the tenant is still being configured and
	// refuses deposits (since 1.2).
	CodeTenantInSetup Code = "tenant-in-setup"
	// CodeSetupIncomplete means a required item of the tenant setup
	// checklist is not done (since 1.2).
	CodeSetupIncomplete Code = "setup-incomplete"
	// CodeSetupAlreadyComplete means the tenant setup is already completed
	// (since 1.2).
	CodeSetupAlreadyComplete Code = "setup-already-complete"
	// CodeUnknownBackgroundPreset means the background preset is not one of
	// the library (since 1.2).
	CodeUnknownBackgroundPreset Code = "unknown-background-preset"
	// CodeSystemSMTPUnavailable means an activation link must be mailed but
	// no system SMTP is available (since 1.2).
	CodeSystemSMTPUnavailable Code = "system-smtp-unavailable"
	// CodeAdminAlreadyActive means the admin account is already activated
	// (since 1.2).
	CodeAdminAlreadyActive Code = "admin-already-active"
	// CodeUpdateCheckDisabled means the check for a newer release is
	// disabled by TT_UPDATE_CHECK (since 1.2).
	CodeUpdateCheckDisabled Code = "update-check-disabled"
	// CodeProvisioningTokenInvalid means the provisioning token is unknown,
	// revoked or expired, or used from outside its IP ranges (since 1.2).
	CodeProvisioningTokenInvalid Code = "provisioning-token-invalid"
	// CodeProvisioningScopeExceeded means the request is outside the scope
	// of the provisioning token (since 1.2).
	CodeProvisioningScopeExceeded Code = "provisioning-scope-exceeded"
	// CodeReadOnlyRole means the admin has the read-only auditor role and attempted a write or a read outside its scope (since 2.0).
	CodeReadOnlyRole Code = "read-only-role"
	// CodeSSORequired means the account must sign in through single sign-on, its tenant enforcing it (since 2.0).
	CodeSSORequired Code = "sso-required"
	// CodeSSONotAvailable means no enabled single sign-on matches the e-mail address, the same answer for an unknown domain and a disabled one (since 2.0).
	CodeSSONotAvailable Code = "sso-not-available"
	// CodeSSONotConfigured means an account without activation link was asked for while a tenant of the account has no enabled single sign-on (since 2.0).
	CodeSSONotConfigured Code = "sso-not-configured"
	// CodeSSOIssuerNotAllowed means the issuer of a single sign-on configuration is a multi-tenant endpoint or otherwise unacceptable (since 2.0).
	CodeSSOIssuerNotAllowed Code = "sso-issuer-not-allowed"
	// CodeSSODomainConflict means an e-mail domain is already routed to another tenant's single sign-on (since 2.0).
	CodeSSODomainConflict Code = "sso-domain-conflict"
	// CodeSSOMFARequired means the identity provider did not assert multi-factor authentication while the tenant requires it (since 2.0).
	CodeSSOMFARequired Code = "sso-mfa-required"
	// CodeProofNotAvailable means the proof does not exist yet or is past its retention (since 2.0).
	CodeProofNotAvailable Code = "proof-not-available"
	// CodeImportInvalid means the imported tenant configuration is refused; the first error carries the JSON pointer of the first problem (since 2.0).
	CodeImportInvalid Code = "import-invalid"
	// CodeImportSchemaUnsupported means the schemaVersion of the imported configuration is not read by this server (since 2.0).
	CodeImportSchemaUnsupported Code = "import-schema-unsupported"
	// CodeDropLinkInvalid means the permanent drop link is unknown, revoked or disabled, the same answer for each (since 2.0).
	CodeDropLinkInvalid Code = "drop-link-invalid"
	// CodeDropLinkLimitReached means the tenant already has the maximum number of drop links (since 2.0).
	CodeDropLinkLimitReached Code = "drop-link-limit-reached"
	// CodeLinkOnlyForbidden means the tenant or the confidentiality level does not allow link-only transfers (since 2.0).
	CodeLinkOnlyForbidden Code = "link-only-forbidden"
	// CodeLinkOnlyConflict means linkOnly was combined with recipientVerification (since 2.0).
	CodeLinkOnlyConflict Code = "link-only-conflict"
	// CodeE2EForbidden means the policy of the tenant or level forbids end-to-end encryption (since 2.0).
	CodeE2EForbidden Code = "e2e-forbidden"
	// CodeE2ERequired means the policy of the tenant or level requires end-to-end encryption (since 2.0).
	CodeE2ERequired Code = "e2e-required"
	// CodeE2EArchiveUnavailable means the server cannot build the ZIP of an end-to-end encrypted transfer (since 2.0).
	CodeE2EArchiveUnavailable Code = "e2e-archive-unavailable"
	// CodeE2EFormatInvalid means an end-to-end encrypted upload is not a well-formed TTE2 stream (since 2.0).
	CodeE2EFormatInvalid Code = "e2e-format-invalid"
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
	CodeValidationFailed:              {http.StatusBadRequest, "Invalid request"},
	CodeUnauthenticated:               {http.StatusUnauthorized, "Authentication required"},
	CodeInvalidCredentials:            {http.StatusUnauthorized, "Invalid credentials"},
	CodeForbidden:                     {http.StatusForbidden, "Forbidden"},
	CodeCSRFInvalid:                   {http.StatusForbidden, "Invalid CSRF token"},
	CodeDepositNotAllowed:             {http.StatusForbidden, "Deposit not allowed"},
	CodeIPNotAllowed:                  {http.StatusForbidden, "Address not allowed for this token"},
	CodeBlockedFile:                   {http.StatusForbidden, "File refused"},
	CodeInvitationNotAllowed:          {http.StatusForbidden, "Invitations are reserved to internal users"},
	CodeInvitationGone:                {http.StatusGone, "Invitation no longer valid"},
	CodeVerificationCodeInvalid:       {http.StatusUnprocessableEntity, "Invalid verification code"},
	CodeVerificationExhausted:         {http.StatusGone, "Verification code invalidated"},
	CodeNotFound:                      {http.StatusNotFound, "Not found"},
	CodeMethodNotAllowed:              {http.StatusMethodNotAllowed, "Method not allowed"},
	CodeTransferGone:                  {http.StatusGone, "Transfer no longer available"},
	CodeDownloadLocked:                {http.StatusUnauthorized, "Password required"},
	CodeTransferPasswordInvalid:       {http.StatusUnauthorized, "Wrong password"},
	CodeTransferLocked:                {http.StatusTooManyRequests, "Too many attempts"},
	CodeStateConflict:                 {http.StatusConflict, "Operation not allowed in the current state"},
	CodeAlreadyExists:                 {http.StatusConflict, "Already exists"},
	CodeUploadIncomplete:              {http.StatusConflict, "Upload incomplete"},
	CodeChecksumMismatch:              {http.StatusConflict, "Checksum mismatch"},
	CodeTransferTooLarge:              {http.StatusRequestEntityTooLarge, "Transfer too large"},
	CodePayloadTooLarge:               {http.StatusRequestEntityTooLarge, "Payload too large"},
	CodeRangeNotSatisfiable:           {http.StatusRequestedRangeNotSatisfiable, "Range not satisfiable"},
	CodeUnsupportedMediaType:          {http.StatusUnsupportedMediaType, "Unsupported media type"},
	CodeQuotaExceeded:                 {http.StatusInsufficientStorage, "Storage quota reached"},
	CodeRateLimited:                   {http.StatusTooManyRequests, "Too many requests"},
	CodeMaintenance:                   {http.StatusServiceUnavailable, "Maintenance in progress"},
	CodeMailUnavailable:               {http.StatusServiceUnavailable, "Email cannot be sent"},
	CodeUnknownTenant:                 {http.StatusMisdirectedRequest, "Unknown host"},
	CodeSetupAlreadyDone:              {http.StatusConflict, "Setup already completed"},
	CodeSetupTokenInvalid:             {http.StatusForbidden, "Invalid setup token"},
	CodeNewMasterKeyMissing:           {http.StatusConflict, "New master key not configured"},
	CodeRecipientDomainRefused:        {http.StatusForbidden, "Recipient not allowed"},
	CodeConfidentialityRuleViolated:   {http.StatusUnprocessableEntity, "Confidentiality rule not met"},
	CodeAbuseThresholdBlocked:         {http.StatusForbidden, "Sending limit reached"},
	CodeRecipientVerificationRequired: {http.StatusUnauthorized, "Recipient verification required"},
	CodeMaxDownloadsReached:           {http.StatusGone, "Download limit reached"},
	CodeReplyNotAllowed:               {http.StatusForbidden, "Reply not allowed"},
	CodeAccessLinkInvalid:             {http.StatusGone, "Access link no longer valid"},
	CodeExtensionLimitReached:         {http.StatusConflict, "Extension limit reached"},
	CodeTenantInSetup:                 {http.StatusServiceUnavailable, "Service being set up"},
	CodeSetupIncomplete:               {http.StatusConflict, "Setup incomplete"},
	CodeSetupAlreadyComplete:          {http.StatusConflict, "Setup already complete"},
	CodeUnknownBackgroundPreset:       {http.StatusUnprocessableEntity, "Unknown background preset"},
	CodeSystemSMTPUnavailable:         {http.StatusServiceUnavailable, "System email unavailable"},
	CodeAdminAlreadyActive:            {http.StatusConflict, "Administrator already active"},
	CodeUpdateCheckDisabled:           {http.StatusConflict, "Update check disabled"},
	CodeProvisioningTokenInvalid:      {http.StatusUnauthorized, "Invalid provisioning token"},
	CodeProvisioningScopeExceeded:     {http.StatusForbidden, "Outside the provisioning token scope"},
	CodeReadOnlyRole:                  {http.StatusForbidden, "Read-only role"},
	CodeSSORequired:                   {http.StatusForbidden, "Single sign-on required"},
	CodeSSONotAvailable:               {http.StatusNotFound, "Single sign-on not available"},
	CodeSSONotConfigured:              {http.StatusConflict, "Single sign-on not configured"},
	CodeSSOIssuerNotAllowed:           {http.StatusUnprocessableEntity, "Issuer not allowed"},
	CodeSSODomainConflict:             {http.StatusConflict, "Domain already used by another single sign-on"},
	CodeSSOMFARequired:                {http.StatusForbidden, "Multi-factor authentication required"},
	CodeProofNotAvailable:             {http.StatusNotFound, "Proof not available"},
	CodeImportInvalid:                 {http.StatusUnprocessableEntity, "Invalid configuration file"},
	CodeImportSchemaUnsupported:       {http.StatusUnprocessableEntity, "Configuration version not supported"},
	CodeDropLinkInvalid:               {http.StatusNotFound, "Drop link not valid"},
	CodeDropLinkLimitReached:          {http.StatusConflict, "Drop link limit reached"},
	CodeLinkOnlyForbidden:             {http.StatusForbidden, "Link-only transfers not allowed"},
	CodeLinkOnlyConflict:              {http.StatusBadRequest, "Link-only incompatible with recipient verification"},
	CodeE2EForbidden:                  {http.StatusForbidden, "End-to-end encryption not allowed"},
	CodeE2ERequired:                   {http.StatusBadRequest, "End-to-end encryption required"},
	CodeE2EArchiveUnavailable:         {http.StatusConflict, "Archive unavailable for an end-to-end encrypted transfer"},
	CodeE2EFormatInvalid:              {http.StatusBadRequest, "Malformed end-to-end encrypted upload"},
	CodeInternalError:                 {http.StatusInternalServerError, "Internal error"},
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

// Package secret implements the one-time secrets of V2.1 (CLAUDE.md section
// 22.1, data model docs/architecture/data-model-v2.1.md section 2.1, format
// docs/architecture/e2e-format.md sections 3.3 and 4.1, threat model
// sections 6.56 to 6.63): the creation by a depositor or an API token, the
// status and the one-time reveal of a link, and the "my transfers" list and
// deletion of the creator.
//
// The server never holds a key of a secret: the text is sealed in the
// browser of the creator, and the service checks only what it can without a
// key (e2e-format.md section 4.1). A request is first validated against the
// rules of the OpenAPI schema (a *ValidationError, answered 400
// validation-failed with field codes), then by the keyless framing checks
// the schema cannot express (a *FormatError, answered 400
// secret-format-invalid), then against the settings of the tenant.
//
// Creators. A creator is a deposit session or an API token, identified and
// checked exactly as for a transfer: the HTTP layer builds a
// transfer.Sender, and the eligibility rules of the transfers (blocklist,
// internal rule, remote rule, invitation, allowed senders of an API token)
// are applied again by [Eligibility] (*transfer.Service). The reply and drop
// link sessions cannot create secrets (ErrForbidden, answered 403
// deposit-not-allowed). The creator kind of the secret follows the sender:
// internal, internal_remote, external (with its invitation) or api_token.
//
// Step 2 of V2.1 delivers the link delivery of a text only. The e-mail
// delivery and the optional file (and with them the read receipts mailed by
// step 3) pass the same validation and settings checks, then are refused as
// an interim *ValidationError with the field code CodeNotSupported. Step 3
// removes the two interim cases of checkSettings (create.go) together with
// CodeNotSupported, and moves the key proof check of the store ahead of the
// file refusal (see checkKeyProof).
//
// Recipients. The status of a link ([Service.Status]) consumes nothing and
// returns nothing sealed: the expiry, the public passphrase parameters and
// the size of the file. The reveal ([Service.Reveal]) checks the key proof
// first (a wrong one is not counted against the secret), then the proof in
// the reveal transaction of the store, which counts a wrong passphrase and
// locks the secret at the fifth. Both answer an unknown token (or one of
// another tenant) 404 and write secret_invalid to the security log; a token
// of a pending secret is answered 404 too, without event. Every call counts
// against its client (IPv4 address or IPv6 /64): LinkRequestsPerMinute
// requests per minute, and LinkFailureLimit failures (unknown tokens and
// wrong proofs) within LinkFailureWindow lock the client out for
// LinkLockout; both are answered 429 and written as rate_limited.
//
// Nothing secret is ever written to the audit log, the security log or the
// application log: neither the token, the key, the proofs, the verifiers nor
// the content (threat model T-375); the audit events carry the "sec_"
// identifier only.
package secret

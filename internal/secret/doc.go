// Package secret implements the one-time secrets of V2.1 (CLAUDE.md section
// 22.1, data model docs/architecture/data-model-v2.1.md section 2.1, format
// docs/architecture/e2e-format.md sections 3.3 and 4.1, threat model
// sections 6.56 to 6.63): the creation by a depositor or an API token, the
// status and the one-time reveal of a link, and the "my transfers" list and
// deletion of the creator, the optional file and its one-time download.
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
// Files. A secret may carry one small file, declared at the creation (its
// ciphertext size and sealed metadata): the secret starts pending and the
// creator uploads the TTE2 ciphertext with [Service.UploadFile], checked by
// the keyless validator while it is streamed and encrypted again at rest. A
// link secret becomes active once its file is uploaded. The file counts in
// the storage quota of the tenant from the creation until it is deleted.
// The reveal of a secret with a file returns a one-time grant, valid 10
// minutes, for [Service.DownloadFile]: the first complete download deletes
// the file and destroys its key; an unused grant is swept by the lifecycle
// task.
//
// E-mail delivery. At the creation, the recipient goes through the
// blocklist and the recipient domain rules of the tenant, as a transfer
// recipient (ErrRecipientRefused, audited transfer.recipient_refused,
// never in the security log); the recipient of an invited external is
// forced to its inviter by the store. The secret stays pending after its
// creation (and its file upload) until [Service.Send]: the creator sends
// back the secret token (the server keeps only its SHA-256, compared in
// constant time) and the key of the fragment, used only to compose the
// link https://<registered FQDN>/s/<token>#k=<key> of the mail
// (e2e-format.md 3.3.6, threat model T-363 and T-365). The mail is built
// before the activation (no SMTP settings: ErrMailUnavailable, nothing
// activated), then queued through the [Mailer], in memory only.
//
// Read receipts. For a secret asked with a read receipt, the creator is
// mailed once when it is read, locked, or expired unread
// ([Service.Expired], called by the lifecycle task): the store marks the
// receipt atomically and only the marking caller queues the mail, so that
// a deleted secret never gets one. The receipts never fail nor block a
// request (built and queued without waiting for the delivery).
//
// Abuse detection. Every secret that becomes active (a link secret at its
// creation or after its upload, an e-mail secret after the send call) is
// reported to Options.Abuse, which alerts only: the creation is never
// blocked by the abuse thresholds.
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
// identifier only (and, for secret.sent, the domain of the recipient).
package secret

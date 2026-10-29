// Package transfer is the transfer service of TransTeira (CLAUDE.md
// sections 8 and 10, OpenAPI createTransfer, getTransfer, cancelTransfer
// and finalizeTransfer): it declares a transfer and its files, lets its
// sender follow, cancel and finalize it, and enforces the per-transfer
// limit and the storage quota of the tenant. The bytes of the files go
// through the tus upload engine (package upload), never through this
// package.
//
// # Senders
//
// Every operation acts for a [Sender], built by the HTTP layer from the
// deposit session and the real client IP. A transfer is visible to the
// sender who created it only, by the rule shared with the upload engine
// ([store.Depositor.Owns]: same normalized address and, for an external
// sender, same invitation; for a reply, same original transfer). Any other caller, including a sender of another
// tenant, gets [ErrNotFound], exactly as for an unknown transfer.
//
// The eligibility of the sender is checked again at creation and at
// finalization (threat T-25, the obligation stated by package deposit),
// since a deposit session outlives the conditions that opened it: the
// tenant blocklist (address and domain), the internal rule (client IP and
// mail domain, package netpolicy) for an internal sender, an active
// invitation naming the same address for an external one. A refusal is the
// generic [ErrForbidden] and a deposit_refused line in the security log
// with the reason only.
//
// A remote internal sender (store.DepositorInternalRemote, spec 6.4)
// deposits from outside the IP ranges: instead of the IP part of the
// internal rule, the tenant must still allow the deposit from outside and
// its address must still be verified and have been verified once from the
// internal network. It is otherwise an internal sender (recipients,
// policies, open transfer cap); its transfer.created audit event carries
// details.remote true.
//
// A reply sender (store.DepositorReply, spec 10) is the recipient of a
// transfer answering its sender: the sender of the original transfer is
// the only recipient (requested recipients are ignored, like T-17), the
// recipient domain rules do not bind it, the confidentiality levels apply,
// and it counts as an external sender for the open transfer cap and the
// abuse detection (external quota). At creation and again at finalization
// the tenant must still allow replies, the original must have been sent by
// an internal sender or an API token to this address, its sender must be
// neither blocklisted nor outside the internal domains
// ([ErrReplyNotAllowed], 403 reply-not-allowed), and the original must
// still be available ([ErrOriginalGone], 410 transfer-gone); these policy
// refusals are never written to the security log. The creation is audited
// as transfer.created (origin reply) and transfer.reply_created (details
// replyTo).
//
// An external sender cannot choose recipients: the internal user who issued
// the invitation is the only recipient (T-17). An internal sender names 1
// to Options.MaxRecipients recipients (TT_MAX_RECIPIENTS, decision P15).
//
// An API token sender (the HTTP layer has checked the client IP against
// the ranges of the token) names the sender address in senderEmail, which
// is mandatory (and forbidden with a deposit session): a plain address,
// checked with the strict syntax of the recipients, of a tenant internal
// domain and not blocklisted; the IP part of the internal rule does not
// apply. Its transfers have an internal sender kind and carry the token:
// only that token reads, cancels, finalizes and uploads them, never a
// deposit session, even with the same address ([store.Depositor.Owns]).
// The cap on unfinished transfers and the idempotency keys are counted per
// token, and the audit events name the token, never the address, with
// origin api, plus one api_token.used event per created transfer.
//
// # Quota and limits
//
// The declared total is compared with the per-transfer limit of the tenant
// ([ErrTooLarge], 413), then, in the creation transaction and under the
// tenant lock, with the quota minus the declared totals of the uploading,
// scanning and available transfers ([ErrQuotaExceeded], 507, T-124). A
// transfer exactly at the quota fits. The reservation is released when the
// transfer is canceled, expires or is purged. Until the cleanup job exists,
// nothing frees the quota held by a transfer that is never uploaded, so the
// same transaction also caps the unfinished transfers of each sender
// (Options.MaxOpenTransfers, TT_MAX_OPEN_TRANSFERS, for internal senders;
// MaxOpenTransfersExternal for external and reply ones): [ErrRateLimited], 429.
//
// # Abuse detection
//
// With Options.Abuse, the blocking abuse rules of the tenant (CLAUDE.md
// section 15) are checked in the same transaction, before the quota
// ([ErrAbuseBlocked], 403, audited and alerted by the detector, never in
// the security log), and every rule is evaluated after the commit. The
// interface [AbuseChecker] uses types of this package: the application
// adapts *abuse.Detector to it.
//
// # Idempotency
//
// A creation with an Idempotency-Key records the SHA-256 of the canonical
// request with the key. Replaying the key within 24 hours returns the same
// transfer when the request is the same, and [ErrIdempotencyMismatch] (409)
// when it differs.
//
// # Text
//
// Messages are cleaned with textsafe.SanitizeMessage and file names checked
// by package filename, which share the same classes of hidden characters
// (package textsafe).
//
// # Keys and files
//
// Each file gets its own data key, created in the transaction that creates
// its row (decision P6), a random storage name and a 256-bit upload
// identifier. The password, when given, is hashed with argon2id before the
// transaction, through a hasher bounding the concurrent computations
// (DefaultHashConcurrency, threat T-125).
//
// Canceling and finalizing take the upload lock of every file, so that no
// PATCH runs meanwhile; a cancellation destroys the data key of each file
// before its files on disk and its rows (T-110).
//
// # Errors
//
// The errors map to HTTP as follows: [ErrInvalid] (*ValidationError) 400
// validation-failed; [ErrForbidden] 403 deposit-not-allowed;
// [ErrAbuseBlocked] (*AbuseBlockedError) 403 abuse-threshold-blocked;
// [ErrBlockedFile] 403 blocked-file; [ErrNotFound] 404 not-found;
// [ErrConflict], [ErrBusy] and [ErrIdempotencyMismatch] 409 state-conflict; [ErrIncomplete]
// (*FilesError) 409 upload-incomplete; [ErrChecksumMismatch] (*FilesError)
// 409 checksum-mismatch; [ErrTooLarge] (*TooLargeError) 413
// transfer-too-large; [ErrRateLimited] (*RateLimitError) 429 rate-limited
// with Retry-After; [ErrQuotaExceeded] 507 quota-exceeded; anything else
// 500.
//
// # Antivirus hook
//
// Options.OnFinalized is called after each finalization commit. Step 7
// plugs the antivirus queue in there and sweeps the scanning transfers at
// startup, so that a call lost in a crash is recovered.
package transfer

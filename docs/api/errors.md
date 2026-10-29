# TransTeira API error catalog

Every error returned by the TransTeira API (`/api/v1`) is an
[RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457) object served with the
`application/problem+json` media type.

```json
{
  "type": "https://github.com/ed-fr/transteira/blob/main/docs/api/errors.md#rate-limited",
  "title": "Too many requests",
  "status": 429,
  "code": "rate-limited",
  "retryAfterSeconds": 1800,
  "instance": "req_01JABCP0S1T2U3V4W5X6Y7Z8A9"
}
```

## How to read an error

| Member | Meaning |
|---|---|
| `code` | **The stable contract.** Clients must branch on `code`, never on `title` or `detail`. A code is never renamed or removed within an API version. New codes may be added (the enumeration is extensible), so clients must handle unknown codes gracefully, usually by falling back on the HTTP status. |
| `type` | Link to the section of this page that describes the code (`errors.md#<code>`). |
| `title` | Short summary, **localized** in the language negotiated for the request (French or English). Display it, do not parse it. |
| `detail` | Optional human-readable explanation, also localized. |
| `status` | The HTTP status code, repeated in the body. |
| `instance` | Request identifier, also sent in the `X-Request-Id` header and written to the server logs. Quote it when contacting the administrators so they can correlate the error with the logs. |

Some codes carry extension members:

| Member | Used by | Meaning |
|---|---|---|
| `errors` | `validation-failed` | List of `{field, code, allowed?, line?, column?, message?}` objects, one per invalid field. `field` is the JSON pointer (RFC 6901) of the field in the request body, such as `/recipients/0` or `/files/2/name`, or the name of a header (`Idempotency-Key`) or query parameter (`confirm`). For a mail template (`code: invalid-template`), `field` names the part (`/subject`, `/bodyHtml` or `/bodyText`), `line` and `column` (1-based, the column in characters) locate the problem when it has a position, and `message` explains it in English. |
| `attemptsRemaining` | `verification-code-invalid`, `transfer-password-invalid` | Number of attempts left before lockout or invalidation. |
| `retryAfterSeconds` | `rate-limited`, `transfer-locked`, `maintenance`, `state-conflict` (admin deletion of a transfer being uploaded, GDPR erasure blocked by an upload in progress) | Seconds to wait before retrying; the `Retry-After` header carries the same value. |
| `maxTransferBytes` | `transfer-too-large` | Per-transfer size limit of the entity, in bytes. |
| `files` | `upload-incomplete`, `checksum-mismatch` | Identifiers of the files concerned. |

Error responses are never cached (`Cache-Control: no-store`) and never contain internal details
such as stack traces, SQL errors or file paths.

Refusals that may indicate an attack (wrong credentials, wrong codes, unknown host, refused
deposits, rate limiting) are also written to the security log, which fail2ban or CrowdSec may
use to ban the client IP.

## Codes

### validation-failed

- **HTTP status:** 400 Bad Request
- **Meaning:** the request is malformed (invalid JSON, wrong type) or a field is invalid.
  The `errors` member lists each invalid field with a reason code and, when relevant, the
  accepted values (for example `expiryDays` with `allowed: [1, 7, 30]`). Since 1.1, on
  transfer creation: `maxDownloads` outside 1 to 1000 and `recipientVerification: true` (not
  offered until per-recipient links are available) are reported as `not-allowed`, a malformed
  `confidentialityLevel` as `invalid-format` and an unknown one as `not-allowed`. A mail address that
  is not a bare address (`user@entity-a.example.com`; a display-name form such as
  `Name <user@entity-a.example.com>` is refused, never rewritten) is reported with the code
  `invalid-email` on its field: `/email` (deposit session, invitation, data subject search or
  erasure, admin account, setup), `/recipients/<n>` (transfer creation, notification resend),
  `/fromAddress` and `/to` (SMTP settings and test), and the `email` filter of the transfer
  list. In the tenant configuration: an entity FQDN that is malformed (`/fqdn`,
  `invalid-format`) or equal to an admin host (`/fqdn`, `reserved-host`), a confirmation that is not the exact entity name when deleting it
  (`confirm`), a corrupt branding image (`/image`), and a mail template that uses an unknown variable, any template
  syntax other than `{{snake_case}}` variables, or lacks a required variable (one
  `invalid-template` entry per problem, with its position). In a JSON Merge Patch, `null` on
  a field that cannot be removed is refused with one `not-nullable` entry per field (for
  example `/name` when updating an entity). In the operations of an entity: a blocklist value
  that is not a valid email address, domain name or SHA-256 fingerprint for its kind (`/value`),
  a notification resend to an address that is not an original recipient of the transfer
  (`/recipients/<n>`, `invalid-format`), a missing address in a data subject search or
  erasure (`/email`, `required`), and a list filter that is not valid (an unknown `status` or `kind`, an audit `action` that does
  not have the `area.action` form, a `limit` outside 1 to 200, a malformed `cursor`). In the
  system operations of the super admin: `PUT /admin/system/maintenance` requires `enabled`
  (missing: `required`, null: `not-nullable`, not a boolean: `invalid-format`, on `/enabled`),
  refuses an unknown member (`invalid-format` naming it) and a message in an unsupported
  language or with forbidden characters (`/message/<lang>`); `PATCH /admin/system/settings`
  refuses `diskAlertThreshold: null` (`not-nullable`), a threshold outside 0.50 to 0.99 and an
  unknown member. These body checks come after the role check: another administrator gets
  `403 forbidden` whatever the body.
- **Typical endpoints:** any endpoint accepting a body or query parameters.
- **What to do:** fix the listed fields and send the request again. Do not retry unchanged.

### unauthenticated

- **HTTP status:** 401 Unauthorized
- **Meaning:** credentials are missing or expired: no admin session, expired deposit session,
  or, on an operation that also accepts an API token, neither a deposit session nor an
  `Authorization` header (a present but invalid token gives `invalid-credentials` instead);
  on those operations the response carries `WWW-Authenticate: Bearer`. On the admin host, it
  also answers an expired or revoked session
  (logout, password change, TOTP re-enrollment or disabling from another session, account
  disabled or reset) and a session of a disabled account, and the session cookie is then
  cleared; and an admin session whose login step does not open the operation (a session still
  waiting for its TOTP code or enrollment only opens that step), which keeps its cookie. The
  interactive documentation `/api/docs` answers it on the admin host without an admin session.
- **Typical endpoints:** `/admin/*` (including `POST /admin/system/master-key/rotations`),
  `/transfers`, `/invitations`, `/deposit-sessions/current`, `/api/docs`.
- **What to do:** sign in again, verify the email address again, or send the
  `Authorization: Bearer <token>` header.

### invalid-credentials

- **HTTP status:** 401 Unauthorized
- **Meaning:** wrong username or password, wrong TOTP code, or a malformed, unknown, revoked or
  expired API token (a token of another entity is unknown on this entity's host). The response
  does not say which part was wrong. A token is checked before the client IP: an invalid token
  gets this answer from any address, and is written to the security log
  (`api_token_invalid`). On an operation that accepts an API token, the response carries
  `WWW-Authenticate: Bearer` (RFC 6750). A revoked or expired token is refused from the next
  request on; an upload request already streaming continues until its body ends or stalls.
  Starting a master key rotation re-confirms the second factor: a wrong TOTP or recovery code
  gives this answer, as does a TOTP code already used within its 30-second step (for example
  the code just used to sign in: wait for the next one); the session stays open.
- **Typical endpoints:** `POST /admin/auth/login`, `POST /admin/auth/totp`,
  `POST /admin/me/totp` (from an authenticated session), `POST /admin/me/totp/confirm`,
  `PUT /admin/me/password`, `DELETE /admin/me/totp`, `POST /admin/system/master-key/rotations`,
  any endpoint called with an API token.
- **What to do:** check the credentials. Repeated failures lead to `rate-limited` and may get
  the client IP banned.

### forbidden

- **HTTP status:** 403 Forbidden
- **Meaning:** the caller is authenticated but its role does not allow the operation (for
  example a delegated admin calling a super admin endpoint, or a super admin trying to disable
  the TOTP that is mandatory for them). A delegated admin changing the name, FQDN, storage quota
  or transfer ceiling of its entity, or setting its transfer limit above the ceiling set by the
  super admin, also gets `forbidden`, and nothing is changed. The global statistics and the
  instance-wide audit log are reserved to the super admin as well; a delegated admin reads the
  statistics and the audit log of its own entities instead.
- **Typical endpoints:** `/admin/system/*`, `/admin/admins`, `POST /admin/tenants`,
  `PATCH /admin/tenants/{tenantId}`, `DELETE /admin/tenants/{tenantId}`, `DELETE /admin/me/totp`.
- **What to do:** do not retry; ask a super admin if the access is legitimately needed.

### csrf-invalid

- **HTTP status:** 403 Forbidden
- **Meaning:** the CSRF token of a cookie-authenticated, state-changing request is missing or
  invalid.
- **Typical endpoints:** state-changing requests made from the browser with a session cookie,
  e.g. `DELETE /transfers/{transferId}`, `DELETE /deposit-sessions/current`, and every
  state-changing `/admin/*` request with the admin session. The request is also refused when its
  `Origin` header is present and differs from `https://<entity host>` (`https://<admin host>`
  on the admin host), or when its `Sec-Fetch-Site` header is present and is not `same-origin`.
  These two header checks alone (no token yet) also protect `POST /admin/setup`,
  `POST /admin/auth/login`, `POST /admin/activation` and `POST /downloads/{linkToken}/unlock`.
- **What to do:** send the `csrfToken` returned in the session payload in the `X-CSRF-Token`
  header; reload the page to obtain a fresh one, then retry. On the admin host, the token is
  derived from the session with a key of the current master key: after a master key rotation
  the open sessions stay valid but their tokens do not, so fetch `GET /admin/me` again for the
  current `csrfToken`, then retry.

### deposit-not-allowed

- **HTTP status:** 403 Forbidden
- **Meaning:** a public deposit is refused. The code is deliberately generic and identical for
  every reason (client outside the internal IP ranges of the entity, email domain not internal,
  address or domain on the blocklist), so that the response does not reveal which check failed.
  The precise reason is written to the security log only. With an API token, the client IP is
  checked against the token instead (`ip-not-allowed`), and this code answers a `senderEmail`
  outside the internal domains of the entity, on the blocklist, or not allowed by the token
  (when the token has `allowedSenders`, the address must equal one of its addresses or have
  exactly one of its domains; checked on `POST /transfers` and again on
  `POST /transfers/{transferId}/finalize`).
- **Typical endpoints:** `POST /deposit-sessions`,
  `POST /verification-challenges/{challengeId}/confirm`, `POST /transfers`, `POST /invitations`,
  `POST /transfers/{transferId}/finalize` (API token).
- **What to do:** deposit from the internal network with an internal address, or ask an internal
  user for an invitation. With an API token, use a sender address of an internal domain allowed
  by the token, or ask an admin to update the token's `allowedSenders`.

### ip-not-allowed

- **HTTP status:** 403 Forbidden
- **Meaning:** a valid API token was used from an IP address outside the `allowedCidrs`
  configured for that token. This code is only visible to the token holder, since the token is
  authenticated first. Written to the security log. The tus operations answer `403` without a
  body.
- **Typical endpoints:** any endpoint called with an API token: `POST /transfers`,
  `GET` and `DELETE /transfers/{transferId}`, `POST /transfers/{transferId}/finalize`, and
  `HEAD`, `PATCH` and `DELETE /uploads/{uploadId}`.
- **What to do:** call from an allowed address, or ask an admin to update the token's allowed
  ranges.

### blocked-file

- **HTTP status:** 403 Forbidden
- **Meaning:** the SHA-256 fingerprint of one of the files is on the blocklist of the entity.
- **Typical endpoints:** `POST /transfers/{transferId}/finalize`.
- **What to do:** remove the file from the transfer. Do not retry with the same file.

### invitation-not-allowed

- **HTTP status:** 403 Forbidden
- **Meaning:** only internal users may invite external people; the caller is external (for
  example a depositor using an invitation).
- **Typical endpoints:** `POST /invitations`.
- **What to do:** ask an internal user to send the invitation.

### invitation-gone

- **HTTP status:** 410 Gone
- **Meaning:** the invitation has expired or been revoked. An invitation can be used several
  times; each use extends its validity to 12 months after that use.
- **Typical endpoints:** `GET /invitations/{invitationToken}`, `POST /deposit-sessions`,
  `POST /verification-challenges/{challengeId}/confirm`.
- **What to do:** ask the person who invited you for a new invitation.

### verification-code-invalid

- **HTTP status:** 422 Unprocessable Content
- **Meaning:** the email verification code is wrong. `attemptsRemaining` tells how many tries
  are left before the code is invalidated.
- **Typical endpoints:** `POST /verification-challenges/{challengeId}/confirm`.
- **What to do:** check the code received by email and try again.

### verification-exhausted

- **HTTP status:** 410 Gone
- **Meaning:** the verification code has been invalidated, after too many wrong attempts or
  because it expired (codes are valid for 15 minutes).
- **Typical endpoints:** `POST /verification-challenges/{challengeId}/confirm`.
- **What to do:** request a new code (`POST /deposit-sessions`). Code sending is rate limited.

### not-found

- **HTTP status:** 404 Not Found
- **Meaning:** the resource does not exist, or it belongs to another entity or is outside the
  caller's scope. Both cases return the same response on purpose. The administration
  (`/admin/*`) exists only on the dedicated admin host (`TT_ADMIN_HOSTS`): under an entity
  host every `/admin/*` path answers `not-found`, and under the admin host every entity
  endpoint does. An unknown, used or expired activation link also answers `not-found`, and so
  does an entity a delegated admin is not assigned to, exactly like an entity that does not
  exist, and an entity being deleted. A transfer or an upload created by another API token, or
  by a deposit session, answers `not-found` to a token (and one created by a token answers it to
  any deposit session), and a deposit operation called with an API token on the admin host
  answers it too. The public branding images answer `not-found` for a logo
  the entity has not configured (the background falls back to the default image), and a legal
  document the entity has written in neither the negotiated nor its default language.
- **Typical endpoints:** any endpoint with an identifier in its path, `/admin/*` on an entity
  host, `POST /admin/activation`.
- **What to do:** check the identifier or link. Do not retry unchanged.

### method-not-allowed

- **HTTP status:** 405 Method Not Allowed
- **Meaning:** the path exists but does not accept this HTTP method. The `Allow` response
  header lists the accepted methods.
- **Typical endpoints:** any endpoint.
- **What to do:** fix the HTTP method using the `Allow` header. Do not retry unchanged.

### transfer-gone

- **HTTP status:** 410 Gone
- **Meaning:** the transfer has expired, been deleted, or been removed after its first download. Since 1.1, also: the original transfer of a reply is no longer available (when the reply session is opened, when the reply transfer is created, or when it is finalized).
- **Typical endpoints:** `GET /downloads/{linkToken}` and its sub-resources, `POST /downloads/{linkToken}/reply`, `POST /transfers` and `POST /transfers/{transferId}/finalize` for a reply.
- **What to do:** ask the sender to send the files again.

### download-locked

- **HTTP status:** 401 Unauthorized
- **Meaning:** the transfer is password protected and has not been unlocked in this browser.
- **Typical endpoints:** `GET /downloads/{linkToken}/files/{fileId}`,
  `GET /downloads/{linkToken}/archive`.
- **What to do:** unlock the transfer with `POST /downloads/{linkToken}/unlock`, then retry.
  The password is sent by the sender through another channel.

### transfer-password-invalid

- **HTTP status:** 401 Unauthorized
- **Meaning:** the transfer password is wrong. `attemptsRemaining` tells how many tries are
  left before the transfer is temporarily locked.
- **Typical endpoints:** `POST /downloads/{linkToken}/unlock`.
- **What to do:** check the password with the sender and try again.

### transfer-locked

- **HTTP status:** 429 Too Many Requests
- **Meaning:** too many wrong passwords were entered (3); unlocking is blocked for 15 minutes.
- **Typical endpoints:** `POST /downloads/{linkToken}/unlock`.
- **What to do:** wait for `Retry-After` (`retryAfterSeconds`) seconds before trying again.

### state-conflict

- **HTTP status:** 409 Conflict
- **Meaning:** the operation is not allowed in the current state of the resource. Examples:
  cancelling or finalizing a transfer that is no longer being uploaded, or while one of its
  uploads is in progress (another request holds it); finalizing a transfer that has no file
  left because every upload was terminated, or one of whose files has no key any more; an
  `Idempotency-Key` replayed with a different request body; resending the notification of a
  transfer that is not `available`; an admin deleting a transfer while one of its uploads (tus
  `PATCH`) is in progress, answered with `Retry-After` (`retryAfterSeconds`): deleting a
  transfer that has already ended is not a conflict but a `204` no-op; a GDPR erasure
  (`eraseDataSubject`) that meets a transfer of the address being uploaded, or a deposit
  started meanwhile with one of its invitations, answered with `Retry-After`: what was already
  erased stays erased and every step can be replayed, so repeating the call after the delay
  completes the erasure (revoking an invitation is never a conflict: an invitation already
  revoked or expired is a `204` no-op);
  deleting, disabling, demoting or resetting the last usable super admin (not disabled,
  activated, TOTP enabled); an admin deleting, disabling, demoting or resetting their own
  account; promoting to super admin an account that is not activated or has no TOTP enabled;
  resetting the credentials of a disabled account; confirming a TOTP enrollment that was not
  started or whose secret expired (15 minutes after the start); renaming or re-scoping an API
  token that is revoked; disabling maintenance mode (`enabled: false`) while `TT_MAINTENANCE=true`
  forces it (enabling it is accepted: the messages are stored); starting a master key rotation
  while one is already running in this instance (or was started meanwhile by
  `rotate-master-key`), while an interrupted rotation between other keys than the configured
  ones exists (configure its keys to resume it, or abandon it with
  `rotate-master-key -abandon`), or once the rotation to the configured new key has completed
  (`restartRequired: true` in `GET /admin/system/master-key`: restart with the new key as
  `TT_MASTER_KEY_FILE`). Each of these three rotation cases carries its own `detail` (rotation
  running, rotation between other keys unfinished, restart required); it never names a key.
  `GET /admin/system/master-key` reports the same state.
- **Typical endpoints:** `POST /transfers`, `DELETE /transfers/{transferId}`,
  `POST /transfers/{transferId}/finalize`,
  `DELETE /admin/tenants/{tenantId}/transfers/{transferId}`,
  `POST /admin/tenants/{tenantId}/transfers/{transferId}/resend`,
  `POST /downloads/{linkToken}/abuse-reports`,
  `POST /admin/tenants/{tenantId}/data-subjects/erase`,
  `PUT /admin/system/maintenance`, `POST /admin/system/master-key/rotations`,
  `PATCH /admin/admins/{adminId}`,
  `DELETE /admin/admins/{adminId}`, `POST /admin/admins/{adminId}/reset-credentials`,
  `POST /admin/me/totp/confirm`, `PATCH /admin/tenants/{tenantId}/api-tokens/{tokenId}`.
- **What to do:** reload the resource to get its current state before deciding what to do;
  when `Retry-After` is present, retry after that delay.

### already-exists

- **HTTP status:** 409 Conflict
- **Meaning:** a resource with the same unique key already exists (for example an entity FQDN
  such as `transfer.entity-b.example.com`, an admin username or a blocklist entry).
- **Typical endpoints:** `POST /admin/tenants`, `PATCH /admin/tenants/{tenantId}`,
  `POST /admin/admins`, `POST /admin/tenants/{tenantId}/blocklist`.
- **What to do:** choose another value or update the existing resource.

### upload-incomplete

- **HTTP status:** 409 Conflict
- **Meaning:** the transfer cannot be finalized because some files have not been fully
  uploaded. `files` lists them.
- **Typical endpoints:** `POST /transfers/{transferId}/finalize`.
- **What to do:** resume the tus uploads of the listed files (`HEAD` then `PATCH` on
  `/uploads/{uploadId}`), then finalize again.

### checksum-mismatch

- **HTTP status:** 409 Conflict
- **Meaning:** the SHA-256 computed by the server for an uploaded file does not match the
  fingerprint declared by the client. `files` lists the files concerned.
- **Typical endpoints:** `POST /transfers/{transferId}/finalize`.
- **What to do:** check the source files, then create a new transfer.

### transfer-too-large

- **HTTP status:** 413 Content Too Large
- **Meaning:** the declared total size of the transfer exceeds the per-transfer limit of the
  entity, given in `maxTransferBytes`.
- **Typical endpoints:** `POST /transfers`.
- **What to do:** split the files across several transfers.

### payload-too-large

- **HTTP status:** 413 Content Too Large
- **Meaning:** the request body is larger than the endpoint accepts (for example a logo above
  5 MiB or a background image above 10 MiB), or an image whose dimensions exceed the limits of
  its kind or whose decoding and re-encoding would need more than 320 MiB (both checked before
  decoding; see `docs/operations/tenants.md` for the resulting limits per format).
- **Typical endpoints:** `PUT /admin/tenants/{tenantId}/branding/{asset}`.
- **What to do:** send a smaller body.

### range-not-satisfiable

- **HTTP status:** 416 Range Not Satisfiable
- **Meaning:** the byte range requested to resume a download is outside the file. The
  `Content-Range` header (`bytes */<size>`) gives the size of the file.
- **Typical endpoints:** `GET /downloads/{linkToken}/files/{fileId}`.
- **What to do:** request a range within the file, or the whole file without `Range`.

### unsupported-media-type

- **HTTP status:** 415 Unsupported Media Type
- **Meaning:** the `Content-Type` of the request is not accepted by the endpoint, or a branding
  image is not a PNG, JPEG or WebP image (detected from its content, whatever its declared type;
  SVG is refused). A branding upload must declare an `image/*` type.
- **Typical endpoints:** `PUT /admin/tenants/{tenantId}/branding/{asset}`, any JSON endpoint
  called without `application/json`.
- **What to do:** send the body with a supported media type.

### quota-exceeded

- **HTTP status:** 507 Insufficient Storage
- **Meaning:** the storage quota of the entity is reached. New deposits are blocked until space
  is freed by expiration or deletion; the administrators are notified.
- **Typical endpoints:** `POST /transfers`.
- **What to do:** try again later, or contact the administrators of the service.

### rate-limited

- **HTTP status:** 429 Too Many Requests
- **Meaning:** too many requests were made from this client, for this address or by this user,
  or the service is temporarily saturated. Examples: verification codes (5 per hour per
  address, 20 per hour per client IP), invitations (20 per hour per inviting address), sign-in
  attempts, repeated invalid API tokens from the same client IP (10 within 10 minutes lock that
  IP, an IPv6 address counting as its /64, for 15 minutes: every further invalid token gets
  `429`, while a valid token keeps working; the tus operations answer `429` without a body),
  the mail queue of the service (or of the entity) being full, or the
  open-transfer cap: a sender may have only a limited number of unfinished transfers at once
  (`TT_MAX_OPEN_TRANSFERS`, 10 by default, for an internal user and for each API token; 3 for an
  invited external depositor; finalizing or cancelling one frees a slot), or too many simultaneous download
  streams (2 per client for one transfer, 4 for one transfer, 8 per client across the
  transfers of the entity; a client is an IP address, an IPv6 address counting as its /64).
  On the admin host: failed sign-ins (5 per username and client IP, 20 per client IP within
  15 minutes lock for 15 minutes; 5 wrong second factors of one admin, TOTP enrollment
  confirmations and the TOTP re-confirmation of a master key rotation included, lock their
  second factor for 15 minutes), and a per-client limit of
  the sign-in steps (setup, password, second factor, TOTP enrollment confirmation, activation:
  20 at once, then one every 3 seconds), the SMTP tests of an entity (5 per administrator
  and entity within 10 minutes), and the notification resends of a transfer (5 per hour per
  transfer, whoever the administrator), and abuse reports (3 per day per recipient link,
  5 per hour per client IP).
- **Typical endpoints:** any endpoint, mainly `POST /deposit-sessions`, `POST /invitations`,
  `POST /transfers`, `GET /downloads/{linkToken}/files/{fileId}`,
  `GET /downloads/{linkToken}/archive`, `POST /admin/auth/login`, `POST /admin/auth/totp`,
  `POST /admin/setup`, `POST /admin/activation`, `POST /admin/me/totp/confirm`,
  `PUT /admin/me/password`, `POST /admin/tenants/{tenantId}/smtp/test`,
  `POST /admin/tenants/{tenantId}/transfers/{transferId}/resend`,
  `POST /admin/system/master-key/rotations`.
- **What to do:** wait for `Retry-After` (`retryAfterSeconds`) seconds before retrying. Scripts
  must not retry in a tight loop.

### maintenance

- **HTTP status:** 503 Service Unavailable
- **Meaning:** maintenance mode is active (`TT_MAINTENANCE=true` or enabled by the super admin);
  new deposits are temporarily refused. Downloads, the administration and the health check keep
  working. When the super admin set a maintenance message, `detail` carries it as plain text, in
  the language negotiated from `Accept-Language`, else the entity's default language, else
  English, else any language that has one; without a message, `detail` is absent. The `title`
  stays in English. The response carries `Retry-After` (300 seconds, also in
  `retryAfterSeconds`). The tus `PATCH` requests get a `503` without a body, with
  `Tus-Resumable` and `Retry-After`: resume the upload (`HEAD`, then `PATCH`) after the
  maintenance. The problem carries no `Content-Language` and does not say which language the
  `detail` is written in (it may be a fallback); `GET /tenant` reports `maintenance: true`, the
  same message as `maintenanceMessage` and its language as `maintenanceMessageLanguage`, to mark
  the message up (for example the HTML `lang` attribute).
- **Typical endpoints:** `POST /deposit-sessions`, `POST /transfers`,
  `PATCH /uploads/{uploadId}`, `POST /transfers/{transferId}/finalize`, `POST /invitations`.
- **What to do:** retry after `Retry-After`; show `detail` (as text, never as HTML) to the user.

### mail-unavailable

- **HTTP status:** 503 Service Unavailable
- **Meaning:** the verification, invitation or notification email cannot be sent right now: no
  SMTP server is configured for the entity, its SMTP settings are unusable, the SMTP circuit of the entity is
  open (its server failed several times in a row and is not tried again for a minute), or the
  mail queue is shutting down. Nothing was sent, and nothing was changed. Admin activation
  links are never mailed (they are returned by `POST /admin/admins` and
  `POST /admin/admins/{adminId}/reset-credentials`). In the administration, only the resend of
  a transfer notification answers it, when no SMTP server is configured for the entity.
- **Typical endpoints:** `POST /deposit-sessions`, `POST /invitations`,
  `POST /admin/tenants/{tenantId}/transfers/{transferId}/resend`.
- **What to do:** retry later. If the error persists, contact the administrators of the service:
  the SMTP settings of the entity are probably missing.

### unknown-tenant

- **HTTP status:** 421 Misdirected Request
- **Meaning:** the `Host` header matches neither a configured entity nor an admin host
  (`TT_ADMIN_HOSTS`). The admin host never answers it. An admin host can never be the FQDN of
  an entity: the server refuses to start when one is, and the creation of an entity with that
  FQDN is refused.
- **Typical endpoints:** any endpoint.
- **What to do:** use the address of your entity (for example
  `https://transfer.entity-a.example.com`). Check the reverse proxy configuration if the address
  is correct.

### setup-already-done

- **HTTP status:** 409 Conflict
- **Meaning:** the first-run setup (super admin creation) has already been completed.
- **Typical endpoints:** `POST /admin/setup`.
- **What to do:** sign in with the existing super admin account.

### setup-token-invalid

- **HTTP status:** 403 Forbidden
- **Meaning:** the first-run setup token is missing or wrong. The setup always needs one: the
  value of the `TT_SETUP_TOKEN` environment variable when it is configured, otherwise a random
  token that the server generates at each start while no admin exists and writes once, at
  warning level, to its application log (`docker logs`).
- **Typical endpoints:** `POST /admin/setup`.
- **What to do:** send the value of `TT_SETUP_TOKEN`, or the token of the last start found in
  the application log, in `setupToken`.

### new-master-key-missing

- **HTTP status:** 409 Conflict
- **Meaning:** a master key rotation was requested but no new master key is provided to the
  container (`TT_MASTER_KEY_NEW_FILE`). It is checked before the TOTP code, so no attempt is
  consumed.
- **Typical endpoints:** `POST /admin/system/master-key/rotations`.
- **What to do:** provide the new master key (Docker secret or mounted file, see
  `docs/operations/master-key.md`), restart the container, then start the rotation again.

### recipient-domain-refused

- **HTTP status:** 403 Forbidden
- **Since:** 1.1.
- **Meaning:** at least one recipient is refused by the recipient domain rules of the entity (a denied domain, or a domain outside a non-empty allow list). Each refused recipient is named in `errors` (`/recipients/<index>`, code `domain-denied`).
- **Typical endpoints:** `POST /transfers`.
- **What to do:** remove or replace the refused recipients.

### confidentiality-rule-violated

- **HTTP status:** 422 Unprocessable Content
- **Since:** 1.1.
- **Meaning:** the transfer breaks a rule of its confidentiality level; each entry of `errors` names the field and the rule (`required`, `not-allowed` with `allowed`, `internal-only`, `max-exceeded`).
- **Typical endpoints:** `POST /transfers`.
- **What to do:** adjust the transfer to the rules of the level (password, recipient verification, duration, recipients), or choose another level.

### abuse-threshold-blocked

- **HTTP status:** 403 Forbidden
- **Since:** 1.1.
- **Meaning:** the abuse detection of the entity is set to block and the transfer would exceed a daily limit of an internal sender (volume, number of transfers, recipients per transfer; these limits never apply to invited externals) or an external quota. Only the first refusal of the day per sender and rule is audited and alerted. The administrators are alerted.
- **Typical endpoints:** `POST /transfers`.
- **What to do:** try again the next day (calendar day of the time zone configured for the entity), or ask the administrators of the entity.

### recipient-verification-required

- **HTTP status:** 401 Unauthorized
- **Since:** 1.1.
- **Meaning:** the per-recipient link requires the recipient to prove their address with a code on this browser first (or a reply is attempted without that proof).
- **Typical endpoints:** `GET /downloads/{linkToken}/files/{fileId}`, `GET /downloads/{linkToken}/archive`, `POST /downloads/{linkToken}/unlock`, `POST /downloads/{linkToken}/reply`.
- **What to do:** call `POST /downloads/{linkToken}/verification`, then confirm the code received by mail with `POST /downloads/{linkToken}/verification/confirm`.

### max-downloads-reached

- **HTTP status:** 410 Gone
- **Since:** 1.1.
- **Meaning:** the transfer reached the maximum number of downloads chosen by its sender; it is deleted after a short grace period.
- **Typical endpoints:** `GET /downloads/{linkToken}`, `POST /downloads/{linkToken}/unlock`, `GET /downloads/{linkToken}/files/{fileId}`, `GET /downloads/{linkToken}/archive`. A download already started by the same client can still be resumed during the grace period.
- **What to do:** ask the sender for a new transfer.

### reply-not-allowed

- **HTTP status:** 403 Forbidden
- **Since:** 1.1.
- **Meaning:** replying to this transfer is not possible: the entity does not allow replies, the link is a shared link created before version 1.1, the transfer was not sent by an internal depositor, or it is itself a reply (no reply to a reply). The original sender may also be blocklisted or no longer internal.
- **Typical endpoints:** `POST /downloads/{linkToken}/reply`, `POST /downloads/{linkToken}/verification` (purpose `reply`), `POST /transfers` and `POST /transfers/{transferId}/finalize` (a reply whose entity disabled replies meanwhile).
- **What to do:** contact the sender by another means.

### access-link-invalid

- **HTTP status:** 410 Gone
- **Since:** 1.1.
- **Meaning:** the "My transfers" access link is unknown, expired (15 minutes) or already used.
- **Typical endpoints:** `POST /me/sessions`.
- **What to do:** request a new link with `POST /me/access-links`.

### extension-limit-reached

- **HTTP status:** 409 Conflict
- **Since:** 1.1.
- **Meaning:** extending the transfer would keep it available more than 90 days after its creation; `extendableTo` of the transfer tells the latest expiry possible.
- **Typical endpoints:** `POST /me/transfers/{transferId}/extension`.
- **What to do:** choose a shorter duration, or send the files again in a new transfer.

### internal-error

- **HTTP status:** 500 Internal Server Error
- **Meaning:** an unexpected server-side error occurred. The response never contains internal
  details. When the deletion of an entity fails midway, the entity stays in the `deleting`
  status (no longer served, visible to the super admin only): repeating
  `DELETE /admin/tenants/{tenantId}` resumes it from where it stopped, and the periodic cleanup
  task completes it otherwise.
- **Typical endpoints:** any endpoint.
- **What to do:** retry later. If the error persists, report it to the administrators with the
  `instance` identifier so they can find it in the logs.

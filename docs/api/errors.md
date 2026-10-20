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
| `errors` | `validation-failed` | List of `{field, code, allowed?}` objects, one per invalid field. |
| `attemptsRemaining` | `verification-code-invalid`, `transfer-password-invalid` | Number of attempts left before lockout or invalidation. |
| `retryAfterSeconds` | `rate-limited`, `transfer-locked`, `maintenance` | Seconds to wait before retrying; the `Retry-After` header carries the same value. |
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
  accepted values (for example `expiryDays` with `allowed: [1, 7, 30]`).
- **Typical endpoints:** any endpoint accepting a body or query parameters.
- **What to do:** fix the listed fields and send the request again. Do not retry unchanged.

### unauthenticated

- **HTTP status:** 401 Unauthorized
- **Meaning:** credentials are missing or expired: no admin session, expired deposit session,
  or missing API token.
- **Typical endpoints:** `/admin/*`, `/transfers`, `/invitations`, `/deposit-sessions/current`.
- **What to do:** sign in again, verify the email address again, or send the
  `Authorization: Bearer <token>` header.

### invalid-credentials

- **HTTP status:** 401 Unauthorized
- **Meaning:** wrong username or password, wrong TOTP code, or an invalid, revoked or expired
  API token. The response does not say which part was wrong.
- **Typical endpoints:** `POST /admin/auth/login`, `POST /admin/auth/totp`,
  `PUT /admin/me/password`, any endpoint called with an API token.
- **What to do:** check the credentials. Repeated failures lead to `rate-limited` and may get
  the client IP banned.

### forbidden

- **HTTP status:** 403 Forbidden
- **Meaning:** the caller is authenticated but its role does not allow the operation (for
  example a delegated admin calling a super admin endpoint).
- **Typical endpoints:** `/admin/system/*`, `/admin/admins`, `POST /admin/tenants`.
- **What to do:** do not retry; ask a super admin if the access is legitimately needed.

### csrf-invalid

- **HTTP status:** 403 Forbidden
- **Meaning:** the CSRF token of a cookie-authenticated, state-changing request is missing or
  invalid.
- **Typical endpoints:** state-changing requests made from the browser with a session cookie,
  e.g. `DELETE /transfers/{transferId}`, `DELETE /deposit-sessions/current`. The request is
  also refused when its `Origin` header is present and differs from `https://<entity host>`, or
  when its `Sec-Fetch-Site` header is present and is not `same-origin`.
- **What to do:** send the `csrfToken` returned in the session payload in the `X-CSRF-Token`
  header; reload the page to obtain a fresh one, then retry.

### deposit-not-allowed

- **HTTP status:** 403 Forbidden
- **Meaning:** a public deposit is refused. The code is deliberately generic and identical for
  every reason (client outside the internal IP ranges of the entity, email domain not internal,
  address or domain on the blocklist), so that the response does not reveal which check failed.
  The precise reason is written to the security log only.
- **Typical endpoints:** `POST /deposit-sessions`,
  `POST /verification-challenges/{challengeId}/confirm`, `POST /transfers`, `POST /invitations`.
- **What to do:** deposit from the internal network with an internal address, or ask an internal
  user for an invitation.

### ip-not-allowed

- **HTTP status:** 403 Forbidden
- **Meaning:** an API token was used from an IP address outside the `allowedCidrs` configured
  for that token. This code is only visible to the token holder.
- **Typical endpoints:** any endpoint called with an API token, mainly `POST /transfers`.
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
  caller's scope. Both cases return the same response on purpose.
- **Typical endpoints:** any endpoint with an identifier in its path.
- **What to do:** check the identifier or link. Do not retry unchanged.

### method-not-allowed

- **HTTP status:** 405 Method Not Allowed
- **Meaning:** the path exists but does not accept this HTTP method. The `Allow` response
  header lists the accepted methods.
- **Typical endpoints:** any endpoint.
- **What to do:** fix the HTTP method using the `Allow` header. Do not retry unchanged.

### transfer-gone

- **HTTP status:** 410 Gone
- **Meaning:** the transfer has expired, been deleted, or been removed after its first download.
- **Typical endpoints:** `GET /downloads/{linkToken}` and its sub-resources.
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
- **Meaning:** the operation is not allowed in the current state of the resource (for example
  deleting a transfer that is already being deleted, or resending an expired transfer).
- **Typical endpoints:** `DELETE /transfers/{transferId}`,
  `POST /admin/tenants/{tenantId}/transfers/{transferId}/resend`,
  `PUT /admin/system/maintenance`.
- **What to do:** reload the resource to get its current state before deciding what to do.

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
- **Meaning:** the request body is larger than the endpoint accepts (for example an oversized
  logo or background image).
- **Typical endpoints:** `PUT /admin/tenants/{tenantId}/branding/{asset}`.
- **What to do:** send a smaller body.

### unsupported-media-type

- **HTTP status:** 415 Unsupported Media Type
- **Meaning:** the `Content-Type` of the request is not accepted by the endpoint.
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
  attempts, API calls, or the mail queue of the service (or of the entity) being full.
- **Typical endpoints:** any endpoint, mainly `POST /deposit-sessions`, `POST /invitations`,
  `POST /admin/auth/login`.
- **What to do:** wait for `Retry-After` (`retryAfterSeconds`) seconds before retrying. Scripts
  must not retry in a tight loop.

### maintenance

- **HTTP status:** 503 Service Unavailable
- **Meaning:** maintenance mode is active; new deposits are temporarily refused. Downloads and
  the health check keep working.
- **Typical endpoints:** `POST /deposit-sessions`, `POST /transfers`,
  `POST /transfers/{transferId}/finalize`, `POST /invitations`.
- **What to do:** retry later, after `Retry-After` when present.

### mail-unavailable

- **HTTP status:** 503 Service Unavailable
- **Meaning:** the verification or invitation email cannot be sent right now: no SMTP server
  is configured for the entity, its SMTP settings are unusable, the SMTP circuit of the entity
  is open (its server failed several times in a row and is not tried again for a minute), or
  the mail queue is shutting down. Nothing was sent.
- **Typical endpoints:** `POST /deposit-sessions`, `POST /invitations`.
- **What to do:** retry later. If the error persists, contact the administrators of the service:
  the SMTP settings of the entity are probably missing.

### unknown-tenant

- **HTTP status:** 421 Misdirected Request
- **Meaning:** the `Host` header does not match any configured entity.
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
- **Meaning:** the first-run setup token is missing or wrong (only checked when the
  `TT_SETUP_TOKEN` environment variable is configured).
- **Typical endpoints:** `POST /admin/setup`.
- **What to do:** send the value of `TT_SETUP_TOKEN` in `setupToken`.

### new-master-key-missing

- **HTTP status:** 409 Conflict
- **Meaning:** a master key rotation was requested but no new master key is provided to the
  container.
- **Typical endpoints:** `POST /admin/system/master-key/rotations`.
- **What to do:** provide the new master key (Docker secret or mounted file, as described in the
  installation guide), restart the container, then start the rotation again.

### internal-error

- **HTTP status:** 500 Internal Server Error
- **Meaning:** an unexpected server-side error occurred. The response never contains internal
  details.
- **Typical endpoints:** any endpoint.
- **What to do:** retry later. If the error persists, report it to the administrators with the
  `instance` identifier so they can find it in the logs.

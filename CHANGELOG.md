# Changelog

All notable changes to TransTeira are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- OpenAPI 3.1 specification of the V1 API (`api/openapi.yaml`).
- Project layout proposal (`docs/architecture/project-structure.md`).
- STRIDE threat model (`docs/security/threat-model.md`).
- Claude Code project settings and specialised agents (tests, security review, code review).
- Go module `github.com/ed-fr/transteira` with pinned tools (golangci-lint, govulncheck,
  oapi-codegen) run through `go tool`; gitleaks is pinned and run with `go run` in its own
  module graph.
- Local quality pipeline `make check`: formatting, vet, lint, govulncheck, Spectral OpenAPI lint,
  generated-code and `.env.example` freshness, tests and coverage thresholds.
- Pre-push gitleaks hook (`make hooks`).
- Packages `internal/version`, `internal/config`, `internal/api/problem` (RFC 9457),
  code generated from the OpenAPI specification (`internal/api/gen`), and the
  `transteira` binary skeleton.
- AGPL-3.0 `LICENSE`, `README.md`, `SECURITY.md`, `.env.example`.
- Data layer `internal/store` on SQLite (pure Go driver) and PostgreSQL (pgx): query registry
  validating every tenant query (exactly one `tenant_id = ?`, single table), typed scoped and
  system executors, repositories for tenants, network rules and blocklist.
- PostgreSQL row-level security as a second isolation layer, with two roles (owner for
  migrations via `TT_DB_MIGRATE_DSN`, runtime role owning nothing) and a startup check refusing
  unsafe role configurations.
- Versioned migrations applied by `transteira migrate` (checksums, lock, refusal of a newer schema).
- Packages `internal/tenant` (Host normalisation, cached resolver) and `internal/id` (prefixed
  ULIDs, high-entropy tokens).
- PostgreSQL test environment (`test/docker-compose.test.yml`) and adversarial tenant isolation
  tests (`test/isolation`); `make check` now requires PostgreSQL.
- `docs/install/postgresql.md`: PostgreSQL role setup.
- `transteira serve`: HTTP server on the standard library mux with the generated strict server
  interface; middlewares for panic recovery, request IDs, real client IP from trusted proxies only,
  tenant resolution by `Host` (unknown hosts → `421` and security log), security headers, per-IP
  rate limiting, JSON body limit and maintenance mode for deposit operations. Unknown hosts are
  rejected on every path except `/healthz` and `/api/openapi.yaml`. A trusted proxy that sends no
  valid client address yields an unknown client (fail closed). Startup is refused when trusted
  proxies cover every address or use a prefix shorter than /8 (IPv4) or /32 (IPv6).
- Per-operation read and write deadlines (30 s, 2 min for images) on non-streaming routes;
  graceful shutdown within Docker's default stop delay.
- `rate_limited` security events are written at most once per client key and scope every 10 s;
  unknown hosts have their own per-IP limiter (burst of 10, then one every 12 s, then `429`).
- `/healthz` (database, ClamAV `PING`, storage; shared and cached for 3 s), `/api/openapi.yaml` and `GET /api/v1/version`;
  `transteira healthcheck` for container health checks.
- Security log (`TT_LOG_DIR/security.log`) in a stable, injection-proof line format, with
  fail2ban (filter, jail, `DOCKER-USER` action) and CrowdSec (parser, scenarios) integrations and
  `docs/operations/security-log.md`.
- `internal/ratelimit` (keyed token buckets and sliding lockout windows whose locked entries are
  never evicted) and `tools/genstubs` (generated not-implemented stubs for every API operation).
- Problem code `method-not-allowed` (405).
- `internal/crypto`: master key file (base64, 32 bytes; degenerate keys refused) with a derived,
  non-secret key ID; envelope encryption of per-file keys and secrets (AES-256-GCM, per-purpose
  HKDF keys, AAD binding purpose, tenant and row); chunked AES-256-GCM file format (STREAM
  construction, decision P7) with sequential and random-access (HTTP Range) readers, and
  resumable checkpoints that seal the pending tail and caller data under a separate subkey and
  never reuse a nonce; reference test vectors checked by an independent standard-library test.
- Migration `0002_encryption`: `wrapped_keys` (tenant-scoped, row-level security),
  `master_keys` (readable by tenants, IDs are not secret) and `key_rotations`; triggers refusing
  to wrap a key under a retired master key; SQLite `secure_delete` and WAL truncation after
  crypto-erase (`DB.ScrubDeleted`).
- `internal/masterkey`: keyring, vault (seal, open and destroy wrapped keys, also inside a tenant
  transaction), startup key check (start refused on missing, retired or unregistered keys and on
  inconsistent rotations) and resumable `transteira rotate-master-key`, with `-abandon` and
  `-recover-from` (re-wrap keys left under a retired key without loading it into the server).
- `docs/operations/master-key.md`: key generation, storage, rotation, recovery, crypto-erase
  limits for backups, backup and restore; README links to it.
- Depositor identification (`internal/deposit`): eligibility (blocklist, invitation bound to the
  invited address, internal IP range and domain rule), 6-digit verification codes (HMAC-protected,
  15 minutes, 2 attempts, 5 per address and 20 per IP per hour counted in the database), verified
  addresses, deposit sessions (`__Host-tt_deposit` cookie, CSRF token, Origin and Sec-Fetch-Site
  checks) and external invitations; operations `startDepositSession`,
  `confirmVerificationChallenge`, `getCurrentDepositSession`, `endDepositSession`,
  `createInvitation` and `getInvitation`.
- Technical recognition cookie `__Host-tt_known` (decision P26): an already verified internal
  address opens a session without a code only on a browser that confirmed a code for it before;
  deposits through an invitation always require a code. At most 20 invitations per hour per
  inviter.
- `internal/netpolicy`: the internal-user rule (IP range and mail domain), re-evaluated on each
  action.
- Migration `0003_deposit`: SMTP settings, verification challenges, verified addresses, deposit
  sessions and invitations, all tenant-scoped with row-level security.
- `internal/mail`: per-tenant SMTP (plain relay, STARTTLS, implicit TLS), header-injection-proof
  MIME builder, French and English templates, asynchronous queue fair between tenants (per-tenant
  concurrency and backlog caps, per-tenant circuit breaker); `internal/i18n` language
  negotiation. Mailpit in the test environment.
- `internal/crypto`: keyed MACs per purpose (verification codes, CSRF tokens).
- Configuration: `TT_SMTP_TIMEOUT`, `TT_MAIL_QUEUE_SIZE`.
- Problem code `mail-unavailable` (503).
- Transfers and resumable uploads (step 6): operations `createTransfer`, `getTransfer`,
  `cancelTransfer`, `finalizeTransfer` (checks, then `scanning`; antivirus comes next) and tus
  `OPTIONS`/`HEAD`/`PATCH`/`DELETE` on `/uploads/{uploadId}`. Eligibility re-checked at creation and
  finalization, quota reserved at creation, recipient forced to the inviter for external
  depositors, `Idempotency-Key`, argon2id transfer passwords.
- `internal/upload`: tus engine with a per-file lock, streaming encryption and SHA-256, sealed
  checkpoints written atomically after fsync, reset with a new key after a crash, upload expiry
  (`TT_UPLOAD_TTL`) and idle read timeout (`TT_UPLOAD_IDLE_TIMEOUT`).
- `internal/storage` (files confined with `os.Root`, one directory per tenant, random names),
  `internal/filename` (file name rules, decision P8), argon2id in `internal/crypto`.
- Migration `0004_transfers`: transfers, recipients and files with row-level security.
- Antivirus and notifications (step 7): `internal/antivirus` scans with clamd `INSTREAM` (size
  limit, idle and overall timeouts); `internal/scan` takes finalized transfers to `available` or
  `rejected`, fail-closed while clamd is unreachable (retry with back-off, resumed at start-up),
  erases infected files (key first), withholds files that cannot be analysed (`scan_error`),
  creates the `dl_` download link (hash stored, sealed copy for re-display) and sends the mails;
  `internal/notify` builds them (one mail per recipient with an inline QR code and SHA-256
  fingerprints, sender confirmation, `file_problems`, `file_not_scanned`).
- Migration `0005_scan`: scan results, download token and availability date.
- Configuration: `TT_CLAMAV_MAX_SCAN_BYTES`, `TT_CLAMAV_TIMEOUT`, `TT_SCAN_WORKERS`.
- `docs/operations/antivirus.md`: scan flow, fail-closed behaviour, clamd limits, signatures.
- Downloads (step 8): operations `getDownload`, `unlockDownload`, `downloadFile` (single range,
  forced attachment headers, `Content-Security-Policy: default-src 'none'; sandbox; frame-ancestors 'none'`, strong `ETag`, `416` as Problem Details) and `downloadArchive` (ZIP64 in store
  mode with an exact `Content-Length`); transfer passwords checked with argon2id and locked for
  15 minutes after 3 failures within a sliding 15-minute window, per transfer and per IP (counted
  before hashing, stored in the database; a right password refunds only its own IP attempt); `__Host-tt_dl` unlock cookie; first download detected from the union of served ranges
  or a complete archive, acknowledged once to the sender (`first_download` mail); deletion after the
  first download once `TT_DELETE_AFTER_DOWNLOAD_GRACE` has passed (`internal/lifecycle`).
- `internal/zipstream`, `internal/download`, `internal/lifecycle`; migration `0006_download`
  (first download, scheduled deletion, password failure counters).
- Download stream caps (2 per client per transfer, 4 per transfer, 8 per client, `429` with
  `Retry-After`, logged as `rate_limited` scope `download_streams`, not counted by the shipped
  fail2ban and CrowdSec rules); write idle timeout `TT_DOWNLOAD_IDLE_TIMEOUT`.
- `mail.Retrier` and `notify.ViewOf` shared by the scan and download services.
- Go toolchain pinned to 1.27.3 (fix for GO-2026-6809 in `crypto/x509`).
- Cleanup task (step 9): `internal/lifecycle` becomes the single periodic task of section 20 —
  expiry of transfers (keys destroyed, files erased, status `expired`), abandoned tus uploads (quota
  released), purge of ended transfers after 30 days, of used or expired verification codes, ended
  sessions, stale password failure counters, addresses and invitations unused for 12 months, daily
  reconciliation of orphan files on disk (24-hour grace).
- Nightly SQLite copy (`VACUUM INTO`, `quick_check`, atomic rename, rotation): `TT_BACKUP_TIME`,
  `TT_BACKUP_KEEP`; with PostgreSQL, a dedicated `pg_dump` container (`docs/operations/backup.md`).
- Migration `0007_cleanup` (`transfers.ended_at`, purge and keyset sweep indexes); `storage`
  listing for the reconciliation; sweeps paged by cursor; a transfer stuck in analysis expires
  30 days after its finalization (never on its provisional expiry); `TT_BACKUP_DIR` must not
  overlap the data, log or SQLite directories.
- Scan statuses `not_scanned_encrypted` (encrypted archives and documents ClamAV cannot read) and
  partial analyses (`Heuristics.Limits.Exceeded`) reported as not fully scanned; a transfer's validity
  now starts when it becomes available (`expiresAt` is set then); a file that times out, drops
  the clamd connection or crashes clamd is withheld after 3 attempts.
- Configuration: `TT_MAX_RECIPIENTS`, `TT_UPLOAD_IDLE_TIMEOUT`, `TT_MAX_OPEN_TRANSFERS` (open, non-expired
  uploading transfers per internal sender; 3 for invited externals), `TT_UPLOAD_MAX_AGE` (an upload
  expires at most 7 days after its transfer was created, whatever its activity).
- `internal/textsafe`: one sanitiser for free text (control, format, bidirectional and invisible
  characters), shared by invitations and transfers.

### Changed
- OpenAPI: every operation and parameter is described; the SMTP password is removed with an
  explicit `removePassword` flag instead of `null` and must be resent when the SMTP server
  changes; public deposit refusals use the generic `deposit-not-allowed` code; every operation
  documents the `500 internal-error` response.
- Claude Code deny rules extended to key files, production `.env` files and PowerShell.
- OpenAPI: entity identifier patterns follow the strict ULID format
  (`^<prefix>_[0-7][0-9A-HJKMNP-TV-Z]{25}$`); `vch_` and `upl_` tokens carry at least 128 bits;
  FQDNs may end with a punycode label.
- OpenAPI: `KeyRotation` identifiers follow the real formats (`rot_…`, `mk_` + 16 hex characters)
  and its counters are documented 64-bit integers.
- Test PostgreSQL allows 300 connections (parallel test packages).
- OpenAPI: `startDepositSession` and `createInvitation` share a `ServiceUnavailable` 503 response
  (maintenance or mail unavailable); `createInvitation` accepts `Accept-Language`;
  `confirmVerificationChallenge` documents `403 deposit-not-allowed` and `410 invitation-gone`;
  `endDepositSession` documents the cookie-clearing `Set-Cookie`.
- `startDepositSession` answers `201` (session without a code) only for an internal verified address
  presented with a valid recognition cookie; the cookie is documented as the `RecognitionCookie`
  parameter and the `SetDepositCookies` header (formerly `SetDepositCookie`).
- OpenAPI: tus errors are bodyless and always carry `Tus-Resumable` (new `412` response with
  `Tus-Version`); validation errors use JSON pointers; `cancelTransfer` is limited to transfers still
  `uploading`.
- Tenant queries may reference `tenant_id` only in the tenant slot; an alias named `tenant_id` is
  refused.
- OpenAPI: the email template key `virus-detected` is renamed `file-problems` (one alert for the
  infected files and the files withheld after an analysis error); `SenderFile` gains the optional
  sender-only `scanSignature`, `SenderTransfer.downloadUrl` is returned once the transfer is
  available, and `finalizeTransfer` documents the asynchronous, fail-closed analysis.

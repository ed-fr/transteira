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
- Admin accounts and authentication (step 10): dedicated admin host (`TT_ADMIN_HOSTS`, now
  required), first-run setup protected by a setup token (configured, or generated and logged once
  while no admin exists), argon2id passwords, TOTP (RFC 6238, replay refused, secrets sealed by the
  master key and re-wrapped by its rotation), 8 single-use recovery codes, server-side sessions
  (`__Host-tt_admin`, idle `TT_ADMIN_SESSION_IDLE_TIMEOUT`, absolute `TT_ADMIN_SESSION_MAX_AGE`,
  rotated at each step, CSRF token), login lockouts stored in the database, delegated admins with
  activation links shown once to the super admin (never mailed), last super admin protection,
  `transteira admin list`, `transteira admin reset-totp` and `transteira admin reset-password`.
- **Upgrade note**: `TT_ADMIN_HOSTS` is now required; set it to a dedicated admin host name that is
  not a tenant FQDN before starting this version.
- Audit log foundation (`audit_events`, `internal/audit`), purged after 12 months; migration
  `0008_admin`; `docs/operations/admin.md`.
- Tenant configuration (step 11): tenant creation, update (per-transfer ceiling set by the super
  admin, delegated admins limited to language and limit) and resumable deletion with full
  crypto-erase; branding (colors with WCAG contrast check, logo and background re-encoded,
  default background) and public tenant pages; IP ranges and domains; SMTP settings with test,
  DNS check and SSRF guard on every connection (`TT_SMTP_DENY_NETWORKS`); per-tenant mail
  templates (`{{variable}}` syntax only, HTML allowlist, required variables) used by real mails;
  legal notice and privacy policy in limited Markdown; migration `0009_tenant_config`;
  `docs/operations/tenants.md`. Deletion is audited at start (`tenant.deletion_started`) and at
  completion (`tenant.deleted`, system actor `lifecycle`); transfer creation is refused once a
  tenant is being deleted. Image processing is bounded in memory: 320 MiB budget for decoding,
  scaling and re-encoding, worst case per format, color model and layout (tRNS, interlacing,
  MCU rounding, WebP Huffman trees), checked against allocations measured on generated
  worst-case images; one decode and at most 4 buffered upload bodies at a time; backgrounds
  scaled with an approximate bilinear filter, which needs no temporary buffer. `internal/netpolicy` now holds the SMTP dial guard and the
  shared CIDR parser.
- Tenant operations (step 12): migration `0010_operations` (sender IP and download count on
  transfers, daily usage counters `tenant_daily_stats` backfilled from finalized transfers,
  quota alert levels `tenant_quota_alerts`, indexes for the admin lists and GDPR searches;
  row-level security on the new tables); admin operations in `internal/tenantops`: transfer
  list, detail (metadata only), deletion before expiry with crypto-erase (`409` with
  `Retry-After` while an upload is in progress) and notification resend (original recipients
  only, 5 per hour per transfer, existing link never shown nor rotated), invitation list and
  revocation, blocklist management, tenant audit log with filters and instance-wide audit log
  for the super admin. Audit events are now written for transfers (`transfer.created`,
  `.finalized`, `.downloaded`, `.deleted`, `.notification_resent`), invitations
  (`invitation.created`, `.used`, `.revoked`), `address.verified`, the antivirus
  (`file.infected`, `file.not_scanned`), quotas (`quota.warning`, `quota.reached`),
  `blocklist.updated` and data subject rights; the audit package refuses any detail holding
  `@` and `audit.RedactAddresses` redacts free-text reasons (500 characters). Statistics
  (`internal/usage`, `internal/stats`): per-tenant daily counters of finalized transfers,
  bytes uploaded, download starts, bytes served and virus detections, flushed every 30 s and
  kept 13 months, by day (7d, 30d) or month (12m), plus storage against quota; global view
  with disk usage (`internal/diskusage`). Quota alerts (`internal/quota`): 80 % and 100 %
  mails to the delegated admins (else the super admins) through the tenant SMTP, one per
  crossing with hysteresis (75 % / 95 %), audited even without SMTP, checked after each
  creation or refusal and every 15 minutes. GDPR (`internal/datasubject`): search and
  erasure of an address within one tenant (sent and received transfers, invitations, codes,
  sessions, verified address), audit actor replaced by a per-erasure salted pseudonym
  `erased-<16 hex>`, replayable steps (`409` + `Retry-After` when an upload blocks it).
  Antivirus hold (`scan.Worker.Hold`): a transfer deleted while being scanned is withdrawn
  from the analysis before its keys are destroyed and never mails its recipients; holds carry
  an intent (`lifecycle.HoldForErase` drops the mails of a conclusion committed meanwhile,
  `HoldForEdit`, used when a GDPR erasure removes a recipient, defers them and the last
  release sends them from the current state of the transfer), re-checked under the worker
  lock right before sending. Download starts are deduplicated per transfer, object (file or
  archive) and client (IPv4 address or IPv6 /64) over one hour, in a bounded in-memory table
  (100,000 entries): one audit event, download count and usage count per window, and at most
  1,000 recorded starts per transfer per window whatever the clients (a client cycling IPv6
  /64s cannot defeat the deduplication by eviction), while bytes served stay exact. Staged shutdown with per-stage budgets (HTTP server 5 s, handler drain
  1 s, background workers 1 s, usage flush and admin mails 1 s, mail queue drain 1 s: 9 s in
  the worst case, below Docker's default 10 s stop grace period). Strict mail address
  validation for admin accounts, the first-run setup and GDPR searches, like deposits and
  transfers (`mail.ParseAddress`, then store normalization: no display name, angle brackets,
  list or quoted local part); the OpenAPI `Email` schema maps to a Go `string`
  (`x-go-type`) and malformed addresses answer `validation-failed` with the field code
  `invalid-email`. The mail queue logs recipients as an HMAC keyed per process.
  `docs/operations/admin.md` (operations, audit log, GDPR procedure and limits, statistics)
  and quota alerts in `docs/operations/tenants.md`; threat model v0.13 (T-146 to T-151).
- API tokens and interactive API documentation (step 13): migration `0011_api_tokens` (table
  `api_tokens` under forced row-level security, `transfers.api_token_id`, idempotency index
  scoped to the token, index for the per-token open-transfer cap); `internal/apitoken`
  (100 % coverage): secrets `tt_` + 43 base62 characters (256 bits) shown once and stored as
  SHA-256, 1 to 100 mandatory allowed CIDR ranges ("any address" only as `0.0.0.0/0` and
  `::/0`), optional `allowedSenders` (up to 100 addresses or domains, exact match, no
  subdomains; empty allows any internal address), optional expiry, revocation and expiry
  effective on the next request (an upload already streaming continues until it ends or
  idles), last use recorded at most once a minute;
  admin operations `listApiTokens`, `createApiToken`, `updateApiToken` (name, ranges and
  allowed senders;
  `409` on a revoked token) and `revokeApiToken`, audited as `api_token.created`,
  `.updated` (new action) and `.revoked` without secret. Token deposits: an
  `Authorization: Bearer` header takes precedence over the deposit session (cookie dropped,
  no CSRF check) on `createTransfer`, `getTransfer`, `cancelTransfer`, `finalizeTransfer` and
  the tus `HEAD`, `PATCH` and `DELETE`; the token is looked up in the scope of the tenant
  resolved from `Host` (a token of another tenant is unknown, and a token opens nothing on the
  admin host); unknown, revoked or expired tokens get `401 invalid-credentials` and an
  `api_token_invalid` security event (`401` answers carry `WWW-Authenticate: Bearer`), then
  10 failures from one IP within 10 minutes lock it for 15 minutes: further invalid tokens
  get `429` (`rate_limited scope="api_token"`) while valid tokens keep working; a valid
  token used outside its ranges gets `403 ip-not-allowed` (`deposit_refused reason="ip"`).
  `senderEmail` is mandatory and must belong to an internal domain of the tenant (blocklist
  applied) and match the token's `allowedSenders` when set (`403 deposit-not-allowed`,
  checked again at finalization); a transfer belongs to the token that created it only, with
  the open-transfer cap and the `Idempotency-Key` counted per token; `api_token.used` once
  per transfer created, with the sender address as actor (kind `depositor`, pseudonymised by
  a GDPR erasure), and the transfer events carry the `api_token` actor; admin transfer views
  show the origin `api`
  and `apiTokenId`. `/api/docs`: Scalar `@scalar/api-reference` 1.73.1 vendored unmodified in
  `web/apidocs/` (integrity and SHA-256 recorded, remote services disabled), embedded in the
  binary (bundle SHA-256 pinned by a test), served on the admin host to signed-in admins
  (`401` otherwise) and on known tenant FQDNs only with `TT_API_DOCS_PUBLIC=true` (an unknown
  FQDN keeps `421`), under its own CSP (`style-src 'unsafe-inline'`
  on that page only, no inline script, same-origin requests only). Integration guide
  `docs/api/integration.md` (token creation, choice of the allowed ranges and senders, secret
  storage, admin session and CSRF token kept in a private header file rather than on the
  command line, resumable tus deposit, complete bash/curl and PowerShell 7.2 scripts with
  resumption after a
  cut or a restart, error handling, revocation and rotation), API tokens in
  `docs/operations/admin.md`, token review after a restore in `docs/operations/backup.md`;
  threat model v0.14 (T-68 to T-73 implemented, T-115, new T-152 for the documentation page,
  new T-153 for a token impersonating an internal sender). The gitleaks rule
  `transteira-api-token` no longer exempts `docs/` and `api/openapi.yaml`: only example tokens
  of the fake shape `tt_EXAMPLE…` are allowed, anywhere.
- Scan statuses `not_scanned_encrypted` (encrypted archives and documents ClamAV cannot read) and
  partial analyses (`Heuristics.Limits.Exceeded`) reported as not fully scanned; a transfer's validity
  now starts when it becomes available (`expiresAt` is set then); a file that times out, drops
  the clamd connection or crashes clamd is withheld after 3 attempts.
- Configuration: `TT_MAX_RECIPIENTS`, `TT_UPLOAD_IDLE_TIMEOUT`, `TT_MAX_OPEN_TRANSFERS` (open, non-expired
  uploading transfers per internal sender; 3 for invited externals), `TT_UPLOAD_MAX_AGE` (an upload
  expires at most 7 days after its transfer was created, whatever its activity).
- `internal/textsafe`: one sanitiser for free text (control, format, bidirectional and invisible
  characters), shared by invitations and transfers.
- Instance administration (super admin): maintenance mode, system settings, disk alert and
  master key rotation from the administration (migration `0012_system`, table
  `system_settings` under RLS with PostgreSQL). Maintenance (`internal/maintenance`):
  `TT_MAINTENANCE` forces the mode and always wins (`409 state-conflict` on `enabled: false`);
  otherwise the super admin's choice is stored, survives a restart and is audited in the same
  transaction (`maintenance.enabled` / `maintenance.disabled`, message languages only);
  messages per language in plain text (1 to 500 characters; control characters other than
  line feed, Unicode line/paragraph separators and bidirectional controls refused); refused
  deposit operations get `503 maintenance` with the message in the negotiated language as
  `detail` and `Retry-After` (tus `PATCH` bodyless); `GET /tenant` exposes
  `maintenanceMessage`; `Maintenance.adminEnabled`. System settings
  (`internal/systemsettings`): disk alert threshold 0.50 to 0.99 and an optional `alertEmail`
  (merge patch, `null` removes it), audited as `config.updated` with field names only. Disk
  alert (`internal/diskalert`): measure at start-up, every 5 minutes and after a settings
  change; level stored in the database and moved by compare-and-swap (one alert per
  crossing, none again after a restart), cleared 5 points below the threshold; audit events
  `disk.alert_raised` / `disk.alert_cleared`; mail template `disk_alert` (fr, en) to the super
  admins that can sign in and to `alertEmail`, deduplicated, through a new system SMTP server
  (`TT_SYSTEM_SMTP_HOST`, `_PORT`, `_SECURITY`, `_FROM`, `_FROM_NAME`, `_USERNAME`,
  `_PASSWORD_FILE`; the password only from a file outside the volumes, `TT_SYSTEM_SMTP_PASSWORD`
  refused at start-up; own mail queue; no deny list); `GlobalStats.disk` gains `alertActive`
  and `alertMailConfigured`. Master key rotation from the administration
  (`internal/keyrotation`): `startMasterKeyRotation` with a TOTP (or recovery code)
  re-confirmation (`adminauth.ConfirmTOTP`: no replay within a step, shared lockout, session
  kept), new key required before the code is checked (`409 new-master-key-missing`), one
  background worker per instance, resumption of an interrupted rotation between the same keys
  with the same identifier, `409 state-conflict` when running, between other keys or once
  completed; new `GET /admin/system/master-key` (`MasterKeyStatus`, `restartRequired`); an
  interruption by the shutdown is never recorded as failed and the keys are destroyed only
  after the worker stops; rotations audited (`master_key.rotation_started`, `_completed`,
  `_failed`), including `rotate-master-key` (actor `cli`, `-abandon` and `-recover-from`).
  Documentation: maintenance, system settings, disk alert and system SMTP in
  `docs/operations/admin.md`, rotation from the administration in
  `docs/operations/master-key.md`, new error cases in `docs/api/errors.md`; threat model v0.15
  (T-154 to T-158).
- Web interface foundation and public interface (`web/`, Svelte 5 and Vite, Node 24 and npm 11
  at build time only): two static applications embedded in the binary (`web/embed.go`), the
  public one on every tenant host and the admin one under `/admin/` on the admin host (a shell
  at this stage; `/` redirects there). Served by `internal/httpserver/webui.go` from memory:
  fingerprinted assets cached for a year (`immutable`), entry pages `no-cache` (public) or
  `no-store` (admin) with ETag and `304`, application routes `200` and unknown paths the
  application page with `404`, `405` for other methods than `GET` / `HEAD`, `404` Problem under
  `/api`, `X-Robots-Tag: noindex, nofollow`, and a static `503` fallback page when the binary
  was built without the interface. Strict Content Security Policy per application (no inline
  script or style, nothing from another origin; `data:` images on the admin host only for the
  TOTP QR code), enforced on the sources by eslint (`svelte/no-at-html-tags`,
  `svelte/no-inline-styles`, `no-restricted-syntax`) and on the build by
  `scripts/check-dist.mjs`. Public screens: deposit with email verification by one-time code
  (internal users and invited externals), recipients, message, expiry, optional password and
  deletion after the first download, multiple files with a drop zone; resumable browser uploads
  with tus 1.0.0 (retries with backoff, stall watchdog, pause and cancel, resumption after a page
  reload by selecting the same files again), then antivirus status per file with SHA-256
  fingerprints; invitations of external users and the invitation landing page; download page
  with transfer password (lockout countdown), per-file and ZIP download, SHA-256 fingerprints
  and warnings for files not scanned; legal notice and privacy pages (server-sanitised HTML);
  not found, error, session expired and maintenance pages (maintenance banner). French and
  English translations (`web/src/locales/<lang>/<area>.json`, language from the browser or the
  tenant default, choice remembered in `localStorage`), tenant logo, colours (validated, contrast
  checked) and background image, accessibility (RGAA: keyboard navigation, focus management and
  live announcements on navigation, labelled fields and errors, no animation,
  `prefers-reduced-motion`). Typed API client generated from `api/openapi.yaml`
  (`src/shared/api/schema.ts`, staleness checked), CSRF token kept in memory only, every
  API-provided URL filtered by `safeApiHref`. Dependency policy: a single runtime dependency
  (`svelte`), exact versions published at least 14 days earlier, committed lockfile,
  `npm ci --ignore-scripts`, `npm audit` (procedure in `web/README.md`). New make targets
  `web-install`, `web-gen`, `web-check`, `web-build`; `make check` runs the web gates and build
  first, and `make build` embeds the interface. Development loop through Caddy and the Vite dev
  server (`web/dev/Caddyfile`, `*.localhost` hosts). Documentation: `web/README.md`, web layout
  and serving rules in `docs/architecture/project-structure.md`, threat model v0.16 (T-91,
  T-94 and T-95 completed for the interface, new T-159 npm supply chain, T-160 client-side state,
  T-161 tokens in URL paths).

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
- The `disk-alert` email template key is removed from the tenant templates (store key list and
  OpenAPI `EmailTemplateKey`): the disk alert is an instance mail sent through the system SMTP
  server with the built-in `disk_alert` template. The maintenance flag is now a
  `maintenance.Mode` (environment or stored choice) instead of an in-memory boolean.

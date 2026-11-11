# Changelog

All notable changes to TransTeira are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.2.0] - 2026-11-11

An installer for a blank Debian server, on top of 2.1. `install.sh`, a new signed asset of each
release, installs TransTeira, ClamAV and the reference Caddy in Docker on Debian 12 or 13, with
the signed image of its own version pinned by digest, a dedicated firewall, fail2ban and the
automatic Debian security updates, and upgrades that installation later. The application is
rebuilt with Go 1.27.4 (security fix); the API and the database are unchanged: upgrading from 2.1
only means changing the image. Threat model
2.2 in force. Validated by `make check` and `make check-full` (including `install-smoke`, a real
installation and upgrade in Debian 12 and 13 containers on SQLite and PostgreSQL).

### Added

- `install.sh`, a new asset of each release: installs TransTeira, ClamAV and
  the reference Caddy in Docker on a blank Debian 12 or 13 server (amd64 or arm64). It installs Docker
  CE from the official repository, verifies the signed image of its own version by digest (cosign
  pinned by SHA-256, `cosign.pub` embedded), generates the secrets and `.env`, starts both compose
  projects with on-demand TLS, and sets up a dedicated nftables table (`inet transteira_fw`, SSH
  ports read from `sshd -T`, the sshd sockets and `ssh.socket`, listed before the confirmation;
  80/443 accepted over IPv4 only), the fail2ban jails (TCP and HTTP/3) and the automatic Debian
  security updates (each one can be skipped). The installation serves IPv4 only: Docker's userland
  proxy is disabled so that IPv6 clients are refused instead of reaching TransTeira with the
  gateway address of the proxy network. Interactive with defaults, or unattended with `--yes` and options (`--admin-host`,
  `--acme-email`, `--postgres`, `--smtp-*`, `--no-firewall`, `--no-fail2ban`, `--no-auto-updates`,
  `--dry-run`); `--upgrade` upgrades it later (new secrets created if any, new compose files
  checked in a staging folder first, database copy, previous files kept and restored if the new
  version does not become healthy; `.env`, secrets and Caddyfile kept). It never creates the super
  admin: the setup token is shown on the terminal only (not at all with `--yes`), with a reminder
  to save the master key. It is listed in the signed `SHA256SUMS`.
  Guide: [Quick install](docs/install/quick-install.md). The application and the API are unchanged.
- `make install-lint` (syntax, shellcheck by a pinned image, unit tests of the installer) in
  `make check`, `make installer`, and `make install-smoke` in `make check-full` (real installation
  and upgrade in disposable Debian 12 and 13 containers, SQLite and PostgreSQL).

### Changed

- README: a presentation video of 2.1 (asset of the v2.1.0 release, linked from a thumbnail
  in `docs/assets`), and the screenshots regenerated against the current interface.

### Security

- Go toolchain 1.27.4 (fix for GO-2026-6859, a crash of the HTTP/1 server through a race on
  `MaxBytesReader` in `net/http`); `make release` now refuses to run when the local Go is not the
  `toolchain` of `go.mod`, since the command-line client is built with it.

### Fixed

- fail2ban jails (`integrations/fail2ban`): a second action bans 443/udp, so a banned client can no
  longer go on over HTTP/3 with the reference Caddy.

## [2.1.0] - 2026-11-10

The V2.1 scope of the specification (CLAUDE.md section 2, section 22.1): one-time secrets
encrypted in the browser, on top of 2.0. A text of at most 10 000 characters, with an optional
small file and an optional passphrase, is read once and then destroyed; the key stays in the `#`
fragment of the link, the server never sees the secret in clear, and the link is copied by the
author or sent by e-mail, with read receipts. Secrets have their entity settings, administration
and auditor views, statistics, supervision figures (Prometheus, `/status`, Grafana, Zabbix),
audit and security log events (fail2ban, CrowdSec), and API examples in Node and PowerShell.
Still compatible with 2.0: the API stays `/api/v1` with additions only. The module is **enabled
by default in every entity**, and the reverse proxy configurations must be copied again to
redact the secret links in the access logs (migrations 0033 to 0035 are applied at start-up; see
[Upgrade](docs/operations/upgrade.md#from-20-to-21)). Threat model 2.1 in force. Validated by
`make check` and `make check-full` (unit, integration, contract, tenant isolation, fuzzing,
end-to-end on SQLite and PostgreSQL, race detector, automated 20 GB test, release dry run with a
local registry) and by a real trial behind Caddy.

### Added

- **One-time secrets** (specification section 22.1; OpenAPI 2.1.0, migrations 0033 to 0035 on both
  engines, threat model sections 6.56 to 6.63, T-339 to T-375 and P69 to P83, formats in
  `docs/architecture/e2e-format.md` section 3.3 and `docs/architecture/data-model-v2.1.md`). A text
  is sealed in the browser with a key that stays in the `#` fragment of the link and never reaches
  the server; an optional passphrase (PBKDF2-SHA-256, 600 000 iterations, NFC) adds a second
  factor. The server checks a key proof, then a passphrase proof, before any reading; the key proof
  is not counted, 5 counted wrong passphrases lock the secret. The secret is read once, then
  destroyed, or at expiry (1 hour to 30 days). Cryptography in `internal/tte2` and
  `web/src/shared/e2e/secret.ts`, with shared test vectors (`secrets`, `secretNegative`).
- One-time secrets, delivery: by link (the full link is shown once), or by e-mail to one
  recipient (`sendSecret` takes the `secretToken` and the `fragmentKey` once to mail the link, never
  stored nor logged, after the blocklist and the recipient domain rules are checked again). An
  invited external can only create an e-mail secret, which goes to their inviter; they cannot
  create one when the entity turned e-mail delivery off. Optional read receipt to the creator
  (read, expired, locked), sent once. New mails `secret_notification` and `secret_receipt` (French
  and English), customizable per entity (template keys `secret-notification` and
  `secret-receipt`).
- One-time secrets, file: an optional file (10 MiB by default, 1 to 25 MiB per entity), sealed in
  the browser, streamed through a keyless validator into `<tenant dir>/secrets/` and encrypted
  again at rest; it is not scanned by the antivirus. `revealSecret` returns a one-time file grant
  (10 minutes) and `downloadSecretFile` streams the file once (grant in the `TransTeira-Secret-Grant`
  header, bounded by the concurrent stream limits); the first complete download, the grant expiry
  or the lock deletes the file and destroys its key. Secret files count in the storage quota and
  are swept as orphans.
- One-time secrets, API: `createSecret` (deposit session or API token), `getSecretLink`,
  `revealSecret`, `uploadSecretFile`, `downloadSecretFile`, `sendSecret`, `listMySecrets`,
  `deleteMySecret`; the page route `/s/{token}` (`Cache-Control: no-store`); per-client limits of
  the links (`rate_limited` scopes `secret_link_ip` and `secret_link`); new problem codes.
  Examples in Node.js and PowerShell in `docs/api/examples/` (`secret-create.mjs`,
  `secret-create.ps1`), checked by `make check` against the shared vectors.
- One-time secrets, administration: `listTenantSecrets` (metadata only, readable by an auditor),
  `deleteTenantSecret`, `getSecretSettings` and `updateSecretSettings` (enabled, durations, file,
  e-mail delivery, `emailRequiresPassphrase`), also exposed in `features.secrets` of
  `getPublicTenant` and in the configuration export and import (`secretSettings`; secrets
  themselves are never exported). Lifecycle sweeps (expiry, pending secrets after 1 hour,
  tombstones after 30 days, tenant erasure); secrets counted by the data subject search and
  erasure and by the abuse rules (alert only); `POST /secrets`, `PUT /secrets/{id}/file` and
  `POST /secrets/{id}/send` refused during maintenance. Audit actions `secret.*`, security events
  `secret_invalid` and `secret_proof_invalid`, also in the fail2ban and CrowdSec rules.
- One-time secrets, supervision: statistics `secretsCreated` (daily counter
  `tenant_daily_stats.secrets_created`, migration 0035, counted at creation) for each entity and
  in the global view; Prometheus counters `transteira_secrets_created_total`,
  `transteira_secrets_read_total` and `transteira_secrets_locked_total` and gauge
  `transteira_secret_file_bytes` (per tenant, already counted in `transteira_storage_used_bytes`);
  `/status` fields `secretFileBytes`, `secretsCreatedLast24h`, `secretsReadLast24h` and
  `secretsLockedLast24h`; a "One-time secrets" row in the Grafana dashboard and new items and a
  trigger in the Zabbix template. The data subject search and erasure screen shows the secrets.
- One-time secrets, web interface: a "Share a secret" tab on the deposit form (passphrase kept out
  of password managers, hint to prefer a long passphrase), the reveal page `/s/:token` (the key
  leaves the address bar and the router state, nothing consumed before "Show the secret", clipboard
  warning), "My secrets" in "My transfers", administration screens for the settings and the list
  (read-only for the auditor), help topics `secret-share`, `secret-read`, `tenant-secrets` and
  `auditor-tenant-secrets` with screenshots, and the `secrets` feature for `<!-- when: secrets -->`
  in the public guides. Playwright scenarios on both engines, including a capture of every request
  that finds the key only in the `fragmentKey` of the e-mail send (T-344).
- Secret data keys are wrapped by the master key (`wrapped_keys`), so the master key rotation
  covers them. A database backup taken while a secret is alive still holds its sealed text, which
  only the key in the link opens (T-351, P71). `internal/secret` is in the critical 100 % coverage
  list; new tests T-353 (concurrent reveals, exactly one wins) and T-375 (no secret material in the
  logs, the audit rows and the tables).
- **Heads-up for the upgrade to 2.1:** the one-time secrets module is **enabled by default in every
  entity, existing ones included** (decision P81, T-372): each entity gains a channel of small
  end-to-end encrypted content that the antivirus does not scan (text, and a file of up to 10 MiB
  by default; durations 1 hour, 1 day and 7 days; e-mail delivery allowed; no passphrase required
  for e-mail delivery) and secret mails sent under its domain. Delegated admins and the super admin
  can disable it per entity (`enabled` of the secret settings) or restrict it. If your mail
  gateways open or click links, turn on `emailRequiresPassphrase` (T-349).

### Changed

- **Operator action:** the reverse proxy configurations (Caddy, `Caddyfile.on-demand`, Nginx,
  Apache, Traefik) now also redact the token of `/s/{token}` and
  `/api/v1/secret-links/{token}` in the access log. If you copied them, copy or merge the new
  versions, otherwise secret tokens land in your proxy access logs (T-345). `make check` asserts
  that every configuration covers every token path (`TestProxyTokenRedaction`). The fail2ban and
  CrowdSec filters were updated too: they count `secret_invalid` and `secret_proof_invalid`, and
  the `download_streams` exclusion now also matches secret identifiers (`sec_`).
- TransTeira identity in the administration console: the TransTeira symbol as the favicon of the
  admin host (`web/static/favicon.svg`, a root file of the build also reachable on the entity
  hosts but referenced by no public page, with 32 px and 180 px PNG variants for the console), the
  horizontal TransTeira logo in the console header (a version for light backgrounds in the light
  theme, one for dark backgrounds in the dark theme), and the TransTeira greens for the buttons,
  links, focus indicator and charts of the console, in the shades that reach WCAG AA (`#00703F`,
  6.2:1 with white text; `#00BF63` for the links, focus indicator and charts on the dark surface), checked in both themes by
  `src/styles/tokens.test.ts`. The public pages of the entities keep their neutral default look
  (blue palette, neutral default favicon), as does the brand preview of the administration. Logo
  at the top of `README.md` and `README.fr.md`; administration screenshots of the user guides
  regenerated.

### Fixed

- The purge of invitations skips an invitation that a one-time secret (a tombstone included)
  still references, instead of failing on the foreign key and aborting the batch of the tenant.
- `make release-keygen` created the cosign key **without password**: the script passed an empty
  `COSIGN_PASSWORD` to cosign, which uses it without asking. An unset `COSIGN_PASSWORD` is no
  longer passed (cosign asks for the password), a key that opens with the empty password is
  deleted by `make release-keygen` and refused by `make release`, and the release dry run checks
  this detection. The 2.0.0 signing key was given a password before the release (same key pair,
  `cosign.pub` unchanged).

## [2.0.0] - 2026-11-08

The V2 scope of the specification (CLAUDE.md section 2, "enterprise"), on top of 1.0, 1.1 and
1.2: OpenID Connect single sign-on per entity (Microsoft Entra ID, Keycloak), read-only auditor
role with security events in the database, signed proofs of deposit and delivery in PDF, entity
configuration export and import, permanent drop links, link-only transfers without email,
optional end-to-end encryption in the browser and in the command-line client, the `transteira-cli`
command-line client, a signed multi-architecture image published with its SBOM, and a compliance
kit (GDPR record of processing, ISO/IEC 27001:2022 Annex A mapping). Still compatible with 1.x:
the API stays `/api/v1` with additions only, and an upgrade from 1.2 needs no configuration
change (migrations 0026 to 0032 are applied at start-up; see
[Upgrade](docs/operations/upgrade.md#from-12-to-20)). Threat model 2.0 in force. Validated by
`make check` and `make check-full` (unit, integration, contract, tenant isolation, fuzzing,
end-to-end on SQLite and PostgreSQL, race detector, automated 20 GB test, release dry run with a
local registry).

Human trial before the release: single sign-on with a real Microsoft Entra ID tenant with
`require_mfa` on, and an end-to-end encrypted transfer of about 10 GB in the browser behind
Caddy, downloaded and checked. Both passed.

### Added

- Compliance kit (`docs/compliance/`, in English and in French): a pre-filled GDPR record of
  processing activities (article 30) with the real data categories and retention periods, and a
  mapping of the ISO/IEC 27001:2022 Annex A controls to the mechanisms of TransTeira, the
  operator's share and the threat model.
- Auditor guide (`docs/user/en/auditor.md`, `docs/user/fr/auditor.md`), served as the integrated
  help of an auditor; security log sections in the delegated admin and super admin guides; the
  command-line client in the delegated admin and sender guides; new screenshots.

- Design of version 2.0 ("enterprise"): OpenAPI specification 2.0.0, still `/api/v1` and
  additive only (23 new operations: auditor role and security events in the database, OpenID
  Connect single sign-on per tenant, signed proofs of deposit and delivery with their public
  keys, tenant configuration export and import, permanent drop links, link-only transfers,
  optional end-to-end encryption); the new operations answer `404 not-found` and the new
  request members `400 validation-failed` (`not-supported`) until implemented; data model
  (`docs/architecture/data-model-v2.md`) and migrations 0026 to 0029 on both engines; threat
  model 2.0 draft (T-281 to T-336, decisions P55 to P68). The design was validated on
  2026-11-04 and every open point decided (explicit `admins.sso_only`, revoked drop links purged
  after 12 months, proofs kept 12 months after the fact).
- Read-only `auditor` admin role (threat T-281, decision P55): created, changed, invited and
  reset by the super admin like a delegated admin (attached to at least one tenant, TOTP
  required by default); on its tenants it reads the summary, the audit and security events, the
  statistics and the transfers (metadata only), and manages its own password and TOTP. Every
  other operation answers `403 read-only-role`, refused twice: by an operation whitelist in
  front of the handlers, and in the services, where the tenant configuration reads and every
  write deny the role by default (`RequireTenantAuditRead` opens the few allowed reads). A
  spec-walk test checks every administration operation for this role on both engines.
- Security events in the database (threats T-283 to T-285, decision P56): every line of the
  security log, whose file and format do not change (fail2ban, CrowdSec), is also copied to the
  `security_events` table, asynchronously from a bounded queue (overflow dropped from the copy
  only and counted in `transteira_events_dropped_total{subscriber="security_events"}`), identical
  events (type, reason, IP, tenant) within one minute coalesced into one row
  (`occurrences`, `lastSeenAt`), written by batch in one transaction, purged after 12 months by
  the cleanup task. Only closed tokens are kept (type, reason, IP, tenant, and the `scope`,
  `purpose` and `host` fields), never an e-mail address. `listTenantSecurityEvents` returns a
  tenant's own events to its delegated admins, its auditors and the super admin (never an event
  without tenant, row-level security on PostgreSQL); `listGlobalSecurityEvents` the whole
  instance to the super admin, with an optional tenant filter.
- OpenID Connect single sign-on of delegated admins and auditors, per entity (threats T-286 to
  T-297, decisions P57 to P59): configured by the super admin only (issuer, client ID, client
  secret sealed with the master key and rewrapped by its rotation, e-mail domains among the
  internal domains of the entity and unique on the instance, `enforced`, `requireMfa`), with a
  discovery test; authorization code flow with PKCE S256, `state` and `nonce`, confidential
  client, redirect URI `https://<admin host>/api/v1/admin/auth/oidc/callback`. Accounts are
  created in advance (optionally `delivery: none`, single sign-on only, no password); the first
  login links by verified e-mail, then the identity is pinned on (issuer, client ID, subject) and
  the super admin can unpin it. The super admin never uses single sign-on. An SSO session reaches
  only the entities with the same issuer and client ID whose `requireMfa` the login satisfied;
  `enforced` refuses the local password (`403 sso-required`). Microsoft Entra ID needs a
  tenant-specific issuer and, for `requireMfa`, the optional claim `amr`. New variables
  `TT_SSO_USE_PROXY` and `TT_SSO_ALLOW_NETWORKS`; security log event `sso_failed` with a reason,
  counted by a separate fail2ban jail and CrowdSec scenario with a higher threshold; audit
  `admin.login` (`method: oidc`), `admin.identity_linked`, `admin.identity_unlinked`,
  `tenant.sso_updated`, `tenant.sso_deleted`. Guide: `docs/operations/sso.md` (French:
  `docs/operations/fr/sso.md`).
- Signed proofs of deposit and delivery (threats T-298 to T-303, decision P61): a PDF signed by
  the instance holding a readable copy of the statement and, attached, `statement.json` (RFC 8785
  canonical JSON, schema `ProofStatement`, integers only) and `statement.sig` (Ed25519); only the
  attached statement is authoritative and its SHA-256 is printed. The deposit proof is written at
  the end of the antivirus analysis, in the same transaction that makes the transfer available;
  the delivery proof at the first complete download and, for per-recipient links, at each
  recipient's first complete download. Proofs are immutable, one per fact, kept 12 months after
  their creation even when the transfer is deleted, erased by the data-subject erasure when they
  name the address, and deleted with the entity. The sender downloads them from "My transfers"
  while the transfer exists; delegated admins, the super admin and auditors from the admin
  transfer detail, even after deletion (`transfer.proof_downloaded` in the audit log); downloads
  are limited to 10 per minute (burst 20, `429`) per client address (per IPv4 address or per
  IPv6 /64), shared by the sender and administration proof endpoints across tenants. One active Ed25519 instance key,
  created at first use (`proof_key.created`), its private part sealed by the master key and
  rewrapped by its rotation; public keys, active and retired, at `GET /api/v1/proof-keys` (also
  answered while an entity is in setup). New commands: `transteira proof verify [--keys FILE |
  --url https://FQDN] [--json] <proof.pdf>` (offline, no database, prints the fields of the
  verified statement and rejects a fact later than the retirement of its key), `transteira proof
  keys` and `transteira proof retire-key [--yes]` (private part destroyed, audit
  `proof_key.retired`, new key at the next proof, retired public keys stay published). API:
  `getMyTransferProof`, `getTenantTransferProof`, `listProofKeys`, new members
  `DataSubjectSummary.proofs` and `DataSubjectEraseReport.proofsDeleted`, error
  `proof-not-available`. No third-party timestamping (RFC 3161). Documented limits: retiring a key blocks only
  statements whose facts are dated after it (backdated forgeries within a compromised key's
  lifetime and old backups are an accepted residual risk: rotate the master key and retire the
  key); a delivery proof that cannot be written rolls back the whole first-download transaction.
  Guide:
  `docs/operations/proofs.md` (French: `docs/operations/fr/proofs.md`); user guides updated.
- Export and import of the configuration of an entity (threats in the
  threat model 2.0): `exportTenantConfig` (`GET /api/v1/admin/tenants/{tenantId}/export`, super
  admin and delegated admin, not the auditor) returns the general settings without the quota,
  colours and background preset, network rules, SMTP server, port, security and sender only,
  recipient rules, confidentiality levels, abuse thresholds, customised mail templates only,
  legal texts, webhooks by name, kind and events only (disabled), the blocklist, and with
  `includeBranding=true` the logo and background image. Never exported: SMTP user name and
  password, webhook URLs and secrets, API tokens, admins, provisioning data, transfers,
  addresses, invitations, audit, single sign-on. `importTenant` (`POST
  /api/v1/admin/tenants/import`, super admin only, refused to any other admin before the body
  is read, 32 MiB) always creates a new entity in the setup state, in one transaction, with
  strict validation before any decoding (unknown or missing required members, arrays beyond
  their `maxItems`, at most 10000 blocklist entries: `422 import-invalid` with the JSON pointer
  of the first error, `422 import-schema-unsupported`, `409` for a used FQDN, `413`). The SMTP
  credentials, the webhooks and the single sign-on are completed in the setup wizard; the
  network ranges and domains are imported as written and must be confirmed before completing the
  setup (threat T-307, migration 0030 `tenants.network_reviewed_at`): the `internal_networks` and
  `internal_domains` items stay to do, and the completion that is not forced is refused by the
  statement itself, until an admin saves the rules (`updateNetworkRules`, even unchanged; a
  "Confirm" button in the wizard and on the Network screen); `TenantSetup` gains
  `networkReviewedAt`. Existing tenants with rules are backfilled as reviewed. Audit
  `tenant.exported`, `tenant.imported`. Admin screens: export section on the General screen,
  "Duplicate" in the entity list, import screen. User guides and API guide (section 10)
  updated.
- Permanent drop links (threats T-309 to T-314, decision P63): a fixed address
  `https://<tenant host>/drop/ttd_...` given to third parties to send files to a service without a
  personal invitation. Created by the delegated admins and the super admin (at most 100 per
  entity; read-only for auditors) with a public label, 1 to 20 recipients of the internal mail
  domains, a validity of 1, 7 or 30 days within the durations of the chosen confidentiality
  level; edited, disabled, rotated (the old token dies at once) or revoked (kept in the list,
  purged 12 months later when no transfer refers to it). The URL is shown once, at creation and
  rotation; only the SHA-256 of the token is stored. The depositor gets an e-mail code at every
  use (single-use `drop_link` session, no recognition cookie); external quotas, abuse detection
  and the blocklist apply, and the rules of the level apply to the depositor. An unknown, revoked
  or disabled link answers the same `404 drop-link-invalid` and is written to the security log
  (`drop_link_invalid`). A confidentiality level used by an enabled link cannot be deleted
  (`409 state-conflict`); erasing a person's data removes them from the recipients and disables a
  link left without any. Audit `drop_link.*`. Migration 0031 (`verification_challenges.drop_link_id`).
  Limits of a link (P63, migration 0032): an optional expiry date (`expiresAt`; an expired link
  answers like a disabled one, can be extended or cleared, and is purged 12 months after its
  expiry), a cap of transfers per hour through the link, all depositors together
  (`maxDepositsPerHour`, 20 by default, 1 to 1000; checked before a code is sent and again at the
  transfer creation: `429 rate-limited`, security log scope `drop_link`), and an `unused` flag with
  an "Unused for 12 months" badge in the administration. The single use of a session and the
  hourly cap survive the cancellation of a transfer (`deposit_sessions.used_at`, migration 0032);
  at most three times `maxDepositsPerHour` codes are sent through a link per hour, whatever the
  address. The recipients of a link are never disclosed to its depositor: any `recipients` in
  the creation is refused the same way, the transfer and "My transfers" answers carry an empty
  `recipients` and a `dropLinkLabel`, the confirmation mail names the link, and the proofs of
  these transfers are for the administrators only. A link whose recipient left the internal mail
  domains is refused like a disabled one. The reverse proxy configurations mask the `/drop/` and
  `/api/v1/drop-links/` tokens in their logs.
- Link-only transfers (threats T-315 to T-317, decision P64): `linkOnly` on `createTransfer`, for
  internal depositors and API tokens only, when the entity allows it (`linkOnlyAllowed`, super
  admin, off by default) and the confidentiality level allows it (on by default); incompatible
  with recipient verification. No mail is sent to the (optional) recipients; the link is drawn
  at finalization and returned **once**, in the answer of `finalizeTransfer`, with only its hash
  stored; the sender confirmation mail has no link, and administrators cannot resend the
  notification. A lost link is replaced from "My transfers" (`reissueMyTransferLink`), which
  kills the old one, as soon as the transfer is scanning (the new link works once it is
  available). The proofs of a link-only transfer carry `linkOnly: true` and say "link only:
  recipient not identified" (PDF and `transteira proof verify`). `TenantFeatures.linkOnly` tells
  the forms whether to offer the option.
  Guides (French and English), API integration guide (section 11) and threat model updated.
- End-to-end encryption, format and server support (threats T-318 to T-327 and T-336, decision
  P66; the browser interface is described in the next entry). Format `TTE2` (AES-256-GCM chunks, HKDF-derived per-file keys,
  key only in the link fragment `#k=`) specified in `docs/architecture/e2e-format.md`, with the
  Go reference implementation `internal/tte2` and shared test vectors. `createTransfer` accepts
  `endToEndEncrypted` with generic names `file-<n>.tte2`, `encryptedMetadata` per file and an
  optional `encryptedMessage` (a plaintext message is refused); a transfer password is allowed.
  The server holds no key and checks only the header (each byte judged on arrival) and the
  declared size: a refused slice answers `400 e2e-format-invalid` with a problem body and is
  never stored. Policy `e2ePolicy` per entity (forbidden by default, super admin only, audited)
  and per level (follow the entity, can only tighten), carried by the export and import;
  depositor rules (drop links cannot encrypt), `e2e-forbidden`, `e2e-required`. Files get
  `not_scanned_e2e` (audit reason `e2e`, no "file not scanned" mail), the SHA-256 is the one of
  the ciphertext, the proof of deposit says `endToEndEncrypted`, ciphertext is served as is
  (ranges work) and the ZIP archive answers `409 e2e-archive-unavailable`. Mails carry neither
  key nor message and gain the `e2e_notice` template variable. Administration: policy selectors
  and a badge in the transfer lists. Documentation: threat model, API errors and integration
  guide (section 12), super admin and delegated admin guides.
- End-to-end encryption in the browser (V2 step 8, threats T-318 to T-327, T-160). Deposit: a
  box "Encrypt end to end in my browser" offered by the entity and level policy (allowed,
  required or forbidden, never for drop links). A preparation pass reads each file to compute its
  plaintext SHA-256 (pure TypeScript, about 1.5 minutes per 10 GB), then the files are encrypted
  during the tus upload in a Web Worker that only receives a non-extractable HKDF key. Names,
  folders, types, sizes, SHA-256 and the message are sealed. The done screen shows the key once
  (to send through another channel), or the full link with `#k=` for a link-only transfer.
  Resume after a reload: the key and the per-file salts stay in the `sessionStorage` of the tab
  (record `tt.upload`) until the end or the abandon of the upload (decision of 2026-11-07).
  Download: the key is read from `#k=` (then removed from the URL) or typed (bare key or full
  link); a wrong key and a tampered transfer are detected. A Service Worker (`/e2e-sw.js`, scope
  `/e2e/`) decrypts in streaming, checks the size and the plaintext SHA-256, and builds the ZIP
  archive in the browser (store mode, ZIP64); it never receives the raw key. Without Service
  Worker, an in-memory fallback works up to 512 MiB. Both fingerprints (plaintext and ciphertext)
  are shown. Documentation: depositor and recipient guides (French and English), format
  specification (section 7), threat model.
- Command-line client `transteira-cli` (V2 step 9, threats T-328 to T-331 and T-337): a static
  binary for Linux, macOS and Windows (amd64, arm64) that deposits files and folders with an API
  token and tus (resumes inside a run and between two runs, from a state file), downloads a link
  (per file or as the server ZIP, `.part` files with `Range` resume, SHA-256 checked before the
  rename, no overwrite without `--force`, names sanitised and writing confined to the output
  folder), handles recipient verification and transfer passwords, sends and opens end-to-end
  encrypted transfers (`--e2e`, key delivered out of band or read from a file or the standard
  input) and verifies proofs (`proof verify`). Configuration by flags, environment and a profile
  file (`TT_URL`, `TT_TOKEN_FILE`, `TT_SENDER`, ...); the token is never a flag; HTTPS only with
  no way to disable verification and no redirect followed. `make cli` builds the six binaries
  with `SHA256SUMS` into `dist/cli`; the `cli-cross` gate of `make check` cross-compiles for
  Windows and macOS. Guide: `docs/api/cli.md`.
- Signed multi-architecture image, SBOM and `make release` (V2 step 10, threats T-331 to T-335):
  `make release-keygen` creates the cosign key pair (public key `cosign.pub` committed, private key
  in the vault); `make release` refuses a dirty tree, requires a signed tag `vX.Y.Z` on HEAD, a
  `make check-full` green on this exact commit, a private key outside the repository (mode 0600)
  matching `cosign.pub`, and the `cosign.pub` fingerprint in `README.md`, `README.fr.md` and
  `SECURITY.md`. It builds linux/amd64 and linux/arm64 by cross-compilation without cache (full
  commit SHA in the binary and the image label), pushes the image by digest only, generates an SPDX
  SBOM per platform with syft (Go modules and the interface npm dependency), signs the index and the
  platform manifests with cosign, attaches each SBOM as a signed attestation of its platform digest
  (recorded in Rekor), self-verifies, and only then tags `X.Y.Z`, `X.Y` and, for the highest stable
  version only, `latest`; the CLI binaries get a signed `SHA256SUMS` and a signed SBOM.
  `make release-dry` runs the whole chain against a local registry (part of `make check-full`;
  `RELEASE_REPRO=1` compares two `--no-cache` builds). Verification needs cosign 3.0 or later.
  Guides: `docs/operations/release.md`, `docs/install/docker.md` (verification before deploying),
  `docs/operations/upgrade.md`, `SECURITY.md` (key replacement).

### Changed

- The shipped fail2ban filter and CrowdSec scenario now count `drop_link_invalid` (unknown,
  revoked, disabled or expired permanent drop link), as the threat model states (T-311); the event
  is documented in `docs/operations/security-log.md`, and a test checks that every declared
  security event is covered by the integrations. Copy the integration files again when upgrading.
- `scripts/release.sh` keeps a `COSIGN_PASSWORD` exported by the caller away from docker, make,
  syft and git: only cosign receives it.
- The help topics of the security log screens now open their own guide sections
  (`tenant-security-log`, `system-security-log`) instead of the audit log sections.

- The files of an end-to-end encrypted transfer now count as one download start per client within
  the window, so that a ZIP archive built by the browser counts once against the maximum number of
  downloads instead of once per file (transfers with a download limit only; without a limit every
  file start is still recorded and audited). The window moves at the end of every file response,
  and the start reaching the limit makes such a transfer due for deletion after the longer of the
  grace period and the 4-hour window ceiling, so that the browser can fetch the last file.

## [1.2.1] - 2026-11-04

Patch release: a fix of the ICAP antivirus client (a scan whose request could not be sent to a
silent server waited for the whole scan timeout), a fix of the update check classification, and
`make check` / `make check-full` made green on Linux with Docker Engine, where they had never run.
No API, configuration or database change. Validated by `make check-full` (race detector, 20 GB
test) on Linux with Docker Engine.

### Fixed

- `make check` on Linux with Docker Engine (it had only run on Docker Desktop so far):
  - gosec G304 on the Unix-only `syncDir` (`internal/lifecycle/syncdir_other.go`), never linted
    on Windows because of its build constraint, and a test for its two error paths (100 %
    coverage of `internal/lifecycle` on Linux too);
  - `TestCleanupBackup` no longer misses its nightly copy on a slow start (backup time computed
    as late as possible, 15 s ahead instead of 5 s);
  - end-to-end tests: the source of the helpers' direct calls, rewritten by Docker Engine's
    masquerade rule for the default bridge, is measured and trusted as a `/32`; the server
    trusts the Caddy container's address instead of the whole compose subnet, whose gateway is
    the source of the browser's connections (downloads were refused with "client IP unknown").
    Caddy now starts before the server. Documented in `test/README.md`.
- Update check: a response body cut by the timeout is reported as a network failure instead of
  a parse error (`TestCheckTimeout` was flaky under a heavy CPU load).
- ICAP antivirus: when the request could not be sent and the server stayed silent, the scan
  could wait for the whole scan timeout instead of failing within a second as unavailable. The
  overall read deadline is now set before the sender starts, so the shorter wait it sets on a
  write failure is never undone (seen under the race detector on a loaded machine).
- Webhook tests: the slow receiver of the timeout case aborts its response instead of answering
  200 once the client has left, which a loaded machine could deliver as a success.
- clamd tests: `TestPingContextCanceled` cancels once the fake clamd received the command, so
  that the cancellation always reaches the pending read (it could land during the dial and
  leave the I/O unblocking path uncovered, below the 100 % threshold of `internal/antivirus`).
  The ICAP regression test now also fails if the scan is not cut short after a failed send.

### Changed

- The Go race detector runs in `make check-full` (with a 90-minute test timeout) instead of
  `make check`, where it was enabled whenever gcc was found and pushed the tests past their
  30-minute timeout on Linux. `make check RACE=-race TEST_TIMEOUT=90m` still forces it.

## [1.2.0] - 2026-11-02

The V1.2 scope of the specification (CLAUDE.md section 2, "onboarding"), on top of 1.0 and 1.1:
per-entity favicon, setup state and wizard for a new entity with proposed legal texts, library
of background images and choice of the background at creation, delegated admin invited by mail,
provisioning API for managed service providers with on-demand TLS for Caddy, and display of the
version with an update check. Validated by `make check` and `make check-full` (unit, integration,
contract, tenant isolation, fuzzing, end-to-end on SQLite and PostgreSQL, automated 20 GB test).

Human trial of the new features on a Docker installation upgraded from 1.1.0 (migrations 0022
to 0025 applied at start-up), behind Caddy with on-demand TLS and its internal CA, mails captured
by Mailpit: version display and update check, entity creation with a background from the library
and a delegated admin invited by mail, activation with mandatory TOTP and re-sent invitation, setup
wizard (SMTP test, network ranges and domains, proposed legal texts, favicon from the logo, opening),
provisioning by `ttp_` token with the notification mails and a certificate issued on the first visit
of the new entity, no certificate for an unknown name. All checks passed.

### Added

- OpenAPI specification 1.2.0 (16 new operations: update check, background presets, tenant setup
  state and wizard checklist, proposed legal texts, delegated admin invitation by mail,
  provisioning API for managed service providers, on-demand TLS `ask` endpoint), data model
  (`docs/architecture/data-model-v1.2.md`) and migrations 0022 to 0025. Threat model 1.2: T-244 to
  T-280, decisions P47 to P54.
- Version and update check: the running version is shown in the administration footer; the super
  admin sees the outcome of a daily check of the latest TransTeira release on GitHub (a notice
  and a "Check now" button, never an automatic update). Only the version and the release link are
  kept; `TT_UPDATE_CHECK=false` turns off every outbound connection, `HTTPS_PROXY` is honoured by
  this check only.
- Per-tenant favicon: the favicons (ICO 16/32/48, PNG 32 and 180 for Apple devices) are generated
  by the server from the uploaded logo and served on the tenant host; without a logo, the built-in
  icon. For a logo uploaded before 1.2 they are generated on first use.
- Background library: eight background images generated by the server (no photograph), chosen per
  tenant in the branding screen (`PUT /admin/tenants/{id}/branding/background-preset`) or at
  creation (`backgroundPreset`); an uploaded background still takes precedence.
- Delegated admin invitation by mail: the activation link of a new delegated admin can be mailed
  through the system SMTP (`TT_SYSTEM_SMTP_*`) instead of being copied by the super admin
  (`invitation.delivery: mail`), in French or English; the link is then never returned by the API,
  and TOTP enrollment becomes mandatory for the account. A tenant can be created together with its
  first delegated admin in one transaction (`delegatedAdmin`), and a new link can be sent to an
  account not yet activated (`POST /admin/admins/{id}/invite`, at most 5 per hour), which revokes
  the previous ones. Without a system SMTP the mail delivery answers `503 system-smtp-unavailable`
  and the link can still be copied.
- Tenant setup state and checklist (server side): a tenant can be created in the `setup` state
  (`setupState: setup`; without it, `createTenant` still creates an active tenant). While in setup,
  every public operation of the tenant answers `503 tenant-in-setup` (deposits, codes,
  invitations, uploads, API tokens, downloads, "my transfers"), except its public information,
  images and legal texts, which carry `setupState`. The checklist
  (`GET /admin/tenants/{id}/setup`) is computed from the real configuration: SMTP settings tested
  successfully since their last change, internal IP ranges and domains, legal notice and privacy
  policy written in the default language without "to complete" marker, plus optional branding and
  mail template review. `POST /admin/tenants/{id}/setup/complete` opens the tenant (`409
  setup-incomplete` listing the missing items; `force` for the super admin only); there is no way
  back. `GET /admin/tenants/{id}/text-proposals/{document}/{language}` proposes a legal notice or
  privacy policy filled with the tenant configuration, never saved.
- Setup wizard (administration): an entity created from the administration always starts in the
  setup state and opens on its wizard, a guided checklist linking to the existing screens (each
  with a link back); the legal screens offer the proposed texts, whose `[To complete: …]` markers
  must be replaced before the item is done; the delegated admin sees a call to action on the home
  page and the entity lists show a setup badge. The public pages of an entity in setup show a
  message instead of the deposit form. User guides: new sections "Setup wizard" and "Provisioning
  tokens", entity creation and delegated admin invitation rewritten (French and English), with
  screenshots.
- Provisioning API for managed service providers: provisioning tokens (`ttp_`), created by the
  super admin with a TOTP re-confirmation and bound to IP ranges, FQDN suffixes and caps, create
  entities in the setup state with their first delegated admin through
  `POST /api/v1/provisioning/tenants` (list and follow with `GET`); the activation link is mailed
  and never returned; at most 30 creation attempts and 30 creations per hour per token, every
  refused creation audited as `tenant.provision_refused` (reason code only). New security log
  event `provisioning_token_invalid` (counted by the shipped
  fail2ban and CrowdSec rules), gitleaks rule for `ttp_` tokens, system mails `tenant_provisioned`
  and `tenant_setup_completed` for the super admins, guide `docs/api/provisioning.md`.
- The creation of a provisioning token notifies the super admins: system mail
  `provisioning_token_created` and instance webhook event `provisioning_token.created` (never the
  secret).
- On-demand TLS for Caddy: `GET /tls/ask?domain=<fqdn>` answers `200` for the FQDN of a tenant (setup
  or active) and `404` for anything else, so that Caddy obtains the certificate of a tenant created
  through the provisioning API at its first handshake. Disabled until `TT_TLS_ASK_ALLOWED_IPS` (Caddy's
  exact address, same validation as `TT_TRUSTED_PROXIES`) is set; only the direct TCP peer is
  considered and any request carrying a relay header (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`,
  `X-Forwarded-Host`, `X-Forwarded-Proto`, `Via`) is refused. Its own rate limit per proxy
  (200/s, burst 400), outside the global per-IP limit. Counted by the Prometheus metric `transteira_tls_ask_total{result="allowed|unknown|refused"}`.
  New `integrations/reverse-proxy/caddy/Caddyfile.on-demand` (checked by `make proxy-configs-check`,
  with its `transteira` snippet kept identical to the reference one); the four reverse proxy
  configurations now refuse `/tls/ask` with `404` on all public hosts. Documentation: Caddy and
  provisioning guides, wildcard certificate alternative for Nginx, Traefik and Apache.

### Fixed
- HTTP antivirus engine with a raw body: a scan could fail at random as "answered before reading
  the whole content" when the engine answered quickly, because an empty write after the content
  waited on the request pipe. Empty framing is no longer written.

## [1.1.0] - 2026-10-31

The V1.1 scope of the specification (CLAUDE.md section 2, "operations"), on top of the 1.0.0 core:
monitoring (Prometheus `/metrics`, JSON `/status`, Grafana dashboard, Zabbix template, syslog
export, webhooks), abuse detection and the report button, confidentiality levels and recipient
domain rules, per-recipient links with optional recipient verification and tracking, expiry
reminder, maximum number of downloads, "My transfers", deposit from outside for verified internal
users, reply to a transfer, folder upload, dark mode, per-entity user documentation with a
printable version, and the antivirus switch-off and ICAP/HTTP engines. Validated by `make check`
(unit, integration, contract, tenant isolation, fuzzing, end-to-end on SQLite and PostgreSQL,
automated 20 GB test).

Real big file trial validated by the operator on 2026-10-31 (build `0.0.0-dev+bd68cb9`, the 1.0
trial installation upgraded in place: 9 migrations applied at startup, SQLite, reference Caddy with
`tls internal` on a Docker Desktop workstation): a 7.9 GB file uploaded from a browser with a
network cut and an automatic resume, per-recipient links with recipient verification, a folder
upload with its tree kept in the file list and the ZIP, every SHA-256 matching. Browser upload
throughput about 55 MiB/s (the browser's own HTTP/2 upload rate; the automated client reaches
87 to 97 MiB/s through the same proxy, with 32 MiB chunks like the browser).

### Added
- ICAP and HTTP antivirus engines (specification section 11.1): `TT_ANTIVIRUS_ENGINE=icap|http`
  with `TT_ICAP_*` and `TT_AVHTTP_*` variables, configurable verdict rules, TLS always verified
  and credentials from a file only, refused inside the data, backup and log volumes. EICAR
  self-test at startup and on demand (button in the system settings, `POST /admin/system/antivirus/test`, audited as `antivirus.self_test`):
  the engine is unavailable until it passes (fail-closed), retried 15 s doubling to 10 min,
  never repeated once passed. Guide `docs/operations/antivirus.md`. Threat model T-238 to
  T-242, P44 to P46 implemented.
- Disabling the antivirus (specification section 11.1), instance and entity: `TT_ANTIVIRUS_ENGINE`
  (`clamd` by default, `none` to disable the analysis for the whole instance, no ClamAV container
  needed) and the per-entity switch `antivirusEnabled`, changed by the super administrator only
  (read-only for delegated administrators) and audited (`tenant.antivirus_disabled`,
  `tenant.antivirus_enabled`). Files finalized while disabled are delivered unscanned with the new
  status `not_scanned_disabled`, frozen at finalization (files already waiting keep waiting for the
  engine, re-enabling never rescans): the sender receives the "file not scanned" mail with the
  reason "antivirus disabled" and the download page says so. With the engine `none`, a warning is
  logged and the audit event `antivirus.instance_disabled` recorded at every startup, files still waiting are released (audit event `antivirus.scans_released`),
  `/healthz` no longer probes the antivirus, and the engine name is shown read-only in the system
  settings and in `/status`. New overlay `deploy/docker-compose.no-antivirus.yml`; installation,
  operations and user guides updated (FR/EN). The blocklist by SHA-256, the abuse detection and the
  forced download stay in force. Threat model T-236, T-237, T-243 and P43 implemented.
- Per-entity user documentation and printable version (specification section 4.2): the public help on
  an entity address shows the entity name, logo, colours and real rules (maximum size, durations,
  options, confidentiality levels) through the new guide directives `<!-- rules: summary|limits|levels -->`
  and `<!-- when: feature -->` (section hidden when the entity has the feature off); nothing secret
  is exposed (no IP ranges, internal domains, thresholds or domain lists). A printable page
  `/help/print`, dated and carrying the application version, is saved as PDF with the browser; the
  entity screen links to it. Guides and `web/README.md` updated.
- Dark mode (specification section 13.1): the interfaces follow `prefers-color-scheme` by default,
  live; a "Dark theme" button in the footer of both applications switches the theme and remembers
  it in the technical cookie `tt_theme` (`light` or `dark`, one year, `SameSite=Lax`, no `Domain`,
  never read by the server; any other value is ignored; choosing the system value again deletes it).
  The theme is applied before the first paint by the static script `/theme-init.js` (no inline
  script, CSP unchanged). Palette and tokens for both themes (`--tt-graphic`, `--tt-logo-*`), checked
  by a test (text 4.5:1, borders and focus 3:1 in each theme); entity colors are applied per theme,
  with accessible defaults when a color is not readable on the dark background; state colors are
  never overridden. The contrast check adds the `primary-on-dark` and `accent-on-dark` pairs, which
  are deliberately informational (no warning: no primary color can satisfy both text-on-primary and
  primary-on-dark; the dark theme keeps its own accessible link and focus defaults, the accent is
  decorative). The branding preview shows both themes. End-to-end accessibility checks (axe) now run
  in both themes on every screen; new `public-theme.spec.ts`. Threat model T-230, T-231 implemented.
- Folder upload (specification section 8.2), web side: a folder dropped on the file area (read
  recursively with `webkitGetAsEntry`) or chosen with the new "Add a folder" button (real
  `<input webkitdirectory>`, keyboard path) keeps its tree. Operating system files (`.DS_Store`,
  `Thumbs.db`, `desktop.ini`) are left out with a count; other hidden files and folders are kept and
  flagged "Hidden" (removable); empty folders are ignored; a file whose name or folder the server
  would refuse (client mirror of the `FilePath` rules, NFC) is set aside with the reason; the 1000
  file cap is unchanged. Each file declaration carries `path`; the list before sending, the resume
  fingerprint (a stored record without path is the root), the download page, the administration
  transfer detail and "My transfers" show the folder; the reply screen accepts folders too. User
  guides updated (the ZIP keeps the tree, duplicate names get " (2)").
- Reply to a transfer (specification section 10): per-tenant option `allowTransferReply`, off by
  default, in the Network screen settings. On the download page of a personal link of a transfer sent
  by an internal user or an API token, the recipient sees "Reply", always confirms their address by a
  6-digit code (15 minutes, 2 attempts, even without sender verification) and gets a reply deposit
  session that lives at most until the original transfer expires. The only recipient is the original
  sender (not changeable); external quotas, abuse detection, blocklist, antivirus, size limit and
  storage quota apply, and recipient domain rules do not. No reply to a reply, to a transfer from an
  invited external or through an old shared link (`403 reply-not-allowed`); the original transfer is
  rechecked at creation and finalization (`410 transfer-gone`), as are the option and the blocklist of
  the replier and of the original sender. The sender gets the usual notification mail with a warning
  that the reply comes from outside (`PublicTransfer.reply`, same notice on the download page).
  Audit: `transfer.created` with origin `reply` plus `transfer.reply_created`; the admin transfer
  list shows the origin "Reply". Maintenance mode refuses new replies. Replaces the former `409`
  answer of `purpose: reply`. User guides updated; threat model T-222 to T-225 implemented.
- Deposit from outside for verified internal users (specification section 6.4): per-tenant option
  `allowRemoteInternalDeposit`, off by default, that a delegated administrator switches on the
  Network screen. Only an address of an internal domain already verified once from the internal
  network can deposit outside the ranges; a code is required at every deposit (the recognition
  cookie and an `internal` session opened inside the ranges are never enough), no invitations from
  outside, recipient rules and confidentiality levels as for an internal sender. Such transfers are
  flagged `details.remote` in the audit; with the option on, an ineligible address from outside (foreign domain, never
  verified from the internal network, inactive, unknown) gets the same "a code has been sent"
  answer without any mail, counted in the code limits, and every code is refused at confirmation
  (decoy, no oracle); with the option off outsiders get the generic refusal.
- Abuse detection (specification section 15): per-tenant settings on a new admin screen. Per-sender
  daily volume, daily transfers and recipients per transfer, with optional blocking
  (`abuse-threshold-blocked`); unusual volume (factor over the 30-day average), large external
  transfers and office hours (alert only, internal and remote senders); invitations per inviter per
  hour; external quotas per address per day. Per-sender limits apply to internal senders only and
  count every transfer created or extended that day, cancelled drafts included; with blocking, only
  the first refusal of the day per sender and rule is audited and alerted. Days follow the configured IANA time zone and
  extensions through "My transfers" count the day of the extension. One alert per sender, rule and
  day (mail `abuse-alert`, webhooks `abuse.threshold_exceeded` and `abuse.unusual_activity`),
  audited with the alert, refusals deduplicated separately from alert-only alerts; computed on demand, nothing stored but a de-duplication table purged after
  2 days.
- Abuse reports (specification sections 10 and 15.2): "Report abuse" button on the download page
  (categories, optional 1000-character plain text message), limited to 3 per link per day and 5 per
  IP per hour (`rate_limited` scopes `abuse_report_link` and `abuse_report_ip`, counted by the
  fail2ban and CrowdSec rules). The reporter's address is recorded only when the recipient verified it
  on this browser; no automatic action. Mail `abuse-report` and webhook `abuse.reported` to the
  delegated administrators, "Reports" admin screen to close (with a note) or reopen, kept 12 months,
  pseudonymised by the GDPR erasure. User guides for depositors, recipients and delegated
  administrators.
- "My transfers" (specification 8.7): a sender whose address is already verified requests a
  single-use access link (15 minutes) by mail, opens a 1-hour session and lists, inspects
  (per-recipient tracking), deletes or extends their transfers (durations of the confidentiality
  level, 90 days maximum lifetime). Same answer for known and unknown addresses; new
  `access_link_invalid` security log event handled by the fail2ban and CrowdSec rules; user guide
  and help topic `my-transfers`.
- Version 1.1 design, validated: OpenAPI specification 1.1.0 (35 new operations, not implemented
  yet), V1.1 data model (`docs/architecture/data-model-v1.1.md`) and threat model 1.1 (threats
  T-178 to T-243, decisions P27 to P46). Specification section 11.1: antivirus disable (instance or
  tenant) and interchangeable engines (clamd, ICAP, HTTP).
- Internal event bus (`internal/events`): audit records, security log lines and alerts
  (antivirus, disk, quotas, virus detected, maintenance, master key rotation) are published after
  commit, without ever blocking, for the coming webhooks, syslog and metrics. One shared audit
  writer across the application.
- Database migrations 0014 to 0020 for version 1.1 (per-recipient links, transfer options,
  confidentiality levels, abuse detection, webhooks, "My transfers", mail templates), on SQLite and
  PostgreSQL, with row-level security on every new tenant table. Existing transfers keep their
  single shared link; existing tenants get the default confidentiality levels and abuse settings.
- Webhook alerts (specification section 12.4): Microsoft Teams, Slack and generic JSON signed
  with HMAC-SHA256, configured per tenant by its administrators (tenant alerts) and for the
  instance by the super admin (system alerts). URL and secret sealed with the master key; HTTPS
  only; private networks refused unless allowed by `TT_WEBHOOK_ALLOW_NETWORKS` /
  `TT_WEBHOOK_ALLOW_HTTP_NETWORKS`, cloud metadata, link-local and the container's own networks
  always refused; at most 30 new addresses per hour per administrator; no redirects; 5 attempts with
  back-off and a circuit breaker; deleting or disabling a webhook stops its pending deliveries, a new
  address or secret applies to them; test button; minimal payload, mail addresses only with the new
  tenant option "Include the addresses in the webhooks". Receiver guide in `docs/api/integration.md`.
- Syslog export of the audit and security logs (RFC 5424 over TLS, TCP or UDP, octet-counting
  framing), configured with the `TT_SYSLOG_*` variables; never blocking
  (`docs/operations/syslog.md`).
- Supervision (specification section 19): Prometheus metrics on `/metrics` and a JSON status on
  `/status` (transfers, volumes, quotas, antivirus, disk, HTTP requests, download streams, mail
  queue, webhook and syslog deliveries, dropped events, last cleanup runs), both disabled until
  `TT_METRICS_TOKEN` is set and optionally limited to `TT_METRICS_ALLOWED_IPS`. Values computed
  every 15 seconds; a wrong token is written to the security log (`metrics_token_invalid`, added to
  the fail2ban and CrowdSec filters). Grafana dashboard and Zabbix 7.0 template in `integrations/`;
  the shipped Caddy, Nginx and Apache configurations hide both paths on the tenant hosts
  (`docs/operations/supervision.md`).
- Transfer options (specification sections 8.2, 8.3 and 8.4): optional maximum number of downloads
  per transfer (1 to 1000, counting every download start of all the recipients together; once
  reached, the transfer is deleted after a short grace period and the link answers "maximum number
  of downloads reached"); confidentiality levels managed per tenant by its administrators (1 to 10
  levels, one default, French and English labels, rules on durations, password, internal
  recipients, deletion after the first download and a downloads cap; the rules are copied onto
  each transfer, so editing a level never changes existing transfers; the level is shown in the
  mails, on the download page, in the transfer details and in the audit log); recipient domain
  allow and deny lists per tenant (subdomains included, deny wins, refusals audited).
- Per-recipient links, recipient verification, tracking and expiry reminder (specification
  sections 8.2, 10 and 12.2): every new transfer gives each recipient a personal link, never shown
  to the sender, the administrators or the API tokens (transfers created before 1.1 keep their single
  shared link). With the sender's option or a confidentiality level rule, the recipient first enters
  a 6-digit code sent to the address of the link (valid 15 minutes, 2 tries, 5 codes per hour per
  address and link, 20 per hour per IP shared with the deposit codes, `429` when exceeded); the
  `__Host-tt_rv` cookie then lasts 1 hour. The sender and the administrators see per recipient
  which files were downloaded and when, never the IP address or browser. The `expiry-reminder`
  task (every 15 minutes) mails once per link, the day before expiry, the recipients who have not
  downloaded yet (skipped for blocklisted recipients and for lifetimes under 36 hours). The transfer
  password allows 3 tries counted per link; "delete after the first download" waits for every
  recipient; the sender confirmation no longer contains a link; the first-download receipt names the
  recipient; resending an administrator notification mails each recipient their own link. Security
  log: `verification_code_invalid` gains `purpose` (`deposit` or `recipient`) and `rate_limited` the
  scopes `verification_link` and `verification_ip`. Replying to a transfer answered `409` at that step (implemented later, see the reply entry above).
- `make check-full`: `make check` with the 20 GB test forced, required before every release.
- `make check` prints the duration of every gate.

### Changed
- `golang.org/x/net` 0.62.0 (fixes GO-2026-6860 and another advisory of the HTML parser used to
  sanitize the mail templates).
- SQLite migrations run on a reserved connection with foreign keys disabled before the
  transaction and checked (`foreign_key_check`) before commit, so that rebuilding a referenced table
  never deletes dependent rows.
- `make check` runs the 20 GB test only when the big-file chain changed since its last green run
  (CLAUDE.md section 24.4).
- The big-file test of `make check` uses a 5 GiB file, above the 2 GiB ClamAV and 4 GiB ZIP64
  boundaries; `make check-full` keeps 20 GiB before every release.

## [1.0.0] - 2026-10-26

First stable version: the V1 scope of the specification (CLAUDE.md section 2), validated by
`make check` (unit, integration, contract, tenant isolation, fuzzing, end-to-end on SQLite and
PostgreSQL, automated 20 GB test through the production stack) and by a real trial run by the
operator on 2026-10-25 (`docs/operations/bigfile-trial.md`): files of several GB uploaded from a
browser through the reference Caddy, with a network cut and an automatic resume, then downloaded,
every SHA-256 matching. The trial ran on build `267b890`; the later changes (antivirus outage
alert, default deadline before routing) are covered by `make check` on the release commit,
including the automated 20 GB test. The real client IP behind the production proxy remains to be
checked on the production host (Docker Desktop hides it).

- **Multi-tenant** instance: entity resolved from the `Host` header, data filtered at the data
  layer, PostgreSQL row-level security, one storage folder per entity.
- **Deposit and download**: email verification by one-time code, internal users (IP ranges and
  email domains), invitations for external users, blocklist, resumable tus uploads up to 20 GB,
  password-protected transfers, delete after first download, single-file downloads with byte
  ranges (resumable) and ZIP archives streamed on the fly (not resumable: an interrupted ZIP
  download starts again), SHA-256 fingerprints.
- **Security**: AES-256-GCM chunked encryption at rest with per-file keys wrapped by the master
  key, resumable master key rotation, crypto-erase (copies in backups only once the master key
  has been rotated and the old key destroyed after the backup retention period, see
  `docs/operations/master-key.md`), ClamAV scanning (fail-closed, with an outage alert),
  argon2id passwords and TOTP (mandatory for the super admin), rate limits, strict security
  headers and CSP, security log for fail2ban and CrowdSec, STRIDE threat model 1.0.
- **Administration and API**: super admin and delegated admins, per-entity branding, SMTP, IP
  ranges, domains, limits, quotas, email templates and legal texts, transfers, invitations,
  audit log, statistics, GDPR search and erasure, maintenance mode, disk space alert; REST API
  `/api/v1` (OpenAPI 3.1, interactive documentation embedded) with per-entity API tokens.
- **Operations**: single binary in a `scratch` image, hardened Docker deployment with ClamAV and
  optional PostgreSQL, reverse proxy configurations (Caddy, Nginx, Traefik, Apache), nightly
  database copies, user guides in French and English with integrated help and generated
  screenshots.

The detailed list of the changes made during the development of the V1 follows.

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
- Web administration, part 1 (`web/src/admin`, under `/admin/` on the admin host):
  first-run setup with the setup token, mandatory TOTP enrollment (QR code shown only when valid,
  grouped setup key) and recovery codes shown once (copy, `.txt` download, required
  acknowledgement); account activation from the link of a super admin (token read from the URL
  fragment, then removed from the address bar and history); sign-in with password then TOTP or
  recovery code, attempts left and lockout countdown, intermediate steps kept in memory only
  (5-minute server expiry); navigation guard with role and tenant scope checks and a safe return
  path (`safeNext`); sign-out and session expiry clearing the CSRF token and every in-memory store;
  my account (password change closing the other sessions, new authentication device with new
  recovery codes, disabling TOTP for a delegated admin when allowed); tenants list, creation,
  general settings (merge patch, delegated admins limited to the language and the limit per
  transfer) and deletion with the name typed again; branding with live contrast check, server
  contrast warnings, logo and background upload, display and removal; network ranges and internal
  domains with per-line errors and warnings; SMTP with password kept, replaced or removed, test
  email and SPF / DKIM / DMARC check; mail template editor (variable insertion, required
  variables, server errors with line and column, preview, reset); legal texts in Markdown with a
  server-rendered preview; admin accounts (list, creation with a single-use activation link shown
  once, edit, promotion, credentials reset, deletion). Generic admin components (layout, data
  table with cursor pagination, confirmation dialog, form sections with error summary and
  unsaved-changes guard, status badges). The typed API client sends `Blob` bodies with their
  type and gains the optional `onUnauthenticated` and `recoverCsrf` hooks (one CSRF retry, only
  when authenticated), used by the admin application only; `navigate(…, { force: true })`
  bypasses the navigation guards for forced redirects. `LegalContent` moves to
  `src/shared/components` and the mail template preview (`TemplatePreview`) becomes the second
  and last `{@html}` exception. French and English translations (`admin`, `adminAuth`,
  `adminComponents`, `adminTenants`, `adminAccounts`). Vitest coverage now includes `src/admin`.
  API additions: `GET /admin/tenants/{tenantId}/branding/{asset}` (`getBrandingAsset`, stored
  logo or background, `no-store`, `nosniff`, `ETag`, 404 outside the admin's scope, covered by
  the tenant isolation tests), `EmailTemplate.requiredVariables`, and the sanitised `html` of a
  legal document in the admin `GET` and `PUT` answers. Documentation: first launch and web
  administration in `docs/operations/admin.md`, `web/README.md`, admin tree in
  `docs/architecture/project-structure.md`, threat model v0.17 (T-91 updated for the two
  `{@html}` exceptions, new T-162 secrets on screen, T-163 stored XSS through the template
  preview, T-164 open redirect through `next`, T-165 session lifecycle in the interface, T-166
  branding uploads from the interface).
- Web administration, part 2 (`web/src/admin`): dashboard by role (super admin: table of every
  tenant with its storage level; delegated admin: one card per tenant with the transfers and
  volume of the last 30 days, the storage quota and quick links, loaded at most 4 at a time, each
  with its own error and retry; two-factor recommendation while TOTP is off); tenant
  sub-navigation grouped into Configuration and Operations; tenant operation screens
  (`screens/ops/`): transfers (filters in the URL, detail with files, SHA-256 fingerprints and
  antivirus results, no download link, resend to chosen recipients with the 5 per hour limit and
  its countdown, deletion with an optional reason and crypto-erase), invitations (status filter,
  erased issuer, revocation), blocklist (kind filter, per-kind normalisation of the value,
  duplicate reported on the field, removal), API tokens (list, creation with the "any address"
  shortcut and its warning, allowed senders, optional expiry, secret shown once, edit, revocation
  with the name typed again), audit log (action chosen in grouped lists of tenant actions or typed as a code, actor,
  period, details rendered as text), statistics (7 days, 30 days or 12 months in the URL, key
  figures, storage meter, bar charts with their data table) and personal data (search, erasure
  confirmed by typing the address, report linked to the audit log; the address only in POST
  bodies). New admin components: `SelectField`, `FilterBar`, `StatCard`, `QuotaMeter` (warning
  from 80 %, full from 100 %, never by colour alone), `BarChart` (SVG geometry applied by
  attributes, accessible summary and equivalent table) and `SecretOnceModal`. French and English
  translations (`adminHome`, `adminOps`, `opsTransfers`, `opsInvitations`, `opsBlocklist`,
  `opsTokens`, `opsAudit`, `opsStats`, `opsPrivacy`). Documentation: operating tenants in the web
  interface in `docs/operations/admin.md`, admin components and query-string filters in
  `web/README.md`, admin tree in `docs/architecture/project-structure.md`, threat model v0.18 (new
  T-167 API token secret shown once in the interface, T-168 personal data in the operation
  screens).
- Web administration, part 3 (`web/src/admin`, super admin only): **System** menu entry with its
  sub-navigation (`SystemNav`, routes `/system/*`, hidden and "page not found" for a delegated
  admin) and system screens (`screens/system/`): overview (7 days, 30 days or 12 months in the URL,
  disk meter whose warning level is the configured alert threshold, alert badge, prominent warning
  when the alert cannot be mailed without the system SMTP server, activity and storage of every
  tenant), maintenance mode (state and source, stored choice while `TT_MAINTENANCE` forces the
  mode, French and English plain text messages of at most 500 characters with a client check of
  the refused characters and a text-only preview, confirmations, warning that the messages are
  shown on every tenant), system settings (disk alert threshold edited as a percentage from 50 to
  99 with two decimals, additional alert address typed twice since it is not verified, removal),
  global audit log (tenant and action filters in the URL, every action group including
  administrators and instance, "Entity" column with "Instance" for the events without tenant; no
  "instance only" filter since the API cannot return them alone) and master key rotation (key
  identifiers only, steps 1 and 2 without a new key, two-box checklist then TOTP or recovery code
  in a dialog with "wait for the next code" and the warning that repeated wrong codes end the
  session, progress polled every 2 s with a self-scheduling poller stopped when the screen goes
  away, paused after 10 minutes without user activity ("Resume updates", `activity.ts`) and
  stopped after a persistent error ("Retry"), answers of an earlier polling ignored, bar capped
  at 100 %, milestone announcements,
  interruption detection after about 30 s without progress with a resume under the same
  identifier, 401/429/409 handling, next steps after completion, error after a failure; the code
  stays in component memory and is cleared after each submission). Maintenance banner shown to
  every admin while the mode is on (start date, "forced by the environment", link for the super
  admin), read at sign-in, on each navigation, when the tab is shown again and after a change,
  never on a timer since every read extends the admin session (`maintenance.svelte.ts`,
  `maintenanceBanner.ts`). Super admin dashboard: maintenance card ("state unknown" when it
  cannot be read) and disk card. French and English translations (`adminSystem`, `sysStats`, `sysMaintenance`,
  `sysSettings`, `sysAudit`, `sysMasterKey`). Documentation: system in the web interface in
  `docs/operations/admin.md`, the master key screen in `docs/operations/master-key.md`, system
  screens, maintenance store and poller in `web/README.md`, admin tree in
  `docs/architecture/project-structure.md`, threat model v0.19 (new T-169 master key rotation from
  the interface, T-170 maintenance message shown by the interface, T-165 extended: no
  timer-driven read for an idle admin).
- OpenAPI: `PublicTenant.maintenanceMessageLanguage`, the language the `maintenanceMessage` is
  actually written in after the server fallback (present if and only if the message is). The
  public interface sets it as the `lang` attribute of the maintenance message on the deposit,
  invitation and maintenance screens and in the maintenance banner (RGAA criterion 8.7); after a
  `503 maintenance` problem, whose `detail` does not carry its language, the deposit flow reads
  it from the tenant description or a fresh `GET /tenant`.
- End-to-end test suite `test/e2e` (Playwright 1.55.1 pinned with axe-core 4.10.3, separate Node
  project installed with `npm ci --ignore-scripts`): a real Chromium goes through Caddy (`tls
  internal`, `admin.localhost`, `entity-a.localhost`, `entity-b.localhost`) to the
  `bin/transteira` binary, on SQLite then on PostgreSQL (dedicated `transteira_e2e` database),
  with a fake clamd, Mailpit and seeding through the admin API. Every browser context fails the
  test on a CSP violation, a page error, a request to another origin (no CDN), an HTTP 5xx or an
  undeclared console error; axe-core (WCAG 2.1 A/AA) runs on every screen visited and the browser
  storage is checked. Scenarios: deposit and download with SHA-256 checks (single file and ZIP),
  transfer password and lock, external invitation, antivirus (EICAR built at runtime, file too
  large), access and blocklist, admin authentication, tenant configuration, tenant operations
  (transfer detail, resend, delete, API token shown once then a tus deposit with it, audit,
  statistics, personal data), system screens (in a serial project), tenant isolation from a
  browser, French pass. `make e2e`, one engine with `E2E_DBS=sqlite`, one spec with
  `E2E_ARGS`.
- Machine-wide run lock of the end-to-end suite (`test/e2e/.run.lock`, `scripts/lock.mjs`):
  `make e2e` and `make screenshots` take it before the build and keep it for both engines, a
  Playwright run started directly takes it in its global setup; a second run waits (up to
  `E2E_LOCK_TIMEOUT` minutes) and a lock whose process is gone (or older than
  `E2E_LOCK_MAX_AGE`) is taken over. A run never stops the server or the Caddy of another run.
- Documentation screenshots generated by Playwright (`make screenshots`, SQLite, deterministic
  data, frozen browser clock, 1280 x 800, reduced motion, volatile values neutralised and masked):
  42 screens of the four profiles in French and in English in `docs/user/screenshots/{fr,en}/`,
  listed in `docs/user/screenshots/manifest.json` (name, screen, profile, path).
  `make screenshots-check` (in `make check`) verifies that every entry has both images
  (1280 x 800 PNG of bounded size), that no image is outside the manifest, that names are
  kebab-case and that the manifest still matches the catalog of `test/e2e/support/screenshots.ts`;
  `make screenshots` fails when a capture fails.
- End-to-end network on Linux: the server under test listens on the Docker bridge gateway only
  (read with `docker network inspect bridge`, where `host.docker.internal` points), never on
  every interface, and trusts only that address and the subnet of the compose network of Caddy
  instead of the whole `172.16.0.0/12`; Windows and macOS keep loopback.
- User guides in `docs/user/`, one per profile in English and in French
  (`{en,fr}/{depositor,recipient,delegated-admin,super-admin}.md`), illustrated with the
  generated screenshots, and an index `docs/user/README.md`; the README links them and shows
  screenshots.
- Integrated help built from these guides (`web/scripts/build-help.mjs`, `npm run help:gen`, run
  before `dev`, `check`, `test` and `build`): a strict Markdown subset (headings, paragraphs,
  one-level lists, notes, screenshots, internal links, topic markers) converted into typed data
  modules per language and application (`web/src/help/generated/`, git-ignored), any other
  construct, missing screenshot, broken link, duplicate topic or topic missing in one language
  failing with `file:line` errors. `/help` and `/help/<topic>` in both applications show the
  guides of the application (the super-admin guide never for a signed-in delegated admin), with a
  table of contents, focus on the section of the topic, the page title "Section – Guide", reload
  at the same topic on a language change and "back to the previous screen". Guides are
  lazy-loaded per application and language, screenshots are served fingerprinted under
  `/assets/`, and the help is rendered from structured data, without `{@html}` (threat model
  T-91, v0.21). A test checks that every help topic of both route tables opens a section in both
  languages, in a guide the user of the screen can read.
- Contextual help icons (`HelpIcon`, "?" next to the screen title, accessible name "Help: <screen
  title>") on the API token list and creation, tenant network, tenant SMTP and master key
  screens.
- `transteira backup`: immediate, checked copy of a SQLite database, safe while the server runs.
  By default it goes to `TT_BACKUP_DIR` as `transteira-<timestamp>-manual.db`, with the mechanism
  of the nightly copy (`VACUUM INTO` into a `0600` temporary file, `quick_check`, fsync, atomic
  rename); the nightly rotation never deletes these copies, but it sweeps the temporary files of
  an interrupted manual copy. With `--out <file>` the copy is written directly into that file,
  created empty with mode `0600` and never overwritten. The path and size are printed. With PostgreSQL it points to the `db-backup` container and exits with `2`.
  Documented in `docs/operations/backup.md` (manual copy before an upgrade).
- Container image (`Dockerfile`): three stages (web interface and integrated help, static Go
  binary with the same ldflags as `make build` and the embedded time zone database, final
  `scratch` image holding only the binary, the CA certificates and a minimal root file system);
  base images pinned by digest; runs as the unprivileged user `transteira` (UID/GID 10001) with a
  read-only root file system, the volumes `/data`, `/var/lib/transteira/db`, `/backups` and
  `/logs` owned by that user, and a `HEALTHCHECK` through `transteira healthcheck`. The build
  context excludes secrets, databases, uploaded files, backups and logs (`.dockerignore`).
  `make docker` builds `transteira:<version>` and `transteira:local`; `make docker-check` (in
  `make check`, skipped without Docker or with `DOCKER_CHECK=0`) builds the image and
  smoke-tests it (`scripts/docker-check.sh`: version, image user, start with the production
  hardening, processes as UID 10001, health check reaching `/healthz`, database and security log
  written in their volumes).
- Production compose files (`deploy/`): `docker-compose.yml` with SQLite (default), clamd and a
  separate `clamav-update` container running freshclam (`deploy/clamav/clamd.conf`,
  `deploy/clamav/freshclam.conf`), and the `docker-compose.postgres.yml` overlay (PostgreSQL on
  its own `db` network, one-shot `migrate` container holding the owner DSN, nightly `pg_dump` by
  `db-backup`, roles created by `deploy/postgres/initdb/`). Hardening (threat model T-119,
  decision P24): no published port, every service read-only, without capabilities and with
  `no-new-privileges`, memory and process limits, images pinned by digest; clamd on the
  `internal` network without Internet access, freshclam alone on the `clamav_egress` network and
  sharing only the signature volume, mounted read-only in clamd; the one-shot `clamav-init`
  (root, no network, `CHOWN` and `DAC_READ_SEARCH` only) gives that volume to the `clamav` user
  with `chown -Rh`; the master key, the DSNs and the PostgreSQL passwords as Docker secret files
  outside every volume. The clamd spool (`TemporaryDirectory`, where clamd writes each decrypted
  stream) is a 2304 MiB tmpfs, never a volume, so the plaintext never reaches a disk or a backup
  (T-44); it holds one stream, hence `TT_SCAN_WORKERS=1` and a clamd `mem_limit` of 4 GiB. The
  `internal` and `db` networks have fixed subnets (`INTERNAL_SUBNET`, `DB_SUBNET`), listed with
  the proxy subnet in the `TT_SMTP_DENY_NETWORKS` of `deploy/.env.example`, so that the SMTP
  server of a tenant can reach neither clamd, PostgreSQL nor the proxy (T-90). `db-backup`
  connects with the read-only role `transteira_backup` (`SELECT` only, through default
  privileges, `NOBYPASSRLS`), and the `postgres` superuser is rejected over TCP by `pg_hba.conf`
  (local socket only). Fixed volume names (`transteira_logs` for fail2ban and CrowdSec).
  `deploy/init-secrets.sh [--postgres]` creates the secret files with random values, mode `0400`
  and the owner of the reading container (10001 or 70), never overwriting an existing file,
  refusing symbolic links and, as root, a directory not owned by root; `deploy/.env.example` and
  `deploy/README.md`. Requires Docker Engine 25 and Compose 2.24 or later.
- Reverse proxy configurations (`integrations/reverse-proxy/`): Caddy (reference, with its own
  compose file), Nginx, Traefik (file provider or container labels) and Apache, each with a
  README: TLS for every FQDN, unknown host names refused, `Host` preserved, no buffering, no
  request size limit, long timeouts, `X-Forwarded-For` / `X-Real-IP` overwritten with the real
  client address, HSTS without `includeSubDomains` by default, compression of text only, and
  capability tokens masked in the access logs (left out of the Traefik access log), with their
  limits documented; Caddy drops every request header from its logs (`Referer`,
  `Upload-Metadata`, `X-Csrf-Token`...). The proxy gets a fixed address on the `proxy` network
  (fixed subnet), which is the exact value of `TT_TRUSTED_PROXIES`. Proxy images pinned by
  digest; the Traefik container runs read-only with `NET_BIND_SERVICE` only, and the file
  provider is recommended over the Docker socket; the Nginx and Apache READMEs describe one
  certificate per tenant as an option. `make proxy-configs-check` (in `make check`, skipped
  without Docker) validates the four configurations with the real proxies in Docker (Traefik
  with the hardening of its compose file).
- `make deploy-config-check` (in `make check`, skipped without Docker): `docker compose config`
  of both compose combinations with dummy secrets, hardening invariants of every service,
  `clamconf` on the ClamAV configuration (size limits equal to `TT_CLAMAV_MAX_SCAN_BYTES`,
  mandatory alerts, spool directory), clamd spool on a tmpfs with no volume and
  `TT_SCAN_WORKERS=1`, fixed subnets listed in `TT_SMTP_DENY_NETWORKS`, `db-backup` on the backup
  role, syntax of the shell scripts (`scripts/deploy-config-check.sh`).
- `make deploy-smoke` (outside `make check`: needs Internet access and several minutes): starts
  the production files in an isolated compose project behind the reference Caddy, on SQLite then
  PostgreSQL (`DEPLOY_SMOKE_DB`), with the real ClamAV; checks the hardening and runs setup,
  TOTP, tenant, real client IP in the security log, token deposit with tus, EICAR detection,
  download with SHA-256, encryption at rest and database copies (with PostgreSQL: dump by the
  read-only backup role, its writes refused, superuser refused over TCP), then removes everything
  it created (`scripts/deploy-smoke.sh`, `test/deploy/`).
- Installation guides: `docs/install/docker.md` (step by step, first run, checks, PostgreSQL
  variant), `docs/install/reverse-proxy.md` (choosing a proxy, `TT_TRUSTED_PROXIES`, unknown host
  names, adding a tenant), `docs/install/smtp.md` (per-tenant servers, unauthenticated relay on
  the Docker network and shared relay sender restriction, Microsoft 365 through Graph,
  SPF/DKIM/DMARC, system SMTP); operation guide `docs/operations/upgrade.md` (maintenance mode,
  database copy, upgrade, rollback).
- Threat model v0.22 (step 21): T-119 and P24 implemented; T-06, T-08, T-44 (plaintext in the
  clamd spool, now a tmpfs), T-45, T-46, T-90 (stack subnets denied to tenant SMTP), T-116,
  T-118, T-122 and T-161 completed; new T-172 (tokens in the reverse proxy logs), T-173 (fixed
  address of the trusted proxy), T-174 (unknown hosts refused at the proxy), T-175 (HSTS),
  T-176 (shared unauthenticated SMTP relay), T-177 (manual database copies).
- Automated 20 GB test `make bigfile` (CLAUDE.md section 24.2), the last gate of `make check`, on
  SQLite then PostgreSQL: a 20 GiB file generated on the fly is deposited with an API token through
  tus and the real reference Caddy to the production stack (`deploy/`, real ClamAV), cut in the
  middle of a `PATCH` and resumed from the offset reported by `HEAD`, then downloaded in full and
  once more cut and resumed with `Range` and `If-Range`; every SHA-256 must match and the memory
  of the server (cgroup `anon`, sampled every second by a hardened helper container) must stay
  below `BIGFILE_MAX_MEM` without an upward trend. Variables: `BIGFILE=0` (skip, never before a
  release), `BIGFILE_BYTES`, `BIGFILE_DBS`, `BIGFILE_KEEP`, `BIGFILE_MAX_MEM` (256 MiB);
  `make bigfile-clean` removes what a kept run left. A preflight checks Docker memory and disk
  (including the host drive of the Docker Desktop disk image). Files: `scripts/bigfile.sh`,
  `scripts/lib/stack.sh`, `scripts/lib/memsampler.sh`, `test/bigfile` (client, build tag
  `bigfile`) and `test/bigfile/memcheck`; documented in `test/README.md` ("20 GB test"). Reference
  run (both engines, 1504 s): about 90 MiB/s each way through Caddy, upload resumed at the exact
  byte received, server memory peak about 97 MiB.
- `test/internal/seeded`: shared deterministic pseudo-random content generator with its SHA-256,
  seekable by block, used by the 20 GB test and the integration tests.
- `docs/operations/bigfile-trial.md`: procedure of the human trial with very big files behind the
  production reverse proxy before the V1 is declared done (CLAUDE.md section 27.4): browser
  upload of several 5 to 20 GB files with a network cut and a page reload, downloads, SHA-256
  checks, server observation, results grid, what to send back, troubleshooting and reclaiming
  Docker Desktop disk space.
- Threat model v0.23 (step 22): column G of the test matrix (20 GB test) and its guard paragraph,
  examples of T-21 to T-27, T-28 to T-34, T-47 to T-57 and T-123 to T-128 completed.
- French translations of the Docker installation guide (`docs/install/fr/docker.md`) and of the
  SMTP guide (`docs/install/fr/smtp.md`), linked from the English versions, which remain the
  reference, and from the README.
- README: "How it works" section with an architecture diagram and the life of a transfer
  (Mermaid, rendered by GitHub), and a gallery of six generated screenshots.
- Antivirus outage alert (threat model P10, T-42), `internal/avalert`: when clamd stays
  unreachable while transfers wait for analysis, after a 5-minute grace period (so a restart or a
  signature reload alerts nobody), confirmed by a PING (at most 3 postponements while the worker
  keeps failing), a system mail to the super admins and the alert address, and the tenant
  template `antivirus-unavailable`, now sent, to the delegated admins (else the super admins) of
  each entity with transfers waiting; one mail per outage and at most one per hour, persisted
  (migration 0013, `system_settings.antivirus_alert_mailed_at`), retried while the outage lasts
  when held back by the hourly interval; the alert clears when clamd answers again, or when no
  transfer waits any more and clamd answers a PING; audit actions `antivirus.alert_raised` and
  `antivirus.alert_cleared`.
- Default read and write deadline (30 s) set as soon as a request arrives, before tenant
  resolution, rate limiting and routing (threat model T-123): requests refused early (421, 429,
  404, 405) can no longer be held open; the matched operation's deadline replaces it and the
  streaming routes still clear it.

### Changed
- `make check` now runs `e2e-lint` (Prettier, ESLint, `tsc` and `npm audit` of `test/e2e`,
  `NPM_AUDIT=0` skips the audit), `screenshots-check` and the whole end-to-end suite on both
  engines (`e2e`, after `test` and `cover`); `E2E_BROWSER_INSTALL=0` never downloads
  Chromium.
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
- A tenant FQDN equal to an admin host is refused with the field error code `reserved-host`
  (formerly `invalid-format`), so that the interface can explain why.
- Generated TypeScript types (`web/scripts/gen-types.mjs`) keep request fields that have a default
  value optional, as the OpenAPI specification declares them.
- Web interface: `isEmail` and `EMAIL_MAX_LENGTH` move to `web/src/shared/validation/email.ts`,
  shared by the public and admin applications (still re-exported by `src/public/deposit/form.ts`),
  and Vitest coverage includes `src/shared/validation`. The `Navigation` handed to the admin screens
  exposes the router's reactive `current` location (path and query string), used by the list
  filters; a screen is kept when only the query string changes.
- Admin network screen: an added invalid line counts as a change, so saving shows the error
  summary instead of "no changes"; line list fields no longer repeat their error under the
  per-line list, and the summary reads "N lines are invalid."
- Admin audit log: the display of the events (actor, action, object, details) moves to reusable
  components (`AuditEventsTable`, `AuditActorCell`, `AuditActionCell`, `AuditObjectCell`,
  `AuditDetails`), shared by the tenant and global logs; object links point to the tenant of the
  event. The tenant audit log behaves as before.
- Admin `QuotaMeter` and `quota.ts` accept a `warningRatio` option (default 80 %), used by the disk
  meters with the configured alert threshold.
- Admin shell: `navCurrent` takes an `exact` option, so that a link to a parent path (the system
  overview `/system`) is not marked as current on its sibling sections.
- `make check` runs the Go tests with a 30-minute timeout instead of the 10-minute default of
  `go test`, which the slowest packages could exceed on a loaded machine.
- `maintenance.Mode.Message` also returns the language of the message it chose (negotiated
  language, tenant default, English or any language), and the maintenance interfaces of
  `internal/httpserver` and `internal/api/public` follow. The `503 maintenance` problem still
  carries no `Content-Language` (its `title` stays English and its `detail` may be a fallback).
- The `GET` and `HEAD` requests for the build files of the web interface (clean paths under
  `/assets/`, on any `Host`) are no longer charged to the global per-IP rate limit (50 requests
  per second, burst of 100) but to a separate, larger per-IP limit (`AssetRate` 500 requests per
  second, `AssetBurst` 1000, `rate_limited scope="assets"` in the security log): a cold page load
  fetches dozens of script chunks, and a few users behind one NAT address got `429` on scripts
  and API calls. The asset limit is checked before tenant resolution, so asset requests with
  random `Host` headers cannot force unthrottled tenant lookups. Entry pages, the API, the
  documentation and the help stay under the global limit (threat model T-171, v0.20).
- The router marks the history entries it adds (`ROUTER_ENTRY`, `isRouterEntry(history.state)`),
  so that the help offers "back to the previous screen" only when the previous entry belongs to
  the application; a replaced entry (redirect, same URL) keeps that mark.
- The help topic of the tenant creation screen is `tenant-create` instead of `tenants`.
- The footer help link navigates inside the application (router `nav` passed to `Footer` and
  `HelpLink` by both applications) instead of reloading the page.
- The OpenAPI description of `AdminPassword` states the only rule applied, the length (12 to 1024
  Unicode code points), and the password rule texts of the administration no longer mention a
  list of common passwords.
- The maintenance texts are aligned between the deposit page, the maintenance page and the
  maintenance banner (new transfers and invitations suspended, downloads still available).
- Interface wording: the file table of the download page has a "Download link" column ("Lien
  de téléchargement"), the maintenance state of the statistics reads "Actif" / "Inactif" in
  French, the French password confirmation label reads "Confirmez le mot de passe", and the
  French locales use typographic apostrophes (’) throughout.
- Integrated help, after review: the unknown-topic message repeats the requested topic only when
  it is a well-formed topic of at most 64 characters (generic message otherwise); guides
  containing control characters, Unicode line or paragraph separators or bidirectional formatting
  characters are refused with `file:line` errors; the generated modules are written from the
  structure (no text substitution, image sources as import identifiers) and give each screenshot
  its real size read from the PNG header; section ids stay unique like on GitHub (`foo`, `foo-1`,
  `foo-1-1`); syntax that GitHub reads differently is handled or refused (`__bold__`, tables
  without outer pipes, list items continued or separated after a blank line, an empty `>` line in
  a note, closing hashes of headings); a topic link from the delegated-admin guide to the
  super-admin guide is refused; the help icons of the screens are checked against the route
  topics and the guides; the dev server serves the screenshots and regenerates the help when a
  guide changes.
- README: new "Installation (Docker + reverse proxy)" and "Configuration" sections (essential
  variables), and links to the installation and operation guides, which replace the "will be
  published with the first release" note.
- Documentation aligned with the container image: the security log is in `/logs` on the
  `transteira_logs` volume, and the image runs as UID/GID 10001 (logrotate `create 0640 10001
  10001`, fail2ban `logpath`, bind mount permissions); the antivirus guide describes the
  provided clamd and freshclam containers; the backup guide covers the manual copy and the
  `db-backup` container; the project structure lists `deploy/`, the `Dockerfile` and the
  deployment scripts.
- `transteira` exit codes: `3` (not implemented) is gone; `2` also means a command that does not
  apply to the configuration (`backup` with PostgreSQL).
- The pseudo-random content of the integration tests now comes from `test/internal/seeded`
  (seekable by block): the generated bytes changed, the behaviour of the tests did not.
- `.golangci.yml` lints the code under the `bigfile` build tag, and `make vet` also vets
  `test/bigfile` with that tag.
- `make deploy-smoke` uses the stack library shared with the 20 GB test (`scripts/lib/stack.sh`).
- README: the Development section mentions `make bigfile` and its prerequisites.

### Fixed
- `docker-check` no longer fails at random on "no SQLite database": `grep -q` closed the pipe
  while `docker cp` was still writing, and `pipefail` turned that write error into a failure.
- Integrated help: inline errors inside a multi-line paragraph, list item or note point to their
  own line; a missing guide is reported once and a missing or invalid screenshots manifest gives a
  `file:line` error instead of a stack trace; a failed reload while a guide is shown displays the
  error with its retry button; modified or middle clicks on section links and on the table of
  contents keep the browser behaviour (new tab); the pending focus move is cancelled when the help
  screen goes away.
- A request canceled by the client (a browser leaving a page) during the deposit or admin
  session lookup, the API token lookup or the tenant resolution is logged at debug level
  instead of `ERROR` (`middleware.ClientGone`); real failures keep the `ERROR` level.
- The admin preview of a mail template no longer triggers CSP violations: for the preview only,
  `mail.Preview` removes the style attributes and style elements of the rendered mail and
  replaces each image (such as the `cid:` QR code) by its alt text in brackets
  (`sanitize.ForPreview`), which the admin CSP (`style-src 'self'`, `img-src 'self' data:`)
  would block anyway. The mails sent keep their styles and images; the OpenAPI description of
  `previewEmailTemplate` and `EmailPreview.bodyHtml`, the note of the preview, the docs and the
  threat model (T-91, T-163) say so.
- An invitation refused with `403 deposit-not-allowed` (the inviter or the invited address is
  blocklisted, or the inviter left the internal network) no longer shows "Invitations not
  available / Your address is not allowed to send invitations", which blamed the inviter: the
  form stays and shows a neutral message ("This invitation cannot be sent. Check the address or
  contact your administrator."), revealing nothing about the blocklist. The "not available"
  page remains for `403 invitation-not-allowed` (depositor not internal).

[Unreleased]: https://github.com/ed-fr/transteira/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/ed-fr/transteira/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/ed-fr/transteira/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/ed-fr/transteira/compare/v1.2.1...v2.0.0
[1.2.1]: https://github.com/ed-fr/transteira/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/ed-fr/transteira/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ed-fr/transteira/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ed-fr/transteira/releases/tag/v1.0.0

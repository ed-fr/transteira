# GDPR record of processing activities: file transfer service

Template for the record of processing activities (GDPR, article 30) of an
organisation that operates **TransTeira 2.1**. It is pre-filled from what the
software does (data model, cleanup task, administration screens). Everything
that only the organisation can decide is marked `<to be completed>`.

Français : [docs/compliance/fr/gdpr-processing-record.md](fr/gdpr-processing-record.md).

> This is a template, not legal advice. See the [disclaimer](README.md).
> One TransTeira instance can serve several entities (tenants). If the
> entities are separate controllers, fill one copy per entity; if one legal
> person operates them all, one record with the entities listed is enough.

## 1. Identification

| Item | Value |
|---|---|
| Processing activity | File transfer service ("TransTeira") |
| Record version and date | `<to be completed>` |
| Controller (legal entity, address) | `<to be completed>` |
| Representative of the controller | `<to be completed>` |
| Data protection officer (DPO) or contact | `<to be completed>` |
| Joint controllers (if the entities of a group decide together) | `<to be completed>` or none |
| Entities (tenants) covered | `<to be completed>` (host names, for example `transfer.entity-a.example.com`) |

## 2. Purposes

- Transfer files, possibly very large, from a sender to recipients, with a
  limited lifetime (1, 7 or 30 days).
- Verify the identity of the sender (code sent to their mailbox) and,
  optionally, of each recipient.
- Protect the service and the data: access control, antivirus analysis,
  abuse detection, audit and security logs.
- Prove a deposit or a delivery in case of dispute (signed statements).
- Share one-time secrets (since 2.1): a text of at most 10 000 characters and an optional file, encrypted in the browser, readable once, with a limited lifetime.
- Administer the service (administrator and auditor accounts).

## 3. Legal basis (article 6)

Choose one basis per purpose and delete the others.

| Purpose | Legal basis | Choice |
|---|---|---|
| File transfer between users and invited third parties | Legitimate interest (art. 6.1.f) / performance of a contract (art. 6.1.b) | `<to be completed>` |
| Security, audit and security logs, abuse detection | Legitimate interest (art. 6.1.f) / legal obligation (art. 6.1.c) | `<to be completed>` |
| Proofs of deposit and delivery | Legitimate interest (art. 6.1.f) / contract (art. 6.1.b) | `<to be completed>` |
| One-time secrets (2.1) | Legitimate interest (art. 6.1.f) / performance of a contract (art. 6.1.b) | `<to be completed>` |
| Administration of the service | Legitimate interest (art. 6.1.f) | `<to be completed>` |

TransTeira never asks for consent and uses no consent-based processing.

## 4. Data subjects

| Category | Who |
|---|---|
| Senders | Internal users (address in an internal domain, from the entity network) and invited external people, who deposit files. No account is created. |
| Recipients | People to whom a transfer is addressed, by email. |
| Invited people | External people invited by an internal user to deposit. |
| Depositors through a permanent drop link | External people who deposit to a service (drop link), after verifying their address. |
| Administrators | Super admin and delegated admins. |
| Auditors | Read-only accounts (RSSI, auditors). |
| Creators of one-time secrets (2.1) | Internal users, invited external people and the senders declared by an API token, who create a secret. |
| Recipients of an e-mailed secret (2.1) | People to whom a secret is sent by e-mail. |
| Other people named in free text | People mentioned in a transfer message, in a file name or in an abuse report. |

## 5. Categories of personal data

| Data | Detail | Where it is kept |
|---|---|---|
| Email addresses | Sender, recipients, invited people, depositors, reporters of an abuse; administrator and auditor addresses. | Database (transfers, recipients, invitations, verified addresses, proofs, drop links, administrators). |
| IP addresses | Of the sender at deposit, at address verification (first verification, and first internal verification), of verification requests, of abuse reporters; client IP in the audit and security logs. | Database and log files. |
| File names, sizes and SHA-256 fingerprints | Of each deposited file; the names are free text chosen by the sender. | Database; fingerprints are also in notification emails and proofs. |
| Transfer messages | Optional free text of the sender. | Database. |
| File content | May contain any data, including sensitive data. Encrypted on disk (AES-256-GCM, one key per file). For an end-to-end encrypted transfer, the browser encrypts and the server never holds the key, so **the operator cannot read it**; antivirus analysis is then impossible and the download page says so. | Data volume (encrypted); keys, wrapped by the master key, in the database. |
| One-time secret content (2.1) | The text (at most 10 000 characters) and the optional file of a secret. Zero knowledge: the browser seals them, the key stays in the link fragment and only SHA-256 verifiers are stored, so **the operator cannot read them**, except when the e-mail delivery carries the key in the link of a secret without a passphrase (see section 7). Never scanned by the antivirus. | Database (sealed text); data volume (sealed file); keys, wrapped by the master key, in the database. |
| One-time secret metadata (2.1) | Creator address, recipient address (e-mail delivery only), creator kind, delivery, dates, state, end reason, declared file size, choice of a read receipt. Read receipts are mails to the creator. | Database. |
| Transfer events | Dates of deposit, first download, downloads per recipient and per file (per-recipient links). | Database. |
| Verification state | Codes (stored as a MAC, never in clear), attempts, deposit sessions, date of the last use of a verified address. | Database. |
| Audit log | Time, tenant, actor (address or administrator), IP, action, object. | Database. |
| Security log | Time, event type, real client IP, tenant. No email address. | Log file and database. |
| Proofs of deposit and delivery | Signed statements naming the sender, the recipients, the files and their fingerprints, the dates. No IP address. | Database. |
| Abuse reports | Category, free-text message, reporter IP. | Database. |
| Administrator accounts | Username, email, role, password hash (argon2id), TOTP secret (sealed by the master key), recovery codes (hashed), session records. | Database. |
| Single sign-on identifiers (if used) | Issuer, client ID and subject (`sub`) of the identity provider account linked to an administrator. | Database. |
| Technical cookies | Strictly necessary only, see section 9. | Browser. |

No special categories of data (article 9) are collected by TransTeira itself,
but **the files and messages that users send may contain some**. The
controller decides, in its acceptable-use rules, what may be sent
(confidentiality levels, recipient domain restrictions).

## 6. Recipients of the data

| Recipient | Detail |
|---|---|
| Internal | Sender and recipients of each transfer; delegated admins of the entity (metadata, never file content: decision P18; for one-time secrets, the metadata including the recipient address, never the content); auditors (read-only, the list of secrets); super admin. The creator of a secret receives its read receipts. |
| Processors and service providers | See section 7. |
| Third parties by law | `<to be completed>` (authorities, on legal request) |

## 7. Processors and transfers outside the EU

TransTeira is **self-hosted**: the operator chooses where and by whom it is
run, and the project itself receives no data. The only outgoing connection
to the project is the update check (an anonymous request to the GitHub API
every 24 hours; no tenant, user or instance identifier is sent, but GitHub
sees the IP address of the server; `TT_UPDATE_CHECK=false` disables it,
threat T-245).

| Processor or service | Role | Data concerned | Location | Contract (art. 28) | Transfer outside the EU and safeguards |
|---|---|---|---|---|---|
| Hosting of the VM and its backups | Runs the service and the backups | All data (files are encrypted at rest) | `<to be completed>` | `<to be completed>` | `<to be completed>` |
| SMTP relay (for example Microsoft 365 or another relay) | Sends the emails of the service | Recipient and sender addresses, email content (links, fingerprints, messages). **Secret mails contain the decryption link: the mail chain can read a secret that has no passphrase** (T-362, H21) | `<to be completed>` | `<to be completed>` | `<to be completed>` |
| OpenID Connect provider (for example Microsoft Entra ID), if single sign-on is used | Authenticates administrators and auditors | Administrator identity (email, `sub`) | `<to be completed>` | `<to be completed>` | `<to be completed>` |
| Webhook destinations (Teams, Slack, generic), if used | Receive alerts | Minimal alert payload by default (decision P31) | `<to be completed>` | `<to be completed>` | `<to be completed>` |
| Remote antivirus engine (ICAP, HTTP API), if used | Analyses the files | File content in transit, in clear to the engine | `<to be completed>` | `<to be completed>` | `<to be completed>` |
| Syslog collector or SIEM, if used | Receives audit and security logs | Logs (IP, addresses in the audit log) | `<to be completed>` | `<to be completed>` | `<to be completed>` |
| Managed service provider (ESN), if it operates the instance | Administration, provisioning | `<to be completed>` | `<to be completed>` | `<to be completed>` | `<to be completed>` |

Delete the lines that do not apply. The default ClamAV engine runs in a
container of the same host and sends nothing outside.

## 8. Retention

The periods below are those applied by the software (the cleanup task of
TransTeira, run hourly for the row purges). Where the operator can act, the
last column says where.

| Data | Retention | Operator can change |
|---|---|---|
| Transfers and their files | Until the expiry chosen by the sender (**1, 7 or 30 days**), or earlier: after the first download if the option is ticked, when the maximum number of downloads is reached, or on manual deletion by the sender (My transfers) or an admin. The files are then deleted and their keys destroyed. The (key-less) metadata row of an ended transfer is purged **30 days** after its end. | The available durations and the maximum size per entity (administration, General settings). Not the purge delay. |
| Unfinished uploads | Discarded after `TT_UPLOAD_TTL` (24 h by default) of inactivity, and at the latest `TT_UPLOAD_MAX_AGE`. | `.env`: [`.env.example`](../../.env.example) |
| Transfers stuck in antivirus analysis | Erased 30 days after the deposit if the analysis never completes. | No |
| Verified addresses | Deleted after **12 months** without use; the address must then be verified again. | No |
| Invitations | Valid 12 months from creation or last use; inactive invitations purged afterwards. | An admin can revoke an invitation at any time. |
| Permanent drop links | Expired or revoked links are purged 12 months afterwards, once their transfers are deleted. | An admin can disable, revoke or give an expiry date. |
| One-time secrets (2.1) | Pending (unfinished) secrets are deleted after **1 hour**, with no tombstone. An active secret lasts until the duration chosen by its creator (1 hour to 30 days, from the list offered by the entity), until it is read, deleted, or locked after 5 wrong passphrases. The key of its file is destroyed at the first complete download or 10 minutes after the reveal. A tombstone (addresses, dates, state, file size; no content, no verifier, no salt) is purged **30 days** after the end. Audit entries `secret.*`: 12 months. | The durations offered per entity (secret settings). Not the purge delays. |
| Verification codes | Deleted after use or expiry (rate-limit rows are kept one hour). | No |
| Deposit sessions, password failure counters, "My transfers" access links | Purged after their short validity (hours). | Deposit session length: `TT_DEPOSIT_SESSION_TTL`. |
| Audit log | **12 months**, then purged. No edit or delete through the application, except the pseudonymisation of an erasure. | No |
| Security log, database copy | **12 months** (database purge). The log **file** is rotated by the operator: keep it 12 months as well ([security log](../operations/security-log.md)). | Log rotation (operator). |
| Syslog export | Per the retention of your collector. | Operator. |
| Proofs of deposit and delivery | **12 months** after creation, even if the transfer is deleted. | No |
| Abuse reports | 12 months. | No |
| Abuse alerts (de-duplication data) | 2 days. | No |
| Statistics counters (volumes, counts, no personal data) | 13 months. | No |
| Administrator sessions | Idle timeout 30 minutes and maximum age 12 hours by default. | `TT_ADMIN_SESSION_IDLE_TIMEOUT`, `TT_ADMIN_SESSION_MAX_AGE` |
| Administrator and auditor accounts | Until deleted by the super admin. | Super admin. |
| Database copies (SQLite `VACUUM INTO`, PostgreSQL `pg_dump`) | `TT_BACKUP_KEEP` copies (7 by default for SQLite), then the retention of the VM backups. | `.env` and the backup policy ([backup](../operations/backup.md)). |
| Backups of the VM | `<to be completed>` | Operator. |

## 9. Cookies

TransTeira uses **strictly technical cookies only**: no audience measurement
and no third-party cookie, so no consent banner is needed. Cookies prefixed
`__Host-` are set by the server, for the host only, `Secure`, `HttpOnly`,
`SameSite=Strict` (except the sign-in flow cookie, `Lax`).

| Cookie | Purpose | Duration |
|---|---|---|
| `__Host-tt_deposit` | Deposit session after address verification (also used to create a one-time secret) | Session validity (4 hours by default) |
| `__Host-tt_known` | Recognition of an already verified address | Up to 12 months |
| `__Host-tt_dl` | Grant after a correct transfer password | 1 hour |
| `__Host-tt_rv` | Verification of a recipient on their link | 1 hour |
| `__Host-tt_me` | "My transfers" session (also lists "My secrets") | 1 hour |
| `__Host-tt_admin` | Administration session | Idle 30 min, maximum 12 h by default |
| `__Host-tt_oidc` | Single sign-on flow in progress | 10 minutes, one use |
| `tt_theme` | Light or dark theme chosen by the user (written by the browser, never read by the server) | 1 year |

## 10. Rights of the data subjects

Rights of access, rectification, erasure, restriction, objection and
portability are handled by the controller. TransTeira provides:

- **Search and erasure by email address**: the administration screen
  "Personal data" (delegated admin guide, section
  [Personal data (GDPR)](../user/en/delegated-admin.md)). A delegated admin
  searches an address, sees a summary of the data linked to it in the entity,
  and erases it. Effects: verified address, codes and sessions deleted;
  transfers sent by the address made unreadable and deleted; address removed
  from received transfers (a transfer left without recipient is deleted);
  one-time secrets created or received by the address deleted with their content (counted as `secrets` by the search and `secretsDeleted` by the erasure); invitations deleted or revoked; proofs naming the address deleted; the
  address replaced by a pseudonym in the audit log (decision P19). The
  erasure ends with an erasure report that can be kept as evidence.
- **What is kept on purpose**: blocklist entries, addresses in the allowed
  senders of an API token (edit the token), client IP addresses in the audit
  log until their 12 months end, emails already queued, and free text of
  other senders' transfers that mentions the person (until that transfer
  expires). Details: [administration guide](../operations/admin.md).
- The erasure is **per entity**: repeat it in each entity where the person
  appears.
- Access and portability: the controller extracts the data found by the
  search screen and the audit log, as no self-service exists for the people
  concerned. `<to be completed>` (internal procedure and contact)

## 11. Crypto-erasure and backups

On any deletion (expiry, manual deletion, erasure request), TransTeira
**destroys the key of each file** in the database before deleting the file
(cryptographic erasure), so a surviving copy of the encrypted file is
unreadable from the live system.

Limit to document: a database copy or VM backup taken **while the transfer
existed** still holds the wrapped key, and the current master key opens it.
Its files become unreadable only after a **master key rotation** and the
**destruction of the old key**, once every backup taken before the rotation
has expired. Rotate at least once per backup retention period; a deleted
transfer then stays recoverable from backups for about twice the retention
at most ([master key](../operations/master-key.md#crypto-erase),
[backup](../operations/backup.md), decision P25). State the retention you
apply: `<to be completed>`.

**One-time secrets (2.1).** A copy taken while a secret was live keeps its
sealed text, its wrapped key, its verifiers and its passphrase salt. With the
master key, what remains is the ciphertext made in the browser, protected
only by the key in the link fragment and by the passphrase: whoever holds
that copy, the master key and the link (an old e-mail, for an e-mailed
secret) can read a secret without a passphrase. Short durations, a
passphrase sent through another channel, and a master key rotation followed
by the destruction of the old key reduce this ([backup](../operations/backup.md#crypto-erase-and-copies),
data model D3, T-355, decision P71).

## 12. Security measures (article 32)

Summary; the full mapping is in the [ISO/IEC 27001 Annex A document](iso27001-annex-a.md).

- **Tenant isolation**: every record carries its entity; filtering in the data
  access layer and, with PostgreSQL, row-level security (T-74 to T-79).
- **Encryption at rest**: AES-256-GCM by chunks, one key per file wrapped by
  the master key; master key kept outside the data volume; rotation without
  rewriting files; optional end-to-end encryption in the browser; one-time
  secrets encrypted in the browser (the server never sees the content), read
  once, locked after 5 wrong passphrases.
- **Encryption in transit**: TLS at the reverse proxy (operator).
- **Access control**: administrators with argon2id password and mandatory
  TOTP for the super admin; optional OpenID Connect; delegated admins limited to
  their entities; read-only auditor role; API tokens hashed, per entity,
  revocable.
- **Verification of identity**: one-time code by email, rate limited;
  optional per-recipient verification.
- **Network**: no port published by the container, internal Docker network,
  trusted proxies, IP ranges per entity.
- **Antivirus** analysis of every file (ClamAV, ICAP or HTTP engine).
- **Minimisation and masking**: no file content or addresses in the security
  log; secrets hashed or sealed, never logged; tokens of the one-time secret
  links redacted in the proxy logs; statements without IP.
- **Traceability**: audit log, security log (fail2ban and CrowdSec), syslog
  export, metrics.
- **Resilience**: nightly database copy, documented restore.
- **Secure development**: tests, fuzzing, `govulncheck`, secret scanning,
  threat model; signed images with SBOM.

Organisational measures of the controller (policies, training, contracts,
physical security of the host): `<to be completed>`

## 13. Impact assessment (DPIA)

A data protection impact assessment is not systematically required for this
processing, but the controller decides according to the volume and the
sensitivity of the data it expects to transfer (for example health data on a
large scale). Decision and reference: `<to be completed>`. The
[threat model](../security/threat-model.md) can feed the risk analysis.

## 14. Personal data breaches

The controller's procedure for notifying the supervisory authority within
72 hours and, when needed, the people concerned: `<to be completed>`.
TransTeira provides the audit log, the security log, alerts by email and
webhook, and the [security policy](../../SECURITY.md) for vulnerability reports.

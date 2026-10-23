# Administration

This page covers the admin host, the first-run setup, admin accounts, the
second factor and how to recover access, then the daily operation of a
tenant: transfers, invitations, blocklist, API tokens, audit log, data
subject rights (GDPR) and statistics, and the instance settings of the
super admin: maintenance mode, disk alert and system SMTP server. Tenant
configuration and quota alerts are in [Tenants](tenants.md); the master key
rotation is in [Master key](master-key.md).

- Variables: `TT_ADMIN_HOSTS` (required), `TT_ADMIN_SESSION_IDLE_TIMEOUT`,
  `TT_ADMIN_SESSION_MAX_AGE`, `TT_SETUP_TOKEN` / `TT_SETUP_TOKEN_FILE`,
  `TT_API_DOCS_PUBLIC`, `TT_MAX_OPEN_TRANSFERS` (per API token),
  `TT_MAINTENANCE`, `TT_SYSTEM_SMTP_*`, see `.env.example`.
- Commands: `transteira admin list`, `transteira admin reset-totp <username>`,
  `transteira admin reset-password <username>`.
- Implementation: `internal/adminauth`, `internal/audit`,
  `internal/api/admin`, `internal/tenantops` (operations),
  `internal/apitoken` (API tokens),
  `internal/datasubject` (GDPR), `internal/stats` and `internal/usage`
  (statistics), `internal/maintenance`, `internal/systemsettings`,
  `internal/diskalert` (instance settings).
- Threat model: T-58 to T-73, T-102, T-104 to T-107, T-111, T-112, T-146
  to T-151, T-154 to T-158 in `docs/security/threat-model.md`.

## Admin host

The administration is served **only** on the host names listed in
`TT_ADMIN_HOSTS`, for example `admin.transfer.example.com`. It never answers
on a tenant FQDN (admin routes return 404 there), and the public deposit and
download pages never answer on the admin host. An admin host must not be a
tenant FQDN: TransTeira refuses to start if it is.

Configure the admin host in the reverse proxy like a tenant host (TLS
certificate, real client IP). You can restrict it further at the proxy, for
example to your internal networks or a VPN.

The admin host also serves the interactive API documentation at
`/api/docs`, generated in the browser from the OpenAPI specification and
embedded in the binary (no external resource). It requires an admin
session (401 otherwise). Set `TT_API_DOCS_PUBLIC=true` to also serve it,
without authentication, on the tenant FQDNs, for example for partners who
integrate with the API; the specification itself is always downloadable at
`/api/openapi.yaml`.

## First-run setup

While no admin exists, the setup creates the **super admin**. The web
pages arrive with the web interface; until then, the same steps are
available through the API (`/api/v1/admin/setup`, then
`/api/v1/admin/me/totp/confirm`, see `docs/api/`).

1. Open `https://<admin host>/admin/setup`.
2. Enter the setup token:
   - if `TT_SETUP_TOKEN` (or `TT_SETUP_TOKEN_FILE`) is set, use that value;
   - otherwise TransTeira generates a random token at each start and prints
     it once in the container logs (`docker logs transteira`). It is valid
     until the next restart.
3. Choose a username, an email address and a password (12 to 1024
   characters, no other rule).
4. Scan the QR code with an authenticator app (TOTP) and confirm with a
   code. **TOTP is mandatory for the super admin**: nothing else in the
   administration is usable before it is confirmed.
5. Write down the 8 recovery codes shown once, and keep them in your
   password vault.

Once an admin exists, the setup is closed for good and no token is printed
any more.

## Sessions

- Opaque server-side session in the `__Host-tt_admin` cookie (`Secure`,
  `HttpOnly`, `SameSite=Strict`), rotated after each authentication step.
- Expires after `TT_ADMIN_SESSION_IDLE_TIMEOUT` of inactivity (30 min by
  default) and at the latest after `TT_ADMIN_SESSION_MAX_AGE` (12 h).
- An intermediate step (password accepted, second factor or enrollment
  pending) expires after 5 minutes.
- Every state-changing request needs the CSRF token returned by the API and
  a same-origin request.

## Brute-force protection

- 5 failed logins for one username from one IP within 15 minutes lock that
  pair for 15 minutes; 20 failures from one IP lock the IP. There is no lock
  on a username alone, so nobody can lock the super admin out from
  elsewhere.
- Wrong second factors, including wrong TOTP enrollment confirmation
  codes, are counted per account as well (5 within 15 minutes lock the
  second factor for 15 minutes); only someone holding the password or a
  session can reach that lock.
- Every failure is written to the security log (`admin_login_failed`) and
  every lock as `rate_limited`, for fail2ban and CrowdSec
  (see [Security log](security-log.md)).

## Delegated admins

The super admin creates delegated admins and assigns them to one or more
tenants. The response contains an **activation link, shown once**: give it
to the new admin yourself, through a channel you trust (in person, your
messaging tool). TransTeira never mails it: a tenant's SMTP settings are
managed by that tenant's delegated admins, who could otherwise capture the
link of an account that also manages other tenants (threat model T-143).
The link is valid for 72 hours and works once; the token is in the URL
fragment, so it never reaches the server logs. The admin chooses a
password, then enrolls TOTP when it is required (the default).

A delegated admin only sees and manages their own tenants. Disabling an
account, changing its tenants or its role, or resetting its credentials
revokes its sessions and cancels a pending activation link. A delegated
admin can be promoted to super admin only once activated with TOTP
enrolled. The last usable super admin (password set, TOTP enrolled, not
disabled) cannot be deleted, disabled or demoted, and nobody can delete,
disable, demote or reset their own account. Keeping two super admins is
recommended.

## Changing the second factor

Enrolling or replacing TOTP from an authenticated session requires the
current password. Replacing an active TOTP (new phone) also revokes the
other sessions of the account; the new enrollment issues 8 new recovery
codes. A stolen session alone therefore cannot take over the second
factor. The new secret must be confirmed within 15 minutes, and wrong
confirmation codes count as wrong second factors (see above).

## Losing the second factor

In this order:

1. **Recovery code**: at the second-factor step, enter one of the 8 recovery
   codes instead of the TOTP code. Each code works once. The codes are
   stored as an HMAC keyed from the (sealed) TOTP secret, so a stolen
   database alone cannot be used to test them, and they remain valid
   across a master key rotation. Confirming a new
   TOTP enrollment issues 8 new codes and invalidates the old ones.
2. **Another super admin** can reset the credentials of any other admin
   (`reset-credentials`): password and TOTP are cleared, sessions revoked,
   and a new activation link is shown once, to be transmitted out of
   band.
3. **Local command**, when no other way is left (for example the only super
   admin lost both the TOTP device and the recovery codes). It must be run
   inside the container, so it requires access to the host:

   ```sh
   docker exec -it transteira transteira admin list
   docker exec -it transteira transteira admin reset-totp superadmin
   ```

   It clears the TOTP secret and the recovery codes of that account and
   revokes its sessions; the admin enrolls a new TOTP at the next login
   (the password is unchanged). The action is written to the audit log.
   Anyone who knows the password can enroll in the meantime: if the
   password may be compromised too, use `reset-password` instead.

## Losing the password

Another super admin resets the account as above. If you are the only super
admin, run inside the container:

```sh
docker exec -it transteira transteira admin reset-password superadmin
```

It clears the password, the TOTP and the recovery codes, revokes the
sessions and prints an activation link valid 72 hours, once. Open it to
choose a new password and enroll TOTP again. The action is written to the
audit log.

## Tenant operations

Every operation below is available to the super admin and to the delegated
admins attached to the tenant; a tenant the admin is not attached to
answers 404, like an unknown one. Reads (lists, details, audit log,
statistics) need access to the tenant; changes need the right to change it
and the CSRF token. Lists are newest first and paginated (`limit`, 50 by
default and at most 200, then `cursor` from `nextCursor`).

### Transfers

- **List** (`GET /admin/tenants/{tenantId}/transfers`): metadata only
  (sender, recipients, file count, size, options, dates, download count:
  distinct download starts, counted like `downloadCount` in
  [Statistics](#statistics)),
  filtered by `status`, by `email` (exact match on the sender **or** a
  recipient) and by `createdAfter`.
- **Detail** (`GET …/transfers/{transferId}`): the same, plus the sender's
  IP at creation (absent for transfers created before this version) and,
  for each file, its name, size, SHA-256 fingerprint and antivirus result.
  The content of a file is never accessible from the administration, and
  the download link is never shown.
- **Delete before expiry** (`DELETE …/transfers/{transferId}`, optional
  `reason`): the keys are destroyed first, then the files (crypto-erase);
  the transfer becomes `deleted`, its link answers 410 and its space is
  freed from the quota. A transfer still being scanned is withdrawn from
  the antivirus first: it never becomes available and its recipients are
  never notified. While an upload of the transfer is in progress, the
  deletion answers `409 state-conflict` with `Retry-After`: retry after the
  delay. Deleting a transfer already `expired` or `deleted` does nothing
  (204, no audit). Mails already queued or waiting for a retry (a
  notification, a resend) still go out; their link answers 410. The
  reason is recorded in the audit log with every mail
  address replaced by `[address]` and cut to 500 characters: do not write
  other personal data in it.
- **Resend the notification** (`POST …/transfers/{transferId}/resend`):
  only for an `available` transfer. Without a body it goes to every
  recipient; with `recipients`, every address must be an original
  recipient (you cannot add one). The mail carries the existing link,
  which is not rotated, so links already received keep working; you never
  see it. At most 5 resends per hour per transfer, whoever the admin (429
  beyond); without SMTP settings for the tenant, nothing is queued (503).

### Invitations

- **List** (`GET …/invitations`, filter `status`: `pending`, `used`,
  `expired`, `revoked`), with the issuer of each invitation. After a GDPR
  erasure of an issuer, `invitedBy` shows the pseudonym `erased-…`.
- **Revoke** (`DELETE …/invitations/{invitationId}`): a pending or used
  invitation (a used one remains usable until it expires) stops working at
  once, and the deposit sessions opened with it end. Revoking an invitation
  already revoked or expired does nothing (204, no audit).

### Blocklist

Entries of kind `email`, `domain` (without `@`, such as
`spam.example.net`) or `sha256` (64 hexadecimal characters, a file
fingerprint). Values are trimmed and lower-cased; a value already listed
for the same kind answers 409. A blocked address or domain cannot deposit;
a blocked fingerprint refuses the file at finalization. Adding or removing
an entry records `blocklist.updated`, with the value for a domain or a
fingerprint, never for an address (only its kind and identifier).

### API tokens

API tokens let scripts and third-party software deposit files without a
verification code (CLAUDE.md section 16.4). The integration side (scripts,
tus uploads, error handling) is described in
[`docs/api/integration.md`](../api/integration.md).

- **List** (`GET …/api-tokens`), for any admin attached to the tenant:
  name, prefix (`tt_` and 4 characters), allowed ranges, allowed senders,
  creator, creation,
  last use, expiry and revocation dates, revoked tokens included. The
  secret is never shown again.
- **Create** (`POST …/api-tokens`): a name (1 to 100 characters), the
  allowed IP ranges (`allowedCidrs`, 1 to 100 IPv4 or IPv6 CIDR prefixes,
  mandatory), the allowed senders (`allowedSenders`, optional, recommended,
  see below) and an optional expiry (`expiresAt`; none by default). The
  response holds the secret (`tt_` followed by 43 characters) **once**:
  TransTeira stores only its SHA-256 fingerprint. Give it to the person in
  charge of the script through a channel you trust, and never by mail in
  clear text.
- **Change** (`PATCH …/api-tokens/{tokenId}`, JSON Merge Patch): rename it
  or replace its allowed ranges or allowed senders (`[]` lifts the sender
  restriction); the secret does not change. The expiry
  cannot be changed: create a new token instead. A revoked token cannot be
  changed (409).
- **Revoke** (`DELETE …/api-tokens/{tokenId}`): effective on the next
  request, which gets `401 invalid-credentials`. An upload request already
  streaming is not cut: it goes on until its body ends or stalls
  (`TT_UPLOAD_IDLE_TIMEOUT`), after which the transfer can no longer be
  resumed or finalized. Expiry behaves the same way. Revoking a token
  already revoked does nothing (204, no audit). Transfers created by the
  token stay available to their recipients; one still uploading can no
  longer be finished and is cleaned up when its uploads expire.

Creating, changing and revoking a token need the right to change the
tenant and the CSRF token. A tenant the admin is not attached to, and a
token of another tenant, answer 404.

What a token can do, and the rules you choose for it:

- It is valid only on the FQDN of its tenant, never on another tenant's
  FQDN nor on the admin host, and only for deposits: create, follow,
  finalize or cancel a transfer, and upload its files. It never reaches the
  administration.
- **Allowed ranges.** Requests from any other client address get
  `403 ip-not-allowed` and a `deposit_refused reason="ip"` line in the
  [security log](security-log.md). List the exact addresses the scripts
  leave from (as seen behind the trusted reverse proxies); "any address" is
  possible only by listing both `0.0.0.0/0` and `::/0`, and then deserves
  an expiry date. The ranges of a token replace the internal IP ranges of
  the tenant for its deposits.
- **Sender.** Each deposit names its sender (`senderEmail`), which must
  belong to an internal domain of the tenant and is subject to the
  blocklist. That address receives the confirmation, the antivirus alerts
  and the download receipts.
- **Allowed senders.** Without `allowedSenders`, a token can deposit as
  any internal address: whoever holds it can make a transfer look as if it
  came from any colleague. Set it to the address (or addresses) the job
  really uses: up to 100 entries, each a full address
  (`reporting@entity-a.example.com`) or a domain (`entity-a.example.com`,
  which does not cover its subdomains). A deposit whose sender matches no
  entry gets `403 deposit-not-allowed` and a
  `deposit_refused reason="domain"` line in the security log; the rule is
  checked again at finalization against the current list. Leave the list
  empty only for software that genuinely deposits on behalf of many
  people, with narrow ranges.
- **Limits.** The per-transfer limit, the storage quota, the blocklist and
  the antivirus apply as for an internal user. The cap on unfinished
  transfers (`TT_MAX_OPEN_TRANSFERS`) counts per token.
- **Ownership.** A token sees only the transfers it created; no other
  token, and no deposit session, reaches them. In the transfer list and
  detail, such a transfer shows the origin `api` and the token identifier
  (`apiTokenId`).
- **Last use** (`lastUsedAt`) is updated at most once a minute per token.
  Review the list regularly and revoke the tokens nobody uses any more.
- **Invalid tokens.** A missing, unknown, revoked or expired token gets
  `401` and an `api_token_invalid` line in the security log; 10 invalid
  tokens from one client address within 10 minutes lock that address for
  15 minutes: further invalid tokens get `429`, while valid tokens keep
  working, so that a neighbour behind the same NAT cannot block your
  scripts. The lockout limits floods; the 256-bit secret is what makes
  guessing impossible.

Good practice: one token per application and per server, the narrowest
ranges, the allowed senders set, an expiry for anything temporary, and a yearly rotation (create,
deploy, check `lastUsedAt`, revoke the old one). If a secret may have
leaked, revoke the token first and investigate afterwards. After restoring
a database backup, review the tokens: see
[Backup and restore](backup.md#review-the-api-tokens).

## Maintenance mode

The maintenance mode refuses new deposits during an upgrade or an
intervention, for every tenant, while downloads, the health check and the
administration stay available.

**Two sources** turn it on:

| Source | How | Persistence |
|---|---|---|
| Environment | `TT_MAINTENANCE=true`, then restart | For the life of the process. It **always wins**: while it is set, the administration cannot turn the mode off (`409 state-conflict`). |
| Administration | `PUT /admin/system/maintenance` (**super admin only**, 403 for a delegated admin) with `enabled` and an optional `message` | Stored in the database: it **survives a restart** until the super admin turns it off. |

`GET /admin/system/maintenance` (any authenticated admin) shows `enabled`,
`source` (`environment`, `admin` or `none`), `adminEnabled` (the stored
choice of the super admin, also while the environment forces the mode),
`since` (for the environment: the start of the process) and the messages.
While `TT_MAINTENANCE` forces the mode, `enabled: true` is still accepted
(the messages are stored and the source stays `environment`).

**Messages.** `message` maps a supported language (`fr`, `en`) to the text
shown to depositors, for example:

```json
{ "enabled": true,
  "message": { "fr": "Mise à jour en cours, retour vers 20 h.",
               "en": "Upgrade in progress, back around 8 pm." } }
```

- Each request **replaces** the stored messages entirely; without
  `message`, there is none.
- Each value is **plain text** of 1 to 500 characters. Line feeds are
  allowed; other control characters, the Unicode line and paragraph
  separators (U+2028, U+2029) and the bidirectional control characters
  are refused (`400 validation-failed`, naming for example `/message/fr`).
  The text is never interpreted as HTML: the web interface shows it as
  text.
- Do not put tenant names or other confidential details in it: the same
  message is shown on every tenant.
- The message shown is the one in the language negotiated from the
  browser (`Accept-Language`), else in the tenant's default language, else
  in English, else in any language that has one.

**What is refused** while the mode is on, with `503` and
`Retry-After: 300` (the `maintenance` problem, whose `detail` carries the
message, see [errors](../api/errors.md#maintenance)):

- opening a deposit session (`POST /deposit-sessions`);
- creating a transfer (`POST /transfers`), by a depositor or an API token;
- sending upload chunks (tus `PATCH`, answered `503` without a body, with
  `Tus-Resumable` and `Retry-After`): uploads in progress pause and resume
  after the maintenance;
- finalizing a transfer (`POST /transfers/{id}/finalize`);
- creating an invitation (`POST /invitations`).

Everything else keeps working: downloads, the public tenant information
(`GET /tenant` reports `maintenance: true` and the `maintenanceMessage` for
the negotiated language), the administration and the health check
(`/healthz` keeps its status and reports `"maintenance": true`).

Every change by the super admin is audited (`maintenance.enabled` or
`maintenance.disabled`, object `system` / `maintenance`, with the list of
message languages only, never the text), in the same transaction as the
change.

## System settings and disk alert

`GET` and `PATCH /admin/system/settings` (**super admin only**; `PATCH` is a
JSON merge patch, `application/merge-patch+json`) hold two settings:

| Setting | Rule |
|---|---|
| `diskAlertThreshold` | Share of the disk holding the data directory that raises the disk alert, from `0.50` to `0.99` (rounded to 0.0001). Default `0.85`. |
| `alertEmail` | Optional address that receives the disk alert in addition to the super admins: a bare address (no display name). `null` removes it. It receives the alert in the language of the admin who set it. It is **not verified** (no code is sent to it): check it carefully, since a typo sends the alerts (disk figures and the administration URL, at most one mail per hour) to whoever owns that address. |

Each change is audited as `config.updated` (object `system` / `settings`)
with the **names** of the changed fields only, never the address: watch
these events, since changing `alertEmail` redirects the alerts.

**Disk alert.** TransTeira measures the filesystem of `TT_DATA_DIR` at
start-up, every 5 minutes and right after a change of the settings:

- when the used share reaches the threshold, the alert is **raised**: a
  warning in the application log, the audit event `disk.alert_raised`
  (system actor `disk`, details `usedPercent` and `thresholdPercent`) and,
  if the [system SMTP server](#system-smtp-server) is configured, a mail to
  every super admin that can sign in (enabled and activated), in their own
  language, and to `alertEmail`, duplicates removed;
- it is sent **once per crossing**: the alert level is stored in the
  database, so a restart or concurrent evaluations never send it again
  while the level stays raised;
- the alert mails are **at least one hour apart**, whatever the number of
  crossings: a crossing within the hour of the last mail (for example a
  threshold toggled back and forth) is still logged and audited
  (`disk.alert_raised`), but not mailed (log line `disk alert not mailed:
  an alert mail was sent less than an hour ago`). The time of the last mail
  is stored in the database, so a restart keeps the interval;
- it **clears** once the usage falls 5 points below the threshold (for
  example under 80 % with the default 85 %): audit event
  `disk.alert_cleared`, no mail. The next crossing raises it again;
- lowering the threshold below the current usage raises the alert at once;
- a failure to measure the disk is logged once (and once when the measures
  recover); the level is left as is.

The global statistics (`GET /admin/system/stats`) show the disk figures,
the threshold, `alertActive` (alert raised) and `alertMailConfigured`
(system SMTP server configured). Without system SMTP, the alert is only
visible there, in the audit log and in the application log: configure it.

## System SMTP server

The disk alert concerns the whole instance, so it is not sent through the
SMTP server of a tenant: it uses a **system SMTP server** configured by
environment variables (see `.env.example` for every rule):

| Variable | Role |
|---|---|
| `TT_SYSTEM_SMTP_HOST` | Server name or IP address. Empty (default): system mail is disabled, and the other variables below (except the security mode and sender name) are refused. |
| `TT_SYSTEM_SMTP_PORT` | Default 25 with `none`, 587 with `starttls`, 465 with `tls`. |
| `TT_SYSTEM_SMTP_SECURITY` | `starttls` (default), `tls` (implicit TLS) or `none` (an unauthenticated relay on the internal network only). |
| `TT_SYSTEM_SMTP_FROM`, `TT_SYSTEM_SMTP_FROM_NAME` | Sender address (required) and display name (default `TransTeira`). |
| `TT_SYSTEM_SMTP_USERNAME`, `TT_SYSTEM_SMTP_PASSWORD_FILE` | Credentials, both or neither; refused with `none`. |

- The password is **only read from a file**, such as a Docker secret. The
  file must be an absolute path **outside** the data, backup and log
  volumes and the database folder, like the master key; trailing line
  breaks are removed. `TT_SYSTEM_SMTP_PASSWORD` is not supported: setting
  it stops the start-up, so that the password never appears in the
  environment (`docker inspect`). The password is never logged.
- As an installation setting, the system server may be a relay on
  loopback or on the internal Docker network: `TT_SMTP_DENY_NETWORKS`,
  which protects the SMTP servers typed by tenant admins, does not apply.
- An invalid configuration stops the start-up.
- System mails have their own small queue, separate from the tenant mails.

Example with an authenticated server and a Docker secret:

```yaml
services:
  transteira:
    environment:
      TT_SYSTEM_SMTP_HOST: smtp.example.com
      TT_SYSTEM_SMTP_SECURITY: starttls
      TT_SYSTEM_SMTP_FROM: transteira@example.com
      TT_SYSTEM_SMTP_USERNAME: transteira@example.com
      TT_SYSTEM_SMTP_PASSWORD_FILE: /run/secrets/transteira_system_smtp_password
    secrets:
      - transteira_system_smtp_password

secrets:
  transteira_system_smtp_password:
    file: /opt/secrets/transteira/system_smtp_password
```

With an unauthenticated relay on the internal Docker network (for example a
relay to Microsoft Graph), set only `TT_SYSTEM_SMTP_HOST` (the relay
container name), `TT_SYSTEM_SMTP_SECURITY: none`, `TT_SYSTEM_SMTP_PORT` and
`TT_SYSTEM_SMTP_FROM`. As for the tenants, the sender domain needs SPF,
DKIM and DMARC.

## Audit log

Entries are kept 12 months, then purged by the cleanup task. There is no
way to edit or delete them through the application; the only change ever
made is the replacement of an address by a pseudonym during a GDPR erasure
(see below).

### Reading an entry

Each entry has its time, its tenant (`null` for instance-wide events), its
actor, the client IP, its action, its object (kind and identifier) and
optional details.

| Actor kind | `id` holds |
|---|---|
| `admin` | the admin's username |
| `depositor` | the depositor's mail address, or the pseudonym after an erasure |
| `recipient` | `link` for a download through the shared transfer link |
| `api_token` | the token's identifier |
| `system` | the name of a component (for example `lifecycle`) |

Details never hold a secret nor a mail address: TransTeira refuses to write
them. They carry identifiers and counts (for example `fileCount`,
`totalBytes`, `recipientCount`).

### Actions

| Area | Actions |
|---|---|
| Admin accounts and sign-in | `setup.completed`, `admin.login`, `admin.login_failed`, `admin.logout`, `admin.totp_enrolled`, `admin.totp_disabled`, `admin.recovery_code_used`, `admin.password_changed`, `admin.created`, `admin.updated`, `admin.deleted`, `admin.credentials_reset`, `admin.activated`, `admin.totp_reset_local`, `admin.password_reset_local` |
| Tenant configuration | `tenant.created`, `tenant.updated`, `tenant.branding_updated`, `tenant.asset_uploaded`, `tenant.asset_deleted`, `tenant.network_updated`, `tenant.smtp_updated`, `tenant.template_updated`, `tenant.template_reset`, `tenant.legal_updated`, `tenant.deletion_started`, `tenant.deleted` |
| Transfers | `transfer.created`, `transfer.finalized`, `transfer.downloaded` (start of a file or archive download, never HEAD requests or resumed ranges; details: the file ID or `archive`), `transfer.deleted` (admin, with the redacted reason), `transfer.notification_resent` (number of recipients only) |
| Invitations and addresses | `invitation.created`, `invitation.used`, `invitation.revoked`, `address.verified` |
| Antivirus | `file.infected` (signature name), `file.not_scanned` (reason `too_large` or `encrypted`) |
| Quotas | `quota.warning` (80 %), `quota.reached` (100 %), see [Tenants](tenants.md#quota-alerts) |
| Blocklist | `blocklist.updated` (`op`, `kind`, `entryId`, and the value for a domain or a fingerprint) |
| API tokens | `api_token.created`, `api_token.updated`, `api_token.revoked` (by an admin; object: the token, never its secret), `api_token.used` (once per transfer created with the token; actor: the sender address, as a `depositor`, so a GDPR erasure of that address pseudonymises it; object: the token) |
| Data subject rights | `data_subject.searched`, `data_subject.erased` (counts only; object: the pseudonym) |
| Instance (no tenant) | `maintenance.enabled`, `maintenance.disabled` (message languages only), `config.updated` (system settings: names of the changed fields only), `disk.alert_raised`, `disk.alert_cleared` (system actor `disk`), `master_key.rotation_started`, `master_key.rotation_completed`, `master_key.rotation_failed` (see [Master key](master-key.md#audit)) |

The list is extensible: later versions add actions. A filter on an action
of the right form that does not exist yet simply returns nothing.

### Filters

- **Tenant log** (`GET /admin/tenants/{tenantId}/audit-events`), for any
  admin attached to the tenant: `action`, `actor` (a mail address or an
  admin username, exact match), `from` and `to` (both inclusive). It only
  ever shows events of that tenant, never instance-wide ones.
- **Instance log** (`GET /admin/system/audit-events`), **super admin
  only** (403 for a delegated admin): every tenant plus the events without
  tenant (setup, admin accounts…); with `tenantId`, only that tenant (the
  events without tenant are then excluded). Filter: `action`.

To follow one person, filter on their address as `actor`; after an
erasure, filter on the pseudonym shown as the object of the
`data_subject.erased` entry.

## Data subject rights (GDPR)

An admin who can change the tenant can search for and erase the data linked
to a mail address (CLAUDE.md section 20). The address is sent in a POST
body, never in a URL, and is never written to the audit log.

**Only the tenant you work in is affected.** The same person in another
tenant is neither counted nor erased: repeat the procedure in each tenant
concerned (the super admin has access to them all).

### Procedure

1. **Search** (`POST /admin/tenants/{tenantId}/data-subjects/search`): it
   counts the verified address record, the transfers sent and received,
   the invitations and the audit entries of that address. The security log
   never records addresses, so it always counts 0. The search is audited
   (`data_subject.searched`, without the address).
2. **Erase** (`POST …/data-subjects/erase`): it returns a report with the
   counts of what it did, and is audited as `data_subject.erased`, without
   the address (its object is the pseudonym).
3. If the erasure answers **`409 state-conflict`** (an upload of one of the
   address's transfers is in progress, or a deposit was just started with
   one of its invitations), what was already erased stays erased: call it
   again after `Retry-After` seconds. Every step can be replayed, so a
   repeated or interrupted erasure is simply completed.

### What is erased

- Verification codes, deposit sessions (an open session ends at once) and
  the verified address record, first, so that the address cannot start a
  new deposit meanwhile.
- Transfers sent by the address, and those deposited through an invitation
  of which it is the invitee: crypto-erased (keys, then files) and their
  rows deleted, whatever their status.
- Transfers it received: the address is removed from the recipients; a
  transfer left without any recipient is crypto-erased and deleted. A
  transfer still being scanned is held away from the antivirus meanwhile,
  so it never mails the erased address: if its analysis concluded during
  the erasure, its notification mails are held back and sent afterwards,
  from the transfer as it then stands, to the remaining recipients only.
- Invitations of which it is the invitee: deleted. Invitations it issued:
  revoked, and their issuer replaced by the pseudonym.
- Audit log: wherever the address is the actor (as a depositor or a
  recipient), it is replaced by the pseudonym. Nothing else in the entry
  changes.

### The pseudonym

`erased-` followed by 16 hexadecimal characters: an HMAC-SHA256 of the
address keyed with a random value drawn for this erasure and then
discarded. It groups the entries of one person within one erasure, but the
address cannot be recovered from it, and a second erasure of the same
address gives another pseudonym.

### What is kept, and the limits

- **Blocklist entries**, so that an erasure never unblocks an abuser.
- **Addresses listed in an API token's `allowedSenders`**: admin
  configuration, kept like the blocklist; remove them by updating the token
  if the person must no longer be allowed as a sender.
- **Client IP addresses** in the audit log, until their 12-month retention
  ends (legitimate security interest), now attached to the pseudonym.
- **Mails already queued** for sending still go out: a notification, a
  confirmation or a resend already handed to the mail queue, or waiting in
  the retrier after a refusal (retried for up to the retry period), is not
  withdrawn and its retries do not check the erasure again. The person may
  so still receive a mail sent just before the erasure; its link is dead
  (410) once the transfer is erased, and its files unreadable (keys
  destroyed).
- **Messages and file names of other senders' transfers.** The free-text
  message and the file names of a transfer sent by someone else (to the
  person, or merely mentioning them) are not analysed and are kept until
  that transfer expires or is deleted; delete such a transfer from the
  transfer list if needed.
- **Application logs**: the mail queue logs recipients only as a short
  HMAC-SHA256 hash keyed with a random value drawn at each process start
  and never stored. Entries can be correlated within one run of the
  process only, and the hash cannot be recomputed from the address once
  the process has stopped. The security log holds no address.
- **Backups** (VM, nightly database copies, `pg_dump`) still hold the
  metadata (addresses, file names) until they expire. The files they hold
  become unreadable once their keys are destroyed, subject to the master
  key rotation advice in [Master key](master-key.md) (threat model T-109).
- With PostgreSQL, deleted rows remain on disk until `VACUUM`; with
  SQLite, TransTeira scrubs the database once at the end of the erasure.
- Statistics are daily counters without personal data and are not changed.

## Statistics

`GET /admin/tenants/{tenantId}/stats` (any admin attached to the tenant)
and `GET /admin/system/stats` (super admin only, 403 otherwise), with
`period` = `7d`, `30d` (default) or `12m`.

| Figure | Definition |
|---|---|
| `transferCount`, `bytesUploaded` | Transfers **finalized** during the period and their declared size, whatever happened to them afterwards (deleted, expired, rejected). |
| `downloadCount` | Distinct download **starts** during the period: a file read from its first byte (whole, or a range starting at 0), or the archive. HEAD requests and resumed ranges are not counted. Repeated starts of the same file (or of the archive) of a transfer by the same client (IPv4 address, or IPv6 /64) count once per hour, and at most 1,000 starts of one transfer count per hour whatever the clients; the same rule applies to the `transfer.downloaded` audit events and to the download count of each transfer. |
| `bytesDownloaded` | Plaintext bytes actually served to recipients during the period, counted exactly (not deduplicated). |
| `virusDetections` | Files found infected during the period. |
| `storageUsedBytes`, `storageQuotaBytes`, `storageUsedRatio` | Current values, not limited to the period: declared size of the transfers uploading, scanning or available, against the quota (the ratio may exceed 1). |
| `series` | One point per UTC day for `7d` and `30d` (today included), one per calendar month for `12m` (the current one included, dated on the 1st); days without activity are present with zeros. |

The global statistics add the disk holding the data directory (total, used
= total − free, ratio, the alert threshold of the
[system settings](#system-settings-and-disk-alert), `alertActive` and
`alertMailConfigured`) and one row per active tenant (tenants being
deleted are excluded).

The counters are daily aggregates per tenant, without personal data, kept
13 months. They are accumulated in memory and written every 30 seconds, so
the last seconds of activity may be lost if the process stops abruptly:
statistics are indicative, not a billing record. Transfers finalized
before this version are counted from the migration; past downloads are not
known and start from zero. The deduplication of download starts is kept in
memory (at most 100,000 entries, the oldest forgotten first): after a
restart, a start may be counted once more. Whatever the clients, at most
1,000 starts of one transfer are counted per hour (a window opened at the
first one), so that a client cycling many addresses cannot inflate the
counts.

On a normal stop (`docker compose stop`, SIGTERM), TransTeira shuts down
in stages, each with its own budget, so that the whole fits within
Docker's default 10 s stop grace period:

| Stage | Budget |
|---|---|
| HTTP server: stop accepting, cancel the requests in progress (uploads and downloads stop and can be resumed), wait for the connections to go idle, then close those still open (logged) | 5 s (`ShutdownTimeout`) |
| Wait for the handlers to return | 1 s |
| Background workers: antivirus, download mail retries, cleanup task, quota monitor, disk alert monitor, master key rotation worker (stopped at its current batch, resumable) | 1 s (`BackgroundCloseTimeout`) |
| Final flush of the usage counters, hand-over of the queued admin and system mails | 1 s (`FinalCloseTimeout`) |
| Delivery of the mails still queued, tenant and system queues in parallel (the rest is dropped and logged) | 1 s |

The worst case is 9 s, after which the database is closed cleanly. The
only exception is a master key rotation worker still stopping: the master
keys are destroyed only once it has stopped, even past the budget (a
warning is logged), so that a rotation never sees its keys disappear. Keep
`stop_grace_period` at 10 s or more: a shorter one lets Docker kill the
process before the final flush.

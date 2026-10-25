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
  `internal/diskalert` (instance settings); web interface in
  `web/src/admin` (see `web/README.md`).
- Threat model: T-58 to T-73, T-102, T-104 to T-107, T-111, T-112, T-146
  to T-151, T-154 to T-158, T-162 to T-166 in
  `docs/security/threat-model.md`.

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

While no admin exists, the setup creates the **super admin**, through the
web interface. The same steps are also available through the API
(`/api/v1/admin/setup`, then `/api/v1/admin/me/totp/confirm`, see
`docs/api/`).

1. Open `https://<admin host>/admin/` (for example
   `https://admin.transfer.example.com/admin/`; `/` on the admin host
   redirects there). While no admin exists, every page of the
   administration leads to the setup screen (`/admin/setup`).
2. Enter the setup token:
   - if `TT_SETUP_TOKEN` (or `TT_SETUP_TOKEN_FILE`) is set, use that value;
   - otherwise TransTeira generates a random token (`stp_…`) at each start
     and writes it once to the application log, in a warning that also
     gives the setup address:

     ```sh
     docker logs transteira 2>&1 | grep "Setup token"
     ```

     It is valid until the next restart.

   A wrong token is reported on its field and written to the security log
   as a failed login (`admin_login_failed`, reason `setup_token`); repeated
   attempts are rate limited (`429`), and the screen then counts down
   before the next try.
3. Choose a username, an email address (it receives the super admin
   alerts, such as the disk alert) and a password (12 to 1024 characters,
   no other rule).
4. Scan the QR code with an authenticator app (TOTP), or type the setup key
   shown below it (grouped by 4 characters, with a copy button), then
   confirm with a 6-digit code. **TOTP is mandatory for the super admin**:
   nothing else in the administration is usable before it is confirmed.
5. The **8 recovery codes are shown once**. Copy them or download them as a
   `.txt` file, store them in your password vault (not next to the
   authenticator), then tick "I have saved these recovery codes in a safe place" to
   continue. They are
   never shown again; a new TOTP enrollment issues new ones.

**Confirm the TOTP code (step 4) within 5 minutes** of submitting the form:
until the code is confirmed, the session is only an intermediate sign-in
step, which the server ends 5 minutes after it began (the pending TOTP secret
itself stays valid for 15 minutes, which only matters when the enrollment is
restarted from a full session, for example from the account page). This step
only lives in the page (nothing is stored in the browser): reloading the page
or waiting too long brings you back to the sign-in screen; sign in with the
username and password you just chose, and the enrollment starts again.

The recovery codes (step 5) are shown **after** the confirmation, once the
session is complete, so this step has no 5-minute limit (only the usual idle
timeout of the session). The codes, however, only live in the page: reloading
it or leaving it signs you straight in and the codes are gone for good (a new
TOTP enrollment from the account page issues new ones). The screen therefore
warns and asks for a confirmation before you leave it.

Once an admin exists, the setup is closed for good and no token is printed
any more; `/admin/setup` then leads to the sign-in screen.

## Sessions

- Opaque server-side session in the `__Host-tt_admin` cookie (`Secure`,
  `HttpOnly`, `SameSite=Strict`), rotated after each authentication step.
- Expires after `TT_ADMIN_SESSION_IDLE_TIMEOUT` of inactivity (30 min by
  default) and at the latest after `TT_ADMIN_SESSION_MAX_AGE` (12 h).
- An intermediate step (password accepted, second factor or enrollment
  pending) expires 5 minutes after it began; a pending TOTP secret can be
  confirmed for 15 minutes.
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

## Web administration

The administration is a web application served under `/admin/` on the
admin host. It only talks to the REST API, so everything below can also be
done through the API (`docs/api/`). Pages are never cached (`no-store`) and
nothing but the chosen interface language is stored in the browser.

### Signing in

1. Open `https://<admin host>/admin/`. Without a session, any page leads to
   the sign-in screen and comes back to it once signed in (only paths of
   the administration are accepted as return address).
2. Enter the username and password. The message is the same whatever was
   wrong, so it never tells whether an account exists.
3. Enter the 6-digit code of the authenticator app, or choose **Use a recovery
   code** and type one of the recovery codes (each works once). The screen
   shows the attempts left after a wrong code. An account that must enroll
   TOTP is taken to the enrollment instead (QR code, then recovery codes).

The second step must be completed within **5 minutes**; reloading the page
returns to step 1. After 5 failed logins (or wrong second factors) the
server locks the attempt for 15 minutes, as described in
[Brute-force protection](#brute-force-protection), and the screen shows a
countdown. When the session expires, the next action brings you back to
the sign-in screen with a message; unsaved changes on the current page are
lost. **Sign out** (main navigation) closes the session on the server and clears
everything the page held in memory.

### Activation links

Creating a delegated admin (**Administrators**, then **Create an
administrator**) or resetting
an account's credentials shows its **activation link once**, with its
expiry date (72 hours) and a copy button. TransTeira never emails it: hand
it over yourself through a channel you trust (see
[Delegated admins](#delegated-admins)). The page asks for a confirmation if
you leave before pressing "I have handed over the link"; once you leave,
the link cannot be displayed again, and the only way to get a new one is a
new credentials reset.

The new admin opens the link (`https://<admin host>/admin/activate#act_…`).
As soon as the page loads, before the application starts, the token is
removed from the address bar and the browser history; the page then asks for a password and, when required (the default), a TOTP
enrollment followed by the recovery codes. A used, expired or cancelled
link shows "invalid link": ask the super admin for a new one.

### My account

**My account** (main navigation) shows the profile (username, email address,
role, tenants, two-factor status) and offers:

- **Change password**: requires the current password; the other sessions
  of the account are closed, this one stays open.
- **Change authentication device**: requires the current password, then a new
  QR code to confirm and **new recovery codes** (the old ones stop
  working). Replacing an active TOTP closes the other sessions.
- **Disable two-factor authentication**: offered to a delegated admin only,
  after confirmation with the current password. The server refuses it when
  the super admin made TOTP mandatory for the account (the default), and
  the super admin can never disable it.

**Interface language**: the language switch in the footer applies to the
administration and is remembered in this browser only (`localStorage`,
`tt.lang`). Without a stored choice, the language of the admin profile is
used, then the browser languages, then English. The API has no endpoint to
change the language of an admin profile yet, so the choice does not follow
the admin to another browser.

### Tenant configuration

**Entities** lists the tenants visible to the admin (name, FQDN, status,
storage used, language); a delegated admin attached to a single tenant goes
straight to it. The super admin creates tenants (**Create an entity**: name,
FQDN, language, quota and size limits; a FQDN already used or equal to an
admin host is refused on its field). Each tenant has the following
screens; what each setting does and who may change it is described in
[Tenants](tenants.md):

| Screen | Content |
|---|---|
| General | name, FQDN, default language, quota, ceiling and limit per transfer (a delegated admin only changes the language and the limit, up to the ceiling); deletion by the super admin, who must type the tenant name |
| Branding | colours with a live contrast check (the server's contrast warnings are shown but do not block), logo and background image (PNG, JPEG or WebP; 5 MiB and 10 MiB), with the stored image and a preview of the chosen one |
| Network | internal IP ranges (CIDR) and internal mail domains, one per line, with an error per line and the list as normalised by the server; warnings for an empty list (nobody is internal) and `0.0.0.0/0` (everybody is) |
| SMTP | server, port and security, optional username, password kept, replaced or removed (it must be typed again when the server, port or username changes), test email and SPF / DKIM / DMARC check |
| Mail templates | one entry per template and language, marked when customised; editor with variable buttons (required variables flagged), line and column of server errors, preview, save and reset to the default |
| Legal texts | legal notice and privacy policy per language, in Markdown, with a preview rendered by the server; saving an empty text deletes the document |

A tenant outside the admin's scope shows "not found". Leaving a screen with
unsaved changes asks for a confirmation.

The template preview shows the structure and content of the email as the
server renders it, with its links disabled. For the preview only, the
server removes the inline styles (of the default and customised templates
alike) and replaces the images, such as the QR code, by their description:
the administration's Content Security Policy would block them. The email
itself keeps its styles and images.

### Admin accounts

**Administrators** is reserved to the super admin: the list of accounts with their
role, status and tenants, the creation of delegated admins (tenants to
attach, TOTP required by default, then the activation link), and for each
account: change of email address, tenants, TOTP requirement, promotion to
super admin (only for an activated account with TOTP) or demotion,
disabling, **credentials reset** (new activation link) and deletion. On
your own account, the role change, disabling, reset and deletion are not
offered (use **My account** instead), and the last usable super admin is
protected as described in [Delegated admins](#delegated-admins).

## Operating tenants in the web interface

The screens below use the operations described in
[Tenant operations](#tenant-operations), [Audit log](#audit-log),
[Data subject rights](#data-subject-rights-gdpr) and
[Statistics](#statistics); the rules (who may do what, limits, what is
audited) are the same and are not repeated here.

### Dashboard

The home page depends on the role:

- **Super admin**: a **Maintenance mode** card (on or off, with its start
  date and the mention "forced by the environment" when it applies, and a
  link to the maintenance screen), a **Disk** card (see
  [System overview](#system-overview)) and the table of all tenants (name,
  FQDN, status, storage used against the quota), loaded page by page, with
  a link to the full **Entities** list.
- **Delegated admin**: one card per attached tenant with the transfers and
  the volume uploaded over the last 30 days, the current storage level and
  quick links to its transfers, audit log and statistics. The cards load
  independently (at most 4 requests at once); a card that fails shows its
  own message and a **Try again** button. An admin attached to no tenant
  is told to ask a super admin.

Both see a recommendation to enable two-factor authentication while it is
off on their account.

### Tenant navigation

The sub-navigation of a tenant has two groups: **Configuration** (General,
Branding, Network, SMTP, Mail templates, Legal texts, see
[Tenant configuration](#tenant-configuration)) and **Operations**
(Transfers, Invitations, Blocklist, API tokens, Audit log, Statistics,
Personal data).

The filters of the lists (transfers, invitations, blocklist, audit log)
and the period of the statistics are kept in the page address, so a
filtered view can be bookmarked and the back button restores it. Lists are
newest first; **Load more** fetches the next page.

### Transfers screen

- **Filters**: status, email address (exact match on the sender or a
  recipient) and creation day (**Created from**, that day included).
- **Detail**: status, dates, download count, sender and sender IP, origin
  (internal user, external guest or API token, with the invitation or
  token), options, recipients and, for each file, name, size, type,
  SHA-256 fingerprint (with a copy button) and antivirus result: waiting
  for scan, being scanned, clean, infected (file erased), not scanned
  because too large, not scanned because encrypted, or scan failed (file
  withheld). A status unknown to the interface is shown as is. A link
  opens the audit log from the day the transfer was created (the transfer
  identifier appears in the Object column).
- **No download link and no file content** are ever shown to an admin.
- **Resend the notification** (available transfers only): choose the
  recipients (all by default; no address can be added). At most **5
  resends per hour per transfer**; beyond, the screen shows the remaining
  wait. Without an SMTP server for the tenant nothing is sent, and the
  screen links to the SMTP settings.
- **Delete the transfer** (before it expires), after confirmation, with an
  optional reason recorded in the audit log (mail addresses typed in it
  are replaced by `[address]`). The keys are destroyed (crypto-erase), so
  the files become unreadable, backups included, and the link stops
  working. While an upload is in progress, the screen asks to retry after
  the delay given by the server.

### Invitations screen

Filter by status (pending, used, expired, revoked). The issuer of each
invitation is shown, or "Erased address" after a GDPR erasure of the
issuer. **Revoke** is offered for a pending or used invitation that has
not expired; after confirmation it stops working at once.

### Blocklist screen

Filter by kind, add an entry (kind, value, optional comment) and remove
one after confirmation. The kinds are **email address**, **domain** (without
`@`, such as `spam.example.net`: the addresses of that domain are
blocked) and **SHA-256 digest** (64
hexadecimal characters). The screen normalises the value before sending
it: addresses and digests are lower-cased, domains lower-cased and
converted to punycode (a trailing dot is refused, with the name without it
suggested); the server checks again and has the final word. A value
already listed for the same kind is reported on the value field. Do not
write personal data you do not need in the comment.

### API tokens screen

- **List**: name, prefix, allowed ranges, allowed senders ("any address of
  the internal domains" when the list is empty), creation (date and
  admin), last use, expiry and status (active, expired, revoked); active
  tokens first. The last use is recorded at most once a minute per token,
  so it may lag behind by up to a minute.
- **Create a token**: name, allowed ranges (one per line), allowed senders
  (one address or domain per line) and an optional expiry day (the token
  stops at the end of that day, in your local time). **Allow any address**
  adds `0.0.0.0/0` and `::/0` to the ranges and shows a warning: prefer
  narrow ranges, or at least set an expiry. An empty sender list lets the
  token deposit as any internal address, which the form points out (see
  [API tokens](#api-tokens) for the semantics).
- **The secret is shown once**, in a dialog that closes only once the
  secret has been copied successfully or the admin confirmed storing it
  (**I have stored this secret**); leaving the
  page before that asks for a confirmation. It is never shown again: hand
  it over through a channel you trust, never by mail in clear text.
- **Edit** changes the name, ranges and senders (the secret and the expiry
  do not change). **Revoke** asks you to type the token name; a revoked
  token can no longer be edited.

### Audit log screen

- **Filters**: action, chosen in a list grouped by area (transfers,
  invitations and addresses, antivirus, quotas, blocklist, API tokens,
  personal data, entity configuration) or typed as a code (**Other
  action**, form `domain.verb`, for example an action added by a later
  version). Administrator sign-in and account actions, and instance
  actions (maintenance, settings, disk alert, master key rotation), are
  recorded without a tenant and never appear in a tenant audit log, so
  they are not listed; actor (exact address or admin
  username); period (**From** and **To**, both days included, in your
  local time).
- Each row shows the date, the actor (a pseudonym `erased-…` is labelled
  as an erased address), the action, the object (a transfer links to its
  detail), the IP and the details. Details are shown as plain text pairs,
  never interpreted as HTML.
- There is **no export** in V1: the export of the audit and security logs
  to a SIEM through syslog comes with V1.1.

### Statistics screen

Choose the period (last 7 days, 30 days, the default, or 12 months). The
screen shows the key figures (transfers deposited, volume deposited,
downloads, volume downloaded, virus detections, highlighted when at least
one), the current storage level and two bar charts (transfers and volume
per day, or per month for 12 months), each with a table of its values.
The figures are indicative: the counters are written about every 30
seconds (see [Statistics](#statistics) for their definitions).

The storage level, here and on the dashboard, reads for example
"12 GiB of 100 GiB (12 %)" with a badge: normal, **warning from 80 %**
of the quota (the preventive alert threshold) and **full from 100 %**
(new deposits are refused). The level is always written out, never shown
by colour alone.

### Personal data screen

The **Personal data** screen applies the
[data subject rights procedure](#data-subject-rights-gdpr) to the current
tenant only:

1. **Search** an address: the screen lists what is held (verified address
   record, transfers sent and received, invitations, audit entries). The
   security log never records addresses, so it is not counted.
2. **Erase all data**: the confirmation lists what is erased and what is
   kept on purpose (see
   [What is kept, and the limits](#what-is-kept-and-the-limits)), and asks
   you to type the exact address.
3. The **erasure report** gives the counts and links to the audit log
   filtered on `data_subject.erased`, whose object is the pseudonym that
   replaced the address.

The address only travels in POST bodies: it never appears in the page
address, the browser storage or a screen reader announcement, and the
address and results are forgotten when you leave the screen.

## System in the web interface

The **System** entry of the main menu is shown to the **super admin
only**. Its sub-navigation has five screens: **Overview**, **Maintenance**,
**Settings**, **Audit log** and **Master key**. A delegated admin has no
**System** entry, and the `/system` addresses show "page not found" (the
server also answers `403` to the underlying calls, except
`GET /admin/system/maintenance`, readable by every admin for the
maintenance banner). The screens use the
operations described in [Maintenance mode](#maintenance-mode),
[System settings and disk alert](#system-settings-and-disk-alert),
[Audit log](#audit-log), [Statistics](#statistics) and
[Master key](master-key.md); the rules are not repeated here.

### Super admin dashboard

The home page of the super admin starts with two cards, above the tenant
table:

- **Maintenance mode**: on or off, with the start date and "(forced by the
  environment)" when `TT_MAINTENANCE=true` imposes it, and a link to the
  maintenance screen.
- **Disk**: the disk meter, the alert threshold and the alert state, as on
  the [System overview](#system-overview), and a short warning when the
  alert is not sent by mail. The card loads on its own (from the global
  statistics); if it fails, it shows its message and a **Try again**
  button without affecting the rest of the page.

### System overview

- **Period**: last 7 days, 30 days (the default) or 12 months, kept in the
  page address like the tenant statistics.
- **Data disk**: a meter of the space used on the filesystem of
  `TT_DATA_DIR` ("120 GiB of 500 GiB (24 %)"), whose warning colour starts
  at the **configured alert threshold** (not at 80 % as for the tenant
  quotas), the threshold itself ("Alert threshold: 85 %") and a written
  badge **Alert active** or **No alert** (the only state badge of the disk,
  so that it never contradicts a quota-style level). The alert is raised
  at the threshold and cleared 5 points below it.
- **Alert mail not configured**: when no
  [system SMTP server](#system-smtp-server) is configured, a prominent
  warning says that the disk alert is only visible on this page, in the
  audit log and in the application log. To receive it by mail, set
  `TT_SYSTEM_SMTP_HOST`, `TT_SYSTEM_SMTP_FROM` and the related variables
  (see `.env.example`) and restart: the super admins then receive it, and
  an additional alert address can be set in the
  [settings](#system-settings-screen).
- **Entities**: one row per active tenant, with its name (link to the
  tenant), the transfers and the volume uploaded over the period, and its
  storage level ("12 GiB of 100 GiB (12 %)" with a written badge, warning
  from 80 % of the quota, full from 100 %).
- The figures are indicative: the counters are written about every 30
  seconds.

### Maintenance screen

- **Current state**: on or off, the **source** (none, environment
  `TT_MAINTENANCE=true`, or turned on in the administration) and the start
  date.
- **Form**: the **Maintenance mode on** switch and one message per language
  (French and English). Each message is optional, **plain text** of at most
  **500 characters**; line breaks are kept, formatting and links are not.
  The screen refuses, before sending, control characters other than line
  breaks, the Unicode line and paragraph separators (U+2028, U+2029) and the
  invisible bidirectional characters (a frequent cause: text pasted from
  another application; type it again). This check only helps: the server
  applies the same rules and has the final word. Emptying both messages
  clears the stored messages.
- **Warning**: the messages are shown on the public page of **every
  tenant**, to anyone. Write nothing confidential (no tenant names,
  internal addresses or details of the infrastructure).
- **Preview**: the messages as they will be shown, as text, under the
  standard maintenance text. A language without a message shows the
  message of the other language, if any. The messages are never
  interpreted as HTML, here or on the public pages.
- **Confirmation**: turning the mode on or off asks for a confirmation,
  since it blocks (or reopens) new deposits on every tenant; uploads in
  progress pause until the end of the maintenance.
- **Banner**: while the mode is on, every admin (super admin and delegated
  admins) sees a banner at the top of the administration: "Maintenance
  mode has been on since …: new deposits are refused on every entity",
  with "(forced by the environment)" when it applies, and, for the super
  admin, a link to this screen. The state is read at sign-in, on **each
  navigation** in the administration, when the tab is **shown again**, and
  right after a change on this screen. It is **never read on a timer**:
  every request to the administration API extends the session, so a
  background read would keep an unattended session open beyond its
  30-minute idle timeout. A change made elsewhere (another tab, another
  super admin, a restart with `TT_MAINTENANCE`) therefore appears at the
  next navigation. When the state cannot be read, the dashboard card says
  so, with the link to this screen. The maintenance message itself is
  meant for the public pages and is not repeated in the banner.

**Forced by the environment.** While `TT_MAINTENANCE=true` imposes the
mode, the screen explains it and does not offer to turn it off (a refusal
`409 state-conflict`, for example from another tab, is reported and the
state reloaded). It shows the **choice recorded in the administration**
(`adminEnabled`), which applies once the variable is removed and the
instance restarted. The messages can still be edited, but the API cannot
store messages with `enabled: false` while the environment forces the mode,
so **saving them also records the mode as on** in the administration. When
the recorded choice was off, the screen asks for a confirmation first:
after removing `TT_MAINTENANCE` and restarting, the mode then stays on
until you turn it off on this screen.

### System settings screen

- **Alert threshold**: a percentage from **50 to 99**, with at most two
  decimals (`85`, `85.5` or `85,5`); it is stored as a ratio (`0.855`). The
  alert is raised when the disk usage reaches the threshold and clears
  once it falls **5 points below** it. Lowering the threshold below the
  current usage raises the alert at once.
- **Additional alert address**: optional, receives the disk alert in
  addition to the super admins. The address is **not verified** (no code is
  sent to it), which the screen points out: a new address must be **typed a
  second time** to confirm it. Emptying the field **removes** the address
  (`alertEmail: null`); the alert is then mailed to the super admins only,
  and stays visible in the overview and in the audit log.
- Only the changed fields are sent (merge patch). A reminder explains that
  the alert mails go through the system SMTP server, and a link opens the
  overview.

### Global audit log screen

- **Filters**: **Entity** (a list of all tenants, sorted by name, with
  **All entities and the instance** first) and **action** (the grouped
  list of the tenant audit log, plus the **Administrators and sign-in** and
  **Instance** groups, or a code typed as **Other action**). Both are kept
  in the page address.
- There is **no "instance events only" filter**, because the API cannot
  return them alone: without an entity, the log holds the events of every
  tenant and of the instance; with an entity selected, only that tenant's
  events, the instance events being excluded (the screen says so). There
  is no actor or date filter on this log either.
- **Columns**: an **Entity** column (the tenant name, linking to the
  tenant; the raw identifier for a deleted tenant or when the names cannot
  be loaded; **Instance** for an event without tenant, such as a sign-in,
  an admin account change, the maintenance mode, the system settings, the
  disk alert or a master key rotation), then the columns of the tenant
  audit log (date, actor, action, object, IP, details). Object links point
  to the tenant of the event.

### Master key screen

The screen runs step 3 of the
[master key rotation](master-key.md#rotation) from the administration (see
[Rotating from the administration](master-key.md#rotating-from-the-administration)).
It shows **key identifiers only** (`mk_` and 16 hexadecimal characters),
never key material: the API returns none, and the administration cannot
create, upload or download a key.

- **Master keys**: the current key (`TT_MASTER_KEY_FILE`) and the new key
  (`TT_MASTER_KEY_NEW_FILE`, or "None configured"), with the invitation to
  check them against the vault, and a **Restart required** badge after a
  completed rotation.
- **Latest rotation**: identifier, status (running, completed or failed),
  from and to keys, start and end dates, progress and error.

What the screen offers depends on the state:

| State | What is shown |
|---|---|
| No new key configured | Steps 1 and 2 (generate the key and store it in the vault, mount it with `TT_MASTER_KEY_NEW_FILE` and restart), with the path of the documentation. **No start button.** |
| Ready | A checklist of two boxes, **"The new key is stored in the password vault outside the VM"** and **"I checked both key identifiers"**, then **Start the rotation**. |
| Running | The progress ("N keys re-wrapped out of M", bar capped at 100 %, since keys created under the old key meanwhile can push the count above the total). The rotation runs on the server: the page can be left. |
| Interrupted | The rotation stays running but its progress has not moved for about **30 seconds** (and three reads): the screen suggests it was interrupted, for example by a restart, and offers **Resume the rotation** (checklist and a new code again). |
| Unfinished rotation between other keys | Cannot be resumed from here: configure the keys it names, or abandon it with `rotate-master-key -abandon`. |
| Completed (restart required) | The next steps: point `TT_MASTER_KEY_FILE` to the new key, remove `TT_MASTER_KEY_NEW_FILE` and restart; update the vault; keep the old key as long as older backups exist. After the restart, open pages must be reloaded (see the effect of step 4 in [Rotation](master-key.md#rotation)). No new start before the restart. |
| Failed | The error reported by the server, as text, and **Start the rotation again** (a new rotation) once the cause is fixed. |

**Starting.** Once both boxes are ticked, the start button opens a dialog
that asks for the **current code of the authenticator** or, with the
link to switch, a **recovery code** (consumed once used). **If you have
just signed in, wait for the next code**: a code already used cannot be
used again. A wrong code keeps the dialog open with the attempts left
when the server gives them; once locked, the dialog shows the remaining
wait. Wrong codes are counted per session together with those of the
sign-in, and the dialog says so: the **fifth** wrong code is still answered
as a wrong code (`401 invalid-credentials`) but ends the session, and the
**next request** brings back the sign-in page. A refusal `409` closes the dialog, shows the reason on the page
(no new key configured, a rotation already running, a rotation between
other keys unfinished, a restart required) and reloads the state. The
typed code is kept only in the page memory: it is cleared at each
submission and when the dialog closes, and it never appears in the page
address, the browser storage or an announcement.

**Progress.** While a rotation runs, the screen reads its progress every
**2 seconds**, every 10 seconds while the tab is hidden or the rotation
looks interrupted, with a longer wait after failed reads; it stops on a
final status and when you leave the screen. Since each read extends the
session, the reads **pause after 10 minutes without activity** on the page
(no click, no key press, tab not shown again): a notice says that updates
are paused while you are away and that the rotation continues on the
server, with **Resume updates**. After an error that is not worth retrying
(other than a network or server error), the reads stop with a warning and
a **Retry** button; reloading the status does not restart them. Screen
readers hear the start, the 25, 50, 75 and 100 % milestones and the end,
never every read.

**Resuming.** The interruption detection is only a hint: the API cannot
tell whether the worker runs. **Resume the rotation** sends a new start
request: the server answers with the **same rotation identifier** and
continues where it stopped. If the worker of this server instance was in
fact still running, the server refuses with `409` (already running) and
nothing changes. If another process runs it (the `rotate-master-key`
command), the resumption runs alongside it safely: each key is re-wrapped
with a conditional update, and the worker that finds the rotation finished
elsewhere stops; part of the work is only done twice.

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
(`GET /tenant` reports `maintenance: true`, the `maintenanceMessage` for
the negotiated language and, in `maintenanceMessageLanguage`, the language it
is actually written in: when no message exists in the negotiated language,
the tenant default, English or any written language is used instead, and the
public interface marks the message up with that language for screen readers,
RGAA criterion 8.7), the administration and the health check
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

The disk alert and the antivirus alert (see [Antivirus](antivirus.md#when-clamd-is-unavailable-fail-closed))
concern the whole instance, so they are not sent through the SMTP server of
a tenant: they use a **system SMTP server** configured by
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
| Instance (no tenant) | `maintenance.enabled`, `maintenance.disabled` (message languages only), `config.updated` (system settings: names of the changed fields only), `disk.alert_raised`, `disk.alert_cleared` (system actor `disk`), `antivirus.alert_raised`, `antivirus.alert_cleared` (system actor `antivirus`, see [Antivirus](antivirus.md#when-clamd-is-unavailable-fail-closed)), `master_key.rotation_started`, `master_key.rotation_completed`, `master_key.rotation_failed` (see [Master key](master-key.md#audit)) |

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
  so still receive a mail sent just before the erasure. Its link keeps
  working as long as the transfer exists: a transfer it received that
  still has other recipients is kept, and its link with it; the link is
  dead (410), and the files unreadable (keys destroyed), only once the
  transfer itself is erased.
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

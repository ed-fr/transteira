# Tenants

A tenant (entity) is one organisation served by the shared instance, with
its own host name, branding, rules, SMTP settings, mail templates and legal
texts, and strictly isolated data. This page covers their configuration
from the administration and the storage quota alerts. The daily operation
of a tenant (transfers, invitations, blocklist, audit log, GDPR,
statistics) is described in [Administration](admin.md).

- Implementation: `internal/tenantadmin`, `internal/branding`,
  `internal/mail` (templates), `internal/lifecycle` (deletion),
  `internal/quota` (quota alerts).
- Variable: `TT_SMTP_DENY_NETWORKS`, see `.env.example`.
- Threat model: T-63, T-64, T-92, T-124, T-149 and the SMTP SSRF entry in
  `docs/security/threat-model.md`.

## Who can change what

| Setting | Super admin | Delegated admin of the tenant |
|---|---|---|
| Create, delete the tenant | yes | no |
| Name, FQDN, storage quota | yes | no |
| Per-transfer ceiling (at most 20 GiB) | yes | no |
| Per-transfer limit | yes | only up to the ceiling |
| Default language | yes | yes |
| Branding, IP ranges and domains, SMTP, mail templates, legal texts | yes | yes |

A delegated admin never sees another tenant: its identifier answers 404, as
an unknown one would. Deletion is reserved to the super admin and answers
403 to any other admin, whatever the tenant.

## Host name

Each tenant has one FQDN (`transfer.entity-a.example.com`). It must be
unique and can never be one of the admin hosts (`TT_ADMIN_HOSTS`). Add the
host to the reverse proxy (certificate) before creating the tenant. A
changed FQDN takes effect at once; the old one then answers 421.

## Branding

- **Colors**: primary and accent, `#RRGGBB`. Each read reports the WCAG
  contrast of the pairs used by the interface (AAA, AA or fail): a failing
  pair is a warning, not a refusal, but fix it for accessibility (RGAA).
- **Logo and background image**: PNG, JPEG or WebP, detected from the
  content (5 MiB for a logo, 10 MiB for a background; dimensions and
  decoding memory bounded before decoding; at most 4 uploads read and one
  image decoded at a time). Decoding, resizing and re-encoding may use at
  most 320 MiB, estimated before decoding for the worst case of the
  format (every allocation counted, as the tests measure). Every logo
  fits. For a background, the limit depends on the format: 35 Mpx for an
  8-bit PNG or a gray JPEG; about 26 to 33 Mpx for a 16-bit or interlaced
  PNG; about 12 to 13.7 Mpx for a color JPEG (a 4000x3000 photo or a
  3840x2160 image fit); about 10 Mpx for a CMYK JPEG; about 5.9 Mpx for a
  WebP (3228x1815), whose worst case needs 203 MiB whatever its size. A
  larger image is refused as too large: downscale it to 3840 pixels on its
  longest side (or convert a WebP to JPEG) before uploading it.
  Every image is decoded and re-encoded by TransTeira (logo as PNG,
  background as JPEG), which removes metadata and any hidden content. SVG is
  refused. Without a background, a neutral default image is used.

## IP ranges and internal domains

A depositor is internal when their IP is in one of the tenant's ranges
**and** their address is in one of its domains (CLAUDE.md section 6.2).
Ranges are CIDR prefixes without host bits (`10.20.0.0/16`, not
`10.20.0.1/16`); IPv4-mapped IPv6 prefixes are converted to IPv4.

## SMTP

Each tenant sends through its own SMTP settings: host, port, security
(none, STARTTLS, TLS), optional authentication, sender address. The
password is sealed by the master key and never shown again; when host,
port or username change, give the password again (or remove it).

**Internal networks (SSRF)**: a tenant's SMTP host can never resolve to a
network listed in `TT_SMTP_DENY_NETWORKS` (by default loopback, link-local,
cloud metadata addresses, `0.0.0.0/8` and the IPv4-compatible IPv6 range
`::/96`; the shared range `100.64.0.0/10` stays allowed apart from the
Alibaba Cloud metadata address, for carrier-grade NAT and overlay networks). The check runs on the resolved address at
each connection, so a DNS name cannot be switched to a forbidden address
later. Private ranges stay allowed so that an internal Docker relay keeps
working: add your database and ClamAV networks to the variable.

- **Test**: sends a test mail and reports the SMTP dialogue (limited to 5
  tests per 10 minutes per admin and tenant). The mail may still be
  filtered downstream.
- **DNS check**: indicative SPF, DMARC and DKIM (for the selectors you
  give) of the sender domain. Configure them for every sending domain.

## Mail templates

Each mail (verification code, transfer notification, confirmation, first
download, file problems, file not scanned, invitation, quota warning and
quota reached) can be customised per tenant and language: subject, HTML
body and text body.

- Only variables are allowed: `{{download_link}}`, `{{sender_email}}`… The
  list, with the required ones, is returned with each template. There is no
  template logic, and any other `{{…}}` syntax is refused.
- The HTML is filtered by an allowlist: formatting tags, tables, links
  (`https:` or `mailto:` only), a limited set of inline styles. Scripts,
  forms, frames, remote images and event handlers are removed. The stored
  version is the filtered one.
- Required variables (the link, the code, the file list…) must be present
  in both bodies.
- Reset returns to the default template; preview renders sample data,
  without the inline styles and with images replaced by their description
  (the administration's Content Security Policy would block them); the
  mails sent keep them.

If a customised template cannot be read when a mail is sent, the default
one is used and a warning is logged: mails are never lost because of a
customisation.

## Quota alerts

The super admin sets the storage quota of each tenant. The storage used is
the declared size of the tenant's transfers that are uploading, being
scanned or available; space is reserved when a transfer is created, so a
deposit that would exceed the quota is refused at once (`507
quota-exceeded`) and nothing is written.

TransTeira keeps an alert level per tenant and mails the admins when it
rises:

| Level | Reached when | Mail and audit action |
|---|---|---|
| 80 | the tenant uses at least 80 % of its quota | `quota-warning`, `quota.warning` |
| 100 | the storage used reaches the quota, or a deposit was refused for quota while the tenant uses at least 95 % of it | `quota-reached`, `quota.reached`: new deposits are refused until space is freed (expiry or deletion) |

- **One mail per crossing.** A mail is sent only when the level rises,
  never again while it stays there. To avoid an alert at every small
  change around a threshold, the levels go down with a margin
  (hysteresis): level 80 re-arms only once usage drops below 75 %, and
  level 100 goes back to 80 only below 95 %. A level that goes down is
  recorded silently.
- **Recipients**: the delegated admins attached to the tenant (enabled and
  activated), each in their language; when the tenant has none, the super
  admins. The mail goes through the tenant's own SMTP settings.
- **Risk of the fallback to the super admins** (deliberate, threat model
  T-149): the tenant's SMTP settings may have been set by a delegated
  admin who has since been disabled or detached, possibly pointing at a
  relay they control, which then receives the super admins' addresses and
  the tenant's storage figures. The mail holds no secret and no link token
  (only the administration console URL), and the SMTP egress guard
  (`TT_SMTP_DENY_NETWORKS`) still applies. When a tenant is left without a
  delegated admin, the super admin should review its SMTP settings before
  relying on its alerts.
- **Without SMTP settings**, no mail can be sent: the level is still
  stored, an error is logged, and the rise is recorded in the audit log
  anyway. The audit log is the durable trace of the alerts: check it (or
  the statistics) if a tenant has no working SMTP.
- **When**: right after each transfer creation and each deposit refused for
  quota, and in a sweep of every active tenant at startup and every 15
  minutes, which catches space freed by expirations and deletions and
  quota changes by the super admin.

The current usage and quota of a tenant also appear in its statistics
(`storageUsedBytes`, `storageQuotaBytes`, `storageUsedRatio`): see
[Statistics](admin.md#statistics) for the definition of every figure. The
sum of the quotas may exceed the disk: the super admin watches the disk
usage in the global statistics.

## Legal notice and privacy policy

Written in limited Markdown (headings, paragraphs, bold, italics, lists,
`https:` and `mailto:` links), per language; raw HTML is escaped. Headings
`#`, `##` and `###` are rendered one level down (h2 to h4), below the
page's own title. They are
shown on the tenant's public pages in the visitor's language, or the
tenant's default language, or else in any language it exists in. An empty
text removes the document.

## Deleting a tenant

Only the super admin can delete a tenant, by repeating its exact name. It
is irreversible:

1. the tenant is marked as being deleted: its host answers 421 at once, it
   can no longer be changed and no new transfer can be created in it;
2. every transfer is erased (keys destroyed first, then files);
3. every remaining key (SMTP password…) is destroyed;
4. the tenant's directory (files, logo, background) is removed;
5. the tenant and all its configuration are deleted, then the directory is
   removed once more in case a request still running recreated it.

The deletion goes on server side even if the browser disconnects. If it is
interrupted, calling it again resumes it, and the cleanup task finishes it
at startup and every hour. The audit log records `tenant.deletion_started`
(the admin and their IP, at each call) and a single `tenant.deleted` (actor
`lifecycle`, with the tenant's name and FQDN) when the erasure completes. Audit and security log
entries are kept until their 12-month retention expires.

# Security log

TransTeira writes a dedicated **security log**, separate from the audit log,
for intrusion prevention tools: **fail2ban** and **CrowdSec** read it and ban
the addresses that attack the service. The format below is **stable**: it is
covered by reference ("golden") tests, and any incompatible change would be a
breaking change of TransTeira.

- File: `security.log` in `TT_LOG_DIR` (default `/var/log/transteira`; `/logs` in the Docker image, on the `transteira_logs` volume).
- Opened in append mode, created with mode `0640`; TransTeira creates `TT_LOG_DIR` (mode `0750`) when it is missing. On Unix, an existing file with wider permissions (for example `0644` left by an older deployment or a rotation tool) is tightened to at most `0640` when it is opened (best effort: a failure leaves the file as it is). Reopened on `SIGHUP` on Unix only.
- One line per event, UTF-8, terminated by `\n`.
- Retention: 12 months (CLAUDE.md section 20), handled by log rotation.

Implementation: `internal/securitylog`.

## Line format

```text
2026-10-20T07:41:00.123Z ip=203.0.113.7 tenant=transfer.entity-a.example.com event=unknown_fqdn host="evil.example.net"
```

Grammar (tokens separated by one space):

```text
line    = timestamp " ip=" ip " tenant=" tenant " event=" event *( " " key "=" value ) LF
```

| Position | Token | Content |
|---|---|---|
| 1 | timestamp | RFC 3339, UTC, millisecond precision, always `YYYY-MM-DDTHH:MM:SS.mmmZ`. |
| 2 | `ip=` | Real client IP: IPv4 dotted, or IPv6 in canonical form **without brackets**. IPv4-mapped IPv6 addresses are written as IPv4, IPv6 zones are dropped. `ip=-` when the event has no client address. |
| 3 | `tenant=` | Normalised FQDN of the tenant (`[a-z0-9.-]`, at most 253 bytes), or `-` when the request is not bound to a tenant (unknown host, global endpoint, and every event of the admin host, which belongs to no tenant). |
| 4 | `event=` | Event type, `[a-z][a-z0-9_]*`, at most 64 bytes (catalogue below). |
| 5+ | `key="value"` | Optional fields, in a fixed order per event. Keys are `[a-z_]+` (at most 32 bytes, never `ip`, `tenant` or `event`). |

### Values

Field values are free text and may be controlled by an attacker (Host
header, e-mail address...). They are always written between double quotes,
after the four fixed tokens, with these rules:

- the input is truncated to its first **256 bytes** (cut on a UTF-8 boundary)
  before escaping;
- `\` becomes `\\` and `"` becomes `\"`;
- LF, CR and TAB become `\n`, `\r` and `\t`;
- any other ASCII control byte (0x00-0x1F, 0x7F) and any byte that is not
  valid UTF-8 becomes `\xNN` (two lowercase hex digits);
- any non-printable Unicode character (C1 controls, no-break and other
  special spaces, line and paragraph separators, bidirectional overrides...)
  becomes `\uNNNN` or `\UNNNNNNNN` (lowercase hex).

Consequences, relied upon by the integrations (threat model T-99):

- a line never contains a raw CR or LF, so a value cannot start a new line;
- a value cannot close its quotes, so nothing outside the quotes is ever
  attacker-controlled: a fake ` ip=` token can only appear inside a value;
- the `ip=` token is written by the server from the TCP connection, or from
  `X-Forwarded-For` / `X-Real-IP` **only** when the request comes from a proxy
  listed in `TT_TRUSTED_PROXIES`.

### Client address `ip=-`

`ip=-` means that TransTeira has no trustworthy client address for the
event. In particular, a request that comes from a **trusted proxy** but
carries no usable client address is logged with `ip=-`, never with the proxy
address: banning the proxy would cut off every user. That is the case when
both headers are missing or empty, when `X-Real-IP` is repeated or invalid,
when the right-to-left walk of `X-Forwarded-For` reaches a malformed entry,
or when every `X-Forwarded-For` entry is itself a trusted proxy. Malformed
entries to the left of the first untrusted address are never reached: they
come from the client and are ignored. These lines **never match** the fail2ban
filter nor the CrowdSec parser, so they are never bannable. Many `ip=-`
lines usually mean a reverse proxy that does not forward the client address
(section 18.2 of the specification).

## Event catalogue

| Event | Meaning | Fields |
|---|---|---|
| `verification_code_invalid` | Wrong e-mail verification code entered. | `purpose`: since 1.1, `deposit` (sender verification) or `recipient` (recipient verification on a personal download link). Optional context. |
| `transfer_password_invalid` | Wrong password entered to unlock a download. | `transfer`: the first 14 characters of the transfer identifier (`trf_` and the time part of the ULID): enough to group the attempts on one transfer, not enough to identify it. The download token and the password are never written. |
| `admin_login_failed` | Failed admin authentication, on the admin host (`tenant=-`): wrong password (also an unknown, disabled or not yet activated username, without telling them apart), wrong TOTP code, wrong recovery code, or wrong setup token on the first-run setup. | `reason`: `password`, `totp`, `recovery_code` or `setup_token`. The username is never written. |
| `api_token_invalid` | API token refused on a deposit operation (`Authorization: Bearer`): empty, malformed, unknown on this tenant (a token of another tenant included), revoked or expired, without telling them apart. Answered `401 invalid-credentials`. | None. The token is never written. |
| `unknown_fqdn` | `Host` header matching neither a tenant nor an admin host (`TT_ADMIN_HOSTS`): the request is rejected with `421 Misdirected Request` on every path except `/healthz` and `/api/openapi.yaml`, which answer without a tenant. | `host`: the received Host (escaped, truncated). |
| `deposit_refused` | Deposit refused. | `reason`: `ip` (outside the tenant's IP ranges, or a valid API token used from outside its allowed ranges: `403 ip-not-allowed`; the token identifier is in the application log, never here), `domain` (address outside the allowed domains, or a token deposit whose sender is not in the token's `allowedSenders`), `blocklist`, `invitation` (missing, unknown or expired). |
| `metrics_token_invalid` | Since 1.1. Wrong monitoring token on `/metrics` or `/status` (`Authorization: Bearer`, compared with `TT_METRICS_TOKEN`). Answered `401 invalid-credentials`; repeated failures from one client are answered `429` and logged as `rate_limited` with `scope="metrics_token"`. Written with `tenant=-`: these endpoints belong to no tenant. | None. The token is never written. |
| `rate_limited` | A rate limit was exceeded. | `scope`: the limiter (for example `global`, `assets`, `verification_code`, `verification_link`, `verification_ip`, `admin_login`, or `transfer_password` when an unlock is refused because the transfer or the client IP is locked: 3 wrong passwords within a sliding 15-minute window lock for 15 minutes; a right password clears the transfer counter and withdraws only the failure it had just added to the IP counter, so failures on other transfers still count; this scope also carries the `transfer` field described above; or `download_streams` when a download is refused because too many streams are open at once: 2 per client for one transfer, 4 for one transfer across all clients, 8 per client across all transfers of the tenant, where a client is an IPv4 address or an IPv6 /64; this scope carries the same truncated `transfer` field). `verification_link` and `verification_ip` (since 1.1) are answered `429` when a recipient verification code cannot be sent: more than 5 codes per hour for one address and link, or more than 20 per hour from one IP (shared with the deposit codes); both are counted by the shipped fail2ban and CrowdSec rules. See [Admin host scopes](#admin-host-scopes) for `admin_login` and `admin_auth`, and [API token scope](#api-token-scope) for `api_token`. |

See [Log throttling](#log-throttling) for the events that are not written
for every occurrence.

### API token scope

The `api_token` scope locks a client (IPv4 address or IPv6 /64) out of
the API token path, in memory: **10 invalid tokens** (`api_token_invalid`)
within a sliding **10-minute** window lock it for **15 minutes**. While it
is locked, every request carrying `Authorization: Bearer` on a deposit
operation gets `429 rate-limited` with `Retry-After`, a valid token
included, before any lookup; requests with a deposit session are not
affected. The `rate_limited` line is throttled like every other scope (one
per client every 10 seconds) and counted by the shipped fail2ban filter
and CrowdSec scenario.

```text
2026-10-20T07:41:00.123Z ip=203.0.113.9 tenant=transfer.entity-a.example.com event=api_token_invalid
2026-10-20T07:41:00.123Z ip=203.0.113.9 tenant=transfer.entity-a.example.com event=rate_limited scope="api_token"
```

### Admin host scopes

The administration is served on the dedicated admin host(s) only
(`TT_ADMIN_HOSTS`), which belong to no tenant: its events carry `tenant=-`.
Two `rate_limited` scopes concern it, both **counted** by the shipped
fail2ban filter and CrowdSec scenario like every other scope but
`download_streams`:

| Scope | Limit | Answer |
|---|---|---|
| `admin_login` | Kept in the database by the authentication service: 5 failed logins per (username, client IP) and 20 failures (password or second factor) per client IP within 15 minutes lock for 15 minutes; 5 wrong second factors of one administrator, from any IP, lock their second factor for 15 minutes. One line per lock. | `429 rate-limited` with `Retry-After` until the lock ends. |
| `admin_auth` | In memory, per client (IPv4 address or IPv6 /64), on the login steps only (first-run setup, password, second factor, activation link): a burst of 20 requests, then one every 3 seconds, successes included. A coarse flood guard in front of the password hashing; throttled like every `rate_limited` line (one per client every 10 seconds). | `429 rate-limited` with `Retry-After`. |

The other admin operations need a session and only count against the
`global` limit.

Every request counts against exactly one of two per-client limits (IPv4
address or IPv6 /64), checked before the tenant is resolved:

- `assets`: the build files of the web interface (`GET` and `HEAD` under
  `/assets/`, with a clean path, whatever the `Host`): 500 requests per
  second sustained, with a burst of 1000. A cold load of an admin page
  fetches dozens of script chunks, which the `global` limit would refuse to
  users sharing one NAT address; the files are served from memory, but an
  unknown `Host` still costs a tenant lookup, so they are not unlimited.
- `global`: every other request, entry pages, the API, the documentation
  and the help included: 50 requests per second sustained, with a burst
  of 100.

Volumetric protection beyond these limits belongs to the reverse proxy and
to fail2ban or CrowdSec.

New event types and new fields may be added in later versions; existing
names never change. Parsers must ignore unknown fields.

Examples:

```text
2026-10-20T07:41:00.123Z ip=2001:db8::1 tenant=- event=admin_login_failed reason="password"
2026-10-20T07:41:00.123Z ip=2001:db8::1 tenant=- event=rate_limited scope="admin_auth"
2026-10-20T07:41:00.123Z ip=192.0.2.13 tenant=transfer.entity-a.example.com event=deposit_refused reason="ip"
2026-10-20T07:41:00.123Z ip=203.0.113.8 tenant=- event=unknown_fqdn host="198.51.100.1:443"
2026-10-20T07:41:00.123Z ip=- tenant=- event=rate_limited scope="global"
2026-10-20T07:41:00.123Z ip=198.51.100.7 tenant=transfer.entity-a.example.com event=transfer_password_invalid transfer="trf_01JABCD8E3"
2026-10-20T07:41:00.123Z ip=198.51.100.7 tenant=transfer.entity-a.example.com event=rate_limited transfer="trf_01JABCD8E3" scope="transfer_password"
2026-10-20T07:41:00.123Z ip=198.51.100.7 tenant=transfer.entity-a.example.com event=rate_limited transfer="trf_01JABCD8E3" scope="download_streams"
```

## Log throttling

To keep a flood from filling the disk, events are throttled when they are
written (the requests themselves are still rejected every time):

- `rate_limited`: at most **one line per client key and `scope` every
  10 seconds**. The client key is the one used by the rate limiter (the
  client IPv4 address, or the IPv6 /64). Different scopes are throttled
  separately, so one client hitting two limiters can produce two lines per
  10 seconds.
- `unknown_fqdn`: every request with an unknown Host that the unknown-host
  limiter lets through (burst of 10, then one every 12 seconds) gets `421`
  and is logged. The requests it refuses get `429` and write only the
  throttled `rate_limited` event (`scope="unknown_host"`). A sustained scan
  therefore writes about 6 `rate_limited` and 5 `unknown_fqdn` lines per
  minute.

Effect on the ban thresholds: a sustained flood produces about **6 lines per
minute** per client and scope, not one line per request. The shipped
settings take this into account:

- fail2ban, `maxretry = 10` within `findtime = 10m`: a flood is banned in
  under two minutes. Do not set `findtime` below about 2 minutes, or
  throttled `rate_limited` lines alone may never reach `maxretry`.
- CrowdSec, `ed-fr/transteira-bf` leaks 1 event per minute and
  `ed-fr/transteira-fqdn-scan` 2 per minute: 6 events per minute still
  overflow the bucket (capacity 9) in about two minutes. Keep the leak speed
  well below 6 events per minute when tuning.

Counting rate-limit lines therefore measures the *duration* of an abuse, not
its number of requests.

Note on download streams: the per-client caps (2 streams per transfer, 8 per
tenant) count an IPv4 address or an IPv6 /64, so recipients behind one NAT
(an office, a corporate proxy) share them. Several colleagues downloading at
the same time, or a download manager opening many parallel connections, may
then get `429` and produce `rate_limited` lines with
`scope="download_streams"`. The shipped fail2ban filter (`ignoreregex`) and
CrowdSec scenario deliberately do not count these lines, so such sites are
never banned for it; the other `rate_limited` scopes still count. The ignore
rules match the exact line layout (`transfer` then `scope`, nothing after):
keep that field order if you write your own rules.

## Volume

Mount `TT_LOG_DIR` as a dedicated Docker volume (or bind mount) so that the
log survives container updates and can be read from the host or from a
CrowdSec container. The production compose file
([`deploy/docker-compose.yml`](../../deploy/docker-compose.yml)) already
does it: the image sets `TT_LOG_DIR=/logs` and mounts the volume with a fixed
name there:

```yaml
services:
  transteira:
    volumes:
      - transteira_logs:/logs
volumes:
  transteira_logs:
    name: transteira_logs
```

On the host, the file is then at
`/var/lib/docker/volumes/transteira_logs/_data/security.log`. With a bind
mount, the directory must be writable by the container user (UID and GID
`10001` in the image). The log
contains IP addresses and possibly e-mail addresses (personal data): keep
the directory readable only by root and the tools that need it.

## Rotation

TransTeira keeps the file open in append mode. On **SIGHUP** it closes the
file and reopens it at the same path; if the reopening fails, it keeps
writing to the previous (rotated) file and reports the error in the
application log on **stdout** (`docker logs transteira`).

> **A reopen failure silently disables banning.** fail2ban and CrowdSec
> follow `security.log`, while TransTeira keeps writing to
> `security.log.1`: no new event reaches them until the next successful
> reopen or a restart. Watch the application log for
> `securitylog: reopen` errors after each rotation.

The usual cause is a new file that the container user cannot open. The
`create` directive must therefore give the file to **the UID and GID the
container runs as**, not to `root`. The image always runs as the fixed user
`transteira`, **UID 10001 and GID 10001** (see the [`Dockerfile`](../../Dockerfile));
the IDs are numeric on the host, where no such user needs to exist.
Use `logrotate` on the host, with a `postrotate` that signals the container
(12 months of weekly files):

```text
/var/lib/docker/volumes/transteira_logs/_data/security.log {
    weekly
    rotate 53
    compress
    delaycompress
    missingok
    notifempty
    # UID and GID of the TransTeira image (user transteira)
    create 0640 10001 10001
    postrotate
        docker kill --signal=HUP transteira >/dev/null 2>&1 || true
    endscript
}
```

Adapt the container name if you changed `container_name` in the compose
file. If you run the image with another user (`user:` in the compose file),
use that UID and GID instead. The image has no shell, so `docker exec
transteira id` does not work: read the user with
`docker inspect --format '{{.Config.User}}' transteira` (`10001:10001`
unless overridden).

Alternative: **`copytruncate`** (and no `create` nor `postrotate`).
logrotate copies the file and truncates it in place, so TransTeira keeps
writing to the same file and no reopen can fail. The trade-off: lines
written between the copy and the truncation are lost from the rotated
archive (fail2ban and CrowdSec, which read the live file, may still see
them).

SIGHUP handling is available on Linux and other Unix systems only (the
production image); on Windows development machines it is a no-op.

## fail2ban

Ready-to-use files: [`integrations/fail2ban/`](../../integrations/fail2ban/README.md).

- `filter.d/transteira.conf`: the date pattern is anchored at the start of
  the line; fail2ban removes the date, then the `failregex` is anchored on
  ` ip=<ADDR> tenant=... event=<event>`. `<ADDR>` only matches an IP
  address, so `ip=-` lines never match.
- `jail.d/transteira.local`: `maxretry = 10`, `findtime = 10m`,
  `bantime = 1h` with increasing bans, and an explicit
  `iptables-multiport` action on the **`DOCKER-USER`** chain. Traffic to
  ports published by Docker goes through `FORWARD`, never `INPUT`: without
  `DOCKER-USER`, bans have no effect.
- `ignoreip` must list every tenant's internal ranges and the corporate
  egress (NAT) addresses: see
  [Never ban your own users](../../integrations/fail2ban/README.md#never-ban-your-own-users).

Check against a real log with
`fail2ban-regex /path/to/security.log /etc/fail2ban/filter.d/transteira.conf`.

## CrowdSec

Ready-to-use files: [`integrations/crowdsec/`](../../integrations/crowdsec/README.md).

- Acquisition `acquis.d/transteira.yaml` with the label `type: transteira`.
- Parser `parsers/s01-parse/transteira-logs.yaml` (grok anchored on the line
  start), setting `source_ip`, `target_fqdn`, `transteira_event` and the
  event time. `ip=-` lines are left unparsed.
- Scenarios: `ed-fr/transteira-bf` (brute force on codes, passwords, admin
  login, API tokens, refused deposits, rate limiting) and
  `ed-fr/transteira-fqdn-scan` (unknown FQDN scanning), both leaky buckets
  grouped by client IP.
- Enforcement with a bouncer: the **Caddy bouncer** for the reference
  reverse proxy, or a firewall bouncer filtering the `DOCKER-USER` chain.
- Allowlist every tenant's internal ranges and the corporate egress (NAT)
  addresses: see
  [Never ban your own users](../../integrations/crowdsec/README.md#never-ban-your-own-users).

Check with `cscli explain --type transteira --log '<line>'`.

## Tests

`internal/securitylog` checks, on every `make check`:

- one reference line per event type (golden tests);
- values containing CR, LF, quotes, control characters, invalid UTF-8 or a
  forged ` ip=` token stay on one line and round-trip exactly;
- the `failregex` of the fail2ban filter, converted to a Go regular
  expression, extracts the right IP from every reference line and nothing
  else from forged ones; same check for the CrowdSec grok pattern, and the
  event lists of the filter and the scenarios match the catalogue;
- a fuzz target (`FuzzLogLine`) for any IP, tenant and value.

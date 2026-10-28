# Syslog export

TransTeira can copy its **audit log** and its **security log** to a syslog
server or a SIEM, in the RFC 5424 format (CLAUDE.md section 19). The export
is a copy: the local logs (the audit table and `security.log`) stay the
reference, and the export never slows down nor blocks the application.

Implementation: `internal/syslog`, fed by the internal event bus
(`internal/events`).

## Configuration

The export is configured by environment variables only; there is no
administration screen and no API for it.

| Variable | Default | Content |
|---|---|---|
| `TT_SYSLOG_ADDR` | empty | `host:port` of the syslog server. Empty: no export, and the other variables must keep their default. |
| `TT_SYSLOG_PROTOCOL` | `tls` | `tls` (TCP with TLS), `tcp` or `udp`. |
| `TT_SYSLOG_STREAMS` | `audit,security` | Logs exported: `audit`, `security` or both. An unknown value stops the startup. |
| `TT_SYSLOG_FACILITY` | `local0` | RFC 5424 facility: `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`, `local0` to `local7`. |
| `TT_SYSLOG_CA_FILE` | empty | PEM file of the certificate authorities trusted for the server, `tls` only. Empty: the authorities of the system. |

Example, towards a SIEM collector on the internal network with its own
certificate authority:

```dotenv
TT_SYSLOG_ADDR=siem.example.com:6514
TT_SYSLOG_PROTOCOL=tls
TT_SYSLOG_CA_FILE=/run/secrets/siem-ca.pem
```

Mount the CA file read-only, like the master key (a Docker secret or a bind
mount outside the data volumes).

### Choosing the transport

- **`tls`** (recommended, default): TLS 1.2 or later. The certificate of the
  server is **always verified**, against `TT_SYSLOG_CA_FILE` or the system
  authorities, and its name must match the host of `TT_SYSLOG_ADDR`. There is
  no option to disable the verification.
- **`tcp`** and **`udp`** send the messages **unencrypted**. They contain
  personal data (mail addresses, IP addresses): use them only on a trusted
  internal network, for example a collector on the same Docker network.
- `tcp` and `tls` use the octet-counting framing of RFC 6587
  (`<length> <message>`); configure the collector accordingly (rsyslog
  `imtcp` and syslog-ng `network()` detect it; Graylog and Wazuh accept it on
  their TCP syslog inputs).
- `udp` sends one datagram per message of at most 2048 bytes: a longer message loses the end of its text first, then whole structured data parameters from the end (`stream`, `tenant`, `action` and `ip` last); a value is never cut. UDP gives no delivery guarantee.

## Message format

One event gives exactly one message. Example of an audit event (one line):

```text
<133>1 2026-10-27T08:09:10.123456Z transteira transteira 1 admin.login [transteira@32473 stream="audit" tenant="ten_01..." action="admin.login" actor_kind="admin" actor="super-admin" ip="203.0.113.7" object_kind="admin" object_id="adm_01..." audit_id="aud_01..."] admin.login admin adm_01...
```

Example of a security event:

```text
<132>1 2026-10-27T08:09:10.123456Z transteira transteira 1 unknown_fqdn [transteira@32473 stream="security" action="unknown_fqdn" ip="203.0.113.7" host="evil.example.net"] 2026-10-27T08:09:10.123Z ip=203.0.113.7 tenant=- event=unknown_fqdn host="evil.example.net"
```

| Part | Content |
|---|---|
| PRI | facility × 8 + severity: **notice (5)** for the audit log, **warning (4)** for the security log. |
| TIMESTAMP | UTC, microseconds. |
| HOSTNAME | Host name of the container. |
| APP-NAME | `transteira`. |
| PROCID | Process ID. |
| MSGID | The audit action (`admin.login`, `transfer.deleted`...) or the security event type (`unknown_fqdn`, `admin_login_failed`...). |
| STRUCTURED-DATA | Element `transteira@32473` (see below). |
| MSG | Security log: the line exactly as written in `security.log` (see [Security log](security-log.md)). Audit log: `<action> <object kind> <object id>`, with `\` and `"` escaped as well. |

Parameters of the `transteira@32473` element (empty ones are left out):

| Parameter | Content |
|---|---|
| `stream` | `audit` or `security`, always present. |
| `tenant` | Audit: ID of the tenant. Security: its FQDN. Left out when the event belongs to no tenant. |
| `action` | Same as MSGID. |
| `actor_kind`, `actor` | Who acted (audit only): kind of actor and its identifier or address. |
| `ip` | Real client IP. |
| `object_kind`, `object_id` | Object concerned (audit only). |
| `audit_id` | ID of the audit entry (audit only), to find it in the administration. |
| other | The fields of the security event (`host`, `reason`...), as in `security.log`. |

The details of the audit entries are **never** exported: they stay in the
database, readable in the administration.

Values are escaped as RFC 5424 requires (`"`, `\` and `]`), and control
characters, invalid UTF-8 and invisible characters are written in a visible
form (the same rules as the security log), so that an attacker can neither
break a message nor forge a second one. Each value is cut at 256 bytes.

## When the server is unreachable

- The connection is opened at the first message, and reopened after a
  failure with a growing delay (1 s, then doubling up to 1 min).
- During that delay, the messages are **dropped and counted**, never queued
  without limit; the application is never blocked.
- A warning is written in the application log at most once a minute, with the
  address, the error and the counters (never the content of the messages).
- The local logs are complete in any case: after an outage, compare the SIEM
  with the audit log of the administration and with `security.log`.

TransTeira counts the messages sent and dropped; the supervision endpoints
`/metrics` and `/status` of version 1.1 will expose these counters.

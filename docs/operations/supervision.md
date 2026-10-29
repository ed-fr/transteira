# Supervision

TransTeira exposes three endpoints for monitoring tools:

| Endpoint | Format | Access | Use |
|---|---|---|---|
| `/healthz` | JSON | Open (no token) | Liveness and readiness: application, database, antivirus. Made for Uptime Kuma and load balancer probes. |
| `/metrics` | Prometheus text, version 0.0.4 | Token | Metrics for Prometheus, Grafana and Zabbix. |
| `/status` | JSON | Token | The same picture in JSON, for tools that do not read the Prometheus format (Observium, scripts). |

`/metrics` and `/status` belong to no tenant: they answer on any `Host`, outside the tenant
routing, and they still answer in maintenance mode. Their contract is in `api/openapi.yaml`
(`getMetrics`, `getStatus`, schema `InstanceStatus`). They are configured by environment
variables only; the administration has no screen for them.

## Configuration

| Variable | Meaning |
|---|---|
| `TT_METRICS_TOKEN` | Bearer token, 32 to 512 characters. Unset, together with `TT_METRICS_TOKEN_FILE`: both endpoints answer `404`, as for an unknown path. |
| `TT_METRICS_TOKEN_FILE` | Path of a file (for example a Docker secret) holding the token. Alternative to `TT_METRICS_TOKEN`; set only one of them. |
| `TT_METRICS_ALLOWED_IPS` | Optional comma-separated CIDR list. Only these client addresses may reach the endpoints. |

Generate a token with, for example, `openssl rand -base64 48 | tr -d '\n'`, and keep it in a file
readable by the monitoring tool only. Prefer `TT_METRICS_TOKEN_FILE` to `TT_METRICS_TOKEN`: the
value then stays out of `docker inspect` and of the environment.

### Order of the checks

1. If no token is configured: `404`.
2. If `TT_METRICS_ALLOWED_IPS` is set and the real client IP (read from `X-Forwarded-For` or
   `X-Real-IP` only when the request comes from `TT_TRUSTED_PROXIES`) is outside it: `404`. The
   endpoint then looks absent to an outsider.
3. No `Authorization` header: `401 unauthenticated`.
4. Wrong token: `401 invalid-credentials`, and a `metrics_token_invalid` event in the
   [security log](security-log.md) (`tenant=-`, the token is never written, so fail2ban and
   CrowdSec can ban the source).
5. Ten failures from one client within 10 minutes lock it out for 15 minutes: `429` and a `rate_limited` event
   with `scope="metrics_token"`.

The token goes in a header, never in the URL (`Authorization: Bearer <token>`).

### Rotating the token

Change the value (or the content of the file) and restart the container: the token is read at
start. Then update the monitoring tool (Prometheus credentials file, Zabbix macro). Until both
match, the tool receives `401` and the security log records `metrics_token_invalid`.

## Behavior

- Values are computed every 15 seconds from a snapshot: a scrape never queries the database and
  costs the same whatever its frequency. A scrape interval of 30 to 60 seconds is enough.
- Each collection also runs the component checks of `/healthz` (database, antivirus, storage),
  once every 15 seconds whatever the number of scrapers.
- Counters (`_total`) count since the start of the process and restart from zero with it;
  `rate()`, `increase()` and Zabbix "change per second" absorb the reset.
- The `tenant` label is the tenant ID (`ten_...`), never the name. `/status` carries both the `id`
  and the `name` of each tenant, which gives the correspondence.
- No personal data: no e-mail address, file name, token or IP address appears in any metric.

## Metrics

All names start with `transteira_`.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `build_info` | gauge | `version`, `commit` | Always 1. Identifies the running build. |
| `uptime_seconds` | gauge | | Seconds since the process started. |
| `maintenance` | gauge | | 1 while the maintenance mode is on. |
| `transfers_total` | counter | `tenant` | Transfers made available. |
| `uploaded_bytes_total` | counter | `tenant` | Bytes of files uploaded. |
| `downloads_total` | counter | `tenant` | Downloads started. |
| `downloaded_bytes_total` | counter | `tenant` | Bytes of files downloaded. |
| `antivirus_detections_total` | counter | `tenant` | Infected files detected (and deleted). |
| `storage_used_bytes` | gauge | `tenant` | Storage used by the tenant. |
| `storage_quota_bytes` | gauge | `tenant` | Storage quota of the tenant. |
| `active_transfers` | gauge | `tenant` | Transfers currently available. |
| `scan_queue_files` | gauge | | Files waiting for or under antivirus analysis. |
| `antivirus_up` | gauge | | 1 when the antivirus answers. |
| `antivirus_alert` | gauge | | 1 while the antivirus outage alert is raised. |
| `disk_used_ratio` | gauge | | Used fraction of the data disk, 0 to 1. |
| `disk_used_bytes` | gauge | | Bytes used on the data disk. |
| `disk_total_bytes` | gauge | | Size of the data disk. |
| `disk_alert` | gauge | | 1 while the disk space alert is raised (threshold set in the administration, 85 % by default). |
| `download_streams` | gauge | | Downloads open at this moment. |
| `http_requests_total` | counter | `class` (`1xx` to `5xx`) | HTTP responses by status class. |
| `webhook_deliveries_total` | counter | `result` (`delivered`, `failed`, `dropped`, `skipped_open_circuit`) | Webhook delivery outcomes. |
| `events_dropped_total` | counter | `subscriber` | Internal events lost because a subscriber (mail, webhook, syslog...) could not keep up. |
| `syslog_messages_total` | counter | `result` (`sent`, `failed`, `dropped`) | Syslog export outcomes. |
| `mail_queue_length` | gauge | | Alert mails waiting to be sent. |
| `mail_dropped_total` | counter | | Alert mails dropped. |
| `lifecycle_last_success_timestamp_seconds` | gauge | `task` | Unix time of the last successful run of each periodic task (`expire`, `delete-after-download`, `abandoned-uploads`, `tenant-deletions`, `purge-rows`, `orphans`, `expiry-reminder`, `backup`). Absent until the task has succeeded once since the start. |

New metrics may be added in a minor version; existing names are never renamed within `1.x`.

## `/status`

A JSON object (schema `InstanceStatus`), simpler to read than the Prometheus text:

| Field | Meaning |
|---|---|
| `status` | `ok`, or `degraded` when a component of `checks` is unavailable. |
| `version`, `checkedAt`, `uptimeSeconds`, `maintenance` | Build, time of the snapshot, uptime, maintenance mode. |
| `checks` | `database`, `antivirus`, `storage`: state of each component. |
| `disk` | `totalBytes`, `usedBytes`, `usedRatio`, `alertThreshold`, `alertActive`. |
| `antivirus` | `engine`, `queuedFiles`, `alertActive`. |
| `lifecycle` | End time of the last successful run of each periodic task. |
| `tenants` | One row per active tenant: `id`, `name`, `storageUsedBytes`, `storageQuotaBytes`, `storageUsedRatio`, `activeTransfers`, `transfersLast24h`. |

`/status` carries the tenant names, `/metrics` does not: give the status token only to tools you
would trust with the list of your entities.

## Tools

| Tool | How | Where |
|---|---|---|
| Prometheus | Scrape job with a bearer credentials file, `https` on the admin host. | [`integrations/grafana/`](../../integrations/grafana/README.md) |
| Grafana | Importable dashboard: disk, storage per tenant, transfers, downloads, antivirus, HTTP, alert channels, periodic tasks. | [`integrations/grafana/`](../../integrations/grafana/README.md) |
| Zabbix 7.0 | Template with one HTTP agent item, dependent items, tenant discovery and triggers. | [`integrations/zabbix/`](../../integrations/zabbix/README.md) |
| Observium, scripts | Read `/status` with `curl` and `jq`. | [`integrations/zabbix/`](../../integrations/zabbix/README.md#reading-status-from-a-script-observium) |
| Uptime Kuma | HTTP(s) monitor on `/healthz`, no token. | Any host name served by the proxy. |

## Security notes

- **Do not publish `/metrics` and `/status` on the tenant FQDNs** (threat model T-191). They are
  token protected, but a tenant host has no reason to expose them. The reference
  configurations of Caddy, Nginx and Apache answer `404` for both paths on every host except the
  admin host, and Traefik has a documented rule
  ([details](../../integrations/reverse-proxy/README.md#monitoring-endpoints)). You can also
  scrape from the Docker network or restrict the callers with `TT_METRICS_ALLOWED_IPS`.
- The token only gives read access to aggregated figures. It cannot read a transfer, a file or
  an address.
- Use `https` between the monitoring tool and the proxy: the token travels in a header.
- Wrong tokens are logged as `metrics_token_invalid` with the real client IP: the fail2ban and
  CrowdSec integrations ban brute force attempts. Add the monitoring server to `ignoreip` so a
  mistyped token after a rotation does not ban it.
- Metrics expose no personal data. Tenant IDs are opaque identifiers.

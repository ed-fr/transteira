# Zabbix (and Observium, scripts)

`transteira-template.yaml` is a Zabbix 7.0 template. One HTTP agent item downloads `/metrics`
(Prometheus text); the other items are dependent items that extract values with the
`PROMETHEUS_PATTERN` preprocessing, so TransTeira is queried once per minute. Full
documentation of the endpoint, its token and the metric list:
[docs/operations/supervision.md](../../docs/operations/supervision.md).

## 1. Enable the endpoint

Set `TT_METRICS_TOKEN_FILE` (or `TT_METRICS_TOKEN`) on TransTeira, and optionally
`TT_METRICS_ALLOWED_IPS` with the address of the Zabbix server or proxy
(for example `192.0.2.20/32`), then restart the container. Without a token, `/metrics` and
`/status` answer `404`.

## 2. Import the template

1. **Data collection**, **Templates**, **Import**, choose `transteira-template.yaml`.
2. Create a host for TransTeira (no interface needed: the HTTP agent item uses its URL) and link
   the template **TransTeira**.
3. Set the macros on the host:

| Macro | Value |
|---|---|
| `{$TRANSTEIRA.URL}` | `https://admin.transfer.example.com` (admin host, no trailing slash) |
| `{$TRANSTEIRA.TOKEN}` | the token (type **Secret text**) |
| `{$TRANSTEIRA.DISK.WARN}` | `0.85` by default, ratio from 0 to 1 |
| `{$TRANSTEIRA.QUOTA.WARN}` | `0.8` by default, tenant quota ratio from 0 to 1 |

The template provides items for health, disk, antivirus, HTTP errors, mail, events and syslog.
A discovery rule creates, for each tenant ID, items for storage used and quota, active
transfers, transfers and downloads per second, and antivirus detections.

Triggers: disk above `{$TRANSTEIRA.DISK.WARN}`, disk alert, antivirus down or in alert, events,
syslog or mails dropped (counter increased), webhook deliveries failed, HTTP 5xx for ten
minutes, no data for five minutes, and per tenant the quota above `{$TRANSTEIRA.QUOTA.WARN}`.

The raw item stores the whole `/metrics` answer as text, and Zabbix limits a text value to
64 KB. A normal instance stays far below; with a very large number of tenants, use the
`/status` approach below instead.

When the token is rotated, update `{$TRANSTEIRA.TOKEN}`. Add the Zabbix server to `ignoreip` of
fail2ban so that a token mismatch during the rotation does not ban it.

## Reading `/status` from a script (Observium)

`/status` returns the same data as JSON, for tools that do not read the Prometheus format. The
token is passed to curl through its configuration on standard input, never on the command line:

```bash
#!/usr/bin/env bash
# Prints one line per figure; the token comes from a file.
set -euo pipefail
url=https://admin.transfer.example.com/status
printf 'header = "Authorization: Bearer %s"\n' "$(cat /etc/transteira/metrics_token)" |
  curl -fsS -K - "$url" |
  jq -r '"status \(.status)",
         "disk_used_ratio \(.disk.usedRatio)",
         "antivirus_queue \(.antivirus.queuedFiles)",
         (.tenants[] | "tenant \(.id) \(.storageUsedRatio) \(.activeTransfers)")'
```

For a Nagios or Observium style check, `jq -e '.status == "ok"'` exits with 1 when the status is
`degraded`.

## Uptime Kuma

Uptime Kuma uses `/healthz`, which needs no token: an HTTP(s) monitor on
`https://transfer.entity-a.example.com/healthz`.

# Grafana and Prometheus

`transteira-dashboard.json` is a Grafana dashboard (schema 39, Grafana 10 or later) for the
metrics that TransTeira serves on `/metrics`. Full documentation of the endpoint, its token and
the metric list: [docs/operations/supervision.md](../../docs/operations/supervision.md).

## 1. Enable the endpoint

In the `.env` of the TransTeira deployment:

```text
TT_METRICS_TOKEN_FILE=/run/secrets/metrics_token
# Optional: only the monitoring server may reach the endpoint.
# TT_METRICS_ALLOWED_IPS=192.0.2.10/32
```

Create the token file (32 to 512 characters), mount it as a secret, restart the container.
Without a token, `/metrics` and `/status` answer `404`.

## 2. Scrape with Prometheus

Put the same token in `/etc/prometheus/transteira_token` (the file holds only the token, mode
`0400`), then add a job:

```yaml
scrape_configs:
  - job_name: transteira
    scheme: https
    metrics_path: /metrics
    scrape_interval: 30s
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/transteira_token
    static_configs:
      - targets: ["admin.transfer.example.com"]
```

Scrape the admin host (`TT_ADMIN_HOSTS`): the reference proxy configurations do not publish
`/metrics` on the tenant FQDNs. TransTeira refreshes its values every 15 seconds, so a scrape
interval below that gives no better resolution.

## 3. Import the dashboard

1. In Grafana: **Dashboards**, **New**, **Import**, upload `transteira-dashboard.json`.
2. Select your Prometheus data source for the `Prometheus` input.
3. The **Tenant** variable lists the tenant IDs (`ten_...`) found in
   `transteira_storage_quota_bytes`; the **Data source** variable can be changed afterwards.

Rows: health (antivirus, alerts, maintenance, uptime, version), data disk, storage per tenant,
transfers and volumes, downloads, antivirus, HTTP and mail, alert channels (webhooks, dropped
events, syslog) and the age of the last run of each periodic task.

## Alerting

TransTeira already raises its own alerts (mail, webhooks). If you prefer Prometheus rules, these
expressions are a good start:

```text
transteira_antivirus_up == 0
transteira_disk_used_ratio > 0.85
transteira_storage_used_bytes / transteira_storage_quota_bytes > 0.8
increase(transteira_events_dropped_total[15m]) > 0
time() - transteira_lifecycle_last_success_timestamp_seconds{task="expire"} > 7200
```

## Uptime Kuma

Uptime Kuma does not need the token: add an HTTP(s) monitor on
`https://transfer.entity-a.example.com/healthz` (no authentication; it answers whatever the
host and in maintenance mode).

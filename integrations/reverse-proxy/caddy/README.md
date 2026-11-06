# Caddy (reference configuration)

Caddy is the reference reverse proxy of TransTeira: automatic certificates,
streaming by default, and the configuration used by the deployment smoke test
and the 20 GB test. Read the [common requirements](../README.md) first.

## Files

| File | Role |
|---|---|
| `Caddyfile` | Site block for the admin host and the tenant FQDNs, with the `transteira` snippet holding every setting. |
| `Caddyfile.on-demand` | The same configuration (same global options, same `transteira` snippet, same admin host block) plus `on_demand_tls { ask http://transteira:8080/tls/ask }` and a generic `https://` site with `tls { on_demand }`: certificates for the tenant FQDNs are obtained at the first handshake, with no edit of the file when a tenant is created. See [On-demand certificates](#on-demand-certificates). |
| `docker-compose.yml` | The shared reverse proxy (`caddy:2.11.7-alpine`), in its own compose project: ports 80, 443 and 443/udp, volumes `caddy_data` (certificates, keep it) and `caddy_config`, fixed address `172.30.0.10` on the external `proxy` network. |

## Installation

1. Create the shared network once (see [the common README](../README.md#the-proxy-network-and-tt_trusted_proxies)):

   ```sh
   docker network create --subnet 172.30.0.0/24 proxy
   ```

2. Copy this folder to the proxy host (for example `/opt/reverse-proxy`), then
   edit the `Caddyfile`: the ACME contact address (`email`) and the host
   names of the site block. Point the DNS records of every name at the host.
3. Start the proxy:

   ```sh
   docker compose up -d
   docker compose logs -f caddy     # certificate issuance
   ```

4. In the TransTeira `.env`: `TT_TRUSTED_PROXIES=172.30.0.10` and
   `TT_ADMIN_HOSTS=admin.transfer.example.com`, then start TransTeira
   (`deploy/`).

**Adding a tenant**: append its FQDN to the site address list and reload,
without downtime:

```sh
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
```

Caddy is shared: other sites go in their own blocks in the same `Caddyfile`
(or in files pulled in with `import sites/*`). Keep the global options block
at the top.

## On-demand certificates

For a provider creating tenants through the [provisioning API](../../../docs/api/provisioning.md),
use `Caddyfile.on-demand` instead of `Caddyfile` (mount it as `/etc/caddy/Caddyfile`). Point the
DNS of the tenants at the proxy (a wildcard record under the provider's suffix, or one record per
tenant). At the first TLS handshake for a name, Caddy calls
`http://transteira:8080/tls/ask?domain=<fqdn>` over the `proxy` network and requests the
certificate only if TransTeira answers `200`.

In the TransTeira `.env`, allow Caddy to call the endpoint, by its exact address (the same as
`TT_TRUSTED_PROXIES`):

```sh
TT_TLS_ASK_ALLOWED_IPS=172.30.0.10
```

Unset (the default), the endpoint is disabled and no certificate is ever issued. Only a request
whose direct TCP peer is listed is answered; `X-Forwarded-For` is never read, and a request
carrying a relay header (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `X-Forwarded-Host`,
`X-Forwarded-Proto` or `Via`) gets `404` (a public request relayed by Caddy would otherwise
appear to come from the allowed address). Caddy's asks have a limit of their own, 200 per
second (burst 400), outside the global per-IP limit.

Things to know:

- **ACME rate limits.** Let's Encrypt limits the certificates issued per registered domain per
  week and the failed validations per hostname and hour. Many tenants under one registered
  domain, or tenants whose DNS record is missing, can exhaust them. Prefer **one wildcard
  certificate** with the DNS-01 challenge when the provider has a wildcard DNS under its
  suffix: it needs a Caddy build with the module of the DNS provider (`xcaddy`), and a
  `tls { dns <provider> ... }` block in place of `on_demand`.
- **Issuance failures** are only visible in Caddy's log (`docker compose logs caddy`, look for
  `obtaining certificate` errors): TransTeira counts the answers it gives, not the outcomes of
  the ACME exchange. The metric `transteira_tls_ask_total{result}` (see
  [supervision](../../../docs/operations/supervision.md)) shows how many names were allowed,
  unknown or refused.
- **Never expose the ask URL.** It is called over the internal network only; both Caddyfiles
  answer `404` for `/tls/ask` on every public site.
- **Deleting a tenant**: also remove its DNS record. A name that still resolves to the proxy is
  refused by TransTeira (unknown), so no new certificate is issued, but a stale record invites a
  takeover of the name (threat model T-280).
- **Shared proxy.** `on_demand_tls` is a global option: any other site of the same Caddy using
  `tls { on_demand }` would also be checked against TransTeira's ask URL, which refuses every
  name but the tenant FQDNs. The `https://` catch-all site of the variant also receives every
  name no other site claims (TransTeira answers `421` to an unknown `Host`): it must not coexist
  with another `https://` or `:443` catch-all, and the other services keep their explicit site
  blocks.
- `make proxy-configs-check` fails if the `transteira` snippets of the two Caddyfiles differ:
  change both together.

## Settings explained

| Requirement | Setting |
|---|---|
| TLS per FQDN | Automatic: Caddy obtains and renews one certificate per name of the site block (HTTP-01 or TLS-ALPN-01, so ports 80 and 443 must be reachable from the Internet). Names that are not listed get no certificate. |
| HTTP to HTTPS | Automatic redirect on port 80 for every listed name. |
| Request buffering off | Default: `reverse_proxy` streams request bodies unless `request_buffers` is set. Never set it. |
| Response buffering off | `flush_interval -1`: every write is flushed to the client at once. |
| No size limit | Default: Caddy has no request body limit (do not add `request_body { max_size }`). |
| Timeouts | Global `servers { timeouts }`: `read_body 0` and `write 0` (no deadline on a whole body or response), `read_header 30s`, `idle 5m`. Upstream `transport http`: `read_timeout 0`, `write_timeout 0`, `keepalive 90s` (below TransTeira's 120 s). |
| Real client IP | Without the `trusted_proxies` server option, Caddy discards the client's `X-Forwarded-For` and sets it to the TCP peer; `header_up X-Real-IP {remote_host}` adds `X-Real-IP`. Do not configure `trusted_proxies` unless another proxy or a CDN sits in front of Caddy. |
| Host | Passed through unchanged (default). |
| HSTS | `header Strict-Transport-Security "max-age=31536000"` ([about `includeSubDomains`](../README.md#hsts-and-includesubdomains)). |
| Compression | `encode zstd gzip`, restricted to HTML, CSS, JavaScript, JSON and SVG responses, and never on `/api/v1/uploads…` or `/api/v1/downloads/…`. |
| Tokens in the logs | A `format filter` on the access log and on Caddy's default logger (which carries the error logs) replaces the token segment of `/d/`, `/i/`, `/drop/`, `/api/v1/downloads/`, `/api/v1/invitations/` and `/api/v1/drop-links/` with `REDACTED`, and drops **every request header** (`request>headers delete`): `Referer` carries capability links, `Upload-Metadata` the file names and the sender's message (base64, not encrypted), `X-Csrf-Token` a session-bound secret. Caddy itself only redacts `Cookie`, `Set-Cookie` and `Authorization` (API tokens), and only unless the `log_credentials` server option is set: never set it. If a log consumer needs one header (for example `User-Agent`), delete `Referer`, `Upload-Metadata`, `X-Csrf-Token`, `Cookie` and `Authorization` one by one instead (`request>headers>Upload-Metadata delete`, …). |

The access log goes to the container output (`docker compose logs caddy`), in
JSON. Example of a logged download:

```json
"uri":"/api/v1/downloads/REDACTED/files/0b3c…"
```

## CrowdSec bouncer

To block the addresses banned by CrowdSec at the proxy (before they reach
TransTeira), build Caddy with the CrowdSec bouncer module
(`github.com/hslatman/caddy-crowdsec-bouncer`, with `xcaddy`) and add its
`crowdsec` directive. See [`integrations/crowdsec/README.md`](../../crowdsec/README.md#bouncer).
fail2ban bans at the firewall instead ([`integrations/fail2ban/`](../../fail2ban/README.md)).

## Limits

- Only the canonical paths are redacted. A path written differently by a
  client (for example `//d/…` or percent-encoded) is logged as received;
  the links sent by TransTeira always use the canonical form.
- HTTP/3 needs UDP port 443 (published in the compose file); remove
  `443:443/udp` to disable it.

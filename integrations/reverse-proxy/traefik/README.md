# Traefik

Read the [common requirements](../README.md) first. Written for Traefik v3
(validated with `traefik:v3.7.16`; `observability` on routers needs v3.1 or
later).

## Files

| File | Role |
|---|---|
| `traefik.yml` | Static configuration: entry points (with the timeouts), ACME resolver, docker and file providers, access log. |
| `dynamic/transteira.yml` | Dynamic configuration for the file provider: four routers, two middlewares, the `transteira` service. |
| `docker-compose.labels.yml` | Alternative to the dynamic file: the same routers as labels on the TransTeira container (docker provider), applied on top of `deploy/docker-compose.yml`. |
| `docker-compose.yml` | The shared reverse proxy (`traefik:v3.7.16`), in its own compose project, with the fixed address `172.30.0.10` on the external `proxy` network. |

Use **either** the dynamic file **or** the labels, not both.

## Installation

1. Create the shared network once, with a fixed subnet (see
   [the common README](../README.md#the-proxy-network-and-tt_trusted_proxies)):
   `docker network create --subnet 172.30.0.0/24 proxy`.
2. Copy this folder to the proxy host, set the ACME contact address in
   `traefik.yml` and the host names in `dynamic/transteira.yml` (or in the
   labels). Point the DNS records of every name at the host.
3. Start Traefik: `docker compose up -d`.
4. In the TransTeira `.env`: `TT_TRUSTED_PROXIES=172.30.0.10`. With labels,
   start TransTeira with the override:

   ```sh
   docker compose -f deploy/docker-compose.yml \
     -f integrations/reverse-proxy/traefik/docker-compose.labels.yml up -d
   ```

**The file provider is recommended.** With it only, remove the `docker`
provider from `traefik.yml` and the Docker socket from `docker-compose.yml`:
even read-only, access to the Docker API amounts to root on the host, and
Traefik faces the Internet. If you need the docker provider (labels),
consider a Docker socket proxy that only allows reading containers. The
`network` of the docker provider (and the `traefik.docker.network` label) is
the real name of the shared network (`PROXY_NETWORK` in `deploy/.env`).

The compose file hardens the container: read-only root file system (Traefik
only writes `acme.json` in the `letsencrypt` volume), every capability
dropped except `NET_BIND_SERVICE` (ports 80 and 443), `no-new-privileges`.

**Adding a tenant**: add a `Host(...)` to the four rules. The file provider
reloads the file by itself (`watch: true`); labels need a
`docker compose up -d` of TransTeira. Traefik requests the new certificate
automatically.

## Settings explained

| Requirement | Setting |
|---|---|
| TLS per FQDN | Automatic: the `letsencrypt` resolver (HTTP-01 on the `web` entry point) obtains one certificate per `Host()` name of the routers. Certificates are stored in the `letsencrypt` volume (`acme.json`): keep it. |
| HTTP to HTTPS | `entryPoints.web.http.redirections` (permanent). The ACME HTTP challenge keeps working: Traefik answers it before the redirection. |
| Timeouts (critical) | `entryPoints.websecure.transport.respondingTimeouts`: **`readTimeout: 0`** and `writeTimeout: 0`. Since Traefik v3, `readTimeout` defaults to **60 s for the whole request**, which cuts every tus `PATCH` that lasts more than a minute. `idleTimeout: 180s` only concerns keep-alive connections between requests. Towards TransTeira, the default `serversTransport` has no response deadline and closes idle connections after 90 s (below TransTeira's 120 s). |
| Request and response buffering off | Default: Traefik streams both ways. **Never add the `buffering` middleware** to a TransTeira router: it holds the whole request body in memory or on disk. Responses are flushed every 100 ms by default (`responseForwarding.flushInterval`). |
| No size limit | Default: Traefik has no body limit (it only exists in the `buffering` middleware). |
| Real client IP | No `forwardedHeaders.trustedIPs` on the entry points: Traefik discards the `X-Forwarded-*` and `X-Real-Ip` headers sent by the client and sets them from its TCP peer. `aliasHeadersStrategy: delete` drops headers aliasing them (`X_Real_Ip`). |
| Host | `passHostHeader: true` (default). |
| HSTS | `transteira-hsts` middleware: `stsSeconds: 31536000`, `stsIncludeSubdomains: false` ([about `includeSubDomains`](../README.md#hsts-and-includesubdomains)). |
| Compression | `transteira-compress` middleware (`zstd`, `gzip`) with `includedContentTypes` limited to HTML, CSS, JavaScript, JSON and SVG, applied only to the `transteira` and `transteira-tokens` routers: the uploads (`/api/v1/uploads`) and downloads (`/api/v1/downloads/`) routers have no compression. |
| Tokens in the logs | Traefik cannot rewrite a logged path. The routers whose path carries a token, `transteira-downloads` (`/api/v1/downloads/`) and `transteira-tokens` (`/d/`, `/i/`, `/api/v1/invitations/`), set `observability.accessLogs: false`: their requests are not in the access log. Request headers are never logged (`fields.headers.defaultMode: drop`). |

Routers and priorities: `transteira` (priority 10) catches everything; the
three path routers (priority 100) take precedence for their paths.

## Limits

- The token routes are **absent** from the access log (no status code, no
  duration); TransTeira's audit log records downloads and invitation uses.
- The HTTP to HTTPS redirect is handled by an internal router; it was not
  logged in the validation tests, but a plain-HTTP request carrying a token
  could appear in the log of a future version. TransTeira only sends HTTPS links.
- At `log.level: DEBUG`, Traefik logs request paths, tokens included. Keep
  `INFO` or higher in production.

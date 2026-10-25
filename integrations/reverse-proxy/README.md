# Reverse proxy configurations

TransTeira never faces the Internet directly: its container publishes no port
and a reverse proxy, shared with the other services of the Docker host,
terminates TLS for every tenant FQDN and for the admin host, then forwards to
`transteira:8080` over the external Docker network `proxy`.

| Proxy | Folder | Certificates | Notes |
|---|---|---|---|
| **Caddy** (reference) | [`caddy/`](caddy/) | Automatic (ACME), one per FQDN | Shortest configuration, used by the deployment smoke test and the 20 GB test. Token redaction in the access log by a log filter. |
| Nginx | [`nginx/`](nginx/) | certbot (webroot), one certificate for all FQDNs | Needs nginx 1.27.3 or later. Token redaction by a `map` in the log format. |
| Traefik | [`traefik/`](traefik/) | Automatic (ACME), one per `Host()` | File provider or container labels. `respondingTimeouts` must be changed (60 s by default). Token routes are left out of the access log. |
| Apache httpd | [`apache/`](apache/) | certbot (webroot), one certificate for all FQDNs | Needs 2.4.54 or later; `LimitRequestBody 0` is mandatory (1 GiB by default). Token redaction with a second log format. |

The example names are fictitious: `admin.transfer.example.com` (the admin
host, `TT_ADMIN_HOSTS`), `transfer.entity-a.example.com` and
`transfer.entity-b.example.com` (two tenants). Replace them with your own, and
add each new tenant FQDN to the proxy configuration (and to the certificate for
Nginx and Apache) when you create the tenant in the administration.

## Common requirements

Every configuration in this folder implements the following points. If you
write your own, check each of them: most failures with big files come from one
of them being missed.

1. **TLS for every FQDN.** One certificate per tenant FQDN and for the admin
   host. Unknown host names are refused by the proxy (no certificate, or a
   refusal), and TransTeira itself answers `421` to an unknown `Host` and logs
   it in the security log.
2. **`Host` passed through unchanged.** TransTeira selects the tenant from the
   `Host` header only (never `X-Forwarded-Host`), and checks the `Origin` of
   browser requests against `https://<Host>`.
3. **No buffering**, neither of requests nor of responses. tus uploads (`PATCH`
   requests of several gigabytes) must reach TransTeira as they arrive, and
   downloads and ZIP archives (generated on the fly) must reach the client
   immediately. A buffering proxy fills its disk or memory and breaks resumption.
4. **No request size limit.** TransTeira enforces the per-transfer limit
   (at most 20 GB) and the tenant quotas itself.
5. **Long timeouts.** A 20 GB transfer takes hours. Deadlines on the whole
   request or response (Caddy `read_body` / `write`, Traefik `readTimeout` /
   `writeTimeout`) are disabled. Idle timeouts (time between two reads or
   writes: Nginx `proxy_read_timeout`, Apache `Timeout`) are set to one hour,
   well above TransTeira's own idle timeouts (`TT_UPLOAD_IDLE_TIMEOUT` and
   `TT_DOWNLOAD_IDLE_TIMEOUT`, 60 s by default, at most 10 minutes), which
   protect against stalled clients.
   Idle upstream connections are closed by the proxy before TransTeira closes
   them (its keep-alive timeout is 120 s).
6. **Real client IP.** The proxy sets `X-Forwarded-For` to the address of its
   TCP peer, discarding what the client sent, and sets `X-Real-IP` to the same
   value. TransTeira honors these headers only from the addresses listed in
   `TT_TRUSTED_PROXIES` (see below).
7. **Methods passed through.** tus uses `POST`, `HEAD`, `PATCH`, `DELETE` and
   `OPTIONS`; no configuration here restricts methods.
8. **HSTS** is set by the proxy (`Strict-Transport-Security: max-age=31536000`),
   and plain HTTP is redirected to HTTPS (port 80 stays open for the ACME
   HTTP-01 challenge).
9. **Compression of text only.** The application does not compress; the proxy
   compresses HTML, CSS, JavaScript, SVG and JSON. Uploads
   (`/api/v1/uploads…`), downloaded files (`/api/v1/downloads/{token}/files/…`,
   which support byte ranges) and ZIP archives (`/api/v1/downloads/{token}/archive`)
   are never compressed: they are excluded by path, on top of the content type
   restriction. Compressing them would cost CPU for nothing, break byte ranges
   and force buffering.
10. **No capability token in the access log** (threat model T-161). The paths
    `/d/{token}`, `/i/{token}`, `/api/v1/downloads/{token}/…` and
    `/api/v1/invitations/{token}` contain secrets: anyone reading the log could
    download the transfer or use the invitation. Each configuration masks the
    token (Caddy, Nginx, Apache) or leaves these routes out of the access log
    (Traefik). The `Referer` header is not logged either. See
    [Limits](#limits) for the error logs.

## The `proxy` network and `TT_TRUSTED_PROXIES`

Create the shared network once, **with a fixed subnet**, before starting the
proxy and TransTeira:

```sh
docker network create --subnet 172.30.0.0/24 proxy
```

The proxy compose files of this folder give the proxy the fixed address
`172.30.0.10` on it (`ipv4_address`), and TransTeira trusts exactly that
address, in its `.env`:

```sh
TT_TRUSTED_PROXIES=172.30.0.10
```

Why a fixed subnet and a fixed address:

- Without them, Docker picks a subnet and assigns addresses dynamically: the
  proxy may get a new address after a restart, TransTeira would then no longer
  trust it, and every client would appear as unknown (fail closed: internal
  deposits refused).
- List **the exact address**, not the subnet: every container on the `proxy`
  network (other services share it) could otherwise forge `X-Forwarded-For`
  and choose its client IP, bypassing the tenants' IP filtering, the rate
  limits and the fail2ban or CrowdSec bans. TransTeira refuses prefixes
  shorter than /8 and warns for prefixes shorter than /24 (IPv4) or /64
  (IPv6).
- Choose a subnet that overlaps neither your LAN nor any tenant's internal IP
  ranges: a trusted proxy must never sit inside a tenant's internal range.
  `172.30.0.0/24` is an example.

The current address of each container on the network:

```sh
docker network inspect proxy --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'
```

**Client addresses reaching the proxy.** The proxy only sees the real client
address if Docker forwards it. With the default iptables port publishing, it
does for IPv4. An IPv6 client reaching a host whose Docker has IPv6 disabled is
relayed by `docker-proxy`, and the proxy then sees the gateway of the network
(for example `172.30.0.1`) for every such client: enable IPv6 in Docker, or
publish the proxy ports in host network mode, if you serve IPv6 clients.
Check the client IP of a request in the TransTeira audit log after the
installation.

## HSTS and `includeSubDomains`

The configurations send `Strict-Transport-Security: max-age=31536000`, without
`includeSubDomains` and without `preload`. A browser that received it reaches
the host only over HTTPS for a year.

`includeSubDomains` extends the rule to every subdomain **of the host that sent
the header**. On the dedicated names used here (`transfer.entity-a.example.com`,
`admin.transfer.example.com`) it is harmless and may be added. It becomes
dangerous when TransTeira is served on a name that other services live under
(for example a tenant served directly on `entity-a.example.com`, or `preload`
of a shared parent domain): every subdomain, including internal sites still on
plain HTTP, would become unreachable over HTTP for the duration of `max-age`,
and this cannot be undone remotely. Add `includeSubDomains` only after checking
that every subdomain of each served name is HTTPS-only.

## Validation

`make proxy-configs-check` (part of `make check`) validates the four
configurations with the real proxies, in Docker, using pinned images:
`caddy validate` and `caddy fmt`, `nginx -t`, `httpd -t` (both with throwaway
certificates at the certbot paths), and Traefik started with the static
configuration, first with the file provider then with the container labels,
checking that every router, middleware and service is enabled. The two proxy
compose files are checked with `docker compose config`. The check is skipped,
with a message, when Docker is not available. Details: [`check.sh`](check.sh).

The Caddy configuration is also exercised for real by the deployment smoke test
and the 20 GB test.

## Limits

- **Error logs may still contain tokens.** The access logs are redacted, but
  the error logs of the proxies may print the request line when an upstream
  error occurs (TransTeira unreachable, connection reset): Nginx `error_log`
  (`request: "GET /d/…"`), Apache `ErrorLog` (proxy errors). Caddy redacts its
  error log as well (the same filter is applied to its default logger).
  Traefik does not log request paths at the `INFO` level, but does at `DEBUG`.
  Restrict access to the proxy logs, keep them for a short time, and do not run
  the proxy at debug level in production.
- **Traefik cannot rewrite a logged path**: the token routes are simply absent
  from its access log (their status codes and durations are lost too).
  TransTeira's own audit log records downloads and invitation uses.
- **The tokens are still visible to the proxy itself** (it terminates TLS):
  the proxy host must be as trusted as the TransTeira host.
- **Unknown host names** are refused by the proxy before reaching TransTeira,
  so most of them never appear in the TransTeira security log (event for
  unknown FQDNs): ban scanners at the proxy (CrowdSec bouncer) if needed.

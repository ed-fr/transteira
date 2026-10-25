# Apache httpd

Read the [common requirements](../README.md) first. Requires **Apache 2.4.54
or later** with the event MPM; the validation uses `httpd:2.4.69-alpine`.

## Files

| File | Role |
|---|---|
| `transteira.conf` | Complete configuration, included at the end of `httpd.conf`: modules (loaded only when missing), global timeouts and TLS settings, redacted access log formats, default virtual hosts refusing unknown names, HTTP virtual host (ACME challenges, redirect) and HTTPS virtual host for the admin host and the tenant FQDNs. |

## Installation

**Official `httpd` image**, in its own compose project with a fixed address on
the `proxy` network (create it first:
`docker network create --subnet 172.30.0.0/24 proxy`, see
[the common README](../README.md#the-proxy-network-and-tt_trusted_proxies)):

```yaml
name: reverse-proxy
services:
  apache:
    image: httpd:2.4.69-alpine@sha256:070da7661f0be8a05430b2c125c0cde9e53176b4048c813024021969a0e3893c
    restart: unless-stopped
    ports: ["80:80", "443:443"]
    command: ["sh", "-c", "grep -q transteira.conf conf/httpd.conf || echo 'Include conf/extra/transteira.conf' >> conf/httpd.conf; exec httpd-foreground"]
    volumes:
      - ./transteira.conf:/usr/local/apache2/conf/extra/transteira.conf:ro
      - ./letsencrypt:/etc/letsencrypt:ro
      - ./certbot-webroot:/var/www/certbot:ro
    networks:
      proxy:
        ipv4_address: 172.30.0.10
networks:
  proxy:
    external: true
```

**Debian or Ubuntu package**: enable the modules
(`a2enmod proxy proxy_http ssl socache_shmcb http2 headers rewrite deflate filter setenvif`),
copy the file to `/etc/apache2/sites-available/transteira.conf`, **remove its
`Listen 443` line** (already in `ports.conf`), `a2ensite transteira`, and point
the `CustomLog` lines to `${APACHE_LOG_DIR}/transteira-access.log`. Outside
Docker, replace `transteira:8080` with the address of the TransTeira container.

**Certificates (certbot, webroot).** Apache needs a certificate before the
HTTPS virtual hosts can start: comment them out, start Apache, then request one
certificate named `transteira` for all names:

```sh
docker run --rm -v "$PWD/letsencrypt:/etc/letsencrypt" -v "$PWD/certbot-webroot:/var/www/certbot" \
  certbot/certbot certonly --webroot -w /var/www/certbot --cert-name transteira \
  -d admin.transfer.example.com -d transfer.entity-a.example.com -d transfer.entity-b.example.com \
  --email acme-contact@example.com --agree-tos --no-eff-email
```

Restore the virtual hosts and reload (`docker compose exec apache httpd -k graceful`).
Renew with `certbot renew` (for example daily from cron), followed by a
graceful reload. Apache's own ACME module, `mod_md`, is an alternative to
certbot (`MDomain` with every name).

In the TransTeira `.env`: `TT_TRUSTED_PROXIES=172.30.0.10`.

**Adding a tenant**: add its FQDN to the two `ServerAlias` lines, rerun the
certbot command with the full list of names (plus `--non-interactive`), then
reload.

**One certificate per tenant (option).** The shared certificate lists every
tenant FQDN, so any visitor of one tenant can read the names of all the
others in it. If the tenants must not see each other, give each one its own
certificate (`certbot certonly … --cert-name <tenant> -d <tenant FQDN>`) and
its own HTTPS `<VirtualHost>`: copy the virtual host, set `ServerName` to the
tenant FQDN (no `ServerAlias`) and point `SSLCertificateFile` and
`SSLCertificateKeyFile` at its certificate. Caddy and Traefik issue one
certificate per name by default.

## Settings explained

| Requirement | Setting |
|---|---|
| TLS per FQDN | One certbot certificate (`/etc/letsencrypt/live/transteira/`) carrying every name. The first virtual host of each port is the default one and answers `403` to unknown names. |
| HTTP to HTTPS | `mod_rewrite` redirect (301) except `/.well-known/acme-challenge/` (certbot webroot). |
| No size limit | **`LimitRequestBody 0`**. Since Apache 2.4.54 the default is **1 GiB**, which would refuse large tus `PATCH` requests. |
| Request buffering off | `mod_proxy_http` streams request bodies to TransTeira, with `Content-Length` or chunked. Do **not** set `proxy-sendcl` (it spools chunked bodies to disk to compute a length), and add no input filter (mod_security, `SetInputFilter DEFLATE`) on TransTeira: they read the body before proxying. |
| Response buffering off | `flushpackets=on` on `ProxyPass`: every chunk of a download or ZIP archive is sent to the client at once. |
| Timeouts | `Timeout 3600` (client side) and `ProxyTimeout 3600` (TransTeira side) are idle timeouts per read or write, not deadlines on the whole transfer. `mod_reqtimeout` keeps its defaults: its body timeout grows with every 500 bytes received, so it never cuts an upload that is moving. `ttl=60` closes idle backend connections before TransTeira does (120 s). |
| Real client IP | `RequestHeader unset X-Forwarded-For` then `mod_proxy_http` adds `X-Forwarded-For` with the client address: TransTeira receives exactly that address, never the client's own value. `RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"`. `mod_remoteip` is not used: Apache is the edge. |
| Host | `ProxyPreserveHost On` (without it, TransTeira would receive `transteira:8080` and reject the request). |
| tus | Every method is passed through. |
| HSTS | `Header always set Strict-Transport-Security "max-age=31536000"`. |
| Compression | `AddOutputFilterByType DEFLATE` limited to HTML, CSS, JavaScript, JSON and SVG, and `no-gzip` set for `/api/v1/uploads` and `/api/v1/downloads/`. |
| Tokens in the logs | `SetEnvIf Request_URI` sets `TT_TOKEN_PREFIX` (the matched prefix) for `/d/`, `/i/`, `/api/v1/downloads/` and `/api/v1/invitations/`. Two `CustomLog` lines: the `transteira_redacted` format (`"GET /d/REDACTED HTTP/2.0"`, nothing after the prefix) when the variable is set, the `transteira` format otherwise. Neither logs the Referer. |

Example of a logged download (`rt_us` is the duration in microseconds):

```text
192.0.2.10 - - [25/Oct/2026:09:22:17 +0000] "GET /api/v1/downloads/REDACTED HTTP/2.0" 200 2071 "Mozilla/5.0 …" host=transfer.entity-a.example.com rt_us=2103
```

## Limits

- **`ErrorLog` is not redacted**: proxy errors (TransTeira unreachable,
  connection reset) may include the requested URL. Restrict access to the
  error log and keep it briefly.
- The redacted lines lose everything after the token prefix (file identifier,
  `/archive`, `/unlock`). TransTeira's audit log keeps the details.
- Each long transfer holds one Apache worker thread for its whole duration:
  size `MaxRequestWorkers` for the number of simultaneous transfers (the
  defaults of the event MPM are ample for TransTeira's low concurrency).
- Only the canonical paths are redacted; a path written differently by a
  client (`//d/…`, percent-encoded) is logged as received.

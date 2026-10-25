# Nginx

Read the [common requirements](../README.md) first. Requires **nginx 1.27.3
or later** (the `resolve` parameter of `upstream` servers in the open source
edition); the validation uses `nginx:1.30.6-alpine`.

## Files

| File | Role |
|---|---|
| `transteira.conf` | Complete `http`-level configuration: upstream, redacted access log format, HTTP server (ACME challenges, redirect), default servers refusing unknown names, HTTPS server for the admin host and the tenant FQDNs. Install it as `/etc/nginx/conf.d/transteira.conf`. |

## Installation (Docker)

1. Create the shared network once, with a fixed subnet (see
   [the common README](../README.md#the-proxy-network-and-tt_trusted_proxies)):
   `docker network create --subnet 172.30.0.0/24 proxy`.
2. Run nginx in its own compose project, with a fixed address on `proxy`, and
   remove the image's `default.conf` (it would also listen on port 80):

   ```yaml
   name: reverse-proxy
   services:
     nginx:
       image: nginx:1.30.6-alpine@sha256:47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951
       restart: unless-stopped
       ports: ["80:80", "443:443"]
       volumes:
         - ./transteira.conf:/etc/nginx/conf.d/default.conf:ro
         - ./letsencrypt:/etc/letsencrypt:ro
         - ./certbot-webroot:/var/www/certbot:ro
       networks:
         proxy:
           ipv4_address: 172.30.0.10
   networks:
     proxy:
       external: true
   ```

   `resolver 127.0.0.11` is Docker's embedded DNS, available on user-defined
   networks such as `proxy`. Outside Docker, replace `transteira:8080` with the
   address of the TransTeira container and remove `resolver` and `resolve`.
3. **Certificates (certbot, webroot).** nginx needs a certificate before the
   HTTPS server can start. Comment out the HTTPS `server` block and the
   `default_server` on 443, start nginx, then request one certificate named
   `transteira` for all names:

   ```sh
   docker run --rm -v "$PWD/letsencrypt:/etc/letsencrypt" -v "$PWD/certbot-webroot:/var/www/certbot" \
     certbot/certbot certonly --webroot -w /var/www/certbot --cert-name transteira \
     -d admin.transfer.example.com -d transfer.entity-a.example.com -d transfer.entity-b.example.com \
     --email acme-contact@example.com --agree-tos --no-eff-email
   ```

   Restore the blocks and reload (`docker compose exec nginx nginx -s reload`).
   Renew with the same image (`certbot renew`, for example daily from cron),
   followed by a reload.
4. In the TransTeira `.env`: `TT_TRUSTED_PROXIES=172.30.0.10`.

**Adding a tenant**: add its FQDN to the two `server_name` lists, rerun the
certbot command with the full list of names (plus `--non-interactive`;
`--cert-name transteira` updates the existing certificate), then reload.

**One certificate per tenant (option).** The shared certificate lists every
tenant FQDN, so any visitor of one tenant can read the names of all the
others in it. If the tenants must not see each other, give each one its own
certificate (`certbot certonly … --cert-name <tenant> -d <tenant FQDN>`) and
its own HTTPS `server` block: copy the block and change `server_name` and the
two certificate paths. Caddy and Traefik issue one certificate per name by
default.

## Settings explained

| Requirement | Setting |
|---|---|
| TLS per FQDN | One certbot certificate (`/etc/letsencrypt/live/transteira/`) carrying every name; `ssl_reject_handshake on` on the default 443 server refuses unknown names, and the default 80 server closes the connection (`return 444`). |
| HTTP to HTTPS | `return 301 https://$host$request_uri`, except `/.well-known/acme-challenge/` (certbot webroot). |
| Request buffering off | `proxy_request_buffering off` (with `proxy_http_version 1.1`, required to stream request bodies). |
| Response buffering off | `proxy_buffering off`, `proxy_max_temp_file_size 0`: nothing is spooled to `/var/cache/nginx`. |
| No size limit | `client_max_body_size 0` (the default, 1 MiB, would refuse every upload chunk). |
| Timeouts | Idle timeouts of one hour: `client_body_timeout`, `send_timeout`, `proxy_send_timeout`, `proxy_read_timeout`. nginx has no deadline on a whole request. Upstream `keepalive_timeout 60s`, below TransTeira's 120 s. |
| Real client IP | `proxy_set_header X-Forwarded-For $remote_addr` (overwritten, not `$proxy_add_x_forwarded_for`, which would append to the client's value) and `X-Real-IP $remote_addr`. |
| Host | `proxy_set_header Host $host`. |
| tus | Every method is passed through; nothing to add. |
| HSTS | `add_header Strict-Transport-Security "max-age=31536000" always`. Do not declare `add_header` in a `location`: nginx would then drop the server-level headers there. |
| Compression | `gzip` with `gzip_types` limited to CSS, JavaScript, JSON and SVG (HTML is always included), and `gzip off` in the `/api/v1/uploads` and `/api/v1/downloads/` locations. |
| Tokens in the logs | `map $request_uri $transteira_log_uri` replaces the token segment of `/d/`, `/i/`, `/api/v1/downloads/` and `/api/v1/invitations/` with `REDACTED`; the `transteira` log format logs that variable instead of `$request` and leaves out the Referer. Every TransTeira server uses it. |

Example of a logged download:

```text
192.0.2.10 - - [25/Oct/2026:09:21:05 +0000] "GET /api/v1/downloads/REDACTED/files/0b3c HTTP/2.0" 200 2071 "Mozilla/5.0 …" host=transfer.entity-a.example.com rt=0.002
```

## Limits

- **`error_log` is not redacted**: when TransTeira is unreachable or resets a
  connection, nginx logs the full request line (`request: "GET /d/…"`). nginx
  cannot filter it. Restrict access to the error log and keep it briefly, or
  raise its level (`error_log … crit;`) at the cost of losing upstream errors.
- Only the canonical paths are redacted; a path written differently by a
  client (`//d/…`, percent-encoded) is logged as received. The links sent by
  TransTeira always use the canonical form.
- Adding a tenant requires a certificate change and a reload (no automatic
  ACME in nginx open source).

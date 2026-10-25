# Reverse proxy

TransTeira never faces the Internet directly. Its container publishes no
port: a reverse proxy, **shared with the other services of the Docker host
and run from its own compose project**, terminates TLS for every tenant FQDN
and for the administration host, then forwards to `transteira:8080` over the
external Docker network `proxy` (CLAUDE.md section 18).

Ready-to-use configurations, validated with the real proxies by
`make proxy-configs-check`, are in
[`integrations/reverse-proxy/`](../../integrations/reverse-proxy/README.md).

## Choosing a proxy

| Proxy | Configuration | Choose it when |
|---|---|---|
| **Caddy** (reference) | [`caddy/`](../../integrations/reverse-proxy/caddy/README.md) | You start from scratch: automatic certificates per FQDN, streaming by default, the shortest configuration. It is the one used by the deployment smoke test and the 20 GB test. |
| Nginx | [`nginx/`](../../integrations/reverse-proxy/nginx/README.md) | Your host already runs Nginx (1.27.3 or later). Certificates with certbot. |
| Traefik | [`traefik/`](../../integrations/reverse-proxy/traefik/README.md) | Your host already runs Traefik. Automatic certificates; file provider or container labels. Its default `respondingTimeouts` (60 s) must be changed. |
| Apache httpd | [`apache/`](../../integrations/reverse-proxy/apache/README.md) | Your host already runs Apache (2.4.54 or later). Certificates with certbot; `LimitRequestBody 0` is mandatory. |

If a proxy already serves other sites on the host, reuse it: add the
TransTeira site (admin host and tenant FQDNs) to its configuration and attach
it to the `proxy` network with a fixed address. Each folder has a `README.md`
that explains every setting.

## What every proxy must do

Most failures with big files come from one of these points being missed. The
[common requirements](../../integrations/reverse-proxy/README.md#common-requirements)
detail them; in short:

1. **TLS for every FQDN**: one certificate per tenant FQDN and for the admin
   host (automatic with Caddy and Traefik). Plain HTTP is redirected to HTTPS.
2. **`Host` passed through unchanged**: TransTeira selects the tenant from
   it.
3. **No buffering**, of requests (tus uploads of several gigabytes) or of
   responses (downloads and ZIP archives generated on the fly).
4. **No request size limit**: TransTeira enforces the per-transfer limit
   (at most 20 GB) and the quotas itself.
5. **Long timeouts**: a 20 GB transfer takes hours. No deadline on a whole
   request or response; idle timeouts of about one hour.
6. **Real client IP**: `X-Forwarded-For` set to the TCP peer (discarding what
   the client sent) and `X-Real-IP`, honored by TransTeira only from
   `TT_TRUSTED_PROXIES` (below).
7. **Every method passed through**: tus uses `POST`, `HEAD`, `PATCH`,
   `DELETE` and `OPTIONS`.
8. **HSTS** is set by the proxy, not by TransTeira.
9. **Compression of text only**, never of uploads, downloaded files or ZIP
   archives.
10. **No capability token in the access log**: the paths `/d/{token}`,
    `/i/{token}`, `/api/v1/downloads/{token}/…` and
    `/api/v1/invitations/{token}` are masked or left out.

## The `proxy` network

Create the shared network once per host, with a fixed subnet, before starting
the proxy and TransTeira:

```sh
docker network create --subnet 172.30.0.0/24 proxy
```

The provided proxy compose files join it with the fixed address
`172.30.0.10`; the TransTeira compose file joins it as an external network
(`PROXY_NETWORK` in `deploy/.env` if you named it differently). Choose a
subnet that overlaps neither your LAN nor the internal IP ranges of any
tenant.

## `TT_TRUSTED_PROXIES`

TransTeira reads the client IP from `X-Forwarded-For` / `X-Real-IP` **only
when the request comes from an address listed in `TT_TRUSTED_PROXIES`**;
from any other address, these headers are ignored and the TCP peer is the
client. This is what prevents a client from choosing its own IP. Set it in
`deploy/.env` to the address of the proxy on the `proxy` network:

```sh
TT_TRUSTED_PROXIES=172.30.0.10
```

- **List the exact address, not the subnet.** Other services share the
  `proxy` network: any container inside a trusted range could forge
  `X-Forwarded-For` and bypass the tenants' IP filtering, the rate limits and
  the fail2ban or CrowdSec bans. TransTeira refuses prefixes shorter than /8
  and warns for prefixes shorter than /24 (IPv4) or /64 (IPv6).
- **Give the proxy a fixed address** (`ipv4_address` in its compose file).
  Without it, the proxy may get a new address after a restart: TransTeira
  would no longer trust it, every client would appear with the proxy address,
  and internal deposits would be refused (fail closed).
- **Empty**, every client is seen with the address of the proxy: the IP
  filtering of the tenants cannot work.
- A trusted proxy must never sit inside a tenant's internal IP range.

Check the current addresses on the network:

```sh
docker network inspect proxy --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'
```

After the installation, check in the audit log of a tenant that the recorded
IP addresses are those of the clients. IPv6 clients need IPv6 enabled in
Docker (or the proxy ports published in host network mode), otherwise they
all appear with the gateway address of the network: see
[client addresses reaching the proxy](../../integrations/reverse-proxy/README.md#the-proxy-network-and-tt_trusted_proxies).

## Unknown host names

TransTeira answers `421` to a request whose `Host` is neither a tenant FQDN
nor the admin host, and writes an `unknown_fqdn` event to its security log,
which the fail2ban and CrowdSec integrations use to ban host name scanners
(for example the CrowdSec scenario `ed-fr/transteira-fqdn-scan`).

With the provided configurations, however, **the proxy refuses unknown host
names itself** (no certificate for them, or no matching site): these requests
never reach TransTeira, so most of them never produce an `unknown_fqdn`
event and are not counted by fail2ban or CrowdSec. Only the requests that a
proxy forwards with an unknown `Host` (for example a catch-all site pointing
at TransTeira) reach it and are logged. If you want to
ban scanners that probe random host names, do it at the proxy (CrowdSec
bouncer for Caddy, or the proxy's own logs as a CrowdSec source). The other
security events (failed codes and logins, wrong passwords, invalid API
tokens, refused deposits, rate limiting) are unaffected.

## Adding a tenant

When you create a tenant in the administration, also:

1. create its DNS record;
2. add its FQDN to the proxy configuration (and to the certificate for Nginx
   and Apache);
3. reload the proxy, for example with Caddy:

   ```sh
   docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
   ```

Until then, the proxy refuses the new name and the tenant is unreachable.

## Restricting the admin host

The administration is served only on `TT_ADMIN_HOSTS`. You can restrict that
host further at the proxy, for example to your internal networks or a VPN,
without affecting the tenants.

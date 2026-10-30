# Installing TransTeira with Docker

> Version française : [fr/docker.md](fr/docker.md).

This guide installs TransTeira on a VM running Docker, behind a reverse proxy
shared with other services (CLAUDE.md section 18). It uses the production
compose files of [`deploy/`](../../deploy/README.md), with SQLite by default;
the [PostgreSQL variant](#postgresql-variant) is described at the end.

The example names are fictitious: `admin.transfer.example.com` is the
administration host, `transfer.entity-a.example.com` and
`transfer.entity-b.example.com` are two tenants. Replace them with your own.

```
Internet ──► reverse proxy (own compose, ports 80/443) ──► network "proxy" ──► transteira:8080
                                                                                  │ network "internal"
                                                                               clamav (clamd)
```

Contents:

1. [Prerequisites](#1-prerequisites)
2. [DNS](#2-dns)
3. [The `proxy` network](#3-the-proxy-network)
4. [Reverse proxy](#4-reverse-proxy)
5. [Image](#5-image)
6. [Secrets and the master key](#6-secrets-and-the-master-key)
7. [Configuration (`.env`)](#7-configuration-env)
8. [Start](#8-start)
9. [First run: the super admin](#9-first-run-the-super-admin)
10. [Tenants](#10-tenants)
11. [Checks and monitoring](#11-checks-and-monitoring)
12. [Security log, fail2ban and CrowdSec](#12-security-log-fail2ban-and-crowdsec)
13. [Backups](#13-backups)

## 1. Prerequisites

- **Docker Engine 25 or later** (the health checks use `start_interval`)
  with the **Compose v2 plugin 2.24 or later** (`docker compose`, not the old
  `docker-compose`; 2.24 is needed for `env_file` with `required:`, and the
  project's `make deploy-smoke` needs 2.24.4 for `!override`). Check with
  `docker version` and `docker compose version`. The commands below run on
  the Docker host, as root (or with `sudo`), from a clone of the repository:

  ```sh
  git clone https://github.com/ed-fr/transteira.git /opt/transteira
  cd /opt/transteira
  ```

- **Memory.** The compose file sets these limits: TransTeira 1 GiB
  (everything is streamed, nothing is held in memory), clamd **4 GiB** (about
  1 to 1.5 GiB of signatures, plus its spool: clamd writes each decrypted
  stream, up to 2 GiB, to a tmpfs in memory, so that the plaintext never
  reaches a disk; [Antivirus, the clamd spool](../operations/antivirus.md#the-clamd-spool)),
  freshclam 1.5 GiB (it test-loads new signatures before installing them).
  That is 6.5 GiB at worst, plus 1.5 GiB with PostgreSQL (server and backup
  container): plan a VM with **at least 8 GiB of RAM** (10 GiB with
  PostgreSQL) and 2 CPUs or more.
- **Swap.** Run the VM **without swap, or with an encrypted swap**: under
  memory pressure the kernel may write the pages of the clamd spool (the
  plaintext of the file being scanned) to the swap device.
- **Disk.** Every Docker volume lives under the Docker data root
  (`/var/lib/docker` by default). Size it for:
  - the encrypted files (`transteira_data`): the sum of the tenant quotas,
    plus the uploads in progress, which count until they are finished or
    expire. One transfer can reach **20 GB**, and the encryption adds less
    than 0.1 %;
  - the database, its nightly copies (`transteira_backups`), the security
    log, the ClamAV signatures (about 1 GiB) and the images.

  TransTeira alerts the super admin when the disk holding the data reaches
  85 % (adjustable in the administration). The 20 GB test of the project
  needs 60 to 80 GB of free space; a production VM usually needs more.
- **Network.** Ports **80 and 443** reachable by the users (and from the
  Internet if the proxy obtains its certificates with the ACME HTTP-01 or
  TLS-ALPN-01 challenges). TransTeira itself publishes no port. The `clamav-update`
  container needs outgoing HTTPS to `database.clamav.net`.

## 2. DNS

Create a DNS record (A, and AAAA if you serve IPv6) pointing at the VM for:

- the **administration host** (`admin.transfer.example.com`): a dedicated
  name, never a tenant FQDN. You may restrict it to your internal networks
  or a VPN at the proxy;
- **each tenant FQDN** (`transfer.entity-a.example.com`, …). You can add
  tenants later: each new FQDN then needs a DNS record and an entry in the
  proxy configuration.

Each sending domain also needs SPF, DKIM and DMARC records: see
[SMTP](smtp.md#spf-dkim-and-dmarc).

## 3. The `proxy` network

The reverse proxy and TransTeira share an external Docker network named
`proxy`. Create it once per host, **with a fixed subnet**, so that the proxy
can get a fixed address that TransTeira trusts:

```sh
docker network create --subnet 172.30.0.0/24 proxy
```

`172.30.0.0/24` is an example: pick a subnet that overlaps neither your LAN
nor the internal IP ranges of any tenant. Why it matters:
[the `proxy` network and `TT_TRUSTED_PROXIES`](reverse-proxy.md#tt_trusted_proxies).

## 4. Reverse proxy

Choose a proxy and start it in **its own compose project**, as described in
[Reverse proxy](reverse-proxy.md). Caddy is the reference: it obtains the
certificates automatically and its configuration is the shortest.

For Caddy, copy [`integrations/reverse-proxy/caddy/`](../../integrations/reverse-proxy/caddy/README.md)
to the proxy folder (for example `/opt/reverse-proxy`), set the ACME contact
address and the host names in the `Caddyfile`, then:

```sh
cd /opt/reverse-proxy
docker compose up -d
```

The provided proxy compose files give the proxy the fixed address
`172.30.0.10` on the `proxy` network. If the proxy is already running for
other services, add the TransTeira site block to its configuration and make
sure it has a fixed address on the `proxy` network.

Certificates can only be issued once the DNS records resolve; until
TransTeira runs, the proxy answers `502` for its names.

## 5. Image

Build the image from the repository (Docker with BuildKit, the default):

```sh
make docker
```

It builds `transteira:<version>` and `transteira:local`, the default of
`TRANSTEIRA_IMAGE` in `deploy/.env`. Without `make`, the equivalent is:

```sh
docker build -t transteira:local .
```

(`make docker` also stamps the version, commit and date into the binary.)
A published image on a registry will come later; `TRANSTEIRA_IMAGE` then
points at it, pinned to a version (never `latest`).

The image is built `FROM scratch`: the static binary, the CA certificates and
the minimal files of the `transteira` user (UID and GID **10001**), nothing
else (no shell). It writes only to its volumes: `/data` (encrypted files),
`/var/lib/transteira/db` (SQLite), `/backups` (database copies) and `/logs`
(security log).

## 6. Secrets and the master key

The **master key** encrypts the key of every file. Create it, with the right
owner, using the provided script:

```sh
sh deploy/init-secrets.sh
```

It writes `deploy/secrets/master_key` (32 random bytes in base64, mode
`0400`, owned by UID 10001 so that the container can read it), outside every
Docker volume, and never overwrites an existing file. With PostgreSQL, add
`--postgres` (see [PostgreSQL variant](#postgresql-variant)).

> **Copy the master key into a password vault outside the VM now, before
> the first start. This is mandatory.** A VM backup does not contain the key,
> by design: without it, the files and the backups can never be decrypted.
> Record its key ID next to it once TransTeira has started. Details,
> rotation and restore: [Master key](../operations/master-key.md).

```sh
cat deploy/secrets/master_key     # copy the value into the vault entry
```

Keep the `deploy/secrets/` folder readable by root only, and never commit it
(it is ignored by git).

## 7. Configuration (`.env`)

Copy the deployment template and edit it:

```sh
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
```

`deploy/.env` is read twice: by Docker Compose (image name, network, secret
paths) and by the TransTeira container (its `TT_*` variables). It lists the
settings that matter for a Docker deployment; every variable, with its
default and its limits, is documented in the [root `.env.example`](../../.env.example).
Do not set `TT_DATA_DIR`, `TT_BACKUP_DIR`, `TT_LOG_DIR`, `TT_LISTEN_ADDR`,
`TT_CLAMAV_ADDR`, `TT_MASTER_KEY_FILE` or `TT_DB_*`: the compose files fix
them to match the volumes, secrets and services.

The essential variables:

| Variable | Value |
|---|---|
| `TT_ADMIN_HOSTS` | The administration host, for example `admin.transfer.example.com` (required, never a tenant FQDN). |
| `TT_TRUSTED_PROXIES` | The **exact** address of the proxy on the `proxy` network, `172.30.0.10` with the provided proxy files. Empty, every client is seen as the proxy and the IP filtering of the tenants cannot work. |
| `TT_SYSTEM_SMTP_HOST`, `TT_SYSTEM_SMTP_PORT`, `TT_SYSTEM_SMTP_SECURITY`, `TT_SYSTEM_SMTP_FROM` | The system SMTP server, which sends the disk space alert to the super admins. Without it, the alert only shows in the administration and the logs. See [SMTP](smtp.md#system-smtp-for-the-alerts). |
| `TRANSTEIRA_IMAGE` | `transteira:local` after `make docker`, or a pinned published image. |
| `INTERNAL_SUBNET`, `DB_SUBNET`, `TT_SMTP_DENY_NETWORKS` | Fixed subnets of the `internal` (clamd) and `db` (PostgreSQL) networks, `172.31.10.0/24` and `172.31.11.0/24` by default, and the networks the SMTP server of a tenant may never reach: the default list plus these two subnets and the `proxy` subnet. Change the subnets if they overlap your LAN or another Docker network, and the list with them ([SMTP](smtp.md#unauthenticated-relay-on-the-internal-docker-network)). |
| `TT_SCAN_WORKERS` | `1`: one file scanned at a time, because the clamd spool (in memory) holds one stream ([Antivirus](../operations/antivirus.md#the-clamd-spool)). |
| `TT_SETUP_TOKEN` | Optional: the setup token of the first super admin (see below). |
| `TT_DEPOSIT_SESSION_TTL` | Optional, `4h` by default (15 min to 24 h): lifetime of a depositor's session from the email verification, **not extended by activity**. Every upload request needs a live session, so an upload still running when it ends stops with "session expired". At 4 h, a 20 GB transfer needs about 11 Mbit/s of upload bandwidth; for slow links (remote sites, external guests), raise it, for example to `12h`. |

The SMTP servers of the tenants are not set here: each tenant has its own,
configured in the administration ([SMTP](smtp.md)).

## 8. Start

```sh
docker compose -f deploy/docker-compose.yml up -d
```

Compose takes `deploy/` as the project folder, so it reads `deploy/.env`
and the relative secret paths from there, whatever the current folder.

At each start, clamd needs one to two minutes to load its signatures;
TransTeira starts once clamd is healthy, and applies the database migrations
automatically. Follow the start:

```sh
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs -f transteira
```

`ps` should show `transteira` and `clamav` as `healthy`, and `clamav-update`
running (`clamav-init` exits once it has set the volume owners). If
TransTeira refuses to start, its log names the variable or the file at fault
(for example a master key file with a wrong format or inside a volume).

The compose file hardens every container: non-root users, read-only root
file systems, no capability, `no-new-privileges`, memory and process limits.
The one exception is the one-shot `clamav-init` container, which runs as
root, without any network, with the `CHOWN` and `DAC_READ_SEARCH`
capabilities only, to give the signature volume to the `clamav` user, then
exits. clamd has no Internet access; signature updates run in the separate
`clamav-update` container ([Antivirus](../operations/antivirus.md#signatures)).

### Disabling the antivirus (optional)

To run without ClamAV, add the `docker-compose.no-antivirus.yml` overlay last:

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.no-antivirus.yml up -d
```

(with PostgreSQL: `-f deploy/docker-compose.yml -f deploy/docker-compose.postgres.yml -f deploy/docker-compose.no-antivirus.yml`).
It sets `TT_ANTIVIRUS_ENGINE=none` and does not start the ClamAV containers. Every file is then
delivered unscanned and flagged, `/healthz` no longer checks the antivirus, and a WARN is logged at
startup. **Security warning**: the instance can then distribute malware (threat model T-236); do it
only as an explicit choice. Consequences and the per-entity switch:
[Antivirus](../operations/antivirus.md#disabling-the-antivirus).

## 9. First run: the super admin

While no administrator exists, TransTeira prints a **setup token** in its
log, once per start, at the `WARN` level:

```sh
docker compose -f deploy/docker-compose.yml logs transteira | grep "Setup token"
```

The line reads `No admin exists yet. Setup token: stp_… (valid until
restart). Open https://admin.transfer.example.com/admin/setup`. A new token
is generated at each restart. To choose the token yourself instead, set
`TT_SETUP_TOKEN` (16 to 128 characters) in `deploy/.env` before the start,
or `TT_SETUP_TOKEN_FILE` with a Docker secret; nothing is then printed.

Then:

1. open `https://admin.transfer.example.com/admin/setup`;
2. enter the setup token, a username, an email address (it receives the super
   admin alerts) and a password;
3. scan the QR code with an authenticator app and confirm a 6-digit code:
   **TOTP is mandatory for the super admin**, and nothing else in the
   administration is usable before it is confirmed (confirm within
   5 minutes);
4. save the 8 recovery codes in your password vault: they are shown once.

Once the super admin exists, the setup is closed for good and no token is
printed any more. Details: [Administration, first-run setup](../operations/admin.md#first-run-setup)
and the [super administrator guide](../user/en/super-admin.md#first-launch).

Remove `TT_SETUP_TOKEN` from `deploy/.env` afterwards if you had set it.

## 10. Tenants

Create the tenants in the administration (**Entities**, super admin only):
name, FQDN, default language, storage quota. Then configure, or let their
delegated admins configure, branding, internal IP ranges and email domains,
SMTP settings and mail templates.

For each tenant:

1. its FQDN has a DNS record pointing at the VM (section 2);
2. the FQDN is added to the reverse proxy configuration (and to the
   certificate with Nginx or Apache), then the proxy is reloaded, for
   example with Caddy:

   ```sh
   docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
   ```

3. its SMTP settings work (**Send a test email** button) and its sending domain has SPF,
   DKIM and DMARC ([SMTP](smtp.md)).

References: [Tenants](../operations/tenants.md) (every setting and who can
change it), [super administrator guide](../user/en/super-admin.md#entities)
and the [delegated administrator guide](../user/en/delegated-admin.md).

## 11. Checks and monitoring

**Health check.** `/healthz` is served on every host that reaches
TransTeira, the administration host as well as each tenant FQDN, without
authentication:

```sh
curl -s https://admin.transfer.example.com/healthz
```

```json
{"status":"ok","version":"1.0.0","maintenance":false,"checks":{"database":"ok","antivirus":"ok","storage":"ok"}}
```

It answers **200** with `"status":"ok"` when the database, clamd and the data
volume all answer, and **503** with `"status":"degraded"` (and the failed
component `unavailable`) otherwise. The maintenance mode does not change the
status: it shows as `"maintenance":true`. The response never contains error
details (they are in the application log). The Docker `HEALTHCHECK` of the
image probes the same endpoint from inside the container.

**Uptime Kuma.** Add an HTTP(s) monitor on
`https://admin.transfer.example.com/healthz` (or on a tenant FQDN, to also
check its DNS, certificate and proxy route): any status other than 200 is a
failure. Optionally, an "HTTP(s) - Json Query" monitor on `$.status` equal to
`ok`, and a second one on `$.maintenance` to be told when the maintenance
mode is on. A check interval of one minute is plenty: the result is cached
for 3 seconds and the endpoint is rate limited like any other path.

**Version.** The health check reports the version; the binary prints it too:

```sh
docker exec transteira /transteira version
```

**Client IP.** After the first deposit, check in the audit log of the tenant
(administration) that the IP addresses are those of the clients, not
`172.30.0.10`: otherwise `TT_TRUSTED_PROXIES` or the proxy forwarding is
wrong ([Reverse proxy](reverse-proxy.md#tt_trusted_proxies)).

## 12. Security log, fail2ban and CrowdSec

TransTeira writes a dedicated security log (failed codes, wrong transfer
passwords, failed admin logins, invalid API tokens, unknown FQDNs, refused
deposits, rate limiting) with the real client IP, at
`/var/lib/docker/volumes/transteira_logs/_data/security.log` on the host.

- Format and rotation (logrotate with `create 0640 10001 10001`):
  [Security log](../operations/security-log.md).
- Banning at the host firewall, on the `DOCKER-USER` chain:
  [fail2ban](../../integrations/fail2ban/README.md).
- Or CrowdSec, with the Caddy bouncer to block at the proxy:
  [CrowdSec](../../integrations/crowdsec/README.md).

Exclude your own networks from bans (see "Never ban your own users" in both
integrations). Unknown host names are mostly refused by the proxy before
they reach TransTeira ([Reverse proxy](reverse-proxy.md#unknown-host-names)).

## 13. Backups

- **The VM backup** (for example Veeam) captures the Docker volumes:
  encrypted files, database, database copies and logs.
- **A clean copy of the database** is written every night by TransTeira
  (SQLite, `VACUUM INTO` at `TT_BACKUP_TIME`, 02:30 UTC by default, 7 copies
  kept) into the `transteira_backups` volume, so that the VM backup never
  depends on a database file caught in the middle of a write. With
  PostgreSQL, the `db-backup` container runs `pg_dump` instead.
- **The master key is backed up separately**, in the password vault (section
  6): it is never in the VM backup.

Take a manual copy before an upgrade with
`docker exec transteira /transteira backup`. Details and the restore
procedure: [Backup and restore](../operations/backup.md); upgrades:
[Upgrade](../operations/upgrade.md).

## PostgreSQL variant

SQLite suits most installations (one instance, low concurrency). To use
PostgreSQL instead, choose it **at installation**: the compose overlay
[`deploy/docker-compose.postgres.yml`](../../deploy/docker-compose.postgres.yml)
adds:

- `postgres`, on its own internal `db` network (never shared with ClamAV or
  the proxy);
- `migrate`, a one-shot container that applies the migrations with the owner
  role at every `up`, so that the running server only holds the runtime role,
  which can neither change the schema nor bypass row-level security;
- `db-backup`, the nightly `pg_dump` into the `transteira_backups` volume
  (`TT_BACKUP_TIME`, `TT_BACKUP_KEEP`), with the read-only
  `transteira_backup` role.

Steps 1 to 5 and 7 are unchanged. Replace steps 6 and 8 with:

```sh
sh deploy/init-secrets.sh --postgres
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.postgres.yml up -d
```

`init-secrets.sh --postgres` adds random database passwords (superuser,
owner, runtime and backup roles), the two connection strings and the
`pgpass` file of the backup container, each owned by the container that
reads it. The superuser can only connect over the local socket of the
`postgres` container, never over the network. The passwords are only read at the first
start, when the database volume is empty. To avoid repeating both `-f`
options, set `COMPOSE_FILE=docker-compose.yml:docker-compose.postgres.yml` in
`deploy/.env` and run `docker compose` from `deploy/`.

The roles and the checks TransTeira makes at start-up are described in
[PostgreSQL roles](postgresql.md).

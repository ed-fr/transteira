# Deploying TransTeira with Docker

Production compose files for a VM running Docker (CLAUDE.md section 18). The
step-by-step guide is [docs/install/docker.md](../docs/install/docker.md); this
page is the short version.

| File | Purpose |
|---|---|
| `docker-compose.yml` | TransTeira with SQLite (default), clamd, signature updates |
| `docker-compose.postgres.yml` | Overlay: PostgreSQL, one-shot migrations, nightly `pg_dump` |
| `docker-compose.no-antivirus.yml` | Overlay: no antivirus (`TT_ANTIVIRUS_ENGINE=none`), ClamAV containers not started ([Disabling the antivirus](#disabling-the-antivirus)) |
| `.env.example` | Deployment settings (copy to `.env`); every variable is in the root `.env.example` |
| `clamav/clamd.conf`, `clamav/freshclam.conf` | ClamAV configuration, aligned with `TT_CLAMAV_*` ([antivirus](../docs/operations/antivirus.md)) |
| `postgres/initdb/` | Creates the database and its owner, runtime and backup roles, and rejects the superuser over TCP ([PostgreSQL roles](../docs/install/postgresql.md)) |
| `init-secrets.sh` | Creates the secret files with random values and the right owners |

## Requirements

- **Docker Engine 25 or later** (health checks with `start_interval`).
- **Docker Compose 2.24 or later** (`env_file` with `required:`); 2.24.4 or
  later to run `make deploy-smoke` (`!override`).
- **RAM**: 8 GiB at least (10 GiB with PostgreSQL), see the limits below.
  **No swap, or an encrypted swap**: the clamd spool holds the plaintext of
  the file being scanned in memory.

## Layout

```
 reverse proxy (own compose, integrations/reverse-proxy/)
        | network "proxy" (external)
   transteira (UID 10001, read-only, no port published)
        | network "internal" (no Internet)        | network "db" (overlay, no Internet)
   clamav: clamd (UID 100, read-only)         postgres, migrate, db-backup
        ^ volume transteira_clamav_db (read-only)
   clamav-update: freshclam, network "clamav_egress" (Internet), no route to clamd
```

- **No port is published**: the reverse proxy reaches `transteira:8080` over the
  shared `proxy` network.
- **clamd never reaches the Internet**, so a file that exploited a parser flaw
  could not be sent out. Signatures are downloaded by `clamav-update`, the only
  container on the `clamav_egress` network, into a volume that clamd reads
  read-only and reloads every 10 minutes (`SelfCheck`).
- **Volumes have fixed names**: `transteira_data` (encrypted files),
  `transteira_db` (SQLite), `transteira_backups` (database copies),
  `transteira_logs` (security log, read by fail2ban or CrowdSec at
  `/var/lib/docker/volumes/transteira_logs/_data/security.log`),
  `transteira_clamav_db` (signatures), and `transteira_pg` with PostgreSQL.
- **The clamd spool is a tmpfs**, never a volume: clamd writes each stream it
  scans, that is the decrypted file, to `/var/tmp/clamav`, so the plaintext
  must not reach a disk or a backup. It holds one 2 GiB stream, hence
  `TT_SCAN_WORKERS=1` ([antivirus](../docs/operations/antivirus.md#the-clamd-spool)).
- **Fixed subnets**: `internal` (`INTERNAL_SUBNET`, default `172.31.10.0/24`)
  and, with PostgreSQL, `db` (`DB_SUBNET`, default `172.31.11.0/24`). They
  are listed, with the `proxy` subnet, in `TT_SMTP_DENY_NETWORKS`, so that
  the SMTP server of a tenant can reach neither clamd, PostgreSQL nor the
  proxy ([SMTP](../docs/install/smtp.md#unauthenticated-relay-on-the-internal-docker-network)).
- **The master key is a Docker secret**, read from a host file outside every
  volume ([master key](../docs/operations/master-key.md)).
- Memory limits: TransTeira 1 GiB (everything is streamed), clamd 4 GiB
  (about 1 to 1.5 GiB of signatures, reloaded without a second copy, plus up
  to 2.25 GiB of tmpfs spool, which counts in the container memory),
  freshclam 1.5 GiB (it test-loads new signatures), PostgreSQL 1 GiB.
- Hardening: every container runs read-only, without capability and with
  `no-new-privileges`, as a non-root user, except the one-shot `clamav-init`
  (root, no network, `CHOWN` and `DAC_READ_SEARCH` only), which gives the
  signature volume to the `clamav` user and exits.

## Quick start (SQLite)

Run from the repository root, as root (or with sudo) on the Docker host.

1. Create the network shared with the reverse proxy (once per host), then set
   up the proxy from [integrations/reverse-proxy/](../integrations/reverse-proxy/):

   ```sh
   docker network create --subnet 172.30.0.0/24 proxy
   ```

2. Build the image (or set `TRANSTEIRA_IMAGE` to a released image):

   ```sh
   make docker
   ```

3. Create the master key, then **copy it into your password vault**:

   ```sh
   sh deploy/init-secrets.sh            # deploy/secrets/master_key, UID 10001, mode 0400
   ```

4. Configure: copy `deploy/.env.example` to `deploy/.env`, then set at least
   `TT_ADMIN_HOSTS` and `TT_TRUSTED_PROXIES` (the reverse proxy address on the
   `proxy` network).

5. Start, and follow the logs: while no admin exists, TransTeira prints a
   setup token to create the first super admin on
   `https://<TT_ADMIN_HOSTS>/admin/setup`.

   ```sh
   docker compose -f deploy/docker-compose.yml up -d
   docker compose -f deploy/docker-compose.yml logs -f transteira
   ```

   The first start of ClamAV takes one to two minutes (signature loading);
   TransTeira starts once clamd is healthy.

6. Check: `docker compose -f deploy/docker-compose.yml ps` shows `transteira`
   and `clamav` `healthy` and `clamav-update` running (it has no health
   check; `clamav-init` has exited), and `https://<tenant FQDN>/healthz`
   answers through the proxy.

## PostgreSQL

```sh
sh deploy/init-secrets.sh --postgres     # adds the database passwords, DSNs and pgpass
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.postgres.yml up -d
```

The `migrate` service applies the migrations with the owner role at every
`up`, then exits; the long-running `transteira` service only holds the runtime
role, which cannot change the schema or bypass row-level security. The
`db-backup` service writes a `pg_dump` every night (`TT_BACKUP_TIME`, UTC) to
the `transteira_backups` volume and keeps `TT_BACKUP_KEEP` dumps
([backup](../docs/operations/backup.md)); it connects with the read-only
`transteira_backup` role. The `postgres` superuser is rejected over TCP:
use `docker exec -it -u postgres transteira-postgres psql` for maintenance.

## Disabling the antivirus

By default every file is analysed by ClamAV. An operator can turn the analysis
off for the whole instance (specification section 11.1) by adding the
`docker-compose.no-antivirus.yml` overlay, last:

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.no-antivirus.yml up -d
# with PostgreSQL:
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.postgres.yml \
  -f deploy/docker-compose.no-antivirus.yml up -d
```

It sets `TT_ANTIVIRUS_ENGINE=none` on `transteira`, removes its dependency on
`clamav` (the PostgreSQL dependencies are kept) and puts `clamav`,
`clamav-update` and `clamav-init` in the inactive profile `clamav`: they are
not started. Containers created by an earlier `up` are not removed
automatically: run `docker compose ... rm -sf clamav clamav-update clamav-init`.

Consequences: a WARN is logged at startup; files still waiting for analysis at
startup are released as "not analysed: antivirus disabled" (audit event
`antivirus.scans_released`); every file deposited afterwards is delivered
unscanned and flagged (the sender is told by email, the download page says so);
`/healthz` no longer probes the antivirus; the engine name is shown read-only
to the super admin and in `/status`. The blocklist by SHA-256, the abuse
detection and the forced download stay in force. To go back, drop the overlay
and run `up -d`; files delivered meanwhile are never analysed afterwards.

**Security warning**: with no analysis, the instance can distribute malware
(threat model T-236). Choose it only knowingly. Details:
[Antivirus](../docs/operations/antivirus.md#disabling-the-antivirus).

## Checking the files

`make deploy-config-check` (part of `make check`) validates both compose
combinations with `docker compose config`, checks that no port is published,
that the clamd spool is a tmpfs, that the fixed subnets are listed in
`TT_SMTP_DENY_NETWORKS` and that `db-backup` uses the backup role, and has
`clamconf` parse `clamav/clamd.conf` and verify its limits and mandatory
alerts.

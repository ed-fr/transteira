# Upgrade

This page describes how to move a Docker deployment
([`deploy/`](../../deploy/README.md)) to a new version of TransTeira, and how
to go back if the new version misbehaves. Versions follow semantic
versioning; the running version is shown by `/healthz`, in the administration
and by `docker exec transteira /transteira version`.

In the commands below, `-f deploy/docker-compose.yml` stands for the compose
files of your deployment: add `-f deploy/docker-compose.postgres.yml` with
PostgreSQL (and any file of your own), or set `COMPOSE_FILE` in
`deploy/.env` and run `docker compose` from `deploy/`.

## Before the upgrade

1. **Read the [CHANGELOG](../../CHANGELOG.md)** for every version between
   yours and the target: new or renamed variables, changes to the compose
   files or the proxy configurations, manual steps. Compare
   `deploy/.env.example` and the root `.env.example` with your `deploy/.env`.
2. **Turn the maintenance mode on**, so that no deposit is half-finished
   during the switch. In the administration, as super admin:
   **System > Maintenance**, with a message in each language (stored in the
   database, it survives the restart of the upgrade). Alternatively set
   `TT_MAINTENANCE=true` in `deploy/.env` and recreate the container; remove
   it afterwards. Downloads, the administration and the health check keep
   working; uploads in progress pause (`503` with `Retry-After`) and resume
   by themselves afterwards. See [Maintenance mode](admin.md#maintenance-mode).
3. **Take a database copy** right before the upgrade:

   - SQLite:

     ```sh
     docker exec transteira /transteira backup
     ```

     It writes `transteira-<timestamp>-manual.db` to the `transteira_backups`
     volume (never deleted by the nightly rotation) and prints its path.
   - PostgreSQL: run a dump in the `db-backup` container:

     ```sh
     docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.postgres.yml exec db-backup sh -c \
       'umask 077; f=/backups/transteira-$(date -u +%Y%m%dT%H%M%SZ)-manual.dump; pg_dump --enable-row-security --format=custom --file="$f.tmp" && mv "$f.tmp" "$f"'
     ```

   Details: [Backup and restore, manual copy](backup.md#manual-copy-before-an-upgrade).
4. **Take a VM snapshot** (or make sure a fresh VM backup exists), so that
   the volumes and the database copy can be brought back together.
5. **Note the current image**, to go back to it if needed:

   ```sh
   docker inspect --format '{{.Config.Image}}' transteira
   ```

   Keep that image on the host (do not prune it) until the new version is
   validated.

## Upgrade

1. **Get the new image.**
   - Built from the repository: check out the release tag, then build. The
     image is tagged with the version, so the previous one stays available:

     ```sh
     git fetch --tags
     git checkout v<new version>
     make docker                       # transteira:<new version> and transteira:local
     ```

   - Published image (when available): `docker pull <image>:<new version>`.

   Set `TRANSTEIRA_IMAGE` in `deploy/.env` to the new tag
   (`transteira:<new version>`): pinning a version, rather than
   `transteira:local`, keeps the rollback a one-line change.
2. **Apply the changes** listed in the CHANGELOG to `deploy/.env`, and
   update the proxy configuration if it says so.
3. **Recreate the containers:**

   ```sh
   docker compose -f deploy/docker-compose.yml up -d
   ```

   - **The database migrations are applied automatically at start-up** with
     SQLite.
   - With the PostgreSQL overlay, the one-shot `migrate` service applies them
     first, with the owner role; `transteira` starts only once it has
     succeeded. If `migrate` fails, `transteira` does not start on the new
     version: read the log of `migrate` (`docker compose … logs migrate`),
     then fix the cause or [roll back](#rollback).
   - The new container starts once clamd is healthy (one to two minutes if
     ClamAV is recreated too).
4. **Check:**

   ```sh
   docker compose -f deploy/docker-compose.yml ps         # transteira and clamav healthy
   docker compose -f deploy/docker-compose.yml logs transteira
   curl -s https://admin.transfer.example.com/healthz     # "status":"ok", the new "version"
   docker exec transteira /transteira version
   ```

   Then sign in to the administration, open a tenant page, and if possible
   make a small deposit and download (maintenance mode refuses deposits:
   test once it is off, or on a test tenant right after).
5. **Turn the maintenance mode off** (administration, or remove
   `TT_MAINTENANCE` and recreate the container).
6. When the new version is validated, delete the manual database copy
   (it holds wrapped file keys, see
   [crypto-erase and copies](backup.md#crypto-erase-and-copies)) and remove
   the old image.

## Rollback

**Migrations only go forward.** A new version may change the database
schema in a way the previous version does not understand. **Never start the
previous image on a database that the new version has already migrated**
without first restoring the copy taken before the upgrade: the old version
could misread or damage the data.

To go back:

1. Stop TransTeira:

   ```sh
   docker compose -f deploy/docker-compose.yml stop transteira
   ```

2. Restore the database copy taken before the upgrade, as described in
   [Backup and restore, restore](backup.md#restore): for SQLite, replace
   `transteira.db` in the `transteira_db` volume with the
   `transteira-<timestamp>-manual.db` copy, delete the `-wal` and `-shm`
   files and give the file to UID/GID `10001`; for PostgreSQL, restore the
   manual dump into a recreated database.
3. Set `TRANSTEIRA_IMAGE` in `deploy/.env` back to the previous image, and
   check out the matching tag if you use the repository's compose files.
4. Start again and check as above:

   ```sh
   docker compose -f deploy/docker-compose.yml up -d
   ```

Whatever happened between the copy and the rollback is lost from the
database: with the maintenance mode on, that is mostly downloads (their audit
entries, first-download notices) and admin changes. A transfer deleted
during that window (expiry, deletion after the first download) comes back in
the database without its files, which have been erased: delete it from the
administration.

The other way to roll back is to restore the VM snapshot taken before the
upgrade, which brings back the volumes and the database together.

## The master key

An upgrade does not touch the master key: the same Docker secret is mounted
by the new container, and the encrypted files are neither read nor rewritten.
Never combine an upgrade with a [master key rotation](master-key.md#rotation):
finish one, check it, then start the other. If you restore a database copy,
it needs the master key that was active when the copy was taken (see
[Backup and restore](master-key.md#backup-and-restore)).

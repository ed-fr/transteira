# Backup and restore

TransTeira keeps two kinds of data: the **database** (metadata, wrapped
keys, settings) and the **data volume** (the encrypted files). The VM
backup (for example Veeam) captures the Docker volumes; TransTeira adds a
**clean nightly copy of the database**, so that the VM backup never has to
rely on a database file caught in the middle of a write (CLAUDE.md
section 23, threat model T-114).

- Variables: `TT_BACKUP_DIR`, `TT_BACKUP_TIME`, `TT_BACKUP_KEEP`, see
  `.env.example`.
- Implementation: the `backup` task of the cleanup task
  (`internal/lifecycle`), `store.DB.Backup`, and the `transteira backup`
  command for an immediate copy (see
  [Manual copy, before an upgrade](#manual-copy-before-an-upgrade)).
- Related: [Master key](master-key.md) (the key a restore needs, and
  crypto-erase in backups).

> A backup without the master key that was active when it was taken is
> useless: every file and every stored secret stays encrypted. Keep the key
> in a password vault, never in the same backup job as the volumes.

## SQLite: nightly copy by TransTeira

Every day at `TT_BACKUP_TIME` (UTC, `02:30` by default), TransTeira:

1. writes a copy of the live database with `VACUUM INTO` to a temporary
   file in `TT_BACKUP_DIR` (`.transteira-<timestamp>.db.tmp`), created
   empty with mode `0600` beforehand so that the copy is never readable by
   others;
2. checks the copy with `PRAGMA quick_check`;
3. flushes it to disk, sets its mode to `0600` and renames it atomically to
   `transteira-YYYYMMDDTHHMMSSZ.db`;
4. keeps the `TT_BACKUP_KEEP` newest copies (7 by default) and deletes the
   older ones and any temporary file left by an interrupted copy.

A failure is logged at `ERROR` and the temporary file is removed; the
previous copies are kept. `VACUUM INTO` copies the live pages only: data
already deleted (including destroyed keys, thanks to `secure_delete`) is
never carried into a copy.

Mount `TT_BACKUP_DIR` as its own volume so that the VM backup captures it.
TransTeira refuses to start when it overlaps the data directory, the log
directory or the folder of the SQLite database (equal, inside or
containing), or when its path contains `?` or `#`; the master key file must
not be located under any of these directories either. At each copy the
directory is created with mode `0700` if missing, set back to `0700` (with a
warning) if group or others can access it, and refused if it is a symbolic
link.

## Manual copy, before an upgrade

Take a copy right before an upgrade (or any risky operation) with the
`backup` command of the binary. The image has no shell, so run the binary
itself in the running container:

```sh
docker exec transteira /transteira backup
```

It prints the path and the size of the copy, for example
`Database copy written to /backups/transteira-20261025T091500Z-manual.db (1843200 bytes).`
(`/backups` is `TT_BACKUP_DIR` in the Docker image, on the `transteira_backups` volume),
and exits with `0`. The copy is made exactly like the nightly one (`VACUUM
INTO` into a temporary file created with mode `0600`, `PRAGMA
quick_check`, flush, atomic rename) and lands in `TT_BACKUP_DIR`, that is
in the backups volume, so the VM backup captures it too.

- **Safe while the server runs.** `VACUUM INTO` reads a single, consistent
  snapshot of the WAL database: transfers in progress are not disturbed
  and nothing needs to be stopped. Enabling the maintenance mode first
  still gives a copy without any half-finished deposit.
- **Never rotated.** The name carries the `-manual` marker
  (`transteira-YYYYMMDDTHHMMSSZ-manual.db`), which the nightly rotation
  ignores: a pre-upgrade copy is not deleted at night, whatever
  `TT_BACKUP_KEEP` says. Delete the manual copies by hand once they are no
  longer needed (they hold the wrapped keys of the files, see
  [Crypto-erase and copies](#crypto-erase-and-copies)). The temporary
  file of an interrupted manual copy (`.transteira-…-manual.db.tmp`) is
  removed by the next nightly copy, like that of an interrupted nightly one.
- **Another file.** `--out <file>` writes the copy to that file instead
  (its directory must exist and be writable by the container user, for
  example a path inside a mounted volume). The file is created empty with
  mode `0600` and the copy is written into it directly (no temporary file
  and rename, unlike the copies in `TT_BACKUP_DIR`). An existing file is
  never overwritten: the command fails instead. Give an absolute path: a
  relative one is resolved against the working directory of the process.
- To keep the copy outside the VM, take it out of the container:
  `docker cp transteira:/backups/transteira-<timestamp>-manual.db .`
  (adapt the path if you changed `TT_BACKUP_DIR`), and store it with the
  same care as the master key's vault entry.

The command needs the same environment as the server (it reads the
configuration, but neither the master key nor the files) and does not
migrate the database. It refuses to run when the database file does not
exist. Exit codes: `0` copy written, `1` failure (the partial copy is
removed), `2` usage error or PostgreSQL.

To restore a manual copy, follow [Restore](#restore): it is an ordinary
`transteira-*.db` copy.

With PostgreSQL, `transteira backup` writes nothing: it explains that the
dumps are taken by the `db-backup` container and exits with `2`. To take a
dump right now, run `pg_dump` in that container with the same options as
its nightly loop (the connection settings come from its environment):

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.postgres.yml exec db-backup sh -c \
  'umask 077; f=/backups/transteira-$(date -u +%Y%m%dT%H%M%SZ)-manual.dump; pg_dump --enable-row-security --format=custom --file="$f.tmp" && mv "$f.tmp" "$f"'
```

Its name (`-manual.dump`) still matches the `transteira-*.dump` pattern of
the retention shown below, which may delete it after `KEEP` nightly dumps:
copy it elsewhere if it must be kept longer.

## PostgreSQL: dedicated backup container

The TransTeira image is minimal (no shell, no PostgreSQL client), so it does
not run `pg_dump`. With PostgreSQL, the `backup` task does nothing (it says
so once at startup) and a **dedicated container** based on the official
`postgres` image (same major version as the server) takes the dumps. The
Docker step of the project provides it in the compose file; its principle:

```yaml
  db-backup:
    image: postgres:17.6
    restart: unless-stopped
    networks: [db]
    volumes:
      - backups:/backups
    environment:
      PGHOST: postgres
      PGDATABASE: transteira
      # Read-only role (SELECT only), never the owner.
      PGUSER: transteira_backup
      PGPASSFILE: /run/secrets/pgpass
      # Every table forces row-level security: the system scope lets the
      # dump read the rows of every tenant.
      PGOPTIONS: "-c app.system_scope=on"
      KEEP: "7"
    secrets: [pgpass]
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        umask 077
        while true; do
          sleep $$(( ( $$(date -u -d 02:30 +%s) - $$(date -u +%s) + 86400 ) % 86400 ))
          f=/backups/transteira-$$(date -u +%Y%m%dT%H%M%SZ).dump
          if pg_dump --enable-row-security --format=custom --file="$$f.tmp"; then
            mv "$$f.tmp" "$$f"
          else
            rm -f "$$f.tmp"
          fi
          ls -1t /backups/transteira-*.dump | tail -n +$$((KEEP + 1)) | xargs -r rm -f
          sleep 60
        done
```

(The compose file copies the `pgpass` secret into its tmpfs at start, see
`deploy/docker-compose.postgres.yml`.)

Every table uses `FORCE ROW LEVEL SECURITY`, so every role, the owner
included, only sees the rows its session is allowed to see. A plain
`pg_dump` therefore stops with "query would be affected by row-level
security policy": the dump needs `--enable-row-security` and the system
scope (`PGOPTIONS="-c app.system_scope=on"`), as above; the policies honour
the system scope for any role.

**The dump role is read-only.** `db-backup` connects as
`transteira_backup`: `LOGIN`, `NOBYPASSRLS`, no `CREATE`, no `TEMPORARY`,
and `SELECT` on the application tables and sequences only, through default
privileges that the PostgreSQL init script sets for every object the owner
role creates ([PostgreSQL roles](../install/postgresql.md#backup-role)). A
compromise of the backup container can thus read the database, but neither
change it nor its schema; never give it the owner role. Its password file is
the `pgpass` secret (`postgres:5432:transteira:transteira_backup:<password>`),
created by `deploy/init-secrets.sh --postgres` with mode `0400`: libpq
ignores a password file readable by group or others. Give the dumps the same
retention as `TT_BACKUP_KEEP`.

## Crypto-erase and copies

Each copy holds the wrapped keys of the files that existed when it was
taken. A deleted or expired transfer is therefore still recoverable from a
copy, with the current master key, until that copy is rotated out
(`TT_BACKUP_KEEP` days) **and** the VM backups that captured it have
expired. A master key rotation followed by the destruction of the old key
makes all older copies unreadable (decision P25, threat model T-109); see
[Crypto-erase](master-key.md#crypto-erase).

## Restore

You need, from the **same point in time** as far as possible:

1. a database copy (`transteira-*.db` for SQLite, `transteira-*.dump` for
   PostgreSQL);
2. the data volume (the encrypted files);
3. the master key active when the copy was taken (see
   [Backup and restore](master-key.md#backup-and-restore)).

### SQLite

1. Stop the TransTeira container.
2. Restore the data volume from the VM backup.
3. Replace the file named by `TT_DB_DSN` by the chosen copy, and delete
   any `-wal` and `-shm` files next to it.
4. The copy has mode `0600`: make sure its owner is the container user,
   **UID and GID `10001`** in the image (a file owned by root cannot be
   opened by the container), then start TransTeira. The migrations bring an
   older copy up to date.

With the production compose file (`deploy/docker-compose.yml`), the
database is `/var/lib/transteira/db/transteira.db` in the `transteira_db`
volume and the copies are in the `transteira_backups` volume. On the Docker
host, as root, from the repository root:

```sh
docker compose -f deploy/docker-compose.yml stop transteira
v=/var/lib/docker/volumes
cp "$v/transteira_backups/_data/transteira-<timestamp>.db" "$v/transteira_db/_data/transteira.db"
rm -f "$v/transteira_db/_data/transteira.db-wal" "$v/transteira_db/_data/transteira.db-shm"
chown 10001:10001 "$v/transteira_db/_data/transteira.db"
chmod 0600 "$v/transteira_db/_data/transteira.db"
docker compose -f deploy/docker-compose.yml start transteira
```

A copy that comes from the image of an **older** version is migrated at
start; never start an older image on a database already migrated by a newer
one (see [Upgrade](upgrade.md#rollback)).

### PostgreSQL

1. Stop the TransTeira container.
2. Restore the data volume from the VM backup.
3. Recreate an empty database owned by the owner role (the three roles must
   exist: on a new server, the init script of the compose overlay creates
   them), then restore the dump with the owner role and the system scope:
   `PGOPTIONS="-c app.system_scope=on" pg_restore --no-owner --exit-on-error -U transteira_owner -d transteira transteira-<ts>.dump`.
   The grants to the application role, the default privileges of the backup
   role and the row-level security policies are part of the dump.
4. Start TransTeira.

### After a restore

The nightly copy and the data volume are usually a few hours apart:

- files uploaded after the copy are on disk but unknown to the database:
  the cleanup task removes them once their modification time is more than
  24 hours old, which can be at the first run after startup;
- transfers deleted after the copy come back in the database without their
  files (their keys were destroyed after the copy, but the copy still holds
  them): downloading them fails, and they expire normally.

Tell the users concerned to send their most recent transfers again.

### Review the API tokens

A restored database knows the API tokens **as they were when the copy was
taken** (threat model T-115):

- a token **revoked after the copy is valid again**: its holder can deposit
  with it until it is revoked a second time;
- a token whose allowed ranges or allowed senders were narrowed after the
  copy gets its former ranges or senders back;
- a token created after the copy no longer exists: the scripts using it get
  `401 invalid-credentials`.

Right after the restore, before reopening the service if you can (for
example in maintenance mode), list the tokens of every tenant
(`GET /admin/tenants/{tenantId}/api-tokens`, see [API tokens](admin.md#api-tokens))
and compare them with your records or with the `api_token.*` entries of
the audit log you still have (the audit log is restored with the database,
so the entries written after the copy are lost):

1. revoke again every token that had been revoked or replaced since the
   copy, and every token you do not recognise;
2. restore the allowed ranges and senders that had been changed since the copy;
3. create again, and deploy, the tokens created since the copy.

When in doubt, rotate the tokens of the tenant (create a new token, deploy
it, revoke the old one): a revoked token can never be reactivated by the
application itself.

## Deleted tenants

Deleting a tenant destroys its keys by cascade, so its files can no longer
be decrypted, but its directory under `TT_DATA_DIR` is not removed: the
cleanup task only logs it. Remove that directory by hand once the tenant is
gone.

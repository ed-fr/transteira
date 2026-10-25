# PostgreSQL roles

SQLite is the default database engine. When you choose PostgreSQL (`TT_DB_DRIVER=postgres`),
TransTeira needs **two roles**, so that the account used by the running application can never
change the schema or switch off row-level security (RLS), the second layer of isolation between
entities:

| Role | Variable | Used for | Rights |
|---|---|---|---|
| Owner (e.g. `transteira_owner`) | `TT_DB_MIGRATE_DSN` (or `TT_DB_MIGRATE_DSN_FILE`) | Applying schema migrations at startup, then granting rights to the runtime role | Owns the application schema and its tables |
| Runtime (e.g. `transteira_app`) | `TT_DB_DSN` (or `TT_DB_DSN_FILE`) | Everything else | `CONNECT` on the database; `USAGE` on the schema and `SELECT/INSERT/UPDATE/DELETE` on the tables, granted automatically by the owner after each migration |

At startup TransTeira **refuses to run** if the runtime role:

- is a superuser or has `BYPASSRLS`;
- owns, or is a member of a role that owns, the application schema or one of its tables;
- is a member of a superuser or `BYPASSRLS` role;
- has `CREATE` on the application schema.

It logs a warning if the runtime role can create temporary tables (`TEMPORARY`), which could hide
application tables.

A third role, used only for the dumps, is recommended: see [Backup role](#backup-role). The
compose overlay of [`deploy/`](../../deploy/README.md) creates all three roles at the first start
(`deploy/postgres/initdb/10-transteira-roles.sql`).

## Example setup

Run as a PostgreSQL administrator, replacing the passwords:

```sql
CREATE ROLE transteira_owner LOGIN PASSWORD 'change-me-owner'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE transteira_app LOGIN PASSWORD 'change-me-app'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE transteira_backup LOGIN PASSWORD 'change-me-backup'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

CREATE DATABASE transteira OWNER transteira_owner;
\c transteira

-- Remove the permissive PUBLIC defaults.
REVOKE ALL ON DATABASE transteira FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA transteira AUTHORIZATION transteira_owner;
GRANT CONNECT ON DATABASE transteira TO transteira_app;
GRANT CONNECT ON DATABASE transteira TO transteira_backup;

-- Backup role: read-only access to every table and sequence the owner creates.
GRANT USAGE ON SCHEMA transteira TO transteira_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE transteira_owner IN SCHEMA transteira
  GRANT SELECT ON TABLES TO transteira_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE transteira_owner IN SCHEMA transteira
  GRANT SELECT ON SEQUENCES TO transteira_backup;

-- The owner and runtime roles work in the application schema.
ALTER ROLE transteira_owner IN DATABASE transteira SET search_path = transteira;
ALTER ROLE transteira_app IN DATABASE transteira SET search_path = transteira;
```

Never grant `transteira_owner` to `transteira_app`.

Then configure TransTeira, preferably with Docker secrets:

```sh
TT_DB_DRIVER=postgres
TT_DB_DSN_FILE=/run/secrets/transteira_db_dsn            # postgres://transteira_app:...@postgres:5432/transteira
TT_DB_MIGRATE_DSN_FILE=/run/secrets/transteira_migrate_dsn  # postgres://transteira_owner:...@postgres:5432/transteira
```

The owner credentials are only needed while migrations run. For a stricter setup, run
`transteira migrate` in a one-shot container that receives `TT_DB_MIGRATE_DSN`, and keep it out
of the long-running application container.

The local test environment (`test/postgres-init/01-roles.sql`) follows the same model (without the
backup role).

## Backup role

The nightly `pg_dump` (`db-backup` container, [Backup and restore](../operations/backup.md)) never
uses the owner role. It connects as `transteira_backup`:

- `LOGIN`, `NOSUPERUSER`, **`NOBYPASSRLS`**, no `CREATEDB`, `CREATEROLE` or `REPLICATION`;
- `CONNECT` on the database, `USAGE` on the application schema, and **`SELECT` only** on its tables
  and sequences, through `ALTER DEFAULT PRIVILEGES FOR ROLE transteira_owner`: every table a later
  migration creates (as the owner) is readable by it, without any grant in TransTeira;
- no `CREATE` and no `TEMPORARY` (the `PUBLIC` defaults are revoked).

A compromise of the backup container can therefore read the database, as any backup can, but can
neither modify the data nor change the schema. Row-level security still applies to it: the dump
runs with `--enable-row-security` and `PGOPTIONS="-c app.system_scope=on"`, and the policies honour
the system scope for any role, so the dump holds every tenant.

On a database created before this role existed, run the statements of the *Backup role* block
above as an administrator (after `CREATE ROLE transteira_backup …`), plus, for the tables that
already exist:

```sql
GRANT SELECT ON ALL TABLES IN SCHEMA transteira TO transteira_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA transteira TO transteira_backup;
```

## The superuser

The superuser (`postgres`) is not needed once the roles exist. The compose overlay rejects it over
TCP (`deploy/postgres/initdb/20-transteira-hba.sh` puts `host all postgres all reject` first in
`pg_hba.conf` at the first start): it can only connect over the local Unix socket of the container,
with `peer` authentication:

```sh
docker exec -it -u postgres transteira-postgres psql -d transteira
```

TransTeira, `migrate` and `db-backup` connect over TCP with their own roles. On another server,
apply the same rule in `pg_hba.conf`.

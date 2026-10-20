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

## Example setup

Run as a PostgreSQL administrator, replacing the passwords:

```sql
CREATE ROLE transteira_owner LOGIN PASSWORD 'change-me-owner'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE transteira_app LOGIN PASSWORD 'change-me-app'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

CREATE DATABASE transteira OWNER transteira_owner;
\c transteira

-- Remove the permissive PUBLIC defaults.
REVOKE ALL ON DATABASE transteira FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA transteira AUTHORIZATION transteira_owner;
GRANT CONNECT ON DATABASE transteira TO transteira_app;

-- Both roles work in the application schema.
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

The local test environment (`test/postgres-init/01-roles.sql`) follows the same model.

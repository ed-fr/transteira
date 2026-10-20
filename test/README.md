# Test environment

`make test` runs the Go test suite against **both** database engines
(CLAUDE.md sections 17 and 24): SQLite needs nothing, PostgreSQL runs in a
throwaway container described by `test/docker-compose.test.yml`.

## How it works

- Compose project `transteira-test`, one service: `postgres` (PostgreSQL 17,
  pinned Alpine image).
- Port bound to the loopback interface only: `127.0.0.1:55432`.
- Data on `tmpfs`: every restart starts from an empty cluster. Durability
  settings (`fsync`, `synchronous_commit`, `full_page_writes`) are off for speed.
- `postgres-init/01-roles.sql` creates two `NOSUPERUSER`, `NOBYPASSRLS`
  roles (superusers and `BYPASSRLS` roles ignore row-level security, which
  would hide broken tenant-isolation policies):
  - `transteira_owner` runs the migrations and owns the schema objects. It
    may create schemas (one per test) and grants `USAGE` and DML to the app
    role. Owners bypass RLS unless tables use `FORCE ROW LEVEL SECURITY`.
  - `transteira_app` is what the application connects as: `CONNECT` only,
    plus the owner's grants. No `CREATE`, so it cannot alter its policies,
    and no `TEMPORARY`, since a temporary table could shadow an application
    table (`pg_temp` comes first in `search_path`).
  - The `PUBLIC` defaults (`TEMPORARY` on the database, `CREATE` on
    `public`) are revoked, so every privilege is explicit.

All credentials (`transteira_test`, `transteira_owner`, `transteira_app`) are **local fakes** for
this disposable database only. Never reuse them.

Test DSNs (override with `make test TEST_POSTGRES_DSN=... TEST_POSTGRES_MIGRATE_DSN=...`),
exported to the tests as `TT_TEST_POSTGRES_DSN` and `TT_TEST_POSTGRES_MIGRATE_DSN`:

```
app:     postgres://transteira_app:transteira_app@127.0.0.1:55432/transteira_test?sslmode=disable
migrate: postgres://transteira_owner:transteira_owner@127.0.0.1:55432/transteira_test?sslmode=disable
```

## Commands

| Command | Effect |
|---|---|
| `make test-env-up` | Start PostgreSQL and wait until it is healthy. |
| `make test-env-down` | Stop it and delete its volumes. |
| `make test` | Start the environment, then run all tests on SQLite and PostgreSQL. `TT_TEST_REQUIRE_POSTGRES=1` makes PostgreSQL tests fail, not skip, when the database is unreachable. Used by `make check`. |
| `make test-pg` | Alias of `make test`. |
| `make test-sqlite` | Quick local loop: tests without PostgreSQL (PostgreSQL tests skip). Not part of `make check`. |

Docker Desktop (or another Docker engine with Compose v2) must be running for
`make test`.

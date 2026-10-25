# Test environment

`make test` runs the Go test suite against **both** database engines
(CLAUDE.md sections 17 and 24): SQLite needs nothing, PostgreSQL runs in a
throwaway container described by `test/docker-compose.test.yml`.

## How it works

- Compose project `transteira-test`, services `postgres` (PostgreSQL 17,
  pinned Alpine image) and `mailpit` (captures every mail, SMTP on
  `127.0.0.1:51025`, HTTP API on `127.0.0.1:58025`), plus `caddy` in the `e2e`
  profile, started only by the end-to-end tests.
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
| `make test-env-down` | Stop the whole environment (including the e2e Caddy) and delete its volumes. |
| `make test` | Start the environment, then run all tests on SQLite and PostgreSQL. `TT_TEST_REQUIRE_POSTGRES=1` makes PostgreSQL tests fail, not skip, when the database is unreachable. Used by `make check`. |
| `make test-pg` | Alias of `make test`. |
| `make test-sqlite` | Quick local loop: tests without PostgreSQL (PostgreSQL tests skip). Not part of `make check`. |

Docker Desktop (or another Docker engine with Compose v2) must be running for
`make test`.

## End-to-end tests (`test/e2e`)

Playwright drives a real Chromium through the reference reverse proxy (Caddy, in
Docker) to the server binary built by `make build`, on SQLite then on PostgreSQL.

### Commands

| Command | Effect |
|---|---|
| `make e2e` | Take the run lock, build, start PostgreSQL and Mailpit, then run the whole suite with `E2E_DB=sqlite`, then `E2E_DB=postgres`. Part of `make check`. |
| `make e2e E2E_DBS=sqlite` | One engine only. |
| `make e2e E2E_ARGS="specs/smoke.spec.ts"` | One spec file (any `playwright test` argument: `-g "title"`, `--headed`, `--debug`, `--workers=1`...). |
| `make e2e E2E_DBS=sqlite E2E_ARGS="--project=chromium"` | Every spec except the system ones. |
| `make e2e E2E_DBS=sqlite E2E_ARGS="--project=system-serial --no-deps"` | Only the system specs (`admin-system.spec.ts`: maintenance mode, settings), without waiting for the main project they depend on. |
| `make screenshots` | Regenerate the documentation screenshots (see below), SQLite only, under the run lock. |
| `make screenshots-check` | Check `docs/user/screenshots` against its manifest (part of `make check`, under a second). |
| `make e2e-install` | `npm ci --ignore-scripts` in `test/e2e`, only when the lockfile changed (stamp in `node_modules`). |
| `make e2e-browser` | Installs Playwright's Chromium unless it is already cached. `E2E_BROWSER_INSTALL=0` never downloads (offline). |
| `make e2e-lint` | Prettier, ESLint, `tsc` and `npm audit --audit-level=high` on `test/e2e` (`NPM_AUDIT=0` skips the audit when offline). |

Without make, once `make build` and `make test-env-up` have run (the global setup then takes the
run lock itself):

```sh
cd test/e2e
E2E_DB=sqlite npx playwright test specs/smoke.spec.ts
E2E_DB=postgres npx playwright test -g "public home"
```

`--project=system-serial --no-deps` runs the system specs alone there as well.

Docker must be running, and port 443 of `127.0.0.1` must be free (Caddy publishes
it there; set `E2E_HTTPS_PORT` to use another port: every URL then carries it).
Chromium resolves `*.localhost` to the loopback interface by itself: no hosts file.

### One run at a time

Every run shares `.run/`, the Caddy container (port 443) and the `transteira_e2e` database, and
`make e2e` rebuilds `web/dist` and `bin/transteira`. A machine-wide lock serialises the runs:

- `make e2e` and `make screenshots` start `scripts/with-lock.mjs`, which creates
  `test/e2e/.run.lock/` with an atomic `mkdir` (`owner.json`: PID, host, start time, purpose,
  token) **before the build**, keeps it for both engines and removes it when the command ends
  (also on failure or Ctrl+C);
- `global-setup.ts` joins that lock (token in `E2E_LOCK_TOKEN`), or takes it itself when
  Playwright is started directly; `global-teardown.ts` releases a lock it took. Nothing of an
  earlier run (server, Caddy, `.run/`) is touched before the lock is held, and the fallback
  teardown does nothing without it;
- a second run prints `waiting for another e2e run (PID ...)` and polls every 2 s, up to
  `E2E_LOCK_TIMEOUT` minutes (45 by default), then fails with the owner's details;
- a lock whose process is gone, or older than `E2E_LOCK_MAX_AGE` minutes (120), is taken over
  (renamed first, so that two waiters never both take it).

Playwright clears `test-results/<engine>` before its global setup: with two direct `npx
playwright test` runs of the same engine, the waiting one may delete the traces of the running
one. Use `make e2e` to avoid it.

### What a run does

`global-setup.ts`, once per engine, cross-platform (Node only, no shell script):

1. Empties `test/e2e/.run/` (gitignored). With PostgreSQL, drops and recreates the
   `transteira` schema of the dedicated database `transteira_e2e`
   (`postgres-init/02-e2e.sql`, same owner / app roles as the Go tests, row-level
   security enforced; the database is created on the fly in a cluster started
   before that script existed).
2. Starts a fake clamd in the runner process (`support/fakeclamd.ts`: PING,
   INSTREAM, EICAR detected; the signature is assembled at runtime).
3. Starts `bin/transteira serve` on `127.0.0.1:<free port>` (Linux: see below) with a temporary root
   (data, database, backups, secrets: random master key and setup token), the
   security log in `.run/logs/`, `TT_CLAMAV_MAX_SCAN_BYTES=1048576` (larger files
   are "not scanned"), tenant and system SMTP to Mailpit, and waits for `/healthz`.
4. Writes `.run/caddy/Caddyfile` with that port and (re)creates the `caddy`
   service: `tls internal` for `admin.localhost`, `entity-a.localhost`,
   `entity-b.localhost`, buffering off, long timeouts.
5. Seeds through the admin API (`support/seed.ts`): setup + TOTP, entities A and
   B (internal networks, domain `example.com`, SMTP to Mailpit), a delegated
   admin of A without TOTP, an API token of A. Everything is written to
   `.run/state.json` (throwaway credentials of the run).
6. Signs both admins in through the real login screen once and saves
   `.run/storage-super.json` and `.run/storage-delegate.json`.

The teardown stops the server, the fake clamd and Caddy and deletes the temporary
root; `.run/` is kept for diagnosis (`server.log`, `logs/security.log`).

Network of the server under test (`support/env.ts`, `listenHost()` and `trustedProxies()`):
Caddy runs in Docker and reaches the server on the host through `host.docker.internal`.

- Windows and macOS (Docker Desktop): those connections arrive on the loopback interface, so
  the server listens on `127.0.0.1` and trusts `127.0.0.1,::1` only.
- Linux: `host.docker.internal` is the gateway of the default Docker bridge (`host-gateway`,
  read with `docker network inspect bridge`, usually `172.17.0.1`). The server listens on that
  address only, never on every interface, and the API helpers call it there. It trusts that
  address (`/32`, the source of the helpers' direct calls) and the subnet of the compose
  network Caddy is attached to (`transteira-test_default`, read with `docker network inspect`;
  Caddy's connections to a host address are not translated), never the whole `172.16.0.0/12`.
  The values are computed once in the runner and inherited by the workers.

### Writing a test

Import `test` and `expect` from `support/fixtures.ts`, never from `@playwright/test`:

- every browser context is guarded: a CSP violation, an uncaught page error, a
  request to another origin than the three hosts, an HTTP 5xx or an unexpected
  console error fails the test. Declare provoked errors with
  `guards.allowHttpError(409, /\/api\/v1\/transfers\//)` (or
  `guards.allowConsoleErrors(/pattern/)`); the anonymous session probes (401 on
  `deposit-sessions/current` and `admin/me`) are allowed by default;
- `checkA11y(page)` runs axe-core (WCAG 2.1 A and AA, from `node_modules`, no
  CDN) and expects zero violations; call it on each screen visited;
- `expectCleanStorage(page)`: only `tt.lang` in `localStorage`, nothing in
  `sessionStorage` (`{ allowSession: ['tt.upload'] }` during a resumable upload);
- `test.use({ storageState: STORAGE_SUPER })` (or `STORAGE_DELEGATE`) starts
  signed in. These sessions are shared by the whole run: a test that signs out
  or changes credentials signs in in its own context (`newContext()` +
  `loginAsSuperAdmin` / `loginAsDelegate`). `freshTotp` never reuses a TOTP step,
  across workers;
- each context has its own client IP (random in `10.0.0.0/8`, internal), sent in
  the test-only `X-E2E-Client-IP` header that only the e2e Caddy turns into
  `X-Forwarded-For` / `X-Real-IP`; `test.use({ clientIp: '203.0.113.7' })` or
  `newContext({ clientIp: externalIp() })` simulates an external client;
- use unique addresses (`internalEmail('sender')`, `externalEmail('guest')`) and
  read mails with `support/mailpit.ts` (`waitForCode`, `waitForMail`, `linksOf`);
- no fixed sleep (`waitForTimeout` is refused by ESLint): wait for a condition.

### Documentation screenshots

`make screenshots` runs `specs/screenshots.spec.ts` with `SCREENSHOTS=1` on SQLite: the
`screenshots` project of `playwright.config.ts` then runs that file alone, on one worker, in
order (normal runs exclude it, and it skips itself without `SCREENSHOTS=1`). It takes about two
minutes.

- The catalog (`support/screenshots.ts`) lists every screen: name (kebab-case, file name),
  screen (host, route, state) and profile (`depositor`, `recipient`, `delegated-admin`,
  `super-admin`). Each entry is captured in English and in French (browser locale) into
  `docs/user/screenshots/<lang>/<name>.png`; `manifest.json` is rewritten from the catalog
  (sorted by name, `path` = `{lang}/<name>.png`) and images no longer listed are deleted.
- Determinism: the run holds only the seed and the fixed data of the spec (Entity A,
  `alice@example.com`, `camille@example.com`, `bob@example.com`, `dana@example.org`, fixed file
  names and contents), one fixed client IP per profile, `page.clock.setFixedTime`, a 1280 x 800
  viewport, reduced motion and no caret.
- Volatile values are replaced by fixed characters of the same length (so that table columns do
  not move) and masked in gray: identifiers, SHA-256 fingerprints and digests, token prefixes and
  secrets, dates and times, the disk usage of the machine, date inputs, the TOTP QR code and key.
  A mask cannot cover a modal dialog (top layer): `shoot(..., { inPlace })` paints those areas
  through the CSSOM (a style element would violate the CSP and fail the guards).
- Two consecutive runs change only a handful of images, by a few pixels (font antialiasing,
  background dithering): review `git status docs/user/screenshots` before committing.
- `make screenshots-check` (`scripts/check-screenshots.mjs`, `node --test`) fails on a missing
  image, an image outside the manifest, a size other than 1280 x 800, an image above 600 KiB,
  a badly formed or unsorted entry, and a manifest that no longer matches the catalog of
  `support/screenshots.ts` (names, screens, profiles: the catalog was edited without
  `make screenshots`).

Adding a screen: add it to the catalog, capture it in the spec (`shoot(page, lang, name)`),
run `make screenshots`, then commit the images and the manifest.

### Debugging

- HTML report: `cd test/e2e && npx playwright show-report playwright-report/sqlite`.
- Traces are kept for failed tests only:
  `npx playwright show-trace test-results/<engine>/<test>/trace.zip`.
- A failed test may print `Internal error: step id not found: fixture@NN`: a
  harmless Playwright 1.55 message (the failure screenshot is attached while the
  guard fixture tears down); the test result and attachments are correct.

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `E2E_DB` | `sqlite` | Engine of one Playwright run (`make e2e` sets it). |
| `E2E_DBS` (make) | `sqlite postgres` | Engines run by `make e2e`. |
| `E2E_ARGS` (make) | | Extra `playwright test` arguments. |
| `E2E_BROWSER_INSTALL` (make) | `1` | `0`: never download Chromium. |
| `E2E_WORKERS` | half the CPUs, 1 to 4 | Parallel workers. |
| `E2E_RETRIES` | `0` | Retries (traces then recorded on the first retry). |
| `E2E_HTTPS_PORT` | `443` | Port Caddy publishes on `127.0.0.1`. |
| `E2E_LISTEN_HOST` | `127.0.0.1` (Linux: the Docker bridge gateway) | Server listen address, also used by the API helpers (Caddy reaches it through `host.docker.internal`). |
| `E2E_TRUSTED_PROXIES` | `127.0.0.1,::1` (Linux: the bridge gateway `/32` and the compose network subnet) | `TT_TRUSTED_PROXIES` of the server: where Caddy's connections and the helpers' calls arrive from. |
| `E2E_COMPOSE_NETWORK` | `transteira-test_default` | Docker network of Caddy, whose subnet is trusted on Linux. |
| `E2E_POSTGRES_DSN`, `E2E_POSTGRES_MIGRATE_DSN` | app / owner roles on `transteira_e2e` | PostgreSQL DSNs of the server. |
| `E2E_MAILPIT_API`, `E2E_MAILPIT_SMTP_PORT` | `http://127.0.0.1:58025`, `51025` | Mailpit. |
| `E2E_SERVER_BINARY` | `bin/transteira` | Server binary (copied to a `.exe` on Windows). |
| `E2E_LOCK_TIMEOUT` | `45` | Minutes a run waits for the run lock. |
| `E2E_LOCK_MAX_AGE` | `120` | Minutes after which a lock is considered stale even if its PID exists. |
| `SCREENSHOTS` | | `1`: run only the screenshots project (`make screenshots`). |

Only one run at a time on the machine: see "One run at a time" above.

### In `make check`

`make check` runs `e2e-lint` and `screenshots-check` with the static checks, then `test` and
`cover`, then `e2e` (both engines; `make check` does not modify versioned files, so it never
regenerates the screenshots). Offline with Chromium cached: `make check E2E_BROWSER_INSTALL=0
NPM_AUDIT=0`.

## Deployment smoke test (`test/deploy`, `make deploy-smoke`)

End-to-end test of the **production** files (`Dockerfile`, `deploy/`, the reference Caddy of
`integrations/reverse-proxy/caddy/`), as an operator would deploy them, with the real ClamAV.
It is **not** part of `make check`: it needs Internet access (ClamAV signature updates by the
`clamav-update` service) and takes a few minutes. Run it before committing any change to the
Dockerfile, `deploy/` or the Caddy configuration.

| Command | Effect |
|---|---|
| `make deploy-smoke` | Build the image (`make docker`), then run the test on SQLite, then on the PostgreSQL overlay. |
| `make deploy-smoke DEPLOY_SMOKE_DB=sqlite` | One engine only (`sqlite`, `postgres` or `both`). |
| `bash scripts/deploy-smoke.sh [sqlite\|postgres\|both]` | Same, without rebuilding the image (`TRANSTEIRA_IMAGE`, default `transteira:local`). |

Files: `scripts/deploy-smoke.sh` (orchestration, Docker checks), `test/deploy/smoke.mjs` (HTTPS
checks, Node without dependencies), `test/deploy/docker-compose.smoke*.yml` (overrides).

### What a run does, per engine

1. Copies `deploy/` to a temporary folder, creates the secrets with `deploy/init-secrets.sh`
   (`--postgres` for PostgreSQL) and a `.env` from `deploy/.env.example` (admin host
   `admin.smoke.localhost`, `TT_TRUSTED_PROXIES` = the smoke proxy address). The setup token is
   **not** set: the test reads the one TransTeira prints in its log, as documented for operators.
2. Creates the network `transteira-smoke-proxy` (subnet `172.31.250.0/24`, distinct from the
   `172.30.0.0/24` of a real installation) and starts the reference Caddy compose file with
   `test/deploy/docker-compose.smoke-caddy.yml`: Caddy at `172.31.250.10`, HTTPS published on
   `127.0.0.1:<free port>` only. Its Caddyfile is generated from the reference one with exactly
   two changes: the site addresses become `admin.smoke.localhost, transfer.smoke.localhost`, and
   that site gets `tls internal` (Caddy's internal CA instead of ACME). Every other directive
   (timeouts, buffering, compression, log redaction, HSTS, `X-Real-IP`) is used as is.
3. Starts `deploy/docker-compose.yml` (+ `docker-compose.postgres.yml`) under the compose project
   `transteira-smoke-<engine>`; `test/deploy/docker-compose.smoke.yml` (and
   `docker-compose.smoke-postgres.yml`) rename every fixed container and volume name of the
   production files, so that a real installation on the same host (`transteira`,
   `transteira_data`...) is never touched. Waits until `transteira` is healthy.
4. Docker checks: processes as UID 10001 (clamd 100, freshclam 100, PostgreSQL 70), read-only root
   file system, all capabilities dropped, `no-new-privileges`, no published port on any service,
   clamd on the internal network only, freshclam alone on the egress network and its first update
   check completed, PostgreSQL on the internal `db` network only.
5. HTTPS through Caddy, with the certificate checked against Caddy's root CA (`smoke.mjs`):
   `/healthz` 200 (database, real clamd), version, first-run setup and TOTP confirmation, tenant
   `transfer.smoke.localhost`, public page with CSP, HSTS and `nosniff`; a deposit with an invalid
   API token is refused and logged in the security log with the real client IP (never the proxy
   address); an API token restricted to that IP deposits, with tus, a random file and an EICAR
   file built at runtime: the real clamd marks EICAR infected (`file.infected` audited with the
   client IP), the recipient view lists the clean file only, the file and the ZIP archive download
   with the original SHA-256, and the data volume holds no plaintext fragment nor original name.
6. `transteira version`; `transteira backup`: with SQLite a copy that passes `PRAGMA quick_check`
   and holds the tenant; with PostgreSQL a refusal that points to `db-backup`, the one-shot
   `migrate` container exited 0, and an on-demand `pg_dump` in `db-backup` holds the tenant.
7. Always removes the containers, networks, volumes and secrets of the run (also on failure,
   after printing the last logs), and fails if a volume of a real installation (`transteira_*`)
   appeared.

The signature volume `transteira-smoke-clamav-db` is kept between runs as a cache of the public
ClamAV signatures (on the first run Docker seeds it from the signatures shipped in the image and
freshclam updates it). `DEPLOY_SMOKE_KEEP_SIGNATURES=0` deletes it at the end.

| Variable | Default | Meaning |
|---|---|---|
| `DEPLOY_SMOKE_DB` | `both` | Make only: engines to test. |
| `TRANSTEIRA_IMAGE` | `transteira:local` | Image under test (script only; the make target builds and uses `transteira:local`). |
| `DEPLOY_SMOKE_SUBNET` / `DEPLOY_SMOKE_PROXY_IP` | `172.31.250.0/24` / `172.31.250.10` | Smoke proxy network, if the default subnet is taken on the host. |
| `DEPLOY_SMOKE_CLAMAV_DB_VOLUME` | `transteira-smoke-clamav-db` | Signature cache volume. |
| `DEPLOY_SMOKE_KEEP_SIGNATURES` | `1` | `0`: delete the signature cache at the end. |
| `DEPLOY_SMOKE_TIMEOUT` | `900` | Seconds to wait for a healthy stack. |

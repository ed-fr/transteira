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

Files: `scripts/deploy-smoke.sh` (orchestration, Docker checks), `scripts/lib/stack.sh` (stack logic
shared with the 20 GB test), `test/deploy/smoke.mjs` (HTTPS
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

## Big-file test (`test/bigfile`, `make bigfile`)

CLAUDE.md section 24.2: a random file of 5 GiB (20 GiB with `BIGFILE=1`, so in `make check-full`),
generated on the fly (never stored on the client),
is deposited with an API token through tus and the **real reference Caddy** in Docker to the
**production stack** (`deploy/`, real ClamAV), with the connection cut in the middle of the upload
and resumed from the offset the server reports; the file is then downloaded in full, and once more
with a cut and a `Range` resume; every SHA-256 (expected, computed by the server, downloaded,
resumed) must match, and the memory of the server must stay bounded and flat. It is the **last
gate of `make check`**, on SQLite then PostgreSQL, when the big-file chain changed since its last
green run (`scripts/bigfile-auto.sh` lists the paths and keeps the fingerprint of that run in the
git-ignored `.cache/bigfile.stamp`); `make check-full` always runs it, before every release.

| Command | Effect |
|---|---|
| `make bigfile` | Build the image (`make docker`), then run the test on both engines (5 GiB each; 20 GiB with `BIGFILE=1`). |
| `make bigfile BIGFILE_BYTES=1073741824 BIGFILE_DBS=sqlite` | Quick run: 1 GiB, one engine (about 3 minutes). |
| `make check-full` | `make check` with the test forced at 20 GiB (`BIGFILE=1`). **Required before every release.** |
| `make check BIGFILE=0` | Skip it even if its chain changed (prints a reminder). **Never before a release.** |
| `make bigfile-clean` | Remove what a failed `BIGFILE_KEEP=1` run left (`transteira-bigfile-*` only). |

Files: `scripts/bigfile.sh` (orchestration, preflight, sampler, cleanup), `scripts/lib/stack.sh`
(stack logic shared with the deployment smoke test), `scripts/lib/memsampler.sh` (memory sampler,
run in a helper container), `test/bigfile` (the Go client, build tag `bigfile`; its configuration,
cut plan and report are unit tested by `make test`), `test/bigfile/memcheck` (memory criteria and
summary), `test/internal/seeded` (deterministic content and its SHA-256).

### Prerequisites

- **Disk:** the Docker disk needs `BIGFILE_BYTES` x 1.15 + 5 GiB free (about 28 GiB for 20 GiB):
  the encrypted file, the upload in progress, the database, the logs. Each engine's stack is
  deleted with its volumes before the next one, so the budget is one file, not two. Give Docker
  Desktop **60 to 80 GB** of disk (Settings > Resources). The preflight measures the used and free
  space of the file system that holds the Docker volumes, from a container. With Docker Desktop on
  Windows, the volumes live in a WSL2 disk image (VHDX, under `%LOCALAPPDATA%\Docker\wsl` or the
  custom folder of the settings) that grows on demand, so the space seen inside the VM is only its
  maximum size; the preflight takes **min(free inside the VM, free on the host drive of the image
  + (size of the image - space used inside))**: the space already allocated in the image but
  unused is writable without growing it. It fails with the figures when space is short;
  `BIGFILE_MIN_FREE` (bytes or a size such as `40GiB`) replaces the estimate when it is wrong for
  your setup. The disk image does not shrink by itself once the volumes are deleted (Docker
  Desktop reclaims the space with its troubleshoot "Clean / Purge data" action, or a compaction of
  the VHDX).
- **Docker Desktop on Linux or macOS:** the volumes also live in a VM disk image (`Docker.raw` on
  macOS, a QCOW2/raw image on Linux) that grows on demand up to the size set in Settings >
  Resources. The preflight only sees the space inside the VM: check yourself that the host drive
  holding the image can still give it about `BIGFILE_BYTES` x 1.15 + 5 GiB, or set
  `BIGFILE_MIN_FREE`. With Docker Engine on Linux (no VM), the measure is the real free space of
  the Docker root directory.
- **Memory:** at least 7 GiB for Docker (`BIGFILE_MIN_DOCKER_MEM`): clamd may use its 4 GiB limit,
  transteira 1 GiB, freshclam 1.5 GiB while it tests new signatures, PostgreSQL 1 GiB, plus Caddy.
- **Network:** none for the test itself; the ClamAV signatures come from the cache volume
  `transteira-bigfile-clamav-db` (seeded from the image on the first run, then refreshed by
  freshclam when Internet is available).
- **Duration:** measured on a Windows 11 workstation with Docker Desktop (WSL2), 20 GiB through
  Caddy: 30 s of local hashing, the upload (cut and resume included) at about 88 to 93 MiB/s,
  **3 min 40 s**, the full download at about 92 MiB/s (3 min 40 s), the abandoned and resumed
  download as long again, so **about 12.5 minutes per engine, 25 minutes for both** with the
  stacks. 1 GiB takes about 3 minutes per engine, most of it clamd scanning the file (above
  `TT_CLAMAV_MAX_SCAN_BYTES`, 2 GiB, the file is delivered unscanned and that wait disappears;
  `BIGFILE_CLAMAV_MAX_SCAN_BYTES=1048576` makes a small run skip it too).
- **cgroups:** the memory sampler reads cgroup v2 (Docker Desktop, current distributions) and
  knows the cgroup v1 file names, but **only cgroup v2 is tested**.

### What a run does, per engine

1. Preflight (once): Docker, image, memory, disk (above); the client and `memcheck` are compiled
   before anything starts.
2. The stack of the deployment smoke test (`scripts/lib/stack.sh`): `deploy/` copied with fresh
   secrets, compose project `transteira-bigfile-<engine>`, its own proxy network
   `transteira-bigfile-proxy` (`172.31.249.0/24`, Caddy at `.10`) and internal/db subnets
   (`172.31.247.0/24`, `172.31.248.0/24`), every fixed name remapped by
   `test/deploy/docker-compose.smoke*.yml`; the reference Caddyfile with the hosts
   `admin.bigfile.localhost, transfer.bigfile.localhost` and `tls internal`, HTTPS on
   `127.0.0.1:<free port>`. `TT_CLAMAV_MAX_SCAN_BYTES` keeps its default (2 GiB) unless
   `BIGFILE_CLAMAV_MAX_SCAN_BYTES` lowers it.
   A Mailpit container (`test/deploy/docker-compose.bigfile-mail.yml`, own network
   `BIGFILE_MAIL_SUBNET`, default `172.31.246.0/24`, HTTP API on `127.0.0.1:<free port>`) receives the
   tenant mail: no API answer carries a download link, so the client reads the recipient's personal
   link from their mail (`BIGFILE_MAIL_API`).
3. Once transteira is healthy: Caddy's root CA is copied, the setup token read from the transteira
   log, the memory sampler started (below) and the offset between its clock and the client's
   measured.
4. The client (`TestBigFile`) runs with the variables below and writes
   `test/bigfile/out/report-<engine>.json`; the clock offset is measured again.
5. transteira and Caddy must never have restarted nor been OOM-killed (`docker inspect`:
   `RestartCount` 0, `OOMKilled` false: a crashed server replaced by a healthy one could go
   unnoticed by the client), and the transteira log must hold no Go `panic:`; checked after the
   client and again just before the teardown (and printed, on any failure, before the teardown).
6. `memcheck` prints the report summary and checks the memory; then the stack, its volumes and the
   sampler are **always** removed (trap), also on failure or Ctrl+C, after printing the last logs
   (the setup token redacted). Nothing outside `transteira-bigfile-*` is touched, and the run
   fails if a volume of a real installation (`transteira_*`) appeared.

Client interface (set by the script; `go test -tags bigfile -run TestBigFile -v ./test/bigfile`
reads the same variables): `BIGFILE_BASE_URL`, `BIGFILE_ADMIN_URL`, `BIGFILE_CA_FILE`,
`BIGFILE_RESOLVE` (`host=127.0.0.1,...`), `BIGFILE_SETUP_TOKEN`, `BIGFILE_BYTES`, `BIGFILE_ENGINE`,
`BIGFILE_REPORT`, `BIGFILE_MAIL_API`, and when set `BIGFILE_CHUNK`, `BIGFILE_CUT_AT`, `BIGFILE_DL_CUT_AT`,
`BIGFILE_SEED`, `BIGFILE_SCAN_TIMEOUT`, `BIGFILE_CLAMAV_MAX_SCAN_BYTES` (see
`test/bigfile/config.go`). File downloads send `Accept-Encoding: zstd, gzip` like a browser, with
the transparent decompression of Go off: a proxy that compressed the file would show up as a
`Content-Encoding` header, and the client fails on it. A failure message never copies the answer
of `/admin/setup` or of the API token creation (TOTP secret, token): only the problem code and
title.

### Memory criteria

A helper container (`<project>-memsampler`: BusyBox of the pinned Caddy image, no network, no
capability, read-only, user nobody, at most 32 processes, a `json-file` log capped at 100 MB, the
host cgroup tree mounted read-only) reads every second the cgroup of transteira and of Caddy,
saved to `test/bigfile/out/mem-<engine>.csv` as
`unix ms, container, anon, current, file, kernel, sock, swap` (bytes; `swap` is
memory.swap.current, 0 without swap accounting). The transteira image has no shell, and
`docker stats` is too slow (1 to 2 s per call) and counts part of the page cache.

- The **checked** metric is `anon` + `swap`: the heap, stacks and buffers of the server (memory.stat
  `anon`), what a leak would grow, plus what of it the kernel pushed to swap (a leak swapped out
  must not hide). `current` (memory.current, the base of `docker stats`) also counts the page
  cache of the file written to and read from the data volume: the kernel fills it up to the
  container limit (1 GiB) and reclaims it on demand. It is reported, never checked; so is the peak
  of the swap.
- **Peak:** the largest `anon` + `swap` sample of the whole run is at most `BIGFILE_MAX_MEM`
  (256 MiB; the 20 GiB runs peak at about 97 MiB).
- **Coverage:** the samples must cover the upload and download windows of the report: at least 8
  samples in each, and no gap longer than 5 s between two consecutive samples (the bounds of the
  window count, so a sampler that started late or died early fails). A passed report without both
  windows fails too.
- **Clocks:** the report is timed with the clock of the client (the host), the samples with the
  clock of the Docker host (the VM, with Docker Desktop). The script measures their offset after
  the sampler starts and after the client ends (`docker exec` of `cat /proc/uptime` in the
  sampler, between two host readings, best of three), the windows are shifted by the mean offset,
  and an offset above `BIGFILE_MAX_CLOCK_OFFSET` (2 s) fails: resynchronize the VM clock
  (restart Docker Desktop, `wsl --shutdown`) when it happens.
- **No upward trend**, over the upload (`upload-total` phase of the report) and over the downloads
  (`download-full` to the end): the mean of the last quarter of the window's samples is at most the
  mean of its first quarter x 1.25 + 64 MiB. The ratio absorbs the working set that settles once a
  transfer runs, the slack the noise of a server that idles at a few tens of MiB; a leak per byte
  or per chunk breaks it on a 20 GiB run.
- Caddy's peak is reported only.

Measured (1 GiB, both engines): `anon` 20 MiB at rest, about 85 MiB during the upload and 100 MiB
during the downloads, flat; Caddy 16 MiB; `current` at the 1 GiB limit (page cache).

### Reading the output

The end of the run prints, per engine: the total time (stack start, client), the client result
(scan status, SHA-256), the upload cut and resume offsets (bytes sent again after the cut), the
download cut, every phase with its duration and throughput, then the memory lines (peak, trend of
each window with its limit, Caddy). `test/bigfile/out/` (ignored by git) keeps the JSON report and
the CSV samples of the last run of each engine. With `BIGFILE_KEEP=1`, a failed stack stays up and
the script prints how to inspect it (logs, `docker stats`, the CA and URL) and how to clean it.

| Variable | Default | Meaning |
|---|---|---|
| `BIGFILE` | `auto` | `auto`: in `make check`, run only when the big-file chain (the module packages the server and the test client depend on, test files aside, plus image, deployment, reference Caddy, scripts, Makefile) or the `BIGFILE_*` settings changed since the last green run of `make check`; `1`: always (`make check-full`); `0`: skip (never before a release). A plain `make bigfile` always runs and does not record its result. |
| `BIGFILE_BYTES` | `5368709120` (`21474836480` with `BIGFILE=1`) | File size (1 MiB to 20 GiB, the largest transfer a tenant may allow). |
| `BIGFILE_DBS` | `both` | `sqlite`, `postgres` or `both` (in that order). |
| `BIGFILE_KEEP` | `0` | `1`: keep a failed stack for diagnosis. |
| `BIGFILE_MAX_MEM` | `256MiB` | Largest `anon` + `swap` sample of the server. |
| `BIGFILE_CHUNK`, `BIGFILE_CUT_AT`, `BIGFILE_DL_CUT_AT`, `BIGFILE_SEED` | client defaults | PATCH size (1 GiB), upload and download cut fractions (0.43, 0.3), content seed. |
| `TRANSTEIRA_IMAGE` | `transteira:local` | Image under test (script only). |
| `BIGFILE_SUBNET` / `BIGFILE_PROXY_IP` | `172.31.249.0/24` / `172.31.249.10` | Proxy network, if the subnet is taken. |
| `BIGFILE_INTERNAL_SUBNET` / `BIGFILE_DB_SUBNET` | `172.31.247.0/24` / `172.31.248.0/24` | Internal and db networks. |
| `BIGFILE_SCAN_TIMEOUT` | `30m` | Client wait from finalize to available (Go duration): a real clamd scans a file up to its limit. |
| `BIGFILE_CLAMAV_MAX_SCAN_BYTES` | `2147483648` | 1048576 to 2147483648: set as `TT_CLAMAV_MAX_SCAN_BYTES` of the stack and given to the client, which expects `not_scanned_too_large` above it and `clean` below (the clamd limits of `deploy/` stop at 2 GiB). |
| `BIGFILE_CLAMAV_DB_VOLUME` | `transteira-bigfile-clamav-db` | Signature cache volume; must start with `transteira-bigfile-` (`bash scripts/bigfile.sh clean --signatures` deletes it). |
| `BIGFILE_TIMEOUT` / `BIGFILE_CLIENT_TIMEOUT` | `900` / `4h` | Wait for a healthy stack (s); client timeout (Go duration). |
| `BIGFILE_MIN_DOCKER_MEM` | `7GiB` | Least Docker memory accepted by the preflight. |
| `BIGFILE_MIN_FREE` | `BIGFILE_BYTES` x 1.15 + 5 GiB | Disk space required by the preflight (bytes or a size such as `40GiB`). |
| `BIGFILE_MAX_CLOCK_OFFSET` | `2s` | Largest offset between the clocks of the samples and of the client (`ms`, `s` or `m`). |

# Changelog

All notable changes to TransTeira are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- OpenAPI 3.1 specification of the V1 API (`api/openapi.yaml`).
- Project layout proposal (`docs/architecture/project-structure.md`).
- STRIDE threat model (`docs/security/threat-model.md`).
- Claude Code project settings and specialised agents (tests, security review, code review).
- Go module `github.com/ed-fr/transteira` with pinned tools (golangci-lint, govulncheck,
  oapi-codegen) run through `go tool`; gitleaks is pinned and run with `go run` in its own
  module graph.
- Local quality pipeline `make check`: formatting, vet, lint, govulncheck, Spectral OpenAPI lint,
  generated-code and `.env.example` freshness, tests and coverage thresholds.
- Pre-push gitleaks hook (`make hooks`).
- Packages `internal/version`, `internal/config`, `internal/api/problem` (RFC 9457),
  code generated from the OpenAPI specification (`internal/api/gen`), and the
  `transteira` binary skeleton.
- AGPL-3.0 `LICENSE`, `README.md`, `SECURITY.md`, `.env.example`.
- Data layer `internal/store` on SQLite (pure Go driver) and PostgreSQL (pgx): query registry
  validating every tenant query (exactly one `tenant_id = ?`, single table), typed scoped and
  system executors, repositories for tenants, network rules and blocklist.
- PostgreSQL row-level security as a second isolation layer, with two roles (owner for
  migrations via `TT_DB_MIGRATE_DSN`, runtime role owning nothing) and a startup check refusing
  unsafe role configurations.
- Versioned migrations applied by `transteira migrate` (checksums, lock, refusal of a newer schema).
- Packages `internal/tenant` (Host normalisation, cached resolver) and `internal/id` (prefixed
  ULIDs, high-entropy tokens).
- PostgreSQL test environment (`test/docker-compose.test.yml`) and adversarial tenant isolation
  tests (`test/isolation`); `make check` now requires PostgreSQL.
- `docs/install/postgresql.md`: PostgreSQL role setup.
- `transteira serve`: HTTP server on the standard library mux with the generated strict server
  interface; middlewares for panic recovery, request IDs, real client IP from trusted proxies only,
  tenant resolution by `Host` (unknown hosts → `421` and security log), security headers, per-IP
  rate limiting, JSON body limit and maintenance mode for deposit operations. Unknown hosts are
  rejected on every path except `/healthz` and `/api/openapi.yaml`. A trusted proxy that sends no
  valid client address yields an unknown client (fail closed). Startup is refused when trusted
  proxies cover every address or use a prefix shorter than /8 (IPv4) or /32 (IPv6).
- Per-operation read and write deadlines (30 s, 2 min for images) on non-streaming routes;
  graceful shutdown within Docker's default stop delay.
- `rate_limited` security events are written at most once per client key and scope every 10 s;
  unknown hosts have their own per-IP limiter (burst of 10, then one every 12 s, then `429`).
- `/healthz` (database, ClamAV `PING`, storage; shared and cached for 3 s), `/api/openapi.yaml` and `GET /api/v1/version`;
  `transteira healthcheck` for container health checks.
- Security log (`TT_LOG_DIR/security.log`) in a stable, injection-proof line format, with
  fail2ban (filter, jail, `DOCKER-USER` action) and CrowdSec (parser, scenarios) integrations and
  `docs/operations/security-log.md`.
- `internal/ratelimit` (keyed token buckets and sliding lockout windows whose locked entries are
  never evicted) and `tools/genstubs` (generated not-implemented stubs for every API operation).
- Problem code `method-not-allowed` (405).

### Changed
- OpenAPI: every operation and parameter is described; the SMTP password is removed with an
  explicit `removePassword` flag instead of `null` and must be resent when the SMTP server
  changes; public deposit refusals use the generic `deposit-not-allowed` code; every operation
  documents the `500 internal-error` response.
- Claude Code deny rules extended to key files, production `.env` files and PowerShell.
- OpenAPI: entity identifier patterns follow the strict ULID format
  (`^<prefix>_[0-7][0-9A-HJKMNP-TV-Z]{25}$`); `vch_` and `upl_` tokens carry at least 128 bits;
  FQDNs may end with a punycode label.
- Tenant queries may reference `tenant_id` only in the tenant slot; an alias named `tenant_id` is
  refused.

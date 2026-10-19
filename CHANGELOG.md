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

### Changed
- OpenAPI: every operation and parameter is described; the SMTP password is removed with an
  explicit `removePassword` flag instead of `null` and must be resent when the SMTP server
  changes; public deposit refusals use the generic `deposit-not-allowed` code; every operation
  documents the `500 internal-error` response.
- Claude Code deny rules extended to key files, production `.env` files and PowerShell.

# TransTeira

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.0.0--dev-lightgrey.svg)](CHANGELOG.md)

**TransTeira** is a self-hosted, multi-tenant large file transfer service, in the spirit of
WeTransfer or SwissTransfer, designed for organisations made of several entities.

> **Status: under development.** The first version (V1) is being built. Nothing is ready for
> production yet.

## Highlights (V1 scope)

- **Multi-tenant**: one instance serves several entities, each with its own domain name,
  branding, language, SMTP server, internal IP ranges and email domains, quotas and strictly
  isolated data.
- **Very large files**: resumable uploads with the [tus](https://tus.io) protocol, end-to-end
  streaming, up to 20 GB per transfer.
- **Security by default**: encryption at rest (AES-256-GCM, envelope encryption, master key
  rotation, crypto-erase), ClamAV antivirus scanning, admin authentication with mandatory TOTP
  for the super admin, strict HTTP security headers, security log ready for fail2ban and CrowdSec.
- **Simple for users**: no account for depositors (email verification by one-time code),
  invitations for external users, password-protected transfers, SHA-256 fingerprints, ZIP
  download generated on the fly.
- **API first**: documented REST API ([OpenAPI 3.1](api/openapi.yaml)) with per-entity API tokens.
- **Light to operate**: a single Go binary in a minimal Docker image, SQLite by default or
  PostgreSQL, configuration by environment variables, reverse proxy configurations for Caddy,
  Nginx, Traefik and Apache.
- **GDPR minded**: automatic expiry and purges, data subject erasure, technical cookies only.

## Documentation

- [API specification](api/openapi.yaml)
- [Project structure](docs/architecture/project-structure.md)
- [Threat model (STRIDE, in French)](docs/security/threat-model.md)
- [Master key](docs/operations/master-key.md): generate the key and store a copy in a password
  vault **before the first start**; without it, encrypted files cannot be recovered.
- [Security log](docs/operations/security-log.md) (fail2ban, CrowdSec)

Installation, operation and user guides will be published with the first release.

## Development

Requirements: Go 1.27+, GNU make, Node.js (for the OpenAPI linter and the web interface),
Docker. On Windows, run `make` from Git Bash.

```sh
make hooks   # install the pre-push secret scan (gitleaks)
make check   # every quality gate: format, vet, lint, govulncheck, OpenAPI lint, tests, coverage
make help    # all targets
```

There is no CI: `make check` must be green before every commit.

## Security

Please report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

TransTeira is free software released under the
[GNU Affero General Public License v3.0](LICENSE).

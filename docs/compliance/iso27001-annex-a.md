# ISO/IEC 27001:2022 Annex A mapping

Correspondence between the 93 controls of **ISO/IEC 27001:2022 Annex A** and
**TransTeira 2.1**, to help build the Statement of Applicability (SoA) and
to prepare audits.

Français : [docs/compliance/fr/iso27001-annex-a.md](fr/iso27001-annex-a.md).

> This is a template, not legal advice and not a certification. It states
> what the software provides; the inclusion of a control in your SoA, the
> justification and the evidence remain your own. See the [disclaimer](README.md).

## Reading the tables

| Status | Meaning |
|---|---|
| **Covered** | TransTeira provides the control by itself. The operator has nothing more to do than install and keep the software up to date. |
| **Shared** | TransTeira provides a mechanism that the operator must **configure or operate** (settings, keys, hosting, monitoring, procedures). |
| **Operator** | Outside the software: organisation, people, premises, host, suppliers. TransTeira may help marginally; the note says how. |

References: `T-xxx` are threats and `Pxx` decisions of the
[threat model](../security/threat-model.md) (French), the other references are
documents of this repository.

An organisation that runs TransTeira does not inherit these statuses for the
rest of its information system: the mapping covers the **file transfer
service** only.

## Summary of the technological controls

| Need | Mechanism | Controls |
|---|---|---|
| Isolation between entities | Tenant in every record, filtering in the data access layer, PostgreSQL row-level security | 8.3 |
| Authentication | argon2id, mandatory TOTP for the super admin, OpenID Connect, rate limits and lockouts | 8.2, 8.5 |
| Encryption | AES-256-GCM by chunks, envelope encryption, master key rotation, optional end-to-end, one-time secrets | 8.24 |
| Detection and traceability | Audit log, security log, syslog, metrics, alerts | 8.15, 8.16 |
| Malware | ClamAV, ICAP or HTTP engine | 8.7 |
| Deletion | Expiry, crypto-erasure, erasure screen, one-time secrets read once | 8.10 |
| Secure development and delivery | `make check`, signed releases with SBOM | 8.8, 8.25 to 8.29, 8.32 |

## 5. Organizational controls (5.1 to 5.37)

| # | Control | Status | Mechanism and note | Reference |
|---|---|---|---|---|
| 5.1 | Policies for information security | Operator | Your policies. The security policy of the project covers vulnerability reporting only. | [SECURITY.md](../../SECURITY.md) |
| 5.2 | Information security roles and responsibilities | Shared | Defined roles in the software: super admin, delegated admin, auditor (read-only). Assigning people to them is yours. | [Administration guide](../operations/admin.md); P55 |
| 5.3 | Segregation of duties | Shared | Super admin (instance, keys, entities) distinct from delegated admins (their entities) and from the auditor, who cannot modify anything. Delegated admins never read file content. | P18, P55; T-281 to T-285 |
| 5.4 | Management responsibilities | Operator | | |
| 5.5 | Contact with authorities | Operator | | |
| 5.6 | Contact with special interest groups | Operator | | |
| 5.7 | Threat intelligence | Shared | Update check informs the super admin of new releases; `govulncheck` in the project checks. You follow the advisories of the project. | [SECURITY.md](../../SECURITY.md); T-244 to T-248 |
| 5.8 | Information security in project management | Operator | Your own projects. The project itself works from a threat model reviewed at each version. | [Threat model](../security/threat-model.md) |
| 5.9 | Inventory of information and other associated assets | Shared | The threat model lists the assets of the service (section 2); the SBOM of each release lists the software components. Your inventory is yours. | [Threat model](../security/threat-model.md) section 2; [Docker install](../install/docker.md#published-signed-image-alternative-to-building) |
| 5.10 | Acceptable use of information and other associated assets | Shared | Per-entity legal notice and privacy policy, confidentiality levels and recipient domain restrictions enforce your rules. The rules are yours. | [Tenants](../operations/tenants.md); T-194 to T-198 |
| 5.11 | Return of assets | Operator | | |
| 5.12 | Classification of information | Shared | Confidentiality levels per entity, with labels and default values you can change, each level imposing its own rules (password, validity, recipient verification, recipient domains). Choosing the scheme is yours. | [Delegated admin guide](../user/en/delegated-admin.md); T-194 to T-198 |
| 5.13 | Labelling of information | Shared | The level shows in the notification emails, on the download page and in the audit log. | [Delegated admin guide](../user/en/delegated-admin.md); P40 |
| 5.14 | Information transfer | Covered | This is the purpose of the product: encrypted at rest, expiring links, optional password, recipient verification, optional end-to-end encryption, fingerprints, antivirus. TLS in transit is provided by your reverse proxy; the transfer rules and agreements with third parties are yours. One-time secrets (2.1) are a second channel: sealed in the browser, read once, optional passphrase, never scanned. | [Depositor guide](../user/en/depositor.md); T-47 to T-57, T-199 to T-206, T-318 to T-327, T-339 to T-375 |
| 5.15 | Access control | Covered | Deposit only from the entity networks and internal domains, or by invitation, drop link or reply; administration by role and entity; API tokens per entity. A one-time secret is created by an internal user, an invited external or an API token, and read by whoever holds the link. | T-16 to T-20, T-58 to T-73, T-212 to T-215, T-339 |
| 5.16 | Identity management | Shared | Administrator accounts are created in advance by the super admin, never by a login; SSO identities are pinned (issuer, subject). Public users are identified by a verified address, no account. Joiner and leaver processes are yours (disable the account, remove the SSO link). | [Single sign-on](../operations/sso.md); T-286 to T-297, P57, P58 |
| 5.17 | Authentication information | Shared | Passwords hashed with argon2id, TOTP secrets sealed by the master key, recovery codes and API tokens stored hashed, activation links single-use. Password policy and distribution are yours. The optional passphrase of a secret is checked through a verifier, with 5 attempts. | T-58 to T-67, T-68 to T-73; P12, P13, T-350 |
| 5.18 | Access rights | Shared | Roles and entity scoping; delegated admins limited to their entities; the super admin attaches and detaches admins. The periodic review of rights is yours (list of administrators in the administration). | [Administration guide](../operations/admin.md); T-146 to T-150 |
| 5.19 | Information security in supplier relationships | Operator | Hosting, SMTP relay, identity provider, antivirus engine. | [GDPR record](gdpr-processing-record.md) section 7 |
| 5.20 | Addressing information security within supplier agreements | Operator | | |
| 5.21 | Managing information security in the ICT supply chain | Shared | Signed images and SBOM to check what you run; dependencies scanned by `govulncheck`; a published threat model of the build chain. | [Docker install](../install/docker.md#published-signed-image-alternative-to-building); T-117 to T-122, T-332 to T-335 |
| 5.22 | Monitoring, review and change management of supplier services | Operator | | |
| 5.23 | Information security for use of cloud services | Operator | TransTeira is self-hosted. If you host it at a cloud provider, or use a cloud SMTP relay or identity provider, the controls are yours; files stay encrypted with a key outside the data volume. | [Master key](../operations/master-key.md) |
| 5.24 | Information security incident management planning and preparation | Operator | Your procedure. TransTeira provides the detection inputs (see 5.25). | [GDPR record](gdpr-processing-record.md) section 14 |
| 5.25 | Assessment and decision on information security events | Shared | Inputs: audit log, security log, abuse reports, alerts by email and webhook. The assessment is yours. | [Security log](../operations/security-log.md); T-216 to T-221 |
| 5.26 | Response to information security incidents | Operator | Tools: block lists, revocation of tokens and links, deletion of transfers, erasure, maintenance mode, master key rotation. | [Administration guide](../operations/admin.md) |
| 5.27 | Learning from information security incidents | Operator | | |
| 5.28 | Collection of evidence | Shared | Audit log not editable through the application (12 months); signed proofs of deposit and delivery (Ed25519, verifiable offline, kept 12 months); log shipping to a SIEM. Retention beyond that and chain of custody are yours. | [Proofs](../operations/proofs.md); [syslog](../operations/syslog.md); T-298 to T-303, T-187 to T-190 |
| 5.29 | Information security during disruption | Shared | Health check, maintenance mode, documented restore. The plans are yours. | [Backup](../operations/backup.md); [supervision](../operations/supervision.md); T-105 to T-107 |
| 5.30 | ICT readiness for business continuity | Operator | See 8.13 and 8.14. | [Backup](../operations/backup.md) |
| 5.31 | Legal, statutory, regulatory and contractual requirements | Shared | This kit and the legal notice and privacy policy proposals per entity. The register of requirements is yours. | [GDPR record](gdpr-processing-record.md) |
| 5.32 | Intellectual property rights | Shared | AGPL-3.0 licence; the SBOM lists the dependencies and their components. Complying with the AGPL when you modify the software is yours. | [LICENSE](../../LICENSE) |
| 5.33 | Protection of records | Shared | Audit, security logs and proofs kept 12 months with integrity measures; backups of the database. Log file rotation and archives are yours. | [Security log](../operations/security-log.md); T-99 to T-104 |
| 5.34 | Privacy and protection of PII | Shared | Minimisation, retention and purge, cookies strictly technical, erasure by address, crypto-erasure. Record, legal basis and DPO are yours. | [GDPR record](gdpr-processing-record.md); P19, P60 |
| 5.35 | Independent review of information security | Operator | The threat model and the source are public and can feed a review. | [Threat model](../security/threat-model.md) |
| 5.36 | Compliance with policies, rules and standards for information security | Operator | Read-only auditor role and audit log help the checks. | T-281 to T-285 |
| 5.37 | Documented operating procedures | Shared | Installation, operation, upgrade, backup, key rotation, release guides in `docs/`. Your local procedures are yours. | [Docker install](../install/docker.md); [upgrade](../operations/upgrade.md) |

## 6. People controls (6.1 to 6.8)

| # | Control | Status | Mechanism and note | Reference |
|---|---|---|---|---|
| 6.1 | Screening | Operator | | |
| 6.2 | Terms and conditions of employment | Operator | | |
| 6.3 | Information security awareness, education and training | Operator | User and admin guides per profile, in the application help, support training. | [User guides](../user/README.md) |
| 6.4 | Disciplinary process | Operator | | |
| 6.5 | Responsibilities after termination or change of employment | Operator | Disable the administrator account, revoke the API tokens they created. | [Administration guide](../operations/admin.md) |
| 6.6 | Confidentiality or non-disclosure agreements | Operator | | |
| 6.7 | Remote working | Shared | Deposit from outside the entity network is refused by default; the optional mode for verified internal users asks for a code at every deposit and is flagged in the audit log and in abuse detection. | T-212 to T-215; P35 |
| 6.8 | Information security event reporting | Shared | "Report abuse" button on the download page alerts the delegated admin; the security policy gives the way to report a vulnerability. Internal reporting channels are yours. | [SECURITY.md](../../SECURITY.md); T-216 to T-221 |

## 7. Physical controls (7.1 to 7.14)

All physical controls concern the premises and the host and are the
operator's. The two rows with a note are the only ones the software
influences.

| # | Control | Status | Mechanism and note | Reference |
|---|---|---|---|---|
| 7.1 | Physical security perimeters | Operator | | |
| 7.2 | Physical entry | Operator | | |
| 7.3 | Securing offices, rooms and facilities | Operator | | |
| 7.4 | Physical security monitoring | Operator | | |
| 7.5 | Protecting against physical and environmental threats | Operator | | |
| 7.6 | Working in secure areas | Operator | | |
| 7.7 | Clear desk and clear screen | Operator | The administration session ends after an idle timeout (30 minutes by default). | [Administration guide](../operations/admin.md) |
| 7.8 | Equipment siting and protection | Operator | | |
| 7.9 | Security of assets off-premises | Operator | | |
| 7.10 | Storage media | Shared | Files and keys are encrypted on the data volume, and the master key is kept outside it. Handling of media is yours. | [Master key](../operations/master-key.md); T-28 to T-40 |
| 7.11 | Supporting utilities | Operator | | |
| 7.12 | Cabling security | Operator | | |
| 7.13 | Equipment maintenance | Operator | | |
| 7.14 | Secure disposal or re-use of equipment | Shared | Because files are encrypted and keys destroyed on deletion, destroying the master key and the database makes the data volume unreadable. Wiping the media is yours. | [Master key](../operations/master-key.md#crypto-erase) |

## 8. Technological controls (8.1 to 8.34)

| # | Control | Status | Mechanism and note | Reference |
|---|---|---|---|---|
| 8.1 | User endpoint devices | Operator | The application stores nothing on the browser beyond technical cookies; the command-line client keeps its token in an environment variable or a file you protect. | [CLI](../api/cli.md); T-328 to T-331, T-337 |
| 8.2 | Privileged access rights | Covered | Instance-wide actions (entities, quotas, keys, SSO, maintenance, provisioning tokens) are reserved to the super admin, whose TOTP is mandatory; creating a provisioning token asks the TOTP code again; the auditor is read-only. | T-58 to T-67, T-154 to T-158, T-267 to T-276, T-281 to T-285; P49, P55 |
| 8.3 | Information access restriction | Covered | Every record carries its entity; filtering in the data access layer, which requires the tenant of the request; PostgreSQL row-level security as a second layer; separate folder per entity on disk, random file names; admins see metadata, never content. Tested at 100 % coverage and per endpoint. | T-01 to T-04, T-74 to T-79; P18 |
| 8.4 | Access to source code | Shared | The source is public (AGPL). Protection of your own fork and of secrets in it is yours; the project scans for secrets before each push. | T-117 to T-122 |
| 8.5 | Secure authentication | Covered | argon2id, mandatory TOTP for the super admin (recommended for all), recovery codes, opaque server-side sessions in `__Host-` cookies, CSRF protection, idle and absolute timeouts, login rate limits and lockouts, OpenID Connect with PKCE (confidential client, optional `enforced`). One-time email codes for the public users, limited in attempts and in rate. | [Administration guide](../operations/admin.md); [SSO](../operations/sso.md); T-58 to T-67, T-286 to T-297, T-09 to T-15; P1, P2 |
| 8.6 | Capacity management | Shared | Storage quota per entity, 80 % and full alerts, disk space alert to the super admin (85 % by default, adjustable), upload and rate limits, Prometheus metrics. Sizing the host is yours. | [Supervision](../operations/supervision.md); [tenants](../operations/tenants.md); T-123 to T-128 |
| 8.7 | Protection against malware | Shared | Every file is analysed before it can be downloaded (ClamAV by default, ICAP or HTTP API engines), a virus deletes the file, an unavailable engine blocks the file (fail-closed), files too large to scan and end-to-end encrypted files are flagged to the recipient. Updating signatures and protecting the host are yours. The files of one-time secrets are never scanned (end-to-end encrypted, small, on by default but disablable per entity). | [Antivirus](../operations/antivirus.md); T-41 to T-46, T-236 to T-243; P10, P43, P66, T-358 |
| 8.8 | Management of technical vulnerabilities | Shared | `govulncheck` and dependency checks in the project's `make check`; private vulnerability reporting; SBOM of each release; update notice for the super admin. Applying updates, patching the host, Docker and ClamAV is yours. | [SECURITY.md](../../SECURITY.md); [Upgrade](../operations/upgrade.md); T-244 to T-248, T-117 to T-122 |
| 8.9 | Configuration management | Shared | Installation settings in environment variables (documented in `.env.example`), entity settings in the database, validated at start; hardened container (non-root, read-only filesystem, no capabilities); entity configuration export and import without secrets. Keeping the configuration under version control is yours. | [`.env.example`](../../.env.example); [Docker install](../install/docker.md); T-304 to T-308; P24 |
| 8.10 | Information deletion | Covered | Automatic purge at expiry, after the first download or at the maximum number of downloads; destruction of the file keys (crypto-erasure); purge of the expired data; erasure by email address. Copies in backups become unreadable only after a master key rotation and destruction of the old key. One-time secrets are read once: the key of the text is destroyed at the reveal, that of the file at its download, or at expiry or lock; tombstones keep no content and are purged after 30 days. | [Master key](../operations/master-key.md#crypto-erase); T-108 to T-112; P19, P25, T-355, T-370, T-371 |
| 8.11 | Data masking | Covered | Passwords and secrets hashed or sealed by the master key and never logged; no email address in the security log; pseudonym in the audit log after an erasure; statements without IP address; minimal webhook payload. Secret tokens, keys, proofs and verifiers are never logged, and the proxy configurations redact `/s/{token}` and `/api/v1/secret-links/{token}`. | T-99 to T-104; P19, P31, T-345, T-375 |
| 8.12 | Data leakage prevention | Shared | Abuse detection thresholds per sender and per entity (volume, count, recipients, off-hours), block list (addresses, domains, SHA-256), recipient domain allow and deny lists, confidentiality levels, external deposit quotas, alerts. Thresholds and rules are yours to set; TransTeira does not inspect file content. One-time secrets are a small unscanned end-to-end channel, on by default (existing entities included), audited, and disablable or restrictable per entity. | [Delegated admin guide](../user/en/delegated-admin.md); T-194 to T-198, T-216 to T-221, T-343, T-372, P81 |
| 8.13 | Information backup | Shared | Nightly consistent copy of the database (`VACUUM INTO` for SQLite, `pg_dump` for PostgreSQL) into the backup volume; documented restore. Backing up the VM and the volumes, and the master key in a vault outside the VM, are yours; restore tests are yours. A copy taken while a one-time secret was live keeps its sealed text and wrapped key (residual risk D3, see [Backup](../operations/backup.md#crypto-erase-and-copies)). | [Backup](../operations/backup.md); [Master key](../operations/master-key.md); T-113 to T-116, T-351, T-355 |
| 8.14 | Redundancy of information processing facilities | Operator | One application instance per database by design. High availability of the host, the volumes and PostgreSQL is yours. | [Backup](../operations/backup.md) |
| 8.15 | Logging | Covered | Audit log (actor, IP, action, object, per entity, 12 months, not editable) and a dedicated security log with a stable format (fail2ban and CrowdSec), copied to the database; export to syslog (RFC 5424). Centralisation and long-term retention are yours. Audit actions `secret.*` and security events `secret_invalid` and `secret_proof_invalid`. | [Administration guide](../operations/admin.md#audit-log); [Security log](../operations/security-log.md); [syslog](../operations/syslog.md); T-99 to T-104, T-187 to T-190; P22, P41, T-346, T-350 |
| 8.16 | Monitoring activities | Shared | Health check `/healthz`, Prometheus metrics and JSON `/status` (token protected), Grafana and Zabbix templates, security log with fail2ban or CrowdSec, abuse alerts, quota and disk alerts by email and webhook. Running the monitoring and reacting are yours. | [Supervision](../operations/supervision.md); [Security log](../operations/security-log.md); T-191 to T-193, T-178 to T-186; P28 |
| 8.17 | Clock synchronization | Operator | Time synchronisation (NTP) of the host. Codes, sessions and logs rely on the host clock. | |
| 8.18 | Use of privileged utility programs | Operator | The `transteira` administration commands (account recovery, key rotation, backup) run on the host with its access rights; restrict that access. | [Administration guide](../operations/admin.md); [Master key](../operations/master-key.md) |
| 8.19 | Installation of software on operational systems | Shared | Signed multi-architecture image and signed Git tags, SBOM attestation, image `FROM scratch`; verification of the signature and pinning by digest are described. Doing the verification at each update is yours. | [Docker install, section 5](../install/docker.md#published-signed-image-alternative-to-building); [Releasing](../operations/release.md); T-332 to T-335, P67 |
| 8.20 | Networks security | Shared | The container publishes no port; the proxy and the application are on a shared network and the antivirus and the database on an internal one; trusted proxies for the real client IP; IP ranges per entity; unknown host names refused and logged; security headers and strict CSP. Firewall, `DOCKER-USER` rules and proxy are yours. | [Reverse proxy](../install/reverse-proxy.md); [Docker install](../install/docker.md); T-05 to T-08, T-172 to T-177; P24 |
| 8.21 | Security of network services | Shared | Reference proxy configurations (Caddy, Nginx, Traefik, Apache) with timeouts, no buffering and real IP forwarding; verified TLS for SSO, syslog, webhooks and remote antivirus engines. TLS certificates and HSTS are the proxy's. | [Reverse proxy](../install/reverse-proxy.md); P30, P41, P45, P59 |
| 8.22 | Segregation of networks | Shared | Internal Docker network for ClamAV and PostgreSQL, not visible to the proxy; outbound guards against requests to internal networks for webhooks and SSO, and an optional deny list for the SMTP hosts an admin can enter. Network zoning around the host is yours. | [Docker install](../install/docker.md); T-133 to T-136; P21, P30, P59 |
| 8.23 | Web filtering | Operator | Not applicable to the service. Its outgoing connections are limited to the ones you configure (SMTP, webhooks, SSO, update check). | T-133 to T-136; T-245 |
| 8.24 | Use of cryptography | Covered | AES-256-GCM by chunks with a key per file (envelope encryption), master key outside the data volume, rotation without rewriting files, crypto-erasure, optional end-to-end encryption in the browser, Ed25519 signed proofs, signed releases. Key custody (vault copy) and TLS at the proxy are yours. One-time secrets: PBKDF2-SHA-256 at 600 000 iterations for the passphrase, HKDF, TTE2 sealing (`docs/architecture/e2e-format.md` section 3.3). | [Master key](../operations/master-key.md); [E2E format](../architecture/e2e-format.md); T-28 to T-40, T-318 to T-327, T-298 to T-303; P7, P13, P61, P65, P82 |
| 8.25 | Secure development life cycle | Covered | API-first (OpenAPI), threat model updated at each version, review of each step, tests before each commit, all run locally by one command. | [Threat model](../security/threat-model.md); T-117 to T-122 |
| 8.26 | Application security requirements | Covered | Requirements in the specification and in the threat model (per component, with the measures); contract tests check the API against its OpenAPI specification. | [Threat model](../security/threat-model.md) sections 6 and 9 |
| 8.27 | Secure system architecture and engineering principles | Covered | Tenant isolation at the lowest layer, fail-closed antivirus, minimal data, least privilege (roles, database role without `BYPASSRLS`), minimal image. | [Threat model](../security/threat-model.md); [PostgreSQL](../install/postgresql.md); P24 |
| 8.28 | Secure coding | Covered | Strict input decoding, escaped output, strict CSP, linters, `go vet`, native Go fuzzing on user inputs. | T-91 to T-98, T-160 to T-170 |
| 8.29 | Security testing in development and acceptance | Covered | Unit, integration, contract, tenant-isolation and end-to-end tests on SQLite and PostgreSQL, fuzzing, `govulncheck`, secret scanning (gitleaks, pre-push hook), coverage gates (85 % overall, 100 % for isolation, encryption and authentication), large-file test through a real reverse proxy. | [Threat model](../security/threat-model.md) section 9 |
| 8.30 | Outsourced development | Operator | Applies if you commission custom changes; the project is developed in the open under AGPL. | |
| 8.31 | Separation of development, test and production environments | Shared | The project tests with local fictitious entities (`*.localhost`) and a mail catcher. Keeping your production separate from test instances is yours. | |
| 8.32 | Change management | Shared | Semantic versioning, CHANGELOG, signed Git tags and signed images with SBOM, upgrade and rollback guides, automatic schema migrations tested on both engines. Your own approval of upgrades is yours. | [Upgrade](../operations/upgrade.md); [Releasing](../operations/release.md); [CHANGELOG](../../CHANGELOG.md); T-332 to T-335 |
| 8.33 | Test information | Covered | The tests use generated and fictitious data (domains in `example.com`), never production data. | |
| 8.34 | Protection of information systems during audit testing | Operator | The read-only auditor role and the audit log let an audit read without modifying. Scope and timing of penetration tests are yours. | T-281 to T-285; P55 |

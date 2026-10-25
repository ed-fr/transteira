# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately through GitHub:
**Security → Advisories → Report a vulnerability** on
<https://github.com/ed-fr/transteira/security/advisories/new>.

Please include:

- the affected version or commit;
- a description of the issue and its impact;
- steps to reproduce or a proof of concept;
- any suggested fix.

You will receive an acknowledgement within 7 days. We will keep you informed of the progress,
agree with you on a disclosure date, and credit you in the release notes unless you prefer to
remain anonymous.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 (development builds `0.0.0-dev`) | No |

Security fixes are provided for the latest minor version only, as patch releases (1.0.1,
1.0.2...): when 1.1.0 is released, 1.0.x stops receiving fixes. Always run the latest patch
release of the supported version.

Only the provided deployment (`deploy/`, `integrations/`) is supported. The third-party images it
pins by digest (ClamAV, PostgreSQL, reverse proxies) receive security fixes only when you update
them (see the [threat model](docs/security/threat-model.md), T-118).

## Scope

The [threat model](docs/security/threat-model.md) describes the assets, trust boundaries and
assumptions of TransTeira. Issues that require control of the host, of the Docker daemon or of
the master key are out of scope.

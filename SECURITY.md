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

TransTeira has not been released yet. Once released, security fixes will be provided for the
latest minor version.

## Scope

The [threat model](docs/security/threat-model.md) describes the assets, trust boundaries and
assumptions of TransTeira. Issues that require control of the host, of the Docker daemon or of
the master key are out of scope.

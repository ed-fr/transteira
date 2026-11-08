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
| 1.2.x | Yes |
| 1.1.x | No |
| 1.0.x | No |
| < 1.0 (development builds `0.0.0-dev`) | No |

Security fixes are provided for the latest minor version only, as patch releases (1.2.1,
1.2.2...): when 1.3.0 is released, 1.2.x stops receiving fixes. Always run the latest patch
release of the supported version.

Only the provided deployment (`deploy/`, `integrations/`) is supported. The third-party images it
pins by digest (ClamAV, PostgreSQL, reverse proxies) receive security fixes only when you update
them (see the [threat model](docs/security/threat-model.md), T-118).

## Verifying releases

Since 2.0.0, the Docker image (multi-architecture) and the command-line client are signed with
[cosign](https://docs.sigstore.dev/cosign/). The public key is `cosign.pub` at the root of the
repository (also attached to each GitHub release); the signatures are recorded in the public
Rekor transparency log.

cosign.pub SHA-256 fingerprint: (published with the first signed release)

Verification needs cosign 3.0 or later. Compare `sha256sum cosign.pub` with the line above, with
`README.md`, `README.fr.md`, the GitHub release asset and the Docker Hub repository description.
The release tag itself is signed with the maintainer's SSH key listed in
`docs/security/allowed_signers`: `git -c gpg.ssh.allowedSignersFile=docs/security/allowed_signers tag -v vX.Y.Z`.

```sh
# Image: signature of the index (image-digest.txt of the release), then the SBOM attestation
# of your architecture (platform-digests.txt of the release):
cosign verify --key cosign.pub docker.io/<account>/transteira@sha256:<index digest>
cosign verify-attestation --key cosign.pub --type spdxjson \
  docker.io/<account>/transteira@sha256:<platform digest> \
  | jq -r '.payload' | base64 -d | jq '.predicate'

# Command-line client:
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.sigstore.json SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

Details: [installation guide](docs/install/docker.md#5-image) and
[client guide](docs/api/cli.md). Pin the image by digest and verify it at every update.

### Signing key compromise, revocation and replacement

If the private signing key is lost or suspected stolen, or on a scheduled rotation:

1. Generate a new key pair (`make release-keygen`); store the new private key and its password
   in the password vault only.
2. Publish the new `cosign.pub` through the repository (commit), the next GitHub release and the
   README, and announce the change in `CHANGELOG.md` and in a security advisory, stating the
   date from which the old key must no longer be trusted.
3. Re-sign the currently supported images and the client with the new key (a patch release).
4. Retire the old key. Old signatures stay visible in Rekor, which also lets anyone detect
   signatures made with the old key after the announced date.

The maintainer monitors Rekor for entries signed by the project key
([rekor-monitor](https://github.com/sigstore/rekor-monitor), or `rekor-cli search --public-key cosign.pub --pki-format x509` on a Rekor v1 log) to detect an
unexpected signature; see [docs/operations/release.md](docs/operations/release.md).

Operators should compare `cosign.pub` across the repository, the release and the README before
trusting a new key.

## Scope

The [threat model](docs/security/threat-model.md) describes the assets, trust boundaries and
assumptions of TransTeira. Issues that require control of the host, of the Docker daemon or of
the master key are out of scope.

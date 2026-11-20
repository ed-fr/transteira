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
| 2.3.x | Yes |
| 2.2.x | No |
| 2.1.x | No |
| 2.0.x | No |
| 1.2.x | No |
| 1.1.x | No |
| 1.0.x | No |
| < 1.0 (development builds `0.0.0-dev`) | No |

Security fixes are provided for the latest minor version only, as patch releases (2.3.1,
2.3.2...): when 2.4.0 is released, 2.3.x stops receiving fixes. 2.2.x, 2.1.x and 2.0.x no longer
receive fixes: upgrade to 2.3, which needs no configuration change (from 2.2 or 2.1 see
[Upgrade](docs/operations/upgrade.md#from-22-to-23); from 2.0 first
[from 2.0 to 2.1](docs/operations/upgrade.md#from-20-to-21)). Always run the latest patch release
of the supported version.

Only the provided deployment (`deploy/`, `integrations/`) is supported. The third-party images it
pins by digest (ClamAV, PostgreSQL, reverse proxies) receive security fixes only when you update
them (see the [threat model](docs/security/threat-model.md), T-118).

## Verifying releases

Since 2.0.0, the Docker image (multi-architecture) and the command-line client are signed with
[cosign](https://docs.sigstore.dev/cosign/). The public key is `cosign.pub` at the root of the
repository (also attached to each GitHub release); the signatures are recorded in the public
Rekor transparency log.

cosign.pub SHA-256 fingerprint: 30f33ae8d62c33e510c39079e77f0c68b3068a052da870847414367988a83e77

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

**Installer.** Since 2.2.0, the release also carries `install.sh`, which runs as root on a
blank Debian server. It is listed in `SHA256SUMS`, so the two commands above (`verify-blob` on
`SHA256SUMS`, then `sha256sum -c --ignore-missing SHA256SUMS`, which must print
`install.sh: OK`) verify it. Both are required: `sha256sum -c` alone only detects a corrupted
download, since `SHA256SUMS` comes from the same place as `install.sh`; on a blank server without
cosign, verify on a workstation or fetch cosign checked by the SHA-256 given in the guide. Do it
after comparing the fingerprint of `cosign.pub`, and never run a copy that was not checked or that
was piped from `curl`. The installer embeds `cosign.pub`
and checks its fingerprint, downloads cosign by a version and SHA-256 baked into the script, and
verifies the image signature and SBOM attestation by digest before pulling it
([quick install guide](docs/install/quick-install.md#2-download-and-verify-the-installer)).

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

### One-time secrets

In scope:

- any path where the fragment key or the passphrase of a secret reaches the server, the logs or a
  request (the only exception is the `fragmentKey` of `sendSecret` for e-mail delivery, which is
  never stored nor logged, T-344 and T-363);
- reading or consuming a secret without the key proof;
- access to the secrets of another entity.

Accepted limits of the design, documented in the threat model, not to be reported as bugs:

- a malicious or compromised server can serve modified JavaScript (TB22);
- anyone who holds the full link can read the secret once, by design;
- copies of the link or of the secret in the clipboard or the browser history (T-344);
- a mail gateway sandbox that runs JavaScript and clicks links can consume an e-mailed secret
  that has no passphrase (T-349, P83; require a passphrase for e-mail delivery to avoid it);
- malicious locking of a secret by someone who holds the full link (T-352, P80);
- the encrypted channel that the antivirus cannot scan, enabled by default (T-343, T-372, P81).

### Express secrets (2.3)

The express secret is an anonymous public endpoint (`POST /api/v1/express-secrets`): text only,
sealed in the browser, read once, no identification. It is off by default in every entity.

In scope:

- creating an express secret while the service is closed: the instance kill switch
  (`TT_EXPRESS_SECRETS_DISABLED`), `expressEnabled` off, or an entity still in setup (T-389);
- creating one with an API token that does not have `expressAllowed` (P91);
- bypassing the per-IP limit, the per-token limit or the cap of pending express secrets (T-391,
  T-393), including by forging `X-Forwarded-For` (T-394);
- an anonymous cross-site creation or report, which the server refuses through `Origin` and
  `Sec-Fetch-Site` (T-395, P85);
- reading, or consuming, an express secret while the service is closed (P90);
- the text, the key, the full link or a `tts_` token reaching the server, the logs or the audit
  log (T-399, T-402);
- access to the express secrets of another entity, including a token presented under another
  host (T-390);
- a delegated admin raising the express limits above their defaults (10 per hour per address,
  100 per hour per token, 1,000 pending): only the super admin can, a delegated admin can only
  lower them or keep a value the super admin raised (T-418);
- changing the express settings or `expressAllowed` without the right (T-403).

Accepted limits of the design, documented in the threat model, not to be reported as bugs:

- illicit content or an anonymous mailbox: the server cannot read the texts, so it cannot moderate
  them (T-396, T-407, T-408, P86, P90); the entity states a contact for abuse reports in its legal
  notice;
- phishing under the entity's domain and branding, mitigated by the third-party notice on the
  reading page (T-397, P88);
- filling the cap of pending express secrets, which closes the anonymous service of the entity
  until the secrets are read or expire (T-392);
- a mail gateway sandbox or a link preview that consumes an express link (T-401);
- attribution limited to the IP address of the creator (VPN, Tor, shared NAT; T-404);
- live links made unreadable while the service is closed (T-389, P90): nothing is consumed, and a
  secret that expires meanwhile is lost;
- no cap on the live express secrets created with API tokens: token creations are not blocked by
  the cap of pending express secrets, so several tokens that have `expressAllowed` multiply the
  number of live secrets (residual of T-393, T-418).

### Administration search (2.3)

In scope:

- a search that answers about an entity outside the scope of the admin, or that shows a transfer
  or an address of another entity (T-409, T-410);
- an auditor obtaining by the search what the audit restrictions refuse them (T-411);
- the text of a search, or a pasted secret link, kept in a log or in the audit log (T-402, T-408).

Accepted limits of the design, documented in the threat model, not to be reported as bugs:

- searches are not recorded in the audit log (T-414, P95);
- an address searched through the "more" link can appear in the access logs of the reverse proxy
  (T-168, T-412);
- the super admin's search queries every active entity, within the limits of the server (T-413).

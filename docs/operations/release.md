# Releasing (maintainer guide)

This page is for the maintainer who publishes TransTeira. There is no CI (CLAUDE.md, section
24.4): the build, the signature and the publication of the image, of its SBOM and of the
command-line client all run **locally**, with `make release`. Operators who only deploy the image
should read [docs/install/docker.md](../install/docker.md#5-image) (verification) instead.

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Signing key](#2-signing-key)
3. [Signed Git tag](#3-signed-git-tag)
4. [Before a release: `make check-full`](#4-before-a-release-make-check-full)
5. [`make release`](#5-make-release)
6. [Dry run: `make release-dry`](#6-dry-run-make-release-dry)
7. [What is published](#7-what-is-published)
8. [GitHub release](#8-github-release)
9. [Monitoring Rekor](#9-monitoring-rekor)

## 1. Prerequisites

- **Go** (cosign v3.1.4 and syft v1.57.0 run through pinned `go run`: nothing else to install).
- **Docker with buildx**. The script creates a dedicated builder `transteira-release` with the
  `docker-container` driver and a BuildKit image pinned by digest (the default `docker` driver
  cannot push by digest); an existing builder of that name that does not run the pinned image is
  recreated. The dry run uses its own builder, `transteira-release-dry`, on the host network to
  reach its throwaway registry on 127.0.0.1; the release builder keeps the default container
  network. Remove them with `docker buildx rm <name>` (recreated on the next run). Both platforms
  are built by cross-compilation, without QEMU.
- A registry account with **two-factor authentication** and, if the registry offers it,
  **immutable tags for the `X.Y.Z` pattern only** (`X.Y` and `latest` move by design: an
  immutability rule on every tag would make the final tagging step fail). Run `docker login` first: the script does not check it, and the push
  fails otherwise. Nothing is hardcoded: the target is `RELEASE_IMAGE`, for example
  `docker.io/<account>/transteira`.
- `gh` (GitHub CLI), logged in, for the GitHub release.
- A password vault outside the machine, for the signing key.

## 2. Signing key

Generate the key pair once:

```sh
make release-keygen
```

It runs `cosign generate-key-pair` in `RELEASE_KEY_DIR` (default
`~/.config/transteira-release/`) and copies `cosign.pub` to the root of the repository, where it
is **committed**. Store `cosign.key` and its password in the **password vault**; never put them
in the repository (`.gitignore` and gitleaks refuse them). Keep `cosign.key` outside the repository
and point `COSIGN_KEY` at it.

`make release-keygen` refuses to overwrite an existing `cosign.key`, only changes the mode of a
folder it created, and warns when it replaces an existing `cosign.pub`. cosign asks for the
password itself (leave `COSIGN_PASSWORD` unset): a key that opens with the empty password is
deleted at once and the command fails, and `make release` refuses such a key. Up to 2.0.0 the
script passed an empty `COSIGN_PASSWORD` to cosign, which then created the key **without
password** without asking: check a key made with an earlier version with
`COSIGN_PASSWORD= cosign public-key --key cosign.key` (it must fail).

The public key is published through several channels so that a single compromised channel is
detectable: the repository, the GitHub release assets, and its **SHA-256 fingerprint**
(`sha256sum cosign.pub`), which `README.md`, `README.fr.md` and `SECURITY.md` must each carry on a
line `cosign.pub SHA-256 fingerprint: <hex>`. `make release` refuses to run unless all three contain
exactly this value. Also put the fingerprint in the **Docker Hub repository description**, a channel
outside GitHub (manual step).

`COSIGN_KEY` is resolved with `realpath` (symlinks followed), must be **outside the repository**,
with mode `0600` (refused if group or other bits are set), must have a password, and its public
key must equal `cosign.pub`.

**Rotation or revocation** (scheduled, loss, suspected theft): follow the procedure in
[SECURITY.md](../../SECURITY.md#signing-key-compromise-revocation-and-replacement): new key pair,
new `cosign.pub` committed and published, current supported versions re-signed, announcement in
`CHANGELOG.md` and in a security advisory. Old signatures stay visible in the Rekor log.

## 3. Signed Git tag

`make release` only starts from a **signed** tag `vX.Y.Z` carried by HEAD, checked with
`git tag -v`. SSH signing is the simplest to set up:

```sh
git config gpg.format ssh
git config user.signingKey ~/.ssh/id_ed25519.pub
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
echo "$(git config user.email) $(cat ~/.ssh/id_ed25519.pub)" >> ~/.config/git/allowed_signers
git tag -s v2.1.0 -m "TransTeira 2.1.0"
git tag -v v2.1.0
```

Also create `docs/security/allowed_signers` in the repository (committed), with the maintainer's
public key, so that operators can run `git tag -v vX.Y.Z` with
`git -c gpg.ssh.allowedSignersFile=docs/security/allowed_signers tag -v vX.Y.Z`. `make release`
requires this file and verifies the tag against it (not against your local configuration), as an
operator would. One line per key:

```text
<email> namespaces="git" ssh-ed25519 AAAA...
```

HEAD must carry exactly this tag. A version with a suffix (for example `v2.0.0-rc.1`) is a
pre-release.

## 4. Before a release: `make check-full`

```sh
make check-full
```

It must end with the **ALL GREEN** line on a clean working tree; it then writes
`.cache/check-full.ok` with the commit hash. `make release` refuses to run if this file does not
match HEAD, so any new commit requires a new `make check-full`. It includes `make release-dry`.

## 5. `make release`

```sh
export RELEASE_IMAGE=docker.io/<account>/transteira
export COSIGN_KEY=~/.config/transteira-release/cosign.key   # outside the repository, mode 0600
# If COSIGN_PASSWORD is unset, the password is asked once (hidden) and reused for every cosign call.
docker login
make release
```

`scripts/release.sh` checks, in order: a clean tree, a signed tag `vX.Y.Z` on HEAD, the
`.cache/check-full.ok` marker, that the public key of `COSIGN_KEY` equals `cosign.pub`, and that
the fingerprint of `cosign.pub` appears in `README.md`, `README.fr.md` and `SECURITY.md`. Then it:

1. builds `linux/amd64` and `linux/arm64` by cross-compilation, **always without the BuildKit cache**
   (cached layers could give a digest that a from-scratch build does not reproduce), with the full
   commit SHA in the binary and in the label `org.opencontainers.image.revision`, and pushes the
   image **by digest only, without any tag**;
2. generates an **SPDX JSON SBOM per platform** with syft, from the pushed image (Go modules and
   the npm production dependency `svelte`, whose `package.json` files are embedded under
   `/usr/share/transteira/web-deps/`);
3. **signs** the index and the platform manifests (`cosign sign --key --recursive`);
4. **attaches each SBOM** as a signed attestation of its **platform digest**
   (`cosign attest --type spdxjson`); everything is recorded in the public **Rekor** log;
5. builds the CLI binaries (GOFLAGS, GOEXPERIMENT and inherited make overrides cleared, `GOENV=off`, `GOTOOLCHAIN=local`, `CGO_ENABLED=0`, `dist/cli` emptied first), signs
   `SHA256SUMS` (`cosign sign-blob --bundle SHA256SUMS.sigstore.json`) and produces the CLI SBOM
   `transteira-cli_<version>_sbom.spdx.json` with its `.sigstore.json` bundle;
6. **verifies its own work** (signatures and attestations);
7. only then **tags** the image `X.Y.Z`, plus `X.Y` only if `X.Y.Z` is the highest stable patch
   of its line, and `latest` only if it is the highest stable `vX.Y.Z` Git tag (an older patch or
   line never moves `X.Y` or `latest` backwards); a
   pre-release only gets `X.Y.Z`;
8. collects the outputs and prints the `gh release create` command (section 8).

## 6. Dry run: `make release-dry`

```sh
make release-dry
```

Runs the whole chain against a local `registry:3`, with a throwaway key and without Rekor
(signing offline with an empty cosign signing configuration: no Rekor, no timestamp authority;
verification with `--insecure-ignore-tlog`), then runs `scripts/docker-check.sh` on the
pulled amd64 image. Nothing leaves the machine. It is part of `make check-full`.

The dry run uses the BuildKit cache. With `RELEASE_REPRO=1`, both builds use `--no-cache` and
their digests are compared (reproducibility):

```sh
RELEASE_REPRO=1 make release-dry
```

Reproducibility is verified **on demand** only, not on every `make check-full`.

## 7. What is published

In `dist/release/vX.Y.Z/`:

| File | Content |
|---|---|
| `image-digest.txt` | `<repository>@sha256:<digest>` of the image index, to pin in `TRANSTEIRA_IMAGE` |
| `platform-digests.txt` | One line per platform (`linux/amd64 sha256:...`), the digests carrying the SBOM attestations |
| `transteira_<version>_<os>_<arch>.spdx.json` | SBOM of the image, one per platform |
| `transteira-cli_<version>_<os>_<arch>[.exe]` | CLI binaries |
| `install.sh` | The installer for a blank Debian server, generated for this version (see below) |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | Sums (CLI binaries and `install.sh`) and their cosign bundle |
| `transteira-cli_<version>_sbom.spdx.json` and `.sigstore.json` | CLI SBOM and its bundle |
| `cosign.pub` | Public key (copy) |

On the registry: the image tags, the signatures and the SBOM attestations.

**`install.sh`** is generated by `scripts/release.sh` (`scripts/install/build.sh`, also
`make installer RELEASE_IMAGE=<repository>`) from `scripts/install/install.sh.in`. The version, the
image repository (`RELEASE_IMAGE`, never written in the repository), the index digest from
`image-digest.txt`, the platform digests from `platform-digests.txt`, the pinned cosign version
and SHA-256 (`scripts/install/cosign.pins`, kept equal to the cosign version of the `Makefile`), the
public key `cosign.pub` and the deployment files (`deploy/`, the reference Caddy folder,
`integrations/fail2ban/`, taken from Git) are baked in. The result is reproducible. It is appended to
`SHA256SUMS` **before** `SHA256SUMS` is signed, so the existing `verify-blob` and
`sha256sum -c` cover it, and `make release-dry` checks that `install.sh --version` reports the
version and that `install.sh --dry-run` plans the image by digest. It is never run for real by
the release. Operators verify it as in [Quick install](../install/quick-install.md#2-download-and-verify-the-installer).

## 8. GitHub release

The update check of the administration reads `releases/latest`, so **every tag needs a GitHub
release**. Push the tag, then create the release with the assets (the command printed by
`make release` is authoritative: it chooses `--latest`, `--latest=false` or `--prerelease` with
the same rule as the Docker `latest` tag; this is its shape for the highest stable version):

```sh
git push origin v2.1.0
gh release create v2.1.0 --verify-tag --latest --title "TransTeira 2.1.0" \
  --notes-file RELEASE_NOTES.md \
  dist/release/v2.1.0/*
```

A pre-release gets `--prerelease --latest=false`, and a patch of an older line `--latest=false`,
so that `releases/latest`, read by the update check, never moves backwards. Put the image digest and the
verification commands ([docs/install/docker.md](../install/docker.md#5-image)) in the notes, and
update `CHANGELOG.md` beforehand.

## 9. Monitoring Rekor

Every signature made with the project key is recorded in Rekor. The maintainer can search for the
entries signed by the key, to detect a signature nobody made, which would reveal a stolen key:

```sh
rekor-cli search --public-key cosign.pub --pki-format x509
```

If the default signing configuration of cosign writes to a Rekor v2 (tile-based) log, which has
no search API, `rekor-cli search` finds nothing there: use
[rekor-monitor](https://github.com/sigstore/rekor-monitor), which works with both and automates
this check. Compare the
result with the list of releases; an unexpected entry triggers the procedure in
[SECURITY.md](../../SECURITY.md#signing-key-compromise-revocation-and-replacement).

#!/usr/bin/env bash
# Local release chain of TransTeira (CLAUDE.md sections 22 and 24.4: no CI; threat model 6.55,
# T-331 to T-335, decision P67). docs/operations/release.md is the maintainer guide.
#
#   scripts/release.sh release   `make release`: publish the signed image, its SBOMs and the
#                                signed command-line client of the tagged commit
#   scripts/release.sh dry       `make release-dry`: the same chain against a throwaway local
#                                registry, with a throwaway key and no transparency log
#   scripts/release.sh keygen    `make release-keygen`: create the cosign key pair outside the
#                                repository and copy its public half to cosign.pub
#
# What `release` does, in order (any failure stops it):
#   1. preconditions: RELEASE_IMAGE set, clean working tree, HEAD at exactly one signed tag
#      vX.Y.Z (`git tag -v`), `make check-full` green for HEAD (.cache/check-full.ok), cosign.pub
#      in the repository with its fingerprint in README.md, README.fr.md and SECURITY.md,
#      COSIGN_KEY outside the repository, mode 0600 and matching cosign.pub;
#   2. multi-architecture build (RELEASE_PLATFORMS, linux/amd64 and linux/arm64 by default,
#      cross-compiled without emulation, see the Dockerfile), without build cache, pushed BY
#      DIGEST ONLY: no tag points at it until it is signed and verified;
#   3. one SPDX JSON SBOM per platform, made by syft from the pushed image (Go modules of the
#      binary and npm packages under /usr/share/transteira/web-deps), checked for both;
#   4. `cosign sign --recursive` of the index digest (index and platform manifests) and
#      `cosign attest --type spdxjson` of each platform digest, recorded in Rekor;
#   5. the command-line client (`make cli`, GOFLAGS cleared, GOTOOLCHAIN=local): SHA256SUMS and
#      the client SBOM signed with `cosign sign-blob --bundle`;
#   6. self-verification with cosign.pub, with the commands of the operator documentation
#      (verify on the index digest, verify-attestation on each digest of platform-digests.txt,
#      verify-blob);
#   7. only then the tags: X.Y.Z and X.Y, and latest when X.Y.Z is the highest stable version
#      tag of the repository (a pre-release only gets X.Y.Z); each tag must resolve to the
#      signed digest;
#   8. everything gathered in dist/release/vX.Y.Z/, and the `gh release create` command printed
#      (the maintainer runs it).
#
# Environment:
#   RELEASE_IMAGE      registry repository, e.g. docker.io/<account>/transteira (release only)
#   COSIGN_KEY         private key file, outside the repository, mode 0600 (release only)
#   COSIGN_PASSWORD    its password (asked once, hidden, when unset)
#   RELEASE_KEY_DIR    keygen output folder (default ~/.config/transteira-release)
#   RELEASE_PLATFORMS  default linux/amd64,linux/arm64
#   RELEASE_REPRO      1: dry only, two builds without cache must give the same digest
#   COSIGN, SYFT       commands (the Makefile passes pinned `go run` commands)
#   DOCKER, MAKE       commands (default docker, make)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
ROOT="$(pwd -P)"

DOCKER="${DOCKER:-docker}"
MAKE="${MAKE:-make}"
COSIGN="${COSIGN:?COSIGN must name the cosign command (make release sets it)}"
SYFT="${SYFT:?SYFT must name the syft command (make release sets it)}"
PLATFORMS="${RELEASE_PLATFORMS:-linux/amd64,linux/arm64}"
# Throwaway registry of the dry run (registry:3 serves the OCI 1.1 referrers API), pinned.
REGISTRY_IMAGE="registry:3@sha256:38907510915c3f1604c7e83d6ab602ab3020d092f73bdaed8696773693ff768c"
# Packages every image SBOM must list: Go modules of the binary (both database drivers) and the
# npm runtime dependency.
SBOM_REQUIRED=("github.com/jackc/pgx/v5" "modernc.org/sqlite" "svelte")
# Files that must carry the fingerprint of cosign.pub (publication channels, T-333).
FINGERPRINT_FILES=(README.md README.fr.md SECURITY.md)
FINGERPRINT_PREFIX="cosign.pub SHA-256 fingerprint: "
# Dedicated BuildKit builders (docker-container driver: the docker driver cannot push by digest),
# pinned. The release builder keeps the default container network; only the dry-run builder is on
# the host network, to reach the throwaway registry on 127.0.0.1.
BUILDER="transteira-release"
BUILDER_NETWORK=""
BUILDKIT_IMAGE="moby/buildkit:v0.34.0@sha256:b059f8d7226d0b326bc871af489a5dddf65e36af4d20d14251b072974d9ee87c"

log() { printf 'release: %s\n' "$*"; }
die() {
	printf 'release: ERROR: %s\n' "$*" >&2
	exit 1
}

# The key password reaches cosign only, never the other child processes (docker, make, syft).
# shellcheck disable=SC2206 # deliberate word splitting of the command variables
cosign() { local -a c=($COSIGN); COSIGN_PASSWORD="${COSIGN_PASSWORD-}" "${c[@]}" "$@"; }
# shellcheck disable=SC2206
syft() { local -a c=($SYFT); "${c[@]}" "$@"; }

# Canonical absolute path of an existing file, symbolic links resolved.
canonical() {
	if command -v realpath >/dev/null 2>&1; then
		realpath "$1"
	else
		readlink -f "$1"
	fi
}

# Permission bits of a file in octal (GNU or BSD stat).
file_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# --- preconditions ------------------------------------------------------------------------------

require_clean_tree() {
	[ -z "$(git status --porcelain --untracked-files=normal)" ] ||
		die "the working tree is not clean (git status): commit or stash first (T-335)"
}

# Prints X.Y.Z of the only vX.Y.Z tag at HEAD, after checking its signature.
release_version() {
	local -a tags
	mapfile -t tags < <(git tag --points-at HEAD --list 'v[0-9]*.[0-9]*.[0-9]*')
	[ "${#tags[@]}" -eq 1 ] || die "HEAD must carry exactly one tag vX.Y.Z (found: ${tags[*]:-none})"
	[[ "${tags[0]}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] ||
		die "tag ${tags[0]} is not a SemVer vX.Y.Z tag"
	[ "$(git cat-file -t "${tags[0]}")" = tag ] || die "tag ${tags[0]} is lightweight: create a signed tag (git tag -s)"
	# Verified against the published signers file, as an operator would, not the local config.
	[ -s docs/security/allowed_signers ] ||
		die "docs/security/allowed_signers is missing: publish the tag-signing SSH key (docs/operations/release.md)"
	git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=docs/security/allowed_signers \
		tag -v "${tags[0]}" >/dev/null 2>&1 ||
		die "tag ${tags[0]} does not verify against docs/security/allowed_signers (git tag -v ${tags[0]}); see docs/operations/release.md"
	printf '%s\n' "${tags[0]#v}"
}

require_check_full() {
	local head stamp
	head="$(git rev-parse HEAD)"
	stamp="$(cat .cache/check-full.ok 2>/dev/null || true)"
	[ "$stamp" = "$head" ] ||
		die "make check-full has not passed on this commit ($head): run it first (CLAUDE.md section 24.4)"
}

# cosign.pub is committed and its fingerprint published in every channel of FINGERPRINT_FILES.
require_pubkey() {
	local fp f
	[ -f cosign.pub ] || die "cosign.pub is missing: run make release-keygen, then commit cosign.pub"
	fp="$(sha256_of cosign.pub)"
	for f in "${FINGERPRINT_FILES[@]}"; do
		grep -qF "${FINGERPRINT_PREFIX}${fp}" "$f" ||
			die "$f does not carry '${FINGERPRINT_PREFIX}${fp}' (T-333, docs/operations/release.md)"
	done
}

# The private key lives outside the repository, is readable by its owner only and matches
# cosign.pub.
require_key() {
	local key pub mode
	key="${COSIGN_KEY:?set COSIGN_KEY to the private key file (outside the repository)}"
	[ -f "$key" ] || die "COSIGN_KEY ($key) is not a file"
	key="$(canonical "$key")"
	case "$key" in
	"$ROOT"/*) die "COSIGN_KEY is inside the repository ($key): keep the private key outside it (T-333)" ;;
	esac
	mode="$(file_mode "$key")"
	[ $((8#$mode & 8#077)) -eq 0 ] || die "COSIGN_KEY ($key) has mode $mode: chmod 600 it"
	pub="$(cosign public-key --key "$key")" || die "cannot read the public key of COSIGN_KEY (wrong password?)"
	[ "$(printf '%s\n' "$pub" | tr -d '\r')" = "$(tr -d '\r' <cosign.pub)" ] ||
		die "COSIGN_KEY does not match cosign.pub"
	COSIGN_KEY="$key"
}

# Asks the key password once (hidden) when COSIGN_PASSWORD is unset, for every cosign call.
ask_password() {
	if [ -z "${COSIGN_PASSWORD+set}" ]; then
		[ -r /dev/tty ] || die "COSIGN_PASSWORD is unset and there is no terminal to ask it"
		read -rsp "cosign key password: " COSIGN_PASSWORD </dev/tty
		printf '\n' >&2
	fi
}

# --- chain --------------------------------------------------------------------------------------

# Highest stable vX.Y.Z tag of the repository matching the shell pattern $1 (e.g. 'v1.2.*').
highest_stable() {
	git tag --list "$1" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1 || true
}

# Docker tags of a version: X.Y.Z alone for a pre-release; otherwise X.Y.Z, plus X.Y when it is
# the highest stable patch of its line, plus latest when it is the highest stable version: a
# release of an older patch or line never moves X.Y or latest backwards.
tags_for() {
	local v="$1"
	if [[ "$v" == *-* || "$v" == *+* ]]; then
		printf '%s\n' "${v//+/-}"
		return
	fi
	printf '%s\n' "$v"
	[ "$(highest_stable "v${v%.*}.*")" != "v$v" ] || printf '%s\n' "${v%.*}"
	[ "$(highest_stable 'v[0-9]*.[0-9]*.[0-9]*')" != "v$v" ] || printf 'latest\n'
}

# Flags of `gh release create` matching the Docker tags: the update check reads releases/latest.
gh_flags() {
	local v="$1"
	if [[ "$v" == *-* ]]; then
		printf -- '--prerelease --latest=false'
	elif [ "$(highest_stable 'v[0-9]*.[0-9]*.[0-9]*')" = "v$v" ]; then
		printf -- '--latest'
	else
		printf -- '--latest=false'
	fi
}

# Creates the release builder when it does not exist yet (kept between runs for its cache).
# An existing builder of that name is reused only when it runs the pinned BuildKit image with
# the expected network; otherwise it is recreated.
ensure_builder() {
	local info
	local -a opts=(--driver-opt "image=$BUILDKIT_IMAGE")
	[ -z "$BUILDER_NETWORK" ] || opts+=(--driver-opt "network=$BUILDER_NETWORK")
	if info="$("$DOCKER" buildx inspect "$BUILDER" 2>/dev/null)"; then
		if grep -q 'Driver: *docker-container' <<<"$info" &&
			grep -qF "image=\"$BUILDKIT_IMAGE\"" <<<"$info" &&
			{ [ -z "$BUILDER_NETWORK" ] && ! grep -q 'network=' <<<"$info" ||
				grep -qF "network=\"$BUILDER_NETWORK\"" <<<"$info"; }; then
			return 0
		fi
		log "builder $BUILDER does not match the pinned settings: recreating it"
		"$DOCKER" buildx rm "$BUILDER" >/dev/null
	fi
	log "creating the BuildKit builder $BUILDER ($BUILDKIT_IMAGE${BUILDER_NETWORK:+, network $BUILDER_NETWORK})"
	"$DOCKER" buildx create --name "$BUILDER" --driver docker-container "${opts[@]}" --bootstrap >/dev/null
}

# build_push REPO VERSION COMMIT DATE NOCACHE(0|1): builds every platform and pushes the index BY
# DIGEST (no tag), sets DIGEST.
build_push() {
	local repo="$1" version="$2" commit="$3" date="$4" nocache="$5" epoch meta
	local -a cacheflags=()
	[ "$nocache" = 0 ] || cacheflags=(--no-cache)
	epoch="$(git log -1 --format=%ct HEAD)"
	meta="$WORK/build-metadata.json"
	log "building $PLATFORMS and pushing $repo by digest${cacheflags[*]:+ (without cache)}"
	ensure_builder
	SOURCE_DATE_EPOCH="$epoch" "$DOCKER" buildx build --builder "$BUILDER" \
		--platform "$PLATFORMS" --provenance=false --sbom=false \
		--build-arg VERSION="$version" --build-arg COMMIT="$commit" --build-arg DATE="$date" \
		--build-arg SOURCE_DATE_EPOCH="$epoch" \
		--output "type=image,name=$repo,push-by-digest=true,name-canonical=true,push=true,rewrite-timestamp=true" \
		--metadata-file "$meta" "${cacheflags[@]}" .
	DIGEST="$(sed -n 's/.*"containerimage.digest": *"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' "$meta" | head -n1)"
	[ -n "$DIGEST" ] || die "no image digest in the build metadata ($meta)"
	log "pushed $repo@$DIGEST"
}

# Digests of the platform manifests of the index REF, as "os/arch digest" lines.
platform_digests() {
	"$DOCKER" buildx imagetools inspect --raw "$1" |
		tr -d ' \n\t' | grep -o '"digest":"sha256:[0-9a-f]\{64\}"[^}]*"platform":{[^}]*}' |
		sed -n 's/"digest":"\(sha256:[0-9a-f]*\)".*"architecture":"\([^"]*\)".*"os":"\([^"]*\)".*/\3\/\2 \1/p'
}

# Digest of the index a tag resolves to.
tag_digest() { "$DOCKER" buildx imagetools inspect --format '{{.Manifest.Digest}}' "$1"; }

# sbom_check FILE NAME... : every NAME is a package of the SPDX document FILE.
sbom_check() {
	local file="$1" n
	shift
	for n in "$@"; do
		grep -q "\"name\": *\"$n\"" "$file" || die "SBOM $file does not list $n (T-334)"
	done
}

# publish REPO VERSION COMMIT KEY OUT TLOG(1|0)
publish() {
	local repo="$1" version="$2" commit="$3" key="$4" out="$5" tlog="$6"
	local date name d p f t index nocache=0 sbom clisbom
	local -a tlogflags=() verifyflags=() plats=() tags=()
	if [ "$tlog" = 0 ]; then
		# cosign 3 takes its services from a signing config: an empty one means no transparency
		# log and no timestamp authority (offline signing with the key alone).
		cosign signing-config create --out "$WORK/offline-signing-config.json" >/dev/null
		tlogflags=(--signing-config "$WORK/offline-signing-config.json")
		verifyflags=(--insecure-ignore-tlog=true)
	fi
	# The commit date, in UTC: the same inputs give the same image (reproducible build).
	date="$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ HEAD)"
	mkdir -p "$out"
	# A release, and both builds of the reproducibility check, start without cache: layers cached
	# by an earlier build can be exported with their old compressed blobs, which gives a digest
	# that a build from scratch does not reproduce (seen with BuildKit 0.34 and rewrite-timestamp).
	if [ "$tlog" = 1 ] || [ "${RELEASE_REPRO:-0}" = 1 ]; then
		nocache=1
	fi
	build_push "$repo" "$version" "$commit" "$date" "$nocache"
	index="$repo@$DIGEST"

	# Dry run only: a second build from scratch must give the same digest.
	if [ "$tlog" = 0 ] && [ "${RELEASE_REPRO:-0}" = 1 ]; then
		local first="$DIGEST"
		build_push "$repo" "$version" "$commit" "$date" 1
		[ "$DIGEST" = "$first" ] || die "the build is not reproducible: $first then $DIGEST (T-335)"
		log "reproducible: two builds without cache gave the same digest"
	fi

	mapfile -t plats < <(platform_digests "$index")
	[ "${#plats[@]}" -eq "$(tr ',' '\n' <<<"$PLATFORMS" | wc -l)" ] ||
		die "the index $index has ${#plats[@]} platform manifests, expected $PLATFORMS"
	printf '%s\n' "$index" >"$out/image-digest.txt"
	printf '%s\n' "${plats[@]}" >"$out/platform-digests.txt"

	log "signing $index and its platform manifests"
	cosign sign --yes --key "$key" --recursive "${tlogflags[@]}" "$index"

	for p in "${plats[@]}"; do
		read -r name d <<<"$p"
		sbom="$out/transteira_${version}_${name//\//_}.spdx.json"
		log "SBOM of $name ($d)"
		syft scan "registry:$repo@$d" --platform "$name" -q -o "spdx-json=$sbom"
		sbom_check "$sbom" "${SBOM_REQUIRED[@]}"
		cosign attest --yes --key "$key" --type spdxjson --predicate "$sbom" "${tlogflags[@]}" "$repo@$d"
	done

	log "command-line client"
	# Fixed path, emptied so that no leftover file is signed with the sums.
	rm -rf dist/cli
	# Nothing of the caller's Go or make configuration reaches the signed binaries: no GOFLAGS, no
	# go env file (GOENV=off), no make overrides inherited from `make release VAR=...`.
	env -u GOFLAGS -u GOEXPERIMENT -u MAKEFLAGS -u MFLAGS -u MAKEOVERRIDES -u LDFLAGS \
		GOENV=off GOTOOLCHAIN=local CGO_ENABLED=0 \
		"$MAKE" --no-print-directory cli VERSION="$version" COMMIT="$commit" DATE="$date"
	cp dist/cli/transteira-cli_"${version}"_* dist/cli/SHA256SUMS "$out/"
	clisbom="$out/transteira-cli_${version}_sbom.spdx.json"
	syft scan "file:$out/transteira-cli_${version}_linux_amd64" -q -o "spdx-json=$clisbom"
	sbom_check "$clisbom" "golang.org/x/term"
	for f in "$out/SHA256SUMS" "$clisbom"; do
		cosign sign-blob --yes --key "$key" --bundle "$f.sigstore.json" "${tlogflags[@]}" "$f" >/dev/null
	done

	# The commands of the operator documentation (docs/install/docker.md, SECURITY.md), from
	# the files of the release folder.
	log "self-verification with $(basename "$PUBKEY")"
	cosign verify --key "$PUBKEY" "${verifyflags[@]}" "$(cat "$out/image-digest.txt")" >/dev/null
	while read -r name d; do
		cosign verify --key "$PUBKEY" "${verifyflags[@]}" "$repo@$d" >/dev/null
		cosign verify-attestation --key "$PUBKEY" --type spdxjson "${verifyflags[@]}" "$repo@$d" >/dev/null
	done <"$out/platform-digests.txt"
	for f in "$out/SHA256SUMS" "$clisbom"; do
		cosign verify-blob --key "$PUBKEY" --bundle "$f.sigstore.json" "${verifyflags[@]}" "$f" >/dev/null
	done
	(cd "$out" && sha256sum -c --quiet SHA256SUMS)
	log "verified: image signatures, SBOM attestations, client sums and SBOM"

	# Tags last: none points at an image that is not signed and verified.
	mapfile -t tags < <(tags_for "$version")
	for t in "${tags[@]}"; do
		"$DOCKER" buildx imagetools create --tag "$repo:$t" "$index" >/dev/null
		[ "$(tag_digest "$repo:$t")" = "$DIGEST" ] || die "$repo:$t does not resolve to $DIGEST after tagging"
	done
	log "tagged $repo with ${tags[*]}"
}

# --- modes --------------------------------------------------------------------------------------

mode_release() {
	: "${RELEASE_IMAGE:?set RELEASE_IMAGE to the registry repository, e.g. docker.io/<account>/transteira}"
	[[ "$RELEASE_IMAGE" =~ ^[a-z0-9.:-]+(/[a-z0-9._-]+)+$ ]] ||
		die "RELEASE_IMAGE must be a repository without tag or digest (e.g. docker.io/<account>/transteira)"
	require_clean_tree
	local version out
	version="$(release_version)"
	require_check_full
	require_pubkey
	ask_password
	require_key
	PUBKEY="$ROOT/cosign.pub"
	out="dist/release/v$version"
	rm -rf "$out"
	publish "$RELEASE_IMAGE" "$version" "$(git rev-parse HEAD)" "$COSIGN_KEY" "$out" 1
	cp cosign.pub "$out/cosign.pub"
	log "done: $(cat "$out/image-digest.txt")"
	log "publish the GitHub release (the update check reads releases/latest):"
	printf '  gh release create v%s --verify-tag %s --notes-file <notes> %s/*\n' "$version" "$(gh_flags "$version")" "$out"
}

mode_dry() {
	local version port cid key ok=0
	version="${VERSION:-0.0.0-dev+$(git rev-parse --short HEAD)}"
	log "dry run of $version against a throwaway registry, throwaway key, no transparency log"
	cid="$("$DOCKER" run -d --rm -p 127.0.0.1::5000 "$REGISTRY_IMAGE")"
	DRY_CID="$cid"
	port="$("$DOCKER" port "$cid" 5000/tcp | head -n1 | sed 's/.*://')"
	local repo="localhost:$port/transteira"
	for _ in $(seq 1 50); do
		if curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1; then
			ok=1
			break
		fi
		sleep 0.2
	done
	[ "$ok" = 1 ] || die "the throwaway registry did not answer on 127.0.0.1:$port"
	# Throwaway key without password; any COSIGN_PASSWORD of the caller is not used here.
	COSIGN_PASSWORD=""
	BUILDER="transteira-release-dry"
	BUILDER_NETWORK="host"
	cosign generate-key-pair --output-key-prefix "$WORK/dry" >/dev/null
	key="$WORK/dry.key"
	PUBKEY="$WORK/dry.pub"
	publish "$repo" "$version" "$(git rev-parse HEAD)" "$key" "$WORK/out" 0

	log "smoke test of the amd64 image pulled from the registry"
	local local_tag="transteira-release-dry:amd64"
	"$DOCKER" pull -q --platform linux/amd64 "$repo@$DIGEST" >/dev/null
	"$DOCKER" tag "$repo@$DIGEST" "$local_tag"
	DOCKER="$DOCKER" bash scripts/docker-check.sh "$local_tag" "$version"
	"$DOCKER" image rm -f "$local_tag" "$repo@$DIGEST" >/dev/null 2>&1 || true
	log "dry run: ALL OK"
}

mode_keygen() {
	local dir="${RELEASE_KEY_DIR:-$HOME/.config/transteira-release}"
	if [ ! -e "$dir" ]; then
		mkdir -p "$dir"
		chmod 700 "$dir"
	fi
	[ -d "$dir" ] || die "RELEASE_KEY_DIR ($dir) is not a folder"
	dir="$(cd "$dir" && pwd -P)"
	case "$dir/" in
	"$ROOT"/*) die "RELEASE_KEY_DIR ($dir) is inside the repository: choose a folder outside it" ;;
	esac
	[ ! -e "$dir/cosign.key" ] || die "$dir/cosign.key already exists: move it away first (key rotation, docs/operations/release.md)"
	[ ! -f "$ROOT/cosign.pub" ] ||
		log "WARNING: cosign.pub of the repository will be REPLACED (key rotation: follow SECURITY.md)"
	log "creating the cosign key pair in $dir (cosign asks for its password: keep it in the password vault)"
	(cd "$dir" && cosign generate-key-pair)
	chmod 600 "$dir/cosign.key"
	cp "$dir/cosign.pub" "$ROOT/cosign.pub"
	log "wrote $dir/cosign.key (private: vault copy, never in the repository) and cosign.pub (commit it)"
	log "publish its fingerprint: ${FINGERPRINT_PREFIX}$(sha256_of "$ROOT/cosign.pub")"
}

WORK="$(mktemp -d)"
DRY_CID=""
cleanup() {
	[ -z "$DRY_CID" ] || "$DOCKER" rm -f "$DRY_CID" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

case "${1:-}" in
release) mode_release ;;
dry) mode_dry ;;
keygen) mode_keygen ;;
*) die "usage: scripts/release.sh release|dry|keygen" ;;
esac

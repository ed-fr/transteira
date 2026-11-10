#!/usr/bin/env bash
# Assembles the release installer, dist/install/install.sh by default, from
# scripts/install/install.sh.in, the baked values below and a payload of the deployment files.
# Run by `make installer` and by scripts/release.sh (release and dry run); never run the OUTPUT on
# a development machine (it installs packages and changes the firewall).
#
# Environment (all values are validated; the build fails on any doubt):
#   INSTALL_VERSION               TransTeira version X.Y.Z (SemVer), required
#   RELEASE_IMAGE                 image repository (e.g. docker.io/<account>/transteira), required;
#                                 never written in the repository, only in the generated file
#   INSTALL_IMAGE_DIGEST_FILE     image-digest.txt of the release: "<RELEASE_IMAGE>@sha256:<index>"
#   INSTALL_PLATFORM_DIGESTS_FILE platform-digests.txt of the release: "linux/<arch> sha256:<digest>"
#                                 lines (amd64 and/or arm64)
#   INSTALL_COSIGN_PUB            public key that verifies the image (default: cosign.pub)
#   INSTALL_OUT                   output file (default: dist/install/install.sh)
#
# Baked from the repository: the cosign release and the SHA-256 of its binaries
# (scripts/install/cosign.pins), the SHA-256 fingerprint of the public key, the payload checksum.
#
# Payload: the tracked files (git ls-files) of deploy/ (as deploy/), of
# integrations/reverse-proxy/caddy/ (as reverse-proxy/caddy/) and of integrations/fail2ban/ (as
# fail2ban/), in a tar sorted by name with fixed owner, modes and dates, gzipped without name or
# time, base64 encoded after the marker line: the same inputs always give the same install.sh.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

die() {
	printf 'install-build: ERROR: %s\n' "$*" >&2
	exit 1
}

template=scripts/install/install.sh.in
pins=scripts/install/cosign.pins
marker=__TRANSTEIRA_INSTALL_PAYLOAD_BELOW__

version=${INSTALL_VERSION:?set INSTALL_VERSION (X.Y.Z)}
repo=${RELEASE_IMAGE:?set RELEASE_IMAGE to the image repository, e.g. docker.io/<account>/transteira}
digest_file=${INSTALL_IMAGE_DIGEST_FILE:?set INSTALL_IMAGE_DIGEST_FILE (image-digest.txt of the release)}
platforms_file=${INSTALL_PLATFORM_DIGESTS_FILE:?set INSTALL_PLATFORM_DIGESTS_FILE (platform-digests.txt of the release)}
pub=${INSTALL_COSIGN_PUB:-cosign.pub}
out=${INSTALL_OUT:-dist/install/install.sh}

[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] ||
	die "INSTALL_VERSION '$version' is not a SemVer version"
[[ "$repo" =~ ^[a-z0-9.:-]+(/[a-z0-9._-]+)+$ ]] ||
	die "RELEASE_IMAGE '$repo' must be a repository without tag or digest"

# Index digest: the file names the same repository.
index=$(tr -d '\r' <"$digest_file" | head -n 1)
[[ "$index" =~ ^(.+)@(sha256:[0-9a-f]{64})$ ]] || die "$digest_file: expected <repository>@sha256:<64 hex>, got '$index'"
[ "${BASH_REMATCH[1]}" = "$repo" ] || die "$digest_file names ${BASH_REMATCH[1]}, not RELEASE_IMAGE ($repo)"
index_digest=${BASH_REMATCH[2]}

# Platform digests: "linux/amd64 sha256:..." lines, amd64 and arm64 only, each at most once.
platforms=""
while read -r plat d || [ -n "${plat:-}" ]; do
	[ -n "$plat" ] || continue
	[[ "$plat" =~ ^linux/(amd64|arm64)$ ]] || die "$platforms_file: unsupported platform '$plat'"
	[[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$platforms_file: bad digest '$d' for $plat"
	case " $platforms " in *" $plat="*) die "$platforms_file: $plat listed twice" ;; esac
	platforms="${platforms:+$platforms }$plat=$d"
done < <(tr -d '\r' <"$platforms_file")
[ -n "$platforms" ] || die "$platforms_file lists no platform"

# cosign pins.
pin() { sed -n "s/^$1=//p" "$pins" | head -n 1; }
cosign_version=$(pin COSIGN_VERSION)
cosign_amd64=$(pin COSIGN_SHA256_LINUX_AMD64)
cosign_arm64=$(pin COSIGN_SHA256_LINUX_ARM64)
[[ "$cosign_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$pins: bad COSIGN_VERSION '$cosign_version'"
[[ "$cosign_amd64" =~ ^[0-9a-f]{64}$ ]] || die "$pins: bad COSIGN_SHA256_LINUX_AMD64"
[[ "$cosign_arm64" =~ ^[0-9a-f]{64}$ ]] || die "$pins: bad COSIGN_SHA256_LINUX_ARM64"

# Public key: one PEM public key, nothing that could break the single-quoted assignment.
[ -f "$pub" ] || die "INSTALL_COSIGN_PUB: $pub is not a file"
pub_text=$(tr -d '\r' <"$pub")
[[ "$pub_text" =~ ^-----BEGIN\ PUBLIC\ KEY-----$'\n'[A-Za-z0-9+/=$'\n']+$'\n'-----END\ PUBLIC\ KEY-----$ ]] ||
	die "$pub is not a single PEM public key"
pub_sha=$(printf '%s\n' "$pub_text" | sha256sum | cut -d' ' -f1)

# Payload.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stage=$work/stage
mkdir -p "$stage"
stage_tree() { # SOURCE_DIR DEST_DIR
	local f rel
	while IFS= read -r -d '' f; do
		rel=${f#"$1"/}
		mkdir -p "$stage/$2/$(dirname "$rel")"
		cp "$f" "$stage/$2/$rel"
	done < <(git ls-files -z -- "$1")
}
stage_tree deploy deploy
stage_tree integrations/reverse-proxy/caddy reverse-proxy/caddy
stage_tree integrations/fail2ban fail2ban
for f in deploy/docker-compose.yml deploy/docker-compose.postgres.yml deploy/.env.example deploy/init-secrets.sh \
	reverse-proxy/caddy/Caddyfile.on-demand reverse-proxy/caddy/docker-compose.yml reverse-proxy/caddy/README.md \
	fail2ban/filter.d/transteira.conf fail2ban/filter.d/transteira-sso.conf fail2ban/jail.d/transteira.local; do
	[ -f "$stage/$f" ] || die "payload: $f is missing (not tracked by git?)"
done
[ ! -e "$stage/deploy/secrets" ] && [ ! -e "$stage/deploy/.env" ] || die "payload: deploy/secrets or deploy/.env is tracked by git"
find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
(cd "$stage" && LC_ALL=C tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
	-cf - deploy fail2ban reverse-proxy) | gzip -n -9 >"$work/payload.tgz"
payload_sha=$(sha256sum "$work/payload.tgz" | cut -d' ' -f1)

# Script: placeholders replaced literally (no regular expression, no escaping issue).
export TTI_VERSION=$version TTI_IMAGE_REPO=$repo TTI_INDEX_DIGEST=$index_digest TTI_PLATFORM_DIGESTS=$platforms \
	TTI_COSIGN_VERSION=$cosign_version TTI_COSIGN_SHA256_AMD64=$cosign_amd64 TTI_COSIGN_SHA256_ARM64=$cosign_arm64 \
	TTI_COSIGN_PUB_SHA256=$pub_sha TTI_PAYLOAD_SHA256=$payload_sha TTI_COSIGN_PUB=$pub_text
mkdir -p "$(dirname "$out")"
tmp_out="$out.tmp"
awk '
	BEGIN {
		n = split("TTI_VERSION TTI_IMAGE_REPO TTI_INDEX_DIGEST TTI_PLATFORM_DIGESTS TTI_COSIGN_VERSION " \
			"TTI_COSIGN_SHA256_AMD64 TTI_COSIGN_SHA256_ARM64 TTI_COSIGN_PUB_SHA256 TTI_PAYLOAD_SHA256 TTI_COSIGN_PUB", keys, " ")
	}
	{
		line = $0
		for (k = 1; k <= n; k++) {
			ph = "@" keys[k] "@"
			while ((i = index(line, ph)) > 0) {
				line = substr(line, 1, i - 1) ENVIRON[keys[k]] substr(line, i + length(ph))
				seen[keys[k]]++
			}
		}
		print line
	}
	END { for (k = 1; k <= n; k++) if (seen[keys[k]] != 1) { print "placeholder @" keys[k] "@ found " seen[keys[k]] + 0 " times" > "/dev/stderr"; exit 3 } }
' "$template" >"$tmp_out" || die "cannot fill the placeholders of $template"
if grep -n '@TTI_[A-Z0-9_]*@' "$tmp_out" >&2; then die "placeholders left in $out"; fi
grep -qx "# The deployment files follow (scripts/install/build.sh): base64 of a gzipped tar." "$tmp_out" ||
	die "$template does not end with the payload comment line"
{
	printf '%s\n' "$marker"
	base64 -w 76 "$work/payload.tgz"
} >>"$tmp_out"
bash -n "$tmp_out" || die "the generated script has a syntax error"
chmod 0755 "$tmp_out"
mv -f "$tmp_out" "$out"
printf 'install-build: wrote %s (TransTeira %s, %s@%s, payload %s, %s bytes)\n' \
	"$out" "$version" "$repo" "$index_digest" "${payload_sha:0:12}" "$(wc -c <"$out" | tr -d ' ')"

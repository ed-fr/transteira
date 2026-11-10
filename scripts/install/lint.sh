#!/usr/bin/env bash
# `make install-lint`: static checks of the release installer, run by `make check`.
#   1. bash -n of the template, of build.sh and of this script;
#   2. a sample installer is built with dummy release values (build.sh also runs bash -n on it);
#   3. shellcheck (pinned image, no network) on the template, build.sh, this script and the
#      sample installer without its payload; skipped with a message when Docker is unavailable,
#      like the other Docker gates;
#   4. the unit tests of the installer functions and of the build (go test ./scripts/install/).
# It never runs the installer (only its --version and, in the Go tests, its --dry-run).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
docker=${DOCKER:-docker}
go=${GO:-go}
# koalaman/shellcheck v0.11.0, multi-architecture index, pinned by digest.
SHELLCHECK_IMAGE="koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d"

fail() {
	echo "install-lint: FAIL: $*" >&2
	exit 1
}
# Paths handed to Docker (a Windows program under Git Bash) must be native.
native() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

for f in scripts/install/install.sh.in scripts/install/build.sh scripts/install/lint.sh scripts/install-smoke.sh; do
	bash -n "$f" || fail "$f has a syntax error"
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
hex() { printf "%0${2}d" 0 | tr 0 "$1"; }
printf 'registry.invalid/example/transteira@sha256:%s\n' "$(hex a 64)" >"$work/image-digest.txt"
printf 'linux/amd64 sha256:%s\nlinux/arm64 sha256:%s\n' "$(hex b 64)" "$(hex c 64)" >"$work/platform-digests.txt"
INSTALL_VERSION=0.0.0-lint RELEASE_IMAGE=registry.invalid/example/transteira \
	INSTALL_IMAGE_DIGEST_FILE="$work/image-digest.txt" INSTALL_PLATFORM_DIGESTS_FILE="$work/platform-digests.txt" \
	INSTALL_OUT="$work/install.sh" bash scripts/install/build.sh >/dev/null
[ "$(bash "$work/install.sh" --version)" = 0.0.0-lint ] || fail "the sample installer does not report its baked version"
# The payload is base64 data, not shell: shellcheck reads the script part only.
sed '/^__TRANSTEIRA_INSTALL_PAYLOAD_BELOW__$/,$d' "$work/install.sh" >"$work/install-script.sh"

if [ "${DOCKER_CHECK:-1}" = 0 ]; then
	echo "install-lint: shellcheck SKIPPED (DOCKER_CHECK=0)"
elif ! "$docker" info >/dev/null 2>&1; then
	echo "install-lint: shellcheck SKIPPED (Docker is not available: '$docker info' failed)"
else
	cp scripts/install/install.sh.in scripts/install/build.sh scripts/install/lint.sh scripts/install-smoke.sh "$work/"
	chmod -R a+rX "$work"
	MSYS_NO_PATHCONV=1 "$docker" run --rm --network none -v "$(native "$work"):/src:ro" "$SHELLCHECK_IMAGE" \
		--shell=bash --severity=style /src/install.sh.in /src/build.sh /src/lint.sh /src/install-smoke.sh /src/install-script.sh ||
		fail "shellcheck reports problems (see above)"
	echo "install-lint: shellcheck OK"
fi

"$go" test -count=1 ./scripts/install/ || fail "the installer unit tests fail"
echo "install-lint: OK"

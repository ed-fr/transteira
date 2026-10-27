#!/usr/bin/env bash
# Decides whether `make check` runs the 20 GB test (CLAUDE.md section 24.4).
#
#   BIGFILE=1     always run it (`make check-full`, before every release)
#   BIGFILE=0     never run it (prints a reminder)
#   BIGFILE=auto  run it only when the big-file chain or the test settings changed since the last
#                 green run: their fingerprint is compared with the one recorded in
#                 .cache/bigfile.stamp after the last green run of this script (a plain
#                 `make bigfile` does not record it).
#
# The chain is every Go package of this module that the server binary and the test client
# depend on (computed with `go list -deps`, test files excluded), plus the non-Go inputs of the
# test: image, deployment, reference Caddy, orchestration scripts, Makefile. The settings are the
# BIGFILE_* variables of the run (size, engines, memory limit, cut points...).
#
# Usage: scripts/bigfile-auto.sh <command running the test>...
set -euo pipefail

mode="${BIGFILE:-auto}"
stamp=".cache/bigfile.stamp"
# Outcome of this run ("skipped" or "ran"), read by `make check` for its final line.
last=".cache/bigfile.last"
mkdir -p .cache
rm -f "$last"

NON_GO_PATHS=(
	api Dockerfile .dockerignore Makefile deploy integrations/reverse-proxy/caddy
	scripts/bigfile.sh scripts/lib test/bigfile go.mod go.sum
)

# Directories (relative to the module root) of the module packages the server and the test client
# depend on, from their import paths, so that the result is the same on Windows and Linux.
chain_paths() {
	local module pkgs
	module="$(go list -m)"
	pkgs="$(go list -tags bigfile -deps -f '{{if .Module}}{{if .Module.Main}}{{.ImportPath}}{{end}}{{end}}' \
		./cmd/transteira ./test/bigfile/...)" || return 1
	# The embedded web interface (web, web/apidocs) is not on the path of the test, which uses the
	# API only: a UI change does not re-run it.
	printf '%s\n' "$pkgs" | sed -n "s|^${module}/||p" | grep -v '^web\(/\|$\)' || true
	printf '%s\n' "${NON_GO_PATHS[@]}"
}

# Fingerprint: the git object id of every tracked or untracked (not ignored) file of the chain,
# working tree content included (one git call), plus the test settings. Test files are left out,
# except under test/bigfile, so that unit-test edits do not trigger a 20 GB run.
fingerprint() {
	local -a paths files=()
	local f list
	list="$(chain_paths)" || {
		echo "bigfile: cannot list the Go packages of the big-file chain (go list failed)" >&2
		return 1
	}
	mapfile -t paths < <(printf '%s\n' "$list" | LC_ALL=C sort -u)
	while IFS= read -r -d '' f; do
		case "$f" in
		test/bigfile/*) ;;
		*_test.go) continue ;;
		esac
		[ -f "$f" ] && files+=("$f")
	done < <(git -c core.quotePath=false ls-files -z -co --exclude-standard -- "${paths[@]}")
	{
		if [ "${#files[@]}" -gt 0 ]; then
			paste -d' ' <(printf '%s\n' "${files[@]}" | git hash-object --stdin-paths) \
				<(printf '%s\n' "${files[@]}")
		fi
		env | grep '^BIGFILE_' | LC_ALL=C sort || true
	} | sha256sum | cut -d' ' -f1
}

case "$mode" in
0)
	echo "bigfile: SKIPPED (BIGFILE=0): never skip the 20 GB test before a release (make check-full)"
	exit 0
	;;
1) ;;
auto)
	current="$(fingerprint)" || exit 2
	if [ -f "$stamp" ] && [ "$(cut -d' ' -f1 "$stamp")" = "$current" ]; then
		echo "bigfile: SKIPPED (auto): the big-file chain and settings are unchanged since the last green run ($(cut -d' ' -f2- "$stamp")); make check-full runs it"
		echo skipped >"$last"
		exit 0
	fi
	echo "bigfile: the big-file chain or settings changed since the last green run: running the 20 GB test"
	;;
*)
	echo "bigfile: BIGFILE must be 0, 1 or auto (got '$mode')" >&2
	exit 2
	;;
esac

before="$(fingerprint)" || exit 2
"$@"
echo ran >"$last"
# Recorded only when the tree did not change during the run, so the stamp always matches what
# was actually tested.
if after="$(fingerprint)" && [ "$after" = "$before" ]; then
	printf '%s %s %s\n' "$before" "$(git rev-parse --short HEAD)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$stamp"
fi

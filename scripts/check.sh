#!/usr/bin/env bash
# Runs the quality gates of `make check` one after the other, stops at the first failure and
# prints the duration of every gate that ran (CLAUDE.md section 24.4).
#
# Usage: scripts/check.sh [VAR=value]... -- <gate>...
# Called by the Makefile with $(CHECK_GATES). MAKE is the make binary of the caller; the
# command-line variables of the caller reach every gate through MAKEFLAGS, and the VAR=value
# arguments (VERSION, COMMIT, DATE) are passed to every gate so that they all build the same version.
set -uo pipefail

MAKE="${MAKE:-make}"
vars=()
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
	vars+=("$1")
	shift
done
[ "${1:-}" = "--" ] && shift
names=()
durations=()
results=()

fmt() { printf '%dm%02ds' $(($1 / 60)) $(($1 % 60)); }

summary() {
	local total=0 i
	echo
	echo "make check: duration per gate"
	for i in "${!names[@]}"; do
		printf '  %-22s %8s  %s\n' "${names[$i]}" "$(fmt "${durations[$i]}")" "${results[$i]}"
		total=$((total + durations[$i]))
	done
	printf '  %-22s %8s\n' "total" "$(fmt "$total")"
}

for gate in "$@"; do
	start=$(date +%s)
	"$MAKE" --no-print-directory "$gate" "${vars[@]}"
	status=$?
	names+=("$gate")
	durations+=($(($(date +%s) - start)))
	if [ "$status" -ne 0 ]; then
		results+=("FAILED")
		summary
		echo "make check: FAILED at gate '$gate'" >&2
		exit "$status"
	fi
	results+=("ok")
done
summary

#!/bin/sh
# Memory sampler of the 20 GB test (scripts/bigfile.sh). Runs in a throwaway helper container
# (BusyBox sh) that sees the cgroup tree of the Docker host read-only (--cgroupns=host,
# /sys/fs/cgroup mounted on /cg): the containers under test need no shell (transteira is a
# scratch image) and the samples cost no `docker` call.
#
#   memsampler.sh NAME=CONTAINER_ID...
#
# Every second, one CSV line per container on stdout, no header:
#
#   <unix time in ms>,<name>,<anon>,<current>,<file>,<kernel>,<sock>,<swap>
#
# from its cgroup: anon, file, kernel and sock of memory.stat, current = memory.current, swap =
# memory.swap.current (0 when swap accounting is off); cgroup v1: rss, cache, 0, 0,
# memory.usage_in_bytes and the swap of memory.stat. Only cgroup v2 is tested.
#
# The time is the epoch second at which the sampler started plus the /proc/uptime elapsed since
# (BusyBox date has no sub-second format): the start waits for the next change of `date +%s`, so
# that the epoch base is exact to the uptime resolution (10 ms) instead of truncated to the
# second. "memsampler: clock <epoch s> <uptime s>" gives that base on stderr: the time of any
# later instant is (epoch + uptime now - uptime base) x 1000, which scripts/bigfile.sh uses to
# measure the offset between this clock and the clock of the client. Diagnostics go to stderr;
# "memsampler: ready" once every cgroup is found.
set -eu

s0=$(date +%s)
while [ "$(date +%s)" = "$s0" ]; do :; done
read -r u0 _ </proc/uptime
e0=$((s0 + 1))

specs=""
for arg in "$@"; do
	name=${arg%%=*}
	id=${arg#*=}
	dir=""
	# cgroup v2: /cg/docker/<id> (Docker Desktop, cgroupfs driver),
	# /cg/system.slice/docker-<id>.scope (systemd driver) or deeper under
	# /cg/user.slice/user-<uid>.slice/user@<uid>.service/... (rootless with systemd);
	# v1: /cg/memory/docker/<id>...
	for d in $(find /cg -maxdepth 7 -type d -name "*$id*" 2>/dev/null); do
		if [ -f "$d/memory.stat" ]; then
			dir=$d
			break
		fi
	done
	if [ -z "$dir" ]; then
		echo "memsampler: no cgroup with memory.stat for $name ($id) under /sys/fs/cgroup" >&2
		exit 1
	fi
	echo "memsampler: $name -> ${dir#/cg}" >&2
	specs="$specs $name=$dir"
done
echo "memsampler: clock $e0 $u0" >&2
echo "memsampler: ready" >&2

while :; do
	read -r u _ </proc/uptime
	for s in $specs; do
		name=${s%%=*}
		dir=${s#*=}
		# A container that stopped has no cgroup any more: no line for it.
		[ -f "$dir/memory.stat" ] || continue
		cur=$(cat "$dir/memory.current" 2>/dev/null || cat "$dir/memory.usage_in_bytes" 2>/dev/null || echo 0)
		sw=$(cat "$dir/memory.swap.current" 2>/dev/null || echo "")
		awk -v e0="$e0" -v u="$u" -v u0="$u0" -v n="$name" -v cur="$cur" -v sw="$sw" '
			{ v[$1] = $2 }
			END {
				anon = ("anon" in v) ? v["anon"] : v["rss"]
				file = ("file" in v) ? v["file"] : v["cache"]
				swap = (sw != "") ? sw : v["swap"]
				printf "%.0f,%s,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f\n", (e0 + u - u0) * 1000, n, anon, cur, file, v["kernel"], v["sock"], swap
			}' "$dir/memory.stat" 2>/dev/null || true
	done
	sleep 1
done

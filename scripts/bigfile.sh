#!/usr/bin/env bash
# 20 GB test (`make bigfile`, CLAUDE.md section 24.2): a random file of BIGFILE_BYTES (20 GiB by
# default, the largest transfer a tenant may allow) uploaded with tus through the real reference
# Caddy in Docker to the PRODUCTION stack (deploy/, real ClamAV), with a connection cut in the
# middle of the upload and of the download, both resumed, the SHA-256 compared end to end, and the
# memory of the server sampled during the whole run. Last gate of `make check`.
#
#   scripts/bigfile.sh            run the test (engines from BIGFILE_DBS)
#   scripts/bigfile.sh clean      remove every leftover transteira-bigfile-* project and network
#                                 (after a BIGFILE_KEEP=1 failure); add --signatures to drop the
#                                 ClamAV signature cache too
#
# Steps:
#   1. preflight: Docker up, image TRANSTEIRA_IMAGE present, free space where Docker keeps its
#      volumes >= BIGFILE_BYTES x 1.15 + 5 GiB (or BIGFILE_MIN_FREE), probed in a container on a
#      throwaway volume; with Docker Desktop on Windows, whose WSL2 disk image grows on demand, the
#      free space is min(free inside the VM, free on the host drive of the disk image + the space
#      already allocated in the image but unused inside); Docker memory >= 7 GiB (clamd alone may
#      use 4 GiB); the Go client compiled (go test -c -tags bigfile ./test/bigfile);
#   2. per engine (BIGFILE_DBS: sqlite, postgres or both, in that order), with the shared stack
#      logic of scripts/lib/stack.sh (same files and overrides as scripts/deploy-smoke.sh): the
#      compose project transteira-bigfile-<engine>, its own proxy network (172.31.249.0/24) and
#      internal/db subnets (172.31.247.0/24, 172.31.248.0/24), Caddy with `tls internal` for
#      admin.bigfile.localhost and transfer.bigfile.localhost on 127.0.0.1:<free port>, the real
#      ClamAV (TT_CLAMAV_MAX_SCAN_BYTES left at 2 GiB unless BIGFILE_CLAMAV_MAX_SCAN_BYTES lowers
#      it: a 20 GiB file is accepted as not scanned);
#   3. waits until transteira is healthy, copies Caddy's internal root CA, reads the setup token
#      from the transteira log, starts the memory sampler: a helper container
#      (scripts/lib/memsampler.sh) reading, once a second, the cgroup memory of transteira and
#      Caddy from the Docker host, saved to test/bigfile/out/mem-<engine>.csv
#      (unix ms, container, anon, current, file, kernel, sock, swap), and measures the offset
#      between the clock of the samples (Docker host, a VM with Docker Desktop) and the clock of
#      the client;
#   4. runs the Go client (test/bigfile, TestBigFile), which writes test/bigfile/out/report-<engine>.json;
#      measures the clock offset again; requires that transteira and Caddy never restarted nor
#      were OOM-killed (docker inspect: RestartCount 0, OOMKilled false) and that the transteira
#      log holds no Go "panic:";
#   5. stops the sampler and checks the memory with test/bigfile/memcheck, on the ANONYMOUS memory
#      of the server plus its swap (memory.stat anon: heap, stacks, buffers; the total
#      memory.current, and thus `docker stats`, also counts the page cache of the file written to
#      and read from the data volume, which the kernel reclaims on demand: it is reported, not
#      checked): peak <= BIGFILE_MAX_MEM, the upload and download windows of the report (shifted
#      by the measured clock offset, which must stay within BIGFILE_MAX_CLOCK_OFFSET) covered by
#      the samples (at least 8, no gap above 5 s), and no upward trend during the upload nor
#      during the download (mean of the last quarter of the window's samples <= mean of its first
#      quarter x 1.25 + 64 MiB); the Caddy peak is reported; the report summary (durations,
#      throughputs, resume offsets) too;
#   6. ALWAYS tears the stack down with its volumes (trap) before the next engine, so that the disk
#      budget stays about one file; with BIGFILE_KEEP=1 a failed run is kept for diagnosis and the
#      commands to inspect and clean it are printed. Only transteira-bigfile-* resources are
#      touched; the script fails if a volume of a real installation (transteira_*) appeared.
#   A summary (durations, throughputs, memory peaks) is printed at the end.
#
# Variables (defaults): BIGFILE (1; 0 skips, never before a release), BIGFILE_BYTES (21474836480),
# BIGFILE_DBS (both), BIGFILE_KEEP (0), BIGFILE_MAX_MEM (256MiB), BIGFILE_CHUNK, BIGFILE_CUT_AT,
# BIGFILE_DL_CUT_AT, BIGFILE_SEED (passed to the client when set, see test/bigfile),
# BIGFILE_SCAN_TIMEOUT (client wait from finalize to available, a Go duration, 30m: a real clamd
# scans a file up to its limit), BIGFILE_CLAMAV_MAX_SCAN_BYTES (1048576 to 2147483648, default
# 2147483648: set as TT_CLAMAV_MAX_SCAN_BYTES of the stack and given to the client, which expects
# not_scanned_too_large above it and clean below; the clamd limits of deploy/ stop at 2 GiB),
# TRANSTEIRA_IMAGE (transteira:local), BIGFILE_SUBNET / BIGFILE_PROXY_IP (172.31.249.0/24 /
# 172.31.249.10), BIGFILE_INTERNAL_SUBNET / BIGFILE_DB_SUBNET, BIGFILE_CLAMAV_DB_VOLUME
# (transteira-bigfile-clamav-db, must start with transteira-bigfile-; kept between runs as a cache
# of the public signatures), BIGFILE_TIMEOUT (seconds to wait for a healthy stack, 900),
# BIGFILE_CLIENT_TIMEOUT (4h), BIGFILE_MIN_DOCKER_MEM (7GiB), BIGFILE_MIN_FREE (disk space
# required, replaces BIGFILE_BYTES x 1.15 + 5 GiB), BIGFILE_MAX_CLOCK_OFFSET (2s, a Go duration).
# test/README.md, section "20 GB test", explains them.
# Debugging the orchestration only: BIGFILE_CLIENT=<shell command> runs that command instead of
# the Go client, with the same environment (the client is then not compiled).
set -euo pipefail

docker=${DOCKER:-docker}
root=$(cd "$(dirname "$0")/.." && pwd)

STACK_TAG=bigfile
STACK_PREFIX=transteira-bigfile-
# shellcheck source=scripts/lib/stack.sh
. "$root/scripts/lib/stack.sh"

network=transteira-bigfile-proxy
clamav_db=${BIGFILE_CLAMAV_DB_VOLUME:-transteira-bigfile-clamav-db}
probe_volume=transteira-bigfile-probe
# The signature cache is created, used and (clean --signatures) deleted by this script: never a
# volume it does not own.
[[ "$clamav_db" =~ ^transteira-bigfile-[A-Za-z0-9_.-]+$ ]] ||
	fail "BIGFILE_CLAMAV_DB_VOLUME must start with transteira-bigfile- (got '$clamav_db')"

# --- clean mode ---------------------------------------------------------------------------------
if [ "${1:-}" = clean ]; then
	"$docker" info >/dev/null 2>&1 || fail "Docker is not available ('$docker info' failed)"
	projects=$({
		"$docker" ps -a --format '{{.Label "com.docker.compose.project"}}'
		"$docker" volume ls --format '{{.Label "com.docker.compose.project"}}'
		"$docker" network ls --format '{{.Label "com.docker.compose.project"}}'
	} | grep -E "^$STACK_PREFIX" | sort -u || true)
	for p in $projects; do
		log "removing project $p"
		stack_purge_project "$p"
	done
	"$docker" network rm "$network" >/dev/null 2>&1 || true
	"$docker" volume rm "$probe_volume" >/dev/null 2>&1 || true
	if [ "${2:-}" = --signatures ]; then
		"$docker" volume rm "$clamav_db" >/dev/null 2>&1 || true
		log "signature cache $clamav_db removed"
	fi
	log "clean: done (work folders under ${TMPDIR:-/tmp}/tmp.* holding throwaway secrets, if any, are yours to delete)"
	exit 0
fi
[ $# -eq 0 ] || {
	echo "usage: $0 [clean [--signatures]]" >&2
	exit 2
}

if [ "${BIGFILE:-1}" = 0 ]; then
	log "SKIPPED (BIGFILE=0): never skip the 20 GB test before a release"
	exit 0
fi

engines=${BIGFILE_DBS:-both}
case "$engines" in
both) engines="sqlite postgres" ;;
sqlite | postgres) ;;
*) fail "BIGFILE_DBS must be sqlite, postgres or both (got '$engines')" ;;
esac

image=${TRANSTEIRA_IMAGE:-transteira:local}
subnet=${BIGFILE_SUBNET:-172.31.249.0/24}
proxy_ip=${BIGFILE_PROXY_IP:-172.31.249.10}
# Exported: they override INTERNAL_SUBNET and DB_SUBNET of the .env in the compose interpolation.
export INTERNAL_SUBNET=${BIGFILE_INTERNAL_SUBNET:-172.31.247.0/24}
export DB_SUBNET=${BIGFILE_DB_SUBNET:-172.31.248.0/24}
timeout=${BIGFILE_TIMEOUT:-900}
client_timeout=${BIGFILE_CLIENT_TIMEOUT:-4h}
admin_host=admin.bigfile.localhost
tenant_host=transfer.bigfile.localhost
bytes=${BIGFILE_BYTES:-21474836480}
keep=${BIGFILE_KEEP:-0}
max_mem=${BIGFILE_MAX_MEM:-256MiB}
out="$root/test/bigfile/out"
GiB=1073741824

[[ "$bytes" =~ ^[1-9][0-9]{0,13}$ ]] || fail "BIGFILE_BYTES must be a positive byte count (got '$bytes')"

# gib BYTES prints BYTES in GiB with one decimal.
gib() { awk -v b="$1" 'BEGIN { printf "%.1f GiB", b / 1073741824 }'; }
# size_bytes SIZE converts 384MiB, 7GiB, 1048576... to bytes (the units of test/bigfile/memcheck).
size_bytes() {
	awk -v s="$1" 'BEGIN {
		n = s; sub(/[A-Za-z]+$/, "", n); u = substr(s, length(n) + 1)
		m["B"] = 1; m[""] = 1; m["KiB"] = 1024; m["MiB"] = 1048576; m["GiB"] = 1073741824
		m["kB"] = 1e3; m["MB"] = 1e6; m["GB"] = 1e9
		if (n !~ /^[0-9]+(\.[0-9]+)?$/ || !(u in m)) exit 1
		printf "%.0f\n", n * m[u]
	}' || fail "bad size '$1' (use bytes or a B, KiB, MiB, GiB, kB, MB or GB unit)"
}

# --- run state and cleanup ------------------------------------------------------------------------
sampler=""
sampler_csv=""
bin_dir=""
caddy_ctr=""
summary=()

# check_containers TRANSTEIRA CADDY prints one line per problem: a container that restarted or
# was OOM-killed (a crash the client may not notice: the healthy replacement answers), or a Go
# panic in the transteira log. Nothing when all is well.
check_containers() {
	local c state n
	for c in "$@"; do
		[ -n "$c" ] || continue
		state=$("$docker" inspect -f '{{.RestartCount}} {{.State.OOMKilled}}' "$c" 2>/dev/null || echo missing)
		[ "$state" = "0 false" ] || echo "$c: RestartCount and OOMKilled are '$state', want '0 false'"
	done
	# grep -c reads the whole log (grep -q could stop early and, with pipefail, hide a match).
	n=$("$docker" logs "$1" 2>&1 | grep -c 'panic:' || true)
	[ "${n:-0}" = 0 ] || echo "$1: $n line(s) with 'panic:' in its log"
}

# stop_sampler [CSV] writes the samples (stdout of the sampler) to CSV, if given, and removes the
# sampler container.
stop_sampler() {
	[ -n "$sampler" ] || return 0
	if [ -n "${1:-}" ]; then
		"$docker" logs "$sampler" 2>/dev/null >"$1" || true
	fi
	"$docker" rm -f "$sampler" >/dev/null 2>&1 || true
	sampler=""
}

final_cleanup() {
	local rc=$?
	set +e
	stop_sampler "$sampler_csv"
	"$docker" volume rm "$probe_volume" >/dev/null 2>&1
	[ -n "$bin_dir" ] && rm -rf "$bin_dir"
	if [ "$rc" != 0 ] && [ -n "$project" ] && "$docker" inspect "$project-transteira" >/dev/null 2>&1; then
		# Before the teardown: a crash, an OOM kill or a panic explains many failures.
		local problems
		problems=$(check_containers "$project-transteira" "$caddy_ctr")
		[ -z "$problems" ] || sed 's/^/bigfile: container problem: /' <<<"$problems" >&2
	fi
	if [ "$rc" != 0 ] && [ "$keep" = 1 ] && [ -n "$project" ]; then
		cat >&2 <<EOF
bigfile: BIGFILE_KEEP=1: the failed stack is KEPT for diagnosis.
bigfile:   logs:     docker logs $project-transteira    (security and audit logs: docker exec is impossible in
bigfile:             the scratch image; docker cp $project-transteira:/logs <folder>)
bigfile:   stack:    docker ps -a --filter label=com.docker.compose.project=$project
bigfile:             docker stats --no-stream \$(docker ps -q --filter label=com.docker.compose.project=$project)
bigfile:   memory:   $out/mem-${project#"$STACK_PREFIX"}.csv
bigfile:   HTTPS:    https://$tenant_host:${SMOKE_HTTPS_PORT:-?}  (resolves to 127.0.0.1; CA: $ca)
bigfile:   work dir: $work  (deployment copy, throwaway secrets)
bigfile:   clean up: bash scripts/bigfile.sh clean && rm -rf '$work'
EOF
	else
		stack_cleanup "$rc"
	fi
	exit "$rc"
}
trap final_cleanup EXIT
trap 'exit 130' INT TERM

# --- preflight --------------------------------------------------------------------------------------
"$docker" info >/dev/null 2>&1 || fail "Docker is not available ('$docker info' failed)"
"$docker" image inspect "$image" >/dev/null 2>&1 || fail "image $image not found: run 'make docker' first"
volumes_before=$(stack_real_volumes)

# Memory: clamd may use its 4 GiB limit, transteira 1 GiB, freshclam 1.5 GiB while it tests new
# signatures, PostgreSQL 1 GiB, plus Caddy.
mem_total=$("$docker" info --format '{{.MemTotal}}')
min_mem=$(size_bytes "${BIGFILE_MIN_DOCKER_MEM:-7GiB}")
if [ "$mem_total" -lt "$min_mem" ]; then
	fail "Docker has $(gib "$mem_total") of memory, the test needs at least $(gib "$min_mem")" \
		"(clamd 4 GiB + transteira 1 GiB + freshclam + PostgreSQL + Caddy): raise the memory of Docker Desktop" \
		"(Settings > Resources, or .wslconfig on WSL2) or set BIGFILE_MIN_DOCKER_MEM"
fi

# Disk: the encrypted file (a few bytes per 64 KiB chunk more than the original), the tus upload in
# progress, the database, the logs and the images. Probed on a volume, where the data volume lives.
need=$((bytes + bytes * 15 / 100 + 5 * GiB))
need_why="BIGFILE_BYTES $(gib "$bytes") x 1.15 + 5 GiB"
if [ -n "${BIGFILE_MIN_FREE:-}" ]; then
	need=$(size_bytes "$BIGFILE_MIN_FREE")
	need_why="BIGFILE_MIN_FREE"
fi
caddy_image=$(sed -n -E 's/^[[:space:]]*image:[[:space:]]*(caddy:[^[:space:]]+).*/\1/p' "$root/integrations/reverse-proxy/caddy/docker-compose.yml" | head -n 1)
[ -n "$caddy_image" ] || fail "no caddy image in integrations/reverse-proxy/caddy/docker-compose.yml"
"$docker" volume create "$probe_volume" >/dev/null
# "<used> <free>" in bytes, of the file system that holds the Docker volumes.
vm_df=$("$docker" run --rm --network none -v "$probe_volume:/v" "$caddy_image" df -Pk /v | awk 'NR == 2 { printf "%.0f %.0f\n", $3 * 1024, $4 * 1024 }') ||
	fail "cannot measure the free space of the Docker volumes"
"$docker" volume rm "$probe_volume" >/dev/null 2>&1 || true
read -r vm_used vm_free <<<"$vm_df"
[[ "${vm_used:-}" =~ ^[0-9]+$ && "${vm_free:-}" =~ ^[0-9]+$ ]] || fail "cannot read the free space of the Docker volumes (got '$vm_df')"
free=$vm_free
where="Docker volumes ($("$docker" info --format '{{.DockerRootDir}}'), probed in a container)"
# Docker Desktop on Windows keeps the volumes in a WSL2 disk image (VHDX) that grows on demand:
# the space seen inside is the image's maximum size, not what the host drive can still give it.
# What the test can still write is the space already allocated in the image but unused inside
# (the image never shrinks by itself) plus what the host drive can add to it.
if [[ "$(uname -s)" =~ ^(MINGW|MSYS|CYGWIN) ]] && [ -n "${LOCALAPPDATA:-}" ]; then
	vhdx_dir=""
	settings="${APPDATA:-}/Docker/settings-store.json"
	if [ -f "$settings" ]; then
		vhdx_dir=$(node -e 'try{const s=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(s.CustomWslDistroDir||"")}catch{}' "$(native "$settings")")
	fi
	[ -n "$vhdx_dir" ] || vhdx_dir="$LOCALAPPDATA/Docker/wsl"
	if [ -d "$vhdx_dir" ]; then
		host_free=$(df -Pk "$vhdx_dir" | awk 'NR == 2 { printf "%.0f\n", $4 * 1024 }')
		# The data disk (docker_data.vhdx, ext4.vhdx before Docker Desktop 4.30) is the largest image.
		vhdx=$(find "$vhdx_dir" -maxdepth 3 -type f -iname '*.vhdx' -printf '%s %p\n' 2>/dev/null | sort -n | tail -n 1)
		vhdx_size=${vhdx%% *}
		if [[ "$host_free" =~ ^[0-9]+$ && "$vhdx_size" =~ ^[0-9]+$ ]]; then
			slack=$((vhdx_size > vm_used ? vhdx_size - vm_used : 0))
			if [ $((host_free + slack)) -lt "$free" ]; then
				free=$((host_free + slack))
				where="Docker Desktop disk image $(native "${vhdx#* }") ($(gib "$host_free") free on its host drive + $(gib "$slack") allocated in the image but unused: image $(gib "$vhdx_size"), $(gib "$vm_used") used inside)"
			fi
		else
			log "WARNING: no Docker Desktop disk image (*.vhdx) found under $vhdx_dir: only the space inside the VM is checked"
		fi
	else
		log "WARNING: Docker Desktop disk image folder not found ($vhdx_dir): only the space inside the VM is checked"
	fi
fi
if [ "$free" -lt "$need" ]; then
	fail "not enough disk space: $(gib "$free") free on the $where, the test needs $(gib "$need")" \
		"($need_why). Free space ('docker system df' shows what" \
		"'docker system prune' could reclaim), give Docker Desktop a larger disk (60 to 80 GB," \
		"Settings > Resources), lower BIGFILE_BYTES, or set BIGFILE_MIN_FREE if the estimate is wrong."
fi
log "preflight: Docker memory $(gib "$mem_total"), $(gib "$free") free on the $where (needs $(gib "$need"))"

# The client and memcheck are compiled once, before any stack is up (a compile error fails fast).
mkdir -p "$out"
bin_dir=$(mktemp -d)
exe=""
[[ "$(uname -s)" =~ ^(MINGW|MSYS|CYGWIN) ]] && exe=.exe
client_bin="$bin_dir/bigfile.test$exe"
memcheck_bin="$bin_dir/memcheck$exe"
(cd "$root" && go build -o "$(native "$memcheck_bin")" ./test/bigfile/memcheck) || fail "test/bigfile/memcheck does not compile"
if [ -n "${BIGFILE_CLIENT:-}" ]; then
	log "client: BIGFILE_CLIENT override ($BIGFILE_CLIENT), the Go client is not used"
else
	(cd "$root" && go test -c -tags bigfile -o "$(native "$client_bin")" ./test/bigfile) ||
		fail "the Go client (test/bigfile, build tag bigfile) does not compile"
fi
max_mem_bytes=$(size_bytes "$max_mem")
max_clock_offset=${BIGFILE_MAX_CLOCK_OFFSET:-2s}
[[ "$max_clock_offset" =~ ^[0-9]+(ms|s|m)$ ]] || fail "BIGFILE_MAX_CLOCK_OFFSET must be a Go duration such as 2s or 500ms (got '$max_clock_offset')"

# ClamAV limit of the stack: lowered when asked (and told to the client, which expects the scan
# status that follows from it); the clamd limits of deploy/ stop at 2 GiB, so never above.
stack_env=()
if [ -n "${BIGFILE_CLAMAV_MAX_SCAN_BYTES:-}" ]; then
	[[ "$BIGFILE_CLAMAV_MAX_SCAN_BYTES" =~ ^[0-9]{7,10}$ ]] &&
		[ "$BIGFILE_CLAMAV_MAX_SCAN_BYTES" -ge 1048576 ] && [ "$BIGFILE_CLAMAV_MAX_SCAN_BYTES" -le 2147483648 ] ||
		fail "BIGFILE_CLAMAV_MAX_SCAN_BYTES must be a byte count from 1048576 to 2147483648 (got '$BIGFILE_CLAMAV_MAX_SCAN_BYTES')"
	stack_env+=("TT_CLAMAV_MAX_SCAN_BYTES=$BIGFILE_CLAMAV_MAX_SCAN_BYTES")
fi

# Optional client settings: exported only when set, so that the client keeps its own defaults.
for v in BIGFILE_CHUNK BIGFILE_CUT_AT BIGFILE_DL_CUT_AT BIGFILE_SEED BIGFILE_SCAN_TIMEOUT BIGFILE_CLAMAV_MAX_SCAN_BYTES; do
	if [ -n "${!v:-}" ]; then export "${v?}"; else unset "$v"; fi
done

# --- memory sampler -------------------------------------------------------------------------------
# start_sampler CONTAINER... starts the helper container $sampler (scripts/lib/memsampler.sh): it
# reads the cgroup of each CONTAINER once a second from the Docker host (read-only, no network,
# no capability, nobody user, few processes, bounded log) and logs
# "ms,container,anon,current,file,kernel,sock,swap" on its stdout. It carries the compose label of
# the project, so that every cleanup path removes it.
start_sampler() {
	local args=() c id
	for c in "$@"; do
		id=$("$docker" inspect --format '{{.Id}}' "$c")
		args+=("$c=$id")
	done
	sampler=$project-memsampler
	"$docker" run -d --name "$sampler" --label "com.docker.compose.project=$project" \
		--network none --cgroupns host --read-only --cap-drop ALL --security-opt no-new-privileges \
		--user 65534:65534 --memory 64m --pids-limit 32 \
		--log-driver json-file --log-opt max-size=100m \
		-v /sys/fs/cgroup:/cg:ro -v "$(native "$root/scripts/lib/memsampler.sh"):/memsampler.sh:ro" \
		--entrypoint sh "$caddy_image" /memsampler.sh "${args[@]}" >/dev/null
	local deadline=$((SECONDS + 30)) logs
	while :; do
		# Captured first: grep -q on a pipe could stop docker logs early (pipefail).
		logs=$("$docker" logs "$sampler" 2>&1 || true)
		grep -q '^memsampler: ready' <<<"$logs" && break
		[ "$("$docker" inspect --format '{{.State.Running}}' "$sampler" 2>/dev/null)" = true ] ||
			fail "the memory sampler stopped: $(tail -n 5 <<<"$logs")"
		[ "$SECONDS" -lt "$deadline" ] || fail "the memory sampler did not start within 30 s"
		sleep 1
	done
}

# host_ms prints the time of the client clock in ms (GNU date, or Node where date has no %N).
host_ms() {
	local t
	t=$(date +%s%3N 2>/dev/null || true)
	[[ "$t" =~ ^[0-9]{13,}$ ]] || t=$(node -e 'console.log(Date.now())')
	printf '%s' "$t"
}

# clock_offset prints the offset, in ms, of the clock of the samples (the Docker host, a VM with
# Docker Desktop) minus the clock of the client: the sampler time of now, computed as the sampler
# does from its "memsampler: clock <epoch> <uptime>" base and /proc/uptime read in the sampler
# container, against the middle of two client readings around that read. Best of three (the
# narrowest bracket); fails when even that bracket is wider than 2 s.
clock_offset() {
	local base e0 u0 t1 up t2 best="" bracket=""
	# stderr of the sampler only (its stdout is the CSV); read takes the first line.
	base=$("$docker" logs "$sampler" 2>&1 >/dev/null | sed -n 's/^memsampler: clock //p')
	read -r e0 u0 <<<"$base"
	[[ "${e0:-}" =~ ^[0-9]+$ && "${u0:-}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || fail "no clock line in the log of the memory sampler (got '$base')"
	for _ in 1 2 3; do
		t1=$(host_ms)
		up=$("$docker" exec "$sampler" cat /proc/uptime) || fail "cannot read the uptime in the memory sampler"
		t2=$(host_ms)
		if [ -z "$bracket" ] || [ $((t2 - t1)) -lt "$bracket" ]; then
			bracket=$((t2 - t1))
			best=$(awk -v e0="$e0" -v u0="$u0" -v u="${up%% *}" -v t1="$t1" -v t2="$t2" \
				'BEGIN { printf "%.0f\n", (e0 + u - u0) * 1000 - (t1 + t2) / 2 }')
		fi
	done
	[ "$bracket" -le 2000 ] || fail "cannot measure the clock offset of the Docker host: docker exec took $bracket ms"
	printf '%s' "$best"
}

# setup_token CONTAINER prints the setup token TransTeira logs while no admin exists.
setup_token() {
	local deadline=$((SECONDS + 60)) tok
	while :; do
		tok=$("$docker" logs "$1" 2>&1 | sed -n -E 's/.*Setup token: ([A-Za-z0-9_-]+).*/\1/p' | tail -n 1)
		[ -z "$tok" ] || {
			printf '%s' "$tok"
			return 0
		}
		[ "$SECONDS" -lt "$deadline" ] || fail "no 'Setup token:' line in the log of $1 within 60 s"
		sleep 1
	done
}

# --- per engine -------------------------------------------------------------------------------------
run_engine() {
	local engine=$1 t0=$SECONDS t
	stack_prepare "$engine" ${stack_env[@]+"${stack_env[@]}"}
	stack_up_proxy "BIGFILE_SUBNET and BIGFILE_PROXY_IP"
	stack_up "$timeout"
	local up_s=$((SECONDS - t0)) tt=$project-transteira
	caddy_ctr=$("$docker" inspect --format '{{.Name}}' "$("${proxy[@]}" ps -q caddy)")
	caddy_ctr=${caddy_ctr#/}
	local token
	token=$(setup_token "$tt")
	local csv="$out/mem-$engine.csv" report="$out/report-$engine.json"
	rm -f "$report"

	local port=$SMOKE_HTTPS_PORT
	export BIGFILE_BASE_URL="https://$tenant_host:$port" BIGFILE_ADMIN_URL="https://$admin_host:$port"
	export BIGFILE_CA_FILE BIGFILE_REPORT BIGFILE_SETUP_TOKEN=$token BIGFILE_BYTES=$bytes
	BIGFILE_CA_FILE=$(native "$ca")
	BIGFILE_REPORT=$(native "$report")
	export BIGFILE_RESOLVE="$tenant_host=127.0.0.1,$admin_host=127.0.0.1" BIGFILE_ENGINE=$engine
	# Not part of the client contract; handy for a client that reads the container logs.
	export BIGFILE_CONTAINER=$tt DOCKER=$docker

	log "$engine: client: $(gib "$bytes") through Caddy on $BIGFILE_BASE_URL (memory of $tt and $caddy_ctr sampled into $csv)"
	sampler_csv=$csv
	start_sampler "$tt" "$caddy_ctr"
	local offsets
	offsets=$(clock_offset)
	log "$engine: clock of the samples minus clock of the client: $offsets ms"
	t=$SECONDS
	local rc=0
	if [ -n "${BIGFILE_CLIENT:-}" ]; then
		bash -c "$BIGFILE_CLIENT" || rc=$?
	else
		(cd "$root/test/bigfile" && "$client_bin" -test.v -test.run '^TestBigFile$' -test.timeout "$client_timeout") || rc=$?
	fi
	local client_s=$((SECONDS - t))
	# Measured again at the end (a drift during the run shows up); a sampler that died has no
	# offset, and memcheck reports the windows it did not cover.
	local end_offset=""
	if [ "$("$docker" inspect --format '{{.State.Running}}' "$sampler" 2>/dev/null)" = true ]; then
		end_offset=$(clock_offset)
		offsets="$offsets,$end_offset"
		log "$engine: clock offset at the end: $end_offset ms"
	fi
	stop_sampler "$sampler_csv"
	local problems
	problems=$(check_containers "$tt" "$caddy_ctr")

	# The memory and report summary is printed even when the client failed (diagnosis).
	local mem_out mem_rc=0 report_args=()
	[ -f "$report" ] && report_args=(-report "$(native "$report")")
	mem_out=$("$memcheck_bin" -csv "$(native "$csv")" -server "$tt" -also "$caddy_ctr" \
		-max-mem "$max_mem_bytes" -label "$engine" -clock-offsets-ms "$offsets" \
		-max-clock-offset "$max_clock_offset" "${report_args[@]}") || mem_rc=$?
	printf '%s\n' "$mem_out"
	[ -z "$problems" ] || fail "$engine: $(tr '\n' ';' <<<"$problems")"
	[ "$rc" = 0 ] || fail "$engine: the client failed (exit $rc) after $client_s s (report: $report)"
	[ -f "$report" ] || fail "$engine: the client passed but wrote no report ($report)"
	[ "$mem_rc" = 0 ] || fail "$engine: memory check failed (samples in $csv)"
	# Once more just before the teardown: nothing crashed while memcheck ran.
	problems=$(check_containers "$tt" "$caddy_ctr")
	[ -z "$problems" ] || fail "$engine: $(tr '\n' ';' <<<"$problems")"
	log "$engine: client passed in $client_s s, no restart, OOM kill nor panic, memory OK"

	stack_cleanup
	caddy_ctr=""
	log "=== $engine: OK in $((SECONDS - t0)) s ==="
	summary+=("=== $engine: OK in $((SECONDS - t0)) s (stack up $up_s s, client $client_s s)")
	while IFS= read -r line; do summary+=("  ${line#memcheck ("$engine"): }"); done <<<"$mem_out"
}

total=$SECONDS
for engine in $engines; do
	run_engine "$engine"
done

volumes_after=$(stack_real_volumes)
[ "$volumes_before" = "$volumes_after" ] ||
	fail "volumes of a real installation changed during the run: before [$volumes_before], after [$volumes_after]"

log "summary ($(gib "$bytes") per engine, memory limit $max_mem):"
for line in "${summary[@]}"; do log "$line"; done
log "ALL OK ($engines) in $((SECONDS - total)) s"

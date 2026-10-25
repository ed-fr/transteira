#!/usr/bin/env bash
# End-to-end smoke test of the PRODUCTION deployment files (`make deploy-smoke`). Not part of
# `make check`: it needs Internet access (ClamAV signature updates) and takes several minutes.
#
#   scripts/deploy-smoke.sh [sqlite|postgres|both]      (default both)
#
# For each engine, with the image TRANSTEIRA_IMAGE (default transteira:local, built by
# `make docker`):
#   1. copies deploy/ into a temporary folder, creates the secrets with deploy/init-secrets.sh
#      (--postgres for PostgreSQL) and a .env from deploy/.env.example (admin host, trusted proxy,
#      proxy network, image);
#   2. creates a smoke proxy network with its own subnet (172.31.250.0/24, never the 172.30.0.0/24
#      of a real installation) and starts the reference Caddy compose file
#      (integrations/reverse-proxy/caddy/docker-compose.yml + test/deploy/docker-compose.smoke-caddy.yml)
#      with a Caddyfile generated from the reference one (see smoke_caddyfile), HTTPS published on
#      127.0.0.1:<free port> only;
#   3. starts deploy/docker-compose.yml (+ docker-compose.postgres.yml) with the real ClamAV, under
#      the compose project transteira-smoke-<engine>, every fixed container and volume name
#      remapped by test/deploy/docker-compose.smoke*.yml; waits until transteira is healthy;
#   4. checks the hardening: processes as UID 10001, read-only root file system, all capabilities
#      dropped, no-new-privileges, no published port on any service of the stack, clamd (and
#      PostgreSQL) on internal networks only, the clamd spool a tmpfs (reports clamd's memory use);
#   5. runs test/deploy/smoke.mjs over HTTPS through Caddy (setup, TOTP, tenant, real client IP in
#      the security log, token deposit with tus, EICAR detected by the real clamd, download and
#      SHA-256, files encrypted at rest; see that file);
#   6. `transteira version`, `transteira backup` (SQLite: a copy that passes PRAGMA quick_check;
#      PostgreSQL: refused with a pointer to db-backup), and for PostgreSQL the one-shot migrate
#      container exited 0, db-backup takes a pg_dump on demand, as the read-only transteira_backup
#      role, that holds the smoke tenant, that role cannot write, and the postgres superuser is
#      rejected over TCP but accepted on the local socket;
#   7. always removes the containers, networks, volumes and secrets it created (trap). Other
#      compose projects (a real installation, transteira-test, ...) are never touched; the script
#      checks that no volume of a real installation (transteira_*) appeared.
#
# The ClamAV signature volume (DEPLOY_SMOKE_CLAMAV_DB_VOLUME, default transteira-smoke-clamav-db)
# is kept between runs as a cache of the public signatures; DEPLOY_SMOKE_KEEP_SIGNATURES=0 deletes
# it at the end. Other settings: DEPLOY_SMOKE_SUBNET, DEPLOY_SMOKE_PROXY_IP,
# DEPLOY_SMOKE_TIMEOUT (seconds to wait for a healthy stack, default 900), DEPLOY_SMOKE_INTERNAL_SUBNET
# and DEPLOY_SMOKE_DB_SUBNET (the fixed subnets of the internal and db networks, by default
# 172.31.251.0/24 and 172.31.252.0/24, never those of a real installation).
set -euo pipefail

docker=${DOCKER:-docker}
root=$(cd "$(dirname "$0")/.." && pwd)
engines=${1:-both}
case "$engines" in
both) engines="sqlite postgres" ;;
sqlite | postgres) ;;
*)
	echo "usage: $0 [sqlite|postgres|both]" >&2
	exit 2
	;;
esac

# Git Bash on Windows: keep container paths (/transteira, /backups...) untouched.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

image=${TRANSTEIRA_IMAGE:-transteira:local}
subnet=${DEPLOY_SMOKE_SUBNET:-172.31.250.0/24}
proxy_ip=${DEPLOY_SMOKE_PROXY_IP:-172.31.250.10}
# Exported: they override INTERNAL_SUBNET and DB_SUBNET of the .env in the compose interpolation.
export INTERNAL_SUBNET=${DEPLOY_SMOKE_INTERNAL_SUBNET:-172.31.251.0/24}
export DB_SUBNET=${DEPLOY_SMOKE_DB_SUBNET:-172.31.252.0/24}
network=transteira-smoke-proxy
clamav_db=${DEPLOY_SMOKE_CLAMAV_DB_VOLUME:-transteira-smoke-clamav-db}
keep_signatures=${DEPLOY_SMOKE_KEEP_SIGNATURES:-1}
timeout=${DEPLOY_SMOKE_TIMEOUT:-900}
admin_host=admin.smoke.localhost
tenant_host=transfer.smoke.localhost

log() { echo "deploy-smoke: $*"; }
fail() {
	echo "deploy-smoke: FAIL: $*" >&2
	exit 1
}
# Paths handed to Docker and Node (Windows programs under Git Bash) must be native.
native() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

"$docker" info >/dev/null 2>&1 || fail "Docker is not available ('$docker info' failed)"
"$docker" image inspect "$image" >/dev/null 2>&1 || fail "image $image not found: run 'make docker' first"

# Volumes of a real installation present before the run: none may appear because of it.
real_volumes() { "$docker" volume ls -q | grep -E '^transteira_' | sort || true; }
volumes_before=$(real_volumes)

# Current run state, used by the cleanup trap.
project=""
work=""
stack=()
proxy=()

# purge_project NAME removes whatever is left of the compose project NAME (containers, volumes
# and networks carrying its compose label), without its compose files. Only smoke projects are
# ever passed here.
purge_project() {
	case "$1" in transteira-smoke-*) ;; *) fail "refusing to purge project $1" ;; esac
	local f="label=com.docker.compose.project=$1"
	"$docker" ps -aq --filter "$f" | xargs -r "$docker" rm -f -v >/dev/null 2>&1 || true
	"$docker" volume ls -q --filter "$f" | xargs -r "$docker" volume rm >/dev/null 2>&1 || true
	"$docker" network ls -q --filter "$f" | xargs -r "$docker" network rm >/dev/null 2>&1 || true
}

# cleanup [STATUS] tears the current engine run down; with a non-zero STATUS it first prints the
# last logs of the stack.
cleanup() {
	local rc=${1:-0}
	set +e
	if [ -n "$project" ]; then
		if [ "$rc" != 0 ] && [ ${#stack[@]} -gt 0 ]; then
			echo "deploy-smoke: --- last logs of $project ---" >&2
			"${stack[@]}" logs --no-color --tail 60 >&2 2>&1
			"${stack[@]}" ps -a >&2 2>&1
		fi
		[ ${#stack[@]} -gt 0 ] && "${stack[@]}" down -v --remove-orphans -t 10 >/dev/null 2>&1
		[ ${#proxy[@]} -gt 0 ] && "${proxy[@]}" down -v --remove-orphans -t 5 >/dev/null 2>&1
		purge_project "$project"
		purge_project "$project-proxy"
	fi
	"$docker" network rm "$network" >/dev/null 2>&1
	[ -n "$work" ] && rm -rf "$work"
	project=""
	work=""
	stack=()
	proxy=()
	set -e
}
final_cleanup() {
	local rc=$?
	cleanup "$rc"
	if [ "$keep_signatures" = 0 ]; then
		"$docker" volume rm "$clamav_db" >/dev/null 2>&1 || true
	fi
	exit "$rc"
}
trap final_cleanup EXIT
trap 'exit 130' INT TERM

# smoke_caddyfile OUT writes the Caddyfile of the smoke proxy, derived from the reference
# integrations/reverse-proxy/caddy/Caddyfile with exactly two changes:
#   - the site addresses become the smoke admin and tenant hosts (*.localhost);
#   - that site block gets `tls internal`: certificates from Caddy's internal CA instead of ACME
#     (no public DNS name, no port 80 reachable from the Internet).
# Every other directive (timeouts, buffering, compression, logs, headers) is used as is.
smoke_caddyfile() {
	local ref="$root/integrations/reverse-proxy/caddy/Caddyfile"
	awk -v hosts="$admin_host, $tenant_host" '
		/^admin\.transfer\.example\.com, .*\{$/ { print hosts " {"; print "\ttls internal"; done = 1; next }
		{ print }
		END { if (!done) exit 3 }
	' "$ref" >"$1" || fail "the site line of $ref was not found (update smoke_caddyfile)"
}

free_port() {
	node -e 'const s=require("net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})'
}

# wait_healthy CONTAINER TIMEOUT
wait_healthy() {
	local c=$1 deadline=$((SECONDS + $2)) state
	while :; do
		state=$("$docker" inspect --format '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c" 2>/dev/null || echo missing)
		case "$state" in
		*/healthy) return 0 ;;
		exited/* | dead/* | missing) fail "$c is $state" ;;
		esac
		[ "$SECONDS" -lt "$deadline" ] || fail "$c not healthy after $2 s (state $state)"
		sleep 2
	done
}

# sorted_words WORD... prints the words sorted (C locale), on one line.
sorted_words() { printf '%s\n' "$@" | grep -v '^$' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//'; }

# container_networks CONTAINER prints its network names, sorted, on one line.
container_networks() {
	# shellcheck disable=SC2046,SC2016 # word splitting wanted (no space in network names); Go template
	sorted_words $("$docker" inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$1")
}

assert_hardened() {
	local c=$1
	[ "$("$docker" inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$c")" = true ] || fail "$c: root file system is not read-only"
	"$docker" inspect --format '{{.HostConfig.CapDrop}}' "$c" | grep -qw ALL || fail "$c: capabilities not all dropped"
	"$docker" inspect --format '{{.HostConfig.SecurityOpt}}' "$c" | grep -q 'no-new-privileges' || fail "$c: no-new-privileges missing"
	[ "$("$docker" inspect --format '{{.HostConfig.Privileged}}' "$c")" = false ] || fail "$c: privileged"
}

assert_uid() {
	local c=$1 want=$2 uids
	uids=$("$docker" top "$c" -o pid,uid | awk 'NR > 1 {print $2}' | sort -u | tr '\n' ' ' | sed 's/ $//')
	[ "$uids" = "$want" ] || fail "$c: processes run as UID(s) '$uids', expected $want"
}

run_engine() {
	local engine=$1 t0=$SECONDS t
	project=transteira-smoke-$engine
	# Leftovers of an interrupted run (killed before its trap ran).
	purge_project "$project"
	purge_project "$project-proxy"
	"$docker" network rm "$network" >/dev/null 2>&1 || true
	work=$(mktemp -d)
	local deploy="$work/deploy"
	log "=== $engine: project $project, work dir $work ==="

	# 1. Deployment folder, secrets, .env, as an operator would.
	mkdir -p "$deploy"
	cp -R "$root/deploy/." "$deploy/"
	rm -rf "$deploy/secrets" "$deploy/.env"
	local pg_flag=()
	[ "$engine" = postgres ] && pg_flag=(--postgres)
	sh "$deploy/init-secrets.sh" "${pg_flag[@]}" "$deploy/secrets" 2>/dev/null | sed 's/^/deploy-smoke:   /'
	if [ "$(uname -s)" = Linux ] && [ "$(id -u)" != 0 ]; then
		# Not root: init-secrets.sh could not give the files to UID 10001 / 70. Throwaway values:
		# make them readable by the containers instead.
		chmod 0755 "$deploy/secrets"
		chmod 0444 "$deploy/secrets"/*
	fi
	sed -e "s|^TRANSTEIRA_IMAGE=.*|TRANSTEIRA_IMAGE=$image|" \
		-e "s|^PROXY_NETWORK=.*|PROXY_NETWORK=$network|" \
		-e "s|^TT_ADMIN_HOSTS=.*|TT_ADMIN_HOSTS=$admin_host|" \
		-e "s|^TT_TRUSTED_PROXIES=.*|TT_TRUSTED_PROXIES=$proxy_ip|" \
		"$root/deploy/.env.example" >"$deploy/.env"
	for v in "TRANSTEIRA_IMAGE=$image" "PROXY_NETWORK=$network" "TT_ADMIN_HOSTS=$admin_host" "TT_TRUSTED_PROXIES=$proxy_ip"; do
		grep -qx "$v" "$deploy/.env" || fail "deploy/.env.example: could not set $v (variable missing?)"
	done

	export SMOKE_PROJECT=$project SMOKE_CLAMAV_DB_VOLUME=$clamav_db SMOKE_PROXY_NETWORK=$network SMOKE_PROXY_IP=$proxy_ip
	SMOKE_HTTPS_PORT=$(free_port)
	export SMOKE_HTTPS_PORT
	smoke_caddyfile "$work/Caddyfile"
	export SMOKE_CADDYFILE
	SMOKE_CADDYFILE=$(native "$work/Caddyfile")

	stack=("$docker" compose -p "$project" --project-directory "$(native "$deploy")" -f "$(native "$deploy/docker-compose.yml")")
	[ "$engine" = postgres ] && stack+=(-f "$(native "$deploy/docker-compose.postgres.yml")")
	stack+=(-f "$(native "$root/test/deploy/docker-compose.smoke.yml")")
	[ "$engine" = postgres ] && stack+=(-f "$(native "$root/test/deploy/docker-compose.smoke-postgres.yml")")
	proxy=("$docker" compose -p "$project-proxy" -f "$(native "$root/integrations/reverse-proxy/caddy/docker-compose.yml")"
		-f "$(native "$root/test/deploy/docker-compose.smoke-caddy.yml")")

	# 2. Proxy network and Caddy.
	"$docker" network create --subnet "$subnet" "$network" >/dev/null ||
		fail "cannot create network $network with subnet $subnet (set DEPLOY_SMOKE_SUBNET and DEPLOY_SMOKE_PROXY_IP)"
	"${proxy[@]}" up -d --quiet-pull 2>&1 | sed 's/^/deploy-smoke:   /'
	local ca="$work/caddy-root.crt" deadline=$((SECONDS + 60))
	until "${proxy[@]}" exec -T caddy cat /data/caddy/pki/authorities/local/root.crt >"$ca" 2>/dev/null && [ -s "$ca" ]; do
		[ "$SECONDS" -lt "$deadline" ] || fail "Caddy did not create its internal CA within 60 s"
		sleep 1
	done
	log "Caddy up on https://127.0.0.1:$SMOKE_HTTPS_PORT ($proxy_ip on $network, internal CA)"

	# 3. The stack. The signature volume is a cache kept between runs (see the header).
	"$docker" volume inspect "$clamav_db" >/dev/null 2>&1 || "$docker" volume create "$clamav_db" >/dev/null
	t=$SECONDS
	"${stack[@]}" up -d --quiet-pull 2>&1 | sed 's/^/deploy-smoke:   /'
	local tt=$project-transteira clam=$project-clamav
	wait_healthy "$tt" "$timeout"
	log "stack healthy in $((SECONDS - t)) s"

	# 4. Hardening.
	assert_hardened "$tt"
	assert_uid "$tt" 10001
	assert_hardened "$clam"
	assert_uid "$clam" 100
	local ids id name ports
	ids=$("${stack[@]}" ps -a -q)
	for id in $ids; do
		name=$("$docker" inspect --format '{{.Name}}' "$id")
		ports=$("$docker" port "$id" 2>/dev/null || true)
		[ -z "$ports" ] || fail "$name publishes ports: $ports"
	done
	local nets
	nets=$(container_networks "$clam")
	[ "$nets" = "${project}_internal" ] || fail "clamav networks are '$nets', expected only ${project}_internal"
	[ "$("$docker" network inspect --format '{{.Internal}}' "${project}_internal")" = true ] || fail "${project}_internal is not internal"
	nets=$(container_networks "$tt")
	if [ "$engine" = postgres ]; then
		[ "$nets" = "$(sorted_words "${project}_db" "${project}_internal" "$network")" ] || fail "transteira networks are '$nets'"
		[ "$(container_networks "$project-postgres")" = "${project}_db" ] || fail "postgres is not on ${project}_db only"
		[ "$("$docker" network inspect --format '{{.Internal}}' "${project}_db")" = true ] || fail "${project}_db is not internal"
		assert_hardened "$project-postgres"
		assert_uid "$project-postgres" 70
	else
		[ "$nets" = "$(sorted_words "${project}_internal" "$network")" ] || fail "transteira networks are '$nets'"
	fi
	log "hardening OK: transteira UID 10001, clamd UID 100, read-only, cap_drop ALL, no-new-privileges," \
		"no published port, clamd on ${project}_internal only"

	# clamd spool in memory (T-44): a tmpfs, no volume on it, owned by clamav, nothing else mounted there.
	"$docker" inspect --format '{{range $k, $v := .HostConfig.Tmpfs}}{{$k}}={{$v}}{{"\n"}}{{end}}' "$clam" |
		grep -q '^/var/tmp/clamav=.*size=' || fail "$clam: /var/tmp/clamav is not a tmpfs with a size"
	# shellcheck disable=SC2016 # Go template
	if "$docker" inspect --format '{{range .Mounts}}{{.Destination}}{{"\n"}}{{end}}' "$clam" | grep -q '^/var/tmp/clamav'; then
		fail "$clam: a volume is mounted on the clamd spool"
	fi
	local spool
	spool=$("$docker" exec "$clam" sh -c 'stat -c "%u:%g %a" /var/tmp/clamav && grep " /var/tmp/clamav " /proc/mounts') ||
		fail "$clam: cannot inspect the spool"
	grep -q '^100:101 700' <<<"$spool" && grep -q ' tmpfs ' <<<"$spool" || fail "$clam: unexpected spool: $spool"
	log "clamd spool: tmpfs, 100:101, mode 0700; clamd memory after start:" \
		"$("$docker" stats --no-stream --format '{{.MemUsage}}' "$clam")"

	# freshclam (clamav-update): alone on the egress network, hardened, and its first update check
	# completes (signatures downloaded, or already up to date in the cached volume).
	local upd=$project-clamav-update fresh
	assert_hardened "$upd"
	assert_uid "$upd" 100
	[ "$(container_networks "$upd")" = "${project}_clamav_egress" ] || fail "clamav-update is not on ${project}_clamav_egress only"
	deadline=$((SECONDS + 600))
	while :; do
		[ "$("$docker" inspect --format '{{.State.Running}} {{.RestartCount}}' "$upd")" = "true 0" ] ||
			fail "clamav-update stopped or restarted: $("$docker" logs --tail 20 "$upd" 2>&1)"
		fresh=$("$docker" logs "$upd" 2>&1)
		if grep -qE 'daily\.c[lv]d (database )?(is up-to-date|updated)' <<<"$fresh"; then break; fi
		if grep -qE 'ERROR' <<<"$fresh"; then fail "freshclam reports errors: $(grep -E 'ERROR' <<<"$fresh" | tail -5)"; fi
		[ "$SECONDS" -lt "$deadline" ] || fail "freshclam did not complete its first check within 600 s: $(tail -n 10 <<<"$fresh")"
		sleep 2
	done
	log "freshclam: $(grep -E 'daily\.c[lv]d' <<<"$fresh" | tail -n 1 | sed -E 's/^.*-> //')"

	# 5. HTTPS checks through Caddy.
	mkdir -p "$work/node"
	SMOKE_CA_FILE=$(native "$ca") SMOKE_ADMIN_HOST=$admin_host SMOKE_TENANT_HOST=$tenant_host \
		SMOKE_CONTAINER=$tt SMOKE_WORK_DIR=$(native "$work/node") DOCKER=$docker \
		node "$(native "$root/test/deploy/smoke.mjs")"

	# 6. Commands in the scratch container, backups.
	local out
	out=$("$docker" exec "$tt" /transteira version) || fail "transteira version failed"
	log "transteira version: $out"
	if [ "$engine" = sqlite ]; then
		out=$("$docker" exec "$tt" /transteira backup 2>&1) || fail "transteira backup failed: $out"
		log "transteira backup: $out"
		rm -rf "$work/backups"
		"$docker" cp "$tt:/backups" "$(native "$work/backups")"
		local copy
		copy=$(find "$work/backups" -type f -name '*.db' | head -n 1)
		[ -n "$copy" ] || fail "no SQLite copy in the backups volume: $(ls -la "$work/backups")"
		node --no-warnings -e '
			const { DatabaseSync } = require("node:sqlite");
			const db = new DatabaseSync(process.argv[1], { readOnly: true });
			const qc = db.prepare("PRAGMA quick_check").get();
			if (Object.values(qc)[0] !== "ok") { console.error("quick_check: " + JSON.stringify(qc)); process.exit(1); }
			const n = db.prepare("SELECT count(*) AS n FROM tenants WHERE fqdn = ?").get(process.argv[2]).n;
			if (n !== 1) { console.error("smoke tenant not in the copy"); process.exit(1); }
		' "$(native "$copy")" "$tenant_host" || fail "the SQLite backup copy is not usable"
		log "backup copy $(basename "$copy"): PRAGMA quick_check ok, holds the smoke tenant"
	else
		if out=$("$docker" exec "$tt" /transteira backup 2>&1); then
			fail "transteira backup succeeded with PostgreSQL (expected a refusal pointing to db-backup)"
		fi
		grep -q 'db-backup' <<<"$out" || fail "transteira backup refusal does not mention db-backup: $out"
		log "transteira backup refused with PostgreSQL, pointing to db-backup (expected)"
		local mig code
		mig=$("${stack[@]}" ps -a -q migrate)
		[ -n "$mig" ] || fail "no migrate container"
		code=$("$docker" inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$mig")
		[ "$code" = "exited 0" ] || fail "migrate is '$code', expected 'exited 0'"
		log "migrate one-shot: exited 0"
		local bk=$project-db-backup
		[ "$("$docker" inspect --format '{{.State.Running}}' "$bk")" = true ] || fail "db-backup is not running"
		assert_hardened "$bk"
		# shellcheck disable=SC2016 # expanded by the shell of the container
		out=$("$docker" exec "$bk" sh -c 'f=/backups/transteira-smoke.dump; pg_dump --enable-row-security --format=custom --file="$f.tmp" && mv "$f.tmp" "$f" && pg_restore --data-only --table=tenants --file=- "$f"' 2>&1) ||
			fail "pg_dump in db-backup failed: $out"
		grep -q "$tenant_host" <<<"$out" || fail "the pg_dump does not hold the smoke tenant (row-level security?)"
		# shellcheck disable=SC2016 # expanded by the shell of the container
		out=$("$docker" exec "$bk" sh -c 'echo "$PGUSER"; psql -XAtc "SELECT current_user"') || fail "psql in db-backup failed: $out"
		[ "$(tr '\n' ' ' <<<"$out")" = "transteira_backup transteira_backup " ] || fail "db-backup does not connect as transteira_backup: $out"
		if out=$("$docker" exec "$bk" psql -XAtc "DELETE FROM transteira.tenants" 2>&1); then
			fail "the backup role could delete rows: $out"
		fi
		grep -q 'permission denied' <<<"$out" || fail "unexpected answer to a write by the backup role: $out"
		if out=$("$docker" exec "$bk" psql -XAtc "CREATE TABLE transteira.smoke_probe (v int)" 2>&1); then
			fail "the backup role could create a table: $out"
		fi
		log "db-backup: on-demand pg_dump OK as transteira_backup (row-level security system scope)," \
			"holds the smoke tenant; writes and DDL refused"
		local pg=$project-postgres
		if out=$("$docker" exec "$pg" psql -XAt -h 127.0.0.1 -U postgres -d transteira -c "SELECT 1" 2>&1); then
			fail "the postgres superuser could connect over TCP"
		fi
		grep -q 'pg_hba.conf rejects' <<<"$out" || fail "unexpected refusal of the superuser over TCP: $out"
		out=$("$docker" exec "$pg" psql -XAt -U postgres -d transteira -c "SELECT 1" 2>&1) ||
			fail "the postgres superuser cannot use the local socket: $out"
		log "postgres: superuser rejected over TCP (pg_hba), accepted on the local socket (peer)"
	fi

	cleanup
	log "=== $engine: OK in $((SECONDS - t0)) s ==="
}

total=$SECONDS
for engine in $engines; do
	run_engine "$engine"
done

volumes_after=$(real_volumes)
[ "$volumes_before" = "$volumes_after" ] ||
	fail "volumes of a real installation changed during the run: before [$volumes_before], after [$volumes_after]"
log "ALL OK ($engines) in $((SECONDS - total)) s"

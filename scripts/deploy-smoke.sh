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
#      with a Caddyfile generated from the reference one (see stack_caddyfile in
#      scripts/lib/stack.sh), HTTPS published on 127.0.0.1:<free port> only;
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
#
# Steps 1 to 3 and 7 live in scripts/lib/stack.sh, shared with scripts/bigfile.sh.
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

STACK_TAG=deploy-smoke
STACK_PREFIX=transteira-smoke-
# shellcheck source=scripts/lib/stack.sh
. "$root/scripts/lib/stack.sh"

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

"$docker" info >/dev/null 2>&1 || fail "Docker is not available ('$docker info' failed)"
"$docker" image inspect "$image" >/dev/null 2>&1 || fail "image $image not found: run 'make docker' first"

# Volumes of a real installation present before the run: none may appear because of it.
volumes_before=$(stack_real_volumes)

final_cleanup() {
	local rc=$?
	stack_cleanup "$rc"
	if [ "$keep_signatures" = 0 ]; then
		"$docker" volume rm "$clamav_db" >/dev/null 2>&1 || true
	fi
	exit "$rc"
}
trap final_cleanup EXIT
trap 'exit 130' INT TERM

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
	local engine=$1 t0=$SECONDS
	# 1. Deployment folder, secrets, .env, as an operator would.
	stack_prepare "$engine"

	# 2. Proxy network and Caddy.
	stack_up_proxy "DEPLOY_SMOKE_SUBNET and DEPLOY_SMOKE_PROXY_IP"

	# 3. The stack. The signature volume is a cache kept between runs (see the header).
	stack_up "$timeout"
	local tt=$project-transteira clam=$project-clamav

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
	local deadline=$((SECONDS + 600))
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

	stack_cleanup
	log "=== $engine: OK in $((SECONDS - t0)) s ==="
}

total=$SECONDS
for engine in $engines; do
	run_engine "$engine"
done

volumes_after=$(stack_real_volumes)
[ "$volumes_before" = "$volumes_after" ] ||
	fail "volumes of a real installation changed during the run: before [$volumes_before], after [$volumes_after]"
log "ALL OK ($engines) in $((SECONDS - total)) s"

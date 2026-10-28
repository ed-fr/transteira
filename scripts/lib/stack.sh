# shellcheck shell=bash
# Shared stack logic of the Docker test scripts that run the PRODUCTION deployment files behind
# the reference Caddy: scripts/deploy-smoke.sh (`make deploy-smoke`) and scripts/bigfile.sh
# (`make bigfile`). Sourced, never executed.
#
# The caller sets, before sourcing:
#   STACK_TAG     prefix of every message (deploy-smoke, bigfile);
#   STACK_PREFIX  compose project prefix the script owns (transteira-smoke-, transteira-bigfile-):
#                 stack_purge_project refuses any other project;
# and, before stack_prepare:
#   docker root image network subnet proxy_ip clamav_db admin_host tenant_host
#   INTERNAL_SUBNET DB_SUBNET (exported: they override those of the .env in the compose files).
#
# Run state, used by stack_cleanup (globals): project work stack[] proxy[] ca.
#
# What a stack is (see scripts/deploy-smoke.sh for the full description):
#   - deploy/ copied to a temporary folder with fresh secrets (deploy/init-secrets.sh) and a .env
#     from deploy/.env.example (image, proxy network, admin host, trusted proxy);
#   - the reference Caddy compose file under the project <project>-proxy, overridden by
#     test/deploy/docker-compose.smoke-caddy.yml (Caddyfile derived from the reference one with
#     `tls internal`, HTTPS on 127.0.0.1:<free port>, fixed address on the test proxy network);
#   - deploy/docker-compose.yml (+ docker-compose.postgres.yml) under the project <project>, every
#     fixed container and volume name remapped by test/deploy/docker-compose.smoke*.yml
#     (SMOKE_PROJECT=<project>), the ClamAV signature volume external and kept as a cache.

: "${STACK_TAG:?STACK_TAG must be set before sourcing scripts/lib/stack.sh}"
: "${STACK_PREFIX:?STACK_PREFIX must be set before sourcing scripts/lib/stack.sh}"

# Git Bash on Windows: keep container paths (/transteira, /backups...) untouched.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

log() { echo "$STACK_TAG: $*"; }
fail() {
	echo "$STACK_TAG: FAIL: $*" >&2
	exit 1
}
# Paths handed to Docker, Node and Go (Windows programs under Git Bash) must be native.
native() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

project=""
work=""
ca=""
stack=()
proxy=()

# stack_real_volumes prints the volumes of a real installation (transteira_*), sorted: none may
# appear because of a test run.
stack_real_volumes() { "$docker" volume ls -q | grep -E '^transteira_' | sort || true; }

# stack_purge_project NAME removes whatever is left of the compose project NAME (containers,
# volumes and networks carrying its compose label), without its compose files. Only projects of
# the calling script (STACK_PREFIX) are accepted.
stack_purge_project() {
	case "$1" in "$STACK_PREFIX"*) ;; *) fail "refusing to purge project $1" ;; esac
	local f="label=com.docker.compose.project=$1"
	"$docker" ps -aq --filter "$f" | xargs -r "$docker" rm -f -v >/dev/null 2>&1 || true
	"$docker" volume ls -q --filter "$f" | xargs -r "$docker" volume rm >/dev/null 2>&1 || true
	"$docker" network ls -q --filter "$f" | xargs -r "$docker" network rm >/dev/null 2>&1 || true
}

# stack_cleanup [STATUS] tears the current run down (stack, proxy, network, work folder); with a
# non-zero STATUS it first prints the last logs of the stack.
stack_cleanup() {
	local rc=${1:-0}
	set +e
	if [ -n "$project" ]; then
		if [ "$rc" != 0 ] && [ ${#stack[@]} -gt 0 ]; then
			# The setup token of the first run is in the transteira log: never echoed (a kept
			# stack, BIGFILE_KEEP=1, still has no admin and accepts it).
			echo "$STACK_TAG: --- last logs of $project (setup token redacted) ---" >&2
			"${stack[@]}" logs --no-color --tail 60 2>&1 | sed -E 's/(Setup token: )[A-Za-z0-9_-]+/\1[redacted]/g' >&2
			"${stack[@]}" ps -a >&2 2>&1
		fi
		[ ${#stack[@]} -gt 0 ] && "${stack[@]}" down -v --remove-orphans -t 10 >/dev/null 2>&1
		[ ${#proxy[@]} -gt 0 ] && "${proxy[@]}" down -v --remove-orphans -t 5 >/dev/null 2>&1
		stack_purge_project "$project"
		stack_purge_project "$project-proxy"
	fi
	"$docker" network rm "$network" >/dev/null 2>&1
	[ -n "$work" ] && rm -rf "$work"
	project=""
	work=""
	ca=""
	stack=()
	proxy=()
	set -e
}

# stack_caddyfile OUT writes the Caddyfile of the test proxy, derived from the reference
# integrations/reverse-proxy/caddy/Caddyfile with exactly two changes:
#   - the site addresses of the admin block and of the tenant block become the test admin host
#     and the test tenant host (*.localhost);
#   - both site blocks get `tls internal`: certificates from Caddy's internal CA instead of ACME
#     (no public DNS name, no port 80 reachable from the Internet).
# Every other directive (timeouts, buffering, compression, logs, headers, the monitoring paths
# hidden on the tenant hosts) is used as is.
stack_caddyfile() {
	local ref="$root/integrations/reverse-proxy/caddy/Caddyfile"
	awk -v admin="$admin_host" -v tenant="$tenant_host" '
		/^admin\.transfer\.example\.com \{$/ { print admin " {"; print "\ttls internal"; a = 1; next }
		/^transfer\.entity-a\.example\.com, .*\{$/ { print tenant " {"; print "\ttls internal"; t = 1; next }
		{ print }
		END { if (!a || !t) exit 3 }
	' "$ref" >"$1" || fail "the site lines of $ref were not found (update stack_caddyfile in scripts/lib/stack.sh)"
}

stack_free_port() {
	node -e 'const s=require("net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})'
}

# stack_wait_healthy CONTAINER TIMEOUT
stack_wait_healthy() {
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

# stack_prepare ENGINE [ENV_LINE...] sets project=${STACK_PREFIX}ENGINE (after purging the
# leftovers of an interrupted run), creates the work folder with the deployment copy, its secrets
# and .env (each ENV_LINE, KEY=VALUE, is appended to the .env), the Caddyfile, and fills stack[]
# and proxy[] with the compose commands. Exports SMOKE_* for the override files.
stack_prepare() {
	local engine=$1
	shift
	project=$STACK_PREFIX$engine
	# Leftovers of an interrupted run (killed before its trap ran).
	stack_purge_project "$project"
	stack_purge_project "$project-proxy"
	"$docker" network rm "$network" >/dev/null 2>&1 || true
	work=$(mktemp -d)
	local deploy="$work/deploy"
	log "=== $engine: project $project, work dir $work ==="

	# Deployment folder, secrets, .env, as an operator would.
	mkdir -p "$deploy"
	cp -R "$root/deploy/." "$deploy/"
	rm -rf "$deploy/secrets" "$deploy/.env"
	local pg_flag=()
	[ "$engine" = postgres ] && pg_flag=(--postgres)
	sh "$deploy/init-secrets.sh" "${pg_flag[@]}" "$deploy/secrets" 2>/dev/null | sed "s/^/$STACK_TAG:   /"
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
	local line
	for line in "$@"; do printf '%s\n' "$line" >>"$deploy/.env"; done

	export SMOKE_PROJECT=$project SMOKE_CLAMAV_DB_VOLUME=$clamav_db SMOKE_PROXY_NETWORK=$network SMOKE_PROXY_IP=$proxy_ip
	SMOKE_HTTPS_PORT=$(stack_free_port)
	export SMOKE_HTTPS_PORT
	stack_caddyfile "$work/Caddyfile"
	export SMOKE_CADDYFILE
	SMOKE_CADDYFILE=$(native "$work/Caddyfile")

	stack=("$docker" compose -p "$project" --project-directory "$(native "$deploy")" -f "$(native "$deploy/docker-compose.yml")")
	[ "$engine" = postgres ] && stack+=(-f "$(native "$deploy/docker-compose.postgres.yml")")
	stack+=(-f "$(native "$root/test/deploy/docker-compose.smoke.yml")")
	[ "$engine" = postgres ] && stack+=(-f "$(native "$root/test/deploy/docker-compose.smoke-postgres.yml")")
	proxy=("$docker" compose -p "$project-proxy" -f "$(native "$root/integrations/reverse-proxy/caddy/docker-compose.yml")"
		-f "$(native "$root/test/deploy/docker-compose.smoke-caddy.yml")")
	return 0
}

# stack_up_proxy creates the test proxy network, starts Caddy and copies its internal root CA to
# $ca ($work/caddy-root.crt). SUBNET_HINT names the variables to set if the subnet is taken.
stack_up_proxy() {
	local hint=$1
	"$docker" network create --subnet "$subnet" "$network" >/dev/null ||
		fail "cannot create network $network with subnet $subnet (set $hint)"
	"${proxy[@]}" up -d --quiet-pull 2>&1 | sed "s/^/$STACK_TAG:   /"
	ca="$work/caddy-root.crt"
	local deadline=$((SECONDS + 60))
	until "${proxy[@]}" exec -T caddy cat /data/caddy/pki/authorities/local/root.crt >"$ca" 2>/dev/null && [ -s "$ca" ]; do
		[ "$SECONDS" -lt "$deadline" ] || fail "Caddy did not create its internal CA within 60 s"
		sleep 1
	done
	log "Caddy up on https://127.0.0.1:$SMOKE_HTTPS_PORT ($proxy_ip on $network, internal CA)"
}

# stack_up TIMEOUT starts the stack (creating the signature cache volume if needed) and waits
# until the transteira container is healthy.
stack_up() {
	local timeout=$1 t=$SECONDS
	"$docker" volume inspect "$clamav_db" >/dev/null 2>&1 || "$docker" volume create "$clamav_db" >/dev/null
	"${stack[@]}" up -d --quiet-pull 2>&1 | sed "s/^/$STACK_TAG:   /"
	stack_wait_healthy "$project-transteira" "$timeout"
	log "stack healthy in $((SECONDS - t)) s"
}

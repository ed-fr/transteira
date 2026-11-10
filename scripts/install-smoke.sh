#!/usr/bin/env bash
# End-to-end test of the release installer (`make install-smoke`, part of `make check-full`, never
# of `make check`): the REAL install.sh runs on a blank Debian server, in a disposable container.
#
#   scripts/install-smoke.sh [12|13|both] [sqlite|postgres|both]      (default both both)
#
# What it does, once:
#   1. a throwaway cosign key and a throwaway registry (registry:3, pinned) on 127.0.0.1:<port>;
#   2. two images of this working tree (versions 99.0.0 and 99.0.1, linux/amd64 and linux/arm64
#      index, like a release) built with the BuildKit builder of the release dry run, pushed by
#      digest, signed, SBOM attested (scripts/release.sh dry does the same);
#   3. two install.sh built by scripts/install/build.sh for them (the key is the throwaway one).
# And for each Debian release (pinned 12 and 13 images) and each engine, in a FRESH container:
#   4. a privileged container with systemd as PID 1 and its own /var/lib/docker (Docker in Docker),
#      the registry joined to its network namespace (so that localhost:<port> is the registry), no
#      Docker, no cosign, no firewall: a blank server;
#   5. install.sh 99.0.0 with the test hook (TT_INSTALL_TEST_MODE: Caddy "tls internal", no
#      transparency log, no outbound network check); the PostgreSQL runs also use the system SMTP
#      options with a password file; the summary shows the setup token, the log file never does;
#   6. test/deploy/smoke.mjs over HTTPS through the installed Caddy (setup, TOTP, tenant with
#      on-demand TLS, deposit, EICAR, downloads, encryption at rest), `docker` being the Docker of
#      the container;
#   7. the host: nftables table, firewall unit, real connections (22, 80, 443 open, another port
#      dropped), fail2ban jails and a real ban from lines of the security log, SMTP secret;
#   8. a second run is refused, then `install.sh 99.0.1 --upgrade`: healthy again, new version,
#      .env (but its image), secrets, Caddyfile, jail and SMTP overlay kept, a database backup
#      made, the entity and its page still there; a downgrade is refused;
#   9. everything created is removed (container, volumes, registry, images, key).
# The per-step durations are printed at the end.
#
# Needs Docker with privileged containers (cgroup v2), Node 24, Go (cosign and syft run with
# `go run`, COSIGN and SYFT) and Internet access (Debian and Docker packages, cosign from GitHub,
# Docker Hub, ClamAV signatures). It never touches a Docker resource it did not create: every
# container and volume carries the label transteira-install-smoke=1 and a name starting with
# transteira-install-. The ClamAV signatures are cached in the volume
# transteira-install-clamav-db between runs (INSTALL_SMOKE_KEEP_SIGNATURES=0 removes it).
#
# Other settings: INSTALL_SMOKE_KEEP=1 keeps the failed container (inspect it, then remove it with
# `docker rm -f -v` and its volume), INSTALL_SMOKE_TIMEOUT (seconds of the installer, default 1800).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
docker=${DOCKER:-docker}
COSIGN=${COSIGN:-env GOFLAGS= go run github.com/sigstore/cosign/v3/cmd/cosign@v3.1.4}
SYFT=${SYFT:-env GOFLAGS= go run github.com/anchore/syft/cmd/syft@v1.57.0}
MAKE=${MAKE:-make}
debians=${1:-both}
engines=${2:-both}
case "$debians" in
both) debians="12 13" ;;
12 | 13) ;;
*)
	echo "usage: $0 [12|13|both] [sqlite|postgres|both]" >&2
	exit 2
	;;
esac
case "$engines" in
both) engines="sqlite postgres" ;;
sqlite | postgres) ;;
*)
	echo "usage: $0 [12|13|both] [sqlite|postgres|both]" >&2
	exit 2
	;;
esac

# Pinned bases (index digests of the -slim images).
# shellcheck disable=SC2034 # read through ${!base_var}
base_12="debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc"
# shellcheck disable=SC2034 # read through ${!base_var}
base_13="debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
REGISTRY_IMAGE="registry:3@sha256:38907510915c3f1604c7e83d6ab602ab3020d092f73bdaed8696773693ff768c"
BUILDKIT_IMAGE="moby/buildkit:v0.34.0@sha256:b059f8d7226d0b326bc871af489a5dddf65e36af4d20d14251b072974d9ee87c"
BUILDER=transteira-release-dry # the builder of the release dry run (host network), shared cache
PREFIX=transteira-install-
LABEL=transteira-install-smoke=1
V1=99.0.0
V2=99.0.1
ADMIN_HOST=admin.smoke.localhost
TENANT_HOST=transfer.smoke.localhost
SIG_VOLUME=${PREFIX}clamav-db
keep_signatures=${INSTALL_SMOKE_KEEP_SIGNATURES:-1}
keep=${INSTALL_SMOKE_KEEP:-0}
install_timeout=${INSTALL_SMOKE_TIMEOUT:-1800}
commit=${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}
date_utc=${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}

export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
log() { echo "install-smoke: $*"; }
fail() {
	echo "install-smoke: FAIL: $*" >&2
	exit 1
}

# --- step timing ---------------------------------------------------------------------------------
step_names=()
step_secs=()
step_t0=$SECONDS
step_label=""
begin() {
	step_label=$1
	step_t0=$SECONDS
	log "--- $1"
}
end() {
	step_names+=("$step_label")
	step_secs+=($((SECONDS - step_t0)))
}
fmt() { printf '%dm%02ds' $(($1 / 60)) $(($1 % 60)); }
print_durations() {
	local i total=0
	echo
	echo "install-smoke: duration per step"
	for i in "${!step_names[@]}"; do
		printf '  %-52s %8s\n' "${step_names[$i]}" "$(fmt "${step_secs[$i]}")"
		total=$((total + step_secs[i]))
	done
	printf '  %-52s %8s\n' total "$(fmt "$total")"
}

# --- state, cleanup ------------------------------------------------------------------------------
work=""
registry_vol=""
host_registry=""
outer=""
outer_vol=""
prep_images=()
pulled_bases=()
ok=0

purge_labelled() {
	"$docker" ps -aq --filter "label=$LABEL" | xargs -r "$docker" rm -f -v >/dev/null 2>&1 || true
	# The signature cache volume carries the label too and survives (see cleanup).
	"$docker" volume ls -q --filter "label=$LABEL" | grep -v "^$SIG_VOLUME\$" | xargs -r "$docker" volume rm >/dev/null 2>&1 || true
}

cleanup() {
	local rc=$?
	set +e
	if [ "$rc" != 0 ] && [ -n "$outer" ] && "$docker" inspect "$outer" >/dev/null 2>&1; then
		echo "install-smoke: --- last lines of the installer log and the containers of $outer (setup token redacted) ---" >&2
		"$docker" exec "$outer" sh -c 'tail -n 40 /var/log/transteira-install.log 2>/dev/null' 2>&1 |
			sed -E 's/(Setup token: )[A-Za-z0-9_-]+/\1[redacted]/g' >&2
		"$docker" exec "$outer" docker ps -a >&2 2>&1
		"$docker" exec "$outer" docker logs --tail 30 transteira 2>&1 | sed -E 's/(Setup token: )[A-Za-z0-9_-]+/\1[redacted]/g' >&2
		if [ "$keep" = 1 ]; then
			echo "install-smoke: INSTALL_SMOKE_KEEP=1: $outer kept (docker exec -it $outer bash); remove it with docker rm -f -v $outer" >&2
			keep_outer=1
		fi
	fi
	if [ "${keep_outer:-0}" != 1 ]; then
		purge_labelled
		[ -z "$registry_vol" ] || "$docker" volume rm "$registry_vol" >/dev/null 2>&1
		[ -z "$outer_vol" ] || "$docker" volume rm "$outer_vol" "$outer_vol-containerd" >/dev/null 2>&1
	fi
	[ "${#prep_images[@]}" -eq 0 ] || "$docker" image rm "${prep_images[@]}" >/dev/null 2>&1
	[ "${#pulled_bases[@]}" -eq 0 ] || "$docker" image rm "${pulled_bases[@]}" >/dev/null 2>&1
	[ "$keep_signatures" != 0 ] || "$docker" volume rm "$SIG_VOLUME" >/dev/null 2>&1
	[ -z "$work" ] || rm -rf "$work"
	if [ "${#step_names[@]}" -gt 0 ]; then print_durations; fi
	if [ "$rc" = 0 ] && [ "$ok" = 1 ]; then
		log "ALL OK ($debians / $engines)"
	fi
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# --- prerequisites -------------------------------------------------------------------------------
"$docker" info >/dev/null 2>&1 || fail "Docker is not available ('$docker info' failed)"
command -v node >/dev/null 2>&1 || fail "node is required (test/deploy/smoke.mjs)"
[ "$(uname -s)" = Linux ] || fail "Linux only (privileged containers with systemd)"
[ "$("$docker" info --format '{{.CgroupVersion}}' 2>/dev/null)" = 2 ] || fail "cgroup v2 is required for systemd in a container"
case "$(uname -m)" in x86_64 | amd64 | aarch64 | arm64) ;; *) fail "unsupported architecture $(uname -m)" ;; esac
avail_kb=$(df -Pk "$root" | awk 'NR == 2 { print $4 }')
[ "$avail_kb" -gt $((12 * 1024 * 1024)) ] || fail "less than 12 GiB free: a run needs about 6 GiB"

purge_labelled # leftovers of an interrupted run
"$docker" volume inspect "$SIG_VOLUME" >/dev/null 2>&1 || "$docker" volume create --label "$LABEL" "$SIG_VOLUME" >/dev/null
work=$(mktemp -d)
mkdir -p "$work/node"

# cosign with the throwaway key (no password); never the password of the release key.
# shellcheck disable=SC2206
cosign() { local -a c=($COSIGN); COSIGN_PASSWORD="" "${c[@]}" "$@"; }
# shellcheck disable=SC2206
syft() { local -a c=($SYFT); "${c[@]}" "$@"; }

# --- 1-3. throwaway key, registry, images, installers --------------------------------------------
begin "release: key, registry"
cosign generate-key-pair --output-key-prefix "$work/smoke" >/dev/null
cosign signing-config create --out "$work/offline-signing-config.json" >/dev/null
registry_vol=${PREFIX}registry-$$
"$docker" volume create --label "$LABEL" "$registry_vol" >/dev/null
host_registry=$("$docker" run -d --rm --label "$LABEL" --name "${PREFIX}registry-host-$$" -p 127.0.0.1::5000 \
	-v "$registry_vol:/var/lib/registry" "$REGISTRY_IMAGE")
port=$("$docker" port "$host_registry" 5000/tcp | head -n 1 | sed 's/.*://')
repo="127.0.0.1:$port/transteira"
for _ in $(seq 1 50); do
	curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 && break
	sleep 0.2
done
curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 || fail "the throwaway registry did not answer on 127.0.0.1:$port"
end

if ! "$docker" buildx inspect "$BUILDER" >/dev/null 2>&1; then
	"$docker" buildx create --name "$BUILDER" --driver docker-container \
		--driver-opt "image=$BUILDKIT_IMAGE" --driver-opt network=host --bootstrap >/dev/null
fi

# platform_digests REF: "os/arch digest" lines of the index REF (as scripts/release.sh does).
platform_digests() {
	"$docker" buildx imagetools inspect --raw "$1" |
		tr -d ' \n\t' | grep -o '"digest":"sha256:[0-9a-f]\{64\}"[^}]*"platform":{[^}]*}' |
		sed -n 's/"digest":"\(sha256:[0-9a-f]*\)".*"architecture":"\([^"]*\)".*"os":"\([^"]*\)".*/\3\/\2 \1/p'
}

# release_one VERSION: image of this tree at VERSION pushed, signed, attested; installer in
# $work/<version>/install.sh.
release_one() {
	local v=$1 out="$work/$1" meta digest name d
	mkdir -p "$out"
	meta="$out/build-metadata.json"
	"$docker" buildx build --builder "$BUILDER" --platform linux/amd64,linux/arm64 --provenance=false --sbom=false \
		--build-arg VERSION="$v" --build-arg COMMIT="$commit" --build-arg DATE="$date_utc" \
		--output "type=image,name=$repo,push-by-digest=true,name-canonical=true,push=true" \
		--metadata-file "$meta" . >/dev/null
	digest=$(sed -n 's/.*"containerimage.digest": *"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' "$meta" | head -n 1)
	[ -n "$digest" ] || fail "no image digest in $meta"
	printf '%s@%s\n' "$repo" "$digest" >"$out/image-digest.txt"
	platform_digests "$repo@$digest" >"$out/platform-digests.txt"
	[ "$(wc -l <"$out/platform-digests.txt")" -eq 2 ] || fail "the index $repo@$digest does not have two platform manifests"
	cosign sign --yes --key "$work/smoke.key" --recursive --signing-config "$work/offline-signing-config.json" "$repo@$digest" >/dev/null
	while read -r name d; do
		syft scan "registry:$repo@$d" --platform "$name" -q -o "spdx-json=$out/sbom-${name//\//_}.json"
		cosign attest --yes --key "$work/smoke.key" --type spdxjson --predicate "$out/sbom-${name//\//_}.json" \
			--signing-config "$work/offline-signing-config.json" "$repo@$d" >/dev/null
	done <"$out/platform-digests.txt"
	INSTALL_VERSION="$v" RELEASE_IMAGE="$repo" INSTALL_IMAGE_DIGEST_FILE="$out/image-digest.txt" \
		INSTALL_PLATFORM_DIGESTS_FILE="$out/platform-digests.txt" INSTALL_COSIGN_PUB="$work/smoke.pub" \
		INSTALL_OUT="$out/install.sh" bash scripts/install/build.sh >/dev/null
	[ "$(bash "$out/install.sh" --version)" = "$v" ] || fail "install.sh of $v does not report it"
}

begin "release: image $V1 (amd64+arm64), signed, installer"
release_one "$V1"
end
begin "release: image $V2 (amd64+arm64), signed, installer"
release_one "$V2"
end
"$docker" stop "$host_registry" >/dev/null # the data stays in the volume
host_registry=""

# --- helpers of a run ----------------------------------------------------------------------------
out_x() { "$docker" exec "$outer" "$@"; }                    # in the server
out_d() { "$docker" exec "$outer" docker "$@"; }             # Docker of the server
out_sh() { "$docker" exec -i "$outer" bash -c "$1"; }        # shell snippet in the server

# The `docker` that test/deploy/smoke.mjs uses: the Docker of the server. `docker cp` goes through
# a temporary path of the server, as its destination is on this machine.
write_docker_wrapper() {
	cat >"$work/docker-in" <<EOF
#!/usr/bin/env bash
set -eu
outer=$outer
if [ "\${1:-}" = cp ]; then
	tmp=/var/tmp/cp-\$\$-\$RANDOM
	docker exec "\$outer" docker cp "\$2" "\$tmp" || exit 1
	docker cp "\$outer:\$tmp" "\$3"
	rc=\$?
	docker exec "\$outer" rm -rf "\$tmp"
	exit \$rc
fi
exec docker exec "\$outer" docker "\$@"
EOF
	chmod 0755 "$work/docker-in"
}

# digest_files DIR...: SHA-256 of every file below the folders, as "sum path" lines (in the server).
digest_snapshot() {
	out_sh '
		cd /
		{
			find /opt/transteira/deploy/secrets -type f -print0 | xargs -0 sha256sum
			sha256sum /opt/reverse-proxy/Caddyfile /etc/fail2ban/jail.d/transteira.local
			[ ! -e /opt/transteira/deploy/docker-compose.installer-smtp.yml ] || sha256sum /opt/transteira/deploy/docker-compose.installer-smtp.yml
			grep -v "^TRANSTEIRA_IMAGE=" /opt/transteira/deploy/.env | sha256sum
			stat -c "%n %u %a" /opt/transteira/deploy/secrets/*
		} | LC_ALL=C sort
	'
}

wait_systemd() {
	local deadline=$((SECONDS + 90)) s
	while :; do
		s=$(out_x systemctl is-system-running 2>/dev/null || true)
		case "$s" in running | degraded) return 0 ;; esac
		[ "$SECONDS" -lt "$deadline" ] || fail "systemd did not boot in the container (state '$s')"
		sleep 1
	done
}

assert_eq() { [ "$2" = "$3" ] || fail "$1: got '$2', expected '$3'"; }

# --- one run -------------------------------------------------------------------------------------
run_one() {
	local deb=$1 engine=$2 tag="debian$1-$2" base_var="base_$1" prep t0=$SECONDS
	local base=${!base_var}
	outer=${PREFIX}$tag-$$
	outer_vol=${PREFIX}$tag-docker-$$
	log "=== Debian $deb, $engine: container $outer ==="

	begin "[$tag] blank server (systemd container, Docker volume)"
	prep=${PREFIX}prep-debian$deb:$$
	if ! "$docker" image inspect "$prep" >/dev/null 2>&1; then
		"$docker" image inspect "$base" >/dev/null 2>&1 || pulled_bases+=("$base")
		"$docker" build -q -t "$prep" --label "$LABEL" - >/dev/null <<EOF
FROM $base
ENV container=docker DEBIAN_FRONTEND=noninteractive
# A minimal server image: systemd as PID 1 and what a cloud image carries (curl, ip).
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates curl iproute2 kmod \
    && rm -rf /var/lib/apt/lists/* && systemctl mask getty.target
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
		prep_images+=("$prep")
	fi
	# Docker's and containerd's stores must not sit on the overlay file system of the container.
	"$docker" volume create --label "$LABEL" "$outer_vol" >/dev/null
	"$docker" volume create --label "$LABEL" "$outer_vol-containerd" >/dev/null
	"$docker" run -d --name "$outer" --label "$LABEL" --privileged --cgroupns=private --stop-signal SIGRTMIN+3 \
		--hostname "install-$tag" --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
		-v /lib/modules:/lib/modules:ro -v "$outer_vol:/var/lib/docker" -v "$outer_vol-containerd:/var/lib/containerd" -v "$SIG_VOLUME:/sigcache" \
		-p 127.0.0.1::443 "$prep" >/dev/null
	wait_systemd
	assert_eq "blank server has no docker" "$(out_x sh -c 'command -v docker || echo none')" none
	# shellcheck disable=SC2016 # expanded by the shell of the server
	assert_eq "OS" "$(out_x sh -c '. /etc/os-release && echo $VERSION_ID')" "$deb"
	local https_port ip
	https_port=$("$docker" port "$outer" 443/tcp | head -n 1 | sed 's/.*://')
	ip=$("$docker" inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$outer")
	[ -n "$ip" ] || fail "no IP address for $outer"
	# The registry shares the network namespace of the server: localhost:<port> is the registry.
	"$docker" run -d --rm --label "$LABEL" --name "${PREFIX}registry-$tag-$$" --network "container:$outer" \
		-e "REGISTRY_HTTP_ADDR=127.0.0.1:$port" -v "$registry_vol:/var/lib/registry" "$REGISTRY_IMAGE" >/dev/null
	write_docker_wrapper
	end

	local -a args=(--yes --admin-host "$ADMIN_HOST" --acme-email "")
	local smtp=0
	if [ "$engine" = postgres ]; then
		smtp=1
		args+=(--postgres --smtp-host mail.example.org --smtp-port 587 --smtp-security starttls
			--smtp-from noreply@example.com --smtp-user relay-user --smtp-password-file /root/smtp-password)
		printf 'smtp-password-%s\n' "$$" | out_sh 'cat > /root/smtp-password; chmod 0600 /root/smtp-password'
	fi
	"$docker" cp "$work/$V1/install.sh" "$outer:/root/install-$V1.sh"
	"$docker" cp "$work/$V2/install.sh" "$outer:/root/install-$V2.sh"

	# ClamAV signatures cached on this machine: copied into the volume of the server as soon as
	# Docker creates it (a few seconds before freshclam's first run), so that it only has to update.
	local seeded=0
	if "$docker" run --rm --label "$LABEL" -v "$SIG_VOLUME:/s:ro" "$prep" sh -c 'ls /s/main.c[vl]d >/dev/null 2>&1'; then
		seeded=1
		# shellcheck disable=SC2016 # expanded by the shell of the server
		"$docker" exec -d "$outer" bash -c '
			until docker volume inspect transteira_clamav_db >/dev/null 2>&1; do sleep 0.3; done
			cp -a /sigcache/. "$(docker volume inspect -f "{{.Mountpoint}}" transteira_clamav_db)/"
		'
	fi

	begin "[$tag] install.sh $V1 (Docker, cosign, images, stack, firewall, fail2ban)"
	local rc=0
	timeout "$install_timeout" "$docker" exec -e TT_INSTALL_TEST_MODE=insecure-test-only "$outer" \
		bash "/root/install-$V1.sh" "${args[@]}" 2>&1 | tee "$work/install-$tag.out" || rc=${PIPESTATUS[0]}
	[ "$rc" = 0 ] || fail "install.sh $V1 exited $rc (last lines above; the whole output was kept with INSTALL_SMOKE_KEEP=1 only)"
	end
	log "ClamAV signatures were $([ "$seeded" = 1 ] && echo "seeded from the cache" || echo "downloaded")"

	begin "[$tag] installer output and state"
	local token
	token=$(out_d logs transteira 2>&1 | sed -n 's/.*Setup token: \([A-Za-z0-9_-]*\).*/\1/p' | tail -n 1)
	[ -n "$token" ] || fail "no setup token in the application log"
	# --yes: the output lands in automation logs, so the summary gives the command, not the token.
	if grep -qF "$token" "$work/install-$tag.out"; then fail "the installer output shows the setup token with --yes"; fi
	grep -qF "docker logs transteira 2>&1 | grep 'Setup token'" "$work/install-$tag.out" ||
		fail "the installer summary does not say how to read the setup token"
	grep -q "https://$ADMIN_HOST/admin/setup" "$work/install-$tag.out" || fail "the installer summary does not show the setup URL"
	grep -q 'MASTER KEY' "$work/install-$tag.out" || fail "no master key reminder in the summary"
	if out_x grep -q "$token" /var/log/transteira-install.log; then fail "the setup token is in /var/log/transteira-install.log"; fi
	rm -f "$work/install-$tag.out"
	assert_eq "state file" "$(out_x grep -E '^TTI_(STATE|INSTALLED_VERSION|ENGINE)=' /opt/transteira/install.conf | tr '\n' ' ')" \
		"TTI_STATE=installed TTI_INSTALLED_VERSION=$V1 TTI_ENGINE=$engine "
	assert_eq "secrets mode" "$(out_x sh -c 'stat -c "%a" /opt/transteira/deploy/.env /opt/transteira/deploy/secrets/master_key' | tr '\n' ' ')" "600 400 "
	assert_eq "master key owner" "$(out_x stat -c %u /opt/transteira/deploy/secrets/master_key)" 10001
	if [ "$smtp" = 1 ]; then
		assert_eq "smtp secret" "$(out_x stat -c '%u %a' /opt/transteira/deploy/secrets/system_smtp_password)" "10001 400"
		out_x grep -q 'docker-compose.installer-smtp.yml' /opt/transteira/deploy/.env || fail "COMPOSE_FILE does not list the SMTP overlay"
	fi
	local c
	for c in transteira transteira-clamav transteira-clamav-update reverse-proxy-caddy-1; do
		out_d inspect --format '{{.State.Status}}' "$c" | grep -qx running || fail "$c is not running"
	done
	assert_eq "transteira version" "$(out_d exec transteira /transteira version | tr -d '\n' | grep -o "$V1" | head -n 1)" "$V1"
	end

	if [ "$seeded" = 0 ]; then
		# First download on this machine: keep the signatures for the next runs.
		# shellcheck disable=SC2016 # expanded by the shell of the server
		out_sh 'cp -a "$(docker volume inspect -f "{{.Mountpoint}}" transteira_clamav_db)/." /sigcache/' ||
			log "WARNING: could not cache the ClamAV signatures"
	fi

	begin "[$tag] smoke.mjs through the installed Caddy"
	local ca="$work/caddy-root.pem" i
	for i in $(seq 1 30); do
		out_d exec reverse-proxy-caddy-1 cat /data/caddy/pki/authorities/local/root.crt >"$ca" 2>/dev/null && [ -s "$ca" ] && break
		sleep 1
	done
	[ -s "$ca" ] || fail "no Caddy root certificate (tls internal)"
	SMOKE_HTTPS_PORT=$https_port SMOKE_CA_FILE=$ca SMOKE_ADMIN_HOST=$ADMIN_HOST SMOKE_TENANT_HOST=$TENANT_HOST \
		SMOKE_CONTAINER=transteira SMOKE_PROXY_IP=172.30.0.10 SMOKE_WORK_DIR="$work/node" DOCKER="$work/docker-in" \
		node "$root/test/deploy/smoke.mjs"
	end

	begin "[$tag] firewall, fail2ban, SMTP, backups"
	check_host "$ip" "$smtp"
	end

	begin "[$tag] second run refused, --upgrade to $V2, downgrade refused"
	check_upgrade "$https_port" "$ca" "${args[@]}"
	end

	begin "[$tag] cleanup"
	"$docker" rm -f -v "$outer" "${PREFIX}registry-$tag-$$" >/dev/null 2>&1 || true
	"$docker" volume rm "$outer_vol" "$outer_vol-containerd" >/dev/null
	outer=""
	outer_vol=""
	end
	log "=== Debian $deb, $engine: OK in $((SECONDS - t0)) s ==="
}

check_host() {
	local ip=$1 smtp=$2 out i
	# nftables table and unit.
	out=$(out_x nft list table inet transteira_fw) || fail "the nftables table inet transteira_fw is missing"
	grep -q 'policy drop' <<<"$out" || fail "the firewall input chain does not drop by default"
	grep -Eq 'tcp dport (22|\{[^}]*\b22\b[^}]*\}) accept' <<<"$out" || fail "SSH port 22 is not open in the ruleset"
	grep -Eq 'meta nfproto ipv4 tcp dport \{ ?80, 443 ?\} accept' <<<"$out" || fail "ports 80 and 443 are not open (IPv4 only) in the ruleset"
	# IPv6 is refused on 80/443 (the proxy network has no IPv6): no userland proxy, no IPv6 accept.
	if grep -Eq '^[[:space:]]*(tcp dport \{ ?80, 443 ?\}|udp dport 443) accept' <<<"$out"; then fail "ports 80/443 are open to IPv6 in the ruleset"; fi
	out_x grep -Eq '"userland-proxy"[[:space:]]*:[[:space:]]*false' /etc/docker/daemon.json || fail "/etc/docker/daemon.json does not disable the userland proxy"
	if out_x sh -c 'ss -Hltnp | grep -q docker-proxy'; then fail "docker-proxy listens: the userland proxy is on"; fi
	assert_eq "transteira-firewall.service" "$(out_x systemctl is-enabled transteira-firewall.service)" enabled
	assert_eq "transteira-firewall.service active" "$(out_x systemctl is-active transteira-firewall.service)" active
	# Real connections from this machine to the server: 22, 80 and 443 open, another port dropped
	# (a timeout, not a refusal: something listens on it).
	"$docker" exec -d "$outer" python3 -c 'import socket, time
socks = []
for p in (22, 8081):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", p))
    s.listen(5)
    socks.append(s)
time.sleep(60)'
	for i in $(seq 1 20); do
		out_x sh -c 'ss -Htln | grep -q ":8081 "' 2>/dev/null && break
		sleep 0.5
	done
	# shellcheck disable=SC2016 # $1 and $2 are those of the inner bash
	probe() { timeout 3 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$ip" "$1" >/dev/null 2>&1; }
	probe 22 || fail "port 22 of the server is not reachable through the firewall"
	probe 80 || fail "port 80 of the server is not reachable through the firewall"
	probe 443 || fail "port 443 of the server is not reachable through the firewall"
	local rc=0
	probe 8081 || rc=$?
	assert_eq "a port that is not open (8081, with a listener) must be dropped: timeout" "$rc" 124
	local code
	code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: $ADMIN_HOST" "http://$ip/healthz" || true)
	case "$code" in 301 | 302 | 307 | 308) ;; *) fail "HTTP on port 80 answered $code, expected a redirect to HTTPS" ;; esac
	log "firewall: table loaded, 22/80/443 reachable, port 8081 dropped, HTTP redirects"

	# fail2ban: both jails up, and a real ban from lines of the security log.
	assert_eq "fail2ban.service" "$(out_x systemctl is-active fail2ban)" active
	out_x fail2ban-client status transteira >/dev/null || fail "jail transteira is not active"
	out_x fail2ban-client status transteira-sso >/dev/null || fail "jail transteira-sso is not active"
	local logpath
	logpath=$(out_d volume inspect transteira_logs --format '{{.Mountpoint}}')/security.log
	assert_eq "jail logpath" "$(out_x fail2ban-client get transteira logpath | grep -o '/var/lib/docker/[^ ]*security.log' | head -n 1)" "$logpath"
	out_sh "
		for n in \$(seq 1 12); do
			printf '%s ip=203.0.113.77 tenant=$TENANT_HOST event=admin_login_failed\n' \"\$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\" >>'$logpath'
		done
	"
	for i in $(seq 1 40); do
		out_x fail2ban-client status transteira | grep -q 'Currently banned:[[:space:]]*1' && break
		sleep 1
	done
	out_x fail2ban-client status transteira | grep -q '203.0.113.77' || fail "fail2ban did not ban 203.0.113.77 from the security log: $(out_x fail2ban-client status transteira)"
	out_x iptables -S DOCKER-USER 2>/dev/null | grep -q -- '-p tcp .*-j f2b-transteira$' || fail "the DOCKER-USER chain does not jump to the fail2ban chain (TCP)"
	out_x iptables -S DOCKER-USER 2>/dev/null | grep -q -- '-p udp .*-j f2b-transteira-udp$' || fail "the DOCKER-USER chain does not jump to the fail2ban chain (UDP, HTTP/3)"
	out_x fail2ban-client set transteira unbanip 203.0.113.77 >/dev/null
	log "fail2ban: jails active, 203.0.113.77 banned from the security log through DOCKER-USER (TCP and UDP), unbanned"

	# Automatic security updates: configuration present, timers enabled.
	out_x test -s /etc/apt/apt.conf.d/52transteira-unattended-upgrades || fail "no unattended-upgrades configuration written by the installer"
	assert_eq "apt-daily-upgrade.timer" "$(out_x systemctl is-enabled apt-daily-upgrade.timer)" enabled

	# Backups (SQLite) and the SMTP of the system.
	if [ "$smtp" = 0 ]; then
		out_d exec transteira /transteira backup >/dev/null || fail "transteira backup failed"
		out_sh "find \"\$(docker volume inspect -f '{{.Mountpoint}}' transteira_backups)\" -type f -name '*.db' | grep -q ." || fail "no SQLite backup copy"
	else
		out_d exec transteira-db-backup sh -c 'pg_dump --enable-row-security --format=custom --file=/backups/x.dump && test -s /backups/x.dump' ||
			fail "pg_dump through transteira-db-backup failed"
	fi
}

check_upgrade() {
	local https_port=$1 ca=$2 before after out rc=0
	shift 2
	before=$(digest_snapshot)
	out=$(out_x env TT_INSTALL_TEST_MODE=insecure-test-only bash "/root/install-$V1.sh" --yes --admin-host "$ADMIN_HOST" 2>&1) && rc=0 || rc=$?
	[ "$rc" != 0 ] || fail "a second run of install.sh without --upgrade succeeded"
	grep -q 'use --upgrade' <<<"$out" || fail "the refusal of a second run does not point to --upgrade: $out"
	out=$(out_x env TT_INSTALL_TEST_MODE=insecure-test-only bash "/root/install-$V2.sh" --upgrade --yes --admin-host x.example.com 2>&1) && rc=0 || rc=$?
	[ "$rc" != 0 ] || fail "--upgrade accepted --admin-host"
	rc=0
	timeout "$install_timeout" "$docker" exec -e TT_INSTALL_TEST_MODE=insecure-test-only "$outer" \
		bash "/root/install-$V2.sh" --upgrade --yes 2>&1 | tail -n 15 || rc=${PIPESTATUS[0]}
	[ "$rc" = 0 ] || fail "install.sh $V2 --upgrade failed"
	assert_eq "version after the upgrade" "$(out_d exec transteira /transteira version | grep -o "$V2" | head -n 1)" "$V2"
	assert_eq "state version" "$(out_x grep '^TTI_INSTALLED_VERSION=' /opt/transteira/install.conf)" "TTI_INSTALLED_VERSION=$V2"
	assert_eq "previous version" "$(out_x grep '^TTI_PREVIOUS_VERSION=' /opt/transteira/install.conf)" "TTI_PREVIOUS_VERSION=$V1"
	assert_eq "previous files kept for the rollback" "$(out_x stat -c '%a' /opt/transteira/previous /opt/transteira/previous/deploy/.env | tr '\n' ' ')" "700 600 "
	if out_x test -e /opt/transteira/previous/deploy/secrets; then fail "the secrets were copied to /opt/transteira/previous"; fi
	out_x grep -q "^TRANSTEIRA_IMAGE=.*@sha256:" /opt/transteira/deploy/.env || fail ".env lost its pinned image"
	after=$(digest_snapshot)
	[ "$before" = "$after" ] || fail ".env, secrets, Caddyfile, jail or SMTP overlay changed by the upgrade: $(diff <(echo "$before") <(echo "$after"))"
	out_sh "find \"\$(docker volume inspect -f '{{.Mountpoint}}' transteira_backups)\" -type f | grep -q ." || fail "the upgrade made no database backup"
	local c
	for c in transteira transteira-clamav reverse-proxy-caddy-1; do
		out_d inspect --format '{{.State.Status}}' "$c" | grep -qx running || fail "$c is not running after the upgrade"
	done
	out_d inspect --format '{{.State.Health.Status}}' transteira | grep -qx healthy || fail "transteira is not healthy after the upgrade"
	# Through Caddy: the version, and the entity created by smoke.mjs still has its page (data kept,
	# on-demand TLS still answered).
	local code
	for _ in $(seq 1 30); do
		code=$(curl -s -o "$work/ver.json" -w '%{http_code}' --max-time 10 --cacert "$ca" \
			--resolve "$ADMIN_HOST:$https_port:127.0.0.1" "https://$ADMIN_HOST:$https_port/api/v1/version" || true)
		[ "$code" = 200 ] && break
		sleep 2
	done
	assert_eq "GET /api/v1/version after the upgrade" "$code" 200
	grep -q "$V2" "$work/ver.json" || fail "the API does not report $V2 after the upgrade: $(cat "$work/ver.json")"
	assert_eq "entity page after the upgrade" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --cacert "$ca" \
		--resolve "$TENANT_HOST:$https_port:127.0.0.1" "https://$TENANT_HOST:$https_port/")" 200
	# Downgrade refused, and nothing changed.
	out=$(out_x env TT_INSTALL_TEST_MODE=insecure-test-only bash "/root/install-$V1.sh" --upgrade --yes 2>&1) && rc=0 || rc=$?
	[ "$rc" != 0 ] || fail "a downgrade was accepted"
	grep -q 'downgrades are not supported' <<<"$out" || fail "unexpected downgrade refusal: $out"
	assert_eq "version after the refused downgrade" "$(out_d exec transteira /transteira version | grep -o "$V2" | head -n 1)" "$V2"
	log "upgrade: $V1 -> $V2 healthy, .env/secrets/Caddyfile/jail/overlay kept, backup made, data kept; second run and downgrade refused"
}

total=$SECONDS
for deb in $debians; do
	for engine in $engines; do
		run_one "$deb" "$engine"
	done
done
ok=1
log "total $(fmt $((SECONDS - total)))"

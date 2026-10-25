#!/usr/bin/env bash
# Smoke test of the TransTeira container image (`make docker-check`, part of `make check`).
#
# Usage: scripts/docker-check.sh <image> <expected version>
#
# Checks, against an already built image:
#   1. `transteira version` runs in the image and prints the expected version;
#   2. the image size (reported, not gated);
#   3. the image user is 10001:10001 (never root);
#   4. the server starts with the production hardening (read-only root file system, tmpfs /tmp,
#      no capability, no-new-privileges, anonymous volumes for /data, the database, /backups and
#      /logs), a throwaway master key mounted read-only as a Docker secret would be, and logs
#      "HTTP server listening";
#   5. its processes run as UID 10001;
#   6. `transteira healthcheck` (the image HEALTHCHECK) reaches /healthz: exit 0 (healthy) or
#      "answered 503" is accepted, since no ClamAV runs here (TT_CLAMAV_ADDR points to a closed
#      port, so /healthz reports the antivirus down); a connection failure is not;
#   7. the server wrote the SQLite database and the security log in their volumes (ownership
#      and permissions of the image directories are right).
# The container, its anonymous volumes and the temporary key are always removed.
set -euo pipefail

image=${1:?usage: docker-check.sh <image> <expected version>}
want_version=${2:?usage: docker-check.sh <image> <expected version>}
docker=${DOCKER:-docker}

# Git Bash on Windows: keep container paths (/data, /run/secrets/...) untouched.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

fail() {
	echo "docker-check: FAIL: $*" >&2
	exit 1
}

container="transteira-docker-check-$$"
tmp=$(mktemp -d)
cleanup() {
	"$docker" rm -f -v "$container" >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

# 1. Version.
got=$("$docker" run --rm "$image" version) || fail "'transteira version' failed in $image"
case "$got" in
*"$want_version"*) echo "docker-check: version OK ($got)" ;;
*) fail "version prints '$got', expected it to contain '$want_version'" ;;
esac

# 2. Size.
# Sum of the layers, uncompressed (`docker image inspect .Size` depends on the image store: with
# the containerd store it adds the compressed blobs), then the size of the `docker save` archive
# compressed with gzip (close to what a registry transfers).
size=$("$docker" history --human=false --format '{{.Size}}' "$image" | awk '{s+=$1} END {print s}')
packed=$("$docker" save "$image" | gzip -c | wc -c | tr -d ' ')
echo "docker-check: image size $(awk -v s="$size" 'BEGIN {printf "%.1f", s/1048576}') MiB uncompressed," \
	"$(awk -v s="$packed" 'BEGIN {printf "%.1f", s/1048576}') MiB gzip-compressed (docker save | gzip)"

# 3. Image user.
user=$("$docker" image inspect --format '{{.Config.User}}' "$image")
[ "$user" = "10001:10001" ] || fail "image user is '$user', expected 10001:10001"
echo "docker-check: image user OK ($user)"

# 4. Start the server. The key is throwaway; it is world-readable only so that UID 10001 can
# read it through the bind mount on Linux (Docker Desktop ignores the host permissions).
head -c 32 /dev/urandom | base64 >"$tmp/master_key"
chmod 0755 "$tmp"
chmod 0644 "$tmp/master_key"
key_src="$tmp/master_key"
if command -v cygpath >/dev/null 2>&1; then
	key_src=$(cygpath -w "$key_src")
fi

"$docker" run -d --name "$container" \
	--read-only --tmpfs /tmp \
	--cap-drop ALL --security-opt no-new-privileges \
	--mount type=volume,dst=/data \
	--mount type=volume,dst=/var/lib/transteira/db \
	--mount type=volume,dst=/backups \
	--mount type=volume,dst=/logs \
	--mount "type=bind,src=$key_src,dst=/run/secrets/transteira_master_key,readonly" \
	-e TT_MASTER_KEY_FILE=/run/secrets/transteira_master_key \
	-e TT_ADMIN_HOSTS=admin.localhost \
	-e TT_CLAMAV_ADDR=127.0.0.1:1 \
	"$image" >/dev/null || fail "cannot start a container from $image"

listening=
for _ in $(seq 1 60); do
	if [ "$("$docker" inspect --format '{{.State.Running}}' "$container")" != "true" ]; then
		"$docker" logs "$container" >&2 || true
		fail "the server exited during startup"
	fi
	# grep without -q reads the whole stream: an early exit would close the pipe on a writer
	# still running and fail the pipeline under pipefail.
	if "$docker" logs "$container" 2>&1 | grep 'HTTP server listening' >/dev/null; then
		listening=1
		break
	fi
	sleep 0.5
done
if [ -z "$listening" ]; then
	"$docker" logs "$container" >&2 || true
	fail "the server did not log 'HTTP server listening' within 30 s"
fi
echo "docker-check: server listening (read-only root file system, no capability)"

# 5. Process user (docker top reads it from the host side: the image has no ps nor id).
uids=$("$docker" top "$container" -o pid,uid | awk 'NR > 1 {print $2}' | sort -u)
[ "$uids" = "10001" ] || fail "processes run as UID(s) '$uids', expected only 10001"
echo "docker-check: processes run as UID 10001"

# 6. Health check.
if out=$("$docker" exec "$container" /transteira healthcheck 2>&1); then
	echo "docker-check: healthcheck OK (healthy)"
elif printf '%s' "$out" | grep -q 'answered 503'; then
	echo "docker-check: healthcheck OK (reached /healthz: 503, expected without ClamAV)"
else
	fail "healthcheck did not reach /healthz: $out"
fi

# 7. Files written in the volumes (grep without -q, see step 4: docker cp must not get EPIPE).
"$docker" cp "$container:/var/lib/transteira/db" - | tar -t | grep 'transteira\.db$' >/dev/null ||
	fail "no SQLite database in /var/lib/transteira/db"
"$docker" cp "$container:/logs" - | tar -t | grep '\.log$' >/dev/null ||
	fail "no security log in /logs"
echo "docker-check: database and security log written in their volumes"

echo "docker-check: ALL OK ($image)"

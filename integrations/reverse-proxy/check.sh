#!/usr/bin/env bash
# Validates the reverse proxy configurations of integrations/reverse-proxy with
# the real proxies, in Docker (make proxy-configs-check):
#
#   - Caddy:   caddy validate and caddy fmt (formatting) on the Caddyfile;
#   - Nginx:   nginx -t on transteira.conf, with throwaway certificates;
#   - Apache:  httpd -t on transteira.conf included in the stock httpd.conf,
#              with throwaway certificates;
#   - Traefik: Traefik started with the static configuration (ACME pointed at
#              an unreachable local address) and the hardening of its compose
#              file (read-only, NET_BIND_SERVICE only), first with the file provider,
#              then with the labels of docker-compose.labels.yml on a dummy
#              container (docker provider); every router, middleware and
#              service must be "enabled" in the Traefik API and the log must
#              hold no error other than the expected ACME ones;
#   - the two proxy compose files: "$docker" compose config.
#
# Skipped (exit 0, with a message) when Docker is not available.
set -euo pipefail

# Same images, pinned by digest, as the proxy compose files (threat model T-118).
CADDY_IMAGE=caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f
NGINX_IMAGE=nginx:1.30.6-alpine@sha256:47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951
HTTPD_IMAGE=httpd:2.4.69-alpine@sha256:070da7661f0be8a05430b2c125c0cde9e53176b4048c813024021969a0e3893c
TRAEFIK_IMAGE=traefik:v3.7.16@sha256:c8a121e4bb1347e8fd52657fab12f2cb70b68f8a018895e2068f92c9e519b9c2

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
docker=${DOCKER:-docker}

if ! command -v "$docker" >/dev/null 2>&1 || ! "$docker" info >/dev/null 2>&1; then
	echo "proxy-configs-check: SKIPPED (Docker is not available)"
	exit 0
fi

# Git Bash on Windows: no path conversion of container paths, and host paths
# in a form Docker Desktop understands.
export MSYS_NO_PATHCONV=1
hostpath() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi
}

TMP=$(mktemp -d)
RUN_ID="tt-proxy-check-$$"
NET="$RUN_ID"
cleanup() {
	"$docker" rm -f "$RUN_ID-traefik" "$RUN_ID-labels" >/dev/null 2>&1 || true
	"$docker" network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
	echo "proxy-configs-check: FAILED: $*" >&2
	exit 1
}

# --- Throwaway certificate at the certbot paths used by Nginx and Apache ------
mkdir -p "$TMP/live/transteira"
if command -v openssl >/dev/null 2>&1; then
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=transteira.invalid \
		-keyout "$(hostpath "$TMP/live/transteira/privkey.pem")" -out "$(hostpath "$TMP/live/transteira/fullchain.pem")" >/dev/null 2>&1
else
	(cd "$TMP/live/transteira" && go run "$(go env GOROOT)/src/crypto/tls/generate_cert.go" --host transteira.invalid >/dev/null 2>&1 &&
		mv cert.pem fullchain.pem && mv key.pem privkey.pem)
fi
chmod -R a+rX "$TMP/live"
LIVE=$(hostpath "$TMP/live")

# --- Caddy ------------------------------------------------------------------------
echo "proxy-configs-check: Caddy"
CADDYFILE=$(hostpath "$DIR/caddy/Caddyfile")
"$docker" run --rm -v "$CADDYFILE:/etc/caddy/Caddyfile:ro" "$CADDY_IMAGE" \
	caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >"$TMP/caddy.log" 2>&1 ||
	{ cat "$TMP/caddy.log" >&2; fail "caddy validate"; }
grep -q '"level":"warn"' "$TMP/caddy.log" && { cat "$TMP/caddy.log" >&2; fail "caddy validate reported warnings"; }
"$docker" run --rm -v "$CADDYFILE:/etc/caddy/Caddyfile:ro" "$CADDY_IMAGE" \
	caddy fmt --diff /etc/caddy/Caddyfile >"$TMP/caddyfmt.log" 2>&1 ||
	{ cat "$TMP/caddyfmt.log" >&2; fail "Caddyfile is not formatted (caddy fmt --overwrite)"; }

# --- Nginx ------------------------------------------------------------------------
echo "proxy-configs-check: Nginx"
"$docker" run --rm --entrypoint nginx \
	-v "$LIVE:/etc/letsencrypt/live:ro" \
	-v "$(hostpath "$DIR/nginx/transteira.conf"):/etc/nginx/conf.d/default.conf:ro" \
	"$NGINX_IMAGE" -t >"$TMP/nginx.log" 2>&1 ||
	{ cat "$TMP/nginx.log" >&2; fail "nginx -t"; }
grep -q '\[warn\]' "$TMP/nginx.log" && { cat "$TMP/nginx.log" >&2; fail "nginx -t reported warnings"; }

# --- Apache -----------------------------------------------------------------------
echo "proxy-configs-check: Apache"
"$docker" run --rm \
	-v "$LIVE:/etc/letsencrypt/live:ro" \
	-v "$(hostpath "$DIR/apache/transteira.conf"):/etc/transteira.conf:ro" \
	"$HTTPD_IMAGE" sh -c 'echo "ServerName localhost" >> conf/httpd.conf &&
		echo "Include /etc/transteira.conf" >> conf/httpd.conf && httpd -t' >"$TMP/httpd.log" 2>&1 ||
	{ cat "$TMP/httpd.log" >&2; fail "httpd -t"; }
grep -qx 'Syntax OK' "$TMP/httpd.log" || { cat "$TMP/httpd.log" >&2; fail "httpd -t did not report Syntax OK"; }

# --- Proxy compose files ----------------------------------------------------------
echo "proxy-configs-check: compose files"
for f in caddy/docker-compose.yml traefik/docker-compose.yml; do
	"$docker" compose -f "$(hostpath "$DIR/$f")" config -q || fail "docker compose config $f"
done

# --- Traefik ----------------------------------------------------------------------
echo "proxy-configs-check: Traefik"
TRAEFIK_DIR="$DIR/traefik"
mkdir -p "$TMP/traefik/dynamic" "$TMP/traefik/empty"
# Test variant of the static configuration: ACME directory unreachable (no
# request to Let's Encrypt), API enabled to read the router status.
grep -q 'caServer: https://acme-v02.api.letsencrypt.org/directory' "$TRAEFIK_DIR/traefik.yml" ||
	fail "traefik.yml: the caServer line expected by this check is missing"
sed 's#https://acme-v02.api.letsencrypt.org/directory#https://127.0.0.1:9/directory#' \
	"$TRAEFIK_DIR/traefik.yml" >"$TMP/traefik/traefik.yml"
printf '\napi:\n  insecure: true\n' >>"$TMP/traefik/traefik.yml"
cp "$TRAEFIK_DIR/dynamic/transteira.yml" "$TMP/traefik/dynamic/"
"$docker" network create "$NET" >/dev/null

ROUTERS="transteira transteira-uploads transteira-downloads transteira-tokens"
MIDDLEWARES="transteira-hsts transteira-compress"

# start_traefik <dynamic dir>
start_traefik() {
	"$docker" rm -f "$RUN_ID-traefik" >/dev/null 2>&1 || true
	"$docker" run -d --name "$RUN_ID-traefik" --network "$NET" --tmpfs /letsencrypt \
		--read-only --tmpfs /tmp --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges \
		-v "$(hostpath "$TMP/traefik/traefik.yml"):/etc/traefik/traefik.yml:ro" \
		-v "$(hostpath "$1"):/etc/traefik/dynamic:ro" \
		-v /var/run/docker.sock:/var/run/docker.sock:ro \
		"$TRAEFIK_IMAGE" >/dev/null
}

api() {
	"$docker" exec "$RUN_ID-traefik" wget -qO- "http://127.0.0.1:8080/api/http/$1" 2>/dev/null
}

# check_traefik <provider>: every TransTeira object of the provider is enabled.
check_traefik() {
	local provider=$1 deadline=$((SECONDS + 40)) body
	until body=$(api "routers/transteira@$provider") && [ -n "$body" ]; do
		[ "$("$docker" inspect -f '{{.State.Running}}' "$RUN_ID-traefik")" = true ] ||
			{ "$docker" logs "$RUN_ID-traefik" >&2; fail "Traefik stopped ($provider)"; }
		[ $SECONDS -lt $deadline ] || { "$docker" logs "$RUN_ID-traefik" >&2; fail "router transteira@$provider never appeared"; }
		sleep 1
	done
	for kind in routers middlewares services; do
		case $kind in
		routers) names=$ROUTERS ;;
		middlewares) names=$MIDDLEWARES ;;
		services) names=transteira ;;
		esac
		for name in $names; do
			body=$(api "$kind/$name@$provider") || { "$docker" logs "$RUN_ID-traefik" >&2; fail "$kind $name@$provider is missing"; }
			case $body in
			*'"status":"enabled"'*) ;;
			*) echo "$body" >&2; fail "$kind $name@$provider is not enabled" ;;
			esac
			case $body in
			*'"error":'*) echo "$body" >&2; fail "$kind $name@$provider reports an error" ;;
			esac
		done
	done
	# Errors other than the expected ACME failures (unreachable directory).
	if "$docker" logs "$RUN_ID-traefik" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E '(^| )(ERR|FTL|PNC) | level=(error|fatal)' | grep -viE 'acme'; then
		fail "Traefik logged errors ($provider)"
	fi
}

# 1. File provider (dynamic/transteira.yml).
start_traefik "$TMP/traefik/dynamic"
check_traefik file

# 2. Docker provider: the labels of docker-compose.labels.yml on a dummy
#    container named like the TransTeira service, without the dynamic file.
labels=()
while IFS= read -r label; do
	labels+=(--label "$label")
done < <(sed -n 's/^ *- "\(traefik\.[^"]*\)"$/\1/p' "$TRAEFIK_DIR/docker-compose.labels.yml")
[ ${#labels[@]} -gt 0 ] || fail "no label found in docker-compose.labels.yml"
"$docker" run -d --name "$RUN_ID-labels" --network "$NET" --network-alias transteira "${labels[@]}" \
	"$CADDY_IMAGE" >/dev/null
start_traefik "$TMP/traefik/empty"
check_traefik docker

echo "proxy-configs-check: OK (Caddy, Nginx, Apache, Traefik file and labels)"

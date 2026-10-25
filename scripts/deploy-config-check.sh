#!/usr/bin/env bash
# Validates the production deployment files (deploy/), without starting anything
# and without any real secret. Run by `make deploy-config-check`.
#
#   1. `docker compose config` accepts docker-compose.yml alone and with the
#      PostgreSQL overlay, using deploy/.env.example as .env and dummy secret
#      files in a temporary folder;
#   2. in both renderings, no service publishes a port and the long-running
#      services run read-only, without capabilities and without privilege
#      escalation (threat model T-119); the clamd spool is a tmpfs with no
#      volume mounted on it and TT_SCAN_WORKERS is 1 (threat model T-44); the
#      internal and db networks have fixed subnets, all listed in
#      TT_SMTP_DENY_NETWORKS with the proxy subnet (T-176); db-backup uses
#      the read-only role transteira_backup (T-119);
#   3. clamconf (from the pinned ClamAV image) parses clamav/clamd.conf and
#      clamav/freshclam.conf without error, with the limits equal to the
#      default TT_CLAMAV_MAX_SCAN_BYTES and the mandatory alerts enabled
#      (docs/operations/antivirus.md);
#   4. deploy/init-secrets.sh and the PostgreSQL init script are valid POSIX
#      shell.
set -euo pipefail

docker=${DOCKER:-docker}
root=$(cd "$(dirname "$0")/.." && pwd)
deploy="$root/deploy"

# Git Bash on Windows: keep container paths (/cfg) untouched.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

fail() {
	echo "deploy-config-check: FAIL: $*" >&2
	exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Paths handed to Docker (a Windows program under Git Bash) must be native.
native() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# --- 1. Compose files --------------------------------------------------------

for f in docker-compose.yml docker-compose.postgres.yml .env.example clamav/clamd.conf \
	clamav/freshclam.conf postgres/initdb/10-transteira-roles.sql postgres/initdb/20-transteira-hba.sh \
	init-secrets.sh; do
	[ -f "$deploy/$f" ] || fail "deploy/$f is missing"
done

# Project directory = the temporary folder, so that .env and ./secrets resolve
# there (the compose files reference them relatively); dummy secrets only.
cp "$deploy/.env.example" "$tmp/.env"
mkdir "$tmp/secrets"
for s in master_key pg_superuser_password pg_owner_password pg_app_password pg_backup_password \
	db_dsn db_migrate_dsn pgpass; do
	echo "dummy-not-a-secret" >"$tmp/secrets/$s"
done

# compose ENV_FILE ... prints the rendered configuration as JSON.
render() {
	local name=$1
	shift
	local args=(--project-directory "$(native "$tmp")" --env-file "$(native "$tmp/.env")")
	for f in "$@"; do args+=(-f "$(native "$deploy/$f")"); done
	"$docker" compose "${args[@]}" config -q || fail "docker compose config rejects $name"
	"$docker" compose "${args[@]}" config --format json >"$tmp/$name.json" ||
		fail "docker compose config --format json failed for $name"
}
render sqlite docker-compose.yml
render postgres docker-compose.yml docker-compose.postgres.yml

# --- 2. Hardening invariants -------------------------------------------------

# Checked with Node (already required by the web build), on the JSON rendering.
check_rendering() {
	node - "$1" "$(native "$tmp/$1.json")" <<'JS' || fail "$1: hardening check failed (see above)"
const [name, file] = process.argv.slice(2);
const cfg = JSON.parse(require("node:fs").readFileSync(file, "utf8"));
const problems = [];
const services = Object.entries(cfg.services ?? {});
for (const [svc, s] of services) {
  if (s.ports?.length) problems.push(`${svc}: publishes a port (no ports: allowed)`);
  if (s.privileged) problems.push(`${svc}: privileged`);
  if (s.network_mode === "host") problems.push(`${svc}: host network`);
  if (s.read_only !== true) problems.push(`${svc}: root file system not read_only`);
  if (!(s.cap_drop ?? []).includes("ALL")) problems.push(`${svc}: does not drop ALL capabilities`);
  if (!(s.security_opt ?? []).includes("no-new-privileges:true")) problems.push(`${svc}: no-new-privileges missing`);
  // Long-running services are bounded and restarted; one-shot ones are not restarted.
  if (s.restart === "unless-stopped" && !s.mem_limit) problems.push(`${svc}: no mem_limit`);
}
const tt = cfg.services?.transteira;
if (!tt) problems.push("no transteira service");
else {
  if (tt.user) problems.push("transteira: user overridden (the image runs as 10001)");
  if (!(tt.secrets ?? []).some((x) => x.source === "transteira_master_key")) problems.push("transteira: master key secret missing");
  if (tt.environment?.TT_MASTER_KEY_FILE !== "/run/secrets/transteira_master_key") problems.push("transteira: TT_MASTER_KEY_FILE must point to the secret");
}
if (cfg.networks?.internal?.internal !== true) problems.push("network internal must be internal: true");
if (cfg.networks?.proxy?.external !== true) problems.push("network proxy must be external");
const clamNets = Object.keys(cfg.services?.clamav?.networks ?? {});
if (clamNets.join() !== "internal") problems.push(`clamav must be on the internal network only, got ${clamNets}`);
for (const v of ["transteira_data", "transteira_db", "transteira_backups", "transteira_logs"]) {
  if (cfg.volumes?.[v]?.name !== v) problems.push(`volume ${v} must have the fixed name ${v}`);
}
// clamd spool: memory only (T-44). clamd writes the decrypted streams there.
const spool = "/var/tmp/clamav";
const clam = cfg.services?.clamav ?? {};
const spoolTmpfs = (clam.tmpfs ?? []).filter((t) => t.split(":")[0] === spool);
if (spoolTmpfs.length !== 1) problems.push(`clamav: ${spool} must be a tmpfs`);
else {
  if (!/(:|,)mode=0?700(,|$)/.test(spoolTmpfs[0])) problems.push(`clamav: the ${spool} tmpfs must have mode 0700`);
  if (!/(:|,)size=\d+[kmg]?(,|$)/.test(spoolTmpfs[0])) problems.push(`clamav: the ${spool} tmpfs must have a size`);
}
for (const [svc, s] of services) {
  for (const v of s.volumes ?? []) {
    const target = typeof v === "string" ? v.split(":")[1] : v.target;
    if (target && (target === spool || target.startsWith(spool + "/")) && v.type !== "tmpfs") {
      problems.push(`${svc}: a volume is mounted on the clamd spool ${target} (it must stay a tmpfs)`);
    }
  }
}
for (const [key, v] of Object.entries(cfg.volumes ?? {})) {
  if (/clamav_tmp/.test(`${key} ${v?.name ?? ""}`)) problems.push(`volume ${key}: no spool volume allowed (the clamd spool is a tmpfs)`);
}
if (String(tt?.environment?.TT_SCAN_WORKERS) !== "1") {
  problems.push(`transteira: TT_SCAN_WORKERS must be 1 (one stream in the clamd spool), got ${tt?.environment?.TT_SCAN_WORKERS}`);
}
// Fixed subnets of the stack networks, denied to the tenant SMTP servers (T-176).
const deny = String(tt?.environment?.TT_SMTP_DENY_NETWORKS ?? "").split(",").map((x) => x.trim());
for (const n of ["internal"].concat(cfg.networks?.db ? ["db"] : [])) {
  const subnet = cfg.networks?.[n]?.ipam?.config?.[0]?.subnet;
  if (!subnet) problems.push(`network ${n} must have a fixed subnet`);
  else if (!deny.includes(subnet)) problems.push(`TT_SMTP_DENY_NETWORKS must list the ${n} subnet ${subnet}`);
}
for (const d of ["172.30.0.0/24", "127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128", "100.100.100.200/32", "0.0.0.0/8", "::/96"]) {
  if (!deny.includes(d)) problems.push(`TT_SMTP_DENY_NETWORKS must list ${d} (default list and proxy subnet)`);
}
const bk = cfg.services?.["db-backup"];
if (bk && bk.environment?.PGUSER !== "transteira_backup") problems.push(`db-backup must connect as transteira_backup, got ${bk.environment?.PGUSER}`);
if (problems.length) {
  for (const p of problems) console.error(`deploy-config-check: ${name}: ${p}`);
  process.exit(1);
}
console.log(`deploy-config-check: ${name} compose OK (${services.length} services, no port, hardened)`);
JS
}
check_rendering sqlite
check_rendering postgres

# --- 3. ClamAV configuration -------------------------------------------------

clamav_image=$(grep -m1 -E '^\s*image:\s*clamav/clamav:' "$deploy/docker-compose.yml" | sed -E 's/^\s*image:\s*//')
[ -n "$clamav_image" ] || fail "no clamav/clamav image in deploy/docker-compose.yml"
mkdir "$tmp/clamav"
cp "$deploy/clamav/clamd.conf" "$deploy/clamav/freshclam.conf" "$tmp/clamav/"
out=$("$docker" run --rm --network none --entrypoint clamconf -v "$(native "$tmp/clamav"):/cfg:ro" \
	"$clamav_image" -c /cfg -n 2>&1) || fail "clamconf failed: $out"
# clamconf exits 0 even on parse errors: look for its ERROR lines.
if grep -q 'ERROR' <<<"$out"; then
	fail "clamconf reports errors: $(grep 'ERROR' <<<"$out")"
fi
# Default TT_CLAMAV_MAX_SCAN_BYTES (internal/config): 2 GiB.
want=2147483648
for opt in StreamMaxLength MaxScanSize MaxFileSize; do
	grep -q "^$opt = \"$want\"" <<<"$out" || fail "clamd.conf: $opt must equal $want (TT_CLAMAV_MAX_SCAN_BYTES)"
done
for opt in AlertExceedsMax AlertEncryptedArchive AlertEncryptedDoc Foreground; do
	grep -q "^$opt = \"yes\"" <<<"$out" || fail "clamd.conf: $opt must be yes"
done
grep -q '^TCPSocket = "3310"' <<<"$out" || fail "clamd.conf: TCPSocket must be 3310 (TT_CLAMAV_ADDR)"
# MaxScanTime below the default TT_CLAMAV_TIMEOUT (10 min).
scan_time=$(sed -nE 's/^MaxScanTime = "([0-9]+)"$/\1/p' <<<"$out")
[ -n "$scan_time" ] && [ "$scan_time" -lt 600000 ] ||
	fail "clamd.conf: MaxScanTime must be set below 600000 ms (TT_CLAMAV_TIMEOUT)"
# MaxThreads at or above the largest TT_SCAN_WORKERS default (2); 10 if unset.
threads=$(sed -nE 's/^MaxThreads = "([0-9]+)"$/\1/p' <<<"$out")
[ "${threads:-10}" -ge 2 ] || fail "clamd.conf: MaxThreads must be at least TT_SCAN_WORKERS (2)"
# The spool directory is the tmpfs of the compose file (T-44).
grep -q '^TemporaryDirectory = "/var/tmp/clamav"' <<<"$out" ||
	fail "clamd.conf: TemporaryDirectory must be /var/tmp/clamav (the tmpfs of the clamav service)"
echo "deploy-config-check: clamd.conf OK (limits $want bytes, alerts on, MaxScanTime ${scan_time} ms)"

# --- 4. Scripts ---------------------------------------------------------------

sh -n "$deploy/init-secrets.sh" || fail "deploy/init-secrets.sh has a syntax error"
sh -n "$deploy/postgres/initdb/20-transteira-hba.sh" || fail "deploy/postgres/initdb/20-transteira-hba.sh has a syntax error"

echo "deploy-config-check: OK"

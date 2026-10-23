# API integration guide

This guide is for integrators who deposit files into TransTeira from a script or a
third-party application: an ERP export every night, a scanner, a reporting job. It covers
the API tokens, then a complete, resumable upload of large files with the
[tus](https://tus.io/protocols/resumable-upload) protocol, with ready-to-use scripts for
**bash + curl** and **PowerShell 7**.

The reference is the OpenAPI specification:

- downloadable at `https://<host>/api/openapi.yaml` (any tenant FQDN or the admin host), to
  generate a client in any language;
- browsable as an interactive documentation at `https://<admin host>/api/docs`, for signed-in
  admins (also on the tenant FQDNs, without authentication, when the operator sets
  `TT_API_DOCS_PUBLIC=true`).

Error codes are described in [errors.md](errors.md). The examples use fictitious hosts:
`transfer.entity-a.example.com` for the tenant, `admin.transfer.example.com` for the
administration.

## Contents

- [Basics](#basics)
- [1. Create an API token](#1-create-an-api-token)
- [2. How a deposit works](#2-how-a-deposit-works)
- [3. Complete script: bash and curl](#3-complete-script-bash-and-curl)
- [4. Complete script: PowerShell 7](#4-complete-script-powershell-7)
- [5. Errors and retries](#5-errors-and-retries)
- [6. Managing tokens: list, change, revoke](#6-managing-tokens-list-change-revoke)

## Basics

- **One host per tenant.** The tenant is chosen by the host name of the URL: deposit on the
  FQDN of your entity, `https://transfer.entity-a.example.com/api/v1/...`. A token only works
  there: on another tenant's FQDN it is unknown (`401`), and on the admin host it opens
  nothing.
- **Versioned API.** Every path starts with `/api/v1`; no incompatible change is made within
  `v1`. New fields and new enumeration values may appear: ignore what you do not know.
- **Errors.** Every error is an RFC 9457 Problem (`application/problem+json`) with a stable
  `code` member: branch on `code` and on the HTTP status, never on `title` or `detail`, which
  are translated. The tus operations (`HEAD`, `PATCH`, `DELETE` on an upload) are the
  exception: their errors have **no body** except a `500`, the status code is the whole answer.
- **Authentication.** Send the token in every request:
  `Authorization: Bearer <token>`. No cookie and no CSRF token are needed; a cookie sent along
  is ignored. A `401` answer carries `WWW-Authenticate: Bearer`.

## 1. Create an API token

A token is created by an admin of the tenant: the super admin, or a delegated admin who may
change that tenant. It has:

- a **name**, to recognise it (`Nightly ERP export`);
- its **allowed IP ranges** (`allowedCidrs`), mandatory: the token is refused from any other
  address;
- its **allowed senders** (`allowedSenders`), optional but recommended: the sender addresses
  (`reporting@entity-a.example.com`) or domains (`entity-a.example.com`) the token may deposit
  as (see [below](#choosing-the-allowed-senders));
- an optional **expiry date** (`expiresAt`); without one, the token works until it is revoked.

The response of the creation contains the secret (`token`, `tt_` followed by 43 characters)
**once**. TransTeira stores only its SHA-256 fingerprint: a lost secret cannot be shown again,
create a new token and revoke the old one. Lists show only the `prefix` (`tt_` and the next 4
characters), enough to recognise a token.

### Choosing the allowed ranges

- List the addresses the script **leaves from**, as TransTeira sees them: the public address
  of the NAT gateway or of the outbound proxy when the script runs behind one, the server's own
  address on an internal network. TransTeira reads the client address behind the reverse proxy
  only from proxies declared in `TT_TRUSTED_PROXIES`; ask the operator if in doubt.
- Prefer a single address (`203.0.113.10/32`, `2001:db8::10/128`) or the smallest range that
  covers the servers running the script. Up to 100 ranges, IPv4 or IPv6.
- To accept any address, say so explicitly with both `0.0.0.0/0` and `::/0`. Do this only for
  a client whose address cannot be known in advance, and give the token an expiry date.
- A request with a valid token from outside its ranges gets `403 ip-not-allowed` and is
  written to the security log. The ranges can be changed later without changing the secret
  (see [section 6](#6-managing-tokens-list-change-revoke)).

### Choosing the allowed senders

Every deposit made with a token names its `senderEmail`, which must belong to an internal
domain of the tenant and not be on the blocklist. Without `allowedSenders`, that is the only
rule: whoever holds the token can deposit **as any internal address**, and the recipients see
a transfer that seems to come from a colleague who never sent it.

- Set `allowedSenders` to the functional address the job really uses
  (`["reporting@entity-a.example.com"]`). An address entry allows that address only; a domain
  entry allows every address of exactly that domain (not its subdomains). The list only
  narrows the rule: the sender must still belong to an internal domain and not be blocked.
- Up to 100 entries, normalised to lowercase. The list can be changed later without changing
  the secret (`allowedSenders: []` lifts the restriction).
- A deposit with a `senderEmail` that matches no entry gets `403 deposit-not-allowed`, like an
  address outside the internal domains. The rule is checked at creation and again at
  finalization, against the token's current list.
- Leave the list empty only for a token that genuinely deposits on behalf of many people (a
  document management system, for instance), and narrow its ranges and its expiry accordingly.
- The audit log records the sender address of each deposit made with a token
  (`api_token.used`), so a misused token can be traced to the addresses it claimed.

### Choosing an expiry

Tokens never expire by default, which suits a server-to-server job that must not stop
unexpectedly. Set `expiresAt` for anything temporary (a migration, a partner integration, a
test) and, as a rule, for every token usable from any address. A rotation every year is a
reasonable habit: create the new token, deploy it, then revoke the old one.

### With curl

The administration requires a password and a TOTP code, so a token is created from an
interactive session. Until the web interface ships, the script below does it through the
admin API; it needs `curl` and `jq`. Edit the first lines, run it, and answer the three
prompts. The password and the TOTP code are read from the terminal and passed to `jq` through
the environment, so they never appear in the process list.

```bash
#!/usr/bin/env bash
# Create a TransTeira API token through the admin API.
set -euo pipefail

TT_ADMIN_URL=https://admin.transfer.example.com      # admin host (TT_ADMIN_HOSTS)
TT_TENANT_ID=ten_01JABCD2N3P4Q5R6S7T8V9W0XY         # tenant of the token
TOKEN_NAME="Nightly ERP export"
ALLOWED_CIDRS='["203.0.113.10/32"]'                 # where the script runs
ALLOWED_SENDERS='["reporting@entity-a.example.com"]' # or []: any internal address
EXPIRES_AT='"2027-06-30T23:59:59Z"'                 # or null: never expires
TOKEN_FILE="$HOME/.config/transteira/token"         # where the secret is saved

read -rp 'Admin username: ' TT_ADMIN_USER
read -rsp 'Admin password: ' TT_ADMIN_PASSWORD; echo
read -rp 'TOTP code: ' TT_TOTP_CODE
export TT_ADMIN_USER TT_ADMIN_PASSWORD TT_TOTP_CODE

umask 077  # every file written below (session headers, secret) is private
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
: > "$work/admin-headers"
# The admin session is the __Host-tt_admin cookie; each authentication step
# returns a new cookie and a new CSRF token. Both are written to a header file
# passed with curl -H @file, never on the command line.
save_session() { # save_session STATE_JSON
  local cookie csrf
  cookie=$(sed -n 's/^[Ss]et-[Cc]ookie: __Host-tt_admin=\([^;]*\).*/\1/p' "$work/headers" | tr -d '\r' | tail -n 1)
  csrf=$(jq -r .csrfToken "$1")
  printf 'Cookie: __Host-tt_admin=%s\nX-CSRF-Token: %s\n' "$cookie" "$csrf" > "$work/admin-headers"
}
admin() { # admin METHOD PATH < JSON body; prints the answer, or the problem on stderr
  if ! curl -sS --fail-with-body -D "$work/headers" -o "$work/body" -X "$1" \
      -H 'Content-Type: application/json' -H @"$work/admin-headers" \
      --data-binary @- "$TT_ADMIN_URL/api/v1$2"; then
    cat "$work/body" >&2; echo >&2; return 1
  fi
  cat "$work/body"
}

# 1. Password, then TOTP (the secrets come from the environment, never argv).
jq -n '{username: env.TT_ADMIN_USER, password: env.TT_ADMIN_PASSWORD}' \
  | admin POST /admin/auth/login > "$work/state.json"
save_session "$work/state.json"
jq -n '{code: env.TT_TOTP_CODE}' | admin POST /admin/auth/totp > "$work/state.json"
save_session "$work/state.json"

# 2. Create the token: the secret is in this response only.
jq -n --arg name "$TOKEN_NAME" --argjson cidrs "$ALLOWED_CIDRS" \
  --argjson senders "$ALLOWED_SENDERS" --argjson exp "$EXPIRES_AT" \
  '{name: $name, allowedCidrs: $cidrs, allowedSenders: $senders, expiresAt: $exp}' \
  | admin POST "/admin/tenants/$TT_TENANT_ID/api-tokens" > "$work/token.json"
mkdir -p "$(dirname "$TOKEN_FILE")"
rm -f "$TOKEN_FILE"  # a new file gets mode 0600 from the umask
jq -r .token "$work/token.json" > "$TOKEN_FILE"
jq '{id, name, prefix, allowedCidrs, allowedSenders, expiresAt}' "$work/token.json"
echo "Secret saved to $TOKEN_FILE"

# 3. Close the admin session.
admin POST /admin/auth/logout < /dev/null > /dev/null
```

The admin session is the `__Host-tt_admin` cookie. The script handles it by hand rather than
with a cookie jar, and sends the CSRF token returned by each sign-in step in `X-CSRF-Token`,
as every state-changing admin request requires. Both values are session secrets: the script
keeps them in `$work/admin-headers` (mode `0600`, in a private temporary directory removed on
exit) and passes that file with `curl -H @file`, so they never appear in the process list.

### With PowerShell 7

```powershell
#Requires -Version 7.0
# Create a TransTeira API token through the admin API.
$ErrorActionPreference = 'Stop'

$AdminUrl  = 'https://admin.transfer.example.com'   # admin host (TT_ADMIN_HOSTS)
$TenantId  = 'ten_01JABCD2N3P4Q5R6S7T8V9W0XY'       # tenant of the token
$TokenSpec = @{
    name           = 'Nightly ERP export'
    allowedCidrs   = @('203.0.113.10/32')                # where the script runs
    allowedSenders = @('reporting@entity-a.example.com') # or @(): any internal address
    expiresAt      = '2027-06-30T23:59:59Z'              # or $null: never expires
}
$TokenFile = Join-Path $HOME '.transteira-token'    # where the secret is saved

$user = Read-Host 'Admin username'
$pass = Read-Host 'Admin password' -AsSecureString
$totp = Read-Host 'TOTP code'

# The admin session is the __Host-tt_admin cookie; each authentication step
# returns a new cookie and a new CSRF token.
$script:cookie = $null; $script:csrf = $null
function Invoke-Admin([string] $Method, [string] $Path, $Body) {
    $headers = @{}
    if ($script:cookie) { $headers.Cookie = "__Host-tt_admin=$script:cookie" }
    if ($script:csrf) { $headers['X-CSRF-Token'] = $script:csrf }
    $params = @{ Method = $Method; Uri = "$AdminUrl/api/v1$Path"; Headers = $headers }
    if ($null -ne $Body) { $params.Body = $Body | ConvertTo-Json; $params.ContentType = 'application/json' }
    $r = Invoke-WebRequest @params
    foreach ($c in $r.Headers['Set-Cookie']) {
        if ($c -match '^__Host-tt_admin=([^;]+)') { $script:cookie = $Matches[1] }
    }
    if ($r.Content) { $json = $r.Content | ConvertFrom-Json; if ($json.csrfToken) { $script:csrf = $json.csrfToken }; $json }
}

# 1. Password, then TOTP.
Invoke-Admin POST /admin/auth/login @{ username = $user; password = (ConvertFrom-SecureString $pass -AsPlainText) } | Out-Null
Invoke-Admin POST /admin/auth/totp @{ code = $totp } | Out-Null

# 2. Create the token: the secret is in this response only.
$token = Invoke-Admin POST "/admin/tenants/$TenantId/api-tokens" $TokenSpec
# Create the file empty and restrict it to the current user BEFORE writing the secret.
New-Item -ItemType File -Path $TokenFile -Force | Out-Null
if ($IsWindows) { icacls $TokenFile /inheritance:r /grant:r "${env:USERNAME}:(R,W)" | Out-Null }
else { chmod 600 $TokenFile }
if ($LASTEXITCODE) { throw "cannot restrict the permissions of $TokenFile" }
Set-Content -LiteralPath $TokenFile -Value $token.token -NoNewline
$token | Select-Object id, name, prefix, allowedCidrs, allowedSenders, expiresAt
"Secret saved to $TokenFile"

# 3. Close the admin session.
Invoke-Admin POST /admin/auth/logout | Out-Null
```

The script creates the secret file empty, restricts it, and only then writes the secret, so
the secret is never readable by other accounts, even for a moment. On Windows, `icacls`
removes the inherited permissions of the file and leaves it readable by the current user
only. The session cookie and the CSRF token stay inside the PowerShell process (request
headers), never on a command line.

### Storing the secret

- Treat the token like a password: whoever holds it can deposit files from its ranges, on
  behalf of its allowed senders, or of any internal address when `allowedSenders` is empty.
- Keep it in a secret store when you have one (a vault, Docker or Kubernetes secrets, the
  Windows Credential Manager, a CI secret variable), otherwise in a file readable by the
  account running the script only (`chmod 600`). Never in the script itself, a repository or
  a shared folder.
- Pass it to tools through a file or a header file, never as a command-line argument: other
  users of the machine can read the process list. The scripts below read it from a file.
- Do not log it. TransTeira never writes it to its own logs; check that your scheduler does not
  record the environment or the command lines of failed jobs.
- One token per application and per server: when one is compromised or decommissioned, you
  revoke it without stopping the others, and the audit log tells who deposited what.
- If a secret may have leaked, revoke the token at once (see
  [section 6](#6-managing-tokens-list-change-revoke)): every new request with it is refused
  from then on.

## 2. How a deposit works

A deposit takes five steps. The complete scripts of sections 3 and 4 implement them with
retries; this section shows each request on its own.

```text
POST /api/v1/transfers                   declare the transfer and its files  -> 201, one uploadUrl per file
  for each file:
    HEAD  <uploadUrl>                    where to start (Upload-Offset)       -> 200
    PATCH <uploadUrl>  (repeat)          send a chunk at Upload-Offset         -> 204, new Upload-Offset
    (connection cut?  HEAD again, then PATCH from the returned offset)
POST /api/v1/transfers/{id}/finalize     hand over to the antivirus           -> 202, status scanning
GET  /api/v1/transfers/{id}  (poll)      until status is available            -> 200
```

### Step 1: create the transfer

```bash
curl -sS -X POST https://transfer.entity-a.example.com/api/v1/transfers \
  -H @auth-header.txt -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: 5f0c6c1e-8b7a-4a8e-9f0d-2c3b4a5d6e7f' \
  --data-binary @- <<'EOF'
{
  "senderEmail": "reporting@entity-a.example.com",
  "recipients": ["finance@entity-a.example.com"],
  "expiryDays": 7,
  "message": "Nightly export",
  "files": [
    { "name": "export-2026-10-19.csv", "size": 52428800,
      "expectedSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }
  ]
}
EOF
```

`auth-header.txt` holds the single line `Authorization: Bearer <token>`, so that the token
stays out of the command line (`curl -H @file`).

- `senderEmail` is **mandatory** with a token and must belong to one of the **internal
  domains** of the tenant and, when the token has `allowedSenders`, match one of them
  (`403 deposit-not-allowed` otherwise, and for an address or domain on the blocklist). No
  verification code is sent: the token is the proof. Use a functional
  address that someone reads: it receives the confirmation, the antivirus alerts and the
  first-download receipt.
- `recipients` is mandatory: 1 to `TT_MAX_RECIPIENTS` addresses (50 by default).
- `expiryDays` is `1`, `7` or `30`; it starts when the transfer becomes available.
- `files` declares every file with its exact `size` in bytes. `expectedSha256` is optional but
  recommended: the server compares it with the fingerprint it computes while receiving the
  bytes, and finalization fails with `409 checksum-mismatch` on a difference.
- Optional: `message`, `password` (sent to the recipients through another channel; the mail
  only says one is needed), `deleteAfterFirstDownload`, `language` (`fr` or `en`, the language
  of the recipients' mail).

The answer (`201`) is the transfer, with its `id` and, for each file in the declared order,
an `uploadUrl` such as `/api/v1/uploads/upl_7Hq2Wm9Zx4Lp1Vb8Rt3Yk6Nd`. The server has checked
the size limit and reserved the declared size in the tenant quota.

### Step 2: upload with PATCH

```bash
# Bytes 0 to 104857599 (the first 100 MiB) of the file, streamed from disk.
dd if=export.bin iflag=skip_bytes,count_bytes skip=0 count=104857600 bs=1M status=none |
  curl -sS -X PATCH -T - "https://transfer.entity-a.example.com/api/v1/uploads/upl_7Hq2Wm9Zx4Lp1Vb8Rt3Yk6Nd" \
    -H @auth-header.txt -H 'Tus-Resumable: 1.0.0' -H 'Upload-Offset: 0' \
    -H 'Content-Type: application/offset+octet-stream' -H 'Content-Length: 104857600' \
    -D - -o /dev/null
```

- Every tus request carries `Tus-Resumable: 1.0.0` (`412` otherwise).
- The body is raw bytes, `Content-Type: application/offset+octet-stream` (`415` otherwise),
  starting at `Upload-Offset`, which must equal the current offset of the upload (`409`
  otherwise).
- The answer `204` carries the new `Upload-Offset`. Repeat with the next chunk until it equals
  the file size.
- Any chunk size is accepted, the whole file included. Chunks of 50 to 500 MiB are a good
  compromise: a cut costs at most one chunk's progress in the worst case, and some proxies in
  the path (outbound proxies, application firewalls) limit the size or the duration of one
  request. The server encrypts and hashes the bytes on the fly and never holds a chunk in
  memory; keep it that way on the client side: stream from the file, never read a chunk into
  a buffer.
- A request whose body stalls for `TT_UPLOAD_IDLE_TIMEOUT` (60 s by default) is cut by the
  server; what was received is kept.

### Step 3: resume after a cut with HEAD

When a `PATCH` fails (connection reset, timeout, `5xx`, `409`), do not guess: ask the server.

```bash
curl -sS -I "https://transfer.entity-a.example.com/api/v1/uploads/upl_7Hq2Wm9Zx4Lp1Vb8Rt3Yk6Nd" \
  -H @auth-header.txt -H 'Tus-Resumable: 1.0.0'
# HTTP/1.1 200 OK
# Upload-Offset: 23068322
# Upload-Length: 52428800
# Upload-Expires: Sat, 24 Oct 2026 05:55:34 GMT
```

`Upload-Offset` is the number of bytes durably stored, which may be more than the last
acknowledged `PATCH`: the bytes received before a cut are kept. Send the next `PATCH` from
exactly that offset. An upload stays resumable until `Upload-Expires`: `TT_UPLOAD_TTL` (24 h
by default) without activity on any file of the transfer, and at most `TT_UPLOAD_MAX_AGE`
(7 days by default) after the creation of the transfer; then it answers `410` and the transfer
must be created again.

### Step 4: finalize

```bash
curl -sS -X POST https://transfer.entity-a.example.com/api/v1/transfers/trf_01JABCD8E3W5Q2Z7K9M4N6P0RS/finalize \
  -H @auth-header.txt
```

The server checks that every file is complete (`409 upload-incomplete` with the list of the
files otherwise), compares the `expectedSha256` values and the blocklist, and hands the files
to the antivirus. It answers `202` at once with the status `scanning`.

### Step 5: follow until available

```bash
curl -sS https://transfer.entity-a.example.com/api/v1/transfers/trf_01JABCD8E3W5Q2Z7K9M4N6P0RS \
  -H @auth-header.txt | jq '{status, downloadUrl, files: [.files[] | {name, scanStatus, sha256}]}'
```

Poll every 10 to 30 seconds:

| `status` | Meaning |
|---|---|
| `scanning` | The antivirus is running. It is fail-closed: while ClamAV is unavailable the transfer waits, it is never released unscanned. |
| `available` | The recipients have received the link, the QR code and the SHA-256 fingerprints; `downloadUrl` and `expiresAt` are set. |
| `rejected` | No file could be delivered (every file infected or in `scan_error`); nobody is notified. |

Per file, `scanStatus` is `clean`, `infected` (erased, the sender is alerted),
`not_scanned_too_large` or `not_scanned_encrypted` (delivered with a warning on the download
page), or `scan_error` (withheld).

A token reads, finalizes and cancels only the transfers **it** created: any other transfer,
including one created by another token of the same tenant, answers `404`. To abandon an
unfinished transfer and release its quota reservation, `DELETE /api/v1/transfers/{id}` (only
while it is still `uploading`).

## 3. Complete script: bash and curl

`tt-deposit.sh` deposits one or more files, resumes every interrupted chunk after a `HEAD`,
finalizes, then waits until the transfer is available. It needs bash, curl 7.76 or later,
`jq`, `sha256sum` and GNU `dd` (Linux, Git Bash on Windows; on macOS install the GNU
coreutils). In Git Bash, the Windows build of `jq` ends its lines with CRLF, which breaks the
identifiers read by the script: put a wrapper named `jq` that runs the Windows build with
`--binary` (`-b`) first in the `PATH`. Memory use stays constant whatever the size of the
files: each chunk is streamed from disk by `dd` into curl.

```bash
#!/usr/bin/env bash
# tt-deposit.sh: deposit files to TransTeira with an API token (tus 1.0.0).
#
# Usage: tt-deposit.sh FILE...
#
# Environment:
#   TT_URL          tenant URL, e.g. https://transfer.entity-a.example.com (required)
#   TT_TOKEN_FILE   file holding the API token (required)
#   TT_SENDER       sender address: internal domain, allowed by the token (required)
#   TT_RECIPIENTS   recipients, comma-separated (required)
#   TT_EXPIRY_DAYS  1, 7 or 30 (default 7)
#   TT_MESSAGE      message to the recipients (optional)
#   TT_CHUNK_SIZE   bytes per PATCH request (default 104857600, 100 MiB)
#   TT_LIMIT_RATE   bandwidth cap passed to curl --limit-rate, e.g. 20M (optional)
#   TT_STATE_FILE   resume state (default ./tt-deposit.state); kept until success
#
# Requires bash, curl 7.76+, jq, sha256sum and GNU dd (coreutils).
# Exit status: 0 available, 1 refused or failed, 2 every file rejected.
set -euo pipefail

: "${TT_URL:?}" "${TT_TOKEN_FILE:?}" "${TT_SENDER:?}" "${TT_RECIPIENTS:?}"
TT_EXPIRY_DAYS=${TT_EXPIRY_DAYS:-7}
TT_CHUNK_SIZE=${TT_CHUNK_SIZE:-104857600}
TT_STATE_FILE=${TT_STATE_FILE:-./tt-deposit.state}
MAX_RETRIES=20
(($# > 0)) || { echo "usage: $0 FILE..." >&2; exit 1; }
# Never send the token over plain HTTP.
[[ $TT_URL == https://* ]] || { echo "TT_URL must start with https://" >&2; exit 1; }

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
# The token goes in a header file (curl -H @file), never on the command line.
(umask 077; printf 'Authorization: Bearer %s\n' "$(tr -d '\r\n' < "$TT_TOKEN_FILE")" > "$work/auth")

log() { printf '%s %s\n' "$(date +%T)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
# retry_after prints the Retry-After of the last answer (default $1 seconds).
retry_after() {
  local v; v=$(sed -n 's/^[Rr]etry-[Aa]fter: *\([0-9]*\).*/\1/p' "$work/headers" | tail -n 1)
  echo "${v:-$1}"
}
# api METHOD PATH [curl options...]: JSON call; body in $work/body, prints the status.
api() {
  local method=$1 path=$2; shift 2
  curl -sS -H @"$work/auth" -D "$work/headers" -o "$work/body" -w '%{http_code}' \
    -X "$method" "$@" "$TT_URL$path" || true
}
problem() { jq -r '"\(.status) \(.code): \(.detail // .title)"' "$work/body" 2>/dev/null || cat "$work/body"; }

# 1. Describe the files: name, size and SHA-256 (checked again at finalization).
files='[]'
for f in "$@"; do
  [[ -f $f ]] || die "$f: not a regular file"
  files=$(jq --arg name "$(basename "$f")" --argjson size "$(stat -c %s "$f")" \
    --arg sha "$(sha256sum "$f" | cut -d' ' -f1)" \
    '. + [{name: $name, size: $size, expectedSha256: $sha}]' <<<"$files")
done
request=$(jq -n --arg sender "$TT_SENDER" --arg rcpt "$TT_RECIPIENTS" \
  --argjson days "$TT_EXPIRY_DAYS" --arg msg "${TT_MESSAGE:-}" --argjson files "$files" \
  '{senderEmail: $sender, recipients: ($rcpt | split(",") | map(gsub("^ +| +$"; ""))),
    expiryDays: $days, files: $files} + (if $msg == "" then {} else {message: $msg} end)')

# 2. Create the transfer. The Idempotency-Key is kept in the state file: after a
#    crash, running the script again with the same files returns the same transfer.
[[ -s $TT_STATE_FILE ]] || od -An -tx1 -N16 /dev/urandom | tr -d ' \n' > "$TT_STATE_FILE"
key=$(cat "$TT_STATE_FILE")
for ((try = 1; ; try++)); do
  status=$(api POST /api/v1/transfers -H 'Content-Type: application/json' \
    -H "Idempotency-Key: $key" --data-binary "$request")
  case $status in
    201) break ;;
    429 | 503) wait=$(retry_after 60); log "create: $status, retrying in ${wait}s"; sleep "$wait" ;;
    000 | 5??) ((try < MAX_RETRIES)) || die "create: giving up ($status)"; sleep $((try * 5)) ;;
    *) die "create: $(problem)" ;;
  esac
done
transfer=$(jq -r .id "$work/body")
jq -r '.files[] | "\(.uploadUrl) \(.size)"' "$work/body" > "$work/uploads"
log "transfer $transfer created (status $(jq -r .status "$work/body"))"

# head_offset URL: durable offset of an upload, or "" (status in $work/status).
head_offset() {
  local s
  s=$(curl -sS -I -H @"$work/auth" -H 'Tus-Resumable: 1.0.0' -D "$work/headers" \
    -o /dev/null -w '%{http_code}' "$TT_URL$1" || true)
  echo "$s" > "$work/status"
  [[ $s == 200 ]] && sed -n 's/^[Uu]pload-[Oo]ffset: *\([0-9]*\).*/\1/p' "$work/headers"
  return 0
}

# 3. Upload each file in chunks; after any cut, HEAD gives the offset to resume from.
upload() { # upload FILE URL SIZE
  local file=$1 url=$2 size=$3 offset len status failures=0
  while :; do
    offset=$(head_offset "$url")
    case $(cat "$work/status") in
      200) ;;
      429 | 503) sleep "$(retry_after 60)"; continue ;;
      000 | 5??) ((++failures < MAX_RETRIES)) || die "$file: HEAD failed"; sleep $((failures * 5)); continue ;;
      *) die "$file: HEAD answered $(cat "$work/status")" ;; # tus errors have no body
    esac
    ((offset < size)) || { log "$file: complete ($size bytes)"; return; }
    len=$((size - offset < TT_CHUNK_SIZE ? size - offset : TT_CHUNK_SIZE))
    log "$file: sending bytes $offset-$((offset + len - 1)) of $size"
    # dd streams the chunk from disk: nothing is loaded in memory.
    status=$(dd if="$file" iflag=skip_bytes,count_bytes skip="$offset" count="$len" \
      bs=1M status=none | curl -sS -X PATCH -T - -H @"$work/auth" \
      -H 'Tus-Resumable: 1.0.0' -H "Upload-Offset: $offset" \
      -H 'Content-Type: application/offset+octet-stream' -H "Content-Length: $len" \
      ${TT_LIMIT_RATE:+--limit-rate "$TT_LIMIT_RATE"} \
      -D "$work/headers" -o /dev/null -w '%{http_code}' "$TT_URL$url") || status=000
    case $status in
      204) failures=0 ;;
      000 | 400 | 409 | 5??) # cut, offset mismatch or server error: HEAD and resume
        [[ $status == 503 ]] && { sleep "$(retry_after 60)"; continue; }
        ((++failures < MAX_RETRIES)) || die "$file: too many failures"
        log "$file: PATCH answered $status, resuming after HEAD"; sleep $((failures * 2)) ;;
      429) sleep "$(retry_after 60)" ;;
      *) die "$file: PATCH answered $status" ;; # 401, 403, 404, 410, 413, 415
    esac
  done
}
i=0
while read -r url size; do
  i=$((i + 1)); upload "${!i}" "$url" "$size"
done < "$work/uploads"

# 4. Finalize: the antivirus then runs asynchronously.
status=$(api POST "/api/v1/transfers/$transfer/finalize")
[[ $status == 202 ]] || die "finalize: $(problem)"
log "transfer $transfer finalized, antivirus analysis in progress"

# 5. Poll until the transfer is available (or rejected).
while :; do
  status=$(api GET "/api/v1/transfers/$transfer")
  case $status in
    200) ;;
    000 | 429 | 5??) sleep "$(retry_after 15)"; continue ;;
    *) die "follow: $(problem)" ;;
  esac
  state=$(jq -r .status "$work/body")
  case $state in
    scanning | uploading) sleep 10 ;;
    available | rejected) break ;;
    *) die "transfer $transfer is $state" ;;
  esac
done
rm -f "$TT_STATE_FILE"
jq -r '.files[] | "\(.scanStatus)\t\(.sha256 // "-")\t\(.name)"' "$work/body"
if [[ $state == available ]]; then
  log "available until $(jq -r .expiresAt "$work/body"): $(jq -r .downloadUrl "$work/body")"
else
  log "rejected: no file could be delivered"; exit 2
fi
```

Run it with the parameters in the environment:

```bash
export TT_URL=https://transfer.entity-a.example.com
export TT_TOKEN_FILE=$HOME/.config/transteira/token
export TT_SENDER=reporting@entity-a.example.com
export TT_RECIPIENTS="finance@entity-a.example.com, controller@entity-a.example.com"
export TT_EXPIRY_DAYS=7
./tt-deposit.sh /srv/exports/export-2026-10-19.csv /srv/exports/summary.pdf
```

Typical output, with a connection cut during the second chunk:

```text
07:55:24 transfer trf_01M5KN83NZXY7Q2STX36N948J0 created (status uploading)
07:55:25 /srv/exports/export-2026-10-19.csv: sending bytes 0-20971519 of 52428800
07:55:31 /srv/exports/export-2026-10-19.csv: sending bytes 20971520-41943039 of 52428800
07:55:32 /srv/exports/export-2026-10-19.csv: PATCH answered 000, resuming after HEAD
07:55:34 /srv/exports/export-2026-10-19.csv: sending bytes 23068322-44039841 of 52428800
07:55:40 /srv/exports/export-2026-10-19.csv: sending bytes 44039842-52428799 of 52428800
07:55:43 /srv/exports/export-2026-10-19.csv: complete (52428800 bytes)
07:55:44 /srv/exports/summary.pdf: sending bytes 0-2999999 of 3000000
07:55:45 /srv/exports/summary.pdf: complete (3000000 bytes)
07:55:46 transfer trf_01M5KN83NZXY7Q2STX36N948J0 finalized, antivirus analysis in progress
clean	1dbabbcf5afef117492411ab8623f91233086c3a4ddd420c1196cc36b5fea62c	export-2026-10-19.csv
clean	9e5a357c5de6d7b7db984ccf8c7b80bc4ac20fa1fcb133053de6033cb7a43062	summary.pdf
07:55:57 available until 2026-10-24T05:55:51.619Z: https://transfer.entity-a.example.com/d/dl_...
```

Two levels of resumption:

- **A cut during a chunk** (network, proxy, server restart): the script asks `HEAD` for the
  durable offset and continues from there, up to 20 consecutive failures with a growing pause.
- **The script itself stopped** (reboot, `kill`, a job timeout): run the same command again,
  from the same directory, with the same files. The `Idempotency-Key` saved in
  `TT_STATE_FILE` makes the creation return the transfer created the first time, and each file
  resumes from its durable offset. The state file is removed once the transfer is available.
  Use one state file per job when several jobs share a directory.

## 4. Complete script: PowerShell 7

`tt-deposit.ps1` does the same with `System.Net.Http.HttpClient`. Each chunk is streamed from
the file through a small read-only stream (`TransTeira.FileSlice`, compiled once per session
with `Add-Type`), so nothing is loaded in memory, whatever the size. It calls the synchronous
`HttpClient.Send`, which needs **PowerShell 7.2 or later** (.NET 6; Windows PowerShell 5.1 is
not supported). The token-creation script of section 1 runs on PowerShell 7.0.

```powershell
#Requires -Version 7.2
<#
.SYNOPSIS
  Deposits files to TransTeira with an API token (tus 1.0.0, resumable).
.EXAMPLE
  ./tt-deposit.ps1 -Url https://transfer.entity-a.example.com -TokenFile ~/.transteira-token `
    -Sender reporting@entity-a.example.com -Recipients finance@entity-a.example.com `
    -Path ./export.csv -ExpiryDays 1
#>
param(
    [Parameter(Mandatory)] [string] $Url,
    [Parameter(Mandatory)] [string] $TokenFile,
    [Parameter(Mandatory)] [string] $Sender,
    [Parameter(Mandatory)] [string[]] $Recipients,
    [Parameter(Mandatory)] [string[]] $Path,
    [ValidateSet(1, 7, 30)] [int] $ExpiryDays = 7,
    [string] $Message,
    [long] $ChunkSize = 100MB,
    [string] $StateFile = './tt-deposit.state',
    [int] $MaxRetries = 20
)
$ErrorActionPreference = 'Stop'

# A read-only window [offset, offset+length) of a file: the request body of one
# PATCH, streamed from disk without loading the chunk in memory.
if (-not ('TransTeira.FileSlice' -as [type])) {
    Add-Type -TypeDefinition @'
namespace TransTeira {
    public sealed class FileSlice : System.IO.Stream {
        private readonly System.IO.FileStream file;
        private long left;
        public FileSlice(string path, long offset, long length) {
            file = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read,
                System.IO.FileShare.Read, 1 << 20);
            file.Seek(offset, System.IO.SeekOrigin.Begin);
            left = length;
        }
        public override int Read(byte[] buffer, int offset, int count) {
            if (left <= 0) return 0;
            int n = file.Read(buffer, offset, (int)System.Math.Min(count, left));
            left -= n;
            return n;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new System.NotSupportedException();
        public override long Position { get => throw new System.NotSupportedException(); set => throw new System.NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long o, System.IO.SeekOrigin s) => throw new System.NotSupportedException();
        public override void SetLength(long v) => throw new System.NotSupportedException();
        public override void Write(byte[] b, int o, int c) => throw new System.NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) file.Dispose(); base.Dispose(disposing); }
    }
}
'@
}

function Write-Log([string] $Text) { Write-Host "$(Get-Date -Format HH:mm:ss) $Text" }

$client = [System.Net.Http.HttpClient]::new()
$client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
if (([Uri]$Url).Scheme -ne 'https') { throw 'Url must start with https:// (the token is never sent over plain HTTP)' }
$client.BaseAddress = [Uri]$Url
$token = (Get-Content -Raw -LiteralPath $TokenFile).Trim()
$client.DefaultRequestHeaders.Authorization =
    [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)

# Sends a request; returns the response, or $null when the connection failed.
function Send-Request([string] $Method, [string] $Uri, [hashtable] $Headers = @{}, $Content = $null) {
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), $Uri)
    foreach ($k in $Headers.Keys) { $req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k]) | Out-Null }
    $req.Content = $Content
    try { return $client.Send($req) }
    catch [System.Net.Http.HttpRequestException], [System.IO.IOException] {
        Write-Log "connection failed: $($_.Exception.Message)"
        return $null
    }
    finally { $req.Dispose() }
}
function Get-RetryAfter($Response, [int] $Default) {
    $d = $Response.Headers.RetryAfter.Delta
    if ($d) { [int]$d.TotalSeconds } else { $Default }
}
function Read-Json($Response) { $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json }
function Stop-WithProblem([string] $Step, $Response) {
    $p = $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    throw "${Step}: HTTP $([int]$Response.StatusCode) $p"
}
function Wait-Retry([ref] $Failures, [string] $Step, [int] $Delay) {
    $Failures.Value++
    if ($Failures.Value -ge $MaxRetries) { throw "${Step}: too many failures" }
    Start-Sleep -Seconds $Delay
}

# 1. Describe the files: name, size and SHA-256 (checked again at finalization).
$items = foreach ($p in $Path) { Get-Item -LiteralPath $p }
$declared = @(foreach ($f in $items) {
    @{ name = $f.Name; size = $f.Length
       expectedSha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$body = @{ senderEmail = $Sender; recipients = @($Recipients); expiryDays = $ExpiryDays; files = $declared }
if ($Message) { $body.message = $Message }
$json = $body | ConvertTo-Json -Depth 5

# 2. Create the transfer. The Idempotency-Key is kept in the state file: after a
#    crash, running the script again with the same files returns the same transfer.
if (-not (Test-Path -LiteralPath $StateFile)) { [guid]::NewGuid().ToString() | Set-Content -LiteralPath $StateFile }
$key = (Get-Content -LiteralPath $StateFile -Raw).Trim()
$failures = 0
while ($true) {
    $content = [System.Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, 'application/json')
    $r = Send-Request POST 'api/v1/transfers' @{ 'Idempotency-Key' = $key } $content
    if ($r -and $r.StatusCode -eq 201) { break }
    if (-not $r -or [int]$r.StatusCode -ge 500 -and [int]$r.StatusCode -ne 503) {
        Wait-Retry ([ref]$failures) 'create' (5 * ($failures + 1)); continue
    }
    if ([int]$r.StatusCode -in 429, 503) { Start-Sleep -Seconds (Get-RetryAfter $r 60); continue }
    Stop-WithProblem 'create' $r   # 400, 401, 403, 409, 413, 507...
}
$transfer = Read-Json $r
Write-Log "transfer $($transfer.id) created (status $($transfer.status))"

# 3. Upload each file in chunks; after any cut, HEAD gives the offset to resume from.
$tus = @{ 'Tus-Resumable' = '1.0.0' }
for ($i = 0; $i -lt $transfer.files.Count; $i++) {
    $file = $transfer.files[$i]; $local = $items[$i].FullName; $size = [long]$file.size
    $failures = 0
    while ($true) {
        $r = Send-Request HEAD $file.uploadUrl $tus
        if (-not $r -or [int]$r.StatusCode -ge 500 -and [int]$r.StatusCode -ne 503) {
            Wait-Retry ([ref]$failures) "$($file.name): HEAD" (5 * ($failures + 1)); continue
        }
        if ([int]$r.StatusCode -in 429, 503) { Start-Sleep -Seconds (Get-RetryAfter $r 60); continue }
        if ($r.StatusCode -ne 200) { throw "$($file.name): HEAD answered $([int]$r.StatusCode)" } # no body
        $offset = [long]($r.Headers.GetValues('Upload-Offset') | Select-Object -First 1)
        if ($offset -ge $size) { Write-Log "$($file.name): complete ($size bytes)"; break }

        $len = [Math]::Min($ChunkSize, $size - $offset)
        Write-Log "$($file.name): sending bytes $offset-$($offset + $len - 1) of $size"
        $content = [System.Net.Http.StreamContent]::new([TransTeira.FileSlice]::new($local, $offset, $len), 1MB)
        $content.Headers.ContentType = 'application/offset+octet-stream'
        $content.Headers.ContentLength = $len
        $r = Send-Request PATCH $file.uploadUrl ($tus + @{ 'Upload-Offset' = $offset }) $content
        $content.Dispose()
        $code = if ($r) { [int]$r.StatusCode } else { 0 }
        if ($code -eq 204) { $failures = 0; continue }
        if ($code -in 429, 503) { Start-Sleep -Seconds (Get-RetryAfter $r 60); continue }
        if ($code -in 0, 400, 409 -or $code -ge 500) {   # cut, offset mismatch, server error
            Write-Log "$($file.name): PATCH answered $code, resuming after HEAD"
            Wait-Retry ([ref]$failures) "$($file.name): PATCH" (2 * ($failures + 1)); continue
        }
        throw "$($file.name): PATCH answered $code"   # 401, 403, 404, 410, 413, 415
    }
}

# 4. Finalize: the antivirus then runs asynchronously.
$r = Send-Request POST "api/v1/transfers/$($transfer.id)/finalize"
if (-not $r -or $r.StatusCode -ne 202) { if ($r) { Stop-WithProblem 'finalize' $r } else { throw 'finalize: connection failed' } }
Write-Log "transfer $($transfer.id) finalized, antivirus analysis in progress"

# 5. Poll until the transfer is available (or rejected).
while ($true) {
    $r = Send-Request GET "api/v1/transfers/$($transfer.id)"
    if (-not $r -or [int]$r.StatusCode -in 429, 503 -or [int]$r.StatusCode -ge 500) {
        Start-Sleep -Seconds $(if ($r) { Get-RetryAfter $r 15 } else { 15 }); continue
    }
    if ($r.StatusCode -ne 200) { Stop-WithProblem 'follow' $r }
    $transfer = Read-Json $r
    if ($transfer.status -in 'available', 'rejected') { break }
    if ($transfer.status -notin 'uploading', 'scanning') { throw "transfer $($transfer.id) is $($transfer.status)" }
    Start-Sleep -Seconds 10
}
Remove-Item -LiteralPath $StateFile
$transfer.files | Format-Table name, scanStatus, sha256 -AutoSize | Out-Host
if ($transfer.status -eq 'available') {
    Write-Log "available until $($transfer.expiresAt): $($transfer.downloadUrl)"
} else {
    Write-Log 'rejected: no file could be delivered'; exit 2
}
```

Run it:

```powershell
./tt-deposit.ps1 -Url https://transfer.entity-a.example.com `
    -TokenFile (Join-Path $HOME '.transteira-token') `
    -Sender reporting@entity-a.example.com `
    -Recipients finance@entity-a.example.com, controller@entity-a.example.com `
    -Path D:\exports\export-2026-10-19.csv, D:\exports\summary.pdf `
    -ExpiryDays 7 -Message 'Nightly export'
```

Typical output, the job having been stopped during the first file and started again:

```text
07:57:54 transfer trf_01M5KNCNX59Q9QBQXMC7568C16 created (status uploading)
07:57:54 export-2026-10-19.csv: sending bytes 0-20971519 of 52428800
          (process stopped, then the same command run again)
07:58:04 transfer trf_01M5KNCNX59Q9QBQXMC7568C16 created (status uploading)
07:58:04 export-2026-10-19.csv: sending bytes 11669158-32640677 of 52428800
07:58:13 export-2026-10-19.csv: sending bytes 32640678-52428799 of 52428800
07:58:20 export-2026-10-19.csv: complete (52428800 bytes)
07:58:20 summary.pdf: sending bytes 0-2999999 of 3000000
07:58:21 summary.pdf: complete (3000000 bytes)
07:58:21 transfer trf_01M5KNCNX59Q9QBQXMC7568C16 finalized, antivirus analysis in progress
```

The same transfer comes back after the restart (same `Idempotency-Key`), and the upload
resumes from the 11 669 158 bytes the server had stored. A cut in the middle of a chunk
(`connection failed`, then `PATCH answered 0, resuming after HEAD`) is handled within the run,
as in the bash script.

To schedule it on Windows, run `pwsh.exe -NoProfile -File C:\scripts\tt-deposit.ps1 ...` from
the Task Scheduler with an account dedicated to the job, the token file readable by that
account only, and a fixed working directory for the state file (or `-StateFile`).

## 5. Errors and retries

| Answer | Meaning | What the scripts do |
|---|---|---|
| `401 unauthenticated` | No `Authorization` header. The answer carries `WWW-Authenticate: Bearer`. | Stop. |
| `401 invalid-credentials` | Token malformed, unknown on this host, revoked or expired. Checked before the client address, written to the security log (`api_token_invalid`). The answer carries `WWW-Authenticate: Bearer`. | **Stop.** Never retry an invalid token: 10 failures from one address within 10 minutes lock that address out for 15 minutes (every further invalid token gets `429`; valid tokens keep working), and fail2ban or CrowdSec may ban it for longer. |
| `403 ip-not-allowed` | Valid token, called from outside its `allowedCidrs`. Written to the security log. | Stop; fix the ranges (section 6) or the egress address. |
| `403 deposit-not-allowed` | `senderEmail` outside the internal domains, not in the token's `allowedSenders` (when set; checked at creation and finalization), or blocked. | Stop; use an allowed sender or change the token's `allowedSenders`. |
| `403 blocked-file` | At finalization: a file fingerprint is on the blocklist. | Stop. |
| `404 not-found` | Unknown transfer or upload, or one that belongs to another token. | Stop. |
| `409 state-conflict` | Same `Idempotency-Key` with a different body, or the transfer is no longer `uploading`. | Stop (creation, finalization). |
| `409` on `PATCH` | `Upload-Offset` differs from the server's offset, or another request is uploading this file. | `HEAD`, then resume. |
| `409 upload-incomplete`, `409 checksum-mismatch` | At finalization: a file is incomplete, or its fingerprint differs from `expectedSha256`. | Stop: check the source file. |
| `410` on `HEAD` or `PATCH` | Upload expired (`TT_UPLOAD_TTL`, `TT_UPLOAD_MAX_AGE`) or transfer cancelled. | Stop; create a new transfer. |
| `413 transfer-too-large` | The declared total exceeds the tenant limit (`maxTransferBytes` in the problem, 20 GB at most). | Stop; split into several transfers. |
| `413` on `PATCH` | Bytes beyond the declared size. | Stop; the file changed after it was declared. |
| `429 rate-limited` | Too many requests: an invalid token from an address locked out after repeated invalid tokens, or more than `TT_MAX_OPEN_TRANSFERS` unfinished transfers for this token (10 by default; finalizing or cancelling one frees a slot). | Wait `Retry-After` seconds, then retry. |
| `503 maintenance` | Maintenance mode: new deposits are refused for a while. Uploads already started can be resumed afterwards. | Wait `Retry-After` seconds, then retry. |
| `507 quota-exceeded` | The tenant storage quota is reached. | Stop; the administrators are notified. |
| `5xx`, connection errors | Transient failure. | Retry with a growing pause, at most 20 times. |

General rules for your own client:

- Branch on the status and the `code`; read `Retry-After` on `429` and `503` (also present
  without a body on the tus operations).
- Make the creation idempotent: send an `Idempotency-Key` (1 to 64 visible ASCII characters, a
  random UUID for example) and keep it until the transfer is created. Within 24 hours, the same key with
  the same body returns the same transfer (`201`) instead of creating a second one; with a
  different body it gets `409 state-conflict`. Keys are scoped to the token.
- Never treat an `HTTP 2xx` on the last `PATCH` as the end of the work: only `available`
  after finalization means the recipients were notified.
- Log the `instance` member of a problem (also the `X-Request-Id` header): administrators use
  it to find the request in their logs.

## 6. Managing tokens: list, change, revoke

These calls use an admin session, opened as in the scripts of
[section 1](#1-create-an-api-token): reuse their sign-in steps and replace the creation by
the calls below, before the logout, with the header file `$work/admin-headers` (session
cookie and CSRF token) written after the TOTP step. Reading
needs access to the tenant; changes need the right to change it. A tenant the admin is not
attached to answers `404`, like a token of another tenant.

| Operation | Request |
|---|---|
| List (secrets never shown, revoked tokens included) | `GET /api/v1/admin/tenants/{tenantId}/api-tokens` |
| Rename, change the ranges or the allowed senders | `PATCH /api/v1/admin/tenants/{tenantId}/api-tokens/{tokenId}`, `Content-Type: application/merge-patch+json`, body `{"allowedCidrs": ["203.0.113.11/32"]}`, `{"allowedSenders": ["reporting@entity-a.example.com"]}` or `{"name": "..."}` |
| Revoke | `DELETE /api/v1/admin/tenants/{tenantId}/api-tokens/{tokenId}` |

For example, with curl and the session header file (never the cookie or the CSRF token on the
command line):

```bash
curl -sS "$TT_ADMIN_URL/api/v1/admin/tenants/$TT_TENANT_ID/api-tokens" \
  -H @"$work/admin-headers" \
  | jq '.[] | {id, name, prefix, allowedCidrs, allowedSenders, lastUsedAt, revokedAt}'

curl -sS -X DELETE "$TT_ADMIN_URL/api/v1/admin/tenants/$TT_TENANT_ID/api-tokens/tok_01JABCJ5M6N7P8Q9R0S1T2V3V4" \
  -H @"$work/admin-headers" -o /dev/null -w '%{http_code}\n'
```

- **Revocation and expiry take effect on the next request**: every request that starts after
  them gets `401 invalid-credentials`. A `PATCH` upload already streaming when the token is
  revoked or expires is not cut: it goes on until its body ends or stalls
  (`TT_UPLOAD_IDLE_TIMEOUT`), and the bytes it delivered are stored, but the transfer can no
  longer be resumed or finalized with that token.
- Revoking a token already revoked answers `204` and changes nothing. A revoked token cannot be
  modified (`409 state-conflict`) and stays in the list for the record.
- The expiry date is set at creation only. To change it, create a new token and revoke the old
  one.
- `lastUsedAt` is the last successful authentication, updated at most once a minute per token.
  A token unused for months is probably forgotten: revoke it.
- The audit log of the tenant records `api_token.created`, `api_token.updated` and
  `api_token.revoked` (by the admin), and `api_token.used` once per transfer created with a
  token, with the sender address (`senderEmail`) as actor and the token as object; the
  transfer events (`transfer.created`, `transfer.finalized`...) name the token (`tok_...`) as
  actor. Secrets never appear in it. Like every depositor address, the sender address of
  `api_token.used` is pseudonymised by the erasure of the person's data.

### Rotating a token

1. Create a new token with the same ranges and allowed senders.
2. Deploy its secret where the job reads it.
3. Check that the next run succeeds (`lastUsedAt` of the new token).
4. Revoke the old token.

A transfer belongs to the token that created it: a transfer still uploading when its token is
revoked can no longer be resumed or finalized, and is cleaned up when its uploads expire. Rotate
between two runs.

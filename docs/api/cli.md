# Command-line client

`transteira-cli` is a single, static binary (Linux, macOS, Windows; amd64 and arm64) that
deposits files into TransTeira, downloads a transfer link and checks a proof of deposit or
delivery, from a terminal or a script. It is a plain consumer of the public API (`/api/v1`): it
uses an [API token](integration.md#1-create-an-api-token), the
[tus](https://tus.io/protocols/resumable-upload) protocol, and resumes by itself after a
network cut, even between two runs. It also understands end-to-end encrypted transfers
(`TTE2` format), which the scripts of the [integration guide](integration.md) leave to you.

> The exact flags of each command are listed by `transteira-cli <command> -h` (for example
> `transteira-cli upload -h`). This guide describes the behaviour and the main options; if a
> flag name differs from the help of the binary you run, the help is right.

The examples use fictitious hosts: `transfer.entity-a.example.com` for the tenant.

## Contents

- [1. Install](#1-install)
- [2. Configuration](#2-configuration)
- [3. Commands](#3-commands)
- [4. Examples](#4-examples)
- [5. Resuming an upload](#5-resuming-an-upload)
- [6. Downloads](#6-downloads)
- [7. Exit codes](#7-exit-codes)

## 1. Install

### From the release binaries

Each GitHub release carries one binary per platform and a `SHA256SUMS` file:

```text
transteira-cli_<version>_linux_amd64
transteira-cli_<version>_linux_arm64
transteira-cli_<version>_darwin_amd64
transteira-cli_<version>_darwin_arm64
transteira-cli_<version>_windows_amd64.exe
transteira-cli_<version>_windows_arm64.exe
SHA256SUMS
```

Download the binary and `SHA256SUMS` into the same folder, then check the binary against the
sums before running it.

```bash
# Linux: checks the files present in the folder, ignores the others.
sha256sum --check --ignore-missing SHA256SUMS
# macOS
shasum -a 256 --check --ignore-missing SHA256SUMS
chmod +x transteira-cli_*_linux_amd64
```

```powershell
# Windows PowerShell: compare the two values by eye or in a script.
(Get-FileHash .\transteira-cli_2.0.0_windows_amd64.exe -Algorithm SHA256).Hash
Select-String 'windows_amd64' .\SHA256SUMS
```

The checksums are published with the release, and `SHA256SUMS` is signed. Verify the
signature first, with the project public key `cosign.pub` (from the repository at the release
tag or from the release assets), then the binary against the sums:

```bash
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.sigstore.json SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

The release also carries the SBOM of the client, `transteira-cli_<version>_sbom.spdx.json`, with
its bundle `transteira-cli_<version>_sbom.spdx.json.sigstore.json`, verified the same way with
`cosign verify-blob`. Take `cosign.pub` from the project, not from the place where you
downloaded the binary, and compare `sha256sum cosign.pub` with the fingerprint line of
`README.md` and `SECURITY.md`. Verification needs cosign 3.0 or later.

The client never updates itself.

### From source

With Go installed:

```bash
make cli          # dist/cli/transteira-cli_<version>_<os>_<arch>[.exe] for the six platforms, and dist/cli/SHA256SUMS
```

The binaries are built with `CGO_ENABLED=0 -trimpath` and carry the version, commit and date
(`transteira-cli version`). For a single platform without `make`:
`CGO_ENABLED=0 go build -trimpath -o transteira-cli ./cmd/transteira-cli`.

## 2. Configuration

Each setting is resolved in this order: **command-line flags, then environment variables, then
the selected profile** of the configuration file.

| Setting | Flag | Environment variable | Profile member |
|---|---|---|---|
| Tenant URL (`https://host[:port]`, no path) | `--url` | `TT_URL` | `url` |
| File holding the API token | `--token-file` | `TT_TOKEN_FILE` | `tokenFile` |
| The API token itself | none | `TT_TOKEN` | `token` |
| Sender address | `--sender` | `TT_SENDER` | `sender` |
| Extra certificate authorities (PEM file) | `--ca-file` | `TT_CA_FILE` | `caFile` |
| Profile name | `--profile` | `TT_PROFILE` | none |
| Configuration file | `--config` | `TT_CLI_CONFIG` | none |

These are the same names as the scripts of the [integration guide](integration.md), so a
script can be replaced by the client without changing its environment. Set only one of
`TT_TOKEN` and `TT_TOKEN_FILE` (and only one of `token` and `tokenFile` in a profile).

### Configuration file

Default path: `transteira/config.json` in the user configuration directory of the system
(`os.UserConfigDir`):

| System | Path |
|---|---|
| Linux | `$XDG_CONFIG_HOME/transteira/config.json`, else `~/.config/transteira/config.json` |
| macOS | `~/Library/Application Support/transteira/config.json` |
| Windows | `%AppData%\transteira\config.json` |

The file is optional; `--config` or `TT_CLI_CONFIG` name another one (it must then exist). It
holds named profiles, one per entity for example:

```json
{
  "default": "entity-a",
  "profiles": {
    "entity-a": {
      "url": "https://transfer.entity-a.example.com",
      "tokenFile": "entity-a.token",
      "sender": "reports@entity-a.example.com"
    },
    "entity-b": {
      "url": "https://transfer.entity-b.example.com",
      "tokenFile": "/etc/transteira/entity-b.token",
      "sender": "reports@entity-b.example.com",
      "caFile": "/etc/ssl/corp-ca.pem"
    }
  }
}
```

A relative `tokenFile` or `caFile` is relative to the folder of the configuration file. The
profile is `--profile`, else `TT_PROFILE`, else `default`. Unknown members are refused.

### Keeping the token safe

- **The token is never taken from the command line.** There is no `--token` flag: an argument
  shows in the shell history and in the process list of every user. Use a token file or
  `TT_TOKEN`.
- On Linux and macOS, the configuration file and any token file are **refused when the group
  or others have a right on them** (as `ssh` does with its keys). Fix it with
  `chmod 600 <file>`. This check is not made on Windows, where the permission bits do not
  describe the access control list: keep the files in your profile folder and let only your
  account read them.
- The token is never printed, and it is redacted in the `--verbose` log.
- Prefer a token limited to its sender addresses (`allowedSenders`) and with an expiry date.

### Network

- **HTTPS only**, TLS 1.2 or later, certificate always verified. There is **no option to
  disable the verification**. The system certificate authorities are used; add a private one
  with `--ca-file` (`TT_CA_FILE`).
- `HTTPS_PROXY` / `NO_PROXY` are honoured.
- **Redirects are never followed**, and the `Authorization` header is only sent to the
  configured origin: a misconfigured or hostile redirection cannot receive the token.

## 3. Commands

```text
transteira-cli upload   [options] FILE|FOLDER...
transteira-cli download [options] LINK|-
transteira-cli proof verify FILE.pdf (--url URL | --keys-file FILE)
transteira-cli config check
transteira-cli config profiles
transteira-cli version
```

### upload

Deposits files and folders as one transfer, then waits until it is `available` (or `rejected`)
and prints the link.

| Option | Meaning |
|---|---|
| `--to` | Recipient address; repeat it or separate addresses with commas. |
| `--from` | Sender address; overrides `--sender`, `TT_SENDER` and the profile (required with an API token unless one of them sets it). |
| `--message`, `--message-file` | Message to the recipients (not both; the file is limited to 20,000 bytes). With `--e2e` the message is sealed too: prefer `--message-file`, since `--message` is visible in the process list and the shell history (a warning says so). |
| `--expiry 1\|7\|30` | Days of validity (7 by default). |
| `--delete-after-download` | Delete the transfer after its first download. |
| `--max-downloads N` | Maximum number of downloads. |
| `--verify-recipients` | Each recipient gets a personal link and confirms their address by code. |
| `--level KEY` | Confidentiality level of the entity. |
| `--link-only` | No mail is sent to the recipients; the link is printed for you to pass on. |
| `--e2e` | End-to-end encryption (see below). |
| `--key-out FILE` | With `--e2e`, write the key to a new file (mode 0600, created before anything is sent) instead of printing it. |
| `--password-file FILE`, `--password-prompt` | Transfer password, read from a file or asked without echo. |
| `--language` | Language of the mails. |
| `--chunk-size` | Bytes per `PATCH` request (100 MiB by default). |
| `--state-file` | Resume state file (see [section 5](#5-resuming-an-upload)). |
| `--restart` | Abandon the unfinished transfer of the state file and start again. |
| `--no-wait` | Return once the files are sent, without waiting for the antivirus verdict. |
| `--json` | Machine-readable output (see below). |

The connection options of [section 2](#2-configuration) (`--url`, `--token-file`, `--sender`,
`--profile`, `--config`, `--ca-file`) apply, as well as `--verbose`, which logs one line per
request (method, path without query, status, request identifier, duration) on the error
output, never a secret. Options may be given before or after the files; after `--`, every argument is a file name
(`transteira-cli upload --to a@example.org -- -weird.txt`). There is no `--token`.

A folder is walked with its tree (the relative path of each file is kept). Symbolic links are
skipped and reported. With `--e2e`, the tree is sealed in the encrypted metadata instead of
being sent in the clear.

The password has no flag with its value, for the same reason as the token. With
`--password-file`, the file must be readable by you only (it is refused otherwise on Linux and
macOS, like the token file) and one trailing line ending is removed. `--password-prompt` asks
twice, without echo, and needs a terminal.

On success, the standard output lists the transfer identifier, its status, the expiry and each
file (name, size, SHA-256, antivirus status), then the link of a `--link-only` transfer. A file
the antivirus did not analyze (`not_scanned_too_large`, `not_scanned_e2e`,
`not_scanned_disabled`) or that could not be analyzed (`scan_error`) is flagged by a warning on
the error output. While the files are sent, throttled progress lines are written to the error
output when it is a terminal.

`--json` prints one object: `transferId`, `status`, `expiresAt` (once available), `link`
(link-only), `key` (end-to-end, absent with `--key-out` or `--link-only`), `keyFile` (the path
given to `--key-out`) and `files` (`name`, `path`, `size`, `sha256`, `scanStatus`).

#### End-to-end encryption

With `--e2e` the client makes a new 256-bit key for the transfer and encrypts every file
before it leaves the machine; names, folders, types and the message are sealed too. The server
never holds the key and cannot read the files. This needs the entity policy (and the level) to
allow it: otherwise the server answers `403 e2e-forbidden`.

The link printed at the end does **not** contain the key. The key is printed once, alone, with
the reminder to send it to the recipients **through another channel** (telephone, another
messaging service); the mails TransTeira sends carry the link without the key. With
`--link-only` the full link with its `#k=` key is printed instead, since you pass it on
yourself. With `--key-out FILE`, the key goes to a new file with mode 0600 and is not printed;
the file is created (mode 0600, never overwriting an existing file) before anything is sent, so
the command refuses at once if it cannot be created, and removes the empty file if the upload
fails or is rejected. Only as a last resort, if the final write of the key fails after the
transfer was created, the key is printed on the standard output with a warning so it is not lost.

The client reads each file twice: once to compute the plaintext and ciphertext SHA-256 (the
server needs the ciphertext one at creation), once to encrypt while it sends. No file is
loaded in memory. See [section 12 of the integration guide](integration.md#12-end-to-end-encrypted-transfer-by-script)
and [`docs/architecture/e2e-format.md`](../architecture/e2e-format.md) for the format.

### download

Downloads the files of a link. `LINK` is the download link of the mail; `-` reads it from the
standard input.

| Option | Meaning |
|---|---|
| `--output DIR` | Folder to write into (current folder by default). |
| `--file NAME\|ID` | Download only this file (identifier, name or relative path); repeat for several. A name is not split at commas. |
| `--archive` | Download the server-built ZIP instead (refused for an end-to-end encrypted transfer). |
| `--force` | Overwrite existing files. |
| `--password-file FILE`, `--password-prompt` | Transfer password. Without `--password-file`, it is asked at the terminal when needed, so `--password-prompt` is optional. |
| `--key-file FILE` | End-to-end key (see below). |
| `--json` | Machine-readable output: `sender`, `message`, `expiresAt`, `endToEnd`, `archive` and `files` (`id`, `path`, `size`, `sha256`, `scanStatus`, `skipped`). |

The connection options `--url`, `--profile`, `--config`, `--ca-file` and `--verbose` apply too.
The server is the origin of the link, so `--url` is only needed for a bare `dl_...` token; no
token is needed and none is ever sent. A password file follows the same rules as for `upload`.

When the transfer requires the recipient to be verified, the client asks the server to send
the code, then asks you to type it at the terminal (a terminal is required: with a pipe or a
script the command fails and says so). The session cookies are kept in memory only. The same
holds for a password without `--password-file` and for an end-to-end key without `--key-file`.

For an end-to-end encrypted transfer the key comes from `--key-file`, else from the `#k=`
fragment of the link (the key file wins over a key in the link), else it is asked at the terminal
without echo. The files are decrypted on the fly
and the sealed names and folders are used (after the checks of [section 6](#6-downloads)); the
message of the sender is decrypted and shown.

**A link with `#k=` on the command line is visible in the list of processes of the machine.**
The client warns on the error output when it sees one. Pass the link on the standard input
with `-` instead, or give the bare key with `--key-file` and the link without its fragment.

### proof verify

Checks a signed proof of deposit or delivery (PDF), the same check as `transteira proof verify`
of the server binary, without needing the server:

```bash
transteira-cli proof verify proof.pdf --url https://transfer.entity-a.example.com
transteira-cli proof verify proof.pdf --keys-file keys.json   # offline: public keys saved earlier
```

### config check and config profiles

`config check` resolves the configuration as the other commands do (flags, environment,
profile; it takes the connection options of [section 2](#2-configuration)), validates it and
reports what it found without printing the token: profile, URL, configuration file, extra
certificate authorities, sender, and whether a token is set. It makes no request. A
configuration the other commands would refuse (bad URL, token or configuration file readable by
others...) fails with exit code 1. A missing token is not an error here (downloads need none).
`--json` prints the same as an object. `config profiles` lists the profiles of the
configuration file (name and URL; `--config` or `TT_CLI_CONFIG` chooses the file) and marks the
default one with `*`; `--json` is available.

### version

Prints the version, commit and date of the binary (`--json` for an object).

### help

`transteira-cli help`, `-h` and `--help` list the commands; `<command> -h` lists its options.

## 4. Examples

Create the token file once, restricted to you **before** the secret is written:

```bash
install -m 600 /dev/null ~/.config/transteira/entity-a.token
cat > ~/.config/transteira/entity-a.token     # paste the token, then Ctrl-D
```

```powershell
# The profile folder is private to your account; write the token without echo and without history.
$secure = Read-Host -AsSecureString 'API token'
[System.Net.NetworkCredential]::new('', $secure).Password | Set-Content -NoNewline "$env:APPDATA\transteira\entity-a.token"
```

### Upload a folder

```bash
export TT_URL=https://transfer.entity-a.example.com
export TT_TOKEN_FILE=~/.config/transteira/entity-a.token
export TT_SENDER=reports@entity-a.example.com

transteira-cli config check
transteira-cli upload --to alice@example.org,bob@example.org --expiry 7 \
  --message "Monthly reports" ./reports-2026-10
```

```powershell
$env:TT_URL = 'https://transfer.entity-a.example.com'
$env:TT_TOKEN_FILE = "$env:APPDATA\transteira\entity-a.token"
$env:TT_SENDER = 'reports@entity-a.example.com'

transteira-cli.exe config check
transteira-cli.exe upload --to alice@example.org,bob@example.org --expiry 7 `
  --message 'Monthly reports' .\reports-2026-10
```

With a profile in the configuration file, the three variables are not needed:
`transteira-cli upload --profile entity-b --to ... file.bin`.

### Link only, without mail

```bash
transteira-cli upload --link-only --to alice@example.org --password-file ./pw.txt big.iso
# prints the download link: pass it on yourself, and the password through another channel
```

### End-to-end encrypted, key delivered out of band

```bash
# Sender: the link goes by mail, the key goes into a file to read to the recipient by telephone.
transteira-cli upload --e2e --to alice@example.org --key-out ./transfer.key ./contracts
# stdout: https://transfer.entity-a.example.com/d/dl_...   (no key in it)
```

```powershell
transteira-cli.exe upload --e2e --to alice@example.org --key-out .\transfer.key .\contracts
```

### Download a link without the key in the process list

```bash
# The link (with #k= if the key came in it) is read from the standard input.
printf '%s' 'https://transfer.entity-a.example.com/d/dl_...#k=...' | transteira-cli download --output ./in -

# Or: link without the fragment on the command line, the key in a file.
transteira-cli download --key-file ./transfer.key --output ./in 'https://transfer.entity-a.example.com/d/dl_...'
```

```powershell
# Read the link without echo, then pipe it: it never appears in the argument list.
$link = Read-Host -AsSecureString 'Link'
[System.Net.NetworkCredential]::new('', $link).Password | transteira-cli.exe download --output .\in -

transteira-cli.exe download --key-file .\transfer.key --output .\in 'https://transfer.entity-a.example.com/d/dl_...'
```

### Password-protected transfer

```bash
transteira-cli upload --password-file ./pw.txt --to alice@example.org report.pdf
transteira-cli download --password-file ./pw.txt --output ./in 'https://transfer.entity-a.example.com/d/dl_...'
# or type it at the terminal: --password-prompt
```

### In a script

`--json` prints one JSON document on the standard output; the progress and the warnings go to
the error output. Branch on the [exit code](#7-exit-codes).

```bash
out=$(transteira-cli upload --json --to ops@example.org nightly.tar) || status=$?
case "${status:-0}" in
  0) echo "$out" ;;
  3) echo "rejected by the antivirus" >&2 ;;
  *) echo "deposit failed (status $status)" >&2 ;;
esac
```

## 5. Resuming an upload

A network cut inside a run is handled by the client: it asks the server for the durable offset
(`HEAD`) and goes on, with a growing pause, `Retry-After` honoured, up to 20 attempts, and no
retry on definitive answers (`401`, `403`, `4xx` problems), as described in
[section 5 of the integration guide](integration.md#5-errors-and-retries).

If the process itself stops (power cut, Ctrl-C, closed laptop), run **the same command** again:
the client reads its state file and resumes the same transfer without sending again what the
server already holds.

- The **state file** is `./.transteira-upload-<hash>.json` in the current folder, or the path
  given with `--state-file`. It is created with mode 0600 and deleted at the end of a successful
  upload. The hash covers the server URL, the sorted absolute paths and every option that shapes
  the transfer: recipients, sender, message, expiry, the deletion, verification and link-only
  flags, the maximum number of downloads, the level, the language, `--e2e` and whether a password
  is set (not its value). `--chunk-size` and the content of the password file may change between
  runs. Changing anything else starts a new transfer and leaves the old one on the server until
  it expires: cancel it by running `--restart` with the original command.
- The state file is **refused** when it is a symbolic link, readable by the group or others, or
  owned by another user (Linux and macOS). On Windows the mode 0600 means nothing: the file
  (which holds the E2E key) inherits the ACL of its folder, so keep it in a private folder.
- It holds the transfer identifier, the upload URLs, the idempotency key, and the size,
  modification date and SHA-256 of each file.
- **For an `--e2e` upload it also holds the transfer key and the per-file salts**, in the
  clear, until the upload ends. Anyone who can read that file while the upload is unfinished
  can decrypt the transfer. Do not copy, commit, back up or share it, and keep the folder
  private. It is deleted on success and when the upload is definitively abandoned; if you give
  up by hand, delete it yourself (it is the only copy of the key on disk).
- If a file changed since the first run (size, date or content), the client refuses to resume
  and says so, suggesting `--restart`. `--restart` cancels the unfinished transfer on the server (`DELETE`), removes
  the state and starts a new transfer.
- A wrong `--password-file` stops after a single attempt on a resumed transfer.
- Each block of an end-to-end upload is compared with its recorded digest before it is
  encrypted again, so a modified file can never be encrypted twice under the same nonce.

## 6. Downloads

- Each file is written to `.<name>.part` in the output folder, then renamed once complete.
  If the run stops, run it again: the `.part` file is resumed with an HTTP `Range` request.
- The **SHA-256 is checked before the rename**: the one shown by the server for a normal
  transfer, the one sealed in the metadata for an end-to-end transfer. On a mismatch the
  partial file is deleted and the client exits with an error: a corrupted file is never kept
  under its final name.
- **No file is overwritten** unless `--force` is given.
- Names and folders come from the server (or from the encrypted metadata, which the sender
  controls) and are never trusted: they are sanitised (no `..`, no absolute path, no control
  or hidden characters, names reserved by Windows such as `CON` or `NUL`, characters Windows
  refuses, duplicates) and the writing is **confined to the output folder** by the operating
  system (`os.Root`). A name that cannot be made safe becomes `file`. Existing symbolic links
  are not followed.
- Files and folders of an end-to-end transfer are written with mode 0600 and 0700. A link
  carrying a key whose transfer the server serves unencrypted is refused (integrity error): it
  may be a downgrade attack. In archive mode, the output says "listed" for digests that were
  not checked.
- For an end-to-end transfer, the ciphertext is decrypted on the fly into the `.part` file and
  never written to disk; any authentication error is fatal and removes the partial file.

## 7. Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Failure: network, server refusal, configuration, integrity error, file already exists. |
| 2 | Usage error: unknown flag or command, missing argument, invalid option value or combination. |
| 3 | The transfer was rejected by the antivirus (a virus was found; the files are deleted). Some files may also have been withheld. The result is still printed. |

Errors are printed on the error output as `transteira-cli: <message>`. Ctrl-C stops the command
with exit code 1 and keeps the state file (upload) or the `.part` files (download): run the same
command again to resume. The first Ctrl-C asks for a clean stop; a second one kills the process
immediately (the state is kept as of the last durable offset).

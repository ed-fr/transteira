# Command-line client

`transteira-cli` is a single, static binary (Linux, macOS, Windows; amd64 and arm64) that
deposits files into TransTeira, downloads a transfer link, shares a one-time text secret and
checks a proof of deposit or delivery, from a terminal or a script. It is a plain consumer of the
public API (`/api/v1`): it uses an [API token](integration.md#1-create-an-api-token), the
[tus](https://tus.io/protocols/resumable-upload) protocol, and resumes by itself after a
network cut, even between two runs. It also understands end-to-end encrypted transfers
(`TTE2` format), which the scripts of the [integration guide](integration.md) leave to you.

> The exact flags of each command are listed by `transteira-cli <command> -h` (for example
> `transteira-cli upload -h`). This guide describes the behaviour and the main options; if a
> flag name differs from the help of the binary you run, the help is right.

> **One-time secrets.** Since 2.3, `transteira-cli secret create` creates an **express secret**
> (a one-time text, encrypted on your machine, shared by a link) and `transteira-cli secret read`
> reads a secret link once: express secrets, and the secrets of 2.1 that have **neither
> passphrase nor file**. A secret with a passphrase or a file is refused before anything is
> consumed: open its link in a browser, or script it through the API (see
> [section 13 of the integration guide](integration.md#13-one-time-secrets-by-script)).
> `transteira-cli download` only accepts `/d/` download links, and points to `secret read` when
> it is given a `/s/` secret link.

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
(Get-FileHash .\transteira-cli_<version>_windows_amd64.exe -Algorithm SHA256).Hash
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
script can be replaced by the client without changing its environment. Two variables of the
express secret scripts have no counterpart: `TT_EXPIRES` and `TT_LINK_FILE` are not read by the
client. Use `--expires` for `secret create` and the `LINK` argument (or `-`) for `secret read`; a job that keeps
`TT_EXPIRES=1h` and switches to the client silently creates secrets of 1 day, which stay
exposed longer. Set only one of
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
transteira-cli secret create [options] [-] < TEXT
transteira-cli secret create [options] --file FILE
transteira-cli secret read [options] LINK|-
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

### secret create

Since 2.3. Creates an **express secret** (specification section 22.2): a text read **once**,
destroyed at the first reading or at its expiry, and shared by a link. The text is encrypted on
your machine; the server receives only the sealed text and two verifiers, never the text nor the
key ([`e2e-format.md`](../architecture/e2e-format.md), sections 3.3 and 3.3.9).

```text
transteira-cli secret create [options] [-] < TEXT
transteira-cli secret create [options] --file FILE
```

| Option | Meaning |
|---|---|
| `--file FILE` | Read the text from this file instead of the standard input. On Linux and macOS the file must be readable by you only (`chmod 600`), as the token and password files; it must be a regular file (for a pipe, use the standard input). |
| `--expires 1h\|1d\|7d` | Lifetime of the secret if nobody reads it, from its creation (`1d` by default). These three durations are fixed, whatever the durations the entity offers to the other secrets. |
| `--anonymous` | Send no API token, even when the configuration has one (not with `--token-file`). The token configuration (`TT_TOKEN`, `TT_TOKEN_FILE`, the `token` and `tokenFile` of the profile) is then neither read nor checked, so a broken or unused one does not make the command fail. |
| `--raw` | Send the input byte for byte: keep a leading byte order mark and the final line break (see below). |
| `--json` | Print one object instead of the link: `id`, `link`, `expiresAt`. |

The connection options `--url`, `--token-file`, `--profile`, `--config`, `--ca-file` and
`--verbose` of [section 2](#2-configuration) apply (there is no `--sender`: an express secret has
no creator address).

**The text.**

- **It is never taken from the command line** (threat T-406): an argument shows in the shell
  history and in the process list of every user. The command refuses any argument other than
  `-` (exit code 2) and reads the text from the standard input (`-`, the default), until its
  end, or from `--file`. When the standard
  input is a terminal, it says how to end the text: Ctrl-D on an empty line (Ctrl-Z then Enter on
  Windows); the text is then echoed on the screen as you type it.
- **One final line break is dropped** (`\n` or `\r\n`), and so is a **leading UTF-8 byte order
  mark**, nothing else: `echo`, a here-string and a file saved by an editor all end with a line
  break, which a browser user would not have typed, and Windows tools (`Set-Content -Encoding
  UTF8` of Windows PowerShell 5.1, some editors) start a UTF-8 file with a byte order mark, which
  would otherwise become an invisible first character of the secret (a password that no longer
  works once copied). Spaces, inner line breaks and a second final line break are kept. `--raw`
  sends the input byte for byte. **The example scripts of the integration guide
  ([section 14](integration.md#14-express-secrets-by-script)) never drop anything**, as with
  `--raw`: the same file then gives two secrets that differ by their final line break. Pass
  `--raw` when the text was prepared for the scripts, or when a script reads the secret and
  expects the file as is.
- It must hold **1 to 10 000 characters**, counted as **Unicode code points** of the text as
  given (after the two removals above; no normalization, line breaks count), the unit of the
  browser page, and be **valid UTF-8** (an encoded surrogate is invalid). An empty text, a longer
  text or invalid UTF-8 is refused before anything is sent (exit code 1).
- On **Windows PowerShell 5.1**, text piped to a program is converted with `$OutputEncoding`,
  ASCII by default, which turns every other character into `?`: set
  `$OutputEncoding = [System.Text.UTF8Encoding]::new($false)` first, or use `--file` with a file
  saved as UTF-8. PowerShell 7 pipes UTF-8.

**The token.** The API token is **optional**:

- **Without a token** (none configured, or `--anonymous`), the creation is **anonymous**. It is
  accepted only if the entity has enabled anonymous express secrets (off by default), within a
  limit per client IP address (10 per hour by default, set by the entity) and while the entity
  holds fewer unread express secrets than its ceiling (1 000 by default).
- **With a token** (from `--token-file`, `TT_TOKEN_FILE`, `TT_TOKEN` or the profile), the creation
  is attributed to the token and limited per token (100 per hour by default) instead of per IP;
  it is accepted even when the anonymous mode of the entity is off. **The token must be allowed
  to create express secrets** (`expressAllowed`, off by default, set by an admin of the entity on
  the token): otherwise the server refuses with `express-token-not-allowed`, and the client says
  so. A token is never downgraded to an anonymous creation: a refused token is an error; add
  `--anonymous` to create without it.
- An instance can disable express secrets altogether (`TT_EXPRESS_SECRETS_DISABLED`), with or
  without a token.

**What it does.** The client draws a new 256-bit key from the cryptographic generator of the
system **for every secret** (a retry never reuses a key), seals the text, checks that its own
sealed text opens again, then sends one request, `POST /api/v1/express-secrets`, **once**: it is
never repeated automatically, even after a network error or a rate limit (run the command again,
with a new key). The server answers the secret token; the client composes the link itself on the
host of the configured URL:

```text
https://transfer.entity-a.example.com/s/tts_<43 characters>#k=<43 characters>
```

**The output.** The **standard output receives the link alone**, followed by a line break (or,
with `--json`, the object `{"id": "sec_...", "link": "https://...#k=...", "expiresAt": "..."}`);
nothing else is ever written there. When the error output is a terminal, a reminder follows on
it (identifier, anonymous or with the token, expiry), without the link. The client never writes
the link anywhere else: no log, no file, no `--verbose` line (which shows the path
`/api/v1/express-secrets` only).

**Security notes.**

- **The full link is the secret.** Whoever has it reads the text, once. Send it through a private
  channel; do not paste it into a ticket, a log, a chat channel or a mail that other people or
  tools read. A script that captures the output must not write it into its own logs.
- A link pasted into a mail can be **consumed by a mail security gateway** that opens the links
  it sees: prefer an instant message, or a 2.1 secret with a passphrase sent by another channel.
- The recipient sees that the secret is an express secret, created by a third party the entity
  did not verify (or by an integration, with a token), and can report it.

### secret read

Since 2.3. Reads a secret link **once** and writes its text.

```text
transteira-cli secret read [options] LINK|-
```

`LINK` is the full link `https://<host>/s/<token>#k=<key>`; `-` reads it from the standard input
(the first line). A link without its `#k=` key is refused: the key is needed to read the text.
**A link on the command line is visible in the process list and the shell history**: the
client then warns on the error output; pass it with `-` instead.

| Option | Meaning |
|---|---|
| `--output FILE` | Write the text to this new file (mode 0600) instead of the standard output. |
| `--force` | With `--output`, replace an existing file (the new file is written next to it with mode 0600, then renamed over it). |

The connection options `--profile`, `--config`, `--ca-file` and `--verbose` apply; **the server is
the origin of the link** (`--url` is not used), and **no API token is ever sent**, and the token
configuration (`TT_TOKEN`, `TT_TOKEN_FILE`, the profile token) is neither read nor checked: a broken
one does not make the command fail. `--token-file` is not registered for this command (since 2.3:
passing it is a usage error, exit code 2). The requests
carry no `Origin` nor `Sec-Fetch-Site` header.

**What it does.**

1. With `--output`, the file is created first (never replacing one without `--force`), so that a
   secret is never consumed for a file that cannot be written.
2. It asks the status of the secret (`GET /api/v1/secret-links/{token}`), which **consumes
   nothing**. A secret with a **passphrase** or a **file** is refused here, without any reveal:
   open its link in a browser. A closed express service, an unknown link, or a secret already
   read, expired, deleted or locked are reported here too (see below). The status call is tried
   up to 3 times after a network error or a server error; a rate limit is reported, not waited
   for.
3. It reveals the secret (`POST /api/v1/secret-links/{token}/reveal`) with the two proofs derived
   from the key, **once**: this request is never repeated (the reveal is one-time). A wrong key is
   refused by the server before anything is consumed.
4. It decrypts the text with the key of the link and writes it.

**The output.** The **standard output receives the text alone, exactly as revealed** (no line
break added) when it is a pipe or a file. When it is a **terminal**, the text is shown followed by
a line break, and its control characters and bidirectional formatting characters are shown
escaped (`\x1b`, `\u202e`...), with a warning, so that a text written by a third party cannot
drive the terminal (escape sequences, carriage returns that overwrite a line) nor reorder what
is shown; use `--output FILE` or a redirection for the exact text. For an **express secret** a
note on the error output says that it was created anonymously by a third party the entity did
not verify (or by an integration with an API token), that the entity is not its author, and that
abuse can be reported by opening the link in a browser.

If the `--output` file cannot be written after the reveal, the text, which cannot be read again,
is written on the standard output as a last resort, with a message, and the exit code is 1.

### Secret messages and exit codes

Errors are printed on the error output; the exit code is 1 for a refusal or a failure, 2 for a
usage error (text given as an argument, invalid `--expires`, `--anonymous` with `--token-file`,
`--force` without `--output`, invalid link). Each message ends with the answer of the server in
parentheses (status, code and request identifier). The main cases:

| Command | Answer of the server | Message (start) |
|---|---|---|
| create | `403 express-secrets-disabled`, anonymous | `express secrets are not available: the entity does not accept anonymous express secrets (or the server instance disabled them); an API token allowed to create express secrets may still do it` |
| create | `403 express-secrets-disabled`, with a token | `express secrets are not available: the server instance disabled them` |
| create | `403 express-token-not-allowed` | `the API token is not allowed to create express secrets: an admin of the entity must allow express secrets on the token (expressAllowed), or create the secret without the token with --anonymous` |
| create | `401 invalid-credentials` | `the API token was refused: it is unknown, revoked, expired or of another entity; --anonymous creates the secret without it` |
| create | `403 ip-not-allowed` | `the API token was refused: it is not allowed from this IP address (allowed ranges of the token); --anonymous creates the secret without it` |
| create, read | `429 rate-limited` | `too many requests: try again in 20m0s` (the `Retry-After` delay; `try again later` without one) |
| create | `429 express-secret-limit-reached` | `too many express secrets are waiting to be read on this entity: try again later (they free up when they are read or expire), or use an API token allowed to create express secrets` |
| create | `404` (server older than 2.3) | `the server does not offer express secrets (TransTeira 2.3 or later is needed)` |
| create | `400 validation-failed`, `400 secret-format-invalid` | `the server refused the secret as malformed: the client and the server versions may not match` |
| read | `403 express-secrets-disabled` | `express secrets are not available: the entity closed the express secret service; nothing was consumed, and the link works again if the service reopens before the secret expires` |
| read | `404 not-found` | `no secret behind this link: check the link, or the secret ended long ago` |
| read | `410 secret-gone` | `the secret is no longer available: ` then `it was already read, and a secret is read once only: if you did not read it, someone else did, tell its sender`, `it expired before it was read`, `it was deleted by its creator or an admin of the entity` or `it was locked after too many wrong passphrases` |
| read | `403 secret-proof-invalid` | `the key of the link was refused: the link is incomplete or altered; nothing was consumed` |
| read | status with a passphrase or a file | `secret not supported by the command-line client: this secret is protected by a passphrase: open the link in a browser (nothing was consumed)` (or `this secret carries a file`) |
| read | text that does not open | `the secret could not be opened with the key of the link (...); the secret is consumed: ask its sender for a new one` |

A maintenance or a tenant still being configured (`503`) is reported with the answer of the
server. After Ctrl-C, `create` says that no link was printed (run it again: a new key is drawn)
and `read` that the secret is consumed if the reveal had reached the server.

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

### Share a secret once

```bash
# A new password, readable once within one hour; the link alone is printed.
openssl rand -base64 18 | transteira-cli secret create --expires 1h
# stdout: https://transfer.entity-a.example.com/s/tts_...#k=...

# A multi-line text from a private file, with the token of the profile (allowed for express secrets).
umask 077
cat > ./vpn-access.txt     # paste the text, then Ctrl-D
transteira-cli secret create --profile entity-a --file ./vpn-access.txt --expires 7d
rm ./vpn-access.txt

# Without the token of the profile (anonymous: the entity must have enabled it).
transteira-cli secret create --anonymous --url https://transfer.entity-a.example.com < ./note.txt

# Read a link received in a message: the link on the standard input, the text into a new
# private file (or on the standard output without --output).
printf '%s\n' "$LINK" | transteira-cli secret read --output ./received.txt -
```

```powershell
# The text is typed without echo and piped: it appears neither in the arguments nor in the history.
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)   # Windows PowerShell 5.1
$secure = Read-Host -AsSecureString 'Secret'
[System.Net.NetworkCredential]::new('', $secure).Password | transteira-cli.exe secret create --expires 1h

# Read: the link is typed without echo too.
$link = Read-Host -AsSecureString 'Link'
[System.Net.NetworkCredential]::new('', $link).Password | transteira-cli.exe secret read -
```

In a script, `--json` gives the identifier and the expiry with the link; keep the link out of
the logs of the script (it is the secret):

```bash
created=$(printf '%s' "$NEW_PASSWORD" | transteira-cli secret create --json --expires 1d) || exit 1
link=$(jq -r .link <<<"$created")       # hand it over through a private channel only
echo "secret $(jq -r .id <<<"$created") expires at $(jq -r .expiresAt <<<"$created")" >&2
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
| 1 | Failure: network, server refusal, configuration, integrity error, file already exists; for `secret`, an invalid text, a closed service, a secret already read, expired or not supported by the client (see [the secret messages](#secret-messages-and-exit-codes)). |
| 2 | Usage error: unknown flag or command, missing argument, invalid option value or combination (for `secret create`, a text given as an argument; for `secret read`, an invalid link). |
| 3 | The transfer was rejected by the antivirus (a virus was found; the files are deleted). Some files may also have been withheld. The result is still printed. |

Errors are printed on the error output as `transteira-cli: <message>`. Ctrl-C stops the command
with exit code 1 and keeps the state file (upload) or the `.part` files (download): run the same
command again to resume. The first Ctrl-C asks for a clean stop; a second one kills the process
immediately (the state is kept as of the last durable offset).

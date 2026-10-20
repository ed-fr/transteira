# Master key

TransTeira encrypts every stored file and every stored secret. All of this
encryption depends on one **master key**: you provide it to the container,
you keep a copy outside the VM, and you rotate it when needed. This page
covers the whole life cycle of the key.

- Variables: `TT_MASTER_KEY_FILE` (required) and `TT_MASTER_KEY_NEW_FILE`
  (only during a rotation), see `.env.example`.
- Command: `transteira rotate-master-key` (options `-batch-size`,
  `-abandon`, `-recover-from`).
- Implementation: `internal/crypto` (key format, envelope) and
  `internal/masterkey` (keyring, startup check, rotation).
- Threat model: T-35 to T-40, T-109, T-116 in `docs/security/threat-model.md`.

> **If the master key is lost, the data is lost.** Every file and every
> stored secret becomes unrecoverable, including in backups. There is no
> backdoor and no recovery key. Keep a copy in a password vault before you
> store anything (see [Vault copy](#vault-copy)).

## What the master key protects

TransTeira uses **envelope encryption**:

- each file is encrypted with its own random key (a *data encryption key*,
  DEK), in AES-256-GCM, chunk by chunk;
- stored secrets (SMTP passwords, and later the TOTP secrets of admins) are
  encrypted the same way;
- the DEKs and the secrets are **wrapped** (encrypted) by keys derived from
  the master key, and stored in the database (table `wrapped_keys`, one row
  per key, tagged with the ID of the master key that wraps it).

Consequences:

- The master key never touches file contents directly. A **rotation only
  re-wraps the rows of `wrapped_keys`**: files are never read or rewritten,
  whatever their size.
- Each wrapped key is bound to its tenant and its row: a wrapped key copied
  to another row or another entity cannot be decrypted.
- Without the master key, the database and the data volume are useless to an
  attacker, and to you.

## Generating a key

A key is **32 random bytes, encoded in standard base64** (44 characters).

Linux / macOS:

```sh
umask 077
openssl rand -base64 32 > transteira_master_key
```

Windows PowerShell (written as ASCII, without a byte order mark):

```powershell
$bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
[System.IO.File]::WriteAllText("$PWD\transteira_master_key",
  [Convert]::ToBase64String($bytes), [System.Text.Encoding]::ASCII)
```

File format rules, checked at startup:

- the content must decode (standard base64) to **exactly 32 bytes**;
- surrounding spaces and a trailing newline are tolerated;
- anything else (wrong length, URL-safe or invalid base64, a BOM, several
  keys, a degenerate key made of a single repeated byte) is **refused and
  the server does not start**.

Never generate a key from a passphrase, a hash of a word or an online tool.

## Providing the key to the container

Provide the key as a **Docker secret** (or any file mounted read-only), and
point `TT_MASTER_KEY_FILE` to it:

```yaml
services:
  transteira:
    environment:
      TT_MASTER_KEY_FILE: /run/secrets/transteira_master_key
    secrets:
      - transteira_master_key

secrets:
  transteira_master_key:
    file: /opt/secrets/transteira/transteira_master_key
```

Rules:

- **Outside the volumes.** The key must not live inside `TT_DATA_DIR`,
  `TT_BACKUP_DIR`, `TT_LOG_DIR` or the folder of the SQLite database:
  otherwise a VM backup would store the key next to the data it protects
  (T-116). Startup refuses such a path.
- **Never as an environment variable value.** The variable holds a *path*,
  not the key: environment values are visible through `docker inspect` and
  in process listings (T-35).
- **Never in git**, never in the image, never in a ticket or a chat.
- **Permissions**: on the host, make the file readable only by its owner
  (for example `chmod 600`, owned by root or by a dedicated account) and its
  folder not world-readable. With compose file secrets, the file is
  bind-mounted as is: it must be readable by the user the container runs as.
- TransTeira only reads the key; it never logs it or returns it through the
  API. Error messages only mention the key ID.

## Vault copy

Store a copy of every master key in a **password vault outside the VM**
(CLAUDE.md sections 16.1 and 23). It is required to restore: a VM backup
does not contain the key, by design.

For each key, record in the vault entry:

- the base64 content of the key;
- its **key ID** (see below), so you can match the entry with the key
  reported by TransTeira;
- the date it was put into service, and later the date it was retired.

## Key ID

Each key has an identifier: `mk_` followed by 16 hexadecimal characters
(for example `mk_3f9a0c41d27be865`). It is derived from the key itself
(HMAC-SHA256 of a fixed label, truncated to 64 bits):

- it is **not secret** and reveals nothing about the key: it can appear in
  logs, error messages and the vault entry title;
- the same key always gives the same ID, so no extra configuration is
  needed;
- every wrapped key in the database records the ID of the master key that
  wraps it, and the database keeps the list of master keys (`active` or
  `retired`) and of rotations.

TransTeira uses it for the startup check, for rotation progress, and in its
log messages. To find which vault entry matches a key mentioned in a
message, compare the IDs. The startup check and the `rotate-master-key`
command identify keys only by their ID.

## Startup check

TransTeira loads the key file(s) **before it opens the database**: a key
file that is missing, unreadable, malformed or located inside a volume
refuses the start before anything is read or written. Then, right after
the database migrations, it checks the keys against the database, in this
order:

| Situation | Result |
|---|---|
| Empty database (first start) | The current key is recorded as active. |
| No master key recorded yet, but rows wrapped with another key (keys mixed up) | **Start refused** (`missing_key`), nothing recorded. The message gives the key IDs the rows need. |
| A rotation to key B is **completed** but `TT_MASTER_KEY_FILE` still points to the old key A | **Start refused** (`rotation_completed`): set `TT_MASTER_KEY_FILE` to the new key file and remove `TT_MASTER_KEY_NEW_FILE`. |
| A rotation to key B is **running** but `TT_MASTER_KEY_NEW_FILE` holds another key C | **Start refused** (`rotation_mismatch`), naming B and C: put B back and finish the rotation, or abandon it (see [Abandoning a rotation](#abandoning-a-rotation): always possible for a clean-up rotation, and for a regular one while nothing is wrapped under B). |
| A rotation from the current key to B is **running**, keys are already wrapped under B, and `TT_MASTER_KEY_NEW_FILE` was removed | **Start refused** (`rotation_mismatch`): put back `TT_MASTER_KEY_NEW_FILE` and finish the rotation. |
| `TT_MASTER_KEY_FILE` holds a key recorded as **retired**, whatever the latest rotation | **Start refused** (`retired_key`): set `TT_MASTER_KEY_FILE` to the active key. |
| `TT_MASTER_KEY_NEW_FILE` holds a key recorded as **retired** | **Start refused** (`retired_key`): a retired key never wraps anything again; generate a new key. |
| Some rows are wrapped with a key that is **not provided** (wrong key file, restored backup, `TT_MASTER_KEY_NEW_FILE` removed too early) | **Start refused** (`missing_key`). The message gives the missing key ID. Provide the matching key from the vault. |
| Some rows are wrapped with a **retired** key (see [Recovering keys left under a retired key](#recovering-keys-left-under-a-retired-key)) | **Start refused** (`missing_key`); the message points to `rotate-master-key -recover-from`. |
| The **active** key recorded in the database is neither the current nor the new key | **Start refused** (`active_key_missing`), naming the active key. Provide it from the vault. |
| Every wrapped key uses a key that is provided | Normal start. |

Refusing to start is deliberate: starting with the wrong key would create
new data under one key while old data needs another, and could make files
unreadable without anyone noticing.

## Rotation

Rotate the master key when you suspect it leaked, when someone who had
access to it leaves, and at least once per backup retention period (see
[Crypto-erase](#crypto-erase)). The rotation re-wraps the keys stored in the
database; files are not touched, so it takes seconds to minutes even for
terabytes of data.

1. **Generate the new key** (see [Generating a key](#generating-a-key)) and
   store it in the vault right away, with its key ID.
2. **Declare it and restart.** Mount the new file as a second secret and set
   `TT_MASTER_KEY_NEW_FILE`, keeping `TT_MASTER_KEY_FILE` on the current key:

   ```yaml
   services:
     transteira:
       environment:
         TT_MASTER_KEY_FILE: /run/secrets/transteira_master_key
         TT_MASTER_KEY_NEW_FILE: /run/secrets/transteira_master_key_new
       secrets:
         - transteira_master_key
         - transteira_master_key_new

   secrets:
     transteira_master_key:
       file: /opt/secrets/transteira/transteira_master_key
     transteira_master_key_new:
       file: /opt/secrets/transteira/transteira_master_key_new
   ```

   ```sh
   docker compose up -d
   ```

   From now on, new keys are wrapped with the new master key; existing ones
   are still read with the old one. Restart **every** TransTeira process:
   one still running with the old key alone would keep wrapping keys under
   it.
3. **Run the rotation**:

   ```sh
   docker compose exec transteira transteira rotate-master-key
   ```

   - It is safe while the server is running: it works in small batches with
     short transactions (`-batch-size`, 500 by default), and every row stays
     readable with one key or the other at any time.
   - It prints its progress on the standard output, whatever
     `TT_LOG_LEVEL` is. If it is interrupted (connection lost, container
     restarted, Ctrl+C), **just run it again**: it resumes where it stopped.
   - When every row is re-wrapped, the new key becomes `active`, the old one
     `retired`, and the rotation `completed`. The database files are then
     scrubbed (see [Crypto-erase](#crypto-erase)).
4. **Switch the configuration and restart.** Point `TT_MASTER_KEY_FILE` to
   the new key file, remove `TT_MASTER_KEY_NEW_FILE` (and the old secret),
   then `docker compose up -d`. Until you do, the next start is refused (see
   [Startup check](#startup-check)).
5. **Update the vault**: mark the new key as current, and mark the old one
   as retired with the date of the rotation.
6. **Keep the old key** in the vault as long as you keep backups taken
   **before** the rotation: those backups hold keys wrapped with the old
   master key. When the last such backup has expired, **delete the old key**
   from the vault and from the host (see [Crypto-erase](#crypto-erase)).

Planned: the rotation will also be available from the super admin
interface, with a TOTP re-confirmation; it will run the same resumable
process. Steps 1, 2 and 4 to 6 stay manual, since they change the
deployment.

The rotation is recorded in the database (`key_rotations`) and in the
application log; it will also appear in the audit log once that log is
available.

**Effect of step 4 on users.** The master key also derives the MAC keys
that protect three values: the stored hashes of email verification codes
(valid 15 minutes), the CSRF tokens of deposit sessions (4 hours) and the
entries of the browser recognition cookie `__Host-tt_known` (up to 12
months). They always use the key named by `TT_MASTER_KEY_FILE` and are not
re-wrapped, so they stay valid during the rotation but stop verifying at the
restart of step 4: a user who was entering a code must request a new one, an
open deposit page must be reloaded (or the session reopened), and every
internal depositor is asked for a verification code once more on their next
visit. Switch at a quiet time; no data is lost.

### Abandoning a rotation

A running rotation can be given up when nothing depends on it:

- a **regular rotation** whose new key is lost or was a mistake, **before
  any key was wrapped under it**;
- a **clean-up rotation** (`-recover-from`, see below), always: its target
  is the active key, so nothing is lost. This unblocks an interrupted
  recovery whose old key has since been destroyed.

First **remove `TT_MASTER_KEY_NEW_FILE` and restart every TransTeira
process**, so that no process keeps wrapping keys under the new key, then:

```sh
docker compose exec transteira transteira rotate-master-key -abandon
```

The rotation is marked `failed`; the active key does not change, and a new
rotation can start. For a regular rotation the command refuses while keys
are already wrapped under the new key (keys created by the server since
step 2, or rows already re-wrapped): abandoning would leave them needing a
key the next rotation does not know. Put the new key back in
`TT_MASTER_KEY_NEW_FILE` and finish the rotation instead. The check and the
update are done in one transaction that blocks writes to the wrapped keys,
so no key can slip under the new key in between.

### Recovering keys left under a retired key

A key can end up wrapped under a retired master key after its rotation
completed: a TransTeira process that kept running with the old key alone
(not restarted in step 2), or a database restored from a backup taken
during the rotation. The database refuses new keys under a retired master
key, but rows written in a race or restored may remain. The startup check
then refuses the new key alone and names the retired key.

Re-wrap them under the active key with the old key from the vault. The old
key must **never be added to the server's configuration** (neither
`TT_MASTER_KEY_FILE`, nor `TT_MASTER_KEY_NEW_FILE`, nor a secret of the
server service): give it to a **one-off container** of the same image,
started with the server's configuration plus a temporary read-only bind
mount of the old key file, and removed afterwards:

```sh
# On the host, outside the data, backup and log directories: a temporary
# copy of the old key from the vault, readable by the container user.
install -m 600 /dev/null /opt/secrets/transteira/old.key
# ... write the base64 key into it ...

docker compose run --rm --no-deps \
  -v /opt/secrets/transteira/old.key:/run/old-key/old.key:ro \
  transteira rotate-master-key -recover-from /run/old-key/old.key

rm /opt/secrets/transteira/old.key
```

`docker compose run` starts a new container of the `transteira` service
with its environment, secrets, networks and volumes (the database), runs
the command and exits; `--rm` removes it. It works whether the server is
running or not.

- `TT_MASTER_KEY_FILE` must hold the **active** key.
- The old key file follows the location rules of `TT_MASTER_KEY_FILE`
  (outside the data, backup and log volumes and the SQLite folder). It is
  read **by this command only**.
- It runs a clean-up rotation from the retired key to the active key,
  resumable like a regular one; the master keys keep their status. If it is
  interrupted and the old key is no longer available, abandon it (see
  above).
- Afterwards, find out why keys were written under the retired key, and
  delete the temporary copy of the old key.

## Crypto-erase

When a transfer is deleted (expiry, manual deletion, data erasure request),
TransTeira **first destroys the wrapped key rows** of its files, then
deletes the files. A copy of a file that survives elsewhere can no longer be
decrypted **from the live system**. What this does and does not guarantee:

- **SQLite**: TransTeira enables `secure_delete`, which overwrites deleted
  content in the database pages, and runs a WAL checkpoint in `TRUNCATE`
  mode after each deletion (wrapped key, tenant) and at the end of a
  rotation, so that the WAL, which still holds pages written before the
  deletion, is emptied. When active readers prevent a complete checkpoint, a
  warning is logged and the next checkpoint completes it.
- **Filesystem and storage** (residual risk, both engines): truncating the
  WAL frees its blocks but does not overwrite them, and a copy-on-write
  filesystem (Btrfs, ZFS), SSD wear levelling, thin provisioning or VM and
  storage snapshots may keep old copies of database pages. TransTeira cannot
  reach them: rely on the rotation and on the destruction of old master
  keys described below.
- **PostgreSQL** (accepted residual risk): deleted rows remain on disk as
  dead tuples until `VACUUM` reclaims them (autovacuum does so eventually);
  they also remain in the WAL segments, in WAL archives if you keep them,
  and in every `pg_dump` file taken before the deletion. Run `VACUUM` if
  you need the space overwritten sooner, and give archives and dumps the
  same retention as backups.
- **Backups**: every backup taken while a transfer existed holds its
  encrypted files **and** its wrapped keys, and the **current** master key
  opens them (a rotation keeps the same data keys and re-wraps them).
  Deleting a transfer therefore protects the copies in existing backups
  **only after** a rotation **and** the destruction of the old master key,
  once every backup taken before that rotation has expired (threat model
  T-109).
- **Recommendation**: rotate the master key at least once per backup
  retention period (for example every 30 days for a 30-day retention), and
  destroy each old key as soon as the last backup that needs it has
  expired. A deleted transfer then stays recoverable from backups for at
  most about twice the retention.

## Backup and restore

Back up the master key **separately from the volumes** (the vault), never in
the same backup job.

A restore needs three things:

1. the database backup (the regular copy in `TT_BACKUP_DIR`, or a
   `pg_dump` with PostgreSQL);
2. the data volume (the encrypted files);
3. **the master key that was active when the backup was taken**. If a
   rotation happened since, that is the old key; a backup taken while a
   rotation was in progress needs both keys (old as `TT_MASTER_KEY_FILE`,
   new as `TT_MASTER_KEY_NEW_FILE`).

If you are not sure which key a backup needs, start TransTeira on it: the
startup check refuses and reports the missing key ID, which you match with
the vault. After restoring onto an old key, you may run a new rotation to
return to the current key.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Start refused: `TT_MASTER_KEY_FILE` is required | Variable not set | Set it to the path of the mounted key file. |
| Start refused: key file must not be located inside a volume | Key stored under `TT_DATA_DIR`, `TT_BACKUP_DIR`, `TT_LOG_DIR` or the SQLite folder | Move the key outside these folders (Docker secret under `/run/secrets`). |
| Start refused: invalid key / wrong length | File is not 32 bytes of standard base64 (BOM, URL-safe base64, truncated copy, passphrase, a single repeated byte) | Recreate the file from the vault copy, or generate a new key on a fresh install. |
| Start refused: key file cannot be read | Secret not mounted, wrong path, or file not readable by the container user | Check the `secrets:` section and the host file permissions. |
| Start refused: rows wrapped with a key that is not provided (`mk_...`) | Wrong key, restored backup from before a rotation, or `TT_MASTER_KEY_NEW_FILE` removed before the rotation completed | Find the key with that ID in the vault and provide it; if a rotation is unfinished, put back `TT_MASTER_KEY_NEW_FILE` and run the rotation. |
| Start refused: no master key is registered yet, but wrapped keys use `mk_...` | The current key is not the one that wrapped the existing rows | Start with the key that has that ID. Nothing was recorded. |
| Start refused: these keys are retired, run `rotate-master-key -recover-from` | Keys were wrapped under a retired key after its rotation | [Recover them](#recovering-keys-left-under-a-retired-key). |
| Start refused: rotation completed, switch to the new key | `TT_MASTER_KEY_FILE` still points to the old key | Rotation step 4. |
| Start refused: the rotation to `mk_B` is running, but `TT_MASTER_KEY_NEW_FILE` holds `mk_C` | The new key file was replaced during a rotation, or a clean-up rotation is unfinished | Put back key B and finish the rotation, or [abandon it](#abandoning-a-rotation) (a clean-up rotation always, a regular one if nothing is wrapped under B). |
| Start refused: the rotation is running and keys are wrapped under `mk_B`, but `TT_MASTER_KEY_NEW_FILE` is not set | The new key was removed before the rotation completed | Put back `TT_MASTER_KEY_NEW_FILE` and run `rotate-master-key`. |
| Start refused: `TT_MASTER_KEY_NEW_FILE` holds a retired key | An old key was reused for a new rotation | Generate a new key. |
| Start refused: the active master key is `mk_...`, which is not provided | Neither configured key is the active one | Provide the active key from the vault. |
| `TT_MASTER_KEY_NEW_FILE` must differ from `TT_MASTER_KEY_FILE` | Both variables point to the same file | Point the new variable to the new key file. |
| `rotate-master-key` refuses to run: no new master key configured | `TT_MASTER_KEY_NEW_FILE` not set in the running container | Rotation step 2 (set it and restart) before step 3. |
| Rotation interrupted | Connection lost, container restarted, Ctrl+C | Run the command again; it resumes. |
| Rotation failed: wrapped key `wk_...` cannot be unwrapped with master key `mk_...` | A corrupted row (disk fault, manual edit, row copied from elsewhere); the batch was rolled back and the rotation marked `failed` | Restore that row from a backup or, if what it protects is lost anyway, delete the transfer or setting that uses it; then run the command again (a new rotation starts). |
| Keys keep being created under the old master key | A TransTeira process still runs without `TT_MASTER_KEY_NEW_FILE` (not restarted in step 2) | Restart every process with both keys, then run the command again; it resumes. |
| The running rotation does not match the configured keys | A rotation between other keys is running (another new key, or a recovery) | Configure the keys it names to finish it, or `rotate-master-key -abandon` (a clean-up rotation always, a regular one if nothing is wrapped under its new key). |
| `-abandon` refuses: keys are already wrapped under its target key | A regular rotation whose new key the server or the rotation already used | Put the new key back in `TT_MASTER_KEY_NEW_FILE` and finish the rotation. |
| Start refused: `TT_MASTER_KEY_FILE` holds a retired key | An old key was put back as the current key | Set `TT_MASTER_KEY_FILE` to the active key. |
| `-recover-from` refuses: the key is not recorded as retired | The file is not an old key of this installation (or is the active one) | Use the old key whose ID the startup check reported. |
| `-recover-from` refuses: `TT_MASTER_KEY_FILE` is not the active key | The recovery always goes to the active key | Set `TT_MASTER_KEY_FILE` to the active key first. |
| Key lost, no vault copy | - | The stored files and secrets cannot be recovered. Start a fresh installation with a new key; re-enter the SMTP passwords. |

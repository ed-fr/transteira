# Proofs of deposit and delivery

Since 2.0, TransTeira can give a **proof** of two facts of a transfer: that the
files were deposited and made available, and that they were downloaded. A proof
is a PDF **signed by the instance**, which a sender, a delegated admin, the
super admin or an auditor can keep and, in a dispute, have verified offline by
anyone.

Français : [docs/operations/fr/proofs.md](fr/proofs.md).

- Commands: `transteira proof verify`, `transteira proof keys`,
  `transteira proof retire-key`.
- Operations: `getMyTransferProof`, `getTenantTransferProof`, `listProofKeys`
  (`api/openapi.yaml`, schema `ProofStatement`).
- Audit actions: `transfer.proof_downloaded`, `proof_key.created`,
  `proof_key.retired`.
- Threat model: T-298 to T-303 (section 6.49), decision P61 in
  `docs/security/threat-model.md`.
- Data model: [docs/architecture/data-model-v2.md](../architecture/data-model-v2.md), section 2.3.

## What a proof is

A proof PDF holds a readable copy of a **statement** and, as attached files:

- `statement.json`: the statement in canonical JSON (RFC 8785), the exact bytes
  that were signed (schema `ProofStatement`: entity, transfer, sender,
  recipients, files with their SHA-256 fingerprints, dates, key identifier);
- `statement.sig`: the Ed25519 signature (64 bytes) of those bytes.

**Only the attached signed statement is authoritative.** The visible text of the
PDF is a convenience: it can be edited with any PDF tool without invalidating
anything but the visible text, which is why verification never reads it. The
SHA-256 of the statement is also printed in the PDF.

Two kinds exist:

| Kind | Written | Says |
|---|---|---|
| Deposit | At the end of the antivirus analysis, in the same transaction that makes the transfer available | The sender deposited these files (with their antivirus status) for these recipients. |
| Delivery | At the first complete download of the transfer (overall), and, for per-recipient links, at each recipient's first complete download | The files were downloaded for the first time, and when (and by whom for a recipient proof). |

Proofs are **immutable**: one per fact, never updated. A transfer rejected by the
antivirus has no deposit proof. For an end-to-end encrypted transfer, the
fingerprints are those of the ciphertext and the statement says so.

Statements contain no IP address.

## Retention and erasure

- Kept **12 months after their creation**, **even if the transfer is deleted**
  (a proof must outlive the files it speaks about). Purged by the cleanup task.
- Erased by the **data-subject erasure** (Personal data screen) when the
  statement names the address as sender, recipient or downloader; the report
  counts them (`proofsDeleted`, and `proofs` in the search summary).
- Deleted with the entity.

## Who gets a proof

| Who | Where | Until |
|---|---|---|
| The sender | "My transfers", transfer details | While the transfer exists |
| Delegated admin, super admin, auditor | Administration, transfer details | 12 months, even after the transfer is deleted |

Recipients do not download proofs. Every download is recorded in the audit log
(`transfer.proof_downloaded`) and limited to **10 per minute per client address
(burst 20)**, where the address is a single IPv4 address or an IPv6 /64, shared by
the sender and administration proof endpoints and across entities; beyond, `429`. A proof that does not exist yet (no download, no
analysis result) or is past its retention answers `404 proof-not-available`
([errors](../api/errors.md)).

## Verifying a proof

Verification needs **no database and no access to the instance**: the PDF and
the public keys are enough. Use the `transteira` binary (the same as the
server's, from the image or a release).

1. Fetch the public keys of the instance. They are public, served on the FQDN of
   every entity and on the admin host, with the same list everywhere:

   ```bash
   curl -fsS https://transfer.example.com/api/v1/proof-keys > keys.json
   ```

   ```json
   {"items":[{"keyId":"psk_01JABCP1Q2R3S4T5V6W7X8Y9Z0","algorithm":"Ed25519",
     "publicKey":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
     "createdAt":"2026-11-04T09:00:00Z","retiredAt":null}]}
   ```

   Keep this file with the proof: it lets you verify later, even if the
   instance is gone. `/proof-keys` is answered even while an entity is still in
   setup (it holds no entity data).

1. Verify:

   ```bash
   transteira proof verify --keys keys.json proof-deposit.pdf
   # or, fetching the keys itself over HTTPS:
   transteira proof verify --url https://transfer.example.com proof-deposit.pdf
   # machine-readable result:
   transteira proof verify --json --keys keys.json proof-deposit.pdf
   ```

   Give exactly one of `--keys` and `--url`. The command checks the Ed25519
   signature of `statement.json` with the key named in the statement, then
   prints the fields **read from the verified statement** (never from the visible
   text of the PDF). Exit status 0 means verified. Any failure (altered
   statement, unknown key, malformed PDF) prints `FAILED` with the reason and
   exits non-zero.

   The text you see in a PDF viewer is **informative only**. Trust only the
   output of `transteira proof verify` (fields read from the verified
   statement) or its `--json` output. The command reads only the exact PDF
   structure TransTeira writes: a modified or incrementally updated PDF is
   rejected.

1. Compare what it printed (transfer, sender, recipients, files and
   fingerprints, dates) with the facts in dispute. To check a file you hold,
   compute its SHA-256 and compare it with the fingerprint in the statement.

A proof whose fact is **after** the retirement of its signing key is rejected:
see below.

## Signing keys

- One **active Ed25519 key** for the whole instance, created automatically when
  the first proof is written (audit `proof_key.created`). Its identifier starts
  with `psk_` and is signed in each statement.
- The **private part** is stored in the database, **sealed by the master key**
  like the other instance secrets: it is covered by the
  [master key rotation](master-key.md), never exported, logged or returned by
  the API. It is distinct from the key that signs the release image.
- The **public keys**, active and retired, are published at
  `https://<entity fqdn>/api/v1/proof-keys` (and on the admin host) and are
  **never removed**: they must verify old proofs.

List the keys held by the instance (needs the instance configuration, run it in
the container):

```bash
docker compose exec transteira transteira proof keys
```

### Retiring the key

There is no administration screen: retirement is a **deliberate command** on the
host.

When to retire:

- **Suspected compromise** of the database (or a backup) **together with the
  master key**: anyone holding both can sign proofs. Retire the key at once,
  then rotate the master key ([procedure](master-key.md)). Do both: retiring
  alone does not protect against old backups (see "What retirement does not
  do" below).
- **Periodic hygiene**, if your policy requires key rotation (for example
  yearly). Nothing breaks: older proofs keep verifying.

How:

```bash
docker compose exec transteira transteira proof retire-key        # asks for confirmation
docker compose exec transteira transteira proof retire-key --yes  # non-interactive
```

Effects:

- the **live sealed private part is destroyed** (cryptographic erasure): the
  instance can no longer sign with that key (backups made before the retirement
  still hold it, see below);
- the audit log records `proof_key.retired`;
- the **next proof creates a new active key** (`proof_key.created`);
- the retired **public key stays published**, with its `retiredAt` date, so
  that the proofs it signed still verify;
- `transteira proof verify` **rejects a statement whose fact is dated after
  the retirement** of its key. Statements for facts dated before the retirement
  stay valid.

#### What retirement does not do

Retirement does **not** stop backdated forgeries. All dates in a statement are
chosen by whoever signs it, and verification only compares the fact date with
the `retiredAt` of the key. Someone who obtained the database or a backup (the
nightly `VACUUM INTO` copy, a `pg_dump`) **and** the master key can unseal the
private key and sign statements dated **within the key's lifetime**: these
cannot be told apart from genuine ones by signature. Retirement deletes the
live sealed key, but every backup made before it still contains the key sealed
under the same master key, and a master key rotation does not change those old
backups. This is an accepted residual risk, of the same kind as the trust in the
operator (threat model T-299, H1), with no third-party timestamping (RFC 3161)
in 2.0.

After a suspected compromise:

1. **rotate the master key AND retire the proof key** (retiring alone is not
   enough, rotating alone is not enough);
2. destroy or secure the backups made before, since they still hold the key;
3. treat the proofs signed by the compromised key with caution, and cross-check
   them with the audit log and the mails sent to the sender and recipients.

#### Race at retirement

A signer prepared just before `transteira proof retire-key` commits can still
sign once with the retired key. A **delivery** proof written in that window
(its fact date is "now", after the retirement) fails verification and is kept
as an unverifiable immutable row; a **deposit** proof (fact date = end of the
deposit, before the retirement) verifies. This window lasts milliseconds and
the operation is manual: it is accepted. Retire during low activity, or in
maintenance mode (it refuses new deposits; downloads continue). The fact stays
in the audit log.

## Backup and restore

- The keys live in the **database**; the private part is unreadable without the
  **master key**. Restoring a database backup restores the keys and the proofs
  (restore the master key too: see [Backup](backup.md)).
- Proofs issued after the backup used are lost with it.
- If the database is lost with no backup, the public keys you saved with your
  proofs (`keys.json`) still verify them.
- Because the private key is destroyed at retirement, restoring a backup taken
  **before** a retirement brings the old key back as active: retire it again.

## When a proof cannot be written

"No fact without proof": a delivery proof is written in the same transaction
as the first-download record. If it cannot be written (key problem, master key
problem), the whole first-download transaction is **rolled back**, including the
"delete after first download" scheduling and the first-download notice. The
transfer stays downloadable until a later complete download succeeds. The error
is logged at **error level**: operators should alert on it.

## Limits

- A proof is worth the **trust placed in the instance operator**: whoever holds
  the database and the master key (threat model H1) can sign a statement. It
  proves what the instance recorded, not what a third party certified.
- There is **no third-party timestamping** (RFC 3161) in 2.0. Dates come from the
  instance clock.
- Visible PDF text is truncated for very long file lists ("see statement.json"):
  the attached statement always has everything.

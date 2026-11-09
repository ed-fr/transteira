# TTE2: end-to-end encryption format

> V2, step 7. Status: **reference specification**, implemented by `internal/tte2` (Go) and
> reproduced by the browser (TypeScript, step 8, section 7) and the command-line client (step 9).
> Test vectors: [`internal/tte2/testdata/vectors.json`](../../internal/tte2/testdata/vectors.json).
> Threat model: section 6.53 (T-318 to T-327, T-336), decision P66.
>
> **V2.1 (one-time secrets), step 1, since 2.1:** section 3.3 is the **proposed definitive format**
> of the secrets (design validated by human review on 2026-11-09; implemented at step 2 with shared test
> vectors). Threat model: sections 6.56 to 6.63 (T-339 to T-375), decisions P69 to P83, in
> particular P82 (this format).

TTE2 is the format of the optional end-to-end encryption of a transfer (specification section 22).
The sender's client encrypts every file, the metadata of every file (name, path, media type,
plaintext size and SHA-256) and the transfer message with a transfer key that the server never
receives. The server stores and serves the ciphertext as an ordinary file; it additionally applies
its own at-rest encryption (TTEF, `internal/crypto`) on top, unchanged.

All integers are unsigned and **big-endian**. `||` is concatenation, `u32(x)` is the 4-byte
big-endian encoding of `x`. Strings are ASCII byte strings without terminator.

## 1. Transfer key

- `K`: 32 bytes from a cryptographically secure generator (`crypto.getRandomValues` in the
  browser, `crypto/rand` in Go), **new for every transfer**.
- Carried in the **fragment** of the download link: `https://<fqdn>/d/<token>#k=<key>`, where
  `<key>` is `K` in base64url **without padding**: exactly **43 characters** of
  `A-Z a-z 0-9 - _`, canonical (the unused low bits of the last character are zero). Anything
  else is an invalid key (`ErrInvalidKey`). A browser never sends the fragment to the server
  (neither in requests nor in `Referer`).
- `K` itself is never used as a cipher key. Every object has its own key derived with
  **HKDF-SHA-256** (RFC 5869), output length 32 bytes:

| Object | HKDF secret | HKDF salt | HKDF info |
|---|---|---|---|
| File `i` | `K` | the 16-byte salt of the file header | `"transteira/tte2/v1/file" \|\| u32(i)` |
| Metadata of file `i` | `K` | none (empty) | `"transteira/tte2/v1/metadata" \|\| u32(i)` |
| Message | `K` | none (empty) | `"transteira/tte2/v1/message"` |
| Secret root key `K'` (V2.1, section 3.3) | `K` of the secret | `P` (32 bytes) with a passphrase; none (empty) without | `"transteira/tte2/v1/secret"` |
| Secret key proof (V2.1) | `K` of the secret | none (empty) | `"transteira/tte2/v1/secret/key-proof"` |
| Secret text (V2.1) | `K'` | none (empty) | `"transteira/tte2/v1/secret/text"` |
| Secret proof (V2.1) | `K'` | none (empty) | `"transteira/tte2/v1/secret/proof"` |
| File and metadata of a secret (V2.1) | `K'`, as the transfer key, index `0` | as for a file and its metadata | as for a file and its metadata (`i = 0`) |

`i` is the 0-based position of the file in the `files` array of `createTransfer`, in
`[0, 2^32 - 1]`. The index in the info binds a file and its metadata to their position, so the
server cannot swap two files; the random salt makes each file key unique even if a key were ever
reused (command-line client, V2.1 secrets). No key is shared by two objects.

A secret key `K` is **never** a transfer key and a transfer key is never a secret key: `K` of a
secret only feeds the two secret rows above, and `K'` plays the role of the transfer key for the
other rows. All the info strings are distinct and none is used with two different input keys of
the same kind, so every derived key is domain-separated (section 3.3.7).

All ciphers are **AES-256-GCM** with 12-byte nonces and 16-byte tags.

## 2. File stream

A file is encrypted into one stream: a 32-byte header followed by `n >= 1` chunks.

### 2.1 Header

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `"TTE2"` (`54 54 45 32`) |
| 4 | 1 | version | `0x01` |
| 5 | 1 | kind | `0x01` (file) |
| 6 | 2 | reserved | `00 00` |
| 8 | 4 | chunk size `C` | plaintext bytes per chunk, a power of two in [64 KiB, 8 MiB]; 1 MiB by default |
| 12 | 16 | salt | random, new for every file |
| 28 | 4 | reserved | `00 00 00 00` |

A header is valid only if **every** field has exactly the value above (any other magic, version,
kind, chunk size, or a non-zero reserved byte is `ErrBadHeader`). Other kinds and versions are
reserved for future formats.

### 2.2 Chunks

The file key is `HKDF(K, salt, "transteira/tte2/v1/file" || u32(i))`. Chunk `j` (counter from 0)
is

    AES-256-GCM(file key, nonce_j, plaintext_j, AAD = the whole 32-byte header)

with the STREAM nonce

    nonce_j = 00 00 00 00 00 00 00 || u32(j) || last

where `last` is `0x01` for the final chunk and `0x00` otherwise. Each chunk on the wire is its
ciphertext followed by its tag (`len(plaintext_j) + 16` bytes).

Every chunk holds exactly `C` plaintext bytes except the **final** one, which holds `r` bytes
with `1 <= r <= C`, or `r = 0` only when the file is empty (then it is the only chunk). There are
at most `2^32` chunks. A writer therefore keeps a full chunk until it knows whether more
plaintext follows: the final chunk may be full.

Binding the header in the AAD authenticates the chunk size and the salt; the counter detects
reordering, duplication and removal of chunks; the `last` flag detects truncation at a chunk
boundary and data appended after the final chunk; the index in the key derivation detects a file
presented at another position.

### 2.3 Sizes

For a plaintext of `P` bytes, `n = max(1, ceil(P / C))` and the stream size is

    S = 32 + P + 16 n  =  32 + (n - 1)(C + 16) + (r + 16)

Conversely a size `S` is valid for chunk size `C` if and only if, with `body = S - 32`,
`q = floor(body / (C + 16))` and `rem = body mod (C + 16)`:

- `rem = 0` and `q >= 1`: `n = q` and the final chunk is full (`P = q C`);
- `rem = 16` and `q = 0`: the empty file (`P = 0`, `S = 48`);
- `rem >= 17`: `n = q + 1` and `r = rem - 16` (`P = q C + r`);
- any other remainder (1 to 15, or 16 with `q >= 1`) is invalid; so is `n > 2^32` or `S < 48`.

The smallest valid stream is **48 bytes** (header and the empty final chunk). The Go functions
are `CiphertextSize`, `PlaintextSize` and `ValidSize`.

### 2.4 Decryption

A reader must never present unauthenticated plaintext as complete. The reference `Reader` reads
one byte ahead to know whether a chunk is the last, returns a chunk's plaintext only after its
tag has verified, and reports the end of the file only once the final chunk has verified and the
source is exhausted. Errors are classified in this order (every implementation must give the
same results on the vectors):

1. Fewer than 32 bytes: `ErrTruncated`. Invalid header: `ErrBadHeader`.
2. A chunk of `C + 16` bytes **followed by more data** is opened as a middle chunk (`last = 0`).
   At counter `2^32 - 1` it is `ErrCounterOverflow`. If it fails to open but opens as a final
   chunk (`last = 1`): `ErrTrailingData`; otherwise `ErrAuth`.
3. The chunk that **ends the input** is the final chunk. Fewer than 16 bytes: `ErrTruncated`.
   Exactly 16 bytes after at least one chunk: `ErrFormat` (an empty final chunk only exists for an
   empty file). If it fails to open as a final chunk, but has `C + 16` bytes and opens as a middle
   chunk: `ErrTruncated` (missing final chunk); otherwise `ErrAuth`.

`ErrAuth` covers a wrong key, a wrong file index, altered bytes (including the salt or the chunk
size in the header), reordered, duplicated or removed chunks, and data appended after a short
final chunk. A decryption failure is **fail closed**: the client discards (or flags) the partial
output; the browser and the command-line client never keep a partially decrypted file as if it
were complete.

Memory is bounded by one encrypted chunk plus one plaintext chunk (at most about 16 MiB with the
largest chunk size); buffers grow with the data actually received.

## 3. Sealed blobs: metadata and message

Metadata and the message use the same framing, a **sealed blob**:

    blob    = 0x01 || nonce (12 random bytes) || AES-256-GCM ciphertext || tag (16 bytes)
    on wire = base64url(blob) without padding

Decoding is strict: only the base64url alphabet (no padding, no whitespace or line breaks),
canonical (unused trailing bits zero), first byte `0x01`, at least 29 decoded bytes; otherwise
`ErrEncoding`. A tag failure is `ErrAuth`.

### 3.1 Metadata (`encryptedMetadata`, one per file)

- Key: `HKDF(K, no salt, "transteira/tte2/v1/metadata" || u32(i))`; AAD: `"TTE2M" || u32(i)`.
- At most **4096 decoded bytes** (5462 base64url characters), checked by the server on the
  string length and by clients before decoding.
- Plaintext: a UTF-8 JSON object

```json
{"v":1,"index":1,"count":3,"name":"Report.pdf","path":"projects/2026","type":"application/pdf","size":1234567,"sha256":"<64 lowercase hex>"}
```

| Field | Type | Rule |
|---|---|---|
| `v` | integer | `1` |
| `index` | integer | equal to `i` (the position the blob is opened for) |
| `count` | integer | number of files of the transfer, `>= 1` and `> index`; detects a file removed by the server |
| `name` | string | original file name, non-empty |
| `path` | string | optional relative folder path; omitted when empty |
| `type` | string | media type, may be empty |
| `size` | integer | plaintext size, `>= 0`; checked by the recipient after decryption |
| `sha256` | string | SHA-256 of the plaintext, 64 lowercase hex characters; checked by the recipient after decryption (T-323) |

Parsing is strict: a single JSON object, no unknown field (names are case-sensitive), no `null`
value, every field but `path` present, integers without fraction or exponent; otherwise
`ErrInvalidMetadata`. A repeated field keeps its last value (as with `JSON.parse`). The reference
writer emits the fields in the order above without HTML escaping; byte equality of the JSON is
not required between implementations (the vectors give the plaintext to seal).

`name` and `path` are **not sanitized** by this format: they are sender-controlled and the server
never sees them. Every client applies the server's file name and folder rules (T-52, T-226) after
decryption and renders them as text (T-324).

### 3.2 Message (`encryptedMessage`, optional, one per transfer)

- Key: `HKDF(K, no salt, "transteira/tte2/v1/message")`; AAD: `"TTE2T"`.
- Plaintext: the raw message text, valid UTF-8 of at most **5000 Unicode code points**
  (`ErrInvalidMessage` otherwise). The sealed string is at most **32768 characters**.
- A plain `message` is refused by the server for an end-to-end encrypted transfer.

### 3.3 V2.1 secrets

> Since 2.1. **Designed at step 1 of V2.1** (validated by human review on 2026-11-09); implemented at
> step 2 in `internal/tte2` and `web/src/shared/e2e/`, with the shared test vectors of section 6.
> Threat model: sections 6.56 to 6.63, decision P82.

A one-time secret (specification section 22.1) is a text and an optional small file, encrypted in
the creator's browser (or by an API client), stored by the server, and returned **once** to
whoever proves possession of the key (and of the passphrase, if any). The construction reuses the
primitives above: HKDF-SHA-256 of section 1, the sealed blob framing of this section and the file
stream of section 2. Nothing below changes the transfer formats.

**Rule: before a successful reveal, the server returns nothing sealed under `K'` or `K`.** No
answer given before the reveal commits (status call, failed reveal, error bodies) carries the
sealed text, the sealed file metadata, a verifier or any other value computed from `K'` or `K`;
the status call returns only the expiry, the public passphrase descriptor and the ciphertext size
of the file. The sealed text and the sealed file metadata are returned by the successful reveal
only, in the transaction that clears them (section 3.3.4). Any object sealed under `K'` is an
offline oracle for the passphrase to whoever holds `K` (section 3.3.7, point 7): returning one
before the reveal would let the holder of the link alone, without the passphrase, search for it
offline instead of being limited to 5 counted online attempts. A contract test checks that the
status schema has no sealed member.

#### 3.3.1 Link and key

- `K`: 32 bytes from a cryptographically secure generator, **new for every secret** (a client
  never reuses `K`, not even to retry a failed creation: a retry creates a new secret with a new
  `K`).
- Link: `https://<fqdn>/s/<token>#k=<key>`, where `<token>` is the secret token (`tts_` and 43
  base62 characters, about 256 bits, drawn by the server; it locates the secret and is stored as
  its SHA-256 only) and `<key>` is `K` encoded exactly as in section 1 (43 canonical base64url
  characters, `ErrInvalidKey` otherwise). The token and the key are two independent secrets: the
  token is sent to the server, the key never is (except for the email delivery of section
  3.3.6).
- `K` itself is never a cipher key; it only feeds the two derivations of 3.3.2 and 3.3.4.

#### 3.3.2 Passphrase and secret root key `K'`

An optional passphrase protects the secret against whoever obtains the whole link.

- **Passphrase rules (clients):** a non-empty string of Unicode scalar values (a JavaScript
  string with a lone surrogate is refused, as is invalid UTF-8 in Go), normalized to **NFC**, then
  encoded in UTF-8; at most **1024 bytes** after normalization; no trimming, no case folding.
  The empty passphrase is refused (`ErrInvalidPassphrase`): "no passphrase" is expressed by the
  absence of the passphrase descriptor, never by an empty string.
- **Descriptor** (public, chosen by the creator's client, stored by the server, returned by the
  status call): `{kdf: "pbkdf2-sha256", iterations: 600000, salt: <16 random bytes, base64url
  without padding, 22 canonical characters>}`.
- **Passphrase key:** `P = PBKDF2-HMAC-SHA-256(password = passphrase bytes, salt, c = 600 000,
  dkLen = 32)` (RFC 8018).
- **The iteration count is a constant of the format.** Clients refuse a descriptor whose `kdf` is
  not `pbkdf2-sha256`, whose `iterations` is not exactly `600000` or whose salt is not exactly 16
  bytes (`ErrInvalidPassphrase`), both when creating and when opening. A server (or anyone who
  alters the database) therefore cannot make a recipient derive a cheap passphrase verifier
  (section 3.3.7, point 7).
- **Secret root key:**

      K' = HKDF-SHA-256(IKM = K, salt = P, info = "transteira/tte2/v1/secret")   with a passphrase
      K' = HKDF-SHA-256(IKM = K, salt = empty, info = "transteira/tte2/v1/secret")   without

  32 bytes. `K'` is never a cipher key either: it is the input key of the derivations of 3.3.3 to
  3.3.5. HKDF-Extract is `HMAC(salt, IKM)`: it is a PRF in `K` (uniform, 256 bits) whatever the
  salt, and a PRF in `P` when `K` is known, so `K'` is out of reach of whoever lacks `K` and, for a
  passphrase secret, of whoever has `K` but not the passphrase (section 3.3.7).

#### 3.3.3 Text

- Key: `HKDF(K', no salt, "transteira/tte2/v1/secret/text")`; AAD: `"TTE2S"` (distinct from
  `"TTE2M" || u32(i)` and `"TTE2T"`).
- Framing: the sealed blob of section 3 (`0x01 || nonce || ciphertext || tag`, base64url without
  padding, strict decoding), with a fresh random 12-byte nonce. The text key seals exactly one
  plaintext in the life of `K`.
- Plaintext: the raw text, valid UTF-8 of **0 to 10 000 Unicode code points**
  (`ErrInvalidSecret` otherwise). An empty text is allowed only when the secret has a file (client
  rule, also checked by the server, section 4).
- Size bounds: at most 40 000 plaintext bytes (4 bytes per code point), so the blob is **29 to
  40 029 decoded bytes** (`1 + 12 + 40 000 + 16`) and the sealed string **39 to 53 372
  characters** (40 029 is a multiple of 3: exactly `4 x 13 343` characters, no partial group).
  The server checks the bounds on the string length; clients check them before decoding.

#### 3.3.4 Proofs of possession and verifiers

To reveal a secret, a client proves that it holds `K` and, for a passphrase secret, the
passphrase. Two proofs keep the two facts apart, so that whoever knows only the token (the path of
the link) can neither reveal nor lock a secret (section 3.3.7, point 6):

| Value | Definition | Who computes it, when |
|---|---|---|
| key proof | `HKDF(K, no salt, "transteira/tte2/v1/secret/key-proof")`, 32 bytes | creator at creation, recipient at reveal |
| key verifier | `SHA-256(key proof)` | creator, sent at creation; stored by the server |
| proof | `HKDF(K', no salt, "transteira/tte2/v1/secret/proof")`, 32 bytes | creator at creation, recipient at reveal |
| verifier | `SHA-256(proof)` | creator, sent at creation; stored by the server |

All four travel as **64 lowercase hexadecimal characters** (anything else is refused). At
creation the client sends the two verifiers, never a proof; at reveal it sends the two proofs. The
server compares `SHA-256(received key proof)` with the key verifier and `SHA-256(received proof)`
with the verifier, each **in constant time** (`crypto/subtle.ConstantTimeCompare` on the two
32-byte digests), always both, and then decides:

1. key verifier mismatch: the client does not have `K` (it may have the token alone): refused,
   security event `secret_proof_invalid` (reason `key`), **not counted** toward the lock, limited
   by the per-IP rate limit;
2. key verifier match, verifier mismatch: wrong passphrase (or a client bug): refused, counted;
   the 5th counted failure locks the secret (content destroyed), event `secret_proof_invalid`
   (reason `passphrase`);
3. both match: the reveal proceeds (atomic, single winner).

**Attempt slots.** The count must hold under concurrency: 50 parallel reveals with a right key
proof and a wrong passphrase must not all be compared before the first failure is recorded. With
a right key proof (checked first, never counted), the server therefore **claims an attempt slot
before comparing the proof**, in the reveal transaction:
`UPDATE secrets SET failed_proofs = failed_proofs + 1 WHERE id = ? AND state = 'active' AND
expires_at > ? AND failed_proofs < 5`. No row updated means that the secret is no longer active
or that its 5 slots are taken (`410 secret-gone` with the reason of its state). The claim holds
the row (PostgreSQL row lock, SQLite single writer) until the transaction ends, so concurrent
reveals of one secret are serialized and at most 5 proofs are ever compared. The proof is then
compared inside the transaction: a right proof reveals and **releases the slot as part of the
reveal** (`failed_proofs - 1`, state `read`, sealed text and sealed file metadata returned and
cleared); a wrong proof keeps the slot (counted failure), and the 5th sets the secret `locked`
in the same transaction. A rollback releases the slot. The data model
(`docs/architecture/data-model-v2.1.md`, section 2.1) gives the checks that allow the claimed
fifth slot only inside that transaction.

Without a passphrase, `K'` is a function of `K`, so case 2 only happens with a faulty or modified
client. A wrong passphrase is detected **by the proof**, before the recipient receives any
ciphertext: the server never sees a decryption error, and a correct proof means that the
recipient's `K'` equals the creator's, so the text opens. A creating client should open its own
sealed text with its `K'` before sending, so that a verifier never certifies a text it cannot
open.

#### 3.3.5 Optional file

- The file is an ordinary **TTE2 file stream** (section 2) with transfer key `K'` and file index
  `0`: file key `HKDF(K', header salt, "transteira/tte2/v1/file" || u32(0))`, random 16-byte salt,
  STREAM nonces. No new format, no new kind byte.
- Its metadata is a sealed blob of section 3.1 with key `K'`, index `0` and `count = 1`
  (`"TTE2M" || u32(0)`, at most 4096 decoded bytes); the recipient checks `index = 0`,
  `count = 1`, the size and the SHA-256 of the plaintext, and sanitizes the name (T-324). Being
  sealed under `K'`, it is returned by the successful reveal only, never by the status call
  (rule of section 3.3); the status call gives only the ciphertext size.
- Size: the ciphertext is at most the tenant's `fileMaxBytes` (1 MiB to 25 MiB, 10 MiB by
  default); the declared ciphertext size must be a valid stream size (section 2.3). A retried
  upload sends the **same bytes**; a client that encrypts again draws a new salt.
- The file is never scanned by the antivirus (the server cannot read it).

#### 3.3.6 Email delivery (exception: the server receives `K` once)

With delivery by email, the mail must carry the full link, key included (user decision of
2026-11-09). The server keeps only the SHA-256 of the secret token, so it cannot compose the link
alone: the creator's client sends **both halves of the link once**, in the body of the `send`
request (`secretToken` and `fragmentKey`), after the creation and the optional file upload. The
server:

- checks that `secretToken` has the token shape (`tts_` and 43 base62 characters) and that its
  SHA-256 equals the stored `token_hash` of that secret, compared in constant time (another
  token answers `404`, like an unknown secret or one of another creator; no security event: the
  caller is the authenticated creator and the token has 256 bits);
- checks only the encoding of `K` (section 1) and uses it as an **opaque string**: it derives
  nothing from it, never opens the sealed text or the file with it;
- composes the link exactly as in section 3.3.1, `https://<fqdn>/s/<token>#k=<key>`, where
  `<fqdn>` is the **registered FQDN** of the tenant (`id.SecretURL`), never the `Host` header
  received (threat model T-365, as the download and drop links);
- prepares the mail before activating the secret (no SMTP settings: `503 mail-unavailable`, the
  secret stays `pending`), then activates it and queues the mail;
- never stores the token nor `K` (no column, no file, no checkpoint), never logs them (request
  bodies, mail bodies and errors are never logged), never puts them in the audit (`secret.sent`
  carries the delivery and the domain of the recipient) or the security log; the mail exists
  in the in-memory mail queue only until it is sent or dropped;
- with a passphrase, still cannot read the secret (it lacks `P`); without a passphrase, a server
  that broke this rule could read it during the life of the secret. This is the accepted risk of
  the email delivery, stated in the threat model (T-362, T-363); the interface recommends a
  passphrase sent by another channel for this delivery.

The key also reaches the mail chain (entity SMTP or relay, recipient's mailbox, and mail security
gateways that rewrite links, which can send the whole URL, fragment included, to their provider).

#### 3.3.7 Security rationale

1. **Domain separation.** Every derived key has its own (input key, salt, info) triple: `K`
   feeds only `"…/secret"` (salt `P` or empty) and `"…/secret/key-proof"` (no salt); `K'` feeds
   `"…/secret/text"`, `"…/secret/proof"`, `"…/metadata" || u32(0)` and `"…/file" || u32(0)`
   (with the file salt). The info strings differ pairwise, HKDF-Expand produces one block
   (`HMAC(PRK, info || 0x01)`), so no two objects share a key; the AADs differ as well, so a blob
   moved from one field to another fails with `ErrAuth`.
2. **No key or nonce reuse.** `K` is new per secret; the text key and the metadata key each seal
   one plaintext, with a random nonce; the file key depends on a random salt and uses the STREAM
   nonces of section 2.
3. **The verifiers leak nothing usable.** A proof is a 256-bit HKDF output; its SHA-256 does not
   give it back (preimage resistance), and it is independent of the text and file keys (different
   info). Without `K`, the database gives nothing to test. The server learns the proofs only at the
   reveal, when they no longer protect anything; a proof does not give `K'` or `K` (HKDF is one-way).
4. **Constant-time comparison** of the digests of the received proofs (section 3.3.4); the responses do
   not depend on where two values differ.
5. **Wrong passphrase.** It yields a wrong proof (3.3.4, case 2): nothing is consumed, nothing is
   decrypted, the counter limits online guesses to 5.
6. **Token alone.** Whoever has only the token (proxy logs, history of the path, a link stripped
   of its fragment) cannot compute the key proof (256-bit `K`), so its failures are refused
   without counting: it can neither reveal nor lock a secret. Only a holder of the full link can
   lock a passphrase secret (accepted, threat model T-352). This is why the key proof exists: with
   a single proof (the first design), five random proofs from a token holder would have destroyed
   any secret.
7. **Offline brute force** of the passphrase needs `K` (the link) **and** one object computed from
   `K'`: any such object is an oracle for whoever has `K` (derive `K'` from a guess, then test
   it). The candidates are the stored verifier (in the database, in clear), the sealed text and
   the sealed file metadata (in the database under the server layer, so with the master key too,
   or in the reveal response), and the file. This is why the server returns **nothing sealed
   under `K'` before a successful reveal** (rule of section 3.3): with that rule, the link alone
   gives no oracle and a link holder is limited to the 5 counted online attempts; without it, a
   status call returning the sealed metadata would have let the link alone suffice. Each offline
   guess costs one PBKDF2 at 600 000 iterations, of the order of 10<sup>4</sup> guesses per
   second on a high-end GPU (an estimate). Indicatively, with the link and the database: one
   dictionary word falls in minutes, 8 random lowercase letters in months of GPU time, 4 random
   words of a 7 776-word list in thousands of GPU-years. Without `K`, nothing can be tested
   offline. The fixed iteration count stops a malicious server from obtaining a cheaper verifier
   from a recipient, and the server drops the verifiers and the salt with the content when the
   secret ends (tombstone), so that a database read **after** the end gives no oracle. **Backups
   are not covered:** a database backup taken while the secret was live keeps the sealed text,
   its wrapped server key, the verifiers and the salt; the cryptographic erasure at the reveal
   does not reach that copy. With such a backup (and the master key for the sealed text), an old
   link gives the text of a secret without passphrase and an offline oracle for one with a
   passphrase. The real protection of the text is `K`, then the passphrase: short durations and a
   passphrase sent by another channel (above all with the email delivery, which puts `K` in
   mailboxes) limit this residual risk (threat model T-351, T-355, P71).
8. **Empty passphrase versus none.** HKDF with an empty salt uses 32 zero bytes, and an HMAC key
   is zero-padded: "no passphrase" is `salt = 0^32`. A passphrase secret collides with it only if
   `P = 0^32`, probability 2<sup>-256</sup>; in any case `K` is new per secret, so two secrets never
   share an input key. The empty passphrase is refused anyway (3.3.2): it would give a public `P`
   and only the appearance of protection.
9. **Downgrades by the server.** Removing the passphrase descriptor, changing the salt or adding a
   descriptor only makes the recipient derive a wrong `K'`, hence a wrong proof: a denial of
   service, never a disclosure. A changed iteration count is refused (3.3.2).

#### 3.3.8 Go functions (step 2)

`DeriveSecretKey(K, passphrase, descriptor) -> K'` (NFC, rules of 3.3.2, empty descriptor for no
passphrase), `SecretKeyProof(K)`, `SecretProof(K')`, `SecretVerifier(proof) = SHA-256(proof)`,
`SealSecret(K', text)`, `OpenSecret(K', sealed)`, `CheckSecretFraming(sealed)` (keyless: strict
base64url, first byte, length bounds of 3.3.3). The file uses the existing `Writer` / `Reader`,
`SealMetadata` / `OpenMetadata` with `K'` and index 0. New error names: `ErrInvalidSecret`,
`ErrInvalidPassphrase`. Helpers: `PassphraseDescriptor` (zero value: no passphrase) with
`NewPassphraseDescriptor`, `EncodedSalt` and `DecodePassphraseSalt`; `EncodeProof` / `ParseProof`
(64 lowercase hexadecimal characters, `ErrInvalidSecret` otherwise); `VerifierMatches(verifier,
proof)` for the server (SHA-256, then `subtle.ConstantTimeCompare`); `SecretTextIsEmpty(sealed)`
for the keyless empty-text check of section 4.1. The browser (`web/src/shared/e2e/secret.ts`)
reproduces them with WebCrypto (`PBKDF2`, `HKDF`, `AES-GCM`, `SHA-256`).

## 4. What the server validates

The server holds no key. During the tus upload of a file of an end-to-end encrypted transfer, it
runs the keyless `tte2.Validator` on every received slice **before** writing it:

- the header, **each byte judged on arrival**: magic, version, kind, reserved bytes and the four
  chunk size bytes (a valid chunk size is `00 xx 00 00` with `xx` a power of two, 64 KiB to
  8 MiB), so a wrong byte is refused at once and never stored; a corrected stream may resume;
- as soon as the chunk size is known (byte 9), that the declared size (`createTransfer` size,
  equal to `Upload-Length`) is exactly a valid stream size for that chunk size (section 2.3);
- that no byte goes beyond the declared size.

A failing slice is refused (`400 e2e-format-invalid`) and nothing of it is written. The validator
keeps at most the first 32 bytes; its state (at most 49 bytes: version `0x01`, declared size and
offset as `u64`, header prefix) is stored in the upload checkpoint and strictly re-validated on
resume. At creation the server also requires `size >= 48`, the generic name `file-<n>.tte2`, an
`encryptedMetadata` per file and, when present, an `encryptedMessage`, within the size bounds
above.

What the server **cannot** check: the authenticity of the chunks, the metadata and the message
(it has no key), the declared plaintext SHA-256 (it computes and shows the SHA-256 **of the
ciphertext**), the file names. The recipient's client does these checks.

### 4.1 Secrets (since 2.1)

For a secret (section 3.3) the server holds no key either (apart from the opaque `K` of an email
delivery, section 3.3.6). Malformed values follow **one rule**: the request is first validated
against the OpenAPI schema, and any violation the schema expresses (pattern, enumeration, length,
bound) is `400 validation-failed` with field codes; `400 secret-format-invalid` is kept for the
keyless checks the schema cannot express. Nothing is stored in either case.

Schema level (`400 validation-failed`):

- at creation: an `encryptedText` outside 39 to 53 372 characters or with a character outside
  base64url; a `verifier` or `keyVerifier` that is not 64 lowercase hexadecimal characters; a
  passphrase descriptor other than `kdf = pbkdf2-sha256`, `iterations = 600000` and a salt of 22
  canonical base64url characters (16 bytes; the pattern fixes the last character); a declared
  file size below 48 bytes or above 25 MiB, or an `encryptedMetadata` outside 1 to 5462 base64url
  characters;
- at the email send: a key that is not 43 canonical base64url characters (the pattern fixes the
  last character, so it is exactly what `DecodeKey` accepts);
- at the reveal: a key proof or proof that is not 64 lowercase hexadecimal characters.

Keyless checks (`400 secret-format-invalid`):

- at creation: an `encryptedText` that fails `CheckSecretFraming` beyond the schema (canonical
  decoding, first byte `0x01`); a blob of exactly 29 decoded bytes (empty text) when no file is
  declared; a declared file whose `encryptedMetadata` fails `CheckMetadataFraming` (canonical
  decoding, version byte, room for the nonce and the tag). A declared size above the tenant's
  `fileMaxBytes` is `413 secret-file-too-large`;
- during the file upload (one request, raw body, no tus): a body that is not exactly the declared
  size, or that fails the keyless `tte2.Validator` of section 4 (header judged byte by byte, size
  valid for the chunk size); the partial file is deleted.

At the reveal it compares the digests of the two proofs with the two verifiers in constant time,
the key proof first, then the proof after claiming an attempt slot (section 3.3.4). Before a
successful reveal it returns nothing sealed under `K'` or `K` (section 3.3). What the server **cannot** check: that the text is valid UTF-8 within 10 000 code
points, the passphrase rules, the content of the file metadata, the authenticity of the file
chunks, and that the verifiers match the sealed text (the creator's client checks it).

## 5. Known limits

- **Forged header**: a modified client can send a valid header followed by arbitrary bytes of a
  valid size; it passes the server validation (residual of T-327). The server validation stops a
  plain file from being passed off as encrypted by an unmodified or careless client, not a
  determined one; content encrypted by other means is always possible, as for any file. The
  recipient's reader then fails with `ErrAuth`.
- **GCM is not key-committing**: a malicious sender could craft a ciphertext that decrypts under
  two different keys. No impact here: there is one key per transfer and the sender already
  controls the content.
- **Sizes leak**: the ciphertext size reveals the plaintext size (to 16 bytes per chunk), and
  the number of files, the times and the parties are visible to the server; there is no padding
  (accepted, T-321).
- **Served code**: the browser implementation is served by the server; end-to-end encryption
  protects against a passive operator and against reading storage and backups, not against an
  active one who modifies the served code (T-320). The signed command-line client is the
  alternative.
- **No antivirus**: encrypted files are never scanned (`not_scanned_e2e`, T-318).
- **Secrets (since 2.1)**: the length of a secret text leaks to the server to within the UTF-8
  encoding (no padding, as for messages; accepted, T-341); a passphrase protects against the
  holder of the full link only as much as its entropy allows once the database also leaks
  (section 3.3.7, point 7, T-351); the email delivery hands `K` to the server and to the mail
  chain (section 3.3.6, T-362, T-363); a secret file is never scanned (T-358); served code is
  trusted as for transfers (T-347).

## 6. Test vectors

`internal/tte2/testdata/vectors.json` is generated by
`go test ./internal/tte2 -run TestVectors -update` and verified by `TestVectors` on every run.
It contains, for the key given as `keyHex` and `keyFragment`:

- `files`: valid streams with `C = 64 KiB` (empty, 1 byte, exactly `C`, `C + 1`, three chunks),
  with their fixed salts: sealing the plaintext again with the salt must give the ciphertext byte
  for byte. The plaintext of a file vector is `plaintextLength` bytes where byte `k` is
  `k mod 251`;
- `fileNegative`: altered streams (reordered, duplicated or missing chunks, truncation, trailing
  data, wrong index, wrong key, flipped bits, bad header fields, empty final chunk after data),
  each built from parts (`{base, from, to}` slices of a file vector, `{hex}` literal bytes) with
  the expected error name;
- `sizes`: `ValidSize` / `PlaintextSize` cases;
- `validator`: inputs for the keyless validator with the declared size and the expected outcome,
  identical whether the input is checked in one go or byte by byte;
- `metadata`, `messages`: sealed blobs with their fixed nonces and plaintexts;
  `metadataNegative`, `messageNegative`: blobs that must fail with the given error.

**Secrets (step 2 of V2.1).** The vectors of section 3.3 are added at step 2 to the same file and
verified by the same test, in Go and in TypeScript: `secrets` (key, passphrase and descriptor, the
intermediate `P` and `K'`, key proof, proof, both verifiers, sealed text with a fixed nonce, and a
file with a fixed salt and its metadata), including a passphrase that changes under NFC and one
secret without passphrase; `secretNegative` (wrong passphrase, wrong key, other iteration count,
empty passphrase, text over 10 000 code points, blob moved from the metadata field, altered
bytes) with the expected error names.

Encodings: fields ending in `Hex` are lowercase hexadecimal, `ciphertextBase64` is standard
base64 with padding, sealed values are base64url without padding as on the wire. Error names are
the Go sentinel names (`ErrAuth`, `ErrTruncated`, `ErrTrailingData`, `ErrBadHeader`, `ErrFormat`,
`ErrEncoding`, `ErrInvalidMetadata`, `ErrInvalidMessage`, and since 2.1 `ErrInvalidSecret`,
`ErrInvalidPassphrase`); other implementations map their errors to these names.

## 7. Browser implementation (step 8)

The browser code lives in `web/src/shared/e2e/` (format and download), `web/src/e2e-sw/` (Service
Worker) and `web/src/public/deposit/` (deposit screens). It follows the vectors of section 6.

### 7.1 Deposit

1. **Preparation pass.** Before the upload, each file is read once to compute its plaintext
   SHA-256 (`sha256.ts`, pure TypeScript, about 100 MB/s or more: roughly 1.5 minutes per 10 GB).
   The hash must be known before the upload because it is sealed in the metadata.
2. **Key.** `K` is drawn with `crypto.getRandomValues`. The page imports it as a
   **non-extractable HKDF `CryptoKey`** and never hands the raw bytes to the encryption code.
3. **Encryption in a Web Worker** (`upload.worker.ts`, `upload-crypto*.ts`). The Worker receives
   the HKDF key, derives each file key from the file salt, and encrypts chunk by chunk while the
   tus engine uploads. Nothing is held in memory beyond a few chunks.
4. **Sealed values.** Names, folders, media types, sizes, plaintext SHA-256 and the message are
   sealed (`sealed.ts`) before `createTransfer`. The server only gets generic names.
5. **End of deposit.** The done screen shows the key once, to be sent by another channel. For a
   link-only transfer, it shows the full link ending with `#k=<key>`.

**Resume after a reload.** `K` and the per-file salts are kept in the `sessionStorage` of the tab
(record `tt.upload`, with the transfer identifier and the file descriptions). They are erased at
the end or at the abandon of the upload. Without them, a resumed upload could not produce the same
ciphertext. Decision of 2026-11-07. The record also holds the plaintext SHA-256 of each file:
after a reload, the reselected files are hashed again before anything is encrypted, and a file
whose fingerprint differs is refused (the transfer is abandoned). During the upload, each plaintext
chunk is compared with the SHA-256 of that chunk taken at the preparation pass before it is
encrypted (`file-changed` otherwise). A salt and its nonces therefore never encrypt two different
plaintexts, even when a file changes behind the browser. Residual: a script injected in the page could read them, but
it would read the plaintext files as well (threat model T-160, T-319, T-320).

### 7.2 Download

- **Key.** Read from the fragment `#k=` then removed from the URL (`history.replaceState`), or
  typed in a field (bare key or full link). It is kept in memory only.
- **Checks.** A wrong key is detected when no sealed item opens. A count or index mismatch in the
  sealed metadata means tampering (T-322).
- **Fingerprints.** The page shows the plaintext SHA-256 (declared by the sender, verified while
  downloading) and the ciphertext SHA-256 (computed by the server).

### 7.3 Service Worker protocol

Decryption is done in streaming by the Service Worker `/e2e-sw.js` (scope `/e2e/`). The shared
types are in `sw-protocol.ts`.

1. The page posts `register` over a `MessageChannel` with an entry: for each file, the
   same-origin ciphertext URL, the **non-extractable HKDF base key** (never the raw `K`), the file
   index, the sanitized name, the declared size and the declared plaintext SHA-256. An entry is
   either one file or an archive of several.
2. The Service Worker answers `registered` (or `rejected`). The page then navigates to
   `/e2e/<id>`, where `<id>` is 128 random bits in base64url (22 characters).
3. The Service Worker fetches the ciphertext, derives the file key once the 32-byte header has
   arrived, decrypts chunk by chunk, checks the size and the plaintext SHA-256 **while
   streaming**, and answers with `Content-Disposition: attachment`. On any mismatch it errors the
   stream, so the browser marks the download as failed.
4. For an archive, it builds the **ZIP in the browser** (store mode, ZIP64, names sanitized by
   `archive-names.ts`), file after file.
5. It reports `started`, then `done` or `failed` (with a code) to the page.

An entry is **single use** and valid for **60 seconds** (`ENTRY_TTL_MS`); at most 32 entries wait
at once; an entry dropped for age or room reports `failed` with the code `unavailable`. The
Service Worker only handles `/e2e/` requests; an unknown, used or expired identifier is answered
`204 No Content`, so that the download page stays in place. The page starts one download at a
time: the next one waits until the previous one has started or failed.

### 7.4 Fallback without Service Worker

Some private browsing modes forbid Service Workers. The page then decrypts in memory and saves a
`Blob`, up to **512 MiB** of plaintext (`MEMORY_LIMIT`). The ciphertext read is capped at the
largest valid size for the declared plaintext size, and it is decrypted chunk by chunk. A browser
without WebCrypto (for example a page served over plain HTTP) is told so, instead of a tamper
warning. Beyond that, it shows a message
suggesting another browser (the command-line client will cover this case at step 9).

### 7.5 Download limit counting

The server cannot build a ZIP of an encrypted transfer, so the browser downloads the files one by
one. To keep the "maximum number of downloads" meaningful, the files of an end-to-end encrypted
transfer count as **one download start per client within the window**
(`dedupObject` in `internal/download/started.go`): a browser ZIP counts once, not once per file.
This applies only to transfers with a download limit; without a limit every file start is recorded
and audited as before. The window of the counted client moves at the end of every response, so
that a long file does not push the next one outside it (up to the 4-hour ceiling). The start that
reaches the limit makes the transfer due for deletion after the longer of the grace period and that
ceiling, so that the files stay available until the counted client has fetched the last one; every
other client is refused at the limit meanwhile. Clients sharing one address on a shared link count
once for all the files (accepted, T-197).

### 7.6 Browser requirements

A modern browser with WebCrypto, Web Workers, Service Workers and streams.

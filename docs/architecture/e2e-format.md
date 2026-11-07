# TTE2: end-to-end encryption format

> V2, step 7. Status: **reference specification**, implemented by `internal/tte2` (Go) and
> reproduced by the browser (TypeScript, step 8, section 7) and the command-line client (step 9).
> Test vectors: [`internal/tte2/testdata/vectors.json`](../../internal/tte2/testdata/vectors.json).
> Threat model: section 6.53 (T-318 to T-327, T-336), decision P66.

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
| *Reserved (V2.1 secrets)* | `K` | none (empty) | `"transteira/tte2/v1/secret"` |

`i` is the 0-based position of the file in the `files` array of `createTransfer`, in
`[0, 2^32 - 1]`. The index in the info binds a file and its metadata to their position, so the
server cannot swap two files; the random salt makes each file key unique even if a key were ever
reused (command-line client, V2.1 secrets). No key is shared by two objects.

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

The one-time secrets of V2.1 will reuse the sealed blob construction with the reserved info
`"transteira/tte2/v1/secret"` and their own AAD label, and their own random key in the link
fragment.

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

Encodings: fields ending in `Hex` are lowercase hexadecimal, `ciphertextBase64` is standard
base64 with padding, sealed values are base64url without padding as on the wire. Error names are
the Go sentinel names (`ErrAuth`, `ErrTruncated`, `ErrTrailingData`, `ErrBadHeader`, `ErrFormat`,
`ErrEncoding`, `ErrInvalidMetadata`, `ErrInvalidMessage`); other implementations map their
errors to these names.

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

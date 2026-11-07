// Package upload deposits files on a TransTeira server for the
// command-line client (cmd/transteira-cli upload), through the API of
// docs/api/integration.md section 2, with the resume rules of its section 5
// and, optionally, end-to-end encryption (section 12 and
// docs/architecture/e2e-format.md).
//
// # Flow
//
// [Run] collects the files of [Options.Paths] (directories are walked,
// their tree kept in the path of each file; symbolic links and special
// files are skipped and reported through [Options.Warn]), then:
//
//  1. hash pass: the SHA-256 of each file is computed in a stream (and, for
//     an end-to-end encrypted transfer, the stream is sealed once to learn
//     the size and SHA-256 of the ciphertext, see below);
//  2. the state file is written, then createTransfer is sent with an
//     Idempotency-Key kept in that state;
//  3. each file is sent with tus PATCH requests of [Options.ChunkSize]
//     bytes streamed from the disk; after a cut, a 409 or a retryable
//     answer, HEAD gives the offset to resume from (pauses of
//     [client.Client.Pause], at most [client.DefaultMaxAttempts] attempts
//     without progress);
//  4. finalizeTransfer (a 409 upload-incomplete sends HEAD again and
//     completes the files, a 409 checksum-mismatch is fatal);
//  5. unless [Options.NoWait], getTransfer is polled every
//     [Options.PollInterval] until the transfer is available or rejected.
//
// Memory use is bounded by one end-to-end chunk and the I/O buffers,
// whatever the size of the files: nothing is ever read whole in memory.
//
// # State file
//
// The state file (by default ./.transteira-upload-<hex>.json, where <hex>
// is the SHA-256 of the server URL, the sorted absolute paths of
// [Options.Paths] and the options that shape the transfer) makes a deposit
// resumable across runs. It is written atomically, with mode 0600, and
// holds the idempotency key, the transfer identifier once known, the
// upload URL, size, modification time and SHA-256 of each file, the
// link-only download link once received, and, for an end-to-end encrypted
// transfer, the transfer key K, the header salt, the ciphertext size and
// SHA-256, the SHA-256 of every plaintext chunk and the sealed metadata of
// each file plus the sealed message. With K inside, the state file is as
// sensitive as the key itself: it must stay private (on Windows, where
// modes do not apply, in a private directory) and it is removed at the end.
// The transfer password is never written to it. Files whose name starts
// with ".transteira-upload-" are never collected.
//
// Running again with the same options and state file resumes the same
// transfer: a pending creation is sent again with the same key (the
// server returns the same transfer), a created transfer is read back
// (getTransfer) and each upload resumes after HEAD. A file whose size or
// modification time differs from the state gives [ErrStateMismatch]: the
// caller suggests [Options.Restart], which cancels the old transfer
// (cancelTransfer, 404, 409 and 410 ignored) and starts afresh.
//
// The state file is removed after a success, with [Options.NoWait] once
// the transfer is finalized, and after a definitive failure that leaves
// nothing to resume: a creation refused by the server (any non-retryable
// answer, 401 and 403 included: nothing was created), a transfer or upload
// gone (404, 410, or a status expired or deleted) and a rejected transfer
// ([ErrRejected], also returned when some files were withheld). Once the
// transfer exists, it is kept after any other failure: an interruption
// (end of the context, retries exhausted), an authentication or permission
// failure (401, 403, blocked-file), and an error that Restart resolves
// ([ErrStateMismatch], including a checksum-mismatch at finalization).
//
// # End-to-end encryption
//
// With [Options.E2E], a fresh transfer key K ([tte2.NewKey]) and one header
// per file ([tte2.NewHeader] with [tte2.DefaultChunkSize]) are drawn. The
// files are declared as file-1.tte2, file-2.tte2... with the ciphertext
// size ([tte2.CiphertextSize]) and, as expectedSha256, the SHA-256 of the
// ciphertext, computed by the hash pass, which seals every chunk once (the
// encryption is deterministic for a given K, header and plaintext). The
// name, folder, guessed media type, plaintext size and plaintext SHA-256
// go into the sealed metadata ([tte2.SealMetadata]); the message is sealed
// with [tte2.SealMessage] and the plaintext message left empty. A password
// is allowed. The ciphertext is produced again during the upload, from any
// offset: header bytes, then the chunk holding the offset ([tte2.ChunkAt])
// sealed again and sent from the right byte. Each plaintext chunk is
// compared with the SHA-256 recorded by the hash pass before it is sealed:
// a different chunk gives [ErrStateMismatch], so that one nonce never
// seals two different plaintexts (threat T-322). The caller shows
// [Result.Key] once and never logs it.
//
// # Secrets
//
// The key, the password and the API token are never printed, logged or
// passed to [Options.Warn] or [Options.Progress].
package upload

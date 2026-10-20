// Package upload is the tus 1.0.0 upload engine of TransTeira (CLAUDE.md
// §8.6, threat model T-21 to T-24, T-30, T-31 and T-123). It receives the
// bytes of each file of a transfer, encrypts them on the fly with
// internal/crypto, computes their SHA-256 and stores them through
// internal/storage, in constant memory and without a database write per
// chunk (§17).
//
// The package is HTTP-agnostic: the tus handlers (HEAD, PATCH, DELETE
// /api/v1/uploads/{uploadId}) parse the headers, authenticate the caller,
// build a [Principal] and map the errors of this package to HTTP statuses
// (see each error variable).
//
// # Authorization (T-21)
//
// Every operation loads the file by its upload identifier in the tenant
// scope and checks that the principal is the sender of its transfer: the
// same normalized address, the same depositor kind and, for an external
// sender, the same invitation. An unknown or malformed identifier, an
// upload of another tenant and a principal that is not the sender all
// return [ErrNotFound], so that they cannot be told apart.
//
// # Lock (T-24, T-30)
//
// Each upload is guarded by an exclusive in-process lock, keyed by the file
// identifier, taken with try-lock semantics: a concurrent request on the
// same upload gets [ErrBusy] immediately and never waits. The lock is what
// makes resuming safe (two writers resumed from the same checkpoint would
// encrypt different plaintexts under the same nonces), so TransTeira must
// run as a single application instance (CLAUDE.md §4 and §17). The file is
// read again from the database once the lock is held.
//
// # Durability
//
// Progress is kept on disk only, in a sealed checkpoint next to the
// encrypted file (crypto.Writer.Checkpoint, carrying the marshaled SHA-256
// state as its extra payload). A checkpoint is written every
// Options.CheckpointEvery bytes and at the end of every request, including
// when the client disconnects or the context is canceled, always in this
// order: checkpoint the writer, fsync the file, write the checkpoint
// atomically, then acknowledge. When the declared length is reached the
// writer is closed (final chunk), the file is synced, the completion is
// recorded in the database (the only database write of an upload besides
// its creation) and the checkpoint is removed.
//
// # Reset
//
// An upload is never truncated and resumed with the same key. When the
// checkpoint and the file disagree (crypto.ErrStaleCheckpoint after a crash
// between a data write and its checkpoint, a missing file, a file without
// checkpoint, an unreadable or unauthenticated checkpoint), the upload is
// reset: in one transaction a new data key is created, the file row points
// to it and to a new storage name, and the previous key is destroyed; then
// the previous files are removed and a new encrypted file with a checkpoint
// at offset 0 is created. The client sees offset 0 on its next HEAD.
// Transient I/O and database errors never trigger a reset.
//
// # Expiry (T-23)
//
// Uploads expire per transfer: the activity of a transfer is the latest of
// its creation, the completion of each of its files and the checkpoint time
// of each incomplete one ([Engine.TransferActivity]), so that a file not
// started yet stays open while its siblings are being uploaded one after
// the other. An incomplete upload expires Options.UploadTTL after the later
// of that activity and its own checkpoint, and at the latest Options.MaxAge
// (TT_UPLOAD_MAX_AGE, 7 days by default) after the creation of its
// transfer, whatever the activity: Status and Append then return
// [ErrExpired]. The purge is the job of the cleanup task.
//
// A PATCH that brings no byte writes no checkpoint and, for an upload not
// started yet, creates no file: it does not refresh the activity, so that
// empty requests cannot keep an upload (and its quota reservation) alive.
// A file whose offset already equals its length is still completed. The
// Upload-Expires of a PATCH is computed from the time of the checkpoint it
// just wrote, the clock HEAD reads.
//
// # Read timeouts (T-123)
//
// The engine reads the request body until the declared length; the HTTP
// layer bounds the idle time between two reads (for example by extending
// the connection read deadline on each read) and cancels the context or
// fails the body when it expires. The engine then saves the progress and
// returns [ErrInterrupted].
//
// # Deletion
//
// The data key is always destroyed before the files on disk (T-110): the
// key, and for a termination the file row, are deleted in one transaction,
// the files after the commit, then the database is scrubbed.
package upload

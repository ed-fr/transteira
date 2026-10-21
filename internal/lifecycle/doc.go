// Package lifecycle runs the periodic sweeps of TransTeira's data
// lifecycle (CLAUDE.md sections 16.1 and 20, threat model T-110, decision
// P23). For now it deletes the transfers whose DeleteAfter has passed: the
// transfers sent with "delete after the first download", once the grace
// period that follows their first complete download is over. The cleanup
// task of a later step extends it (expiry, verified addresses, invitations,
// journals).
//
// # Sweeps
//
// [Sweeper.Start] runs a sweep at once, then one every Options.Interval,
// until [Sweeper.Close]. [Sweeper.Sweep] runs one on demand; sweeps never
// overlap. A sweep lists the due transfers of every tenant
// ([store.Transfers.DueDeletions], the only system query of the package,
// which returns identifiers only), then erases each one in the scope of its
// tenant (CLAUDE.md section 5):
//
//  1. the data key of every file is destroyed in one transaction, then the
//     encrypted files are removed from disk ([Remover.RemoveFiles]), under
//     the upload locks of the files: cryptographic erasure comes first;
//  2. the state file of the byte ranges served for the transfer is removed
//     ([States.RemoveState]);
//  3. in one transaction, the sealed copy of the download token is
//     destroyed ([Vault.DestroyTx]), then the transfer becomes deleted
//     ([store.Transfers.MarkDeletedTx]). Its row and its token hash stay,
//     so that the link answers "gone" (410).
//
// The database is scrubbed once per sweep that deleted a transfer
// ([store.DB.ScrubDeleted]; [Remover.RemoveFiles] scrubs once more for the
// file keys); an incomplete checkpoint (store.ErrScrubBusy) is only a
// warning, the next scrub completes it.
//
// # Resumption
//
// Every step is idempotent, and only the last one takes the transfer out of
// the due list, so a failure or a crash at any step is completed by the next
// sweep: a destroyed file key is skipped, a missing file or state is not an
// error. A transfer that is no longer available or no longer due when it is
// read, or inside the final transaction, is skipped. A failure is logged and
// counted, and the sweep goes on with the next transfer. Logs hold
// identifiers and counts only, never an address, a name or a token.
//
// # Downloads in progress
//
// The download layer stops serving a transfer once its DeleteAfter has
// passed, and the sweeper only touches a transfer after that time, so a
// download that is still streaming during the grace period is never cut by
// design. A stream opened before DeleteAfter can however still be running
// when the transfer is deleted:
//
//   - a reader that opens the encrypted file again, or unwraps its data key
//     again, fails at its next chunk read: the file and the key are gone;
//   - a reader that keeps the file open, with its data key already
//     unwrapped, may finish the response: on Linux an open file survives its
//     removal (unlink), and so it does on Windows with the current Go
//     toolchain (files opened with shared delete access, removed with POSIX
//     semantics). The content is gone once the reader closes the file;
//   - where an open file cannot be removed (a Windows handle opened without
//     shared delete access, or an older file system), [Remover.RemoveFiles]
//     reports the error after destroying the keys: the transfer stays due
//     and the next sweep removes the file once the stream has closed it.
//
// A stream ending after the deletion may also write the state file again;
// such an orphan holds byte counts only and is left to the cleanup task.
package lifecycle

// Package lifecycle is the single periodic cleanup task of TransTeira
// (CLAUDE.md sections 16.1, 20 and 23; threat model T-23, T-108, T-109,
// T-110, T-114; decisions P5, P23 and P25). One [Sweeper] serves the whole
// instance and runs these tasks:
//
//	Task                    Interval          Action
//	delete-after-download   1 min             transfers deleted after their first download, once the grace period is over
//	expire                  1 min             available transfers past their expiry, transfers scanning for 30 days; files of rejected transfers
//	abandoned-uploads       15 min            uploading transfers whose uploads expired (upload TTL or maximum age)
//	purge-rows              1 h               ended transfers after 30 days, codes, sessions, password failures, verified addresses, invitations
//	orphans                 24 h              files of the tenant directories that the database proves orphaned
//	backup                  daily, UTC time   copy of a SQLite database (TT_BACKUP_TIME, TT_BACKUP_KEEP)
//
// # Scheduling
//
// [Sweeper.Start] runs every task but backup at once, in the order of the
// table, then each task again once its interval has elapsed since the end
// of its previous run; backup runs daily at Options.BackupTime UTC (never at
// start). Tasks never overlap: a run waits for the one in progress. The
// failure of a task is logged and never stops the others. [Sweeper.RunTask]
// runs one task on demand. [Sweeper.Close] cancels the runs in progress,
// which stop at their next step.
//
// [Sweeper.LastRun] keeps, for the supervision, the end of the last
// successful run of each task: a run that did everything it found due.
// A run that returns an error does not move it: a listing that failed, a
// run canceled by Close, and also a run that left work for the next one
// after a failure, which the erasure tasks report as "N transfer(s) left
// for the next run", purge-rows and orphans as the joined failures of
// their purges and tenants (a tenant that orphans skips for having too many
// rows is only logged), and backup as its error. A LastRun older than
// a few intervals of its task therefore means that some data due for
// deletion is still there.
//
// # Erasure
//
// delete-after-download, expire and abandoned-uploads share one erasure
// path. Each lists its due transfers with a system query of the store that
// returns identifiers only ([store.Transfers.DueDeletions],
// [store.Transfers.DueExpirations] then [store.Transfers.RejectedKeyed],
// [store.Transfers.AbandonedUploads]),
// then erases each transfer in the scope of its tenant (CLAUDE.md section
// 5), in the order of T-110. The listings are walked with a keyset cursor
// ([store.SweepPage]: due time, tenant, transfer): each page starts after
// the last transfer of the previous one while the pages are full, so a
// full page of transfers that stay listed (failing, or no longer due when
// read) never hides the transfers after it, whatever their tenant.
//
// expire erases the available transfers whose ExpiresAt passed, and the
// transfers still scanning store.ScanningMaxAge (30 days) after their
// finalization, a stuck analysis, each such erasure being logged as a
// warning. The provisional expiry of a scanning transfer is never
// enforced: its validity starts when it becomes available.
//
// Each transfer goes through these steps:
//
//  1. the transfer is read and found due (for abandoned-uploads, the upload
//     engine decides from the last upload activity), the upload locks of
//     its files are taken, and it is read and found due again under them,
//     so that no finalization, upload or cancellation runs meanwhile;
//  2. the data key of every file is destroyed in one transaction, then the
//     encrypted files and their checkpoints are removed from disk
//     ([Remover.RemoveFiles]): cryptographic erasure comes first;
//  3. the state file of the byte ranges served is removed;
//  4. in one transaction, the transfer is checked due once more, the sealed
//     copy of its download token is destroyed, and it becomes deleted
//     ([store.Transfers.MarkDeletedTx]) or expired
//     ([store.Transfers.MarkExpiredTx]), which releases its quota. Its row
//     and its token hash stay, so that the link answers "gone" (410).
//
// A rejected transfer listed by expire because a file kept its key (a file
// that could not be analyzed) only gets step 2 and stays rejected. A
// transfer that the antivirus made available between steps 2 and 4 (it was
// still scanning at its expiry) is expired anyway: its keys are gone.
//
// # Row purges
//
// purge-rows enumerates the tenants ([store.Tenants.IDs]) and, in the scope
// of each, deletes the rows of the transfers ended (rejected, expired or
// deleted) more than EndedRetention (30 days) ago, one transaction each
// ([store.Transfers.DeleteTx], refused while a key remains): their link
// then answers 404. Then it purges, in this order, the verification
// codes, the deposit sessions, the password failure counters, the verified
// addresses unused for 12 months and the inactive invitations, last
// because a transfer references its invitation without cascade.
//
// # Orphan files
//
// orphans compares the directory of every known tenant ([Files.List]) with
// the database ([store.TransferFiles.StorageRefs] and the available
// transfers) and removes, once older than OrphanGrace (24 hours, on their
// modification time): an encrypted file with no file row or whose data key
// is destroyed; a checkpoint with no file row, of a complete file or of a
// transfer no longer uploading; a download state of no available transfer;
// a temporary file left by a crash. When a file row refers to the entry,
// the upload lock of the file is taken and the row read again first.
// Unknown entries are counted and logged, never removed; the directory of
// an unknown tenant is logged, never touched; a tenant with more rows than
// store.MaxReconcileRows is skipped.
//
// # Backup
//
// With SQLite, backup first checks Options.BackupDir on every run: it is
// created with mode 0700 when missing, refused when it is a symbolic link
// or not a directory, and restricted to mode 0700 when its group or others
// can access it (Unix). It then creates an empty temporary file with mode
// 0600 (O_EXCL), which VACUUM INTO fills in place, so that the copy is
// never readable by others whatever the umask; checks it with PRAGMA
// quick_check, syncs it and renames it to transteira-YYYYMMDDTHHMMSSZ.db,
// then keeps the newest Options.BackupKeep copies (the one just written
// always among them, even after a clock step backwards) and removes the
// temporary files of an interrupted copy and their journal files. Close
// interrupts a copy in progress, whose temporary file is removed. With
// PostgreSQL the copies are made by a dedicated pg_dump container: the task
// is not scheduled and Start logs it once.
//
// A copy holds the wrapped data keys of the files present that night:
// after an erasure, the copies taken before it can still decrypt the files
// they cover, together with a file backup of the data volume, until they
// leave the rotation (at most BackupKeep days) or the master key is
// rotated, which makes their wrapped keys useless (P25). The copy itself
// contains no deleted row: VACUUM INTO copies the live pages only.
//
// # Resumption
//
// Every step is idempotent, and only the last one takes a transfer out of
// its due list, so a failure or a crash at any step is completed by the next
// run: a destroyed key is skipped, a missing file or state is not an error.
// A transfer no longer due when it is read, or inside the final
// transaction, is skipped. A failure is logged and counted, and the run
// goes on with the next transfer, purge, tenant or entry. The database is
// scrubbed ([store.DB.ScrubDeleted]) once per run that erased or purged
// something; an incomplete checkpoint (store.ErrScrubBusy) is only a
// warning, the next scrub completes it. Logs hold identifiers and counts
// only, never an address, a name or a token.
//
// # Downloads in progress
//
// The download layer stops serving a transfer once its DeleteAfter or its
// expiry has passed, and the sweeper only touches a transfer after that
// time, so a download is never cut by design. A stream opened before can
// however still be running when the transfer is erased:
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
//     and the next run removes the file once the stream has closed it.
//
// A stream ending after the erasure may also write the state file again;
// such an orphan holds byte counts only and orphans removes it.
package lifecycle

// Package storage keeps the encrypted file contents of TransTeira on the
// local file system (CLAUDE.md §3, §5 and §8.6). It never sees plaintext:
// callers write the output of internal/crypto through it.
//
// # Layout
//
//	<dataDir>/<tenantID>/<name>.ttef     encrypted file (TransTeira encrypted format)
//	<dataDir>/<tenantID>/<name>.ckpt     sealed resume checkpoint of an upload
//	<dataDir>/<tenantID>/<name>.dlstate  download state of a transfer
//
// A state file holds small bookkeeping of the download layer (the byte
// ranges served per file of a transfer, at most [MaxStateSize] bytes). It
// is named with [StateName], which hashes a server generated identifier
// (the transfer ID) into the storage name format. Each extension is its own
// namespace: removing a stored file never removes a state file of the same
// name, and the reverse.
//
// Tenant directories are created on demand with mode 0750 and files with
// mode 0640 (both subject to the process umask on Unix).
//
// # Path safety (threat model T-32, T-33)
//
// Paths are built only from validated, server generated identifiers, never
// from user input:
//
//   - the tenant identifier must be a well-formed "ten_" ULID
//     ([tenant.ID.Validate]);
//   - the storage name must be exactly 32 lowercase hexadecimal characters,
//     as produced by [NewName] (128 bits from crypto/rand), so that it can
//     neither be guessed nor reveal the original file name. State names
//     ([StateName]) have the same format; they derive from a transfer ID
//     and are not secret, which is harmless since they hold no file data.
//
// Any other value is refused with [ErrInvalid] before the file system is
// touched.
//
// As a second, independent layer, every file system operation goes through
// an [os.Root] opened on dataDir. os.Root resolves paths relative to the
// root and refuses, by construction, any path or symbolic link that would
// escape it (including a tenant directory replaced by a symlink pointing
// outside dataDir), on every platform. This was preferred to filepath.Rel
// plus Lstat checks, which are subject to time-of-check/time-of-use races.
// Symbolic links that stay inside dataDir are followed.
//
// # Errors
//
// Errors wrap [ErrInvalid], [ErrNotFound] or [ErrExists] when relevant.
// Their messages contain the operation and the random storage name, never
// an absolute path: path errors from the operating system are unwrapped to
// their underlying cause.
//
// # Durability
//
// Checkpoints and state files are written atomically: temporary file
// created with O_EXCL in the same directory, fsync, rename over the entry,
// then fsync of the directory so that the rename itself is durable. Windows does not support
// fsync on a directory handle; there the directory sync is a documented
// no-op (NTFS journals the rename metadata).
//
// On Windows, a file that is still open cannot be removed or replaced:
// callers close their handles before [Store.Remove]. A checkpoint may
// however be read (an unlocked tus HEAD) while the upload replaces it: on
// Windows only, [Store.WriteCheckpoint] retries a rename refused with
// ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION up to 5 times, 10 ms
// apart, before failing. [Store.CheckpointModTime] reads the time of a
// checkpoint without opening it.
package storage

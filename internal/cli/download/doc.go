// Package download fetches a TransTeira download link from the command line
// (transteira-cli download): the download page, the recipient verification,
// the password unlock, and the files, written into a target directory
// without ever escaping it (threat T-330).
//
// # Flow
//
// [Run] reads the page (getDownload). When the link is a per-recipient link
// awaiting verification, it asks for a code to be mailed
// (startRecipientVerification), reads it through [Options.Code] and confirms
// it; when the transfer has a password, it reads it through
// [Options.Password] and unlocks the link (unlockDownload). The grant
// cookies (__Host-tt_rv, __Host-tt_dl) only live in the in-memory jar of
// the [client.Client]. It then reads the page again for the file list and
// downloads each file, or the server ZIP archive with [Options.Archive].
//
// # Writing to disk
//
// Every path comes from [safepath.Entries] over the whole file list, and
// every write goes through a [safepath.Dir]: a file is first written to its
// ".name.part" temporary file, its SHA-256 is checked, and only then is it
// renamed to its final name. An existing target is refused before anything
// is downloaded unless [Options.Force] is set. A part file left by an
// interrupted run is resumed with an HTTP Range request (its bytes are
// hashed again first); a connection cut during a run is resumed the same
// way after a pause. A digest mismatch removes the part file and fails with
// [ErrIntegrity].
//
// # End-to-end encrypted transfers
//
// The transfer key comes from the "#k=" fragment of the link or from
// [Options.Key]; it is never sent to the server, written to disk, logged or
// returned in an error. The sealed metadata of every file is opened with
// it: when none opens the key is wrong ([ErrWrongKey]); when only some open,
// or their count and indexes disagree with the list served, the transfer
// was altered ([ErrIntegrity]). Names and folders come from the metadata,
// through [safepath.Entries]. The ciphertext is decrypted chunk by chunk on
// the fly: only plaintext reaches the disk, and the size and SHA-256 of the
// plaintext are compared with the metadata before the rename. A resumed
// download truncates the part file to a chunk boundary, reads the stream
// header again (Range bytes=0-31) and continues from that chunk. Any
// authentication failure removes the part file ([ErrIntegrity]). The server
// builds no archive for such a transfer: [Options.Archive] is refused.
package download

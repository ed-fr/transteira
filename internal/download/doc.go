// Package download is the recipient side of TransTeira (CLAUDE.md section
// 10, threat model T-47 to T-57, decisions P3, P4, P9 and P23): it resolves
// the download links, checks the transfer passwords, streams the files with
// Range support and the ZIP archive, and records the first complete
// download. It is independent of HTTP: the handlers map its errors to
// problems (see the errors) and serve its streams.
//
// # Access by token
//
// A download token ("dl_" + base62, 256 bits) is looked up by its SHA-256
// in the scope of the tenant of the request only. A malformed or unknown
// token, or one of another tenant, gives ErrNotFound (404). A known token
// whose transfer is not available (expired, deleted, rejected), past its
// expiry, past its deletion after the first download, or without any
// deliverable file gives ErrGone (410): the token proves the recipient got
// the link (P9). Only the files whose scan status is deliverable
// (store.ScanStatus.Deliverable) are listed and served; scan signatures
// and the other recipients are never exposed.
//
// # Password and download grant
//
// The transfer password is verified with argon2id (P3) through a hasher of
// bounded concurrency. Two counters, kept in the database, lock for 15
// minutes after 3 wrong passwords within any 15 minutes (a sliding window;
// P4, T-48): the transfer, from any IP, and the client IP (an IPv6 client
// by its /64), on any transfer of the tenant. Each attempt is counted
// against both before the password is verified, in the transaction that
// checks the locks, so that concurrent attempts can never have more
// passwords verified than the limit allows, and a locked client costs no
// hashing. A right password clears the transfer counter and refunds the
// attempt on the client counter only: the client keeps its earlier
// failures on other transfers. An attempt whose password could not be
// verified (request canceled, no hashing slot) is refunded on both
// counters. Wrong
// passwords are written to the security log (transfer_password_invalid,
// with a truncated transfer ID), refusals on a lock as rate_limited
// (scope transfer_password).
//
// A right password adds a grant to the stateless GrantCookieName cookie:
// GrantCookiePrefix, then at most GrantMaxEntries entries separated by
// dots, each the unpadded base64url of an expiry (8 bytes, big-endian Unix
// seconds, GrantTTL after the unlock) followed by the HMAC (MAC purpose
// download-grant) of the tenant ID, the transfer ID and that expiry. The
// cookie holds no clear data; an entry is worthless for another tenant,
// another transfer, past its expiry, or after a master key rotation.
// Expired entries and older entries of the same transfer are dropped when a
// grant is added; a value longer than MaxGrantCookieLen is ignored.
//
// # Files and served ranges
//
// [Service.OpenFile] gives a [Content]: the stored file decrypted chunk by
// chunk (crypto.ReaderAt, one chunk in memory) behind an io.ReadSeeker that
// http.ServeContent uses to answer Range requests. The Content records the
// byte ranges actually read; when it is closed, they are merged, under an
// in-process lock of the transfer, into the union of the served ranges of
// each file, kept in the state file storage.StateName(transferID) and
// written at most once per request, never per chunk nor in the database.
// The last read of a response is credited only when the HTTP layer reports
// it as delivered (a GET answered 200 or 206, written without error), so
// that a broken response never counts bytes the client did not get. An
// empty file counts as served once such a GET was delivered. The state is
// bounded by storage.MaxStateSize: when it would not fit, the smallest
// ranges are forgotten, which can only delay the completion.
//
// The state writes are coalesced: a state is written when the bytes newly
// served since its last write reach 1 MiB, when a file or the transfer
// becomes complete, or when it holds too many ranges; otherwise it stays
// in memory until a qualifying request, until it has been idle for a
// minute, until it is among the oldest beyond a bounded number of
// transfers (it is then written and evicted), or until Close. A state that
// cannot be written (database or disk failure) stays in memory for a later
// attempt, within the same bound. Close flushes the states in memory on a
// best effort basis: when its context ends first, the states left are
// dropped and counted in one warning. A crash or such a drop loses the
// ranges kept in memory, which only delays the completion. A state is
// never written for a transfer that is no longer available: a response
// ending after the deletion resurrects nothing.
//
// # Concurrent streams
//
// Each file or archive response holds, until it ends, a slot of its
// transfer (MaxStreamsPerTransfer, all clients), of its client on that
// transfer (MaxStreamsPerTransferClient, so that one client cannot take
// every slot of a transfer) and of its client (MaxStreamsPerClient, all
// transfers of the tenant); a client is an IPv4 address or an IPv6 /64.
// Beyond any of them, the request is refused with a *TooManyStreamsError
// (ErrTooManyStreams, T-55) and a rate_limited security event is written
// (scope download_streams, with the truncated transfer ID), at most one per
// client of the tenant per StreamEventInterval. The counters are in
// process, TransTeira running as a single instance.
//
// # First download
//
// The transfer counts as downloaded once every byte of every deliverable
// file has been served at least once, across requests, or once its archive
// was written to its end ([Archive.Write]; a partial archive never counts).
// The first download is then recorded by one conditional update
// (store.Transfers.MarkFirstDownloadTx), so that exactly one request
// records it even when several complete at once; that request alone sends
// the first_download mail to the sender, with the deletion time when there
// is one, through a mail.Retrier (retried while the mail queue is full or
// the tenant's circuit is open). With the "delete after the first
// download" option the transfer becomes due for deletion Options.Grace
// later (TT_DELETE_AFTER_DOWNLOAD_GRACE), so that an interrupted last range
// can resume; the lifecycle sweeper erases it, and the link then answers
// ErrGone. The range state is removed once the first download is recorded;
// whoever deletes a transfer removes its state file too.
//
// # Download starts and usage
//
// A download start is a GET of a file read from offset 0 (whole file, or a
// range starting at 0; an empty file once delivered) or a written archive;
// never a HEAD request nor a resumed range. Each start records, in one
// tenant-scoped transaction, the transfer.downloaded audit event (actor
// kind recipient, actor "link", object the transfer, details the file ID
// or "archive") and one more store.Transfer.DownloadCount, before the first
// byte, bounded by a short timeout. Serving never depends on that
// recording: a failure is logged and the download goes on unrecorded. The
// starts and the plaintext bytes actually served (counted like the served
// ranges) also go to Deps.Usage, for the tenant statistics.
//
// A start is recorded (audit event, download count and usage start) at most
// once per tenant, transfer, object and client (IPv4 address or IPv6 /64)
// within Options.StartWindow, one hour by default, so that a client looping
// on the first byte cannot flood the append-only audit log. The record is
// kept in a bounded in-memory map (Options.MaxStarts entries, the oldest
// dropped first) that a restart forgets. Since a client holding many keys
// (the /64s of an IPv6 /48) could evict every entry, at most
// Options.MaxStartsPerTransfer starts of one transfer (1000 by default) are
// recorded per window opened at its first one, whatever the clients, in a
// separate bounded map that such cycling cannot reset. Served bytes stay
// exact.
//
// # Logs
//
// Logs hold tenant, transfer and file identifiers only: never a token, a
// password, an address or a file name.
package download

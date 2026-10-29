// Package download is the recipient side of TransTeira (CLAUDE.md section
// 10, threat model T-47 to T-57, T-197 and T-199 to T-206, decisions P3,
// P4, P9, P23, P27 and P38):
// it resolves the download links, checks the transfer passwords, streams
// the files with Range support and the ZIP archive, and records the first
// complete download. It is independent of HTTP: the handlers map its
// errors to problems (see the errors) and serve its streams.
//
// # Access by token
//
// A download token ("dl_" + base62, 256 bits) is looked up by its SHA-256
// in the scope of the tenant of the request only. A malformed or unknown
// token, or one of another tenant, gives ErrNotFound (404). A known token
// whose transfer is not available (expired, deleted, rejected), past its
// expiry, past its deletion after the first download, or without any
// deliverable file gives ErrGone (410): the token proves the recipient got
// the link (P9). A transfer whose download limit is reached gives
// ErrMaxDownloads (410) on its page (see "Download limit"). Only the files
// whose scan status is deliverable (store.ScanStatus.Deliverable) are
// listed and served; scan signatures and the other recipients are never
// exposed.
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
// Without download limit, a download start is a GET of a file read from
// offset 0 (whole file, or a range starting at 0; an empty file once
// delivered) or a written archive; never a HEAD request nor a resumed
// range (a transfer with a download limit: see "Download limit"). Each
// start records, in one tenant-scoped transaction, the
// transfer.downloaded audit event (actor kind recipient, actor "link",
// object the transfer, details the file ID
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
// # Download limit
//
// A transfer may cap its download starts (store.Transfer.MaxDownloads, 1
// to 1000, all recipients together; CLAUDE.md section 8.2, threat model
// T-197). A start of such a transfer is not recorded after the first byte
// on a best effort basis, as above, but decided before any byte, by
// [Content.Begin] and [Archive.Begin], which the HTTP layer calls once the
// response is about to be answered 200 or 206 (after the preconditions
// and the Range header were evaluated, so that a 304, 412 or 416 answer
// never counts), and before writing the headers:
//
//   - A GET by a client (IPv4 address or IPv6 /64) whose start of the same
//     object (file or archive) is remembered within Options.StartWindow is
//     served without being counted: a resumed range, or a new request from
//     offset 0 within the window.
//   - Any other GET, whatever its range, is a download start: its audit
//     event and its count (store.Transfers.ClaimDownloadTx, one
//     conditional update) are written in one transaction before the first
//     byte, so that concurrent starts never exceed the limit; at the limit
//     it is refused with ErrMaxDownloads (410 max-downloads-reached). A
//     range from a later offset by a client that never started counts too:
//     otherwise anyone holding the link could fetch every byte but the
//     first without being counted. The start reaching the limit makes the
//     transfer due for deletion Options.Grace later (the grace period of
//     the deletion after the first download, P23); the existing deletion
//     sweep erases it, and the link then answers ErrGone.
//   - A HEAD request is never counted and remembers nothing; it is refused
//     like the GET would be when the limit is reached (from the state read
//     when the request was opened).
//   - A failure of the count refuses the request (fail closed, 500); a
//     start that is refused or fails remembers nothing.
//
// The window of a counted client runs from its start and is moved to the
// end of each of its interrupted responses of a file (a write error, or
// the client gone before the end of the response), so that a long
// download can still resume an hour after its last interruption. A
// response written to its end moves nothing, whether it delivered the end
// of the file or a range the client chose to end before it (a
// "bytes=0-0" loop cannot keep the window open), so that the same client
// downloading again after the window is counted again. Interruptions
// never move the window past the time of the counted start plus
// startCeilingWindows (4) windows, 4 hours by default: a client
// interrupting its responses on purpose cannot keep its key uncounted for
// the life of the transfer. Since the key is the client address, every
// client behind the same IPv4 address or IPv6 /64 (NAT, CGNAT) is served
// uncounted within that window (accepted, T-197); a download longer than
// the ceiling counts as a new start when resumed after it. The memory is the
// bounded in-process map of the deduplication: a restart, an eviction or
// a new client address (a mobile network) makes a resumption count as a
// new start, refused once the limit is reached (accepted, T-197). The
// decisions on a transfer are serialized by its in-process lock, so that
// the concurrent requests of a download manager are counted once. Should
// the HTTP layer not call Begin, the first read of the file (or Write of
// the archive) begins it as a GET, and a refusal fails it before any byte.
// A request already allowed is served to its end, even when the limit is
// reached meanwhile.
//
// The download page and the unlock of a transfer whose limit is reached
// answer ErrMaxDownloads, even during the grace period: no new download
// may start, and a download in progress resumes without the page. Before,
// the page tells the starts left ([View].DownloadsRemaining, absent while
// locked). Without limit, the version 1.0 path is unchanged.
//
// # Confidentiality level
//
// The page shows the confidentiality level snapshotted at the creation of
// the transfer ([View].Confidentiality: key, labels by language and rules).
// While locked, the level is absent: the page keeps the 1.0 set of fields
// (sender, expiry, flags), so an intercepted link does not reveal which
// transfers are the sensitive ones. The HTTP layer picks the label in the
// language of the request ([Confidentiality.Label]).
//
// # Recipient links and verification
//
// Since 1.1 each recipient of a transfer gets their own link
// (store.RecipientLink, decision P27). A token is looked up among the
// recipient links of the tenant first, then among the shared V1 links, with
// the same ErrNotFound for both; the shared links keep the 1.0 behavior.
// Through a recipient link, the grant entries and the transfer password
// counter are bound to the link (store.LinkFailureKey), so that one
// recipient cannot lock the others out; the per-IP counter is unchanged.
// Each link keeps its own range state (storage.StateName(linkID)), its
// download starts (store.RecipientLinks.ClaimTx, in the transaction of the
// download count and of the limit, which counts every link together) and
// its completion: the completion of each item, then of the link, recorded
// with the first download of the transfer in one transaction. The first
// download mail names the recipient of the first link completed; the
// deletion after the first download waits for every link.
//
// When the transfer requires the recipient verification, a link opens
// nothing until the browser holds a valid entry of the stateless
// VerificationCookieName cookie for it (T-200, T-204): the page is the
// minimal locked view with the masked address of the link, and the unlock,
// the files and the archive answer ErrVerificationRequired, before any
// password attempt. [Service.StartVerification] mails a 6-digit code to the
// address of the link only (vcode rules: 15 minutes, 2 attempts, 5 codes per
// link and hour, 20 per client IP and hour shared with the deposit codes),
// and [Service.ConfirmVerification] checks it by a constant-time MAC
// comparison and adds an entry to the cookie: the layout of the grant
// cookie, under VerificationCookiePrefix and the MAC purpose
// recipient-verification, over the tenant ID, the link ID and the expiry
// (VerificationTTL). The confirmation names no challenge: the codes of a
// link are stored under random identifiers, and the newest one of the link
// (store.Challenges.LatestByLink) is the only one checked, a new code
// replacing the previous ones. Wrong codes are written to the security log as
// verification_code_invalid with purpose "recipient" (P38).
//
// # Logs
//
// Logs hold tenant, transfer, link and file identifiers only: never a
// token, a password, a code, an address or a file name.
package download

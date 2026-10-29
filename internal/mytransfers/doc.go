// Package mytransfers implements "My transfers" (CLAUDE.md section 8.7,
// threat model T-207 to T-211, decisions P32 and P34): a sender without an
// account asks for a one-time access link by mail, opens a short session
// with it, then lists, inspects, deletes or extends the transfers in
// progress they sent from that address.
//
// # Access link request (P32, T-207)
//
// [Service.RequestLink] does exactly the same work whatever the address,
// so that neither its answer nor its timing tells whether the address is
// known: it validates the address, checks that the tenant can send mail at
// all, records the request in the rate limit table (keyed by an HMAC of
// the normalized address, crypto.MACPurposeAccessRate, and by the client
// IP, or its /64 for IPv6), applies the limits, and hands the request to a
// bounded in-memory worker. Beyond MaxRequestsPerIP requests per hour from
// one client the request is refused (*RateLimitError, logged as
// rate_limited with scope ScopeRequestIP) and not recorded; beyond MaxRequestsPerAddress requests per hour for one
// address it is silently dropped. Only the worker looks the address up: a
// verified and still active address of the tenant that is not on its
// blocklist gets a link (token "mta_" + 256 bits, stored hashed, valid
// LinkTTL, single use) mailed as https://<tenant host>/me#mta_..., and the
// audit event my_transfers.link_requested. An unknown address leaves no
// trace anywhere but the rate limit row.
//
// # Session (T-208)
//
// [Service.StartSession] consumes the link and opens a session in one
// transaction: an unknown, expired, used or foreign link answers
// ErrAccessLinkInvalid and writes access_link_invalid to the security log;
// repeated failures from one client lock it out for a while
// (*RateLimitError, rate_limited with scope ScopeSessionIP). The session
// cookie token ("ms_" + 256 bits, stored hashed) is valid SessionTTL
// (absolute), bound to the tenant and the normalized address, and carries a
// CSRF token derived by MAC (crypto.MACPurposeMeCSRF).
//
// # Transfers (T-209, T-210)
//
// Every operation on transfers is scoped to the tenant and the address of
// the session (and to the transfers of a deposit session, never those of
// an API token): any other transfer is ErrNotFound. [Service.Delete] erases
// like an administrator (lifecycle, crypto-erase, retries while an upload
// holds a file); [Service.Extend] moves the expiry forward within the
// durations allowed by the snapshotted rules of the transfer, never beyond
// 90 days after its creation.
//
// Every error that is not one of the sentinel errors of the package is an
// internal failure whose message never holds an address or a token.
package mytransfers

// Package deposit identifies the people who deposit files (CLAUDE.md
// sections 6 to 9): it decides who may deposit, verifies their mail address
// with a one-time code, opens the deposit sessions carried by a cookie and
// lets internal users invite external ones.
//
// # Eligibility
//
// [Service.Start] checks, in this order (OpenAPI startDepositSession):
//
//  1. the address syntax ([mail.ParseAddress], then [store.NormalizeEmail]);
//  2. the tenant blocklist: the address, then its domain;
//  3. with an invitation token: the invitation must exist in the tenant, be
//     active and name the same address; the depositor is then external;
//  4. otherwise the internal rule (spec 6.2, package netpolicy): the client
//     IP is in one of the tenant CIDR ranges AND the mail domain is one of
//     the tenant domains.
//
// Every refusal answers the same generic error ([ErrForbidden]), except an
// expired or revoked invitation presented with a valid token
// ([ErrInvitationGone], decision P9), and writes a deposit_refused line to
// the security log with the reason only (never the address, the token or a
// code).
//
// An internal depositor's eligibility is checked again whenever an action
// relies on it: confirming a code and creating an invitation re-run the
// blocklist and the internal rule, so that a session opened at the office
// does not allow inviting from outside. Step 6 (transfers) MUST do the
// same at transfer creation: re-check BOTH the tenant blocklist (the
// depositor address and its domain) AND, for an internal session, the
// internal IP rule (netpolicy.Evaluate on the current client IP and the
// session address), since the session outlives both.
//
// # Verification codes
//
// A 6-digit code, drawn uniformly from crypto/rand, is mailed through the
// tenant SMTP server. The code is never stored or logged: the challenge
// keeps an HMAC-SHA256 of the challenge ID and the code under a key derived
// from the master key (purpose otp). A challenge lives 15 minutes and
// tolerates 2 wrong codes.
//
// The rate limits (5 codes per address and 20 per client IP over a sliding
// hour, both per tenant: the same IP has its own allowance in every tenant)
// are counted in the database, so they survive a restart (threat T-137).
// The counts run in the write transaction that inserts the challenge, after
// the tenant lock, so concurrent requests cannot exceed them (threat T-12);
// the store opens its PostgreSQL transactions READ COMMITTED whatever the
// server default, which this lock-then-count pattern requires.
// The invitations are limited the same way: MaxInvitationsPerInviter per
// inviter address and tenant over the same hour.
//
// Retention: since the limits count rows by creation time, a challenge row
// (and an invitation row) must be kept at least until created_at +
// RateWindow, even once used or expired. The future cleanup job therefore
// purges only the challenges with created_at < now - 1 hour.
//
// The mail is rendered and the tenant SMTP settings loaded before the
// transaction: a tenant without SMTP settings gets ErrMailUnavailable (503)
// with nothing written. The mail is queued after the commit. When the queue
// refuses it (full, closed or circuit open), the challenge or the
// invitation is deleted, best effort, and the request fails as before (429
// or 503): a refused request leaves no usable code or link and does not
// count against the limits. The remaining corner case: if the process
// stops between the commit and the queueing, or the compensation itself
// fails, a challenge whose code nobody received stays until it expires (15
// minutes, counting against the limits for an hour), and an invitation
// whose link nobody received stays pending; neither can be used without the
// secret that only the lost mail carried.
//
// # Recognition cookie and the "already verified" shortcut
//
// A verified address (spec 7) is not asked for a code again only when two
// conditions hold: the depositor is internal (no invitation: decision A, an
// invitation-based deposit always requires a code, so that a forwarded
// invitation link opens nothing by itself), and the browser presents the
// technical recognition cookie set when that address entered a code on
// that browser (decision B; spec 7 allows such a cookie, the database
// remains authoritative). Otherwise a code is sent, so that a colleague's
// verified address cannot be used from another internal machine.
//
// The cookie RecognitionCookie holds up to RecognitionMaxEntries entries
// separated by "." (at most 244 bytes). Each entry is 48 characters of
// unpadded base64url encoding 36 bytes:
//
//	day (4 bytes, big-endian, in clear) | MAC (32 bytes)
//	MAC = HMAC-SHA256 under the master-key-derived key of purpose
//	      recognition, over (tenant ID, normalized address, salt, day)
//
// day is the issue day in whole days since the Unix epoch; salt is the 16
// random bytes kept with the verified address (store
// VerifiedAddress.RecognitionSalt). The cookie never contains the address,
// and an entry is worthless in another tenant, for another address, with a
// rewritten day, more than RecognitionMaxAgeDays after its issue day, or
// once the salt changed. The salt is drawn at the first verification and
// again when an address unused for 12 months is verified anew;
// store.VerifiedAddresses.ResetRecognition replaces it on demand (erasure
// of a person's data, administration action), which revokes every entry of
// the address on every browser. Start and Confirm receive the raw cookie
// value, parsed defensively (bounded length, at most RecognitionMaxEntries
// entries, junk ignored), and return in Session.Recognition the new value
// for internal depositors: a new entry of this address issued today, then
// the other fresh entries without the older ones of this address, capped;
// the HTTP layer sets it for RecognitionMaxAge. The shortcut also requires
// the address to be verified and active for the tenant. Finishing a master
// key rotation invalidates every recognition cookie: each depositor enters
// a code once more.
//
// # Sessions and CSRF
//
// A session token is "ds_" followed by 256 bits in base62; only its SHA-256
// is stored. Its CSRF token is "csrf_" followed by the base64url HMAC of the
// session token under a key derived from the master key (purpose csrf): it
// is never stored, and recomputed on demand. When a master key rotation
// completes and TT_MASTER_KEY_FILE switches to the new key, outstanding codes
// and CSRF tokens stop verifying: users request a new code or reload the
// page.
//
// A session of an external depositor dies with its invitation: [Service.Session]
// refuses it as soon as the invitation is revoked or expired.
//
// # Invitations
//
// The invitation link is https://<tenant FQDN>/i/<token>, built from the
// FQDN registered for the tenant and never from the request Host (threat
// T-03). The /i/ route belongs to the web interface, which comes later; it
// reads the token and calls getInvitation. The token is "inv_" followed by
// 256 bits in base62 (OpenAPI pattern ^inv_[A-Za-z0-9]{22,43}$); only its
// SHA-256 is stored. The message of the inviter is stripped of control and
// invisible formatting characters before it is stored (threats T-18, T-81). The
// configurable per-inviter quota and the external deposit quotas are part
// of V1.1 (spec 15.2).
package deposit

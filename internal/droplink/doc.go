// Package droplink manages the permanent drop links of the tenants (since
// 2.0, spec 22): the administration side, which creates, changes, rotates
// and revokes the links. The public side (landing page and deposits) lives
// in the deposit and transfer packages.
//
// Every method takes the [adminauth.Principal] of the session and checks it
// itself: an authenticated session first, then [adminauth.RequireTenantAuditRead]
// for the reads (the auditor role may read) or [adminauth.RequireTenantWrite]
// for the changes. A tenant the caller is not attached to, and a tenant
// being deleted, are answered like a missing tenant ([ErrNotFound]); a link
// of another tenant like a missing link. The changes are audited
// (drop_link.created, .updated, .rotated, .revoked) with the link ID and
// counts, never with the token, its hash or the recipient addresses.
//
// # Errors
//
// The HTTP layer maps them with errors.Is:
//
//   - [ErrInvalidInput] (an *[InvalidError] naming the field): 400
//     validation-failed;
//   - [ErrUnauthenticated]: 401 unauthenticated;
//   - [adminauth.ErrReadOnlyRole]: 403 read-only-role;
//   - [ErrForbidden]: 403 forbidden;
//   - [ErrNotFound]: 404 not-found;
//   - [ErrStateConflict]: 409 state-conflict (change or rotation of a
//     revoked link);
//   - [ErrLimitReached]: 409 drop-link-limit-reached.
//
// Any other error is an internal failure (500 internal-error).
package droplink

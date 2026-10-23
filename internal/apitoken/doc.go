// Package apitoken manages the API tokens of the tenants (CLAUDE.md
// section 16.4, threats T-68 to T-73): the administrators list, create,
// rename, re-scope and revoke them, and the deposit API authenticates the
// scripts that present one. It writes no HTTP: the handlers of packages
// api/admin and api/public map its results and errors.
//
// # Tokens
//
// A token secret is "tt_" followed by 43 base62 characters (256 bits from
// crypto/rand, [Generate]). It is returned once, at its creation; the store
// keeps its SHA-256 only, with its first [PrefixLen] characters to
// recognize it. A token has a name, 1 to 100 allowed IP ranges ("any
// address" is spelled out as 0.0.0.0/0 and ::/0), an optional expiry and,
// once revoked, its revocation time: a revoked token is refused at once.
//
// # Administration (threats T-63, T-64)
//
// Every administration method takes the [adminauth.Principal] of the caller
// and checks it before anything else, request body included: an
// authenticated session, then [adminauth.RequireTenantAccess] for the list
// or [adminauth.RequireTenantWrite] for the changes. A tenant the caller is
// not attached to, and a tenant being deleted, are answered like a missing
// tenant ([ErrNotFound]); a token of another tenant like a missing token.
// The changes are audited (api_token.created, api_token.updated,
// api_token.revoked) with the token ID, never with the secret or its hash.
//
// # Authentication (threats T-69, T-70, T-73)
//
// [Service.Authenticate] parses the Authorization header strictly, hashes
// the secret and looks the hash up in the scope of the tenant resolved from
// the Host header, so that a token of another tenant is unknown. A missing
// bearer token is [ErrMissing]; a malformed, unknown, revoked or expired
// token is [ErrInvalid], one error for all, so that the answer is no
// oracle; a valid token presented from outside its ranges is
// [ErrIPNotAllowed]. The last use is recorded at most once a minute per
// token, so that a large upload does not write to the database at every
// chunk (spec 17).
//
// # Errors of the administration
//
// The HTTP layer maps them with errors.Is:
//
//   - [ErrInvalidInput] (an *[InvalidError] naming the field): 400
//     validation-failed;
//   - [ErrUnauthenticated]: 401 unauthenticated;
//   - [ErrForbidden]: 403 forbidden;
//   - [ErrNotFound]: 404 not-found;
//   - [ErrStateConflict]: 409 state-conflict (change of a revoked token).
//
// Any other error is an internal failure (500 internal-error).
package apitoken

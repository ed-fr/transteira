// Package tenantops is the operation service of the tenants (CLAUDE.md
// sections 6.5, 9, 10, 15.2 and 21): the administrators list and inspect
// the transfers of a tenant, delete one before its expiry, resend its
// notification, list and revoke the invitations, manage the blocklist, and
// read the audit log of a tenant or, for the super admin, of the whole
// instance. It writes no HTTP: the handlers of package api/admin map its
// results and errors.
//
// # Authorization (threats T-63, T-64)
//
// Every method takes the [adminauth.Principal] of the caller and checks it
// before anything else, request body included: an authenticated session
// ([adminauth.RequireAuthenticated]), then [adminauth.RequireTenantAccess]
// for the reads (lists, transfer details, tenant audit log) or
// [adminauth.RequireTenantWrite] for the changes (delete, resend, revoke,
// blocklist create and delete). A tenant the caller is not attached to,
// and a tenant being deleted, are answered exactly like a missing tenant
// ([ErrNotFound]); a transfer, invitation or entry of another tenant
// exactly like a missing one, since every store read runs in the scope of
// the tenant. The global audit log requires [adminauth.RequireSuperAdmin]
// ([ErrForbidden] otherwise).
//
// # Errors
//
// The HTTP layer maps the errors with errors.Is:
//
//   - [ErrInvalid] (an *[InvalidError] naming the field): 400
//     validation-failed;
//   - [ErrUnauthenticated]: 401 unauthenticated;
//   - [ErrForbidden]: 403 forbidden;
//   - [ErrNotFound]: 404 not-found;
//   - [ErrAlreadyExists]: 409 already-exists;
//   - [ErrBusy] (a *[BusyError] with the Retry-After delay) and
//     [ErrNotAvailable], both matching [ErrStateConflict]: 409
//     state-conflict;
//   - [ErrRateLimited] (a *[RateLimitError] with the Retry-After delay):
//     429 rate-limited;
//   - [ErrMailUnavailable]: 503 mail-unavailable;
//   - anything else: 500 internal-error.
//
// # Deletion and the antivirus (T-147)
//
// [Service.DeleteTransfer] goes through the Eraser (lifecycle.Sweeper,
// mode lifecycle.MarkDeleted), which holds the antivirus before destroying
// any key: a transfer being scanned is never made available and none of
// its recipients is told. A deletion refused because an upload request
// holds a file is retried DefaultBusyRetries times, DefaultBusyDelay
// apart, then answered with a *[BusyError]. A transfer already expired or
// deleted is left as it is, without audit.
//
// # Resend (T-146)
//
// [Service.ResendNotification] reuses the download token sealed when the
// transfer became available: it is opened for the build of the mails,
// wiped after it, and never rotated (links already received keep working),
// returned or logged. The recipients must be original recipients of the
// transfer. Resends are limited per transfer (DefaultResendLimit per
// DefaultResendWindow, kept in memory).
//
// # Audit and personal data (T-150)
//
// Every change writes an audit event in the scope of the tenant, after it
// is committed; a write failure is logged, never returned: transfer.deleted
// (details: the reason, its mail addresses replaced by "[address]" and cut
// to MaxReasonLen characters), transfer.notification_resent (details: the
// number of recipients only), invitation.revoked, and blocklist.updated
// (details: op, kind, entryId, and the value for a domain or a fingerprint
// only). The actor is the username of the administrator. No detail holds a
// mail address: the audit package refuses any (audit.ErrPersonalDetail).
// The no-op cases (transfer already ended, invitation revoked or expired)
// record nothing.
package tenantops

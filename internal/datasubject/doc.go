// Package datasubject serves the rights of the data subjects (CLAUDE.md
// section 20): an administrator searches a tenant for the data linked to a
// mail address, and erases it.
//
// # Scope and authorization
//
// Both operations take the [adminauth.Principal] of the caller and require
// an authenticated session and the right to change the tenant
// ([adminauth.RequireTenantWrite]). A tenant the caller is not attached
// to, and a tenant being deleted, are answered exactly like a missing one
// ([ErrNotFound]). Only that tenant is searched or changed: the same
// address in another tenant is neither counted nor touched.
//
// # Erasure
//
// [Service.Erase] runs these steps, each of which can be replayed safely,
// so that an interrupted erasure is completed by a new call:
//
//  1. the verification codes, the deposit sessions (an open session ends
//     at once) and the verified address record are deleted first, so that
//     the address cannot open a new deposit while it is being erased;
//  2. the transfers sent by the address, and those deposited with an
//     invitation of which it is the invitee, are crypto-erased and their
//     rows deleted ([lifecycle.Sweeper.EraseTransfer] with
//     [lifecycle.DeleteRow]);
//  3. the transfers of which it is a recipient: when it is the only
//     recipient, the transfer is erased in the same way; otherwise the
//     address is removed from the recipients while the antivirus worker
//     holds the transfer, so that a transfer still scanning never mails it.
//     The status does not matter: an ended transfer (expired, deleted,
//     rejected) is handled the same way, and no row keeps the address;
//  4. the invitations of which it is the invitee are deleted; those it
//     issued are revoked and their issuer replaced by the pseudonym;
//  5. the address is replaced by the pseudonym wherever it is the actor
//     of an audit event of the tenant;
//  6. the database is scrubbed once (store.DB.ScrubDeleted);
//  7. the erasure is audited as data_subject.erased, its object being the
//     pseudonym and its details the counts of the report.
//
// A transfer held by an upload request is retried a few times, then the
// erasure stops with [ErrBusy] (409, to be retried). Erasures of one
// service are serialized.
//
// The pseudonym is [store.PseudonymPrefix] followed by the first
// [store.PseudonymHexLen] hexadecimal characters of an HMAC-SHA256 of the
// normalized address keyed with 32 random bytes drawn for this erasure and
// wiped afterwards: it groups the rows of one person within one erasure
// without allowing the address to be recovered, and differs from one
// erasure to the next.
//
// Kept on purpose: blocklist entries, client IP addresses in the audit
// log, mails already queued, and backups (unreadable once the keys are
// destroyed). The security log never records addresses, so the search
// always reports zero security events.
//
// # Confidentiality
//
// Neither the address nor the salt is ever logged, audited or put in an
// error message: the audit events of this package hold counts only.
package datasubject

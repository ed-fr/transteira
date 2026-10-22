// Package audit writes the audit log of CLAUDE.md section 21.1: who did
// what, when, from where and on which object. It is a thin, typed layer over
// [store.AuditEvents]: the actions are named constants, the details are a
// small map checked so that no secret can be recorded by mistake, and the
// events of an operation can be written inside its transaction.
//
// The log is append-only (threat T-102): this package offers no update and
// no deletion; the 12-month purge belongs to the cleanup task.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Action is the action of an audit event (OpenAPI AuditAction, an
// extensible enumeration).
type Action string

// Actions of the administrator accounts and authentication. The values
// listed in the AuditAction enumeration of the specification keep their
// spelling there (admin.login, admin.logout, admin.created, admin.updated,
// admin.deleted, setup.completed); the others extend it.
const (
	// ActionSetupCompleted: the first-run setup created the super admin.
	ActionSetupCompleted Action = "setup.completed"
	// ActionAdminLogin: an administrator completed a login.
	ActionAdminLogin Action = "admin.login"
	// ActionAdminLoginFailed: a login step of an existing administrator
	// failed (wrong password, TOTP code or recovery code).
	ActionAdminLoginFailed Action = "admin.login_failed"
	// ActionAdminLogout: an administrator logged out.
	ActionAdminLogout Action = "admin.logout"
	// ActionAdminTOTPEnrolled: an administrator confirmed a TOTP enrollment.
	ActionAdminTOTPEnrolled Action = "admin.totp_enrolled"
	// ActionAdminTOTPDisabled: an administrator disabled their TOTP.
	ActionAdminTOTPDisabled Action = "admin.totp_disabled"
	// ActionAdminRecoveryCodeUsed: a recovery code replaced the TOTP code.
	ActionAdminRecoveryCodeUsed Action = "admin.recovery_code_used"
	// ActionAdminPasswordChanged: an administrator changed their password.
	ActionAdminPasswordChanged Action = "admin.password_changed"
	// ActionAdminCreated: the super admin created an account.
	ActionAdminCreated Action = "admin.created"
	// ActionAdminUpdated: the super admin changed an account.
	ActionAdminUpdated Action = "admin.updated"
	// ActionAdminDeleted: the super admin deleted an account.
	ActionAdminDeleted Action = "admin.deleted"
	// ActionAdminCredentialsReset: the super admin reset the password and
	// TOTP of an account.
	ActionAdminCredentialsReset Action = "admin.credentials_reset" //nolint:gosec // G101 false positive: an audit action name.
	// ActionAdminActivated: an administrator chose a password from an
	// activation link.
	ActionAdminActivated Action = "admin.activated"
	// ActionAdminTOTPResetLocal: the local command reset the TOTP of an
	// account (transteira admin reset-totp).
	ActionAdminTOTPResetLocal Action = "admin.totp_reset_local"
	// ActionAdminPasswordResetLocal: the local command reset the password,
	// TOTP and recovery codes of an account and issued an activation link
	// (transteira admin reset-password).
	ActionAdminPasswordResetLocal Action = "admin.password_reset_local"
)

// Actions of transfers, invitations, address verification, antivirus,
// quotas, the blocklist and the exercise of data subject rights. Each value
// is listed in the AuditAction enumeration of the specification.
const (
	// ActionTransferCreated: a depositor created a transfer.
	ActionTransferCreated Action = "transfer.created"
	// ActionTransferFinalized: a depositor finalized the upload of a
	// transfer.
	ActionTransferFinalized Action = "transfer.finalized"
	// ActionTransferDownloaded: the download of a file or of the archive
	// started (never for HEAD requests or resumed ranges).
	ActionTransferDownloaded Action = "transfer.downloaded"
	// ActionTransferDeleted: an administrator deleted a transfer before its
	// expiry (details carry the redacted reason).
	ActionTransferDeleted Action = "transfer.deleted"
	// ActionTransferNotificationResent: an administrator resent the
	// notification of a transfer to its recipients.
	ActionTransferNotificationResent Action = "transfer.notification_resent"
	// ActionInvitationCreated: an internal user invited an external one.
	ActionInvitationCreated Action = "invitation.created"
	// ActionInvitationUsed: an external user deposited through an
	// invitation.
	ActionInvitationUsed Action = "invitation.used"
	// ActionInvitationRevoked: an administrator revoked an invitation.
	ActionInvitationRevoked Action = "invitation.revoked"
	// ActionAddressVerified: a mail address passed its verification code.
	ActionAddressVerified Action = "address.verified"
	// ActionFileInfected: the antivirus found a virus in a file, which was
	// deleted.
	ActionFileInfected Action = "file.infected"
	// ActionFileNotScanned: a file could not be scanned (size) and was
	// accepted.
	ActionFileNotScanned Action = "file.not_scanned"
	// ActionQuotaWarning: a tenant reached 80 % of its storage quota.
	ActionQuotaWarning Action = "quota.warning"
	// ActionQuotaReached: a tenant reached its storage quota.
	ActionQuotaReached Action = "quota.reached"
	// ActionBlocklistUpdated: an administrator added or removed a blocklist
	// entry.
	ActionBlocklistUpdated Action = "blocklist.updated"
	// ActionDataSubjectSearched: an administrator searched the data linked
	// to an address (the address is never recorded).
	ActionDataSubjectSearched Action = "data_subject.searched"
	// ActionDataSubjectErased: an administrator erased the data linked to an
	// address (the address is never recorded).
	ActionDataSubjectErased Action = "data_subject.erased"
)

// Object kinds.
const (
	// ObjectAdmin is an administrator account (object ID: its "adm_" ID).
	ObjectAdmin = "admin"
	// ObjectTenant is a tenant (object ID: its tenant ID).
	ObjectTenant = "tenant"
	// ObjectTransfer is a transfer (object ID: its "trf_" ID).
	ObjectTransfer = "transfer"
	// ObjectFile is a file of a transfer (object ID: its file ID).
	ObjectFile = "file"
	// ObjectInvitation is an invitation (object ID: its invitation ID).
	ObjectInvitation = "invitation"
	// ObjectBlocklistEntry is a blocklist entry (object ID: its entry ID).
	ObjectBlocklistEntry = "blocklist_entry"
	// ObjectDataSubject is the subject of a rights request (object ID: a
	// pseudonym, never the address).
	ObjectDataSubject = "data_subject"
	// ObjectDepositSession is a deposit session (object ID: its session
	// ID).
	ObjectDepositSession = "deposit_session"
)

// ErrSecretDetail reports details whose key names a secret (password,
// token, code...): nothing is written. Details describe an action, never a
// credential.
var ErrSecretDetail = errors.New("audit: details must not hold a secret")

// ErrPersonalDetail reports details holding a mail address (a string key or
// value containing an at sign, at any depth): nothing is written. The audit
// log keeps addresses in the actor column only, where a GDPR erasure can
// pseudonymize them; free text must go through [RedactAddresses] first.
var ErrPersonalDetail = errors.New("audit: details must not hold a mail address")

// secretKeyParts are the fragments of a detail key refused by
// [ErrSecretDetail], compared case-insensitively.
var secretKeyParts = []string{"password", "passphrase", "secret", "token", "code"}

// Event is an audit event to record.
type Event struct {
	// TenantID is the tenant of the event, "" for a global event (setup,
	// administrator accounts).
	TenantID tenant.ID
	// ActorKind and Actor identify who acted: an administrator by their
	// username, the system by a short name ("cli"...).
	ActorKind store.AuditActorKind
	Actor     string
	// IP is the client IP, the zero Addr when there is none (local command).
	IP netip.Addr
	// Action is what was done.
	Action Action
	// ObjectKind and ObjectID identify what it was done on.
	ObjectKind string
	ObjectID   string
	// Details are optional facts about the action (changed fields, method),
	// serialized as a JSON object of at most store.MaxAuditDetailsBytes
	// bytes. No key may name a secret ([ErrSecretDetail]) and no value may
	// hold one; no key or string value may hold a mail address
	// ([ErrPersonalDetail]).
	Details map[string]any
}

// Writer records audit events. It is safe for concurrent use.
type Writer struct {
	db     *store.DB
	events *store.AuditEvents
}

// New returns a writer appending to the audit log of db.
func New(db *store.DB) *Writer {
	return &Writer{db: db, events: db.AuditEvents()}
}

// Record appends ev in its own transaction.
func (w *Writer) Record(ctx context.Context, ev Event) error {
	row, err := toStore(ev)
	if err != nil {
		return err
	}
	if _, err := w.events.Append(ctx, row); err != nil {
		return fmt.Errorf("audit: record %s: %w", ev.Action, err)
	}
	return nil
}

// RecordTx appends ev inside the system transaction tx, so that it is
// written if and only if the operation it records commits.
func (w *Writer) RecordTx(ctx context.Context, tx *store.SystemTx, ev Event) error {
	row, err := toStore(ev)
	if err != nil {
		return err
	}
	if _, err := w.events.AppendTx(ctx, tx, row); err != nil {
		return fmt.Errorf("audit: record %s: %w", ev.Action, err)
	}
	return nil
}

// RecordScoped appends ev in its own transaction bound to tenant tid, so
// that the database enforces the tenant isolation (row-level security with
// PostgreSQL). ev.TenantID must be "" (it is then set to tid) or tid;
// another tenant or a malformed tid yields store.ErrInvalid.
func (w *Writer) RecordScoped(ctx context.Context, tid tenant.ID, ev Event) error {
	if _, err := toStore(ev); err != nil {
		return err
	}
	scoped, err := w.db.Scoped(tid)
	if err != nil {
		return fmt.Errorf("audit: record %s: %w", ev.Action, err)
	}
	return scoped.Tx(ctx, func(tx *store.ScopedTx) error { return w.RecordScopedTx(ctx, tx, ev) })
}

// RecordScopedTx appends ev inside the tenant transaction tx, so that it is
// written if and only if the operation it records commits, under the
// tenant isolation of tx (row-level security with PostgreSQL). It applies
// the same checks as [Writer.Record]: every audit write of a tenant
// operation goes through it. ev.TenantID must be "" (it is then set to the
// tenant of tx) or that tenant; another tenant yields store.ErrInvalid.
// After an error, the caller must abort the transaction.
func (w *Writer) RecordScopedTx(ctx context.Context, tx *store.ScopedTx, ev Event) error {
	row, err := toStore(ev)
	if err != nil {
		return err
	}
	if _, err := w.events.AppendScopedTx(ctx, tx, row); err != nil {
		return fmt.Errorf("audit: record %s: %w", ev.Action, err)
	}
	return nil
}

// toStore checks ev and converts it to a store event. The store validates
// the remaining fields (actor, action and object syntax, details size).
func toStore(ev Event) (store.AuditEvent, error) {
	row := store.AuditEvent{
		TenantID: ev.TenantID, ActorKind: ev.ActorKind, Actor: ev.Actor, IP: ev.IP,
		Action: string(ev.Action), ObjectKind: ev.ObjectKind, ObjectID: ev.ObjectID,
	}
	if len(ev.Details) == 0 {
		return row, nil
	}
	for k := range ev.Details {
		lower := strings.ToLower(k)
		for _, part := range secretKeyParts {
			if strings.Contains(lower, part) {
				return store.AuditEvent{}, fmt.Errorf("%w (%s)", ErrSecretDetail, ev.Action)
			}
		}
	}
	details, err := json.Marshal(ev.Details)
	if err != nil {
		return store.AuditEvent{}, fmt.Errorf("audit: encode details of %s: %w", ev.Action, err)
	}
	if holdsAddress(details) {
		return store.AuditEvent{}, fmt.Errorf("%w (%s)", ErrPersonalDetail, ev.Action)
	}
	row.Details = details
	return row, nil
}

// holdsAddress reports whether the JSON document doc holds a key or a
// string value containing an at sign. It works on the encoded form so that
// every Go type (typed strings, slices, nested maps, custom marshalers) is
// covered, escapes included. It fails closed: doc comes from json.Marshal
// and always decodes, but should it not, the sentinel "@" stays in place and
// the details are refused.
func holdsAddress(doc []byte) bool {
	v := any("@")
	_ = json.Unmarshal(doc, &v)
	return walkAddress(v)
}

// walkAddress implements holdsAddress on a decoded JSON value.
func walkAddress(v any) bool {
	switch v := v.(type) {
	case string:
		return containsAt(v)
	case []any:
		for _, e := range v {
			if walkAddress(e) {
				return true
			}
		}
	case map[string]any:
		for k, e := range v {
			if containsAt(k) || walkAddress(e) {
				return true
			}
		}
	}
	return false
}

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

// Object kinds.
const (
	// ObjectAdmin is an administrator account (object ID: its "adm_" ID).
	ObjectAdmin = "admin"
)

// ErrSecretDetail reports details whose key names a secret (password,
// token, code...): nothing is written. Details describe an action, never a
// credential.
var ErrSecretDetail = errors.New("audit: details must not hold a secret")

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
	// hold one.
	Details map[string]any
}

// Writer records audit events. It is safe for concurrent use.
type Writer struct {
	events *store.AuditEvents
}

// New returns a writer appending to the audit log of db.
func New(db *store.DB) *Writer {
	return &Writer{events: db.AuditEvents()}
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
	row.Details = details
	return row, nil
}

// Package audit writes the audit log of CLAUDE.md section 21.1: who did
// what, when, from where and on which object. It is a thin, typed layer over
// [store.AuditEvents]: the actions are named constants, the details are a
// small map checked so that no secret can be recorded by mistake, and the
// events of an operation can be written inside its transaction.
//
// The log is append-only (threat T-102): this package offers no update and
// no deletion; the 12-month purge belongs to the cleanup task.
//
// Every event written is also published as an events.LogAudit event on the
// event bus given with [WithPublisher] (the syslog export subscribes to
// it), once the transaction holding it committed: never for an operation
// rolled back, nor for details refused by the checks.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ed-fr/transteira/internal/events"
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
	// ActionTransferRecipientRefused: the recipient domain rules of the
	// tenant refused recipients of a transfer creation (details: the
	// refused domains, never an address; audit only, never in the security
	// log).
	ActionTransferRecipientRefused Action = "transfer.recipient_refused"
	// ActionTransferReplyCreated: the recipient of a transfer created a
	// reply transfer, addressed to the original sender (spec 10), recorded
	// besides transfer.created (details: replyTo, the original transfer).
	ActionTransferReplyCreated Action = "transfer.reply_created"
	// ActionTransferFinalized: a depositor finalized the upload of a
	// transfer.
	ActionTransferFinalized Action = "transfer.finalized"
	// ActionTransferDownloaded: the download of a file or of the archive
	// started (never for HEAD requests or resumed ranges).
	ActionTransferDownloaded Action = "transfer.downloaded"
	// ActionTransferDeleted: an administrator (details carry the redacted
	// reason) or, since 1.1, the sender through "my transfers" deleted a
	// transfer before its expiry.
	ActionTransferDeleted Action = "transfer.deleted"
	// ActionTransferExtended: the sender extended the expiry of a transfer
	// through "my transfers" (details carry the old and new expiry and the
	// number of extensions).
	ActionTransferExtended Action = "transfer.extended"
	// ActionTransferNotificationResent: an administrator resent the
	// notification of a transfer to its recipients.
	ActionTransferNotificationResent Action = "transfer.notification_resent"
	// ActionTransferReminderSent: the system mailed the expiry reminder to
	// the recipients of a transfer who had not downloaded it (the details
	// carry their number).
	ActionTransferReminderSent Action = "transfer.reminder_sent"
	// ActionRecipientVerified: the recipient of a per-recipient link proved
	// their address by code (the details name the link, never the code).
	ActionRecipientVerified Action = "recipient.verified"
	// ActionInvitationCreated: an internal user invited an external one.
	ActionInvitationCreated Action = "invitation.created"
	// ActionInvitationUsed: an external user deposited through an
	// invitation.
	ActionInvitationUsed Action = "invitation.used"
	// ActionInvitationRevoked: an administrator revoked an invitation.
	ActionInvitationRevoked Action = "invitation.revoked"
	// ActionMyTransfersLinkRequested: a "my transfers" access link was
	// mailed to a verified address (recorded only when a link is sent).
	ActionMyTransfersLinkRequested Action = "my_transfers.link_requested"
	// ActionMyTransfersSignedIn: an access link opened a "my transfers"
	// session.
	ActionMyTransfersSignedIn Action = "my_transfers.signed_in"
	// ActionAddressVerified: a mail address passed its verification code.
	ActionAddressVerified Action = "address.verified"
	// ActionFileInfected: the antivirus found a virus in a file, which was
	// deleted.
	ActionFileInfected Action = "file.infected"
	// ActionFileNotScanned: a file was accepted without analysis (details:
	// reason too_large, encrypted or disabled).
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
	// ActionAPITokenCreated: an administrator created an API token (never
	// recorded with its secret).
	ActionAPITokenCreated Action = "api_token.created"
	// ActionAPITokenUpdated: an administrator renamed an API token or
	// replaced its allowed IP ranges.
	ActionAPITokenUpdated Action = "api_token.updated"
	// ActionAPITokenRevoked: an administrator revoked an API token.
	ActionAPITokenRevoked Action = "api_token.revoked"
	// ActionAPITokenUsed: an API token created a transfer (once per
	// transfer, not per request).
	ActionAPITokenUsed Action = "api_token.used"
)

// Actions of the instance: settings, maintenance mode, master key
// rotation, disk and antivirus alerts. They are global events (no tenant),
// each listed in the AuditAction enumeration of the specification.
const (
	// ActionConfigUpdated: the super admin changed the instance settings
	// (details carry the names of the changed fields only, never their
	// values).
	ActionConfigUpdated Action = "config.updated"
	// ActionMaintenanceEnabled: the super admin enabled the maintenance
	// mode (details carry the languages of the messages only).
	ActionMaintenanceEnabled Action = "maintenance.enabled"
	// ActionMaintenanceDisabled: the super admin disabled the maintenance
	// mode.
	ActionMaintenanceDisabled Action = "maintenance.disabled"
	// ActionMasterKeyRotationStarted: a master key rotation started or
	// resumed, from the administration or the local command (details carry
	// the key identifiers, never key material).
	ActionMasterKeyRotationStarted Action = "master_key.rotation_started"
	// ActionMasterKeyRotationCompleted: every key was rewrapped under the
	// new master key.
	ActionMasterKeyRotationCompleted Action = "master_key.rotation_completed"
	// ActionMasterKeyRotationFailed: a master key rotation stopped on an
	// error (an interruption at shutdown is not a failure: the rotation
	// stays resumable).
	ActionMasterKeyRotationFailed Action = "master_key.rotation_failed"
	// ActionDiskAlertRaised: the disk usage reached the alert threshold
	// (recorded even when no system mail can be sent).
	ActionDiskAlertRaised Action = "disk.alert_raised"
	// ActionDiskAlertCleared: the disk usage fell 5 points below the alert
	// threshold.
	ActionDiskAlertCleared Action = "disk.alert_cleared"
	// ActionAntivirusAlertRaised: clamd stayed unreachable beyond the grace
	// period of the antivirus alert (recorded even when no mail can be
	// sent).
	ActionAntivirusAlertRaised Action = "antivirus.alert_raised"
	// ActionAntivirusAlertCleared: clamd answered again after a raised
	// antivirus alert.
	ActionAntivirusAlertCleared Action = "antivirus.alert_cleared"
	// ActionAntivirusScansReleased: the instance started with the antivirus
	// engine "none" and released the files still waiting for a scan as
	// not_scanned_disabled (details: the number of files).
	ActionAntivirusScansReleased Action = "antivirus.scans_released"
)

// Actions of the webhooks (tenant and instance-wide), each listed in the
// AuditAction enumeration of the specification. Their details never hold
// the URL (only its host) nor the signing secret (threat model T-184).
const (
	// ActionWebhookCreated: an administrator created a webhook.
	ActionWebhookCreated Action = "webhook.created"
	// ActionWebhookUpdated: an administrator changed a webhook (names of
	// the changed fields only).
	ActionWebhookUpdated Action = "webhook.updated"
	// ActionWebhookDeleted: an administrator deleted a webhook.
	ActionWebhookDeleted Action = "webhook.deleted"
	// ActionWebhookTested: an administrator sent a test event to a webhook.
	ActionWebhookTested Action = "webhook.tested"
)

// Actions of the abuse report handling (since 1.1).
const (
	// ActionAbuseReportClosed: an administrator closed an abuse report.
	ActionAbuseReportClosed Action = "abuse.report_closed"
	// ActionAbuseReportReopened: an administrator reopened an abuse report.
	ActionAbuseReportReopened Action = "abuse.report_reopened"
	// ActionAbuseReported: a recipient reported an abuse from a download
	// page (object: the abuse report).
	ActionAbuseReported Action = "abuse.reported"
	// ActionAbuseThresholdExceeded: a sender exceeded a per-sender abuse
	// threshold (daily volume or transfers, recipients, external quota,
	// invitations); recorded at every occurrence, the mail and webhook
	// being sent once per sender, rule and day. The sender is the actor
	// (never in the details); details carry the rule, the value, the
	// threshold, whether the creation was refused and the transfer.
	ActionAbuseThresholdExceeded Action = "abuse.threshold_exceeded"
	// ActionAbuseUnusualActivity: a sender behaved unusually (unusual
	// volume, large transfer to external addresses, off hours), with the
	// same actor and details as ActionAbuseThresholdExceeded.
	ActionAbuseUnusualActivity Action = "abuse.unusual_activity"
)

// ActorAntivirus is the system actor (store.ActorSystem) of the events of
// the antivirus: the worker's file events, the finalization of files
// while the antivirus is disabled, the alerts and the start-up release.
const ActorAntivirus = "antivirus"

// Reasons of the file.not_scanned event (details "reason").
const (
	// NotScannedTooLarge: the file is above the antivirus limits.
	NotScannedTooLarge = "too_large"
	// NotScannedEncrypted: an encrypted archive the antivirus cannot read.
	NotScannedEncrypted = "encrypted"
	// NotScannedDisabled: the antivirus was disabled (instance engine
	// "none" or tenant switch off) when the file was finalized.
	NotScannedDisabled = "disabled"
)

// Object kinds.
const (
	// ObjectAbuseReport is an abuse report (object ID: its "abr_" ID).
	ObjectAbuseReport = "abuse_report"

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
	// ObjectAccessLink is a "my transfers" access link (object ID: its
	// "sal_" ID, never the token).
	ObjectAccessLink = "access_link"
	// ObjectSenderSession is a "my transfers" session (object ID: its
	// "mts_" ID, never the cookie token).
	ObjectSenderSession = "sender_session"
	// ObjectAPIToken is an API token (object ID: its "tok_" ID, never the
	// secret).
	ObjectAPIToken = "api_token"
	// ObjectSystem is a part of the instance (object ID: "settings",
	// "maintenance", "disk"...).
	ObjectSystem = "system"
	// ObjectMasterKeyRotation is a master key rotation (object ID: its
	// "rot_" ID).
	ObjectMasterKeyRotation = "master_key_rotation"
	// ObjectWebhook is a webhook (object ID: its "whk_" ID, never its URL).
	ObjectWebhook = "webhook"
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
	db        *store.DB
	events    *store.AuditEvents
	publisher events.Publisher
}

// Option configures a [Writer].
type Option func(*Writer)

// WithPublisher publishes every event written as an events.LogAudit event
// on p, once committed. A nil p publishes nothing (the default).
func WithPublisher(p events.Publisher) Option {
	return func(w *Writer) { w.publisher = events.OrDiscard(p) }
}

// New returns a writer appending to the audit log of db.
func New(db *store.DB, opts ...Option) *Writer {
	w := &Writer{db: db, events: db.AuditEvents(), publisher: events.Discard}
	for _, o := range opts {
		o(w)
	}
	return w
}

// OrNew returns w, or a writer of its own over db (publishing nothing)
// when w is nil: the services accept the shared writer of the application
// as an option.
func OrNew(w *Writer, db *store.DB) *Writer {
	if w != nil {
		return w
	}
	return New(db)
}

// Record appends ev in its own transaction.
func (w *Writer) Record(ctx context.Context, ev Event) error {
	row, err := toStore(ev)
	if err != nil {
		return err
	}
	stored, err := w.events.Append(ctx, row)
	if err != nil {
		return fmt.Errorf("audit: record %s: %w", ev.Action, err)
	}
	w.publish(stored)
	return nil
}

// RecordTx appends ev inside the system transaction tx, so that it is
// written if and only if the operation it records commits.
func (w *Writer) RecordTx(ctx context.Context, tx *store.SystemTx, ev Event) error {
	row, err := toStore(ev)
	if err != nil {
		return err
	}
	stored, err := w.events.AppendTx(ctx, tx, row)
	if err != nil {
		return fmt.Errorf("audit: record %s: %w", ev.Action, err)
	}
	tx.AfterCommit(func() { w.publish(stored) })
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
	stored, err := w.events.AppendScopedTx(ctx, tx, row)
	if err != nil {
		return fmt.Errorf("audit: record %s: %w", ev.Action, err)
	}
	tx.AfterCommit(func() { w.publish(stored) })
	return nil
}

// publish publishes the committed audit event row as an events.LogAudit
// event.
func (w *Writer) publish(row store.AuditEvent) {
	w.publisher.Publish(events.Event{
		Type: events.LogAudit, Severity: events.SeverityInfo, OccurredAt: row.At, TenantID: string(row.TenantID),
		Log: &events.LogRecord{
			Stream: events.StreamAudit, Time: row.At, Tenant: string(row.TenantID), Action: row.Action,
			ActorKind: string(row.ActorKind), Actor: row.Actor, IP: row.IP,
			ObjectKind: row.ObjectKind, ObjectID: row.ObjectID, AuditID: row.ID, Details: row.Details,
		},
	})
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

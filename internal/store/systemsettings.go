package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// reasonSystemSettings is the reason of the system settings queries.
const reasonSystemSettings = "instance settings: maintenance, disk alert"

// Bounds of the disk alert threshold, in basis points (1/100 of a
// percent): 0.50 to 0.99, 0.85 by default (spec 19).
const (
	DefaultDiskAlertThresholdBP = 8500
	MinDiskAlertThresholdBP     = 5000
	MaxDiskAlertThresholdBP     = 9900
)

// Levels of the disk alert persisted in the system settings.
const (
	// DiskAlertLevelNormal: the disk usage is below the alert.
	DiskAlertLevelNormal = 0
	// DiskAlertLevelRaised: the disk alert is raised (and was notified).
	DiskAlertLevelRaised = 1
)

// MaxMaintenanceMessageRunes bounds each maintenance message, in
// characters.
const MaxMaintenanceMessageRunes = 500

// systemSettingsColumns is the column list read by the system settings
// queries.
const systemSettingsColumns = `disk_alert_threshold_bp, alert_email, alert_email_language, maintenance_enabled,
	maintenance_since, maintenance_message, disk_alert_level, disk_alert_changed_at, disk_alert_mailed_at, updated_at`

// Statements of the SystemSettings repository. The table holds exactly one
// row, id 1, created by the migration.
var (
	qSystemSettingsGet = systemQuery(
		`SELECT `+systemSettingsColumns+` FROM system_settings WHERE id = 1`,
		reasonSystemSettings)
	// qSystemSettingsLock touches the row first, so that a concurrent
	// update waits for this transaction on PostgreSQL (READ COMMITTED)
	// instead of overwriting it; SQLite write transactions are already
	// serialized.
	qSystemSettingsLock = systemQuery(
		`UPDATE system_settings SET updated_at = updated_at WHERE id = 1`,
		reasonSystemSettings)
	qSystemSettingsUpdate = systemQuery(
		`UPDATE system_settings SET disk_alert_threshold_bp = ?, alert_email = ?, alert_email_language = ?,
		maintenance_enabled = ?, maintenance_since = ?, maintenance_message = ?, updated_at = ? WHERE id = 1`,
		reasonSystemSettings)
	qSystemSettingsDiskLevel = systemQuery(
		`UPDATE system_settings SET disk_alert_level = ?, disk_alert_changed_at = ? WHERE id = 1 AND disk_alert_level = ?`,
		reasonSystemSettings)
	// qSystemSettingsClaimMail takes the disk alert mail slot when the
	// last mail is old enough, or dated after now (a clock set back).
	qSystemSettingsClaimMail = systemQuery(
		`UPDATE system_settings SET disk_alert_mailed_at = ? WHERE id = 1 AND `+
			`(disk_alert_mailed_at IS NULL OR disk_alert_mailed_at <= ? OR disk_alert_mailed_at > ?)`,
		reasonSystemSettings)
)

// SystemSettingsRow holds the instance settings editable at runtime by the
// super admin, and the persisted disk alert level.
type SystemSettingsRow struct {
	// DiskAlertThresholdBP is the disk usage raising the alert, in basis
	// points (MinDiskAlertThresholdBP to MaxDiskAlertThresholdBP).
	DiskAlertThresholdBP int
	// AlertEmail is the extra recipient of the disk alert, "" for none.
	// The store normalizes it ([NormalizeEmail]).
	AlertEmail string
	// AlertEmailLanguage is the language of the mails sent to AlertEmail;
	// required with it, cleared without it.
	AlertEmailLanguage string
	// MaintenanceEnabled is the maintenance mode chosen by the super admin
	// (the environment may force it on regardless).
	MaintenanceEnabled bool
	// MaintenanceSince is when the super admin enabled the maintenance
	// mode, the zero time when it is off.
	MaintenanceSince time.Time
	// MaintenanceMessage maps a supported language to its maintenance
	// message (1 to MaxMaintenanceMessageRunes characters); empty for
	// none. Get never returns nil.
	MaintenanceMessage map[string]string
	// DiskAlertLevel is DiskAlertLevelNormal or DiskAlertLevelRaised.
	// UpdateTx never changes it: use [SystemSettings.CompareAndSetDiskLevel].
	DiskAlertLevel int
	// DiskAlertChangedAt is the last change of DiskAlertLevel, the zero
	// time when it never changed.
	DiskAlertChangedAt time.Time
	// DiskAlertMailedAt is the last time the disk alert was mailed, the
	// zero time when never. UpdateTx never changes it: use
	// [SystemSettings.ClaimDiskAlertMail].
	DiskAlertMailedAt time.Time
	// UpdatedAt is the last change of the settings, set by UpdateTx; the
	// Unix epoch until the first change.
	UpdatedAt time.Time
}

// SystemSettings is the repository of the instance settings. Its
// operations are system-scoped. Obtain it with [DB.SystemSettings].
type SystemSettings struct {
	db *DB
}

// SystemSettings returns the system settings repository.
func (db *DB) SystemSettings() *SystemSettings { return &SystemSettings{db: db} }

// scanSystemSettings reads one row of systemSettingsColumns.
func scanSystemSettings(sc interface{ Scan(...any) error }) (SystemSettingsRow, error) {
	var (
		s                      SystemSettingsRow
		email, lang            sql.NullString
		since, changed, mailed sql.NullInt64
		message                string
		updated                int64
	)
	if err := sc.Scan(&s.DiskAlertThresholdBP, &email, &lang, &s.MaintenanceEnabled,
		&since, &message, &s.DiskAlertLevel, &changed, &mailed, &updated); err != nil {
		return SystemSettingsRow{}, err
	}
	s.AlertEmail, s.AlertEmailLanguage = email.String, lang.String
	s.MaintenanceSince, s.DiskAlertChangedAt = nullMillis(since), nullMillis(changed)
	s.DiskAlertMailedAt = nullMillis(mailed)
	s.UpdatedAt = fromMillis(updated)
	if err := json.Unmarshal([]byte(message), &s.MaintenanceMessage); err != nil {
		return SystemSettingsRow{}, err
	}
	if s.MaintenanceMessage == nil {
		s.MaintenanceMessage = map[string]string{}
	}
	return s, nil
}

// normalizeSystemSettings validates the fields UpdateTx writes and
// normalizes the alert address. It returns the encoded maintenance
// messages.
func normalizeSystemSettings(s *SystemSettingsRow) (string, error) {
	if s.DiskAlertThresholdBP < MinDiskAlertThresholdBP || s.DiskAlertThresholdBP > MaxDiskAlertThresholdBP {
		return "", invalid("disk alert threshold must be %d to %d basis points", MinDiskAlertThresholdBP, MaxDiskAlertThresholdBP)
	}
	if s.AlertEmail == "" {
		s.AlertEmailLanguage = ""
	} else {
		email, err := NormalizeEmail(s.AlertEmail)
		if err != nil {
			return "", invalid("malformed alert email")
		}
		s.AlertEmail = email
		if !tenant.IsLanguage(s.AlertEmailLanguage) {
			return "", invalid("unsupported alert email language")
		}
	}
	if !s.MaintenanceEnabled {
		s.MaintenanceSince = time.Time{}
	}
	if s.MaintenanceMessage == nil {
		s.MaintenanceMessage = map[string]string{}
	}
	for lang, msg := range s.MaintenanceMessage {
		if !tenant.IsLanguage(lang) {
			return "", invalid("unsupported maintenance message language")
		}
		if msg == "" || !validText(msg, MaxMaintenanceMessageRunes, false) {
			return "", invalid("maintenance message must hold 1 to %d characters", MaxMaintenanceMessageRunes)
		}
	}
	doc, _ := json.Marshal(s.MaintenanceMessage) // a map[string]string always marshals
	return string(doc), nil
}

// Get returns the instance settings.
func (r *SystemSettings) Get(ctx context.Context) (SystemSettingsRow, error) {
	var s SystemSettingsRow
	err := r.db.systemScope(reasonSystemSettings).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		s, err = scanSystemSettings(tx.QueryRow(ctx, qSystemSettingsGet))
		return err
	})
	if err != nil {
		return SystemSettingsRow{}, wrap("get system settings", err)
	}
	return s, nil
}

// UpdateTx changes the instance settings in one transaction: it reads the
// current settings, locked against concurrent updates, and calls fn with
// the transaction and a copy to modify. fn may record an audit event in tx
// (audit.Writer.RecordTx), so that the change and its audit commit
// together; an error from fn rolls everything back and is returned as is.
// The modified copy is then validated and written: the threshold, the
// alert address and language, the maintenance mode, its start and its
// messages. MaintenanceSince is the store's clock when the maintenance
// mode is turned on without one, and cleared when it is off; UpdatedAt is
// the store's clock; DiskAlertLevel, DiskAlertChangedAt and
// DiskAlertMailedAt are left unchanged. It returns the settings as stored, or ErrInvalid for an
// invalid field.
func (r *SystemSettings) UpdateTx(ctx context.Context, fn func(tx *SystemTx, s *SystemSettingsRow) error) (SystemSettingsRow, error) {
	if fn == nil {
		return SystemSettingsRow{}, invalid("update needs a function")
	}
	var out SystemSettingsRow
	err := r.db.systemScope(reasonSystemSettings).Tx(ctx, func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qSystemSettingsLock)
		if err != nil {
			return err
		}
		if err := expectOne(res); err != nil {
			return err
		}
		cur, err := scanSystemSettings(tx.QueryRow(ctx, qSystemSettingsGet))
		if err != nil {
			return err
		}
		next := cur
		next.MaintenanceMessage = make(map[string]string, len(cur.MaintenanceMessage))
		for k, v := range cur.MaintenanceMessage {
			next.MaintenanceMessage[k] = v
		}
		if err := fn(tx, &next); err != nil {
			return err
		}
		now := r.db.now()
		if next.MaintenanceEnabled && next.MaintenanceSince.IsZero() {
			next.MaintenanceSince = now
		}
		message, err := normalizeSystemSettings(&next)
		if err != nil {
			return err
		}
		var since any
		if !next.MaintenanceSince.IsZero() {
			since = toMillis(next.MaintenanceSince)
		}
		if _, err := tx.Exec(ctx, qSystemSettingsUpdate, next.DiskAlertThresholdBP, nullText(next.AlertEmail),
			nullText(next.AlertEmailLanguage), next.MaintenanceEnabled, since, message, toMillis(now)); err != nil {
			return err
		}
		next.DiskAlertLevel, next.DiskAlertChangedAt = cur.DiskAlertLevel, cur.DiskAlertChangedAt
		next.DiskAlertMailedAt = cur.DiskAlertMailedAt
		next.UpdatedAt = fromMillis(toMillis(now))
		if !next.MaintenanceSince.IsZero() {
			next.MaintenanceSince = fromMillis(toMillis(next.MaintenanceSince))
		}
		out = next
		return nil
	})
	if err != nil {
		return SystemSettingsRow{}, wrap("update system settings", err)
	}
	return out, nil
}

// CompareAndSetDiskLevel sets the disk alert level to newLevel, and its
// change time to now (the store's clock when zero), only if it is still
// oldLevel. It reports whether it did: of concurrent callers seeing the
// same crossing, exactly one wins and notifies. It returns ErrInvalid for
// a level other than DiskAlertLevelNormal and DiskAlertLevelRaised.
func (r *SystemSettings) CompareAndSetDiskLevel(ctx context.Context, oldLevel, newLevel int, now time.Time) (bool, error) {
	for _, l := range []int{oldLevel, newLevel} {
		if l != DiskAlertLevelNormal && l != DiskAlertLevelRaised {
			return false, invalid("unknown disk alert level")
		}
	}
	won := false
	err := r.db.systemScope(reasonSystemSettings).Tx(ctx, func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qSystemSettingsDiskLevel, newLevel, toMillis(r.db.orNow(now)), oldLevel)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		won = n == 1
		return err
	})
	if err != nil {
		return false, wrap("set disk alert level", err)
	}
	return won, nil
}

// ClaimDiskAlertMail records now (the store's clock when zero) as the last
// mail of the disk alert, only if the previous one is at least minInterval
// older, or dated after now (a clock set back). It reports whether it did:
// the caller mails the alert only then, so that the alert mails stay
// minInterval apart whatever the number of crossings, even when a super
// admin toggles the threshold. It returns ErrInvalid for a negative
// minInterval.
func (r *SystemSettings) ClaimDiskAlertMail(ctx context.Context, now time.Time, minInterval time.Duration) (bool, error) {
	if minInterval < 0 {
		return false, invalid("negative disk alert mail interval")
	}
	now = r.db.orNow(now)
	won := false
	err := r.db.systemScope(reasonSystemSettings).Tx(ctx, func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qSystemSettingsClaimMail, toMillis(now), toMillis(now.Add(-minInterval)), toMillis(now))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		won = n == 1
		return err
	})
	if err != nil {
		return false, wrap("claim disk alert mail", err)
	}
	return won, nil
}

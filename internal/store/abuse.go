package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	// The runtime image has no zoneinfo (scratch): the IANA database is
	// embedded so that the tenant time zones of the abuse settings always
	// load, in ValidateTimeZone as in the detection (internal/abuse).
	_ "time/tzdata"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Limits and defaults of the abuse detection settings (spec 15, data
// model 2.5). They mirror the checks of tenant_abuse_settings.
const (
	// MinUnusualVolumePct and MaxUnusualVolumePct bound the unusual
	// volume factor, stored as an integer percent (API factor 1.5 to 100).
	MinUnusualVolumePct = 150
	MaxUnusualVolumePct = 10000
	// MaxUnusualMinHistoryDays bounds the days of history a sender needs
	// before the unusual volume rule applies (at least 1).
	MaxUnusualMinHistoryDays = 30
	// MaxOfficeMinute is the end of the day, "24:00": office hours are
	// minutes of the local day, the start from 0 to MaxOfficeMinute - 1,
	// the end from 1 to MaxOfficeMinute, the start before the end.
	MaxOfficeMinute = 1440
	// AllWeekdays is the office weekday mask of the seven days (bit 0 =
	// Monday ... bit 6 = Sunday).
	AllWeekdays = 127
	// MaxAbuseTimeZoneLen bounds the IANA time zone name, in characters.
	MaxAbuseTimeZoneLen = 64
	// MaxInvitationsPerInviterLimit bounds the per-inviter invitation
	// limit (at least 1).
	MaxInvitationsPerInviterLimit = 1000

	// DefaultUnusualMinHistoryDays, DefaultOfficeWeekdays (Monday to
	// Friday), DefaultAbuseTimeZone and DefaultMaxInvitationsPerInviter
	// are the column defaults, seeded for every tenant.
	DefaultUnusualMinHistoryDays    = 7
	DefaultOfficeWeekdays           = 31
	DefaultAbuseTimeZone            = "UTC"
	DefaultMaxInvitationsPerInviter = 20

	// MaxSenderHistoryRows bounds the rows [Transfers.SenderHistory]
	// returns (decision 6 of step 8: a capped scan, newest first).
	MaxSenderHistoryRows = 10_000
	// AbuseAlertRetention is how long a deduplication row of abuse_alerts
	// is kept after its creation (data model 5.1): the deduplication only
	// needs the current local day.
	AbuseAlertRetention = 48 * time.Hour
)

// AbuseRule names a detection rule, as stored in abuse_alerts.rule.
type AbuseRule string

// Detection rules (spec 15).
const (
	// AbuseRuleDailyBytes is the daily volume per sender.
	AbuseRuleDailyBytes AbuseRule = "daily_bytes"
	// AbuseRuleDailyTransfers is the daily number of transfers per sender.
	AbuseRuleDailyTransfers AbuseRule = "daily_transfers"
	// AbuseRuleRecipients is the number of recipients of one transfer.
	AbuseRuleRecipients AbuseRule = "recipients"
	// AbuseRuleUnusualVolume is a daily volume well above the sender's
	// 30-day average.
	AbuseRuleUnusualVolume AbuseRule = "unusual_volume"
	// AbuseRuleLargeExternal is a large transfer to an external recipient.
	AbuseRuleLargeExternal AbuseRule = "large_external"
	// AbuseRuleOffHours is a transfer created outside office hours.
	AbuseRuleOffHours AbuseRule = "off_hours"
	// AbuseRuleInvitations is the per-inviter invitation limit.
	AbuseRuleInvitations AbuseRule = "invitations"
	// AbuseRuleExternalQuota is the daily deposit quota of an external
	// address.
	AbuseRuleExternalQuota AbuseRule = "external_quota"
)

// Valid reports whether r is a known detection rule.
func (r AbuseRule) Valid() bool {
	switch r {
	case AbuseRuleDailyBytes, AbuseRuleDailyTransfers, AbuseRuleRecipients, AbuseRuleUnusualVolume,
		AbuseRuleLargeExternal, AbuseRuleOffHours, AbuseRuleInvitations, AbuseRuleExternalQuota:
		return true
	}
	return false
}

// abuseSettingsColumns is the column list read by the abuse settings
// queries.
const abuseSettingsColumns = `max_daily_bytes_per_sender, max_daily_transfers_per_sender, max_recipients_per_transfer, ` +
	`block_on_exceed, unusual_volume_pct, unusual_min_history_days, large_external_transfer_bytes, ` +
	`office_start_minute, office_end_minute, office_weekdays, time_zone, max_invitations_per_inviter, ` +
	`external_max_daily_bytes, external_max_daily_deposits, updated_at, updated_by`

// Statements of the AbuseSettings, AbuseAlerts and sender activity
// operations. All of them are single-table tenant queries.
var (
	qAbuseSettingsGet = tenantQuery(
		`SELECT ` + abuseSettingsColumns + ` FROM tenant_abuse_settings WHERE tenant_id = ?`)
	qAbuseSettingsUpdate = tenantQuery(
		`UPDATE tenant_abuse_settings SET max_daily_bytes_per_sender = ?, max_daily_transfers_per_sender = ?,
		max_recipients_per_transfer = ?, block_on_exceed = ?, unusual_volume_pct = ?, unusual_min_history_days = ?,
		large_external_transfer_bytes = ?, office_start_minute = ?, office_end_minute = ?, office_weekdays = ?,
		time_zone = ?, max_invitations_per_inviter = ?, external_max_daily_bytes = ?, external_max_daily_deposits = ?,
		updated_at = ?, updated_by = ?
		WHERE tenant_id = ?`)
	qAbuseSettingsInsert = tenantQuery(
		`INSERT INTO tenant_abuse_settings (` + abuseSettingsColumns + `, tenant_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)

	// The validator refuses ON CONFLICT: the deduplication is an
	// increment, then an insert when no row was there, under the tenant
	// lock.
	qAbuseAlertIncrement = tenantQuery(
		`UPDATE abuse_alerts SET attempts = attempts + 1
		WHERE tenant_id = ? AND sender_email = ? AND rule = ? AND day = ? AND blocked = ?`)
	qAbuseAlertInsert = tenantQuery(
		`INSERT INTO abuse_alerts (tenant_id, sender_email, rule, day, blocked, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
	qAbuseAlertDeleteByEmail = tenantQuery(
		`DELETE FROM abuse_alerts WHERE tenant_id = ? AND sender_email = ?`)
	// qAbuseAlertPurge deletes in one statement: the table holds at most
	// two rows (alert-only and blocked) per sender, rule and day over
	// AbuseAlertRetention.
	qAbuseAlertPurge = tenantQuery(
		`DELETE FROM abuse_alerts WHERE tenant_id = ? AND created_at < ?`)

	// qSenderActivity sums, per sender kind, the transfers of a sender
	// created or extended in a window, each counted once whatever its
	// status, through transfers_sender_created_idx. The CAST keeps an
	// integer result on PostgreSQL (sum of BIGINT is NUMERIC).
	qSenderActivity = tenantQuery(
		`SELECT sender_kind, CAST(sum(total_bytes) AS BIGINT), count(*) FROM transfers
		WHERE tenant_id = ? AND sender_email = ?
		AND ((created_at >= ? AND created_at < ?) OR (extended_at >= ? AND extended_at < ?))
		GROUP BY sender_kind`)
	// qSenderHistory lists the creations of a sender since a time, newest
	// first, through transfers_sender_created_idx.
	qSenderHistory = tenantQuery(
		`SELECT created_at, total_bytes FROM transfers WHERE tenant_id = ? AND sender_email = ? AND created_at >= ?
		ORDER BY created_at DESC, id DESC LIMIT ?`)
)

// AbuseSettings are the abuse detection settings of a tenant (spec 15,
// OpenAPI AbuseThresholds). A nil threshold disables its rule.
type AbuseSettings struct {
	// MaxDailyBytesPerSender bounds the volume one sender creates per day.
	MaxDailyBytesPerSender *int64
	// MaxDailyTransfersPerSender bounds the transfers one sender creates
	// per day.
	MaxDailyTransfersPerSender *int
	// MaxRecipientsPerTransfer bounds the recipients of one transfer.
	MaxRecipientsPerTransfer *int
	// BlockOnExceed refuses a transfer over a per-sender limit or an
	// external quota instead of only alerting.
	BlockOnExceed bool
	// UnusualVolumePct is the unusual volume factor in percent
	// (MinUnusualVolumePct to MaxUnusualVolumePct).
	UnusualVolumePct *int
	// UnusualMinHistoryDays is the days of activity a sender needs before
	// the unusual volume rule applies (1 to MaxUnusualMinHistoryDays).
	UnusualMinHistoryDays int
	// LargeExternalTransferBytes is the size from which a transfer to an
	// external recipient raises an alert.
	LargeExternalTransferBytes *int64
	// OfficeStartMinute and OfficeEndMinute are the office hours, in
	// minutes of the local day (see MaxOfficeMinute); both nil disables
	// the off-hours rule.
	OfficeStartMinute *int
	OfficeEndMinute   *int
	// OfficeWeekdays is the mask of the working days, bit 0 = Monday ...
	// bit 6 = Sunday (0 to AllWeekdays).
	OfficeWeekdays int
	// TimeZone is the IANA time zone of the day boundary and of the office
	// hours (1 to MaxAbuseTimeZoneLen characters; the service checks that
	// it loads).
	TimeZone string
	// MaxInvitationsPerInviter bounds the invitations an internal user
	// issues per rolling hour (1 to MaxInvitationsPerInviterLimit).
	MaxInvitationsPerInviter int
	// ExternalMaxDailyBytes and ExternalMaxDailyDeposits bound what an
	// external address (invited or replying) deposits per day.
	ExternalMaxDailyBytes    *int64
	ExternalMaxDailyDeposits *int
	// UpdatedAt is the time of the last change, the zero time when the
	// settings were never edited.
	UpdatedAt time.Time
	// UpdatedBy is the administrator ID of the last change, "" when none.
	UpdatedBy string
}

// DefaultAbuseSettings returns the settings every tenant starts with:
// every threshold disabled, a 7-day history, office days Monday to Friday
// (without office hours), UTC, and 20 invitations per inviter and hour.
func DefaultAbuseSettings() AbuseSettings {
	return AbuseSettings{
		UnusualMinHistoryDays:    DefaultUnusualMinHistoryDays,
		OfficeWeekdays:           DefaultOfficeWeekdays,
		TimeZone:                 DefaultAbuseTimeZone,
		MaxInvitationsPerInviter: DefaultMaxInvitationsPerInviter,
	}
}

// positive64 reports whether p is nil or points to a positive value.
func positive64(p *int64) bool { return p == nil || *p > 0 }

// positive32 reports whether p is nil or points to a value from 1 to the
// largest INTEGER of PostgreSQL.
func positive32(p *int) bool { return p == nil || (*p > 0 && *p <= math.MaxInt32) }

// Validate checks s against the constraints of tenant_abuse_settings and
// returns ErrInvalid, naming the field but never its value, otherwise.
// UpdatedAt is not checked.
func (s AbuseSettings) Validate() error {
	switch {
	case !positive64(s.MaxDailyBytesPerSender):
		return invalid("max daily bytes per sender must be positive")
	case !positive32(s.MaxDailyTransfersPerSender):
		return invalid("max daily transfers per sender must be positive")
	case !positive32(s.MaxRecipientsPerTransfer):
		return invalid("max recipients per transfer must be positive")
	case s.UnusualVolumePct != nil && (*s.UnusualVolumePct < MinUnusualVolumePct || *s.UnusualVolumePct > MaxUnusualVolumePct):
		return invalid("unusual volume percent must be between %d and %d", MinUnusualVolumePct, MaxUnusualVolumePct)
	case s.UnusualMinHistoryDays < 1 || s.UnusualMinHistoryDays > MaxUnusualMinHistoryDays:
		return invalid("unusual minimum history must be between 1 and %d days", MaxUnusualMinHistoryDays)
	case !positive64(s.LargeExternalTransferBytes):
		return invalid("large external transfer size must be positive")
	case (s.OfficeStartMinute == nil) != (s.OfficeEndMinute == nil):
		return invalid("office hours need both a start and an end")
	case s.OfficeStartMinute != nil && (*s.OfficeStartMinute < 0 || *s.OfficeEndMinute > MaxOfficeMinute ||
		*s.OfficeStartMinute >= *s.OfficeEndMinute):
		return invalid("office hours must be minutes of the day, the start before the end")
	case s.OfficeWeekdays < 0 || s.OfficeWeekdays > AllWeekdays:
		return invalid("office weekdays must be a mask of the seven days")
	case s.TimeZone == "" || !validText(s.TimeZone, MaxAbuseTimeZoneLen, true):
		return invalid("time zone must be a name of 1 to %d characters", MaxAbuseTimeZoneLen)
	case s.MaxInvitationsPerInviter < 1 || s.MaxInvitationsPerInviter > MaxInvitationsPerInviterLimit:
		return invalid("max invitations per inviter must be between 1 and %d", MaxInvitationsPerInviterLimit)
	case !positive64(s.ExternalMaxDailyBytes):
		return invalid("external max daily bytes must be positive")
	case !positive32(s.ExternalMaxDailyDeposits):
		return invalid("external max daily deposits must be positive")
	case !validUpdatedBy(s.UpdatedBy):
		return invalid("updater must be an administrator id")
	}
	return nil
}

// ValidateTimeZone checks the time zone of the abuse settings: an IANA
// name of 1 to MaxAbuseTimeZoneLen characters on one line that
// time.LoadLocation loads, never "Local" (the zone of the server, which
// would make the day boundary depend on the host). It returns ErrInvalid
// otherwise, without quoting name. [AbuseSettings.Validate] only checks the
// length, so that settings stored before a zone left the IANA database
// still read; the administration checks the zone with this function.
func ValidateTimeZone(name string) error {
	if name == "" || name == "Local" || !validText(name, MaxAbuseTimeZoneLen, true) {
		return invalid("time zone must be an IANA name of 1 to %d characters", MaxAbuseTimeZoneLen)
	}
	if _, err := time.LoadLocation(name); err != nil {
		return invalid("unknown time zone")
	}
	return nil
}

// nullInt64 maps a nil pointer to SQL NULL.
func nullInt64(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// int64Ptr reads an optional integer: nil for SQL NULL.
func int64Ptr(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

// AbuseSettingsRepo is the tenant-scoped repository of the abuse
// detection settings. Obtain it with [DB.AbuseSettings].
type AbuseSettingsRepo struct {
	db *DB
}

// AbuseSettings returns the abuse settings repository.
func (db *DB) AbuseSettings() *AbuseSettingsRepo { return &AbuseSettingsRepo{db: db} }

// readAbuseSettings reads the settings of the tenant tx is bound to, the
// defaults when the tenant has no row.
func readAbuseSettings(ctx context.Context, tx *ScopedTx) (AbuseSettings, error) {
	var (
		s                                    AbuseSettings
		maxBytes, large, extBytes            sql.NullInt64
		maxTransfers, maxRcpts, pct, extDeps sql.NullInt64
		start, end                           sql.NullInt64
		updated                              int64
	)
	err := tx.QueryRow(ctx, qAbuseSettingsGet).Scan(&maxBytes, &maxTransfers, &maxRcpts, &s.BlockOnExceed, &pct,
		&s.UnusualMinHistoryDays, &large, &start, &end, &s.OfficeWeekdays, &s.TimeZone, &s.MaxInvitationsPerInviter,
		&extBytes, &extDeps, &updated, &s.UpdatedBy)
	if errors.Is(err, ErrNotFound) {
		return DefaultAbuseSettings(), nil
	}
	if err != nil {
		return AbuseSettings{}, err
	}
	s.MaxDailyBytesPerSender, s.LargeExternalTransferBytes, s.ExternalMaxDailyBytes = int64Ptr(maxBytes), int64Ptr(large), int64Ptr(extBytes)
	s.MaxDailyTransfersPerSender, s.MaxRecipientsPerTransfer = intPtr(maxTransfers), intPtr(maxRcpts)
	s.UnusualVolumePct, s.ExternalMaxDailyDeposits = intPtr(pct), intPtr(extDeps)
	s.OfficeStartMinute, s.OfficeEndMinute = intPtr(start), intPtr(end)
	if updated != 0 {
		s.UpdatedAt = fromMillis(updated)
	}
	return s, nil
}

// Get returns the abuse settings of tenant tid: [DefaultAbuseSettings]
// when the tenant has no row (never an error for that). It returns
// ErrInvalid for a malformed tenant ID.
func (r *AbuseSettingsRepo) Get(ctx context.Context, tid tenant.ID) (AbuseSettings, error) {
	return readScoped(ctx, r.db, tid, "get abuse settings", func(tx *ScopedTx) (AbuseSettings, error) {
		return readAbuseSettings(ctx, tx)
	})
}

// GetTx is Get inside tx, for the tenant tx is bound to: a transfer
// creation evaluates the thresholds in its own transaction. After an
// error, the caller must abort the transaction.
func (r *AbuseSettingsRepo) GetTx(ctx context.Context, tx *ScopedTx) (AbuseSettings, error) {
	s, err := readAbuseSettings(ctx, tx)
	if err != nil {
		return AbuseSettings{}, wrap("get abuse settings", err)
	}
	return s, nil
}

// Put stores s as the abuse settings of tenant tid, inserting the row if
// the tenant has none, and returns the stored settings. UpdatedAt is set
// to s.UpdatedAt, or the store's clock when zero (millisecond precision).
// It returns ErrInvalid, changing nothing, when [AbuseSettings.Validate]
// rejects s, and ErrNotFound when the tenant does not exist.
func (r *AbuseSettingsRepo) Put(ctx context.Context, tid tenant.ID, s AbuseSettings) (AbuseSettings, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return AbuseSettings{}, err
	}
	if err := s.Validate(); err != nil {
		return AbuseSettings{}, err
	}
	s.UpdatedAt = r.db.orNow(s.UpdatedAt).UTC().Truncate(time.Millisecond)
	args := []any{
		nullInt64(s.MaxDailyBytesPerSender), nullInt(s.MaxDailyTransfersPerSender), nullInt(s.MaxRecipientsPerTransfer),
		s.BlockOnExceed, nullInt(s.UnusualVolumePct), s.UnusualMinHistoryDays, nullInt64(s.LargeExternalTransferBytes),
		nullInt(s.OfficeStartMinute), nullInt(s.OfficeEndMinute), s.OfficeWeekdays, s.TimeZone,
		s.MaxInvitationsPerInviter, nullInt64(s.ExternalMaxDailyBytes), nullInt(s.ExternalMaxDailyDeposits),
		toMillis(s.UpdatedAt), s.UpdatedBy,
	}
	err := writeScoped(ctx, r.db, tid, "put abuse settings", func(tx *ScopedTx) error {
		return upsert(ctx, tx, qAbuseSettingsUpdate, args, qAbuseSettingsInsert, args)
	})
	if err != nil {
		return AbuseSettings{}, err
	}
	return s, nil
}

// AbuseAlerts is the tenant-scoped repository of the abuse alert
// deduplication rows: one alert mail and webhook per sender, rule, local
// day and kind (alert-only or blocked), with the count of the occurrences
// of the day (decision D28, revised; the alerts themselves are audit
// events). Obtain it with [DB.AbuseAlerts].
type AbuseAlerts struct {
	db *DB
}

// AbuseAlerts returns the abuse alert deduplication repository.
func (db *DB) AbuseAlerts() *AbuseAlerts { return &AbuseAlerts{db: db} }

// validAlertDay reports whether day is a "YYYY-MM-DD" calendar date.
func validAlertDay(day string) bool {
	if len(day) != len(time.DateOnly) {
		return false
	}
	_, err := time.Parse(time.DateOnly, day)
	return err == nil
}

// TryInsertTx records, inside tx and under the tenant lock, that the rule
// was exceeded by the sender address senderEmail (normalized) on the local
// day day ("YYYY-MM-DD" in the tenant time zone), at now (the store's clock
// when zero); blocked tells a refused creation from an alert-only finding,
// which are deduplicated separately. It reports whether the row was
// inserted: false means that the same sender, rule, day and kind were
// already recorded, the attempts of that row are incremented, and the
// caller sends no mail or webhook again. It returns ErrInvalid for a
// malformed address, an unknown rule or a malformed day. After an error,
// the caller must abort the transaction.
func (r *AbuseAlerts) TryInsertTx(ctx context.Context, tx *ScopedTx, senderEmail string, rule AbuseRule, day string, blocked bool, now time.Time) (bool, error) {
	inserted, err := func() (bool, error) {
		email, err := NormalizeEmail(senderEmail)
		if err != nil {
			return false, err
		}
		if !rule.Valid() {
			return false, invalid("unknown abuse rule")
		}
		if !validAlertDay(day) {
			return false, invalid("day must be a YYYY-MM-DD date")
		}
		if err := tx.lock(ctx); err != nil {
			return false, err
		}
		n, err := execCount(ctx, tx, qAbuseAlertIncrement, email, string(rule), day, blocked)
		if err != nil || n > 0 {
			return false, err
		}
		_, err = tx.Exec(ctx, qAbuseAlertInsert, email, string(rule), day, blocked, toMillis(r.db.orNow(now)))
		return err == nil, err
	}()
	if err != nil {
		return false, wrap("insert abuse alert", err)
	}
	return inserted, nil
}

// DeleteByEmailTx deletes, inside tx, every deduplication row of the
// tenant tx is bound to for the sender address email (normalized), and
// returns how many it deleted (GDPR erasure, data model 5.2). It returns
// ErrInvalid for a malformed address. After an error, the caller must
// abort the transaction.
func (r *AbuseAlerts) DeleteByEmailTx(ctx context.Context, tx *ScopedTx, email string) (int64, error) {
	return deleteByEmail(ctx, tx, "delete abuse alerts by address", qAbuseAlertDeleteByEmail, email)
}

// Purge deletes the deduplication rows of tenant tid created strictly
// before now - AbuseAlertRetention (data model 5.1) and returns how many
// it deleted.
func (r *AbuseAlerts) Purge(ctx context.Context, tid tenant.ID, now time.Time) (int64, error) {
	var n int64
	err := writeScoped(ctx, r.db, tid, "purge abuse alerts", func(tx *ScopedTx) error {
		var err error
		n, err = execCount(ctx, tx, qAbuseAlertPurge, toMillis(now.Add(-AbuseAlertRetention)))
		return err
	})
	return n, err
}

// SenderTransferVolume is one transfer of a sender in
// [Transfers.SenderHistory].
type SenderTransferVolume struct {
	// CreatedAt is the creation time of the transfer.
	CreatedAt time.Time
	// TotalBytes is its declared size.
	TotalBytes int64
}

// senderActivity sums the transfers of email (normalized) in the window
// [start, end) for the kinds (all when empty), inside tx.
func senderActivity(ctx context.Context, tx *ScopedTx, email string, start, end time.Time, kinds []DepositorKind) (int64, int, error) {
	if !start.Before(end) {
		return 0, 0, invalid("the activity window must end after its start")
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, 0, err
	}
	s, e := toMillis(start), toMillis(end)
	rows, err := tx.Query(ctx, qSenderActivity, email, s, e, s, e)
	if err != nil {
		return 0, 0, err
	}
	type group struct {
		kind  DepositorKind
		bytes int64
		count int
	}
	groups, err := collect(rows, func(r *sql.Rows) (group, error) {
		var g group
		err := r.Scan(&g.kind, &g.bytes, &g.count)
		return g, err
	})
	if err != nil {
		return 0, 0, err
	}
	var (
		bytes int64
		count int
	)
	for _, g := range groups {
		if len(kinds) == 0 || containsKind(kinds, g.kind) {
			bytes += g.bytes
			count += g.count
		}
	}
	return bytes, count, nil
}

// containsKind reports whether kinds holds k.
func containsKind(kinds []DepositorKind, k DepositorKind) bool {
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}

// SenderActivityTx returns, inside tx, the declared volume and the number
// of the transfers of the tenant tx is bound to sent by the address email
// (normalized) that were created, or extended, at or after start and
// before end, whatever their status: a transfer both created and extended
// in the window counts once (decision 6 of step 8). kinds restricts the
// sender kinds counted (nil or empty: every kind), for instance
// DepositorExternal for the external quota. The window is computed by the
// caller (a local day of the tenant time zone). It returns ErrInvalid for
// a malformed address or an empty window. After an error, the caller must
// abort the transaction.
func (r *Transfers) SenderActivityTx(ctx context.Context, tx *ScopedTx, email string, start, end time.Time, kinds []DepositorKind) (int64, int, error) {
	bytes, count, err := senderActivity(ctx, tx, email, start, end, kinds)
	if err != nil {
		return 0, 0, wrap("sum sender activity", err)
	}
	return bytes, count, nil
}

// SenderActivity is [Transfers.SenderActivityTx] for tenant tid in its own
// read transaction. It returns ErrInvalid for a malformed tenant ID too.
func (r *Transfers) SenderActivity(ctx context.Context, tid tenant.ID, email string, start, end time.Time, kinds []DepositorKind) (int64, int, error) {
	type sums struct {
		bytes int64
		count int
	}
	v, err := readScoped(ctx, r.db, tid, "sum sender activity", func(tx *ScopedTx) (sums, error) {
		b, c, err := senderActivity(ctx, tx, email, start, end, kinds)
		return sums{b, c}, err
	})
	return v.bytes, v.count, err
}

// SenderHistory returns the creation time and declared size of the
// transfers of tenant tid sent by the address email (normalized) and
// created at or after since, whatever their status, newest first, at most
// limit of them (1 to MaxSenderHistoryRows): the history of the unusual
// volume rule, which the caller buckets per local day. It returns
// ErrInvalid for a malformed tenant ID, address or limit.
func (r *Transfers) SenderHistory(ctx context.Context, tid tenant.ID, email string, since time.Time, limit int) ([]SenderTransferVolume, error) {
	if limit < 1 || limit > MaxSenderHistoryRows {
		return nil, invalid("limit must be between 1 and %d", MaxSenderHistoryRows)
	}
	if _, err := r.db.Scoped(tid); err != nil {
		return nil, err
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	return readScoped(ctx, r.db, tid, "list sender history", func(tx *ScopedTx) ([]SenderTransferVolume, error) {
		rows, err := tx.Query(ctx, qSenderHistory, email, toMillis(since), limit)
		if err != nil {
			return nil, err
		}
		return collect(rows, func(r *sql.Rows) (SenderTransferVolume, error) {
			var (
				v       SenderTransferVolume
				created int64
			)
			err := r.Scan(&created, &v.TotalBytes)
			v.CreatedAt = fromMillis(created)
			return v, err
		})
	})
}

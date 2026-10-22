package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Reasons of the usage and quota alert system queries.
const (
	reasonUsageAll   = "global statistics: usage counters of every tenant (no personal data)"
	reasonUsagePurge = "periodic cleanup: purge the usage counters older than 13 months"
)

// dayLength is the length of a usage counter period: one UTC day.
const dayLength = 24 * time.Hour

// Statements of the TenantUsage and QuotaAlerts repositories. The
// validator refuses ON CONFLICT: a counter is an UPDATE, then an INSERT
// when no row existed, under the tenant lock.
var (
	qUsageAdd = tenantQuery(
		`UPDATE tenant_daily_stats SET transfers = transfers + ?, bytes_uploaded = bytes_uploaded + ?,
		downloads = downloads + ?, bytes_downloaded = bytes_downloaded + ?, virus_detections = virus_detections + ?
		WHERE tenant_id = ? AND day = ?`)
	qUsageInsert = tenantQuery(
		`INSERT INTO tenant_daily_stats (tenant_id, day, transfers, bytes_uploaded, downloads, bytes_downloaded,
		virus_detections) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	qUsageRange = tenantQuery(
		`SELECT day, transfers, bytes_uploaded, downloads, bytes_downloaded, virus_detections FROM tenant_daily_stats
		WHERE tenant_id = ? AND day >= ? ORDER BY day`)
	// qUsageRangeAll sums the counters of every tenant since a day. The
	// CASTs keep integer results on PostgreSQL (sum of BIGINT is NUMERIC).
	qUsageRangeAll = systemQuery(
		`SELECT tenant_id, CAST(sum(transfers) AS BIGINT), CAST(sum(bytes_uploaded) AS BIGINT),
		CAST(sum(downloads) AS BIGINT), CAST(sum(bytes_downloaded) AS BIGINT), CAST(sum(virus_detections) AS BIGINT)
		FROM tenant_daily_stats WHERE day >= ? GROUP BY tenant_id ORDER BY tenant_id`,
		reasonUsageAll)
	qUsagePurge = systemQuery(
		`DELETE FROM tenant_daily_stats WHERE day < ?`,
		reasonUsagePurge)

	qQuotaAlertGet = tenantQuery(
		`SELECT level, changed_at FROM tenant_quota_alerts WHERE tenant_id = ?`)
	qQuotaAlertSwap = tenantQuery(
		`UPDATE tenant_quota_alerts SET level = ?, changed_at = ? WHERE tenant_id = ? AND level = ?`)
	qQuotaAlertInsert = tenantQuery(
		`INSERT INTO tenant_quota_alerts (tenant_id, level, changed_at) VALUES (?, ?, ?)`)
)

// UsageCounts are the usage counters of a tenant over a period (statistics,
// spec 21.2). They hold no personal data.
type UsageCounts struct {
	// Transfers counts the transfers finalized.
	Transfers int64
	// BytesUploaded sums their declared sizes.
	BytesUploaded int64
	// Downloads counts the download starts of a file or of the archive.
	Downloads int64
	// BytesDownloaded sums the clear bytes served.
	BytesDownloaded int64
	// VirusDetections counts the infected files.
	VirusDetections int64
}

// IsZero reports whether every counter is zero.
func (c UsageCounts) IsZero() bool { return c == UsageCounts{} }

// DailyUsage is the usage of a tenant over one UTC day.
type DailyUsage struct {
	// Day is 00:00 UTC of the day.
	Day time.Time
	UsageCounts
}

// TenantUsage is the repository of the daily usage counters of the tenants.
// Obtain it with [DB.TenantUsage].
type TenantUsage struct {
	db *DB
}

// TenantUsage returns the usage counter repository.
func (db *DB) TenantUsage() *TenantUsage { return &TenantUsage{db: db} }

// DayOf returns 00:00 UTC of the day of t.
func DayOf(t time.Time) time.Time {
	return t.UTC().Truncate(dayLength)
}

// validDay reports whether day is 00:00 UTC of a day.
func validDay(day time.Time) bool {
	return toMillis(day)%dayLength.Milliseconds() == 0
}

// Add adds delta to the counters of tenant tid for day (00:00 UTC, see
// [DayOf]), creating them when needed. A zero delta changes nothing. It
// returns ErrInvalid for a day that is not 00:00 UTC or a negative counter,
// and ErrNotFound when the tenant does not exist.
func (r *TenantUsage) Add(ctx context.Context, tid tenant.ID, day time.Time, delta UsageCounts) error {
	if _, err := r.db.Scoped(tid); err != nil {
		return err
	}
	if !validDay(day) {
		return invalid("day must be 00:00 UTC")
	}
	if delta.Transfers < 0 || delta.BytesUploaded < 0 || delta.Downloads < 0 || delta.BytesDownloaded < 0 ||
		delta.VirusDetections < 0 {
		return invalid("usage counters only grow")
	}
	if delta.IsZero() {
		return nil
	}
	d := toMillis(day)
	counts := []any{delta.Transfers, delta.BytesUploaded, delta.Downloads, delta.BytesDownloaded, delta.VirusDetections}
	return writeScoped(ctx, r.db, tid, "add usage", func(tx *ScopedTx) error {
		return upsert(ctx, tx, qUsageAdd, append(append([]any{}, counts...), d), qUsageInsert, append([]any{d}, counts...))
	})
}

// scanUsage reads the five counters after the scanned prefix.
func scanUsage(sc interface{ Scan(...any) error }, prefix ...any) (UsageCounts, error) {
	var c UsageCounts
	dest := append(append(make([]any, 0, len(prefix)+5), prefix...), &c.Transfers, &c.BytesUploaded, &c.Downloads,
		&c.BytesDownloaded, &c.VirusDetections)
	err := sc.Scan(dest...)
	return c, err
}

// Range returns the daily counters of tenant tid from fromDay included, by
// day; the days without activity are absent (callers fill the zeros).
func (r *TenantUsage) Range(ctx context.Context, tid tenant.ID, fromDay time.Time) ([]DailyUsage, error) {
	return readScoped(ctx, r.db, tid, "read usage", func(tx *ScopedTx) ([]DailyUsage, error) {
		rows, err := tx.Query(ctx, qUsageRange, toMillis(fromDay))
		if err != nil {
			return nil, err
		}
		return collect(rows, func(r *sql.Rows) (DailyUsage, error) {
			var day int64
			c, err := scanUsage(r, &day)
			return DailyUsage{Day: fromMillis(day), UsageCounts: c}, err
		})
	})
}

// RangeAll returns, for every tenant with counters from fromDay included,
// the sum of its counters since then. It is a system query (reason "global
// statistics: usage counters of every tenant (no personal data)"); a
// tenant without activity is absent from the map.
func (r *TenantUsage) RangeAll(ctx context.Context, fromDay time.Time) (map[tenant.ID]UsageCounts, error) {
	out := map[tenant.ID]UsageCounts{}
	err := r.db.systemScope(reasonUsageAll).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qUsageRangeAll, toMillis(fromDay))
		if err != nil {
			return err
		}
		type row struct {
			tid string
			c   UsageCounts
		}
		rs, err := collect(rows, func(r *sql.Rows) (row, error) {
			var x row
			var err error
			x.c, err = scanUsage(r, &x.tid)
			return x, err
		})
		for _, x := range rs {
			out[tenant.ID(x.tid)] = x.c
		}
		return err
	})
	if err != nil {
		return nil, wrap("read usage of every tenant", err)
	}
	return out, nil
}

// Purge deletes the counters of every tenant for the days strictly before
// before (the cleanup task passes now minus 13 months), and returns how
// many daily rows it deleted.
func (r *TenantUsage) Purge(ctx context.Context, before time.Time) (int64, error) {
	var n int64
	err := r.db.systemScope(reasonUsagePurge).Tx(ctx, func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qUsagePurge, toMillis(before))
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return 0, wrap("purge usage", err)
	}
	return n, nil
}

// Quota alert levels (spec 8.5): the last alert sent for a tenant.
const (
	// QuotaLevelNone is the level without alert.
	QuotaLevelNone = 0
	// QuotaLevelWarning is the level of the 80 % warning.
	QuotaLevelWarning = 80
	// QuotaLevelReached is the level of the quota reached.
	QuotaLevelReached = 100
)

// validQuotaLevel reports whether l is a quota alert level.
func validQuotaLevel(l int) bool {
	return l == QuotaLevelNone || l == QuotaLevelWarning || l == QuotaLevelReached
}

// QuotaAlert is the quota alert state of a tenant.
type QuotaAlert struct {
	// Level is the last level reached: QuotaLevelNone, QuotaLevelWarning or
	// QuotaLevelReached.
	Level int
	// ChangedAt is when the level last changed, zero when it never did.
	ChangedAt time.Time
}

// QuotaAlerts is the tenant-scoped repository of the quota alert levels.
// Obtain it with [DB.QuotaAlerts].
type QuotaAlerts struct {
	db *DB
}

// QuotaAlerts returns the quota alert repository.
func (db *DB) QuotaAlerts() *QuotaAlerts { return &QuotaAlerts{db: db} }

// Get returns the quota alert state of tenant tid: level QuotaLevelNone
// and a zero ChangedAt when no level was ever recorded (including for an
// unknown tenant).
func (r *QuotaAlerts) Get(ctx context.Context, tid tenant.ID) (QuotaAlert, error) {
	return readScoped(ctx, r.db, tid, "get quota alert", func(tx *ScopedTx) (QuotaAlert, error) {
		var (
			a       QuotaAlert
			changed int64
		)
		err := tx.QueryRow(ctx, qQuotaAlertGet).Scan(&a.Level, &changed)
		if errors.Is(err, ErrNotFound) {
			return QuotaAlert{}, nil
		}
		a.ChangedAt = fromMillis(changed)
		return a, err
	})
}

// CompareAndSet moves the quota alert level of tenant tid from old to
// level at now (the store's clock when zero), atomically: it returns true
// when the level was old and is now level, and false, without error, when
// the level was not old (another sweep or transfer changed it first). A
// tenant without recorded level is at QuotaLevelNone. Callers send an
// alert only on true. It returns ErrInvalid for an unknown level and
// ErrNotFound when the tenant does not exist.
func (r *QuotaAlerts) CompareAndSet(ctx context.Context, tid tenant.ID, old, level int, now time.Time) (bool, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return false, err
	}
	if !validQuotaLevel(old) || !validQuotaLevel(level) {
		return false, invalid("unknown quota alert level")
	}
	ms := toMillis(r.db.orNow(now))
	swapped := false
	err := writeScoped(ctx, r.db, tid, "set quota alert", func(tx *ScopedTx) error {
		// The tenant lock orders concurrent swaps on PostgreSQL (SQLite
		// serializes the writers anyway).
		if err := tx.lock(ctx); err != nil {
			return err
		}
		res, err := tx.Exec(ctx, qQuotaAlertSwap, level, ms, old)
		if err != nil {
			return err
		}
		if err := expectOne(res); !errors.Is(err, ErrNotFound) {
			swapped = err == nil
			return err
		}
		if old != QuotaLevelNone {
			return nil // no row means level 0, not old
		}
		// No row with level 0: insert one, unless a row with another level
		// exists, which the primary key refuses.
		if _, err := tx.Exec(ctx, qQuotaAlertInsert, level, ms); err != nil {
			return err
		}
		swapped = true
		return nil
	})
	if errors.Is(err, ErrConflict) {
		return false, nil
	}
	return swapped, err
}

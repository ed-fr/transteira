package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// reasonSupervision is the reason of the system queries behind the
// supervision endpoints (metrics and status): counts only, no identifier of
// a transfer, a file or an address.
const reasonSupervision = "supervision metrics: counts of files waiting for the antivirus and of transfers per tenant"

// Statements of the supervision counts.
var (
	// qScanQueueFiles counts the files waiting for or under analysis: the
	// files not yet analyzed of the transfers in the scanning status.
	qScanQueueFiles = systemQuery(
		`SELECT count(*) FROM transfer_files f JOIN transfers t ON t.tenant_id = f.tenant_id AND t.id = f.transfer_id
		WHERE t.status = 'scanning' AND f.scan_status IN ('pending', 'scanning')`,
		reasonSupervision)
	// qTransferActiveCounts counts, per tenant, the available transfers and
	// those made available since a date. Arguments: since (twice).
	qTransferActiveCounts = systemQuery(
		`SELECT tenant_id, CAST(COALESCE(SUM(CASE WHEN status = 'available' THEN 1 ELSE 0 END), 0) AS BIGINT),
		CAST(COALESCE(SUM(CASE WHEN available_at >= ? THEN 1 ELSE 0 END), 0) AS BIGINT)
		FROM transfers WHERE status = 'available' OR available_at >= ? GROUP BY tenant_id ORDER BY tenant_id`,
		reasonSupervision)
)

// TenantTransferCounts are the transfer counts of one tenant, as returned
// by [Transfers.ActiveCounts].
type TenantTransferCounts struct {
	// TenantID is the tenant.
	TenantID tenant.ID
	// Active is its number of available transfers.
	Active int64
	// MadeAvailableSince is its number of transfers made available since
	// the date given to ActiveCounts, whatever their status now.
	MadeAvailableSince int64
}

// ScanQueueFiles returns the number of files waiting for or under the
// antivirus analysis across all tenants. It is a system query returning a
// count only.
func (r *Transfers) ScanQueueFiles(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.systemScope(reasonSupervision).ReadTx(ctx, func(tx *SystemTx) error {
		return tx.QueryRow(ctx, qScanQueueFiles).Scan(&n)
	})
	if err != nil {
		return 0, wrap("count files waiting for the antivirus", err)
	}
	return n, nil
}

// ActiveCounts returns, for every tenant with an available transfer or a
// transfer made available since the given time, the number of available
// transfers and the number made available since, ordered by tenant ID. It
// is a system query returning counts only.
func (r *Transfers) ActiveCounts(ctx context.Context, since time.Time) ([]TenantTransferCounts, error) {
	var out []TenantTransferCounts
	err := r.db.systemScope(reasonSupervision).ReadTx(ctx, func(tx *SystemTx) error {
		ms := toMillis(since)
		rows, err := tx.Query(ctx, qTransferActiveCounts, ms, ms)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (TenantTransferCounts, error) {
			var c TenantTransferCounts
			err := r.Scan(&c.TenantID, &c.Active, &c.MadeAvailableSince)
			return c, err
		})
		return err
	})
	if err != nil {
		return nil, wrap("count transfers per tenant", err)
	}
	return out, nil
}

// reasonSecretSupervision is the reason of the system query behind the
// one-time secret figures of the supervision endpoints: counts and sizes
// only, no identifier of a secret, a token or an address.
const reasonSecretSupervision = "supervision metrics: counts of one-time secrets and sizes of their files per tenant"

// qSecretSupervisionCounts counts, per tenant, the secrets created, read
// and locked since a date and sums the declared sizes of the stored secret
// files (those counted in the storage quota, see qSecretFileBytes). The
// rows of every state are read: a secret created, read or locked since the
// date is counted while its row exists (tombstones are kept 30 days, an
// abandoned pending secret is deleted after one hour). Arguments: since
// (three times).
var qSecretSupervisionCounts = systemQuery(
	`SELECT tenant_id, CAST(COALESCE(SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END), 0) AS BIGINT),
	CAST(COALESCE(SUM(CASE WHEN read_at >= ? THEN 1 ELSE 0 END), 0) AS BIGINT),
	CAST(COALESCE(SUM(CASE WHEN end_reason = 'locked' AND ended_at >= ? THEN 1 ELSE 0 END), 0) AS BIGINT),
	CAST(COALESCE(SUM(CASE WHEN file_storage_name IS NOT NULL THEN file_size ELSE 0 END), 0) AS BIGINT)
	FROM secrets GROUP BY tenant_id ORDER BY tenant_id`,
	reasonSecretSupervision)

// TenantSecretCounts are the one-time secret figures of one tenant, as
// returned by [Secrets.SupervisionCounts].
type TenantSecretCounts struct {
	// TenantID is the tenant.
	TenantID tenant.ID
	// CreatedSince, ReadSince and LockedSince count the secrets created,
	// read and locked since the date given to SupervisionCounts, among the
	// rows still present.
	CreatedSince, ReadSince, LockedSince int64
	// FileBytes sums the declared sizes of the stored secret files, as
	// counted in the storage quota.
	FileBytes int64
}

// SupervisionCounts returns, for every tenant with a secret row, its
// [TenantSecretCounts] since the given time, ordered by tenant ID. It is a
// system query returning counts and sizes only; it needs no key (r may come
// from DB.Secrets(nil)).
func (r *Secrets) SupervisionCounts(ctx context.Context, since time.Time) ([]TenantSecretCounts, error) {
	var out []TenantSecretCounts
	err := r.db.systemScope(reasonSecretSupervision).ReadTx(ctx, func(tx *SystemTx) error {
		ms := toMillis(since)
		rows, err := tx.Query(ctx, qSecretSupervisionCounts, ms, ms, ms)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (TenantSecretCounts, error) {
			var c TenantSecretCounts
			err := r.Scan(&c.TenantID, &c.CreatedSince, &c.ReadSince, &c.LockedSince, &c.FileBytes)
			return c, err
		})
		return err
	})
	if err != nil {
		return nil, wrap("count secrets per tenant", err)
	}
	return out, nil
}

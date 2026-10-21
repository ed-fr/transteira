package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Reasons of the system queries of the periodic cleanup task (spec 20).
const (
	reasonExpirySweep    = "expire transfers"
	reasonAbandonedSweep = "abandoned uploads"
	reasonCleanupTenants = "periodic cleanup: enumerate the tenants to purge, each in its own scope"
)

// Limits of the cleanup listings and purges.
const (
	// ExpirySweepLimit is the largest page of [Transfers.DueExpirations]
	// and of [Transfers.RejectedKeyed].
	ExpirySweepLimit = maxSweepPage
	// AbandonedSweepLimit is the largest page of
	// [Transfers.AbandonedUploads].
	AbandonedSweepLimit = maxSweepPage
	// ScanningMaxAge is how long a transfer may stay scanning after its
	// finalization: past it, the analysis is considered stuck and the
	// expiry sweep ([Transfers.DueExpirations]) erases the transfer. The
	// provisional ExpiresAt of a scanning transfer is never enforced, since
	// the validity only starts when the transfer becomes available.
	ScanningMaxAge = 30 * 24 * time.Hour
	// PurgeBatchSize bounds the rows one purge transaction examines, and
	// the limit of [Transfers.ListEnded]: the purges commit every
	// PurgeBatchSize rows, so that no transaction holds the SQLite writer
	// for long.
	PurgeBatchSize = 500
	// MaxReconcileRows bounds the rows read by [TransferFiles.StorageRefs]
	// and [Transfers.IDsByStatus] for one tenant, and so their memory (a
	// few hundred bytes per entry, about 100 MB at most). They return
	// [ErrTooManyRows] beyond it: the disk reconciliation then skips the
	// tenant, which is safe, as it only ever deletes files it can prove
	// orphaned.
	MaxReconcileRows = 500_000
	// RateLimitRetention is how long the rows counted by the rate limits
	// (verification challenges and invitations) are kept after their
	// creation, whatever their state: it must be at least the RateWindow of
	// internal/deposit (one hour), which counts the rows created at or after
	// now - RateWindow. The purges delete only rows created strictly before
	// now - RateLimitRetention.
	RateLimitRetention = time.Hour
)

// Errors of the cleanup operations.
var (
	// ErrTooManyRows reports a reconciliation listing above
	// MaxReconcileRows.
	ErrTooManyRows = errors.New("store: too many rows to list at once")
	// ErrBackupUnsupported reports [DB.Backup] on an engine whose copies
	// are made outside TransTeira (PostgreSQL: pg_dump in a dedicated
	// container).
	ErrBackupUnsupported = errors.New("store: database backup is not supported by this engine")
)

// Statements of the periodic cleanup task. The cross-tenant listings are
// system queries returning identifiers only; every purge runs in the
// tenant's scope, selecting a bounded batch of candidates, then deleting
// each of them by primary key with its conditions checked again.
var (
	// qTransferDueExpirations lists the due transfers with their due time,
	// earliest first, one page after a keyset cursor: the available
	// transfers whose expires_at passed, and the scanning transfers
	// finalized ScanningMaxAge ago or more (due at finalized_at +
	// ScanningMaxAge; their provisional expires_at is ignored).
	qTransferDueExpirations = systemQuery(
		`SELECT tenant_id, id, due_at FROM (
		SELECT tenant_id, id, expires_at AS due_at FROM transfers WHERE status = 'available' AND expires_at <= ?
		UNION ALL
		SELECT tenant_id, id, finalized_at + ? AS due_at FROM transfers WHERE status = 'scanning' AND finalized_at <= ?
		) d WHERE (due_at, tenant_id, id) > (?, ?, ?)
		ORDER BY due_at, tenant_id, id LIMIT ?`,
		reasonExpirySweep)
	// qTransferRejectedKeyed lists the rejected transfers that still hold a
	// file key (the files of the same tenant only) with their end, oldest
	// rejection first, one page after a keyset cursor.
	qTransferRejectedKeyed = systemQuery(
		`SELECT tenant_id, id, ended FROM (
		SELECT t.tenant_id, t.id, COALESCE(t.ended_at, 0) AS ended FROM transfers t
		WHERE t.status = 'rejected' AND EXISTS (SELECT 1 FROM transfer_files f
		WHERE f.tenant_id = t.tenant_id AND f.transfer_id = t.id AND f.dek_key_id IS NOT NULL)
		) r WHERE (ended, tenant_id, id) > (?, ?, ?)
		ORDER BY ended, tenant_id, id LIMIT ?`,
		reasonExpirySweep)
	// qTransferAbandoned lists the uploading transfers created at or before
	// a time with their creation, oldest first, one page after a keyset
	// cursor.
	qTransferAbandoned = systemQuery(
		`SELECT tenant_id, id, created_at FROM transfers WHERE status = 'uploading' AND created_at <= ?
		AND (created_at, tenant_id, id) > (?, ?, ?)
		ORDER BY created_at, tenant_id, id LIMIT ?`,
		reasonAbandonedSweep)
	qTenantIDs = systemQuery(
		`SELECT id FROM tenants ORDER BY id`,
		reasonCleanupTenants)

	// qTransferMarkExpired expires a transfer whose sealed download token
	// was destroyed first (T-110); the store checks the file keys
	// beforehand.
	qTransferMarkExpired = tenantQuery(
		`UPDATE transfers SET status = 'expired', ended_at = ?
		WHERE tenant_id = ? AND id = ? AND status IN ('uploading', 'scanning', 'available')
		AND download_token_key_id IS NULL`)
	qTransferListEnded = tenantQuery(
		`SELECT id FROM transfers
		WHERE tenant_id = ? AND status IN ('rejected', 'expired', 'deleted') AND ended_at <= ?
		ORDER BY ended_at, id LIMIT ?`)
	qTransferIDsByStatus = tenantQuery(
		`SELECT id FROM transfers WHERE tenant_id = ? AND status = ? ORDER BY id LIMIT ?`)
	qTransferStatuses = tenantQuery(
		`SELECT id, status FROM transfers WHERE tenant_id = ? LIMIT ?`)
	qFileStorageRefs = tenantQuery(
		`SELECT storage_name, id, transfer_id, dek_key_id, uploaded_at FROM transfer_files WHERE tenant_id = ? LIMIT ?`)
	qTransferCountByInvitation = tenantQuery(
		`SELECT count(*) FROM transfers WHERE tenant_id = ? AND invitation_id = ?`)

	qChallengePurgeList = tenantQuery(
		`SELECT id FROM verification_challenges
		WHERE tenant_id = ? AND (consumed_at IS NOT NULL OR expires_at <= ?) AND created_at < ? AND id > ?
		ORDER BY id LIMIT ?`)
	qChallengePurge = tenantQuery(
		`DELETE FROM verification_challenges
		WHERE tenant_id = ? AND id = ? AND (consumed_at IS NOT NULL OR expires_at <= ?) AND created_at < ?`)
	qSessionPurgeList = tenantQuery(
		`SELECT id FROM deposit_sessions
		WHERE tenant_id = ? AND (ended_at IS NOT NULL OR expires_at <= ?) AND id > ?
		ORDER BY id LIMIT ?`)
	qSessionPurge = tenantQuery(
		`DELETE FROM deposit_sessions WHERE tenant_id = ? AND id = ? AND (ended_at IS NOT NULL OR expires_at <= ?)`)
	qFailurePurgeList = tenantQuery(
		`SELECT key FROM password_failures
		WHERE tenant_id = ? AND scope = ? AND COALESCE(fail_1, 0) <= ? AND COALESCE(fail_2, 0) <= ?
		AND COALESCE(fail_3, 0) <= ? AND COALESCE(locked_until, 0) <= ? AND key > ?
		ORDER BY key LIMIT ?`)
	qFailurePurge = tenantQuery(
		`DELETE FROM password_failures
		WHERE tenant_id = ? AND scope = ? AND key = ? AND COALESCE(fail_1, 0) <= ? AND COALESCE(fail_2, 0) <= ?
		AND COALESCE(fail_3, 0) <= ? AND COALESCE(locked_until, 0) <= ?`)
	qVerifiedPurgeList = tenantQuery(
		`SELECT email, last_used_at FROM verified_addresses
		WHERE tenant_id = ? AND last_used_at <= ? AND email > ?
		ORDER BY email LIMIT ?`)
	qVerifiedPurge = tenantQuery(
		`DELETE FROM verified_addresses WHERE tenant_id = ? AND email = ? AND last_used_at = ?`)
	qInvitationPurgeList = tenantQuery(
		`SELECT id FROM invitations
		WHERE tenant_id = ? AND (revoked_at IS NOT NULL OR expires_at <= ?) AND created_at < ? AND id > ?
		ORDER BY id LIMIT ?`)
	qInvitationPurge = tenantQuery(
		`DELETE FROM invitations
		WHERE tenant_id = ? AND id = ? AND (revoked_at IS NOT NULL OR expires_at <= ?) AND created_at < ?`)
)

// SweepPage selects one page of a keyset-paginated sweep across tenants
// ([Transfers.DueDeletions], [Transfers.DueExpirations],
// [Transfers.RejectedKeyed], [Transfers.AbandonedUploads]). The entries
// come ordered by (SortKey, TenantID, TransferID); a page holds the entries
// strictly after After, so a caller always reaches the later entries, even
// when a full page stays listed (not due any more, or failing).
type SweepPage struct {
	// After is the last entry of the previous page, as returned (its
	// SortKey included); the zero value starts at the first entry.
	After TenantTransfer
	// Limit is the page size, from 1 to the limit of the sweep.
	Limit int
}

// maxSweepPage is the largest page of every keyset-paginated sweep.
const maxSweepPage = 1000

// sweepPage runs the keyset-paginated system query q, which returns tenant
// and transfer identifiers and a sort key and takes args, then the cursor
// (sort key, tenant, transfer) and the limit, and returns one page. It
// returns ErrInvalid for a page limit outside 1 to maxSweepPage.
func (db *DB) sweepPage(ctx context.Context, reason, op string, q SystemQuery, page SweepPage, args ...any) ([]TenantTransfer, error) {
	if page.Limit < 1 || page.Limit > maxSweepPage {
		return nil, invalid("page limit must be between 1 and %d", maxSweepPage)
	}
	key, tid, trfID := int64(math.MinInt64), "", ""
	if page.After != (TenantTransfer{}) {
		key, tid, trfID = toMillis(page.After.SortKey), string(page.After.TenantID), page.After.TransferID
	}
	args = append(args, key, tid, trfID, page.Limit)
	var out []TenantTransfer
	err := db.systemScope(reason).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (TenantTransfer, error) {
			var (
				t  TenantTransfer
				ms int64
			)
			err := r.Scan(&t.TenantID, &t.TransferID, &ms)
			t.SortKey = fromMillis(ms)
			return t, err
		})
		return err
	})
	if err != nil {
		return nil, wrap(op, err)
	}
	return out, nil
}

// DueExpirations returns one page of the transfers of every tenant past
// their expiry at now (spec 20), each with its due time as SortKey,
// earliest due first, after page.After and at most page.Limit of them (1
// to ExpirySweepLimit):
//
//   - the available transfers whose ExpiresAt is at or before now;
//   - the scanning transfers finalized at or before now - scanningMaxAge
//     (ScanningMaxAge, shorter in the tests), due at FinalizedAt +
//     scanningMaxAge: a stuck analysis. The provisional ExpiresAt of a
//     scanning transfer is never enforced.
//
// It is a system query (reason "expire transfers") and returns identifiers
// only; the caller erases each transfer in the scope of its tenant, in the
// order of [Transfers.DueDeletions], and calls [Transfers.MarkExpiredTx]
// after checking the expiry again. It returns ErrInvalid for a page limit
// out of range or a scanningMaxAge that is not positive.
func (r *Transfers) DueExpirations(ctx context.Context, now time.Time, scanningMaxAge time.Duration, page SweepPage) ([]TenantTransfer, error) {
	if scanningMaxAge <= 0 {
		return nil, invalid("the scanning maximum age must be positive")
	}
	return r.db.sweepPage(ctx, reasonExpirySweep, "sweep due expirations", qTransferDueExpirations,
		page, toMillis(now), scanningMaxAge.Milliseconds(), toMillis(now.Add(-scanningMaxAge)))
}

// RejectedKeyed returns one page of the rejected transfers of every tenant
// that still hold a file data key, oldest rejection first (SortKey is
// EndedAt), after page.After and at most page.Limit of them (1 to
// ExpirySweepLimit), so that the expiry sweep destroys those leftover keys
// and files (a rejected transfer keeps its status). It is a system query
// (reason "expire transfers") and returns identifiers only. It returns
// ErrInvalid for a page limit out of range.
func (r *Transfers) RejectedKeyed(ctx context.Context, page SweepPage) ([]TenantTransfer, error) {
	return r.db.sweepPage(ctx, reasonExpirySweep, "sweep rejected transfers", qTransferRejectedKeyed,
		page)
}

// AbandonedUploads returns one page of the transfers of every tenant still
// uploading that were created at or before createdBefore, oldest first
// (SortKey is CreatedAt), after page.After and at most page.Limit of them
// (1 to AbandonedSweepLimit): candidates only, the caller decides whether
// each is abandoned from its upload activity before expiring it with
// [Transfers.MarkExpiredTx], which releases its quota reservation. It is a
// system query (reason "abandoned uploads") and returns identifiers only.
// It returns ErrInvalid for a page limit out of range.
func (r *Transfers) AbandonedUploads(ctx context.Context, createdBefore time.Time, page SweepPage) ([]TenantTransfer, error) {
	return r.db.sweepPage(ctx, reasonAbandonedSweep, "sweep abandoned uploads", qTransferAbandoned,
		page, toMillis(createdBefore))
}

// MarkExpiredTx moves the transfer trfID of the tenant tx is bound to to
// expired, inside tx, keeping its row (and its download token hash, so
// that the link answers "gone"), and sets EndedAt to now. The transfer must
// be uploading, scanning or available; the caller checks that it is due
// (expiry, or an abandoned upload). The data key of every file and the
// sealed download token (DownloadTokenKeyID) must have been destroyed first
// ([WrappedKeys.DeleteTx]), the token key in the same transaction;
// otherwise it returns [ErrKeysRemain] and changes nothing. It returns
// ErrNotFound when the transfer does not exist or belongs to another
// tenant, and ErrConflict when it is in another status. After an error,
// the caller must abort the transaction.
func (r *Transfers) MarkExpiredTx(ctx context.Context, tx *ScopedTx, trfID string, now time.Time) error {
	if err := markExpired(ctx, tx, trfID, now); err != nil {
		return wrap("mark transfer expired", err)
	}
	return nil
}

// markExpired implements MarkExpiredTx, returning raw errors.
func markExpired(ctx context.Context, tx *ScopedTx, trfID string, now time.Time) error {
	var keyed int
	if err := tx.QueryRow(ctx, qFileCountKeyed, trfID).Scan(&keyed); err != nil {
		return err
	}
	if keyed > 0 {
		return ErrKeysRemain
	}
	res, err := tx.Exec(ctx, qTransferMarkExpired, toMillis(now), trfID)
	if err == nil {
		err = expectOne(res)
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	t, err := scanTransfer(tx.QueryRow(ctx, qTransferGet, trfID))
	switch {
	case err != nil:
		return err
	case t.Status != TransferUploading && t.Status != TransferScanning && t.Status != TransferAvailable:
		return ErrConflict
	default:
		return ErrKeysRemain
	}
}

// ListEnded returns the transfers of tenant tid that reached a terminal
// status (rejected, expired or deleted) at or before endedBefore, oldest
// end first, at most limit of them (1 to PurgeBatchSize). The cleanup task
// deletes each of them with [Transfers.DeleteTx] in a scoped transaction;
// a rejected transfer still holding a file key is refused there until the
// expiry sweep ([Transfers.DueExpirations]) erased it. It returns
// ErrInvalid for a malformed tenant ID or limit.
func (r *Transfers) ListEnded(ctx context.Context, tid tenant.ID, endedBefore time.Time, limit int) ([]string, error) {
	if limit < 1 || limit > PurgeBatchSize {
		return nil, invalid("limit must be between 1 and %d", PurgeBatchSize)
	}
	return readScoped(ctx, r.db, tid, "list ended transfers", func(tx *ScopedTx) ([]string, error) {
		return listIDs(ctx, tx, qTransferListEnded, toMillis(endedBefore), limit)
	})
}

// listIDs runs q, which returns one text column, with args.
func listIDs(ctx context.Context, tx *ScopedTx, q TenantQuery, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r *sql.Rows) (string, error) {
		var s string
		err := r.Scan(&s)
		return s, err
	})
}

// IDsByStatus returns the identifiers of the transfers of tenant tid in any
// of statuses (1 or more distinct, known statuses), by status then
// identifier. It reads at most MaxReconcileRows identifiers per status and
// returns [ErrTooManyRows] beyond. It returns ErrInvalid for a malformed
// tenant ID or status list.
func (r *Transfers) IDsByStatus(ctx context.Context, tid tenant.ID, statuses ...TransferStatus) ([]string, error) {
	if len(statuses) == 0 {
		return nil, invalid("at least one status is required")
	}
	seen := make(map[TransferStatus]bool, len(statuses))
	for _, s := range statuses {
		if !s.valid() || seen[s] {
			return nil, invalid("unknown or duplicate status")
		}
		seen[s] = true
	}
	return readScoped(ctx, r.db, tid, "list transfers by status", func(tx *ScopedTx) ([]string, error) {
		out := make([]string, 0)
		for _, s := range statuses {
			ids, err := listIDs(ctx, tx, qTransferIDsByStatus, string(s), r.db.reconcileRows+1)
			if err != nil {
				return nil, err
			}
			if len(ids) > r.db.reconcileRows {
				return nil, ErrTooManyRows
			}
			out = append(out, ids...)
		}
		return out, nil
	})
}

// StorageRef describes the encrypted file a storage name stands for, for
// the reconciliation of a tenant's directory with the database.
type StorageRef struct {
	// FileID is the file ("fil_" + ULID).
	FileID string
	// TransferID is its transfer ("trf_" + ULID).
	TransferID string
	// TransferStatus is the status of the transfer, "" when its row
	// disappeared while the listing ran (its files are then orphans).
	TransferStatus TransferStatus
	// Keyed reports whether the file still has its data key: a file
	// without key is unreadable, its encrypted data is an orphan.
	Keyed bool
	// Completed reports whether the upload of the file is complete.
	Completed bool
}

// StorageRefs returns the storage names of the files of tenant tid, each
// with the file it belongs to. The reset of an upload replaces the storage
// name of its file in place ([TransferFiles.ReplaceDEKTx]): the store keeps
// no pending replacement, the previous name simply stops being listed (an
// orphan). The files are read first, then the transfer statuses: a
// transfer created in between is ignored, one deleted in between leaves an
// empty TransferStatus. It reads at most MaxReconcileRows files and
// transfers and returns [ErrTooManyRows] beyond.
func (r *TransferFiles) StorageRefs(ctx context.Context, tid tenant.ID) (map[string]StorageRef, error) {
	return readScoped(ctx, r.db, tid, "list storage names", func(tx *ScopedTx) (map[string]StorageRef, error) {
		refs, err := storageRefs(ctx, tx, r.db.reconcileRows)
		if err != nil {
			return nil, err
		}
		rows, err := tx.Query(ctx, qTransferStatuses, r.db.reconcileRows+1)
		if err != nil {
			return nil, err
		}
		statuses := make(map[string]TransferStatus)
		_, err = collect(rows, func(r *sql.Rows) (struct{}, error) {
			var trfID, status string
			err := r.Scan(&trfID, &status)
			statuses[trfID] = TransferStatus(status)
			return struct{}{}, err
		})
		if err != nil {
			return nil, err
		}
		if len(statuses) > r.db.reconcileRows {
			return nil, ErrTooManyRows
		}
		for name, ref := range refs {
			ref.TransferStatus = statuses[ref.TransferID]
			refs[name] = ref
		}
		return refs, nil
	})
}

// storageRefs reads the files of the tenant tx is bound to, without their
// transfer status, failing beyond limit files.
func storageRefs(ctx context.Context, tx *ScopedTx, limit int) (map[string]StorageRef, error) {
	rows, err := tx.Query(ctx, qFileStorageRefs, limit+1)
	if err != nil {
		return nil, err
	}
	refs := make(map[string]StorageRef)
	_, err = collect(rows, func(r *sql.Rows) (struct{}, error) {
		var (
			name     string
			ref      StorageRef
			key      sql.NullString
			uploaded sql.NullInt64
		)
		err := r.Scan(&name, &ref.FileID, &ref.TransferID, &key, &uploaded)
		ref.Keyed, ref.Completed = key.Valid, uploaded.Valid
		refs[name] = ref
		return struct{}{}, err
	})
	if err != nil {
		return nil, err
	}
	if len(refs) > limit {
		return nil, ErrTooManyRows
	}
	return refs, nil
}

// purgeBatch examines, inside tx, at most size candidate rows whose key
// sorts after the cursor after ("" at first), deletes the eligible ones and
// returns how many it deleted, the key of the last candidate examined and
// whether the batch was full.
type purgeBatch func(ctx context.Context, tx *ScopedTx, after string, size int) (deleted int64, last string, full bool, err error)

// purge runs batch for tenant tid in successive write transactions, each
// resuming after the last candidate of the previous one, until a batch is
// not full, and returns the total deleted. Because the cursor always moves
// forward, a candidate that stays ineligible never stalls the purge. With
// lock, each transaction first takes the tenant lock, serializing it with
// the writers of the same rows (on SQLite, write transactions are
// serialized anyway).
func (db *DB) purge(ctx context.Context, tid tenant.ID, op string, lock bool, batch purgeBatch) (int64, error) {
	s, err := db.Scoped(tid)
	if err != nil {
		return 0, err
	}
	var total int64
	after := ""
	for {
		var (
			n    int64
			full bool
		)
		err := s.Tx(ctx, func(tx *ScopedTx) error {
			if lock {
				if err := tx.lock(ctx); err != nil {
					return err
				}
			}
			var err error
			n, after, full, err = batch(ctx, tx, after, db.purgeBatch)
			return err
		})
		if err != nil {
			return total, wrap(op, err)
		}
		total += n
		if !full {
			return total, nil
		}
	}
}

// deleteEach deletes, with del and the arguments built by args for each
// key, the candidates listed by the list query q (run with listArgs, then
// the cursor after and the batch size), and returns the batch outcome. A
// key whose deletion affects no row (changed meanwhile) is skipped.
func deleteEach(ctx context.Context, tx *ScopedTx, q TenantQuery, listArgs []any, after string, size int,
	del TenantQuery, args func(key string) []any,
) (int64, string, bool, error) {
	keys, err := listIDs(ctx, tx, q, append(listArgs, after, size)...)
	if err != nil {
		return 0, "", false, err
	}
	var deleted int64
	for _, k := range keys {
		res, err := tx.Exec(ctx, del, args(k)...)
		if err != nil {
			return 0, "", false, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, "", false, err
		}
		deleted += n
	}
	last := ""
	if len(keys) > 0 {
		last = keys[len(keys)-1]
	}
	return deleted, last, len(keys) == size, nil
}

// Purge deletes the verification challenges of tenant tid that are
// consumed or expired at now and were created strictly before now -
// RateLimitRetention (the rate limits still count the younger ones, see
// [Challenges]), in batches of PurgeBatchSize, and returns how many it
// deleted.
func (r *Challenges) Purge(ctx context.Context, tid tenant.ID, now time.Time) (int64, error) {
	ms, created := toMillis(now), toMillis(now.Add(-RateLimitRetention))
	return r.db.purge(ctx, tid, "purge challenges", false, func(ctx context.Context, tx *ScopedTx, after string, size int) (int64, string, bool, error) {
		return deleteEach(ctx, tx, qChallengePurgeList, []any{ms, created}, after, size, qChallengePurge,
			func(k string) []any { return []any{k, ms, created} })
	})
}

// Purge deletes the deposit sessions of tenant tid that are ended or
// expired at now, in batches of PurgeBatchSize, and returns how many it
// deleted.
func (r *DepositSessions) Purge(ctx context.Context, tid tenant.ID, now time.Time) (int64, error) {
	ms := toMillis(now)
	return r.db.purge(ctx, tid, "purge deposit sessions", false, func(ctx context.Context, tx *ScopedTx, after string, size int) (int64, string, bool, error) {
		return deleteEach(ctx, tx, qSessionPurgeList, []any{ms}, after, size, qSessionPurge,
			func(k string) []any { return []any{k, ms} })
	})
}

// Purge deletes the stale password failure counters of tenant tid at now:
// every failure recorded is PasswordFailureWindow old or older (it no
// longer counts) and no lock is running (locked_until at or before now, or
// none). It works in batches of PurgeBatchSize under the tenant lock, like
// the other writers of the counters, and returns how many it deleted.
func (r *PasswordFailures) Purge(ctx context.Context, tid tenant.ID, now time.Time) (int64, error) {
	ms, stale := toMillis(now), toMillis(now.Add(-PasswordFailureWindow))
	var total int64
	for _, scope := range []FailureScope{FailureScopeIP, FailureScopeTransfer} {
		n, err := r.db.purge(ctx, tid, "purge password failures", true, func(ctx context.Context, tx *ScopedTx, after string, size int) (int64, string, bool, error) {
			return deleteEach(ctx, tx, qFailurePurgeList, []any{string(scope), stale, stale, stale, ms}, after, size,
				qFailurePurge, func(k string) []any { return []any{string(scope), k, stale, stale, stale, ms} })
		})
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Purge deletes the verified addresses of tenant tid that are no longer
// active at now (see [VerifiedAddress.Active]: unused for
// VerifiedRetentionMonths, counted from the last use, which is the first
// verification for an address never used since), in batches of
// PurgeBatchSize under the tenant lock (like [VerifiedAddresses.UpsertTx]),
// and returns how many it deleted. The database preselects the addresses
// last used at or before now - VerifiedRetentionMonths (calendar months,
// UTC), a superset of the inactive ones, and the exact rule of Active
// decides, so that an address is purged exactly when Active turns false.
// An address used meanwhile is kept.
func (r *VerifiedAddresses) Purge(ctx context.Context, tid tenant.ID, now time.Time) (int64, error) {
	cutoff := toMillis(now.UTC().AddDate(0, -VerifiedRetentionMonths, 0))
	return r.db.purge(ctx, tid, "purge verified addresses", true, func(ctx context.Context, tx *ScopedTx, after string, size int) (int64, string, bool, error) {
		rows, err := tx.Query(ctx, qVerifiedPurgeList, cutoff, after, size)
		if err != nil {
			return 0, "", false, err
		}
		type candidate struct {
			email    string
			lastUsed int64
		}
		cands, err := collect(rows, func(r *sql.Rows) (candidate, error) {
			var c candidate
			err := r.Scan(&c.email, &c.lastUsed)
			return c, err
		})
		if err != nil {
			return 0, "", false, err
		}
		var deleted int64
		last := ""
		for _, c := range cands {
			last = c.email
			if verifiedActive(fromMillis(c.lastUsed), now) {
				continue
			}
			res, err := tx.Exec(ctx, qVerifiedPurge, c.email, c.lastUsed)
			if err != nil {
				return 0, "", false, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return 0, "", false, err
			}
			deleted += n
		}
		return deleted, last, len(cands) == size, nil
	})
}

// Purge deletes the invitations of tenant tid that are no longer active at
// now (revoked, or expired: ExpiresAt at or before now), were created
// strictly before now - RateLimitRetention (the per-inviter rate limit
// still counts the younger ones, see [Invitations]) and are referenced by
// no transfer: the foreign key from transfers has no cascade, so an
// invitation goes once the rows of its transfers are deleted. Its
// challenges and sessions follow by cascade. It works in batches of
// PurgeBatchSize under the tenant lock, which the creation of a transfer
// takes too ([Transfers.UsedBytesTx]), and returns how many it deleted.
func (r *Invitations) Purge(ctx context.Context, tid tenant.ID, now time.Time) (int64, error) {
	ms, created := toMillis(now), toMillis(now.Add(-RateLimitRetention))
	return r.db.purge(ctx, tid, "purge invitations", true, func(ctx context.Context, tx *ScopedTx, after string, size int) (int64, string, bool, error) {
		ids, err := listIDs(ctx, tx, qInvitationPurgeList, ms, created, after, size)
		if err != nil {
			return 0, "", false, err
		}
		var deleted int64
		last := ""
		for _, invID := range ids {
			last = invID
			var refs int
			if err := tx.QueryRow(ctx, qTransferCountByInvitation, invID).Scan(&refs); err != nil {
				return 0, "", false, err
			}
			if refs > 0 {
				continue
			}
			res, err := tx.Exec(ctx, qInvitationPurge, invID, ms, created)
			if err != nil {
				return 0, "", false, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return 0, "", false, err
			}
			deleted += n
		}
		return deleted, last, len(ids) == size, nil
	})
}

// IDs returns the identifiers of every tenant, ordered, for the periodic
// cleanup task, which then purges each tenant in its own scope. It is a
// system query (the tenants table is the tenant registry).
func (r *Tenants) IDs(ctx context.Context) ([]tenant.ID, error) {
	var out []tenant.ID
	err := r.db.systemScope(reasonCleanupTenants).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qTenantIDs)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (tenant.ID, error) {
			var s string
			err := r.Scan(&s)
			return tenant.ID(s), err
		})
		return err
	})
	if err != nil {
		return nil, wrap("list tenant ids", err)
	}
	return out, nil
}

// Backup writes a consistent copy of the database to path, for the nightly
// copy of spec 23. path is absolute and must not exist yet, or be an empty
// regular file (not a symbolic link), which the caller pre-creates with a
// restricted mode: SQLite fills an existing empty file in place, keeping
// its mode. With SQLite it runs VACUUM INTO, path being a bound parameter: the
// copy is a complete, compacted database built from the live pages only,
// so the content zeroed by secure_delete and the frames still in the WAL
// are not copied; deleted keys are absent from the copy. The statement is
// dialect plumbing run on the writer connection, outside the query
// registry and outside any transaction (VACUUM cannot run in one): it
// reads no tenant data selectively and writes no row. Writers wait while
// the copy runs (metadata only, a small database). A file created by
// SQLite gets the process umask; the caller restricts its mode, checks it
// and renames it into place. With PostgreSQL it returns
// [ErrBackupUnsupported]: a dedicated container runs pg_dump.
func (db *DB) Backup(ctx context.Context, path string) error {
	if db.dialect.backup == "" {
		return ErrBackupUnsupported
	}
	if !filepath.IsAbs(path) {
		return invalid("backup path must be absolute")
	}
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() || fi.Size() != 0 {
			return fmt.Errorf("store: backup: %w", fs.ErrExist)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: backup: %w", err)
	}
	if _, err := db.write.ExecContext(ctx, db.dialect.backup, path); err != nil {
		return wrap("backup", err)
	}
	return nil
}

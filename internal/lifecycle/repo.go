package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// errNotDue reports, from inside the final transaction, a transfer that is
// no longer due: the transaction is rolled back and the transfer skipped.
var errNotDue = errors.New("lifecycle: transfer not due")

// repo is the part of the store the sweeper uses. It exists so that the
// tests can inject a failure at any step; [storeRepo] is the only real
// implementation. The listings of due transfers and tenantIDs are the
// system queries of the store (identifiers only); every other method runs
// in the scope of the tenant it is given.
type repo interface {
	dueDeletions(ctx context.Context, now time.Time, page store.SweepPage) ([]store.TenantTransfer, error)
	dueExpirations(ctx context.Context, now time.Time, scanningMaxAge time.Duration, page store.SweepPage) ([]store.TenantTransfer, error)
	rejectedKeyed(ctx context.Context, page store.SweepPage) ([]store.TenantTransfer, error)
	abandonedUploads(ctx context.Context, createdBefore time.Time, page store.SweepPage) ([]store.TenantTransfer, error)
	transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error)
	finish(ctx context.Context, k kind, tid tenant.ID, trfID string, now time.Time, stillDue func(store.Transfer) bool) error
	scrub(ctx context.Context) error

	tenantIDs(ctx context.Context) ([]tenant.ID, error)
	listEnded(ctx context.Context, tid tenant.ID, endedBefore time.Time, limit int) ([]string, error)
	deleteEnded(ctx context.Context, tid tenant.ID, trfID string) error
	purge(ctx context.Context, p rowPurge, tid tenant.ID, now time.Time) (int64, error)
	purgeSystem(ctx context.Context, p systemPurge, now time.Time) (int64, error)

	storageRefs(ctx context.Context, tid tenant.ID) (map[string]store.StorageRef, error)
	availableIDs(ctx context.Context, tid tenant.ID) ([]string, error)

	backupSupported() bool
	backup(ctx context.Context, path string) error
}

// storeRepo implements repo over a *store.DB, destroying the sealed
// download tokens with vault.
type storeRepo struct {
	db    *store.DB
	vault Vault
}

func (r storeRepo) dueDeletions(ctx context.Context, now time.Time, page store.SweepPage) ([]store.TenantTransfer, error) {
	return r.db.Transfers().DueDeletions(ctx, now, page)
}

func (r storeRepo) dueExpirations(ctx context.Context, now time.Time, scanningMaxAge time.Duration, page store.SweepPage) ([]store.TenantTransfer, error) {
	return r.db.Transfers().DueExpirations(ctx, now, scanningMaxAge, page)
}

func (r storeRepo) rejectedKeyed(ctx context.Context, page store.SweepPage) ([]store.TenantTransfer, error) {
	return r.db.Transfers().RejectedKeyed(ctx, page)
}

func (r storeRepo) abandonedUploads(ctx context.Context, createdBefore time.Time, page store.SweepPage) ([]store.TenantTransfer, error) {
	return r.db.Transfers().AbandonedUploads(ctx, createdBefore, page)
}

func (r storeRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	return r.db.Transfers().Get(ctx, tid, trfID)
}

// finish ends the erasure of kind k of the transfer trfID of tid at now,
// in one transaction: it checks inside it that the transfer is still due
// (stillDue, which applies finalDue; errNotDue otherwise), destroys its
// sealed download token if any, then marks it deleted (kindDelete) or
// expired. The store refuses while a file key remains
// (store.ErrKeysRemain).
func (r storeRepo) finish(ctx context.Context, k kind, tid tenant.ID, trfID string, now time.Time, stillDue func(store.Transfer) bool) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	return s.Tx(ctx, func(tx *store.ScopedTx) error {
		d, err := r.db.Transfers().GetTx(ctx, tx, trfID)
		if err != nil {
			return err
		}
		if !stillDue(d.Transfer) {
			return errNotDue
		}
		if d.DownloadTokenKeyID != "" {
			if err := r.vault.DestroyTx(ctx, tx, d.DownloadTokenKeyID); err != nil {
				return err
			}
		}
		if k == kindDelete {
			return r.db.Transfers().MarkDeletedTx(ctx, tx, trfID)
		}
		return r.db.Transfers().MarkExpiredTx(ctx, tx, trfID, now)
	})
}

func (r storeRepo) scrub(ctx context.Context) error {
	return r.db.ScrubDeleted(ctx)
}

func (r storeRepo) tenantIDs(ctx context.Context) ([]tenant.ID, error) {
	return r.db.Tenants().IDs(ctx)
}

func (r storeRepo) listEnded(ctx context.Context, tid tenant.ID, endedBefore time.Time, limit int) ([]string, error) {
	return r.db.Transfers().ListEnded(ctx, tid, endedBefore, limit)
}

// deleteEnded deletes the row of the ended transfer trfID of tid (with its
// recipients and files, by cascade) in its own transaction.
func (r storeRepo) deleteEnded(ctx context.Context, tid tenant.ID, trfID string) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	return s.Tx(ctx, func(tx *store.ScopedTx) error {
		return r.db.Transfers().DeleteTx(ctx, tx, trfID)
	})
}

func (r storeRepo) purge(ctx context.Context, p rowPurge, tid tenant.ID, now time.Time) (int64, error) {
	return p.run(ctx, r.db, tid, now)
}

func (r storeRepo) purgeSystem(ctx context.Context, p systemPurge, now time.Time) (int64, error) {
	return p.run(ctx, r.db, now)
}

func (r storeRepo) storageRefs(ctx context.Context, tid tenant.ID) (map[string]store.StorageRef, error) {
	return r.db.TransferFiles().StorageRefs(ctx, tid)
}

func (r storeRepo) availableIDs(ctx context.Context, tid tenant.ID) ([]string, error) {
	return r.db.Transfers().IDsByStatus(ctx, tid, store.TransferAvailable)
}

// backupSupported reports whether TransTeira copies the database itself
// (SQLite).
func (r storeRepo) backupSupported() bool {
	return r.db.Driver() == config.DriverSQLite
}

func (r storeRepo) backup(ctx context.Context, path string) error {
	return r.db.Backup(ctx, path)
}

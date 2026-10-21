package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// errNotDue reports, from inside the final transaction, a transfer that is
// no longer available or no longer due: the transaction is rolled back and
// the transfer skipped.
var errNotDue = errors.New("lifecycle: transfer not due")

// repo is the part of the store the sweeper uses. It exists so that the
// tests can inject a failure at any step; [storeRepo] is the only real
// implementation. Every method but due and scrub runs in the scope of the
// tenant it is given.
type repo interface {
	due(ctx context.Context, now time.Time) ([]store.TenantTransfer, error)
	transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error)
	finish(ctx context.Context, tid tenant.ID, trfID string, now time.Time) error
	scrub(ctx context.Context) error
}

// storeRepo implements repo over a *store.DB, destroying the sealed
// download tokens with vault.
type storeRepo struct {
	db    *store.DB
	vault Vault
}

func (r storeRepo) due(ctx context.Context, now time.Time) ([]store.TenantTransfer, error) {
	return r.db.Transfers().DueDeletions(ctx, now)
}

func (r storeRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	return r.db.Transfers().Get(ctx, tid, trfID)
}

// finish destroys the sealed download token of the transfer trfID of tid,
// then marks it deleted, in one transaction, after checking inside it that
// the transfer is still due at now (errNotDue otherwise). The store refuses
// the deletion while a file key remains (store.ErrKeysRemain).
func (r storeRepo) finish(ctx context.Context, tid tenant.ID, trfID string, now time.Time) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	return s.Tx(ctx, func(tx *store.ScopedTx) error {
		d, err := r.db.Transfers().GetTx(ctx, tx, trfID)
		if err != nil {
			return err
		}
		if !due(d.Transfer, now) {
			return errNotDue
		}
		if d.DownloadTokenKeyID != "" {
			if err := r.vault.DestroyTx(ctx, tx, d.DownloadTokenKeyID); err != nil {
				return err
			}
		}
		return r.db.Transfers().MarkDeletedTx(ctx, tx, trfID)
	})
}

func (r storeRepo) scrub(ctx context.Context) error {
	return r.db.ScrubDeleted(ctx)
}

// due reports whether t must be deleted at now: available, with a
// DeleteAfter at or before now.
func due(t store.Transfer, now time.Time) bool {
	return t.Status == store.TransferAvailable && !t.DeleteAfter.IsZero() && !t.DeleteAfter.After(now)
}

package download

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// repo is the part of the store the service uses. It exists so that the
// tests can inject a failure at any step; [storeRepo] is the only real
// implementation. Every method runs in the scope of the tenant it is given
// (CLAUDE.md section 5).
type repo interface {
	// byToken returns the transfer whose download token has the SHA-256
	// hash, in whatever state it is.
	byToken(ctx context.Context, tid tenant.ID, hash []byte) (store.TransferDetails, error)
	// reserve checks the password failure counters keys at now and, unless
	// one is locked, counts one failure on each of them, in one
	// transaction under the tenant lock. It returns the end of the lock
	// that refused the attempt (zero when the attempt may proceed) and,
	// for an attempt that may proceed, the outcome of the failure counted
	// in advance.
	reserve(ctx context.Context, tid tenant.ID, keys []store.FailureKey, now time.Time) (time.Time, store.FailureOutcome, error)
	// unlocked settles a right password whose attempt was counted at at:
	// it deletes the transfer counter trf and refunds the failure counted
	// on the client counter ip, in one transaction.
	unlocked(ctx context.Context, tid tenant.ID, trf, ip store.FailureKey, at time.Time) error
	// refund withdraws the failure counted at at on every counter of keys,
	// for an attempt whose password could not be verified.
	refund(ctx context.Context, tid tenant.ID, keys []store.FailureKey, at time.Time) error
	// transfer reads the transfer trfID as stored.
	transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error)
	// markFirst records the first complete download of the transfer.
	markFirst(ctx context.Context, tid tenant.ID, trfID string, now, deleteAfter time.Time) (bool, error)
	// started records a download start of the transfer trfID: the audit
	// event ev, through the checks of the audit package, and one more
	// download, in one transaction.
	started(ctx context.Context, tid tenant.ID, trfID string, ev audit.Event) error
	// claim records a download start of the transfer trfID, which has a
	// download limit: the audit event ev and the conditional count of the
	// start (store.Transfers.ClaimDownloadTx, deleteAfter being the
	// deletion time set by the start reaching the limit), in one
	// transaction. It returns the starts still allowed, or
	// store.ErrMaxDownloads when the limit was already reached.
	claim(ctx context.Context, tid tenant.ID, trfID string, deleteAfter time.Time, ev audit.Event) (int, error)
}

// storeRepo implements repo over a *store.DB.
type storeRepo struct {
	db *store.DB
	// audit writes the audit events, nil when db is (a service built
	// without a database, in the tests only).
	audit *audit.Writer
}

// auditWriter returns shared, or a writer of its own over db when shared
// is nil; nil for a nil db.
func auditWriter(db *store.DB, shared *audit.Writer) *audit.Writer {
	if db == nil {
		return nil
	}
	return audit.OrNew(shared, db)
}

func (r storeRepo) byToken(ctx context.Context, tid tenant.ID, hash []byte) (store.TransferDetails, error) {
	return r.db.Transfers().GetByDownloadTokenHash(ctx, tid, hash)
}

// tx runs fn in a write transaction of tenant tid.
func (r storeRepo) tx(ctx context.Context, tid tenant.ID, fn func(*store.ScopedTx) error) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	return s.Tx(ctx, fn)
}

func (r storeRepo) reserve(ctx context.Context, tid tenant.ID, keys []store.FailureKey, now time.Time) (time.Time, store.FailureOutcome, error) {
	var (
		until time.Time
		out   store.FailureOutcome
	)
	err := r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		var err error
		if until, err = r.db.PasswordFailures().CheckTx(ctx, tx, keys, now); err != nil || !until.IsZero() {
			return err
		}
		out, err = r.db.PasswordFailures().RecordFailureTx(ctx, tx, keys, now)
		return err
	})
	if err != nil {
		return time.Time{}, store.FailureOutcome{}, err
	}
	return until, out, nil
}

func (r storeRepo) unlocked(ctx context.Context, tid tenant.ID, trf, ip store.FailureKey, at time.Time) error {
	return r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		if err := r.db.PasswordFailures().ResetTx(ctx, tx, []store.FailureKey{trf}); err != nil {
			return err
		}
		return r.db.PasswordFailures().RefundTx(ctx, tx, []store.FailureKey{ip}, at)
	})
}

func (r storeRepo) refund(ctx context.Context, tid tenant.ID, keys []store.FailureKey, at time.Time) error {
	return r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		return r.db.PasswordFailures().RefundTx(ctx, tx, keys, at)
	})
}

func (r storeRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	return r.db.Transfers().Get(ctx, tid, trfID)
}

func (r storeRepo) markFirst(ctx context.Context, tid tenant.ID, trfID string, now, deleteAfter time.Time) (bool, error) {
	var first bool
	err := r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		var err error
		first, err = r.db.Transfers().MarkFirstDownloadTx(ctx, tx, trfID, now, deleteAfter)
		return err
	})
	return first, err
}

func (r storeRepo) started(ctx context.Context, tid tenant.ID, trfID string, ev audit.Event) error {
	return r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		if err := r.audit.RecordScopedTx(ctx, tx, ev); err != nil {
			return err
		}
		return r.db.Transfers().IncrementDownloadsTx(ctx, tx, trfID)
	})
}

func (r storeRepo) claim(ctx context.Context, tid tenant.ID, trfID string, deleteAfter time.Time, ev audit.Event) (int, error) {
	var remaining int
	err := r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		var err error
		if remaining, err = r.db.Transfers().ClaimDownloadTx(ctx, tx, trfID, deleteAfter); err != nil {
			return err
		}
		return r.audit.RecordScopedTx(ctx, tx, ev)
	})
	return remaining, err
}

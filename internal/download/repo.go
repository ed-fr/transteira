package download

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/vcode"
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
	// download, in one transaction. Through the recipient link linkID ("" for
	// a shared link), the start of item (a file ID, "" for the archive) is
	// also recorded on the link (store.RecipientLinks.ClaimTx).
	started(ctx context.Context, tid tenant.ID, trfID, linkID, item string, now time.Time, ev audit.Event) error
	// claim records a download start of the transfer trfID, which has a
	// download limit: the audit event ev and the conditional count of the
	// start (store.Transfers.ClaimDownloadTx, deleteAfter being the
	// deletion time set by the start reaching the limit), and through the
	// recipient link linkID ("" for a shared link) the start of item on the
	// link, in one transaction. It returns the starts still allowed, or
	// store.ErrMaxDownloads when the limit was already reached.
	claim(ctx context.Context, tid tenant.ID, trfID, linkID, item string, now, deleteAfter time.Time, ev audit.Event) (int, error)
	// linkByToken returns the recipient link whose download token has the
	// SHA-256 hash, with its recipient address.
	linkByToken(ctx context.Context, tid tenant.ID, hash []byte) (store.RecipientLink, error)
	// link reads the recipient link linkID as stored.
	link(ctx context.Context, tid tenant.ID, linkID string) (store.RecipientLink, error)
	// completeItem records that item (a file ID, "" for the archive) was
	// fully served through the recipient link linkID at now.
	completeItem(ctx context.Context, tid tenant.ID, linkID, item string, now time.Time) error
	// completeLink records the first complete download through the
	// recipient link linkID of the transfer trfID and, in the same
	// transaction, the first download of the transfer
	// (store.Transfers.MarkFirstDownloadTx, deleteAfter set only once every
	// link is complete). It returns whether this was the first complete
	// download of the transfer, and errLinkUnclaimed for a link whose
	// download start was never recorded.
	completeLink(ctx context.Context, tid tenant.ID, trfID, linkID string, now, deleteAfter time.Time) (bool, error)
	// latestChallenge reads the newest recipient challenge of the recipient
	// link linkID, in whatever state it is (store.ErrNotFound when none).
	latestChallenge(ctx context.Context, tid tenant.ID, linkID string) (store.Challenge, error)
	// createChallenge counts the codes of the recipient link of ch and of
	// its client IP since since and, below both budgets, stores ch, in one
	// transaction after the tenant lock. Over a budget it returns
	// errLimited and the scope of the limit.
	createChallenge(ctx context.Context, tid tenant.ID, ch store.Challenge, since time.Time) (string, error)
	// deleteChallenge removes the challenge chID.
	deleteChallenge(ctx context.Context, tid tenant.ID, chID string) error
	// spend spends one attempt of the open challenge chID at now and
	// returns the attempts left (store.ErrNotFound when it is no longer
	// open).
	spend(ctx context.Context, tid tenant.ID, chID string, now time.Time) (int, error)
	// verified consumes the challenge chID, marks the recipient link linkID
	// verified and records the audit event ev, in one transaction
	// (store.ErrNotFound when the challenge is no longer open).
	verified(ctx context.Context, tid tenant.ID, chID, linkID string, now time.Time, ev audit.Event) error
}

// errLinkUnclaimed reports the completion of a recipient link whose
// download start was never recorded (a failed recording): nothing can be
// recorded for it.
var errLinkUnclaimed = errors.New("download: recipient link completed without a recorded start")

// errLimited aborts the transaction of a code request over a rate limit.
var errLimited = errors.New("download: verification code rate limit reached")

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

func (r storeRepo) started(ctx context.Context, tid tenant.ID, trfID, linkID, item string, now time.Time, ev audit.Event) error {
	return r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		if err := r.audit.RecordScopedTx(ctx, tx, ev); err != nil {
			return err
		}
		if err := r.db.Transfers().IncrementDownloadsTx(ctx, tx, trfID); err != nil {
			return err
		}
		return r.claimLink(ctx, tx, linkID, item, now)
	})
}

func (r storeRepo) claim(ctx context.Context, tid tenant.ID, trfID, linkID, item string, now, deleteAfter time.Time, ev audit.Event) (int, error) {
	var remaining int
	err := r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		var err error
		if remaining, err = r.db.Transfers().ClaimDownloadTx(ctx, tx, trfID, deleteAfter); err != nil {
			return err
		}
		if err := r.claimLink(ctx, tx, linkID, item, now); err != nil {
			return err
		}
		return r.audit.RecordScopedTx(ctx, tx, ev)
	})
	return remaining, err
}

// claimLink records, inside tx, the start of item through the recipient
// link linkID at now; nothing for a shared link (linkID "").
func (r storeRepo) claimLink(ctx context.Context, tx *store.ScopedTx, linkID, item string, now time.Time) error {
	if linkID == "" {
		return nil
	}
	return r.db.RecipientLinks().ClaimTx(ctx, tx, linkID, item, now)
}

func (r storeRepo) linkByToken(ctx context.Context, tid tenant.ID, hash []byte) (store.RecipientLink, error) {
	return r.db.RecipientLinks().GetByTokenHash(ctx, tid, hash)
}

func (r storeRepo) link(ctx context.Context, tid tenant.ID, linkID string) (store.RecipientLink, error) {
	var l store.RecipientLink
	s, err := r.db.Scoped(tid)
	if err != nil {
		return l, err
	}
	err = s.ReadTx(ctx, func(tx *store.ScopedTx) error {
		var err error
		l, err = r.db.RecipientLinks().GetTx(ctx, tx, linkID)
		return err
	})
	return l, err
}

func (r storeRepo) completeItem(ctx context.Context, tid tenant.ID, linkID, item string, now time.Time) error {
	return r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		_, err := r.db.RecipientLinks().CompleteItemTx(ctx, tx, linkID, item, now)
		return err
	})
}

func (r storeRepo) completeLink(ctx context.Context, tid tenant.ID, trfID, linkID string, now, deleteAfter time.Time) (bool, error) {
	var first bool
	err := r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		_, err := r.db.RecipientLinks().CompleteTx(ctx, tx, linkID, now)
		switch {
		case errors.Is(err, store.ErrConflict):
			return errLinkUnclaimed
		case err != nil:
			return err
		}
		first, err = r.db.Transfers().MarkFirstDownloadTx(ctx, tx, trfID, now, deleteAfter)
		return err
	})
	return first, err
}

func (r storeRepo) latestChallenge(ctx context.Context, tid tenant.ID, linkID string) (store.Challenge, error) {
	return r.db.Challenges().LatestByLink(ctx, tid, linkID)
}

func (r storeRepo) createChallenge(ctx context.Context, tid tenant.ID, ch store.Challenge, since time.Time) (string, error) {
	scope := ""
	err := r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		n, err := r.db.Challenges().CountByLinkSinceTx(ctx, tx, ch.RecipientLinkID, since)
		if err != nil {
			return fmt.Errorf("count codes per link: %w", err)
		}
		if n >= vcode.MaxPerAddress {
			scope = scopeCodesPerLink
			return errLimited
		}
		if n, err = r.db.Challenges().CountByIPSinceTx(ctx, tx, ch.ClientIP, since); err != nil {
			return fmt.Errorf("count codes per ip: %w", err)
		}
		if n >= vcode.MaxPerIP {
			scope = scopeCodesPerIP
			return errLimited
		}
		return r.db.Challenges().CreateTx(ctx, tx, ch)
	})
	return scope, err
}

func (r storeRepo) deleteChallenge(ctx context.Context, tid tenant.ID, chID string) error {
	return r.db.Challenges().Delete(ctx, tid, chID)
}

func (r storeRepo) spend(ctx context.Context, tid tenant.ID, chID string, now time.Time) (int, error) {
	return r.db.Challenges().DecrementAttempt(ctx, tid, chID, now)
}

func (r storeRepo) verified(ctx context.Context, tid tenant.ID, chID, linkID string, now time.Time, ev audit.Event) error {
	return r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		if err := r.db.Challenges().ConsumeTx(ctx, tx, chID, now); err != nil {
			return err
		}
		if err := r.db.RecipientLinks().MarkVerifiedTx(ctx, tx, linkID, now); err != nil {
			return err
		}
		return r.audit.RecordScopedTx(ctx, tx, ev)
	})
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// reasonDeleteAfterDownload is the reason of the system query listing the
// transfers due for deletion after their first download across tenants.
const reasonDeleteAfterDownload = "delete after download"

// DeletionSweepLimit is the largest page of [Transfers.DueDeletions].
const DeletionSweepLimit = maxSweepPage

// Statements of the download bookkeeping. The deletion sweep is the only
// system query: everything else stays tenant-scoped.
var (
	// qTransferFirstDownload records the first download of an available
	// transfer without the "delete after the first download" option, at
	// most once.
	qTransferFirstDownload = tenantQuery(
		`UPDATE transfers SET first_downloaded_at = ?
		WHERE tenant_id = ? AND id = ? AND status = 'available' AND first_downloaded_at IS NULL
		AND NOT delete_after_first_download`)
	// qTransferFirstDownloadDelete records the first download of an
	// available transfer with the option, and when it becomes due for
	// deletion, at most once.
	qTransferFirstDownloadDelete = tenantQuery(
		`UPDATE transfers SET first_downloaded_at = ?, delete_after = ?
		WHERE tenant_id = ? AND id = ? AND status = 'available' AND first_downloaded_at IS NULL
		AND delete_after_first_download`)
	// qTransferMarkDeleted deletes an available transfer whose sealed
	// download token was destroyed first (T-110); the store checks the
	// file keys beforehand.
	qTransferMarkDeleted = tenantQuery(
		`UPDATE transfers SET status = 'deleted', ended_at = ?
		WHERE tenant_id = ? AND id = ? AND status = 'available' AND download_token_key_id IS NULL`)
	// qTransferDueDeletions returns identifiers and the due time only,
	// earliest due first, one page after a keyset cursor.
	qTransferDueDeletions = systemQuery(
		`SELECT tenant_id, id, delete_after FROM transfers
		WHERE delete_after IS NOT NULL AND delete_after <= ? AND status = 'available'
		AND (delete_after, tenant_id, id) > (?, ?, ?)
		ORDER BY delete_after, tenant_id, id LIMIT ?`,
		reasonDeleteAfterDownload)
)

// MarkFirstDownloadTx records, inside tx, that the available transfer
// trfID of the tenant tx is bound to was downloaded completely for the
// first time at now: every byte of every deliverable file was served at
// least once, or the whole archive was sent. deleteAfter is when the
// transfer becomes due for deletion ([Transfers.DueDeletions]): it is
// required (not before now) for a transfer with DeleteAfterFirstDownload,
// and must be zero for any other.
//
// The update is conditional, so that exactly one caller records the first
// download: it returns true for that caller, and false, without error, when
// the first download was already recorded (by an earlier or concurrent
// request), whatever the transfer's current status. The caller sends the
// first download notice only on true.
//
// It returns ErrInvalid for a deleteAfter before now or inconsistent with
// the transfer's option, ErrNotFound when the transfer does not exist or
// belongs to another tenant, and ErrConflict when it is not available.
// After an error, the caller must abort the transaction.
func (r *Transfers) MarkFirstDownloadTx(ctx context.Context, tx *ScopedTx, trfID string, now, deleteAfter time.Time) (bool, error) {
	first, err := markFirstDownload(ctx, tx, trfID, now, deleteAfter)
	if err != nil {
		return false, wrap("mark first download", err)
	}
	return first, nil
}

// markFirstDownload implements MarkFirstDownloadTx, returning raw errors.
func markFirstDownload(ctx context.Context, tx *ScopedTx, trfID string, now, deleteAfter time.Time) (bool, error) {
	if !deleteAfter.IsZero() && deleteAfter.Before(now) {
		return false, invalid("delete after must not be before now")
	}
	var (
		res sql.Result
		err error
	)
	if deleteAfter.IsZero() {
		res, err = tx.Exec(ctx, qTransferFirstDownload, toMillis(now), trfID)
	} else {
		res, err = tx.Exec(ctx, qTransferFirstDownloadDelete, toMillis(now), toMillis(deleteAfter), trfID)
	}
	if err == nil {
		err = expectOne(res)
	}
	if !errors.Is(err, ErrNotFound) {
		return err == nil, err
	}
	t, err := scanTransfer(tx.QueryRow(ctx, qTransferGet, trfID))
	switch {
	case err != nil:
		return false, err
	case !t.FirstDownloadedAt.IsZero():
		return false, nil
	case t.Status != TransferAvailable:
		return false, ErrConflict
	case deleteAfter.IsZero():
		return false, invalid("a transfer deleted after its first download needs its deletion time")
	default:
		return false, invalid("only a transfer deleted after its first download has a deletion time")
	}
}

// DueDeletions returns one page of the transfers of every tenant due for
// deletion after their first download at now: available, with a
// DeleteAfter at or before now. They come earliest due first (then by
// tenant and transfer), the SortKey of each being its DeleteAfter, after
// page.After and at most page.Limit of them (1 to DeletionSweepLimit). A
// due transfer stays listed until it is erased; the cursor lets a caller
// reach the transfers after a full page whatever happened to it. It is a
// system query (reason "delete after download") and returns identifiers
// only; the caller erases each transfer in the scope of its tenant: the
// file keys are destroyed, then the files removed from disk, then the
// served range state file removed; last, in one transaction that first
// checks the transfer is still due, the sealed download token is destroyed
// and [Transfers.MarkDeletedTx] sets the status to deleted. It returns
// ErrInvalid for a page limit out of range.
func (r *Transfers) DueDeletions(ctx context.Context, now time.Time, page SweepPage) ([]TenantTransfer, error) {
	return r.db.sweepPage(ctx, reasonDeleteAfterDownload, "sweep due deletions", qTransferDueDeletions,
		page, toMillis(now))
}

// MarkDeletedTx moves the available transfer trfID of the tenant tx is
// bound to to deleted, inside tx, keeping its row (and its download token
// hash, so that the link answers "gone"), and sets EndedAt to the store's
// clock. The data key of every file and
// the sealed download token (DownloadTokenKeyID) must have been destroyed
// first ([WrappedKeys.DeleteTx]), the token key in the same transaction;
// otherwise it returns [ErrKeysRemain] and changes nothing. It returns
// ErrNotFound when the transfer does not exist or belongs to another
// tenant, and ErrConflict when it is not available. The lifecycle sweeper
// destroys the file keys, removes the files and the served range state
// from disk, then destroys the token key and calls MarkDeletedTx in one
// transaction, and finally calls [DB.ScrubDeleted]. After an error, the
// caller must abort the transaction.
func (r *Transfers) MarkDeletedTx(ctx context.Context, tx *ScopedTx, trfID string) error {
	if err := markDeleted(ctx, tx, trfID, r.db.now()); err != nil {
		return wrap("mark transfer deleted", err)
	}
	return nil
}

// markDeleted implements MarkDeletedTx, returning raw errors.
func markDeleted(ctx context.Context, tx *ScopedTx, trfID string, now time.Time) error {
	var keyed int
	if err := tx.QueryRow(ctx, qFileCountKeyed, trfID).Scan(&keyed); err != nil {
		return err
	}
	if keyed > 0 {
		return ErrKeysRemain
	}
	res, err := tx.Exec(ctx, qTransferMarkDeleted, toMillis(now), trfID)
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
	case t.Status != TransferAvailable:
		return ErrConflict
	default:
		return ErrKeysRemain
	}
}

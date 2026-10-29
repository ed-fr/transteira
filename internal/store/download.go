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

// reasonDeleteAfterLinks is the review of qTransferDeleteAfterLinks: the
// tenant slot filters transfers, and the subquery reads the recipient links
// of the same tenant and transfer only (l.tenant_id = t.tenant_id); on
// PostgreSQL the recipient_links policy also restricts it to the tenant.
const reasonDeleteAfterLinks = "delete after download: wait until every recipient link of the same tenant and transfer completed"

// DeletionSweepLimit is the largest page of [Transfers.DueDeletions].
const DeletionSweepLimit = maxSweepPage

// Statements of the download bookkeeping. The deletion sweep is the only
// system query: everything else stays tenant-scoped.
var (
	// qTransferFirstDownload records the first download of an available
	// shared transfer without the "delete after the first download"
	// option, at most once.
	qTransferFirstDownload = tenantQuery(
		`UPDATE transfers SET first_downloaded_at = ?
		WHERE tenant_id = ? AND id = ? AND status = 'available' AND first_downloaded_at IS NULL
		AND NOT delete_after_first_download AND link_mode = 'shared'`)
	// qTransferFirstDownloadDelete records the first download of an
	// available shared transfer with the option, and when it becomes due
	// for deletion, at most once.
	qTransferFirstDownloadDelete = tenantQuery(
		`UPDATE transfers SET first_downloaded_at = ?, delete_after = ?
		WHERE tenant_id = ? AND id = ? AND status = 'available' AND first_downloaded_at IS NULL
		AND delete_after_first_download AND link_mode = 'shared'`)
	// qTransferFirstDownloadLinks records the first complete download
	// through any link of an available per-recipient transfer, at most
	// once, whatever its option: the deletion waits for every recipient
	// (qTransferDeleteAfterLinks).
	qTransferFirstDownloadLinks = tenantQuery(
		`UPDATE transfers SET first_downloaded_at = ?
		WHERE tenant_id = ? AND id = ? AND status = 'available' AND first_downloaded_at IS NULL
		AND link_mode = 'per_recipient'`)
	// qTransferDeleteAfterLinks makes an available per-recipient transfer
	// with the option due for deletion once every recipient link completed
	// a download (binding decision: the deletion waits for all the
	// recipients), keeping an earlier due time.
	qTransferDeleteAfterLinks = reviewedTenantQuery(
		`UPDATE transfers AS t SET delete_after = COALESCE(t.delete_after, ?)
		WHERE t.tenant_id = ? AND t.id = ? AND t.status = 'available' AND t.link_mode = 'per_recipient'
		AND t.delete_after_first_download AND t.first_downloaded_at IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM recipient_links l
			WHERE l.tenant_id = t.tenant_id AND l.transfer_id = t.id AND l.completed_at IS NULL)`,
		reasonDeleteAfterLinks)
	// qTransferClaimDownload counts a download start of an available
	// transfer with a download limit not reached yet. The start reaching
	// the limit also makes the transfer due for deletion, keeping an
	// earlier due time. SET reads the old values on both engines;
	// RETURNING reads the new ones.
	qTransferClaimDownload = tenantQuery(
		`UPDATE transfers SET download_count = download_count + 1,
		delete_after = (CASE WHEN download_count + 1 >= max_downloads THEN COALESCE(delete_after, ?) ELSE delete_after END)
		WHERE tenant_id = ? AND id = ? AND status = 'available' AND max_downloads IS NOT NULL
		AND download_count < max_downloads
		RETURNING max_downloads - download_count`)
	// qTransferMarkDeleted deletes an available transfer whose sealed
	// download token, and the sealed token of each of its recipient links,
	// were destroyed first (T-110); the store checks the file keys
	// beforehand.
	qTransferMarkDeleted = reviewedTenantQuery(
		`UPDATE transfers AS t SET status = 'deleted', ended_at = ?
		WHERE t.tenant_id = ? AND t.id = ? AND t.status = 'available' AND t.download_token_key_id IS NULL
		AND NOT EXISTS (SELECT 1 FROM recipient_links l
			WHERE l.tenant_id = t.tenant_id AND l.transfer_id = t.id AND l.token_key_id IS NOT NULL)`,
		reasonTransferEndLinkKeys)
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
// For a LinkModePerRecipient transfer, the caller calls it after each
// completed link ([RecipientLinks.CompleteTx]), in the same transaction:
// the first completed link records FirstDownloadedAt (true), and the
// DeleteAfter of a transfer with DeleteAfterFirstDownload is only set once
// no link of the transfer is left incomplete (the deletion waits for every
// recipient), by whichever call sees that, first or not.
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
	t, err := scanTransfer(tx.QueryRow(ctx, qTransferGet, trfID))
	if err != nil {
		return false, err
	}
	if t.LinkMode == LinkModePerRecipient {
		return markFirstLinkDownload(ctx, tx, t, now, deleteAfter)
	}
	var res sql.Result
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
	t, err = scanTransfer(tx.QueryRow(ctx, qTransferGet, trfID))
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

// markFirstLinkDownload implements MarkFirstDownloadTx for the
// per-recipient transfer t, returning raw errors.
func markFirstLinkDownload(ctx context.Context, tx *ScopedTx, t Transfer, now, deleteAfter time.Time) (bool, error) {
	switch {
	case t.DeleteAfterFirstDownload && deleteAfter.IsZero():
		return false, invalid("a transfer deleted after its first download needs its deletion time")
	case !t.DeleteAfterFirstDownload && !deleteAfter.IsZero():
		return false, invalid("only a transfer deleted after its first download has a deletion time")
	}
	res, err := tx.Exec(ctx, qTransferFirstDownloadLinks, toMillis(now), t.ID)
	if err == nil {
		err = expectOne(res)
	}
	first := err == nil
	switch {
	case errors.Is(err, ErrNotFound) && t.FirstDownloadedAt.IsZero() && t.Status != TransferAvailable:
		return false, ErrConflict
	case err != nil && !errors.Is(err, ErrNotFound):
		return false, err
	}
	if t.DeleteAfterFirstDownload {
		if _, err := tx.Exec(ctx, qTransferDeleteAfterLinks, toMillis(deleteAfter), t.ID); err != nil {
			return false, err
		}
	}
	return first, nil
}

// ClaimDownloadTx counts, inside tx, a download start (of a file or of the
// archive, never a HEAD request or a resumed range) of the available
// transfer trfID of the tenant tx is bound to, which has a download limit
// (Transfer.MaxDownloads), and returns the starts still allowed after this
// one. It replaces [Transfers.IncrementDownloadsTx] for such a transfer.
// The update is conditional, so that concurrent starts never exceed the
// limit. The start reaching the limit also sets DeleteAfter to deleteAfter
// (an earlier DeleteAfter is kept), so that the deletion sweep
// ([Transfers.DueDeletions]) erases the transfer.
//
// For a LinkModePerRecipient transfer, the start is also recorded on the
// recipient link in the same transaction ([RecipientLinks.ClaimTx]): the
// limit applies to the transfer, all links together.
//
// It returns ErrMaxDownloads when the limit was already reached (nothing is
// counted), ErrInvalid for a zero deleteAfter or a transfer without limit,
// ErrNotFound when the transfer does not exist or belongs to another
// tenant, and ErrConflict when it is not available. After an error, the
// caller must abort the transaction.
func (r *Transfers) ClaimDownloadTx(ctx context.Context, tx *ScopedTx, trfID string, deleteAfter time.Time) (int, error) {
	remaining, err := claimDownload(ctx, tx, trfID, deleteAfter)
	if err != nil {
		return 0, wrap("claim download", err)
	}
	return remaining, nil
}

// claimDownload implements ClaimDownloadTx, returning raw errors.
func claimDownload(ctx context.Context, tx *ScopedTx, trfID string, deleteAfter time.Time) (int, error) {
	if deleteAfter.IsZero() {
		return 0, invalid("a download limit needs the deletion time")
	}
	var remaining int
	err := tx.QueryRow(ctx, qTransferClaimDownload, toMillis(deleteAfter), trfID).Scan(&remaining)
	if !errors.Is(err, ErrNotFound) {
		return remaining, err
	}
	t, err := scanTransfer(tx.QueryRow(ctx, qTransferGet, trfID))
	switch {
	case err != nil:
		return 0, err
	case t.MaxDownloads == nil:
		return 0, invalid("the transfer has no download limit")
	case t.Status != TransferAvailable:
		return 0, ErrConflict
	default:
		return 0, ErrMaxDownloads
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
// clock. The data key of every file, the sealed download token
// (DownloadTokenKeyID) and the sealed token of every recipient link must
// have been destroyed first ([WrappedKeys.DeleteTx],
// [RecipientLinks.DestroyKeysTx]), the token keys in the same transaction;
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

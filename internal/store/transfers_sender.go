package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// MaxTransferLifetime is the longest lifetime of a transfer, from its
// creation to its expiry, that extensions may reach (spec 8.7, D3). The
// database checks it too (transfers_lifetime_check).
const MaxTransferLifetime = 90 * 24 * time.Hour

// Errors of [Transfers.ExtendTx]. Each one leaves the transfer unchanged.
var (
	// ErrNotExtendable reports an extension of a transfer that is not
	// available (still scanning), already expired, or whose downloads are
	// over: its maximum number of downloads is reached or it is due for
	// deletion after its downloads (API 409 state-conflict). It is also
	// returned when the transfer changed concurrently.
	ErrNotExtendable = errors.New("store: the transfer cannot be extended in its current state")
	// ErrExtensionShortens reports an extension whose new expiry is not
	// after the current one (API 400 not-allowed).
	ErrExtensionShortens = errors.New("store: an extension cannot shorten the validity")
	// ErrExtensionLimit reports an extension beyond MaxTransferLifetime
	// after the creation of the transfer (API 409 extension-limit-reached).
	ErrExtensionLimit = errors.New("store: the transfer cannot live more than 90 days")
)

// senderScope is the scope of every "my transfers" statement (T-209): the
// tenant, the sender address, and the transfers of a deposit session (an
// API token owns its transfers, D-API).
const senderScope = `tenant_id = ? AND sender_email = ? AND api_token_id IS NULL`

// senderOpen restricts the scope to the transfers still in progress.
const senderOpen = ` AND status IN ('scanning', 'available')`

// Statements of the "my transfers" view of the transfers. All of them are
// single-table tenant queries.
var (
	// qTransferSenderList lists the transfers in progress of a sender,
	// newest first, after a keyset cursor (created_at, id), through
	// transfers_sender_created_idx.
	qTransferSenderList = tenantQuery(
		`SELECT ` + transferColumns + ` FROM transfers WHERE ` + senderScope + senderOpen + `
		AND (created_at, id) < (?, ?) ORDER BY created_at DESC, id DESC LIMIT ?`)
	qTransferSenderGet = tenantQuery(
		`SELECT ` + transferColumns + ` FROM transfers WHERE ` + senderScope + ` AND id = ?` + senderOpen)
	qTransferSenderStatus = tenantQuery(
		`SELECT status FROM transfers WHERE ` + senderScope + ` AND id = ?`)
	// qTransferExtend applies an extension with every guard of
	// [Transfers.ExtendTx] checked again, so that it never applies to a
	// row changed since it was read. The 90-day bound is
	// MaxTransferLifetime in milliseconds.
	qTransferExtend = tenantQuery(
		`UPDATE transfers SET expires_at = ?, extension_count = extension_count + 1, extended_at = ?,
		expiry_reminder_at = ?
		WHERE ` + senderScope + ` AND id = ? AND status = 'available' AND delete_after IS NULL
		AND (max_downloads IS NULL OR download_count < max_downloads)
		AND expires_at > ? AND expires_at < ? AND created_at + 7776000000 >= ?`)
	// qLinkReminderResetAll re-arms the expiry reminder of every link of a
	// transfer (one reminder per expiry date).
	qLinkReminderResetAll = tenantQuery(
		`UPDATE recipient_links SET reminder_sent_at = NULL WHERE tenant_id = ? AND transfer_id = ?`)
	// qLinkCountDownloaded counts the links of a transfer through which a
	// download started.
	qLinkCountDownloaded = tenantQuery(
		`SELECT count(*) FROM recipient_links WHERE tenant_id = ? AND transfer_id = ? AND first_downloaded_at IS NOT NULL`)
)

// SenderTransfer is a transfer as "my transfers" lists it (OpenAPI
// MyTransfer).
type SenderTransfer struct {
	Transfer
	// Recipients are the normalized recipient addresses, in the sender's
	// order.
	Recipients []string
	// FileCount is the number of files of the transfer.
	FileCount int
	// DownloadedBy counts the recipients through whose own link a download
	// started (per-recipient links only; 0 for a shared transfer).
	DownloadedBy int
}

// SenderTransferDetail is a transfer as "my transfers" shows it (OpenAPI
// MyTransferDetail): with its recipients, files and per-recipient
// tracking, never a link or a token.
type SenderTransferDetail struct {
	TransferDetails
	// DownloadedBy is as in [SenderTransfer].
	DownloadedBy int
	// Tracking is the tracking of each recipient, in position order
	// ([RecipientLinks.TrackingByTransfer]); empty for a shared transfer.
	Tracking []RecipientTracking
}

// TransferExtension is the outcome of [Transfers.ExtendTx].
type TransferExtension struct {
	// PreviousExpiresAt is the expiry before the extension.
	PreviousExpiresAt time.Time
	// ExpiresAt is the new expiry.
	ExpiresAt time.Time
	// Count is the number of extensions of the transfer, this one included.
	Count int
	// ReminderSkipped reports that the new remaining lifetime is under
	// ReminderMinLifetime: the expiry reminder pass is marked done (D16)
	// instead of re-armed.
	ReminderSkipped bool
}

// downloadedBy counts the links of trfID through which a download started.
func downloadedBy(ctx context.Context, tx *ScopedTx, trfID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, qLinkCountDownloaded, trfID).Scan(&n)
	return n, err
}

// ListBySender returns a page of the transfers of tenant tid sent by the
// address email with a deposit session (never with an API token) that are
// still in progress (scanning or available), newest first (by creation
// time, then ID), each with its recipients, number of files and number of
// recipients who downloaded, read in the same transaction. The cursor is
// the NextCursor of the previous page ("" for the first) and limit the
// page size (DefaultPageSize when <= 0, at most MaxPageSize). It returns
// ErrInvalid for a malformed address or cursor.
func (r *Transfers) ListBySender(ctx context.Context, tid tenant.ID, email, cursor string, limit int) (Page[SenderTransfer], error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return Page[SenderTransfer]{}, err
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return Page[SenderTransfer]{}, err
	}
	atCursor, idCursor, err := parseTimeCursor(cursor, id.Transfer)
	if err != nil {
		return Page[SenderTransfer]{}, err
	}
	limit = pageLimit(limit)
	items, err := readScoped(ctx, r.db, tid, "list transfers by sender", func(tx *ScopedTx) ([]SenderTransfer, error) {
		rows, err := tx.Query(ctx, qTransferSenderList, email, atCursor, idCursor, limit+1)
		if err != nil {
			return nil, err
		}
		ts, err := collect(rows, func(r *sql.Rows) (Transfer, error) { return scanTransfer(r) })
		if err != nil {
			return nil, err
		}
		out := make([]SenderTransfer, len(ts))
		for i, t := range ts {
			a, err := adminTransfer(ctx, tx, t)
			if err != nil {
				return nil, err
			}
			n, err := downloadedBy(ctx, tx, t.ID)
			if err != nil {
				return nil, err
			}
			out[i] = SenderTransfer{Transfer: t, Recipients: a.Recipients, FileCount: a.FileCount, DownloadedBy: n}
		}
		return out, nil
	})
	if err != nil {
		return Page[SenderTransfer]{}, err
	}
	return paginate(items, limit, func(t SenderTransfer) string { return timeCursor(t.CreatedAt, t.ID) }), nil
}

// GetBySender returns the transfer trfID of tenant tid sent by the address
// email with a deposit session and still in progress (scanning or
// available), with its recipients, files and per-recipient tracking, read
// in one transaction. It returns ErrNotFound, identically, for a transfer
// that does not exist, belongs to another tenant or another sender, was
// created with an API token or has ended, and ErrInvalid for a malformed
// address.
func (r *Transfers) GetBySender(ctx context.Context, tid tenant.ID, trfID, email string) (SenderTransferDetail, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return SenderTransferDetail{}, err
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return SenderTransferDetail{}, err
	}
	return readScoped(ctx, r.db, tid, "get transfer by sender", func(tx *ScopedTx) (SenderTransferDetail, error) {
		return senderDetail(ctx, tx, trfID, email)
	})
}

// GetBySenderTx is [Transfers.GetBySender] inside tx, for the tenant tx is
// bound to (after [Transfers.ExtendTx], for instance). After an error, the
// caller must abort the transaction.
func (r *Transfers) GetBySenderTx(ctx context.Context, tx *ScopedTx, trfID, email string) (SenderTransferDetail, error) {
	d, err := func() (SenderTransferDetail, error) {
		email, err := NormalizeEmail(email)
		if err != nil {
			return SenderTransferDetail{}, err
		}
		return senderDetail(ctx, tx, trfID, email)
	}()
	if err != nil {
		return SenderTransferDetail{}, wrap("get transfer by sender", err)
	}
	return d, nil
}

// senderDetail implements GetBySender inside tx for a normalized address,
// returning raw errors.
func senderDetail(ctx context.Context, tx *ScopedTx, trfID, email string) (SenderTransferDetail, error) {
	d, err := details(ctx, tx, tx.QueryRow(ctx, qTransferSenderGet, email, trfID))
	if err != nil {
		return SenderTransferDetail{}, err
	}
	n, err := downloadedBy(ctx, tx, trfID)
	if err != nil {
		return SenderTransferDetail{}, err
	}
	tr, err := tracking(ctx, tx, trfID)
	if err != nil {
		return SenderTransferDetail{}, err
	}
	return SenderTransferDetail{TransferDetails: d, DownloadedBy: n, Tracking: tr}, nil
}

// SenderStatus returns the status of the transfer trfID of tenant tid sent
// by the address email with a deposit session, whatever its status, so
// that deleting a transfer of the sender that already ended is a no-op
// rather than a not-found. It returns ErrNotFound when the transfer does
// not exist, belongs to another tenant or another sender, or was created
// with an API token, and ErrInvalid for a malformed address.
func (r *Transfers) SenderStatus(ctx context.Context, tid tenant.ID, trfID, email string) (TransferStatus, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return "", err
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return "", err
	}
	return readScoped(ctx, r.db, tid, "get transfer status by sender", func(tx *ScopedTx) (TransferStatus, error) {
		var s string
		err := tx.QueryRow(ctx, qTransferSenderStatus, email, trfID).Scan(&s)
		return TransferStatus(s), err
	})
}

// ExtendTx extends, inside tx, the expiry of the transfer trfID of the
// tenant tx is bound to, sent by the address email with a deposit session,
// to expiresAt, at now (spec 8.7, D3). The caller computes expiresAt (now
// plus a duration) and checks beforehand that the duration is allowed by
// the snapshotted rules of the transfer (Transfer.Rules); the store checks
// the state and the bounds, then applies a conditional update guarded on
// all of them. In the same transaction it counts the extension
// (ExtensionCount, ExtendedAt) and re-arms the expiry reminder: the
// reminder mark of every recipient link is cleared, and the reminder pass
// of the transfer is cleared too, or marked done at now when the new
// remaining lifetime is under ReminderMinLifetime (D16).
//
// It returns, leaving the transfer unchanged:
//   - ErrNotFound when the transfer does not exist, belongs to another
//     tenant or another sender, was created with an API token or has
//     ended (the same scope as [Transfers.GetBySender]);
//   - ErrNotExtendable when it is still scanning, past its expiry, or its
//     downloads are over (maximum number of downloads reached, or due for
//     deletion after its downloads), or changed concurrently;
//   - ErrExtensionShortens when expiresAt is not after the current expiry;
//   - ErrExtensionLimit when expiresAt is more than MaxTransferLifetime
//     after the creation of the transfer;
//   - ErrInvalid for a malformed address or an expiresAt not after now.
//
// The checks run in that order. After an error, the caller must abort the
// transaction.
func (r *Transfers) ExtendTx(ctx context.Context, tx *ScopedTx, trfID, email string, expiresAt, now time.Time) (TransferExtension, error) {
	x, err := extend(ctx, tx, trfID, email, expiresAt, now)
	if err != nil {
		return TransferExtension{}, wrap("extend transfer", err)
	}
	return x, nil
}

// extend implements ExtendTx, returning raw errors.
func extend(ctx context.Context, tx *ScopedTx, trfID, email string, expiresAt, now time.Time) (TransferExtension, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return TransferExtension{}, err
	}
	if !expiresAt.After(now) {
		return TransferExtension{}, invalid("the new expiry must be after now")
	}
	t, err := scanTransfer(tx.QueryRow(ctx, qTransferSenderGet, email, trfID))
	if err != nil {
		return TransferExtension{}, err
	}
	if err := checkExtension(t, expiresAt, now); err != nil {
		return TransferExtension{}, err
	}
	return applyExtension(ctx, tx, t, expiresAt, now)
}

// checkExtension applies the rules of ExtendTx to t, as read.
func checkExtension(t Transfer, expiresAt, now time.Time) error {
	switch {
	case t.Status != TransferAvailable, !t.ExpiresAt.After(now), !t.DeleteAfter.IsZero(),
		t.MaxDownloads != nil && t.DownloadCount >= int64(*t.MaxDownloads):
		return ErrNotExtendable
	case !expiresAt.After(t.ExpiresAt):
		return ErrExtensionShortens
	case expiresAt.After(t.CreatedAt.Add(MaxTransferLifetime)):
		return ErrExtensionLimit
	}
	return nil
}

// applyExtension runs the guarded update of the extension of t, read in
// tx and checked, and re-arms its reminder. A row changed since it was
// read matches no row: ErrNotExtendable.
func applyExtension(ctx context.Context, tx *ScopedTx, t Transfer, expiresAt, now time.Time) (TransferExtension, error) {
	x := TransferExtension{
		PreviousExpiresAt: t.ExpiresAt, ExpiresAt: expiresAt, Count: t.ExtensionCount + 1,
		ReminderSkipped: expiresAt.Sub(now) < ReminderMinLifetime,
	}
	var reminder any
	if x.ReminderSkipped {
		reminder = toMillis(now)
	}
	ms, exp := toMillis(now), toMillis(expiresAt)
	res, err := tx.Exec(ctx, qTransferExtend, exp, ms, reminder, t.SenderEmail, t.ID, ms, exp, exp)
	if err == nil {
		err = expectOne(res)
	}
	if errors.Is(err, ErrNotFound) {
		return TransferExtension{}, ErrNotExtendable
	}
	if err != nil {
		return TransferExtension{}, err
	}
	if _, err := tx.Exec(ctx, qLinkReminderResetAll, t.ID); err != nil {
		return TransferExtension{}, err
	}
	return x, nil
}

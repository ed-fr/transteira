package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// reasonUsedBytesAll is the reason of the system query summing the storage
// used by every tenant.
const reasonUsedBytesAll = "quota sweep and global statistics: storage used by each tenant"

// reasonTransferAdminList is the review of qTransferAdminList: the tenant
// slot filters transfers, and the correlated subquery reads the recipients
// of the same tenant and transfer only (r.tenant_id = t.tenant_id AND
// r.transfer_id = t.id); on PostgreSQL the transfer_recipients policy also
// restricts it to the tenant of the scope.
const reasonTransferAdminList = "administrator list of the transfers: filter on a recipient address of the same tenant and transfer"

// reasonRecipientDeleteLinkKeys is the review of qRecipientDelete: the
// tenant slot filters transfer_recipients, and the subquery reads the link
// of the same tenant, transfer and recipient only; on PostgreSQL the
// recipient_links policy also restricts it to the tenant.
const reasonRecipientDeleteLinkKeys = "recipient removal: refuse while the link of the same tenant recipient keeps its sealed token"

// Statements of the administrator view of the transfers.
var (
	// qTransferAdminList lists the transfers of a tenant, newest first,
	// after a keyset cursor (created_at, id). The status and the address
	// filters are optional (''): the address matches the sender or a
	// recipient. Arguments after the tenant: status (twice), address
	// (three times), created after, cursor time, cursor id, limit.
	qTransferAdminList = reviewedTenantQuery(
		`SELECT `+transferColumns+` FROM transfers t
		WHERE t.tenant_id = ? AND (? = '' OR t.status = ?)
		AND (? = '' OR t.sender_email = ? OR EXISTS (SELECT 1 FROM transfer_recipients r
			WHERE r.tenant_id = t.tenant_id AND r.transfer_id = t.id AND r.email = ?))
		AND t.created_at > ? AND (t.created_at, t.id) < (?, ?)
		ORDER BY t.created_at DESC, t.id DESC LIMIT ?`,
		reasonTransferAdminList)
	qFileCountByTransfer = tenantQuery(
		`SELECT count(*) FROM transfer_files WHERE tenant_id = ? AND transfer_id = ?`)
	qTransferIncrementDownloads = tenantQuery(
		`UPDATE transfers SET download_count = download_count + 1 WHERE tenant_id = ? AND id = ?`)
	qTransferIDsBySender = tenantQuery(
		`SELECT id FROM transfers WHERE tenant_id = ? AND sender_email = ? ORDER BY id`)
	qTransferIDsByInvitation = tenantQuery(
		`SELECT id FROM transfers WHERE tenant_id = ? AND invitation_id = ? ORDER BY id`)
	qRecipientTransferIDs = tenantQuery(
		`SELECT transfer_id FROM transfer_recipients WHERE tenant_id = ? AND email = ? ORDER BY transfer_id`)
	// qRecipientDelete only deletes a recipient whose link, if any, no
	// longer keeps its sealed token (T-110): the cascade would otherwise
	// drop the link row and leave its key behind.
	qRecipientDelete = reviewedTenantQuery(
		`DELETE FROM transfer_recipients AS r WHERE r.tenant_id = ? AND r.transfer_id = ? AND r.email = ?
		AND NOT EXISTS (SELECT 1 FROM recipient_links l WHERE l.tenant_id = r.tenant_id
			AND l.transfer_id = r.transfer_id AND l.position = r.position AND l.token_key_id IS NOT NULL)`,
		reasonRecipientDeleteLinkKeys)
	qRecipientCountEmail = tenantQuery(
		`SELECT count(*) FROM transfer_recipients WHERE tenant_id = ? AND transfer_id = ? AND email = ?`)
	qRecipientCount = tenantQuery(
		`SELECT count(*) FROM transfer_recipients WHERE tenant_id = ? AND transfer_id = ?`)
	// qTransferUsedBytesAll is qTransferUsedBytes for every tenant at once.
	qTransferUsedBytesAll = systemQuery(
		`SELECT tenant_id, CAST(COALESCE(sum(total_bytes), 0) AS BIGINT) FROM transfers
		WHERE status IN ('uploading', 'scanning', 'available') GROUP BY tenant_id ORDER BY tenant_id`,
		reasonUsedBytesAll)
)

// AdminTransfer is a transfer as the administration lists it: its
// metadata, its recipients and its number of files.
type AdminTransfer struct {
	Transfer
	// Recipients are the normalized recipient addresses, in the sender's
	// order.
	Recipients []string
	// FileCount is the number of files of the transfer.
	FileCount int
}

// AdminTransferFilter selects a page of transfers for the administration,
// newest first.
type AdminTransferFilter struct {
	// Status keeps the transfers of this status only ("" for all).
	Status TransferStatus
	// Email keeps the transfers whose sender or one of whose recipients is
	// this address (exact match after normalization; "" for all).
	Email string
	// CreatedAfter keeps the transfers created strictly after this time
	// (zero: no bound).
	CreatedAfter time.Time
	// Cursor is the NextCursor of the previous page, or "" for the first.
	Cursor string
	// Limit is the page size (DefaultPageSize when <= 0, at most
	// MaxPageSize).
	Limit int
}

// AdminList returns a page of the transfers of tenant tid matching f,
// newest first (by creation time, then ID), in every status, each with its
// recipients and number of files, read in the same transaction. It returns
// ErrInvalid for an unknown status, a malformed address or a malformed
// cursor.
func (r *Transfers) AdminList(ctx context.Context, tid tenant.ID, f AdminTransferFilter) (Page[AdminTransfer], error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return Page[AdminTransfer]{}, err
	}
	if f.Status != "" && !f.Status.valid() {
		return Page[AdminTransfer]{}, invalid("unknown transfer status")
	}
	email := ""
	if f.Email != "" {
		var err error
		if email, err = NormalizeEmail(f.Email); err != nil {
			return Page[AdminTransfer]{}, err
		}
	}
	atCursor, idCursor, err := parseTimeCursor(f.Cursor, id.Transfer)
	if err != nil {
		return Page[AdminTransfer]{}, err
	}
	after := int64(math.MinInt64)
	if !f.CreatedAfter.IsZero() {
		after = toMillis(f.CreatedAfter)
	}
	limit := pageLimit(f.Limit)
	items, err := readScoped(ctx, r.db, tid, "list transfers", func(tx *ScopedTx) ([]AdminTransfer, error) {
		rows, err := tx.Query(ctx, qTransferAdminList, string(f.Status), string(f.Status), email, email, email,
			after, atCursor, idCursor, limit+1)
		if err != nil {
			return nil, err
		}
		ts, err := collect(rows, func(r *sql.Rows) (Transfer, error) { return scanTransfer(r) })
		if err != nil {
			return nil, err
		}
		out := make([]AdminTransfer, len(ts))
		for i, t := range ts {
			if out[i], err = adminTransfer(ctx, tx, t); err != nil {
				return nil, err
			}
		}
		return out, nil
	})
	if err != nil {
		return Page[AdminTransfer]{}, err
	}
	return paginate(items, limit, func(t AdminTransfer) string { return timeCursor(t.CreatedAt, t.ID) }), nil
}

// adminTransfer loads the recipients and the number of files of t, inside
// tx.
func adminTransfer(ctx context.Context, tx *ScopedTx, t Transfer) (AdminTransfer, error) {
	rcpts, err := listIDs(ctx, tx, qRecipientList, t.ID)
	if err != nil {
		return AdminTransfer{}, err
	}
	var n int
	if err := tx.QueryRow(ctx, qFileCountByTransfer, t.ID).Scan(&n); err != nil {
		return AdminTransfer{}, err
	}
	return AdminTransfer{Transfer: t, Recipients: rcpts, FileCount: n}, nil
}

// IncrementDownloadsTx adds one to the DownloadCount of the transfer trfID
// of the tenant tx is bound to, inside tx: a download start of a file or of
// the archive (never a HEAD request or a resumed range). It returns
// ErrNotFound when the transfer does not exist or belongs to another
// tenant. After an error, the caller must abort the transaction.
func (r *Transfers) IncrementDownloadsTx(ctx context.Context, tx *ScopedTx, trfID string) error {
	res, err := tx.Exec(ctx, qTransferIncrementDownloads, trfID)
	if err == nil {
		err = expectOne(res)
	}
	if err != nil {
		return wrap("count download", err)
	}
	return nil
}

// listByEmail runs the identifier list q of tenant tid for the normalized
// address email.
func (r *Transfers) listByEmail(ctx context.Context, tid tenant.ID, op string, q TenantQuery, email string) ([]string, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return nil, err
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	return readScoped(ctx, r.db, tid, op, func(tx *ScopedTx) ([]string, error) {
		return listIDs(ctx, tx, q, email)
	})
}

// IDsBySender returns the identifiers of the transfers of tenant tid sent
// by the address email, in every status, ordered by ID. It returns
// ErrInvalid for a malformed address.
func (r *Transfers) IDsBySender(ctx context.Context, tid tenant.ID, email string) ([]string, error) {
	return r.listByEmail(ctx, tid, "list transfers by sender", qTransferIDsBySender, email)
}

// IDsByRecipient returns the identifiers of the transfers of tenant tid of
// which the address email is a recipient, in every status, ordered by ID.
// It returns ErrInvalid for a malformed address.
func (r *Transfers) IDsByRecipient(ctx context.Context, tid tenant.ID, email string) ([]string, error) {
	return r.listByEmail(ctx, tid, "list transfers by recipient", qRecipientTransferIDs, email)
}

// IDsByInvitation returns the identifiers of the transfers of tenant tid
// deposited with the invitation invID, in every status, ordered by ID. It
// returns ErrInvalid for a malformed invitation ID.
func (r *Transfers) IDsByInvitation(ctx context.Context, tid tenant.ID, invID string) ([]string, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return nil, err
	}
	if !id.Valid(id.Invitation, invID) {
		return nil, invalid("malformed invitation id")
	}
	return readScoped(ctx, r.db, tid, "list transfers by invitation", func(tx *ScopedTx) ([]string, error) {
		return listIDs(ctx, tx, qTransferIDsByInvitation, invID)
	})
}

// RemoveRecipientTx removes the address email (normalized) from the
// recipients of the transfer trfID of the tenant tx is bound to, inside tx
// (GDPR erasure of a recipient of a transfer that has others). The other
// recipients keep their positions. It returns ErrInvalid for a malformed
// address, ErrNotFound when the address is not a recipient of the
// transfer (or the transfer does not exist or belongs to another tenant),
// and ErrKeysRemain when the recipient link still keeps its sealed token,
// which must be destroyed first in the same transaction
// ([WrappedKeys.DeleteTx]). After an error, the caller must abort the transaction.
func (r *Transfers) RemoveRecipientTx(ctx context.Context, tx *ScopedTx, trfID, email string) error {
	email, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	res, err := tx.Exec(ctx, qRecipientDelete, trfID, email)
	if err == nil {
		err = expectOne(res)
	}
	if errors.Is(err, ErrNotFound) {
		var n int
		if err = tx.QueryRow(ctx, qRecipientCountEmail, trfID, email).Scan(&n); err == nil {
			err = ErrNotFound
			if n > 0 {
				err = ErrKeysRemain
			}
		}
	}
	if err != nil {
		return wrap("remove recipient", err)
	}
	return nil
}

// CountRecipientsTx returns the number of recipients of the transfer trfID
// of the tenant tx is bound to, inside tx: 0 when the transfer does not
// exist or belongs to another tenant. After an error, the caller must abort
// the transaction.
func (r *Transfers) CountRecipientsTx(ctx context.Context, tx *ScopedTx, trfID string) (int, error) {
	var n int
	if err := tx.QueryRow(ctx, qRecipientCount, trfID).Scan(&n); err != nil {
		return 0, wrap("count recipients", err)
	}
	return n, nil
}

// UsedBytesAll returns the storage used by every tenant that uses some, as
// [Transfers.UsedBytesTx] computes it for one tenant: the declared sizes of
// the transfers that are uploading, scanning or available. A tenant
// without such a transfer is absent from the map. It is a system query
// (reason "quota sweep and global statistics: storage used by each
// tenant") and returns no personal data.
func (r *Transfers) UsedBytesAll(ctx context.Context) (map[tenant.ID]int64, error) {
	out := map[tenant.ID]int64{}
	err := r.db.systemScope(reasonUsedBytesAll).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qTransferUsedBytesAll)
		if err != nil {
			return err
		}
		type usage struct {
			tid string
			n   int64
		}
		us, err := collect(rows, func(r *sql.Rows) (usage, error) {
			var u usage
			err := r.Scan(&u.tid, &u.n)
			return u, err
		})
		for _, u := range us {
			out[tenant.ID(u.tid)] = u.n
		}
		return err
	})
	if err != nil {
		return nil, wrap("sum used bytes of every tenant", err)
	}
	return out, nil
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// InvitationStatus is the administration status of an invitation (OpenAPI
// InvitationStatus), derived from its revocation, last use and expiry.
type InvitationStatus string

// Invitation statuses, by precedence: a revoked invitation is revoked
// whatever its expiry; an expired one is expired whether it was used or
// not; an active one is used once it served at least once, pending before.
const (
	// InvitationPending is an active invitation never used.
	InvitationPending InvitationStatus = "pending"
	// InvitationUsed is an active invitation used at least once.
	InvitationUsed InvitationStatus = "used"
	// InvitationExpired is an invitation past its expiry, not revoked.
	InvitationExpired InvitationStatus = "expired"
	// InvitationRevoked is a revoked invitation.
	InvitationRevoked InvitationStatus = "revoked"
)

// Status returns the status of the invitation at now (see
// [InvitationStatus]).
func (inv Invitation) Status(now time.Time) InvitationStatus {
	switch {
	case !inv.RevokedAt.IsZero():
		return InvitationRevoked
	case !now.Before(inv.ExpiresAt):
		return InvitationExpired
	case !inv.LastUsedAt.IsZero():
		return InvitationUsed
	}
	return InvitationPending
}

// invitationListTail ends every invitation list statement: the keyset
// cursor (created_at, id), newest first, and the limit.
const invitationListTail = ` AND (created_at, id) < (?, ?) ORDER BY created_at DESC, id DESC LIMIT ?`

// Statements of the administrator view of the invitations and of the GDPR
// erasure. The list statements take, after the tenant, the time of the
// status (except all and revoked), then the cursor and the limit.
var (
	qInvitationListAll = tenantQuery(
		`SELECT ` + invitationColumns + ` FROM invitations WHERE tenant_id = ?` + invitationListTail)
	qInvitationListPending = tenantQuery(
		`SELECT ` + invitationColumns + ` FROM invitations
		WHERE tenant_id = ? AND revoked_at IS NULL AND expires_at > ? AND last_used_at IS NULL` + invitationListTail)
	qInvitationListUsed = tenantQuery(
		`SELECT ` + invitationColumns + ` FROM invitations
		WHERE tenant_id = ? AND revoked_at IS NULL AND expires_at > ? AND last_used_at IS NOT NULL` + invitationListTail)
	qInvitationListExpired = tenantQuery(
		`SELECT ` + invitationColumns + ` FROM invitations
		WHERE tenant_id = ? AND revoked_at IS NULL AND expires_at <= ?` + invitationListTail)
	qInvitationListRevoked = tenantQuery(
		`SELECT ` + invitationColumns + ` FROM invitations
		WHERE tenant_id = ? AND revoked_at IS NOT NULL` + invitationListTail)
	qInvitationCountInvitee = tenantQuery(
		`SELECT count(*) FROM invitations WHERE tenant_id = ? AND email = ?`)
	qInvitationIDsByEmail = tenantQuery(
		`SELECT id FROM invitations WHERE tenant_id = ? AND email = ? ORDER BY id`)
	qInvitationCountAsInviter = tenantQuery(
		`SELECT count(*) FROM invitations WHERE tenant_id = ? AND invited_by = ?`)
	qInvitationDeleteByEmail = tenantQuery(
		`DELETE FROM invitations WHERE tenant_id = ? AND email = ?`)
	// qInvitationPseudonymise replaces the inviter address by a pseudonym
	// and revokes the invitations still active (an earlier revocation time
	// is kept). Arguments after the tenant: pseudonym, now, address.
	qInvitationPseudonymise = tenantQuery(
		`UPDATE invitations SET invited_by = ?, revoked_at = COALESCE(revoked_at, ?)
		WHERE tenant_id = ? AND invited_by = ?`)
)

// InvitationFilter selects a page of invitations, newest first.
type InvitationFilter struct {
	// Status keeps the invitations of this status at Now only ("" for
	// all).
	Status InvitationStatus
	// Now is the time the status is evaluated at; the store's clock when
	// it is zero.
	Now time.Time
	// Cursor is the NextCursor of the previous page, or "" for the first.
	Cursor string
	// Limit is the page size (DefaultPageSize when <= 0, at most
	// MaxPageSize).
	Limit int
}

// List returns a page of the invitations of tenant tid matching f, newest
// first (by creation time, then ID). Callers derive the status of each
// with [Invitation.Status] at the same f.Now. It returns ErrInvalid for an
// unknown status or a malformed cursor.
func (r *Invitations) List(ctx context.Context, tid tenant.ID, f InvitationFilter) (Page[Invitation], error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return Page[Invitation]{}, err
	}
	atCursor, idCursor, err := parseTimeCursor(f.Cursor, id.Invitation)
	if err != nil {
		return Page[Invitation]{}, err
	}
	limit := pageLimit(f.Limit)
	now := toMillis(r.db.orNow(f.Now))
	var (
		q    TenantQuery
		args []any
	)
	switch f.Status {
	case "":
		q, args = qInvitationListAll, nil
	case InvitationPending:
		q, args = qInvitationListPending, []any{now}
	case InvitationUsed:
		q, args = qInvitationListUsed, []any{now}
	case InvitationExpired:
		q, args = qInvitationListExpired, []any{now}
	case InvitationRevoked:
		q, args = qInvitationListRevoked, nil
	default:
		return Page[Invitation]{}, invalid("unknown invitation status")
	}
	args = append(args, atCursor, idCursor, limit+1)
	items, err := readScoped(ctx, r.db, tid, "list invitations", func(tx *ScopedTx) ([]Invitation, error) {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		return collect(rows, func(r *sql.Rows) (Invitation, error) { return scanInvitation(r) })
	})
	if err != nil {
		return Page[Invitation]{}, err
	}
	return paginate(items, limit, func(inv Invitation) string { return timeCursor(inv.CreatedAt, inv.ID) }), nil
}

// CountByEmail returns the number of invitations of tenant tid that
// invited the address email (asInvitee) and that it issued (asInviter),
// in every state (GDPR search). It returns ErrInvalid for a malformed
// address.
func (r *Invitations) CountByEmail(ctx context.Context, tid tenant.ID, email string) (asInvitee, asInviter int, err error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return 0, 0, err
	}
	email, err = NormalizeEmail(email)
	if err != nil {
		return 0, 0, err
	}
	counts, err := readScoped(ctx, r.db, tid, "count invitations by address", func(tx *ScopedTx) ([2]int, error) {
		var c [2]int
		for i, q := range []TenantQuery{qInvitationCountInvitee, qInvitationCountAsInviter} {
			if err := tx.QueryRow(ctx, q, email).Scan(&c[i]); err != nil {
				return c, err
			}
		}
		return c, nil
	})
	if err != nil {
		return 0, 0, err
	}
	return counts[0], counts[1], nil
}

// IDsByEmail returns the identifiers of the invitations of tenant tid that
// invited the address email, in every state, ordered by ID (GDPR erasure).
// It returns ErrInvalid for a malformed address.
func (r *Invitations) IDsByEmail(ctx context.Context, tid tenant.ID, email string) ([]string, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return nil, err
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	return readScoped(ctx, r.db, tid, "list invitations by address", func(tx *ScopedTx) ([]string, error) {
		return listIDs(ctx, tx, qInvitationIDsByEmail, email)
	})
}

// DeleteByEmailTx deletes, inside tx, every invitation of the tenant tx is
// bound to that invited the address email, in every state, together with
// (by cascade) the verification challenges and deposit sessions opened
// with them, and returns how many it deleted (GDPR erasure). The transfers
// deposited with these invitations must be deleted first: otherwise it
// returns ErrConflict and deletes nothing. It returns ErrInvalid for a
// malformed address. After an error, the caller must abort the
// transaction.
func (r *Invitations) DeleteByEmailTx(ctx context.Context, tx *ScopedTx, email string) (int64, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	n, err := execCount(ctx, tx, qInvitationDeleteByEmail, email)
	if err != nil {
		// A transfer still references an invitation: the foreign key
		// violation reads as a missing row, which it is not.
		if errors.Is(classify(err), ErrNotFound) {
			return 0, wrap("delete invitations by address", ErrConflict)
		}
		return 0, wrap("delete invitations by address", err)
	}
	return n, nil
}

// PseudonymiseInviterTx replaces, inside tx, the inviter address inviter
// by pseudonym in every invitation of the tenant tx is bound to that it
// issued, and revokes those still unrevoked at now (an earlier revocation
// keeps its time), and returns how many invitations it changed (GDPR
// erasure of an inviter: the invited people keep their own data). The
// deposit sessions opened with these invitations are not ended; the caller
// ends them if needed. It returns ErrInvalid for a malformed address or a
// pseudonym that [IsPseudonym] rejects. After an error, the caller must
// abort the transaction.
func (r *Invitations) PseudonymiseInviterTx(ctx context.Context, tx *ScopedTx, inviter, pseudonym string, now time.Time) (int64, error) {
	inviter, err := NormalizeEmail(inviter)
	if err != nil {
		return 0, err
	}
	if !IsPseudonym(pseudonym) {
		return 0, invalid("malformed pseudonym")
	}
	n, err := execCount(ctx, tx, qInvitationPseudonymise, pseudonym, toMillis(r.db.orNow(now)), inviter)
	if err != nil {
		return 0, wrap("pseudonymise inviter", err)
	}
	return n, nil
}

// execCount runs the tenant statement q in tx and returns the number of
// rows it affected.
func execCount(ctx context.Context, tx *ScopedTx, q TenantQuery, args ...any) (int64, error) {
	res, err := tx.Exec(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

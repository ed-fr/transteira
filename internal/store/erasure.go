package store

import (
	"context"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Statements of the GDPR erasure of the deposit tables (spec 20): every
// row of one address in one tenant.
var (
	qVerifiedDelete = tenantQuery(
		`DELETE FROM verified_addresses WHERE tenant_id = ? AND email = ?`)
	qChallengeDeleteByEmail = tenantQuery(
		`DELETE FROM verification_challenges WHERE tenant_id = ? AND email = ?`)
	qSessionDeleteByEmail = tenantQuery(
		`DELETE FROM deposit_sessions WHERE tenant_id = ? AND email = ?`)
)

// Delete removes the verified address email (normalized) of tenant tid
// (GDPR erasure): the address must pass the code verification again. It
// reports whether the address was verified, and returns ErrInvalid for a
// malformed address.
func (r *VerifiedAddresses) Delete(ctx context.Context, tid tenant.ID, email string) (bool, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return false, err
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return false, err
	}
	var n int64
	err = writeScoped(ctx, r.db, tid, "delete verified address", func(tx *ScopedTx) error {
		var err error
		n, err = execCount(ctx, tx, qVerifiedDelete, email)
		return err
	})
	return n > 0, err
}

// deleteByEmail runs the deletion q for the address email (normalized)
// inside tx and returns how many rows it deleted.
func deleteByEmail(ctx context.Context, tx *ScopedTx, op string, q TenantQuery, email string) (int64, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	n, err := execCount(ctx, tx, q, email)
	if err != nil {
		return 0, wrap(op, err)
	}
	return n, nil
}

// DeleteByEmailTx deletes, inside tx, every verification challenge of the
// tenant tx is bound to sent to the address email, whatever its state, and
// returns how many it deleted (GDPR erasure). The per-address rate limit of
// the address restarts from zero. It returns ErrInvalid for a malformed
// address. After an error, the caller must abort the transaction.
func (r *Challenges) DeleteByEmailTx(ctx context.Context, tx *ScopedTx, email string) (int64, error) {
	return deleteByEmail(ctx, tx, "delete challenges by address", qChallengeDeleteByEmail, email)
}

// DeleteByEmailTx deletes, inside tx, every deposit session of the tenant
// tx is bound to opened by the address email, open or ended, and returns
// how many it deleted (GDPR erasure): an open session ends at once, its
// cookie no longer resolving. It returns ErrInvalid for a malformed
// address. After an error, the caller must abort the transaction.
func (r *DepositSessions) DeleteByEmailTx(ctx context.Context, tx *ScopedTx, email string) (int64, error) {
	return deleteByEmail(ctx, tx, "delete deposit sessions by address", qSessionDeleteByEmail, email)
}

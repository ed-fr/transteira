package datasubject

import (
	"context"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// repo is the persistence used by the service: the store repositories
// behind one interface, so that the tests can inject failures. Every
// address passed is normalized already.
type repo interface {
	getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	senderTransfers(ctx context.Context, tid tenant.ID, email string) ([]string, error)
	recipientTransfers(ctx context.Context, tid tenant.ID, email string) ([]string, error)
	invitationTransfers(ctx context.Context, tid tenant.ID, invID string) ([]string, error)
	inviteeInvitations(ctx context.Context, tid tenant.ID, email string) ([]string, error)
	countInvitations(ctx context.Context, tid tenant.ID, email string) (asInvitee, asInviter int, err error)
	verified(ctx context.Context, tid tenant.ID, email string) (bool, error)
	countAudit(ctx context.Context, tid tenant.ID, email string) (int, error)
	deleteDepositRows(ctx context.Context, tid tenant.ID, email string) error
	deleteVerified(ctx context.Context, tid tenant.ID, email string) (bool, error)
	removeRecipient(ctx context.Context, tid tenant.ID, trfID, email string) (recipientOutcome, error)
	eraseInvitations(ctx context.Context, tid tenant.ID, email, pseudonym string, now time.Time) (int64, error)
	pseudonymiseAudit(ctx context.Context, tid tenant.ID, email, pseudonym string) (int64, error)
	scrub(ctx context.Context) error
	audit(ctx context.Context, tid tenant.ID, ev audit.Event) error
}

// recipientOutcome is what [repo.removeRecipient] did.
type recipientOutcome int

const (
	// recipientGone: the address is no longer a recipient of the transfer
	// (or the transfer is gone); nothing was done.
	recipientGone recipientOutcome = iota
	// recipientRemoved: the address was removed, other recipients remain.
	recipientRemoved
	// recipientSole: the address is the only recipient; nothing was done,
	// the caller erases the transfer.
	recipientSole
)

// storeRepo implements repo with the store.
type storeRepo struct {
	db     *store.DB
	writer *audit.Writer
}

// newStoreRepo returns the store implementation of repo, recording with
// writer (a writer of its own when nil).
func newStoreRepo(db *store.DB, writer *audit.Writer) *storeRepo {
	return &storeRepo{db: db, writer: audit.OrNew(writer, db)}
}

func (r *storeRepo) getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	return r.db.Tenants().Get(ctx, tid)
}

func (r *storeRepo) senderTransfers(ctx context.Context, tid tenant.ID, email string) ([]string, error) {
	return r.db.Transfers().IDsBySender(ctx, tid, email)
}

func (r *storeRepo) recipientTransfers(ctx context.Context, tid tenant.ID, email string) ([]string, error) {
	return r.db.Transfers().IDsByRecipient(ctx, tid, email)
}

func (r *storeRepo) invitationTransfers(ctx context.Context, tid tenant.ID, invID string) ([]string, error) {
	return r.db.Transfers().IDsByInvitation(ctx, tid, invID)
}

// inviteeInvitations returns the IDs of the invitations of tenant tid that
// invited email, in every state.
func (r *storeRepo) inviteeInvitations(ctx context.Context, tid tenant.ID, email string) ([]string, error) {
	return r.db.Invitations().IDsByEmail(ctx, tid, email)
}

func (r *storeRepo) countInvitations(ctx context.Context, tid tenant.ID, email string) (int, int, error) {
	return r.db.Invitations().CountByEmail(ctx, tid, email)
}

func (r *storeRepo) verified(ctx context.Context, tid tenant.ID, email string) (bool, error) {
	_, err := r.db.VerifiedAddresses().Get(ctx, tid, email)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (r *storeRepo) countAudit(ctx context.Context, tid tenant.ID, email string) (int, error) {
	return r.db.AuditEvents().CountActor(ctx, tid, email)
}

// deleteDepositRows deletes the verification challenges and the deposit
// sessions of email in one transaction.
func (r *storeRepo) deleteDepositRows(ctx context.Context, tid tenant.ID, email string) error {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	return sc.Tx(ctx, func(tx *store.ScopedTx) error {
		if _, err := r.db.Challenges().DeleteByEmailTx(ctx, tx, email); err != nil {
			return err
		}
		_, err := r.db.DepositSessions().DeleteByEmailTx(ctx, tx, email)
		return err
	})
}

func (r *storeRepo) deleteVerified(ctx context.Context, tid tenant.ID, email string) (bool, error) {
	return r.db.VerifiedAddresses().Delete(ctx, tid, email)
}

// removeRecipient removes email from the recipients of the transfer trfID
// when others remain, in one transaction that counts them first.
func (r *storeRepo) removeRecipient(ctx context.Context, tid tenant.ID, trfID, email string) (recipientOutcome, error) {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return 0, err
	}
	out := recipientGone
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		n, err := r.db.Transfers().CountRecipientsTx(ctx, tx, trfID)
		if err != nil || n == 0 {
			return err
		}
		if n == 1 {
			out = recipientSole
			return nil
		}
		err = r.db.Transfers().RemoveRecipientTx(ctx, tx, trfID, email)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err == nil {
			out = recipientRemoved
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	return out, nil
}

// eraseInvitations deletes the invitations that invited email and
// pseudonymises (and revokes) those it issued, in one transaction, and
// returns how many it deleted.
func (r *storeRepo) eraseInvitations(ctx context.Context, tid tenant.ID, email, pseudonym string, now time.Time) (int64, error) {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return 0, err
	}
	var n int64
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		var err error
		if n, err = r.db.Invitations().DeleteByEmailTx(ctx, tx, email); err != nil {
			return err
		}
		_, err = r.db.Invitations().PseudonymiseInviterTx(ctx, tx, email, pseudonym, now)
		return err
	})
	return n, err
}

func (r *storeRepo) pseudonymiseAudit(ctx context.Context, tid tenant.ID, email, pseudonym string) (int64, error) {
	return r.db.AuditEvents().PseudonymiseActor(ctx, tid, email, pseudonym)
}

func (r *storeRepo) scrub(ctx context.Context) error { return r.db.ScrubDeleted(ctx) }

func (r *storeRepo) audit(ctx context.Context, tid tenant.ID, ev audit.Event) error {
	return r.writer.RecordScoped(ctx, tid, ev)
}

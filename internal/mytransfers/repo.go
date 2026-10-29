package mytransfers

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// repo is the storage used by the [Service]. Every method is scoped to the
// tenant it is given; storeRepo implements it over a *store.DB, the tests
// wrap it to inject faults.
type repo interface {
	// smtp reads the SMTP settings of the tenant (store.ErrNotFound when
	// none).
	smtp(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error)
	// recordRequest records an access link request and returns the
	// requests counted before it ([store.SenderAccess.RecordRequest]).
	recordRequest(ctx context.Context, tid tenant.ID, mac []byte, ip netip.Addr, now time.Time) (store.AccessRequestCounts, error)
	// verified reads a verified address (store.ErrNotFound when unknown).
	verified(ctx context.Context, tid tenant.ID, email string) (store.VerifiedAddress, error)
	// blocked reports whether the address or its domain is on the
	// blocklist of the tenant.
	blocked(ctx context.Context, tid tenant.ID, email string) (bool, error)
	// createLink stores an access link.
	createLink(ctx context.Context, tid tenant.ID, hash []byte, email string, now, expiresAt time.Time) (store.SenderAccessLink, error)
	// openSession consumes the access link whose token hashes to linkHash
	// and opens, in the same transaction, a session for its address whose
	// cookie token hashes to sessionHash, provided the address is still
	// verified, active and not blocklisted (store.ErrNotFound otherwise,
	// the link being consumed all the same).
	openSession(ctx context.Context, tid tenant.ID, linkHash, sessionHash []byte, now, expiresAt time.Time) (store.SenderSession, error)
	// session reads an active session ([store.SenderAccess.GetSession]).
	session(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) (store.SenderSession, error)
	// endSession ends an active session.
	endSession(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) error
	// list lists the transfers in progress of a sender.
	list(ctx context.Context, tid tenant.ID, email, cursor string, limit int) (store.Page[store.SenderTransfer], error)
	// get reads a transfer in progress of a sender.
	get(ctx context.Context, tid tenant.ID, trfID, email string) (store.SenderTransferDetail, error)
	// status reads the status of a transfer of a sender, whatever it is.
	status(ctx context.Context, tid tenant.ID, trfID, email string) (store.TransferStatus, error)
	// extend reads the transfer, asks check for the new expiry, extends it
	// and reads it again, in one transaction: the returned detail is the
	// transfer after the extension.
	extend(ctx context.Context, tid tenant.ID, trfID, email string, now time.Time,
		check func(store.SenderTransferDetail) (time.Time, error)) (store.TransferExtension, store.SenderTransferDetail, error)
}

// storeRepo implements repo over a *store.DB.
type storeRepo struct {
	db *store.DB
}

func (r storeRepo) smtp(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error) {
	return r.db.SMTPSettings().Get(ctx, tid)
}

func (r storeRepo) recordRequest(ctx context.Context, tid tenant.ID, mac []byte, ip netip.Addr, now time.Time) (store.AccessRequestCounts, error) {
	return r.db.SenderAccess().RecordRequest(ctx, tid, mac, ip, now)
}

func (r storeRepo) verified(ctx context.Context, tid tenant.ID, email string) (store.VerifiedAddress, error) {
	return r.db.VerifiedAddresses().Get(ctx, tid, email)
}

func (r storeRepo) blocked(ctx context.Context, tid tenant.ID, email string) (bool, error) {
	entries, err := r.db.Blocklist().Match(ctx, tid, email, "")
	return len(entries) > 0, err
}

func (r storeRepo) createLink(ctx context.Context, tid tenant.ID, hash []byte, email string, now, expiresAt time.Time) (store.SenderAccessLink, error) {
	return r.db.SenderAccess().CreateLink(ctx, tid, hash, email, now, expiresAt)
}

func (r storeRepo) openSession(ctx context.Context, tid tenant.ID, linkHash, sessionHash []byte, now, expiresAt time.Time) (store.SenderSession, error) {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return store.SenderSession{}, err
	}
	var (
		sess    store.SenderSession
		refused bool
	)
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		access := r.db.SenderAccess()
		link, err := access.ConsumeLinkTx(ctx, tx, linkHash, now)
		if err != nil {
			return err
		}
		// The address may have been erased, have expired or been
		// blocklisted since the link was mailed (T-208). The link is then
		// consumed all the same (committed without a session): a link is
		// single use whatever its outcome, so that it cannot open a
		// session later, once the address is verified or unblocked again.
		if refused, err = r.refused(ctx, tx, link.Email, now); err != nil || refused {
			return err
		}
		sess, err = access.CreateSessionTx(ctx, tx, sessionHash, link.Email, now, expiresAt)
		return err
	})
	if err == nil && refused {
		err = store.ErrNotFound
	}
	return sess, err
}

// refused reports, inside tx, whether email may no longer open a session
// at now: no longer verified in the tenant, verified but inactive, or on
// its blocklist (address or domain).
func (r storeRepo) refused(ctx context.Context, tx *store.ScopedTx, email string, now time.Time) (bool, error) {
	v, err := r.db.VerifiedAddresses().GetTx(ctx, tx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return true, nil
	case err != nil:
		return false, err
	case !v.Active(now):
		return true, nil
	}
	entries, err := r.db.Blocklist().MatchTx(ctx, tx, email, "")
	return len(entries) > 0, err
}

func (r storeRepo) session(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) (store.SenderSession, error) {
	return r.db.SenderAccess().GetSession(ctx, tid, hash, now)
}

func (r storeRepo) endSession(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) error {
	return r.db.SenderAccess().EndSession(ctx, tid, hash, now)
}

func (r storeRepo) list(ctx context.Context, tid tenant.ID, email, cursor string, limit int) (store.Page[store.SenderTransfer], error) {
	return r.db.Transfers().ListBySender(ctx, tid, email, cursor, limit)
}

func (r storeRepo) get(ctx context.Context, tid tenant.ID, trfID, email string) (store.SenderTransferDetail, error) {
	return r.db.Transfers().GetBySender(ctx, tid, trfID, email)
}

func (r storeRepo) status(ctx context.Context, tid tenant.ID, trfID, email string) (store.TransferStatus, error) {
	return r.db.Transfers().SenderStatus(ctx, tid, trfID, email)
}

func (r storeRepo) extend(ctx context.Context, tid tenant.ID, trfID, email string, now time.Time,
	check func(store.SenderTransferDetail) (time.Time, error),
) (store.TransferExtension, store.SenderTransferDetail, error) {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return store.TransferExtension{}, store.SenderTransferDetail{}, err
	}
	var (
		x     store.TransferExtension
		after store.SenderTransferDetail
	)
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		transfers := r.db.Transfers()
		before, err := transfers.GetBySenderTx(ctx, tx, trfID, email)
		if err != nil {
			return err
		}
		expiresAt, err := check(before)
		if err != nil {
			return err
		}
		if x, err = transfers.ExtendTx(ctx, tx, trfID, email, expiresAt, now); err != nil {
			return err
		}
		after, err = transfers.GetBySenderTx(ctx, tx, trfID, email)
		return err
	})
	return x, after, err
}

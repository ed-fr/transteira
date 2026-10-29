package deposit

import (
	"context"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// repo is the part of the store the service uses. It exists so that the
// tests can inject a failure at any step; [storeRepo] is the only real
// implementation.
type repo interface {
	blocked(ctx context.Context, tid tenant.ID, email string) (bool, error)
	networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error)
	invitation(ctx context.Context, tid tenant.ID, invID string) (store.Invitation, error)
	invitationByHash(ctx context.Context, tid tenant.ID, hash []byte) (store.Invitation, error)
	verified(ctx context.Context, tid tenant.ID, email string) (store.VerifiedAddress, error)
	challenge(ctx context.Context, tid tenant.ID, chID string) (store.Challenge, error)
	deleteChallenge(ctx context.Context, tid tenant.ID, chID string) error
	deleteInvitation(ctx context.Context, tid tenant.ID, invID string) error
	decrementAttempt(ctx context.Context, tid tenant.ID, chID string, now time.Time) (int, error)
	smtp(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error)
	session(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) (store.DepositSession, error)
	endSession(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) error
	transfer(ctx context.Context, tid tenant.ID, trfID string) (store.Transfer, error)
	tx(ctx context.Context, tid tenant.ID, fn func(txRepo) error) error
}

// txRepo is the part of the store used inside a tenant-scoped transaction.
type txRepo interface {
	countByEmail(ctx context.Context, email string, since time.Time) (int, error)
	countByIP(ctx context.Context, ip netip.Addr, since time.Time) (int, error)
	countInvitations(ctx context.Context, inviter string, since time.Time) (int, error)
	createChallenge(ctx context.Context, c store.Challenge) error
	consumeChallenge(ctx context.Context, chID string, now time.Time) error
	upsertVerified(ctx context.Context, v store.VerifiedAddress) ([store.RecognitionSaltSize]byte, error)
	touchVerified(ctx context.Context, email string, now time.Time) error
	createSession(ctx context.Context, s store.DepositSession) error
	countLiveReplies(ctx context.Context, linkID string, now time.Time) (int, error)
	touchInvitation(ctx context.Context, invID string, now time.Time) error
	createInvitation(ctx context.Context, inv store.Invitation) error
}

// storeRepo implements repo over a *store.DB.
type storeRepo struct {
	db *store.DB
}

func (r storeRepo) blocked(ctx context.Context, tid tenant.ID, email string) (bool, error) {
	entries, err := r.db.Blocklist().Match(ctx, tid, email, "")
	return len(entries) > 0, err
}

func (r storeRepo) networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error) {
	return r.db.NetworkRules().Get(ctx, tid)
}

func (r storeRepo) invitation(ctx context.Context, tid tenant.ID, invID string) (store.Invitation, error) {
	return r.db.Invitations().Get(ctx, tid, invID)
}

func (r storeRepo) invitationByHash(ctx context.Context, tid tenant.ID, hash []byte) (store.Invitation, error) {
	return r.db.Invitations().GetByTokenHash(ctx, tid, hash)
}

func (r storeRepo) verified(ctx context.Context, tid tenant.ID, email string) (store.VerifiedAddress, error) {
	return r.db.VerifiedAddresses().Get(ctx, tid, email)
}

func (r storeRepo) challenge(ctx context.Context, tid tenant.ID, chID string) (store.Challenge, error) {
	return r.db.Challenges().Get(ctx, tid, chID)
}

func (r storeRepo) deleteChallenge(ctx context.Context, tid tenant.ID, chID string) error {
	return r.db.Challenges().Delete(ctx, tid, chID)
}

func (r storeRepo) deleteInvitation(ctx context.Context, tid tenant.ID, invID string) error {
	return r.db.Invitations().Delete(ctx, tid, invID)
}

func (r storeRepo) decrementAttempt(ctx context.Context, tid tenant.ID, chID string, now time.Time) (int, error) {
	return r.db.Challenges().DecrementAttempt(ctx, tid, chID, now)
}

func (r storeRepo) smtp(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error) {
	return r.db.SMTPSettings().Get(ctx, tid)
}

func (r storeRepo) session(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) (store.DepositSession, error) {
	return r.db.DepositSessions().GetByTokenHash(ctx, tid, hash, now)
}

func (r storeRepo) endSession(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) error {
	return r.db.DepositSessions().End(ctx, tid, hash, now)
}

func (r storeRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.Transfer, error) {
	d, err := r.db.Transfers().Get(ctx, tid, trfID)
	return d.Transfer, err
}

func (r storeRepo) tx(ctx context.Context, tid tenant.ID, fn func(txRepo) error) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	return s.Tx(ctx, func(tx *store.ScopedTx) error { return fn(storeTx{db: r.db, tx: tx}) })
}

// storeTx implements txRepo over a *store.ScopedTx.
type storeTx struct {
	db *store.DB
	tx *store.ScopedTx
}

func (t storeTx) countByEmail(ctx context.Context, email string, since time.Time) (int, error) {
	return t.db.Challenges().CountSinceTx(ctx, t.tx, email, since)
}

func (t storeTx) countByIP(ctx context.Context, ip netip.Addr, since time.Time) (int, error) {
	return t.db.Challenges().CountByIPSinceTx(ctx, t.tx, ip, since)
}

func (t storeTx) countInvitations(ctx context.Context, inviter string, since time.Time) (int, error) {
	return t.db.Invitations().CountByInviterSinceTx(ctx, t.tx, inviter, since)
}

func (t storeTx) createChallenge(ctx context.Context, c store.Challenge) error {
	return t.db.Challenges().CreateTx(ctx, t.tx, c)
}

func (t storeTx) consumeChallenge(ctx context.Context, chID string, now time.Time) error {
	return t.db.Challenges().ConsumeTx(ctx, t.tx, chID, now)
}

func (t storeTx) upsertVerified(ctx context.Context, v store.VerifiedAddress) ([store.RecognitionSaltSize]byte, error) {
	return t.db.VerifiedAddresses().UpsertTx(ctx, t.tx, v)
}

func (t storeTx) touchVerified(ctx context.Context, email string, now time.Time) error {
	return t.db.VerifiedAddresses().TouchTx(ctx, t.tx, email, now)
}

func (t storeTx) createSession(ctx context.Context, s store.DepositSession) error {
	return t.db.DepositSessions().CreateTx(ctx, t.tx, s)
}

func (t storeTx) countLiveReplies(ctx context.Context, linkID string, now time.Time) (int, error) {
	return t.db.DepositSessions().CountLiveReplyTx(ctx, t.tx, linkID, now)
}

func (t storeTx) touchInvitation(ctx context.Context, invID string, now time.Time) error {
	return t.db.Invitations().TouchTx(ctx, t.tx, invID, now)
}

func (t storeTx) createInvitation(ctx context.Context, inv store.Invitation) error {
	return t.db.Invitations().CreateTx(ctx, t.tx, inv)
}

package transfer

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// repo is the part of the store the service uses. It exists so that the
// tests can inject a failure at any step; [storeRepo] is the only real
// implementation.
type repo interface {
	blocked(ctx context.Context, tid tenant.ID, email, sha256 string) (bool, error)
	networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error)
	confidentialityLevels(ctx context.Context, tid tenant.ID) ([]store.ConfidentialityLevel, error)
	recipientRules(ctx context.Context, tid tenant.ID) (store.RecipientRuleSet, error)
	invitation(ctx context.Context, tid tenant.ID, invID string) (store.Invitation, error)
	apiToken(ctx context.Context, tid tenant.ID, tokID string) (store.APIToken, error)
	tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error)
	transferByKey(ctx context.Context, tid tenant.ID, o owner, key string, since time.Time) (store.TransferDetails, error)
	completeUpload(ctx context.Context, tid tenant.ID, fileID, sha256 string, ciphertextSize int64, now time.Time) error
	downloadToken(ctx context.Context, tid tenant.ID, wkID string) ([]byte, error)
	tracking(ctx context.Context, tid tenant.ID, trfID string) ([]store.RecipientTracking, error)
	tx(ctx context.Context, tid tenant.ID, fn func(txRepo) error) error
}

// txRepo is the part of the store used inside a tenant-scoped transaction.
type txRepo interface {
	usedBytes(ctx context.Context) (int64, error)
	countUploading(ctx context.Context, o owner, since time.Time) (int, error)
	listUploading(ctx context.Context, o owner, since time.Time, limit int) ([]store.Transfer, error)
	listFiles(ctx context.Context, trfID string) ([]store.TransferFile, error)
	newDEK(ctx context.Context) (wkID string, dek []byte, err error)
	createTransfer(ctx context.Context, t store.Transfer, recipients []string, files []store.TransferFile) error
	finalize(ctx context.Context, trfID string, now time.Time) error
	deleteTransfer(ctx context.Context, trfID string) error
}

// owner names whose transfers the open transfer cap and the idempotency
// keys are counted for: the API token when token is set, the normalized
// sender address of the deposit session transfers otherwise.
type owner struct {
	email string
	token string
}

// storeRepo implements repo over a *store.DB, creating the data keys with
// keys.
type storeRepo struct {
	db   *store.DB
	keys DataKeys
}

func (r storeRepo) blocked(ctx context.Context, tid tenant.ID, email, sha256 string) (bool, error) {
	entries, err := r.db.Blocklist().Match(ctx, tid, email, sha256)
	return len(entries) > 0, err
}

func (r storeRepo) networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error) {
	return r.db.NetworkRules().Get(ctx, tid)
}

func (r storeRepo) confidentialityLevels(ctx context.Context, tid tenant.ID) ([]store.ConfidentialityLevel, error) {
	return r.db.ConfidentialityLevels().List(ctx, tid)
}

func (r storeRepo) recipientRules(ctx context.Context, tid tenant.ID) (store.RecipientRuleSet, error) {
	return r.db.RecipientRules().Get(ctx, tid)
}

func (r storeRepo) invitation(ctx context.Context, tid tenant.ID, invID string) (store.Invitation, error) {
	return r.db.Invitations().Get(ctx, tid, invID)
}

func (r storeRepo) apiToken(ctx context.Context, tid tenant.ID, tokID string) (store.APIToken, error) {
	return r.db.APITokens().Get(ctx, tid, tokID)
}

func (r storeRepo) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	return r.db.Tenants().Get(ctx, tid)
}

func (r storeRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	return r.db.Transfers().Get(ctx, tid, trfID)
}

func (r storeRepo) transferByKey(ctx context.Context, tid tenant.ID, o owner, key string, since time.Time) (store.TransferDetails, error) {
	if o.token != "" {
		return r.db.Transfers().GetByTokenIdempotencyKey(ctx, tid, o.token, key, since)
	}
	return r.db.Transfers().GetByIdempotencyKey(ctx, tid, o.email, key, since)
}

func (r storeRepo) completeUpload(ctx context.Context, tid tenant.ID, fileID, sha256 string, ciphertextSize int64, now time.Time) error {
	return r.db.TransferFiles().CompleteUpload(ctx, tid, fileID, sha256, ciphertextSize, now)
}

func (r storeRepo) downloadToken(ctx context.Context, tid tenant.ID, wkID string) ([]byte, error) {
	return r.keys.Open(ctx, tid, crypto.PurposeSecret, wkID)
}

func (r storeRepo) tracking(ctx context.Context, tid tenant.ID, trfID string) ([]store.RecipientTracking, error) {
	return r.db.RecipientLinks().TrackingByTransfer(ctx, tid, trfID)
}

func (r storeRepo) tx(ctx context.Context, tid tenant.ID, fn func(txRepo) error) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	return s.Tx(ctx, func(tx *store.ScopedTx) error { return fn(storeTx{db: r.db, keys: r.keys, tx: tx}) })
}

// storeTx implements txRepo over a *store.ScopedTx.
type storeTx struct {
	db   *store.DB
	keys DataKeys
	tx   *store.ScopedTx
}

func (t storeTx) usedBytes(ctx context.Context) (int64, error) {
	return t.db.Transfers().UsedBytesTx(ctx, t.tx)
}

func (t storeTx) countUploading(ctx context.Context, o owner, since time.Time) (int, error) {
	if o.token != "" {
		return t.db.Transfers().CountUploadingByTokenTx(ctx, t.tx, o.token, since)
	}
	return t.db.Transfers().CountUploadingTx(ctx, t.tx, o.email, since)
}

func (t storeTx) listUploading(ctx context.Context, o owner, since time.Time, limit int) ([]store.Transfer, error) {
	if o.token != "" {
		return t.db.Transfers().ListUploadingByTokenTx(ctx, t.tx, o.token, since, limit)
	}
	return t.db.Transfers().ListUploadingTx(ctx, t.tx, o.email, since, limit)
}

func (t storeTx) listFiles(ctx context.Context, trfID string) ([]store.TransferFile, error) {
	return t.db.TransferFiles().ListByTransferTx(ctx, t.tx, trfID)
}

func (t storeTx) newDEK(ctx context.Context) (string, []byte, error) {
	return t.keys.NewDEKTx(ctx, t.tx)
}

func (t storeTx) createTransfer(ctx context.Context, tr store.Transfer, recipients []string, files []store.TransferFile) error {
	return t.db.Transfers().CreateTx(ctx, t.tx, tr, recipients, files)
}

func (t storeTx) finalize(ctx context.Context, trfID string, now time.Time) error {
	return t.db.Transfers().FinalizeTx(ctx, t.tx, trfID, now)
}

func (t storeTx) deleteTransfer(ctx context.Context, trfID string) error {
	return t.db.Transfers().DeleteTx(ctx, t.tx, trfID)
}

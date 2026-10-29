package scan

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// repo is the part of the store the worker uses. It exists so that the
// tests can inject a failure at any step; [storeRepo] is the only real
// implementation. Every method but sweep runs in the scope of the tenant
// it is given (CLAUDE.md section 5).
type repo interface {
	tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error)
	setScanning(ctx context.Context, tid tenant.ID, fileID string) error
	setResult(ctx context.Context, tid tenant.ID, fileID string, status store.ScanStatus, signature string, now time.Time) error
	countAttempt(ctx context.Context, tid tenant.ID, fileID string) (int, error)
	reject(ctx context.Context, tid tenant.ID, trfID string) error
	makeAvailable(ctx context.Context, tid tenant.ID, trfID string, perRecipient bool, tokens []string, now time.Time) ([]store.RecipientLink, error)
	recipientLinks(ctx context.Context, tid tenant.ID, trfID string) ([]store.RecipientLink, error)
	sweep(ctx context.Context) ([]store.TenantTransfer, error)
}

// storeRepo implements repo over a *store.DB, sealing the download tokens
// with vault.
type storeRepo struct {
	db    *store.DB
	vault Vault
}

func (r storeRepo) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	return r.db.Tenants().Get(ctx, tid)
}

func (r storeRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	return r.db.Transfers().Get(ctx, tid, trfID)
}

// tx runs fn in a write transaction of tenant tid.
func (r storeRepo) tx(ctx context.Context, tid tenant.ID, fn func(*store.ScopedTx) error) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	return s.Tx(ctx, fn)
}

func (r storeRepo) setScanning(ctx context.Context, tid tenant.ID, fileID string) error {
	return r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		return r.db.TransferFiles().SetScanningTx(ctx, tx, fileID)
	})
}

func (r storeRepo) setResult(ctx context.Context, tid tenant.ID, fileID string, status store.ScanStatus, signature string, now time.Time) error {
	return r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		return r.db.TransferFiles().SetScanResultTx(ctx, tx, fileID, status, signature, now)
	})
}

func (r storeRepo) countAttempt(ctx context.Context, tid tenant.ID, fileID string) (int, error) {
	return r.db.TransferFiles().IncrementScanAttempt(ctx, tid, fileID)
}

func (r storeRepo) reject(ctx context.Context, tid tenant.ID, trfID string) error {
	return r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		return r.db.Transfers().MarkRejectedTx(ctx, tx, trfID)
	})
}

// makeAvailable seals each raw download token with the vault (purpose
// secret) and makes the transfer available with the SHA-256 of each token
// and its sealed copy, in one transaction: either all exist or none. The
// store restarts the expiry from now. A shared transfer takes a single
// token (no link is returned); a transfer with one link per recipient
// (perRecipient) takes one token per recipient and returns the links
// created, in position order.
func (r storeRepo) makeAvailable(ctx context.Context, tid tenant.ID, trfID string, perRecipient bool, tokens []string, now time.Time) ([]store.RecipientLink, error) {
	var links []store.RecipientLink
	err := r.tx(ctx, tid, func(tx *store.ScopedTx) error {
		sealed := make([]store.LinkToken, len(tokens))
		for i, token := range tokens {
			wkID, err := r.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
			if err != nil {
				return err
			}
			hash := sha256.Sum256([]byte(token))
			sealed[i] = store.LinkToken{Hash: hash[:], KeyID: wkID}
		}
		if !perRecipient {
			if len(sealed) != 1 {
				return fmt.Errorf("scan: a shared transfer takes one token, %d given", len(sealed))
			}
			return r.db.Transfers().MarkAvailableTx(ctx, tx, trfID, sealed[0].Hash, sealed[0].KeyID, now)
		}
		var err error
		links, err = r.db.Transfers().MarkAvailableLinksTx(ctx, tx, trfID, sealed, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	return links, nil
}

// recipientLinks returns the links of a transfer with one link per
// recipient, with their sealed token, in position order.
func (r storeRepo) recipientLinks(ctx context.Context, tid tenant.ID, trfID string) ([]store.RecipientLink, error) {
	return r.db.RecipientLinks().ListByTransfer(ctx, tid, trfID)
}

// sweep is the only cross-tenant read of the worker: a system query
// (reason "antivirus sweep") returning identifiers only.
func (r storeRepo) sweep(ctx context.Context) ([]store.TenantTransfer, error) {
	return r.db.Transfers().ScanningSweep(ctx)
}

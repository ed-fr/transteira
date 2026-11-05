package proof

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// RetentionMonths is how long a proof is kept after its creation, in months
// (P60).
const RetentionMonths = 12

// DepositTx writes, inside the tenant transaction tx, the deposit proof of
// the transfer trfID of tenant t, at now. The caller calls it in the
// transaction that makes the transfer available
// (store.Transfers.MarkAvailableTx or MarkAvailableLinksTx), right after
// that call, so that the statement holds the final scan status of every
// file and the expiry set by the availability.
//
// depositedAt is the finalization of the deposit (store
// Transfer.FinalizedAt): the moment the sender completed the deposit,
// which the analysis follows; expiresAt is the expiry of the available
// transfer.
//
// A proof already written for the fact is kept and nil returned (retried
// write). It returns ErrNotReady when the transfer is not available in tx.
// Any other error, a concurrent write of the same fact included
// (store.ErrConflict, PostgreSQL only: the transaction is then aborted),
// must abort the caller's transaction.
func (s *Sealer) DepositTx(ctx context.Context, tx *store.ScopedTx, t *tenant.Tenant, trfID string, now time.Time) error {
	if done, err := s.exists(ctx, tx, trfID, store.ProofDeposit, ""); done || err != nil {
		return err
	}
	d, err := s.db.Transfers().GetTx(ctx, tx, trfID)
	if err != nil {
		return fmt.Errorf("proof: read transfer: %w", err)
	}
	st, err := newStatement(store.ProofDeposit, t, d)
	if err != nil {
		return err
	}
	return s.insert(ctx, tx, st, "", now)
}

// OverallDeliveryTx writes, inside the tenant transaction tx, the overall
// delivery proof of the transfer trfID of tenant t, at now. The caller
// calls it in the transaction where store.Transfers.MarkFirstDownloadTx
// returned true (the first download of the transfer), after that call.
// Besides the first download of the transfer, the statement of a transfer
// with per-recipient links names the recipients whose link completed so
// far.
//
// Its other rules are those of [Sealer.DepositTx]; ErrNotReady reports a
// transfer without first download in tx.
func (s *Sealer) OverallDeliveryTx(ctx context.Context, tx *store.ScopedTx, t *tenant.Tenant, trfID string, now time.Time) error {
	if done, err := s.exists(ctx, tx, trfID, store.ProofDelivery, ""); done || err != nil {
		return err
	}
	st, links, err := s.delivery(ctx, tx, t, trfID)
	if err != nil {
		return err
	}
	for _, l := range links {
		if !l.CompletedAt.IsZero() {
			st.RecipientDownloads = append(st.RecipientDownloads, RecipientDownload{
				Email: l.Email, FirstDownloadedAt: FormatTime(l.CompletedAt),
			})
		}
	}
	return s.insert(ctx, tx, st, "", now)
}

// RecipientDeliveryTx writes, inside the tenant transaction tx, the
// delivery proof of the recipient link linkID of the transfer trfID of
// tenant t, at now. The caller calls it in the transaction where
// store.RecipientLinks.CompleteTx reported First (the first complete
// download through that link), after store.Transfers.MarkFirstDownloadTx
// in that transaction, so that the first download of the transfer is
// recorded too. The statement names that recipient only.
//
// Its other rules are those of [Sealer.DepositTx]; ErrNotReady reports a
// link that is not complete, or of another transfer, or a transfer
// without first download, in tx.
func (s *Sealer) RecipientDeliveryTx(ctx context.Context, tx *store.ScopedTx, t *tenant.Tenant, trfID, linkID string, now time.Time) error {
	if done, err := s.exists(ctx, tx, trfID, store.ProofDelivery, linkID); done || err != nil {
		return err
	}
	st, links, err := s.delivery(ctx, tx, t, trfID)
	if err != nil {
		return err
	}
	for _, l := range links {
		if l.ID == linkID && !l.CompletedAt.IsZero() {
			st.RecipientDownloads = []RecipientDownload{{Email: l.Email, FirstDownloadedAt: FormatTime(l.CompletedAt)}}
			return s.insert(ctx, tx, st, linkID, now)
		}
	}
	return fmt.Errorf("%w: recipient link not complete", ErrNotReady)
}

// delivery reads, inside tx, the transfer trfID and its recipient links,
// and returns its delivery statement with its first download.
func (s *Sealer) delivery(ctx context.Context, tx *store.ScopedTx, t *tenant.Tenant, trfID string) (Statement, []store.RecipientLink, error) {
	d, err := s.db.Transfers().GetTx(ctx, tx, trfID)
	if err != nil {
		return Statement{}, nil, fmt.Errorf("proof: read transfer: %w", err)
	}
	if d.FirstDownloadedAt.IsZero() {
		return Statement{}, nil, fmt.Errorf("%w: no first download", ErrNotReady)
	}
	st, err := newStatement(store.ProofDelivery, t, d)
	if err != nil {
		return Statement{}, nil, err
	}
	first := FormatTime(d.FirstDownloadedAt)
	st.FirstDownloadedAt = &first
	list := s.db.RecipientLinks().ListByTransferTx
	if s.listLinks != nil {
		list = s.listLinks
	}
	links, err := list(ctx, tx, trfID)
	if err != nil {
		return Statement{}, nil, fmt.Errorf("proof: read recipient links: %w", err)
	}
	return st, links, nil
}

// exists reports whether the proof of the fact (trfID, kind, linkID) is
// already stored in tx.
func (s *Sealer) exists(ctx context.Context, tx *store.ScopedTx, trfID string, kind store.ProofKind, linkID string) (bool, error) {
	_, err := s.db.TransferProofs().GetTx(ctx, tx, trfID, kind, linkID)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	default:
		return false, fmt.Errorf("proof: read proof: %w", err)
	}
}

// insert signs st with the sealer's key and stores it inside tx as the
// proof of the recipient link linkID ("" for a deposit or an overall
// delivery), created at now and kept RetentionMonths months.
func (s *Sealer) insert(ctx context.Context, tx *store.ScopedTx, st Statement, linkID string, now time.Time) error {
	st.KeyID = s.keyID
	data, err := st.Marshal()
	if err != nil {
		return fmt.Errorf("proof: encode statement: %w", err)
	}
	err = s.db.TransferProofs().InsertTx(ctx, tx, store.TransferProof{
		TransferID: st.TransferID, Kind: st.Kind, RecipientLinkID: linkID, Statement: data,
		Signature: ed25519.Sign(s.priv, data), KeyID: s.keyID,
		CreatedAt: now, ExpiresAt: now.AddDate(0, RetentionMonths, 0),
	})
	if err != nil {
		return fmt.Errorf("proof: store proof: %w", err)
	}
	return nil
}

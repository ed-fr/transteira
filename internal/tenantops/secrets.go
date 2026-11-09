package tenantops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// SecretFilter selects a page of the one-time secrets of a tenant (since
// 2.1).
type SecretFilter struct {
	// State is one of the secret states, "" for every state.
	State string
	// Sender is the creator address (exact match), "" for every creator. It
	// is refused to an auditor (adminauth.ErrReadOnlyRole).
	Sender string
	// Cursor is the NextCursor of the previous page.
	Cursor string
	// Limit is the page size, 0 for the default.
	Limit int
}

// secretStates are the states accepted by the state filter.
var secretStates = map[store.SecretState]bool{
	store.SecretPending: true, store.SecretActive: true, store.SecretRead: true,
	store.SecretExpired: true, store.SecretDeleted: true, store.SecretLocked: true,
}

// ListSecrets lists the one-time secrets of tenant tid, most recent first,
// in every state: metadata only, never the content, a key, a proof, a
// verifier or a token (the store never reads them). An auditor may list,
// without the creator filter (adminauth.ErrReadOnlyRole). An unknown state,
// a malformed address, a malformed cursor and an out-of-range limit are an
// *InvalidError.
func (s *Service) ListSecrets(ctx context.Context, p adminauth.Principal, tid tenant.ID, f SecretFilter) (store.Page[store.Secret], error) {
	if _, err := s.auditReadable(ctx, p, tid); err != nil {
		return store.Page[store.Secret]{}, err
	}
	if f.Sender != "" && p.Admin.Role == store.RoleAuditor {
		return store.Page[store.Secret]{}, adminauth.ErrReadOnlyRole
	}
	sf := store.SecretFilter{State: store.SecretState(f.State)}
	if f.State != "" && !secretStates[sf.State] {
		return store.Page[store.Secret]{}, invalid(FieldState, "unknown secret state")
	}
	if f.Sender != "" {
		var ok bool
		if sf.Sender, ok = normalizeAddress(f.Sender); !ok {
			return store.Page[store.Secret]{}, invalidAddress(FieldSender)
		}
	}
	if err := checkLimit(f.Limit); err != nil {
		return store.Page[store.Secret]{}, err
	}
	page, err := s.repo.listSecrets(ctx, tid, sf, store.SecretListOptions{Cursor: f.Cursor, Limit: f.Limit})
	if err != nil {
		return store.Page[store.Secret]{}, listError("list secrets", err)
	}
	return page, nil
}

// DeleteSecret deletes the pending or active secret secID of tenant tid
// before it is read: its content and keys are destroyed (cryptographic
// erasure), the database is scrubbed, its file is removed, and the secret
// stays as a deleted tombstone. A secret already ended is a no-op without
// audit (nil error), like a transfer already deleted. A malformed ID and a
// secret of another tenant are ErrNotFound. It records secret.deleted with
// the administrator as actor.
func (s *Service) DeleteSecret(ctx context.Context, p adminauth.Principal, tid tenant.ID, secID string, ip netip.Addr) error {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return err
	}
	if !id.Valid(id.Secret, secID) {
		return ErrNotFound
	}
	// The deletion is not interrupted by the cancellation of ctx: the keys
	// are destroyed in one transaction, then the file and the scrub follow.
	bg := context.WithoutCancel(ctx)
	ended, err := s.repo.deleteSecret(bg, tid, secID, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, store.ErrSecretGone):
		return nil
	case err != nil:
		return fmt.Errorf("tenantops: delete secret: %w", err)
	}
	if name := ended.RemovedFile; name != "" {
		// The key of the file is destroyed: a file left on disk is
		// unreadable ciphertext.
		if err := s.secretFiles.RemoveSecretFile(tid, name); err != nil {
			s.logger.WarnContext(ctx, "tenantops: secret file left on disk", slog.String("tenant", string(tid)),
				slog.String("error", err.Error()))
		}
	}
	if err := s.repo.scrub(bg); err != nil {
		s.logger.WarnContext(ctx, "tenantops: scrub after a secret deletion failed", slog.String("error", err.Error()))
	}
	s.record(ctx, p, ip, tid, audit.ActionSecretDeleted, audit.ObjectSecret, secID,
		map[string]any{"creatorKind": string(ended.Secret.CreatorKind)})
	return nil
}

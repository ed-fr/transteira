package secret

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// ListMine returns a page of the secrets of tenant t created by a deposit
// session of the address email (the address of a "my transfers" session),
// newest first, in every state: metadata only. Those of the API tokens are
// never listed. A malformed cursor is a *ValidationError on FieldCursor.
func (s *Service) ListMine(ctx context.Context, t *tenant.Tenant, email, cursor string, limit int) (store.Page[store.Secret], error) {
	page, err := s.repo.ListBySender(ctx, t.ID, email, store.SecretListOptions{Cursor: cursor, Limit: limit})
	switch {
	case errors.Is(err, store.ErrInvalid):
		return store.Page[store.Secret]{}, &ValidationError{Fields: []FieldError{{Pointer: FieldCursor, Code: CodeInvalidFormat}}}
	case err != nil:
		return store.Page[store.Secret]{}, fmt.Errorf("secret: list: %w", err)
	}
	return page, nil
}

// DeleteMine deletes, for the client ip, the pending or active secret secID
// of tenant t created by a deposit session of the address email: its content
// is destroyed (cryptographic erasure) and it becomes a deleted tombstone,
// audited secret.deleted with the address as actor. A secret already ended
// is a no-op (nil). ErrNotFound for an unknown secret, one of another
// tenant, of another address or of an API token.
func (s *Service) DeleteMine(ctx context.Context, t *tenant.Tenant, email string, ip netip.Addr, secID string) error {
	out, err := s.repo.DeleteByCreator(ctx, t.ID, secID, store.SecretActor{Email: email}, s.now())
	switch {
	case errors.Is(err, store.ErrSecretGone):
		return nil
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("secret: delete: %w", err)
	}
	s.erased(ctx, t, out.RemovedFile)
	s.record(ctx, t, audit.Event{
		ActorKind: store.ActorDepositor, Actor: out.Secret.SenderEmail, IP: ip, Action: audit.ActionSecretDeleted, ObjectID: secID,
	})
	return nil
}

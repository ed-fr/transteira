package tenantops

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Invitation is an invitation as the administration lists it (OpenAPI
// Invitation): never its link.
type Invitation struct {
	ID    string
	Email string
	// InvitedBy is the address of the issuer, or its pseudonym
	// ("erased-<16 hex>") after a GDPR erasure.
	InvitedBy string
	// Status is derived at the time of the request.
	Status    store.InvitationStatus
	CreatedAt time.Time
	ExpiresAt time.Time
	// LastUsedAt is zero when the invitation was never used.
	LastUsedAt time.Time
}

// InvitationFilter selects a page of invitations (OpenAPI
// listTenantInvitations).
type InvitationFilter struct {
	// Status keeps the invitations of this status ("" for all).
	Status string
	// Cursor is the nextCursor of the previous page, "" for the first.
	Cursor string
	// Limit is the page size, 0 for store.DefaultPageSize.
	Limit int
}

// invitationStatuses are the statuses accepted by the status filter.
var invitationStatuses = map[store.InvitationStatus]bool{
	store.InvitationPending: true, store.InvitationUsed: true,
	store.InvitationExpired: true, store.InvitationRevoked: true,
}

// ListInvitations returns a page of the invitations of tenant tid, most
// recent first, with their issuer and their status at the time of the
// request.
func (s *Service) ListInvitations(ctx context.Context, p adminauth.Principal, tid tenant.ID, f InvitationFilter) (store.Page[Invitation], error) {
	if err := s.readable(ctx, p, tid); err != nil {
		return store.Page[Invitation]{}, err
	}
	status := store.InvitationStatus(f.Status)
	if f.Status != "" && !invitationStatuses[status] {
		return store.Page[Invitation]{}, invalid(FieldStatus, "unknown invitation status")
	}
	if err := checkLimit(f.Limit); err != nil {
		return store.Page[Invitation]{}, err
	}
	now := s.now()
	page, err := s.repo.listInvitations(ctx, tid, store.InvitationFilter{
		Status: status, Now: now, Cursor: f.Cursor, Limit: f.Limit,
	})
	if err != nil {
		return store.Page[Invitation]{}, listError("list invitations", err)
	}
	out := store.Page[Invitation]{Items: make([]Invitation, len(page.Items)), NextCursor: page.NextCursor}
	for i, inv := range page.Items {
		out.Items[i] = Invitation{
			ID: inv.ID, Email: inv.Email, InvitedBy: inv.InvitedBy, Status: inv.Status(now),
			CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt, LastUsedAt: inv.LastUsedAt,
		}
	}
	return out, nil
}

// RevokeInvitation revokes the invitation invID of tenant tid while it is
// still usable (pending, or used but not expired): its link stops working
// immediately, and the deposit sessions opened with it end (the
// deposit service checks the invitation of every session). Revoking an
// invitation that is already revoked or expired is a no-op without audit
// (nil error), as the specification requires. It records
// invitation.revoked.
func (s *Service) RevokeInvitation(ctx context.Context, p adminauth.Principal, tid tenant.ID, invID string, ip netip.Addr) error {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return err
	}
	if !id.Valid(id.Invitation, invID) {
		return ErrNotFound
	}
	inv, err := s.repo.getInvitation(ctx, tid, invID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("tenantops: get invitation: %w", err)
	}
	now := s.now()
	if st := inv.Status(now); st != store.InvitationPending && st != store.InvitationUsed {
		return nil
	}
	err = s.repo.revokeInvitation(ctx, tid, invID, now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Revoked (or erased) concurrently: the outcome is the same.
		return nil
	case err != nil:
		return fmt.Errorf("tenantops: revoke invitation: %w", err)
	}
	s.record(ctx, p, ip, tid, audit.ActionInvitationRevoked, audit.ObjectInvitation, invID, nil)
	return nil
}

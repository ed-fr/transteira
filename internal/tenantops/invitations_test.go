package tenantops

import (
	"context"
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// invitations stores, in tn, a pending, a used, a revoked and an
// expiring invitation (expired one hour after testStart), oldest first.
func (ev *env) invitations(tn *tenant.Tenant) (pending, used, revoked, expiring string) {
	ev.t.Helper()
	ctx := context.Background()
	pending = ev.invite(tn)
	ev.clock.Advance(time.Second)
	used = ev.invite(tn)
	sc, err := ev.db.Scoped(tn.ID)
	mustNoErr(ev.t, "scope", err)
	mustNoErr(ev.t, "touch", sc.Tx(ctx, func(tx *store.ScopedTx) error {
		return ev.db.Invitations().TouchTx(ctx, tx, used, ev.clock.Now())
	}))
	ev.clock.Advance(time.Second)
	revoked = ev.invite(tn)
	mustNoErr(ev.t, "revoke", ev.db.Invitations().Revoke(ctx, tn.ID, revoked, ev.clock.Now()))
	ev.clock.Advance(time.Second)
	expiring = id.New(id.Invitation)
	hash := sha256.Sum256([]byte(expiring))
	mustNoErr(ev.t, "expiring", ev.db.Invitations().Create(ctx, tn.ID, store.Invitation{
		ID: expiring, TokenHash: hash[:], Email: dave, InvitedBy: alice, ExpiresAt: ev.clock.Now().Add(time.Hour),
	}))
	return pending, used, revoked, expiring
}

// TestListInvitations lists the invitations with their issuer and their
// status at the time of the request.
func TestListInvitations(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		pending, used, revoked, expiring := ev.invitations(ev.a)
		ev.invite(ev.b)
		ev.clock.Advance(2 * time.Hour)

		page, err := ev.svc.ListInvitations(ctx, ev.adminA, ev.a.ID, InvitationFilter{})
		mustNoErr(t, "list", err)
		var ids []string
		var statuses []store.InvitationStatus
		for _, inv := range page.Items {
			ids = append(ids, inv.ID)
			statuses = append(statuses, inv.Status)
		}
		if want := []string{expiring, revoked, used, pending}; !slices.Equal(ids, want) {
			t.Fatalf("listed %v, want %v", ids, want)
		}
		wantStatuses := []store.InvitationStatus{store.InvitationExpired, store.InvitationRevoked, store.InvitationUsed, store.InvitationPending}
		if !slices.Equal(statuses, wantStatuses) {
			t.Errorf("statuses = %v, want %v", statuses, wantStatuses)
		}
		got := page.Items[2]
		if got.Email != dave || got.InvitedBy != alice || got.LastUsedAt.IsZero() ||
			!got.CreatedAt.Equal(testStart.Add(time.Second)) || got.ExpiresAt.IsZero() {
			t.Errorf("used invitation = %+v", got)
		}
		for st, want := range map[string]string{"pending": pending, "used": used, "revoked": revoked, "expired": expiring} {
			page, err := ev.svc.ListInvitations(ctx, ev.super, ev.a.ID, InvitationFilter{Status: st})
			if err != nil || len(page.Items) != 1 || page.Items[0].ID != want {
				t.Errorf("status %s = %+v, %v", st, page.Items, err)
			}
		}
		page, err = ev.svc.ListInvitations(ctx, ev.adminA, ev.a.ID, InvitationFilter{Limit: 3})
		if err != nil || len(page.Items) != 3 || page.NextCursor == "" {
			t.Fatalf("first page = %+v, %v", page, err)
		}
		page, err = ev.svc.ListInvitations(ctx, ev.adminA, ev.a.ID, InvitationFilter{Limit: 3, Cursor: page.NextCursor})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != pending {
			t.Errorf("second page = %+v, %v", page, err)
		}
		_, err = ev.svc.ListInvitations(ctx, ev.adminA, ev.a.ID, InvitationFilter{Status: "lost"})
		wantInvalid(t, "status", err, FieldStatus)
		_, err = ev.svc.ListInvitations(ctx, ev.adminA, ev.a.ID, InvitationFilter{Limit: 500})
		wantInvalid(t, "limit", err, FieldLimit)
		_, err = ev.svc.ListInvitations(ctx, ev.adminA, ev.a.ID, InvitationFilter{Cursor: "1:x"})
		wantInvalid(t, "cursor", err, FieldCursor)
		ev.faults("listInvitations")
		_, err = ev.svc.ListInvitations(ctx, ev.adminA, ev.a.ID, InvitationFilter{})
		wantErr(t, "list failure", err, errBoom)
	})
}

// TestRevokeInvitation revokes a pending or a used invitation once; a
// revoked or expired one is a silent no-op.
func TestRevokeInvitation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		pending, used, revoked, expiring := ev.invitations(ev.a)
		ev.clock.Advance(2 * time.Hour)

		mustNoErr(t, "revoke", ev.svc.RevokeInvitation(ctx, ev.adminA, ev.a.ID, pending, clientIP))
		inv, err := ev.db.Invitations().Get(ctx, ev.a.ID, pending)
		if err != nil || !inv.RevokedAt.Equal(ev.clock.Now()) {
			t.Fatalf("revoked invitation = %+v, %v", inv, err)
		}
		evs := ev.auditEvents(ev.a.ID, audit.ActionInvitationRevoked)
		if len(evs) != 1 || evs[0].ObjectKind != audit.ObjectInvitation || evs[0].ObjectID != pending ||
			evs[0].Actor != "alice.admin" || evs[0].IP != clientIP || len(evs[0].Details) != 0 {
			t.Fatalf("audit = %+v", evs)
		}
		// A used invitation stays usable, so it is revoked too.
		mustNoErr(t, "revoke used", ev.svc.RevokeInvitation(ctx, ev.adminA, ev.a.ID, used, clientIP))
		if inv, _ := ev.db.Invitations().Get(ctx, ev.a.ID, used); !inv.RevokedAt.Equal(ev.clock.Now()) {
			t.Errorf("used invitation not revoked: %+v", inv)
		}
		for _, invID := range []string{pending, used, revoked, expiring} {
			mustNoErr(t, "no-op revoke", ev.svc.RevokeInvitation(ctx, ev.super, ev.a.ID, invID, clientIP))
		}
		if n := len(ev.auditEvents(ev.a.ID, audit.ActionInvitationRevoked)); n != 2 {
			t.Errorf("audit events after no-ops = %d, want 2", n)
		}

		wantErr(t, "malformed", ev.svc.RevokeInvitation(ctx, ev.adminA, ev.a.ID, "inv_bad", clientIP), ErrNotFound)
		wantErr(t, "missing", ev.svc.RevokeInvitation(ctx, ev.adminA, ev.a.ID, missingInv, clientIP), ErrNotFound)

		fresh := ev.invite(ev.a)
		f := ev.faults("getInvitation")
		wantErr(t, "get failure", ev.svc.RevokeInvitation(ctx, ev.adminA, ev.a.ID, fresh, clientIP), errBoom)
		f.errs = map[string]error{"revokeInvitation": errBoom}
		wantErr(t, "revoke failure", ev.svc.RevokeInvitation(ctx, ev.adminA, ev.a.ID, fresh, clientIP), errBoom)
		// Revoked concurrently between the read and the update.
		f.errs = map[string]error{"revokeInvitation": store.ErrNotFound}
		mustNoErr(t, "concurrent revoke", ev.svc.RevokeInvitation(ctx, ev.adminA, ev.a.ID, fresh, clientIP))
		if n := len(ev.auditEvents(ev.a.ID, audit.ActionInvitationRevoked)); n != 2 {
			t.Errorf("audit events after failures = %d, want 2", n)
		}
	})
}

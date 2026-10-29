package datasubject

import (
	"context"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestStoreRepoEdges(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		r := newStoreRepo(ev.db, nil)
		bad := tenant.ID("bad tenant")

		if err := r.deleteDepositRows(ctx, bad, carol); err == nil {
			t.Error("deleteDepositRows(bad tenant) succeeded")
		}
		if err := r.deleteDepositRows(ctx, ev.a.ID, "not an address"); err == nil {
			t.Error("deleteDepositRows(bad address) succeeded")
		}
		mac := make([]byte, store.AddressMACSize)
		if _, err := r.deleteSenderAccess(ctx, bad, carol, mac); err == nil {
			t.Error("deleteSenderAccess(bad tenant) succeeded")
		}
		if _, err := r.deleteSenderAccess(ctx, ev.a.ID, "not an address", mac); err == nil {
			t.Error("deleteSenderAccess(bad address) succeeded")
		}
		if _, err := r.deleteSenderAccess(ctx, ev.a.ID, carol, mac[:3]); err == nil {
			t.Error("deleteSenderAccess(bad mac) succeeded")
		}
		if _, err := r.removeRecipient(ctx, bad, "trf_x", carol); err == nil {
			t.Error("removeRecipient(bad tenant) succeeded")
		}
		if _, err := r.eraseInvitations(ctx, bad, carol, newPseudonym(carol), testStart); err == nil {
			t.Error("eraseInvitations(bad tenant) succeeded")
		}
		if _, err := r.eraseInvitations(ctx, ev.a.ID, "not an address", newPseudonym(carol), testStart); err == nil {
			t.Error("eraseInvitations(bad address) succeeded")
		}
		if _, err := r.eraseAbuse(ctx, bad, carol, newPseudonym(carol)); err == nil {
			t.Error("eraseAbuse(bad tenant) succeeded")
		}
		if _, err := r.eraseAbuse(ctx, ev.a.ID, "not an address", newPseudonym(carol)); err == nil {
			t.Error("eraseAbuse(bad address) succeeded")
		}
		if _, err := r.eraseAbuse(ctx, ev.a.ID, carol, "not a pseudonym"); err == nil {
			t.Error("eraseAbuse(bad pseudonym) succeeded")
		}
		if _, err := r.inviteeInvitations(ctx, bad, carol); err == nil {
			t.Error("inviteeInvitations(bad tenant) succeeded")
		}
		if _, err := r.verified(ctx, bad, carol); err == nil {
			t.Error("verified(bad tenant) succeeded")
		}

		// A transfer that does not exist, and one the address is not a
		// recipient of.
		if out, err := r.removeRecipient(ctx, ev.a.ID, "trf_01JZZZZZZZZZZZZZZZZZZZZZZZ", carol); err != nil || out != recipientGone {
			t.Errorf("removeRecipient(missing) = %v, %v", out, err)
		}
		trfID := ev.transfer(ev.a, alice, "", []string{dave, erin}, stateAvailable)
		if out, err := r.removeRecipient(ctx, ev.a.ID, trfID, carol); err != nil || out != recipientGone {
			t.Errorf("removeRecipient(not a recipient) = %v, %v", out, err)
		}
		if _, err := r.removeRecipient(ctx, ev.a.ID, trfID, "not an address"); err == nil {
			t.Error("removeRecipient(bad address) succeeded")
		}

		// The invitations of the address only.
		want := map[string]bool{}
		for range 3 {
			want[ev.invitation(ev.a, carol, alice)] = true
			ev.invitation(ev.a, dave, alice)
		}
		got, err := r.inviteeInvitations(ctx, ev.a.ID, carol)
		if err != nil || len(got) != 3 {
			t.Fatalf("inviteeInvitations = %v, %v", got, err)
		}
		for _, invID := range got {
			if !want[invID] {
				t.Errorf("unexpected invitation %s", invID)
			}
		}
	})
}

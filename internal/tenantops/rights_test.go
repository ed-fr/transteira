package tenantops

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// operations returns every tenant operation of the service on tid, as
// called by p, on objects of tenant A (a transfer, an invitation, a
// blocklist entry created afresh when the operation consumes one).
func operations(ev *env) map[string]func(p adminauth.Principal, tid tenant.ID) error {
	ctx := context.Background()
	trf := ev.seed(ev.a, store.TransferAvailable, carol)
	del := ev.seed(ev.a, store.TransferAvailable, carol)
	resend := ev.seed(ev.a, store.TransferAvailable, carol)
	inv := ev.invite(ev.a)
	var entries []string
	for i := range 6 {
		e, err := ev.db.Blocklist().Create(ctx, ev.a.ID,
			store.BlocklistEntry{Kind: store.BlockDomain, Value: fmt.Sprintf("old%d.example.net", i)})
		mustNoErr(ev.t, "blocklist", err)
		entries = append(entries, e.ID)
	}
	n := 0
	return map[string]func(adminauth.Principal, tenant.ID) error{
		"ListTransfers": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.ListTransfers(ctx, p, tid, TransferFilter{})
			return err
		},
		"GetTransfer": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.GetTransfer(ctx, p, tid, trf.id)
			return err
		},
		"DeleteTransfer": func(p adminauth.Principal, tid tenant.ID) error {
			// The second deletion is a no-op.
			return ev.svc.DeleteTransfer(ctx, p, tid, del.id, "", clientIP)
		},
		"ResendNotification": func(p adminauth.Principal, tid tenant.ID) error {
			return ev.svc.ResendNotification(ctx, p, tid, resend.id, nil, clientIP)
		},
		"ListInvitations": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.ListInvitations(ctx, p, tid, InvitationFilter{})
			return err
		},
		"RevokeInvitation": func(p adminauth.Principal, tid tenant.ID) error {
			return ev.svc.RevokeInvitation(ctx, p, tid, inv, clientIP)
		},
		"ListBlocklist": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.ListBlocklist(ctx, p, tid, BlocklistFilter{})
			return err
		},
		"CreateBlocklistEntry": func(p adminauth.Principal, tid tenant.ID) error {
			n++
			_, err := ev.svc.CreateBlocklistEntry(ctx, p, tid,
				BlocklistInput{Kind: "domain", Value: fmt.Sprintf("spam%d.example.net", n)}, clientIP)
			return err
		},
		"DeleteBlocklistEntry": func(p adminauth.Principal, tid tenant.ID) error {
			entry := entries[0]
			entries = entries[1:]
			return ev.svc.DeleteBlocklistEntry(ctx, p, tid, entry, clientIP)
		},
		"ListAuditEvents": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.ListAuditEvents(ctx, p, tid, AuditFilter{})
			return err
		},
	}
}

// TestRightsMatrix runs every tenant operation as the super admin, the
// delegated admin of A, the delegated admin of B and an unauthenticated
// session, on tenant A, then on a missing tenant.
func TestRightsMatrix(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		for name, op := range operations(ev) {
			// B's admin cannot even tell that A exists.
			wantErr(t, name+" by B's admin on A", op(ev.adminB, ev.a.ID), ErrNotFound)
			wantErr(t, name+" unauthenticated", op(unauthenticated(ev.adminA), ev.a.ID), ErrUnauthenticated)
			mustNoErr(t, name+" by A's admin", op(ev.adminA, ev.a.ID))
			mustNoErr(t, name+" by the super admin", op(ev.super, ev.a.ID))
			// A missing tenant answers like an inaccessible one.
			wantErr(t, name+" on a missing tenant", op(ev.super, missingTen), ErrNotFound)
			wantErr(t, name+" on a malformed tenant", op(ev.super, "bad"), ErrNotFound)
		}
	})
}

// TestTenantBeingDeleted answers every operation on a tenant being deleted
// like a missing tenant.
func TestTenantBeingDeleted(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ops := operations(ev)
		mustNoErr(t, "status", ev.db.Tenants().SetStatus(context.Background(), ev.a.ID, tenant.StatusDeleting))
		for name, op := range ops {
			wantErr(t, name+" on a tenant being deleted", op(ev.super, ev.a.ID), ErrNotFound)
		}
	})
}

// TestTenantReadFailure reports a failure to read the tenant as an
// internal error.
func TestTenantReadFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ops := operations(ev)
		ev.faults("getTenant")
		for name, op := range ops {
			wantErr(t, name, op(ev.super, ev.a.ID), errBoom)
		}
	})
}

// TestObjectsOfAnotherTenant answers an object of tenant B, addressed
// through tenant A, exactly like a missing object.
func TestObjectsOfAnotherTenant(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		trfB := ev.seed(ev.b, store.TransferAvailable, carol)
		invB := ev.invite(ev.b)
		blkB, err := ev.db.Blocklist().Create(ctx, ev.b.ID, store.BlocklistEntry{Kind: store.BlockDomain, Value: "spam.example.net"})
		mustNoErr(t, "blocklist", err)
		for _, p := range []adminauth.Principal{ev.adminA, ev.super} {
			_, err := ev.svc.GetTransfer(ctx, p, ev.a.ID, trfB.id)
			wantErr(t, "GetTransfer", err, ErrNotFound)
			wantErr(t, "DeleteTransfer", ev.svc.DeleteTransfer(ctx, p, ev.a.ID, trfB.id, "", clientIP), ErrNotFound)
			wantErr(t, "ResendNotification", ev.svc.ResendNotification(ctx, p, ev.a.ID, trfB.id, nil, clientIP), ErrNotFound)
			wantErr(t, "RevokeInvitation", ev.svc.RevokeInvitation(ctx, p, ev.a.ID, invB, clientIP), ErrNotFound)
			wantErr(t, "DeleteBlocklistEntry", ev.svc.DeleteBlocklistEntry(ctx, p, ev.a.ID, blkB.ID, clientIP), ErrNotFound)
		}
		// B's objects are untouched.
		d, err := ev.db.Transfers().Get(ctx, ev.b.ID, trfB.id)
		if err != nil || d.Status != store.TransferAvailable {
			t.Fatalf("B's transfer = %v, %v", d.Status, err)
		}
		inv, err := ev.db.Invitations().Get(ctx, ev.b.ID, invB)
		if err != nil || !inv.RevokedAt.IsZero() {
			t.Fatalf("B's invitation = %+v, %v", inv, err)
		}
		if _, err := ev.db.Blocklist().Get(ctx, ev.b.ID, blkB.ID); err != nil {
			t.Fatalf("B's entry: %v", err)
		}
		if ev.mailer.count() != 0 {
			t.Fatal("a mail was queued")
		}
	})
}

// TestAccessBeforeValidation checks that every operation taking a body or
// filters checks access first: on a tenant the caller cannot reach (or
// that does not exist) an invalid input still answers ErrNotFound.
func TestAccessBeforeValidation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		long := strings.Repeat("x", MaxReasonLen+1)
		ops := []struct {
			name, field string
			op          func(p adminauth.Principal, tid tenant.ID) error
		}{
			{"ListTransfers", FieldStatus, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.ListTransfers(ctx, p, tid, TransferFilter{Status: "lost"})
				return err
			}},
			{"DeleteTransfer", FieldReason, func(p adminauth.Principal, tid tenant.ID) error {
				return ev.svc.DeleteTransfer(ctx, p, tid, missingTrf, long, clientIP)
			}},
			{"ResendNotification", FieldRecipients, func(p adminauth.Principal, tid tenant.ID) error {
				return ev.svc.ResendNotification(ctx, p, tid, missingTrf, make([]string, store.MaxTransferRecipients+1), clientIP)
			}},
			{"ListInvitations", FieldStatus, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.ListInvitations(ctx, p, tid, InvitationFilter{Status: "lost"})
				return err
			}},
			{"ListBlocklist", FieldKindParam, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.ListBlocklist(ctx, p, tid, BlocklistFilter{Kind: "ip"})
				return err
			}},
			{"CreateBlocklistEntry", FieldKind, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.CreateBlocklistEntry(ctx, p, tid, BlocklistInput{Kind: "ip", Value: "192.0.2.1"}, clientIP)
				return err
			}},
			{"ListAuditEvents", FieldAction, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.ListAuditEvents(ctx, p, tid, AuditFilter{Action: "DROP TABLE"})
				return err
			}},
		}
		for _, o := range ops {
			wantErr(t, o.name+" by B's admin on A", o.op(ev.adminB, ev.a.ID), ErrNotFound)
			wantErr(t, o.name+" on a missing tenant", o.op(ev.super, missingTen), ErrNotFound)
			wantErr(t, o.name+" unauthenticated", o.op(unauthenticated(ev.adminA), ev.a.ID), ErrUnauthenticated)
			// The input is indeed invalid for a caller with access.
			wantInvalid(t, o.name+" by A's admin", o.op(ev.adminA, ev.a.ID), o.field)
		}
		// The global audit log checks the role before its filters.
		_, err := ev.svc.ListGlobalAuditEvents(ctx, ev.adminA, GlobalAuditFilter{Action: "bad"})
		wantErr(t, "global audit by A's admin", err, ErrForbidden)
	})
}

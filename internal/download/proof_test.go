package download

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// deliveryOf returns the delivery proof of p, overall (linkID "") or of a
// recipient link (store.ErrNotFound when none).
func (ev *env) deliveryOf(p published, linkID string) (store.TransferProof, error) {
	return ev.db.TransferProofs().Get(context.Background(), p.tn.ID, p.id, store.ProofDelivery, linkID)
}

// mustDelivery returns the delivery proof of p for linkID, its signature
// verified against the published keys, and its statement.
func (ev *env) mustDelivery(p published, linkID string) (store.TransferProof, proof.Statement) {
	ev.t.Helper()
	pr, err := ev.deliveryOf(p, linkID)
	if err != nil {
		ev.t.Fatalf("delivery proof %q: %v", linkID, err)
	}
	keys, err := ev.signer.Keys(context.Background())
	if err != nil {
		ev.t.Fatal(err)
	}
	st, err := proof.VerifyStatement(pr.Statement, pr.Signature, keys)
	if err != nil {
		ev.t.Fatalf("VerifyStatement: %v", err)
	}
	if st.Kind != store.ProofDelivery || st.TransferID != p.id || st.FirstDownloadedAt == nil {
		ev.t.Fatalf("delivery statement = %+v", st)
	}
	return pr, st
}

// noDelivery fails when p has a delivery proof for linkID.
func (ev *env) noDelivery(p published, linkID string) {
	ev.t.Helper()
	if _, err := ev.deliveryOf(p, linkID); !errors.Is(err, store.ErrNotFound) {
		ev.t.Fatalf("delivery proof %q: %v", linkID, err)
	}
}

// links reads the recipient links of p.
func (ev *env) links(p published) []store.RecipientLink {
	ev.t.Helper()
	l, err := ev.db.RecipientLinks().ListByTransfer(context.Background(), p.tn.ID, p.id)
	if err != nil {
		ev.t.Fatal(err)
	}
	return l
}

// TestDeliveryProofShared writes the overall delivery proof of a shared
// transfer once, at its first complete download.
func TestDeliveryProofShared(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100), random(50)}})
		ev.fetch(p, "", p.files[0].ID, 0, -1, true)
		ev.noDelivery(p, "")
		ev.complete(p)
		first, st := ev.mustDelivery(p, "")
		if *st.FirstDownloadedAt != proof.FormatTime(ev.get(p).FirstDownloadedAt) || len(st.RecipientDownloads) != 0 {
			t.Fatalf("statement = %+v", st)
		}
		ev.clock.advance(time.Minute)
		ev.complete(p)
		again, _ := ev.mustDelivery(p, "")
		if again.ID != first.ID {
			t.Fatal("second delivery proof written")
		}
		// Isolation: tenant B does not see it.
		if _, err := ev.db.TransferProofs().Get(context.Background(), ev.b.ID, p.id, store.ProofDelivery, ""); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("proof of A read in B: %v", err)
		}
	})
}

// TestDeliveryProofPerRecipient writes, at the first completion of the
// first link, the overall proof and the proof of that recipient; at the
// first completion of another link, the proof of that recipient only; and
// nothing for a repeated completion.
func TestDeliveryProofPerRecipient(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, perRecipient: true, recipients: []string{dave, erin}})
		l0, l1 := p.links[0].ID, p.links[1].ID
		ev.complete(p.link(0))
		overall, st := ev.mustDelivery(p, "")
		if len(st.RecipientDownloads) != 1 || st.RecipientDownloads[0].Email != dave {
			t.Fatalf("overall statement = %+v", st.RecipientDownloads)
		}
		rec0, st0 := ev.mustDelivery(p, l0)
		if len(st0.RecipientDownloads) != 1 || st0.RecipientDownloads[0].Email != dave {
			t.Fatalf("recipient statement = %+v", st0.RecipientDownloads)
		}
		ev.noDelivery(p, l1)

		ev.clock.advance(time.Minute)
		ev.complete(p.link(1))
		_, st1 := ev.mustDelivery(p, l1)
		if len(st1.RecipientDownloads) != 1 || st1.RecipientDownloads[0].Email != erin {
			t.Fatalf("second recipient statement = %+v", st1.RecipientDownloads)
		}
		if o, _ := ev.mustDelivery(p, ""); o.ID != overall.ID {
			t.Fatal("overall proof written again")
		}

		// A repeated completion writes nothing new.
		ev.clock.advance(time.Minute)
		ev.complete(p.link(0))
		r := newStoreRepo(ev.db, nil, ev.signer)
		if _, err := r.completeLink(context.Background(), ev.a, p.id, l0, ev.clock.now(), time.Time{}); err != nil {
			t.Fatalf("repeated completion: %v", err)
		}
		// Without Proofs (tests only), the completion writes none.
		if _, err := newStoreRepo(ev.db, nil, nil).completeLink(context.Background(), ev.a, p.id, l0, ev.clock.now(), time.Time{}); err != nil {
			t.Fatalf("completion without proofs: %v", err)
		}
		if again, _ := ev.mustDelivery(p, l0); again.ID != rec0.ID {
			t.Fatal("recipient proof written again")
		}
		if o, _ := ev.mustDelivery(p, ""); o.ID != overall.ID {
			t.Fatal("overall proof written again")
		}
	})
}

// failingProofs fails its preparations while fail is set.
type failingProofs struct {
	inner Proofs
	fail  *atomic.Bool
}

func (p failingProofs) Prepare(ctx context.Context) (*proof.Sealer, error) {
	if p.fail.Load() {
		return nil, errFault
	}
	return p.inner.Prepare(ctx)
}

// TestDeliveryProofFailures rolls the first download back with a proof
// that cannot be prepared or written: no first download, no completion of
// the link, no mail, the range state kept, and the next complete download
// records everything.
func TestDeliveryProofFailures(t *testing.T) {
	for _, c := range []struct {
		name, step   string
		perRecipient bool
	}{
		{"shared-prepare", "prepare", false},
		{"shared-overall", "overall", false},
		{"link-prepare", "prepare", true},
		{"link-recipient", "recipient", true},
		{"link-overall", "overall", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, nil)
				var fail atomic.Bool
				fail.Store(true)
				r := newStoreRepo(ev.db, auditWriter(ev.db, nil), ev.signer)
				switch c.step {
				case "prepare":
					r.proofs = failingProofs{inner: ev.signer, fail: &fail}
				case "overall":
					r.overall = func(s *proof.Sealer, ctx context.Context, tx *store.ScopedTx, tn *tenant.Tenant, trfID string, now time.Time) error {
						if fail.Load() {
							// A conflict must not pass for a transfer no
							// longer available.
							return store.ErrConflict
						}
						return s.OverallDeliveryTx(ctx, tx, tn, trfID, now)
					}
				case "recipient":
					r.recipient = func(s *proof.Sealer, ctx context.Context, tx *store.ScopedTx, tn *tenant.Tenant, trfID, linkID string, now time.Time) error {
						if fail.Load() {
							return errFault
						}
						return s.RecipientDeliveryTx(ctx, tx, tn, trfID, linkID, now)
					}
				}
				ev.svc.repo = faultRepo{inner: r, f: ev.f}
				p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, perRecipient: c.perRecipient, recipients: []string{dave, erin}})
				ev.complete(p)
				if !ev.get(p).FirstDownloadedAt.IsZero() {
					t.Fatal("first download recorded without its proof")
				}
				ev.noDelivery(p, "")
				linkID := ""
				if c.perRecipient {
					linkID = p.links[0].ID
					ev.noDelivery(p, linkID)
					if !ev.links(p)[0].CompletedAt.IsZero() || ev.linkState(p, 0) == nil {
						t.Fatal("link completed without its proof, or state lost")
					}
				} else if ev.state(p) == nil {
					t.Fatal("range state lost")
				}
				if len(ev.firstDownloads()) != 0 {
					t.Fatal("first download mail sent")
				}
				if ev.logs.count("delivery proof not written") != 1 {
					t.Fatalf("failure not logged:\n%s", ev.logs.all())
				}

				// The next complete download records it, with its proofs.
				fail.Store(false)
				ev.fetch(p, "", p.files[0].ID, 0, 1, true)
				if ev.get(p).FirstDownloadedAt.IsZero() {
					t.Fatal("first download not recorded at the next request")
				}
				ev.mustDelivery(p, "")
				if linkID != "" {
					ev.mustDelivery(p, linkID)
				}
				ev.waitUntil("first download mail", func() bool { return len(ev.firstDownloads()) == 1 })
			})
		})
	}
}

package scan

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// depositOf returns the deposit proof of the transfer trfID of tenant tn
// (store.ErrNotFound when none).
func (ev *env) depositOf(tn *tenant.Tenant, trfID string) (store.TransferProof, error) {
	return ev.db.TransferProofs().Get(context.Background(), tn.ID, trfID, store.ProofDeposit, "")
}

// verified checks the signature of p against the published keys and
// returns its statement.
func (ev *env) verified(p store.TransferProof) proof.Statement {
	ev.t.Helper()
	keys, err := ev.signer.Keys(context.Background())
	if err != nil {
		ev.t.Fatalf("Keys: %v", err)
	}
	st, err := proof.VerifyStatement(p.Statement, p.Signature, keys)
	if err != nil {
		ev.t.Fatalf("VerifyStatement: %v", err)
	}
	return st
}

// failingProofs fails its preparations while fail is set, then prepares
// with inner.
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

// withRepo replaces the store repo of the worker (still wrapped with the
// faults) by r.
func (ev *env) withRepo(r storeRepo) {
	ev.w.repo = faultRepo{inner: r, f: ev.f}
}

// TestDepositProofOnAvailability writes, with the availability, one
// deposit proof signed by the instance, for a shared transfer and for a
// transfer with one link per recipient, and none for a rejected transfer.
func TestDepositProofOnAvailability(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		shared := ev.scanning(ev.a, clean(10), antivirustest.EICAR())
		perRec := ev.perRecipient(ev.b, clean(12))
		rejected := ev.scanning(ev.a, antivirustest.EICAR())
		ev.start()
		for _, c := range []struct {
			tn    *tenant.Tenant
			id    string
			files int
		}{{ev.a, shared, 2}, {ev.b, perRec, 1}} {
			d := ev.waitStatus(c.tn, c.id, store.TransferAvailable)
			p, err := ev.depositOf(c.tn, c.id)
			if err != nil {
				t.Fatalf("deposit proof of %s: %v", c.id, err)
			}
			st := ev.verified(p)
			if st.Kind != store.ProofDeposit || st.TransferID != c.id || len(st.Files) != c.files ||
				st.FirstDownloadedAt != nil || st.ExpiresAt != proof.FormatTime(d.ExpiresAt) {
				t.Errorf("statement of %s = %+v (transfer expires %v)", c.id, st, d.ExpiresAt)
			}
			if _, err := ev.db.TransferProofs().Get(context.Background(), c.tn.ID, c.id, store.ProofDelivery, ""); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("delivery proof before any download: %v", err)
			}
		}
		ev.waitStatus(ev.a, rejected, store.TransferRejected)
		if _, err := ev.depositOf(ev.a, rejected); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("deposit proof of a rejected transfer: %v", err)
		}
		// Isolation: the proof of tenant B is not found in tenant A.
		if _, err := ev.db.TransferProofs().Get(context.Background(), ev.a.ID, perRec, store.ProofDeposit, ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("proof of B read in A: %v", err)
		}
	})
}

// TestDepositProofFailures leaves the transfer scanning, without proof nor
// mail, when the signing key cannot be prepared or the proof cannot be
// written, then concludes it on a retry, with its proof.
func TestDepositProofFailures(t *testing.T) {
	for _, step := range []string{"prepare", "deposit"} {
		t.Run(step, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{})
				r := newStoreRepo(ev.db, ev.vault, ev.signer)
				var fail atomic.Bool
				fail.Store(true)
				switch step {
				case "prepare":
					r.proofs = failingProofs{inner: ev.signer, fail: &fail}
				case "deposit":
					r.deposit = func(s *proof.Sealer, ctx context.Context, tx *store.ScopedTx, tn *tenant.Tenant, trfID string, now time.Time) error {
						if fail.Load() {
							return errFault
						}
						return s.DepositTx(ctx, tx, tn, trfID, now)
					}
				}
				ev.withRepo(r)
				trfID := ev.perRecipient(ev.a, clean(10))
				ev.f.set("sweep", 0, nil)
				ev.w.Enqueue(ev.a.ID, trfID)
				ev.start()
				// Several failed conclusions: the transfer stays scanning,
				// without link, proof nor mail.
				ev.waitUntil("failed conclusions", func() bool { return ev.logs.count("will retry") >= 2 })
				d := ev.get(ev.a, trfID)
				if d.Status != store.TransferScanning || d.DownloadTokenKeyID != "" {
					t.Fatalf("transfer after the failure = %s %q", d.Status, d.DownloadTokenKeyID)
				}
				links, err := ev.db.RecipientLinks().ListByTransfer(context.Background(), ev.a.ID, trfID)
				if err != nil || len(links) != 0 {
					t.Fatalf("links after the failure = %d, %v", len(links), err)
				}
				if _, err := ev.depositOf(ev.a, trfID); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("proof after the failure: %v", err)
				}
				if n := len(ev.queue.snapshot()); n != 0 {
					t.Fatalf("%d mails after the failure", n)
				}
				if !strings.Contains(ev.logs.all(), "deposit proof: injected fault") {
					t.Errorf("failure not logged:\n%s", ev.logs.all())
				}
				// The retry concludes it, with its proof and its mails.
				fail.Store(false)
				ev.waitStatus(ev.a, trfID, store.TransferAvailable)
				ev.waitIdle()
				p, err := ev.depositOf(ev.a, trfID)
				if err != nil {
					t.Fatalf("proof after the retry: %v", err)
				}
				ev.verified(p)
			})
		})
	}
}

// TestDepositProofIdempotent keeps the proof already written for a
// transfer: a second write in the same state adds nothing.
func TestDepositProofIdempotent(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), Options{})
	trfID := ev.scanning(ev.a, clean(10))
	ev.start()
	ev.waitStatus(ev.a, trfID, store.TransferAvailable)
	first, err := ev.depositOf(ev.a, trfID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sealer, err := ev.signer.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ev.db.Scoped(ev.a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Tx(ctx, func(tx *store.ScopedTx) error {
		return sealer.DepositTx(ctx, tx, ev.a, trfID, time.Now())
	}); err != nil {
		t.Fatalf("second DepositTx: %v", err)
	}
	again, err := ev.depositOf(ev.a, trfID)
	if err != nil || again.ID != first.ID {
		t.Fatalf("proof after a second write = %s, %v (was %s)", again.ID, err, first.ID)
	}
}

// TestRepoWithoutProofs makes a transfer available without writing any
// proof when the worker has no Proofs (tests only).
func TestRepoWithoutProofs(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), Options{})
	trfID := ev.scanning(ev.a, clean(10))
	r := newStoreRepo(ev.db, ev.vault, nil)
	if _, err := r.makeAvailable(context.Background(), ev.a, trfID, false, []string{"dl_" + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"}, time.Now()); err != nil {
		t.Fatalf("makeAvailable: %v", err)
	}
	if d := ev.get(ev.a, trfID); d.Status != store.TransferAvailable {
		t.Fatalf("status = %s", d.Status)
	}
	if _, err := ev.depositOf(ev.a, trfID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("proof written without Proofs: %v", err)
	}
}

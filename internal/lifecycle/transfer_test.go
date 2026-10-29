package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// testHolder records the holds of EraseTransfer; err fails the next Hold.
type testHolder struct {
	mu       sync.Mutex
	err      error
	holds    int
	releases int
	held     int
	keys     []string
}

func (h *testHolder) Hold(_ context.Context, tid tenant.ID, trfID string, intent HoldIntent) (func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		err := h.err
		h.err = nil
		return nil, err
	}
	h.holds++
	h.held++
	h.keys = append(h.keys, fmt.Sprintf("%s/%s/%d", tid, trfID, intent))
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.releases++
		h.held--
	}, nil
}

// isHeld reports whether a hold is in progress.
func (h *testHolder) isHeld() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.held > 0
}

// counts returns the holds and releases so far.
func (h *testHolder) counts() (holds, releases int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.holds, h.releases
}

// withHolder installs a test holder on the sweeper of ev.
func (ev *env) withHolder() *testHolder {
	h := &testHolder{}
	ev.s.holder = h
	return h
}

// eraseTransfer runs EraseTransfer on fx with mode.
func (ev *env) eraseTransfer(fx fixture, mode EraseMode) (EraseResult, error) {
	return ev.s.EraseTransfer(context.Background(), fx.tn.ID, fx.id, mode)
}

// mustErase runs EraseTransfer on fx with mode and expects want.
func (ev *env) mustErase(fx fixture, mode EraseMode, want EraseResult) {
	ev.t.Helper()
	got, err := ev.eraseTransfer(fx, mode)
	if err != nil || got != want {
		ev.t.Fatalf("EraseTransfer = %v, %v; want %v\nlogs:\n%s", got, err, want, ev.logs.all())
	}
}

// expireOutside erases fx without the sweeper and marks it expired.
func (ev *env) expireOutside(fx fixture) {
	ev.t.Helper()
	ctx := context.Background()
	d := ev.get(fx)
	if err := ev.uploads.RemoveFiles(ctx, fx.tn.ID, d.Files); err != nil {
		ev.t.Fatal(err)
	}
	ev.tx(fx.tn, func(tx *store.ScopedTx) error {
		if err := ev.vault.DestroyTx(ctx, tx, d.DownloadTokenKeyID); err != nil {
			return err
		}
		return ev.db.Transfers().MarkExpiredTx(ctx, tx, fx.id, ev.clock.Now())
	})
}

// assertGone checks that the row of fx was deleted with every key and
// file of before.
func (ev *env) assertGone(fx fixture, before store.TransferDetails) {
	ev.t.Helper()
	ctx := context.Background()
	if _, err := ev.db.Transfers().Get(ctx, fx.tn.ID, fx.id); !errors.Is(err, store.ErrNotFound) {
		ev.t.Fatalf("transfer row: %v, want deleted", err)
	}
	if before.DownloadTokenKeyID != "" && ev.keyExists(fx.tn, before.DownloadTokenKeyID) {
		ev.t.Fatal("download token key not destroyed")
	}
	for i, f := range before.Files {
		if f.DEKKeyID != "" && ev.keyExists(fx.tn, f.DEKKeyID) {
			ev.t.Fatalf("file %d data key still stored", i)
		}
		if ev.fileExists(fx.tn, f.StorageName) || ev.exists(fx.tn, f.StorageName+".ckpt") {
			ev.t.Fatalf("file %d still on disk", i)
		}
	}
	if ev.stateExists(fx) {
		ev.t.Fatal("download state still on disk")
	}
	ids, err := ev.db.Transfers().IDsByRecipient(ctx, fx.tn.ID, dave)
	if err != nil {
		ev.t.Fatal(err)
	}
	for _, trfID := range ids {
		if trfID == fx.id {
			ev.t.Fatal("recipient row kept")
		}
	}
}

// liveFixtures returns one transfer of tn per live status, plus a rejected
// one, each with a download state file when available.
func (ev *env) liveFixtures(tn *tenant.Tenant) map[string]fixture {
	ev.t.Helper()
	fxs := map[string]fixture{
		"available": ev.due(tn, 2),
		"scanning":  ev.scanning(tn, 2, t0.Add(-time.Hour)),
		"uploading": ev.uploading(tn, 1, 1, t0.Add(-time.Hour), t0.Add(-time.Hour)),
		"rejected":  ev.rejected(tn, 1),
	}
	return fxs
}

func TestEraseTransferMarkDeleted(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		h := ev.withHolder()
		other := ev.available(ev.b, 1, false)
		fxs := ev.liveFixtures(ev.a)
		for _, fx := range fxs {
			before := ev.get(fx)
			ev.mustErase(fx, MarkDeleted, Erased)
			ev.assertErased(fx, before, store.TransferDeleted)
			// A second deletion has nothing to do.
			ev.mustErase(fx, MarkDeleted, AlreadyEnded)
		}
		if n := ev.usedBytes(ev.a); n != 0 {
			t.Fatalf("quota still used: %d", n)
		}
		ev.assertIntact(other)
		holds, releases := h.counts()
		if holds != 2*len(fxs) || releases != holds || h.isHeld() {
			t.Fatalf("holds %d, releases %d", holds, releases)
		}
		// One scrub per erasure, none for the deletions with nothing to do.
		if n := ev.f.called("scrub"); n != len(fxs) {
			t.Fatalf("%d scrubs, want %d", n, len(fxs))
		}
		if ev.logs.count("transfer erased on request") != len(fxs) {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
	})
}

func TestEraseTransferDeleteRow(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		h := ev.withHolder()
		other := ev.available(ev.b, 1, false)
		fxs := ev.liveFixtures(ev.a)
		fxs["deleted"] = ev.ended(ev.a)
		expired := ev.available(ev.a, 1, false)
		ev.expireOutside(expired)
		fxs["expired"] = expired
		for _, fx := range fxs {
			before := ev.get(fx)
			ev.mustErase(fx, DeleteRow, Erased)
			ev.assertGone(fx, before)
			if _, err := ev.eraseTransfer(fx, DeleteRow); !errors.Is(err, ErrNotFound) {
				t.Fatalf("second erasure: %v, want ErrNotFound", err)
			}
		}
		ev.assertIntact(other)
		if holds, releases := h.counts(); holds != 2*len(fxs) || releases != holds {
			t.Fatalf("holds %d, releases %d", holds, releases)
		}
		// The caller scrubs once after all its erasures.
		if n := ev.f.called("scrub"); n != 0 {
			t.Fatalf("%d scrubs, want none", n)
		}
	})
}

func TestEraseTransferAlreadyEnded(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.withHolder()
		deleted := ev.ended(ev.a)
		expired := ev.available(ev.a, 1, false)
		ev.expireOutside(expired)
		for _, fx := range []fixture{deleted, expired} {
			before := ev.get(fx)
			ev.mustErase(fx, MarkDeleted, AlreadyEnded)
			after := ev.get(fx)
			if after.Status != before.Status || !after.EndedAt.Equal(before.EndedAt) {
				t.Fatalf("status %s -> %s", before.Status, after.Status)
			}
		}
		if ev.f.called("lock") != 0 {
			t.Fatal("files locked for an ended transfer")
		}
	})
}

func TestEraseTransferEndedMeanwhile(t *testing.T) {
	runEach(t, "expired before the final transaction", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.available(ev.a, 1, false)
		ev.f.set("finish", 1, errNotDue)
		ev.mustErase(fx, MarkDeleted, AlreadyEnded)
	})
	runEach(t, "expired before the locks", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.available(ev.a, 1, false)
		ev.f.onCall("lock", func() { ev.expireOutside(fx) })
		ev.mustErase(fx, MarkDeleted, AlreadyEnded)
		if d := ev.get(fx); d.Status != store.TransferExpired {
			t.Fatalf("status %s", d.Status)
		}
	})
	for _, fault := range []string{"transfer", "finish"} {
		runEach(t, "gone at "+fault, func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e)
			fx := ev.available(ev.a, 1, false)
			if fault == "transfer" {
				// The read under the locks finds nothing.
				ev.f.onCall("lock", func() { ev.f.set("transfer", 1, store.ErrNotFound) })
			} else {
				ev.f.set(fault, 1, store.ErrNotFound)
			}
			if _, err := ev.eraseTransfer(fx, DeleteRow); !errors.Is(err, ErrNotFound) {
				t.Fatalf("EraseTransfer = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestEraseTransferNotFound(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		h := ev.withHolder()
		ofB := ev.available(ev.b, 1, false)
		for _, mode := range []EraseMode{MarkDeleted, DeleteRow} {
			for _, fx := range []fixture{
				{tn: ev.a, id: id.New(id.Transfer)},
				{tn: ev.a, id: ofB.id}, // a transfer of another tenant
			} {
				if got, err := ev.eraseTransfer(fx, mode); !errors.Is(err, ErrNotFound) || got != 0 {
					t.Fatalf("EraseTransfer(%v) = %v, %v; want ErrNotFound", mode, got, err)
				}
			}
		}
		ev.assertIntact(ofB)
		if holds, releases := h.counts(); holds != 4 || releases != 4 {
			t.Fatalf("holds %d, releases %d", holds, releases)
		}
	})
}

func TestEraseTransferRefused(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		h := ev.withHolder()
		fx := ev.available(ev.a, 1, false)
		for _, mode := range []EraseMode{0, DeleteRow + 1} {
			if _, err := ev.eraseTransfer(fx, mode); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("mode %d: %v, want ErrInvalid", mode, err)
			}
		}
		if _, err := ev.s.EraseTransfer(context.Background(), "not a tenant", fx.id, MarkDeleted); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("malformed tenant: %v, want ErrInvalid", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := ev.s.EraseTransfer(ctx, fx.tn.ID, fx.id, MarkDeleted); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled: %v", err)
		}
		if holds, _ := h.counts(); holds != 1 {
			t.Fatalf("%d holds, want 1 (the malformed tenant)", holds)
		}
		h.err = context.DeadlineExceeded
		if _, err := ev.eraseTransfer(fx, MarkDeleted); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("hold failure: %v", err)
		}
		ev.assertIntact(fx)
	})
}

func TestEraseTransferBusy(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		h := ev.withHolder()
		fx := ev.uploading(ev.a, 1, 1, t0.Add(-time.Hour), t0.Add(-time.Hour))
		d := ev.get(fx)
		// An upload request holds the incomplete file.
		unlock, err := ev.uploads.LockFiles([]string{d.Files[1].ID})
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []EraseMode{MarkDeleted, DeleteRow} {
			if _, err := ev.eraseTransfer(fx, mode); !errors.Is(err, ErrBusy) {
				t.Fatalf("EraseTransfer(%v) = %v, want ErrBusy", mode, err)
			}
		}
		after := ev.get(fx)
		for i, f := range after.Files {
			if f.DEKKeyID == "" || !ev.keyExists(ev.a, f.DEKKeyID) {
				t.Fatalf("file %d key destroyed while busy", i)
			}
		}
		if after.Status != store.TransferUploading || h.isHeld() {
			t.Fatalf("status %s, held %v", after.Status, h.isHeld())
		}
		unlock()
		ev.mustErase(fx, DeleteRow, Erased)
		ev.assertGone(fx, d)
	})
}

// TestEraseTransferHoldsFirst holds the antivirus before the locks and
// any key destruction, and releases it at the end.
func TestEraseTransferHoldsFirst(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		h := ev.withHolder()
		fx := ev.scanning(ev.a, 1, t0.Add(-time.Hour))
		heldAt := map[string]bool{}
		for _, step := range []string{"transfer", "lock", "remove", "finish"} {
			ev.f.onCall(step, func() { heldAt[step] = h.isHeld() })
		}
		ev.mustErase(fx, MarkDeleted, Erased)
		for _, step := range []string{"transfer", "lock", "remove", "finish"} {
			if !heldAt[step] {
				t.Errorf("step %s ran without the hold (%v)", step, heldAt)
			}
		}
		if h.isHeld() || len(h.keys) != 1 || h.keys[0] != fmt.Sprintf("%s/%s/%d", ev.a.ID, fx.id, HoldForErase) {
			t.Fatalf("holds %v, still held %v", h.keys, h.isHeld())
		}
	})
}

// TestEraseTransferResumesAfterFailure injects a failure at every step of
// EraseTransfer, in both modes: the error is returned with its step (ErrBusy
// for the locks), nothing is marked or deleted, and a second call completes
// the erasure.
func TestEraseTransferResumesAfterFailure(t *testing.T) {
	cases := []struct {
		name   string
		fault  string
		relock bool
		// keysGone tells whether the file keys are destroyed after the
		// failure.
		keysGone bool
	}{
		{"read transfer", "transfer", false, false},
		{"lock files", "lock", false, false},
		{"read transfer under lock", "transfer", true, false},
		{"remove files", "remove", false, false},
		{"file left on disk", "removeAfter", false, true},
		{"remove state", "state", false, true},
		{"destroy token key", "destroy", false, true},
		{"final transaction", "finish", false, true},
	}
	for _, c := range cases {
		for _, mode := range []EraseMode{MarkDeleted, DeleteRow} {
			runEach(t, c.name+modeName(mode), func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e)
				h := ev.withHolder()
				fx := ev.due(ev.a, 2)
				before := ev.get(fx)
				if c.relock {
					ev.f.onCall("lock", func() { ev.f.set(c.fault, 1, nil) })
				} else {
					ev.f.set(c.fault, 1, nil)
				}
				_, err := ev.eraseTransfer(fx, mode)
				if !errors.Is(err, errFault) {
					t.Fatalf("EraseTransfer = %v, want the fault", err)
				}
				if busy := errors.Is(err, ErrBusy); busy != (c.fault == "lock") {
					t.Fatalf("ErrBusy = %v for %s", busy, c.name)
				}
				d := ev.get(fx)
				if d.Status != store.TransferAvailable || !ev.keyExists(ev.a, d.DownloadTokenKeyID) {
					t.Fatalf("after a failure: status %s", d.Status)
				}
				if gone := d.Files[0].DEKKeyID == ""; gone != c.keysGone {
					t.Fatalf("file keys destroyed = %v, want %v", gone, c.keysGone)
				}
				if h.isHeld() {
					t.Fatal("hold not released after a failure")
				}
				if c.fault != "lock" && ev.logs.count("erasure on request failed") != 1 {
					t.Fatalf("logs:\n%s", ev.logs.all())
				}
				ev.mustErase(fx, mode, Erased)
				if mode == MarkDeleted {
					ev.assertDeleted(fx, before)
				} else {
					ev.assertGone(fx, before)
				}
			})
		}
	}
}

// TestEraseTransferWithoutHolder works without an antivirus worker.
func TestEraseTransferWithoutHolder(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		if _, ok := ev.s.holder.(noHolder); !ok {
			t.Fatalf("holder %T, want noHolder", ev.s.holder)
		}
		fx := ev.due(ev.a, 1)
		if !ev.stateExists(fx) {
			t.Fatal("fixture without state")
		}
		before := ev.get(fx)
		ev.mustErase(fx, MarkDeleted, Erased)
		ev.assertDeleted(fx, before)
		if ev.stateExists(fx) || ev.exists(fx.tn, storage.StateName(fx.id)) {
			t.Fatal("state kept")
		}
	})
}

// TestEraseLinkStates: the erasure of a per-recipient transfer removes the
// range state of each of its links too, in both modes; a failure leaves
// them for a new call, and the states of other transfers stay.
func TestEraseLinkStates(t *testing.T) {
	for _, mode := range []EraseMode{MarkDeleted, DeleteRow} {
		runEach(t, modeName(mode), func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e)
			fx, links := ev.perRecipient(ev.a, 7, false, dave, erin)
			other, otherLinks := ev.perRecipient(ev.a, 7, false, dave)
			names := []string{storage.StateName(fx.id), storage.StateName(links[0].ID), storage.StateName(links[1].ID)}
			kept := storage.StateName(otherLinks[0].ID)
			for _, name := range append([]string{kept}, names...) {
				if err := ev.files.WriteState(ev.a.ID, name, []byte(`{}`)); err != nil {
					t.Fatal(err)
				}
			}
			stateOf := func(name string) bool {
				_, err := ev.files.ReadState(ev.a.ID, name)
				return err == nil
			}
			for _, fault := range []string{"linkIDs", "state"} {
				ev.f.set(fault, 1, nil)
				if _, err := ev.eraseTransfer(fx, mode); !errors.Is(err, errFault) || !strings.Contains(err.Error(), stepState) {
					t.Fatalf("%s fault: %v", fault, err)
				}
				if !stateOf(names[1]) || !stateOf(names[2]) {
					t.Fatalf("%s fault: link states removed", fault)
				}
			}
			ev.mustErase(fx, mode, Erased)
			for _, name := range names {
				if stateOf(name) {
					t.Errorf("state %s kept", name)
				}
			}
			if !stateOf(kept) || ev.get(other).Status != store.TransferAvailable {
				t.Error("state of another transfer removed")
			}
		})
	}
}

// modeName names mode in the subtest names.
func modeName(mode EraseMode) string {
	if mode == MarkDeleted {
		return "/mark"
	}
	return "/row"
}

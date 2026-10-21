package lifecycle

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	s := New(Deps{}, Options{})
	if s.interval != DefaultInterval || s.now == nil || s.logger == nil || s.pageSize != store.DeletionSweepLimit {
		t.Fatalf("defaults not applied: interval %v, page %d", s.interval, s.pageSize)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
}

func TestDue(t *testing.T) {
	t.Parallel()
	now := t0
	cases := []struct {
		name string
		tr   store.Transfer
		want bool
	}{
		{"past", store.Transfer{Status: store.TransferAvailable, DeleteAfter: now.Add(-time.Second)}, true},
		{"exactly now", store.Transfer{Status: store.TransferAvailable, DeleteAfter: now}, true},
		{"future", store.Transfer{Status: store.TransferAvailable, DeleteAfter: now.Add(time.Second)}, false},
		{"no deletion time", store.Transfer{Status: store.TransferAvailable}, false},
		{"deleted", store.Transfer{Status: store.TransferDeleted, DeleteAfter: now.Add(-time.Second)}, false},
	}
	for _, c := range cases {
		if got := due(c.tr, now); got != c.want {
			t.Errorf("%s: due = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSweepDeletesDueTransfers(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		dueA := ev.due(ev.a, 3)
		dueB := ev.due(ev.b, 1)
		// A file whose key was destroyed earlier, but left on disk (crash
		// between the key and the file): skipped for the key, removed.
		beforeA := ev.get(dueA)
		ev.tx(ev.a, func(tx *store.ScopedTx) error {
			return ev.vault.DestroyTx(ctx, tx, beforeA.Files[1].DEKKeyID)
		})
		beforeB := ev.get(dueB)
		// Not yet due: downloaded later, still in its grace period.
		pending := ev.available(ev.a, 1, true)
		ev.download(pending, t0.Add(10*time.Minute), t0.Add(10*time.Minute+grace))
		// Downloaded without the option: never due.
		kept := ev.available(ev.b, 1, false)
		ev.download(kept, t0, time.Time{})
		// Never downloaded.
		fresh := ev.available(ev.a, 1, true)

		ev.sweep(Stats{Due: 2, Deleted: 2})
		ev.assertDeleted(dueA, beforeA)
		ev.assertDeleted(dueB, beforeB)
		ev.assertIntact(pending)
		ev.assertIntact(kept)
		ev.assertIntact(fresh)
		if n := ev.f.called("scrub"); n != 1 {
			t.Fatalf("scrub called %d times, want once per sweep", n)
		}

		// Nothing more is due: nothing happens, nothing is scrubbed.
		ev.sweep(Stats{})
		if n := ev.f.called("scrub"); n != 1 {
			t.Fatalf("scrub called %d times after an empty sweep", n)
		}

		// The fake clock reaches the end of the second grace period.
		before := ev.get(pending)
		ev.clock.set(t0.Add(10*time.Minute + grace))
		ev.sweep(Stats{Due: 1, Deleted: 1})
		ev.assertDeleted(pending, before)
		ev.assertIntact(kept)
		ev.assertIntact(fresh)
		if ev.logs.count("deletion sweep done") != 2 {
			t.Fatalf("summary lines:\n%s", ev.logs.all())
		}
	})
}

func TestSweepResumesAfterFailure(t *testing.T) {
	cases := []struct {
		name  string
		fault string
		// keysGone tells whether the file keys are destroyed after the
		// failed sweep.
		keysGone bool
	}{
		{"read transfer", "transfer", false},
		{"lock files", "lock", false},
		{"remove files", "remove", false},
		{"file left on disk", "removeAfter", true},
		{"remove state", "state", true},
		{"destroy token key", "destroy", true},
		{"final transaction", "finish", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e)
				fx := ev.due(ev.a, 2)
				before := ev.get(fx)
				ev.f.set(c.fault, 1, nil)
				ev.sweep(Stats{Due: 1, Failed: 1})
				d := ev.get(fx)
				if d.Status != store.TransferAvailable || !ev.keyExists(ev.a, d.DownloadTokenKeyID) {
					t.Fatalf("after a failed sweep: status %s, token key kept %v", d.Status, d.DownloadTokenKeyID != "")
				}
				if gone := d.Files[0].DEKKeyID == ""; gone != c.keysGone {
					t.Fatalf("file keys destroyed = %v, want %v", gone, c.keysGone)
				}
				if ev.logs.count("left for the next sweep") != 1 {
					t.Fatalf("logs:\n%s", ev.logs.all())
				}
				ev.sweep(Stats{Due: 1, Deleted: 1})
				ev.assertDeleted(fx, before)
			})
		})
	}
}

func TestSweepRefusedWhileFileKeysRemain(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.due(ev.a, 1)
		before := ev.get(fx)
		// The remover reports success without destroying anything: the
		// store refuses the deletion and the token key destruction is
		// rolled back with it.
		ev.f.set("removeNoop", 1, nil)
		ev.sweep(Stats{Due: 1, Failed: 1})
		ev.assertIntact(fx)
		if ev.logs.count("step=mark deleted") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		ev.sweep(Stats{Due: 1, Deleted: 1})
		ev.assertDeleted(fx, before)
	})
}

// runEach runs fn as a sub-test name on a fresh database of every engine.
func runEach(t *testing.T, name string, fn func(t *testing.T, e storetest.Engine)) {
	t.Helper()
	t.Run(name, func(t *testing.T) { storetest.Run(t, fn) })
}

func TestSweepSkipsTransfersNoLongerDue(t *testing.T) {
	runEach(t, "gone", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.due(ev.a, 1)
		ev.f.set("transfer", 1, store.ErrNotFound)
		ev.sweep(Stats{Due: 1, Skipped: 1})
		ev.assertIntact(fx)
	})
	runEach(t, "deleted before the read", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.due(ev.a, 1)
		ev.f.onCall("transfer", func() { ev.deleteOutside(fx) })
		ev.sweep(Stats{Due: 1, Skipped: 1})
		if ev.f.called("lock") != 0 {
			t.Fatal("files locked for a transfer no longer due")
		}
	})
	runEach(t, "deleted before the final transaction", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.due(ev.a, 1)
		ev.f.onCall("finish", func() { ev.deleteOutside(fx) })
		ev.sweep(Stats{Due: 1, Skipped: 1})
		if ev.get(fx).Status != store.TransferDeleted {
			t.Fatal("transfer not deleted")
		}
	})
	runEach(t, "gone before the final transaction", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.due(ev.a, 1)
		// Another component erases the row once the file keys are gone.
		ev.f.onCall("finish", func() {
			ctx, tokenKey := context.Background(), ev.get(fx).DownloadTokenKeyID
			ev.tx(fx.tn, func(tx *store.ScopedTx) error {
				if err := ev.vault.DestroyTx(ctx, tx, tokenKey); err != nil {
					return err
				}
				return ev.db.Transfers().DeleteTx(ctx, tx, fx.id)
			})
		})
		ev.sweep(Stats{Due: 1, Skipped: 1})
		if _, err := ev.db.Transfers().Get(context.Background(), fx.tn.ID, fx.id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get = %v, want ErrNotFound", err)
		}
	})
}

func TestSweepScrub(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.due(ev.a, 1)
		ev.f.set("scrub", 1, store.ErrScrubBusy)
		ev.sweep(Stats{Due: 1, Deleted: 1})
		if ev.logs.count("WARN lifecycle: destroyed keys may remain") != 1 {
			t.Fatalf("busy scrub not warned:\n%s", ev.logs.all())
		}
		ev.due(ev.b, 1)
		ev.f.set("scrub", 1, nil)
		ev.sweep(Stats{Due: 1, Deleted: 1})
		if ev.logs.count("ERROR lifecycle: scrub of the destroyed keys failed") != 1 {
			t.Fatalf("failed scrub not logged:\n%s", ev.logs.all())
		}
	})
}

func TestSweepPages(t *testing.T) {
	runEach(t, "progress", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.s.pageSize = 2
		for range 3 {
			ev.due(ev.a, 1)
		}
		ev.sweep(Stats{Due: 3, Deleted: 3})
		if n := ev.f.called("due"); n != 2 {
			t.Fatalf("listed %d times, want 2 (full page, then empty)", n)
		}
	})
	runEach(t, "no progress", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.s.pageSize = 2
		for range 2 {
			ev.due(ev.a, 1)
		}
		ev.f.set("lock", -1, nil)
		ev.sweep(Stats{Due: 2, Failed: 2})
		if n := ev.f.called("due"); n != 1 {
			t.Fatalf("listed %d times, want 1: a full page without progress ends the sweep", n)
		}
	})
}

func TestSweepErrors(t *testing.T) {
	runEach(t, "listing", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.f.set("due", 1, nil)
		if _, err := ev.s.Sweep(context.Background()); !errors.Is(err, errFault) {
			t.Fatalf("Sweep = %v, want the listing error", err)
		}
	})
	runEach(t, "canceled", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		first := ev.due(ev.a, 1)
		second := ev.due(ev.b, 1)
		before := ev.get(first)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ev.f.onCall("finish", cancel)
		ev.f.onCall("scrub", func() {
			if ctx.Err() == nil {
				t.Error("scrub before the cancellation")
			}
		})
		st, err := ev.s.Sweep(ctx)
		if !errors.Is(err, context.Canceled) || st.Due != 1 {
			t.Fatalf("Sweep = %+v, %v; want one transfer then context.Canceled", st, err)
		}
		// The canceled final transaction failed or committed; either way
		// the next sweep completes the work.
		if st.Deleted == 1 {
			if ev.f.called("scrub") != 1 {
				t.Fatal("deleted transfer not scrubbed after the cancellation")
			}
			ev.sweep(Stats{Due: 1, Deleted: 1})
		} else {
			ev.sweep(Stats{Due: 2, Deleted: 2})
		}
		ev.assertDeleted(first, before)
		if ev.get(second).Status != store.TransferDeleted {
			t.Fatal("second transfer not deleted")
		}
	})
}

func TestFinishInvalidTenant(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	r := storeRepo{db: ev.db, vault: ev.vault}
	if err := r.finish(context.Background(), tenant.ID("bad"), "trf_x", t0); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("finish = %v, want ErrInvalid", err)
	}
}

// TestSweepOpenFile holds a stored file open, as a download stream would.
// Where an open file cannot be removed (Windows without shared delete
// access), the transfer stays due with its file keys destroyed and the next
// sweep completes it once the file is closed; elsewhere it is removed at
// once and the open handle may keep reading the unlinked ciphertext.
func TestSweepOpenFile(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.due(ev.a, 1)
		before := ev.get(fx)
		f, _, err := ev.files.OpenRead(ev.a.ID, before.Files[0].StorageName)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		st, err := ev.s.Sweep(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		switch st {
		case Stats{Due: 1, Deleted: 1}:
			_, rerr := f.ReadAt(make([]byte, 8), 0)
			t.Logf("open file removed at once (%s); reading it afterwards: %v", runtime.GOOS, rerr)
		case Stats{Due: 1, Failed: 1}:
			d := ev.get(fx)
			if d.Status != store.TransferAvailable || d.Files[0].DEKKeyID != "" {
				t.Fatalf("status %s, file key kept %v; want available with the key destroyed",
					d.Status, d.Files[0].DEKKeyID != "")
			}
			if ev.logs.count("step=remove files") != 1 {
				t.Fatalf("logs:\n%s", ev.logs.all())
			}
			_ = f.Close()
			ev.sweep(Stats{Due: 1, Deleted: 1})
		default:
			t.Fatalf("Sweep stats = %+v\nlogs:\n%s", st, ev.logs.all())
		}
		ev.assertDeleted(fx, before)
	})
}

func TestStartClose(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ft := newFakeTicker()
		ev.s.newTicker = ft.new
		results := make(chan sweepResult, 4)
		ev.s.afterSweep = func(st Stats, err error) { results <- sweepResult{st, err} }
		next := func() sweepResult {
			t.Helper()
			select {
			case r := <-results:
				return r
			case <-time.After(waitFor):
				t.Fatalf("no sweep\nlogs:\n%s", ev.logs.all())
				return sweepResult{}
			}
		}
		ev.clock.set(t0)
		fx := ev.due(ev.a, 1)
		before := ev.get(fx)

		if err := ev.s.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		if err := ev.s.Start(context.Background()); !errors.Is(err, ErrStarted) {
			t.Fatalf("second Start = %v, want ErrStarted", err)
		}
		// The first sweep runs at once; the transfer is not due yet.
		if r := next(); r.err != nil || r.st != (Stats{}) {
			t.Fatalf("first sweep = %+v", r)
		}
		if ft.period != DefaultInterval {
			t.Fatalf("ticker period %v, want %v", ft.period, DefaultInterval)
		}
		// The fake clock passes the grace period; the next tick deletes it.
		ev.clock.set(t0.Add(grace))
		ft.c <- t0.Add(grace)
		if r := next(); r.err != nil || r.st != (Stats{Due: 1, Deleted: 1}) {
			t.Fatalf("second sweep = %+v", r)
		}
		ev.assertDeleted(fx, before)
		// A listing failure is logged and the loop goes on.
		ev.f.set("due", 1, nil)
		ft.c <- t0.Add(grace + time.Minute)
		if r := next(); !errors.Is(r.err, errFault) {
			t.Fatalf("third sweep = %+v", r)
		}
		if ev.logs.count("ERROR lifecycle: sweep failed") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}

		if err := ev.s.Close(context.Background()); err != nil {
			t.Fatalf("Close: %v", err)
		}
		select {
		case <-ft.stopped:
		case <-time.After(waitFor):
			t.Fatal("ticker not stopped")
		}
		if err := ev.s.Close(context.Background()); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if err := ev.s.Start(context.Background()); !errors.Is(err, ErrClosed) {
			t.Fatalf("Start after Close = %v, want ErrClosed", err)
		}
	})
}

func TestCloseTimeout(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.s.newTicker = newFakeTicker().new
	entered, release := make(chan struct{}), make(chan struct{})
	ev.f.onCall("due", func() {
		close(entered)
		<-release
	})
	if err := ev.s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ev.s.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close = %v, want context.Canceled while a sweep runs", err)
	}
	close(release)
	if err := ev.s.Close(context.Background()); err != nil {
		t.Fatalf("Close after the sweep: %v", err)
	}
	if ev.logs.count("sweep failed") != 0 {
		t.Fatalf("a sweep interrupted by Close was logged as failed:\n%s", ev.logs.all())
	}
}

func TestStartStopsWithContext(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ft := newFakeTicker()
	ev.s.newTicker = ft.new
	ctx, cancel := context.WithCancel(context.Background())
	if err := ev.s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-ft.stopped:
	case <-time.After(waitFor):
		t.Fatal("loop not stopped by its context")
	}
}

func TestRealTicker(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.s.interval = 5 * time.Millisecond
	sweeps := make(chan struct{}, 8)
	ev.s.afterSweep = func(Stats, error) {
		select {
		case sweeps <- struct{}{}:
		default:
		}
	}
	if err := ev.s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		select {
		case <-sweeps:
		case <-time.After(waitFor):
			t.Fatal("the real ticker does not drive the sweeps")
		}
	}
}

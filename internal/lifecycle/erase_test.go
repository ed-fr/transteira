package lifecycle

import (
	"context"
	"crypto/sha256"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// week is the expiry (7 days) of the fixtures made available, or
// finalized, at t0 - 1h.
var week = t0.Add(7*24*time.Hour - time.Hour)

// stuckAt is when a fixture finalized at t0 - 1h and still scanning becomes
// due (store.ScanningMaxAge).
var stuckAt = t0.Add(store.ScanningMaxAge - time.Hour)

func TestDueRules(t *testing.T) {
	t.Parallel()
	now := t0
	past, future := now.Add(-time.Second), now.Add(time.Second)
	avail := func(deleteAfter, expires time.Time) store.Transfer {
		return store.Transfer{Status: store.TransferAvailable, DeleteAfter: deleteAfter, ExpiresAt: expires}
	}
	age := 30 * 24 * time.Hour
	scanning := func(finalized time.Time) store.Transfer {
		// The provisional expiry is long past: it is never enforced.
		return store.Transfer{Status: store.TransferScanning, FinalizedAt: finalized, ExpiresAt: past.Add(-time.Hour)}
	}
	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"deletion past", dueDeletion(avail(past, time.Time{}), now), true},
		{"deletion exactly now", dueDeletion(avail(now, time.Time{}), now), true},
		{"deletion future", dueDeletion(avail(future, time.Time{}), now), false},
		{"deletion unset", dueDeletion(avail(time.Time{}, time.Time{}), now), false},
		{"deletion of a deleted transfer", dueDeletion(store.Transfer{Status: store.TransferDeleted, DeleteAfter: past}, now), false},
		{"expiry past", dueExpiry(avail(time.Time{}, past), now, age), true},
		{"expiry now", dueExpiry(avail(time.Time{}, now), now, age), true},
		{"expiry future", dueExpiry(avail(time.Time{}, future), now, age), false},
		{"expiry unset", dueExpiry(store.Transfer{Status: store.TransferAvailable}, now, age), false},
		{"scanning past its provisional expiry", dueExpiry(scanning(now.Add(-age+time.Second)), now, age), false},
		{"scanning at the maximum age", dueExpiry(scanning(now.Add(-age)), now, age), true},
		{"scanning beyond the maximum age", dueExpiry(scanning(now.Add(-age-time.Second)), now, age), true},
		{"scanning unfinalized", dueExpiry(store.Transfer{Status: store.TransferScanning, ExpiresAt: past}, now, age), false},
		{"expiry uploading", dueExpiry(store.Transfer{Status: store.TransferUploading, ExpiresAt: past}, now, age), false},
		{"expiry expired", dueExpiry(store.Transfer{Status: store.TransferExpired, ExpiresAt: past}, now, age), false},
		{"rejected keyed", rejectedKeyed(store.TransferDetails{
			Transfer: store.Transfer{Status: store.TransferRejected}, Files: []store.TransferFile{{}, {DEKKeyID: "wk"}},
		}), true},
		{"rejected unkeyed", rejectedKeyed(store.TransferDetails{
			Transfer: store.Transfer{Status: store.TransferRejected}, Files: []store.TransferFile{{}},
		}), false},
		{"available keyed is not rejected", rejectedKeyed(store.TransferDetails{
			Transfer: store.Transfer{Status: store.TransferAvailable}, Files: []store.TransferFile{{DEKKeyID: "wk"}},
		}), false},
		{"final delete", finalDue(kindDelete, avail(past, time.Time{}), now, store.TransferAvailable, age), true},
		{"final delete not due", finalDue(kindDelete, avail(future, time.Time{}), now, store.TransferAvailable, age), false},
		{"final expire", finalDue(kindExpire, avail(time.Time{}, past), now, store.TransferAvailable, age), true},
		{"final expire stuck", finalDue(kindExpire, scanning(now.Add(-age)), now, store.TransferScanning, age), true},
		{"final expire scanning young", finalDue(kindExpire, scanning(now.Add(-age+time.Second)), now, store.TransferScanning, age), false},
		{"final expire made available meanwhile", finalDue(kindExpire, avail(time.Time{}, future), now, store.TransferScanning, age), true},
		{"final expire not due", finalDue(kindExpire, avail(time.Time{}, future), now, store.TransferAvailable, age), false},
		{"final expire deleted meanwhile", finalDue(kindExpire, store.Transfer{Status: store.TransferDeleted}, now, store.TransferScanning, age), false},
		{"final abandoned", finalDue(kindAbandoned, store.Transfer{Status: store.TransferUploading}, now, store.TransferUploading, age), true},
		{"final abandoned finalized", finalDue(kindAbandoned, store.Transfer{Status: store.TransferScanning}, now, store.TransferUploading, age), false},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
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

		ev.sweep(stats{due: 2, erased: 2})
		ev.assertDeleted(dueA, beforeA)
		ev.assertDeleted(dueB, beforeB)
		ev.assertIntact(pending)
		ev.assertIntact(kept)
		ev.assertIntact(fresh)
		if n := ev.f.called("scrub"); n != 1 {
			t.Fatalf("scrub called %d times, want once per sweep", n)
		}
		if got := ev.s.LastRun(TaskDeleteAfterDownload); !got.Equal(ev.clock.Now()) {
			t.Fatalf("LastRun = %v", got)
		}

		// Nothing more is due: nothing happens, nothing is scrubbed.
		ev.sweep(stats{})
		if n := ev.f.called("scrub"); n != 1 {
			t.Fatalf("scrub called %d times after an empty sweep", n)
		}

		// The fake clock reaches the end of the second grace period.
		before := ev.get(pending)
		ev.clock.set(t0.Add(10*time.Minute + grace))
		ev.sweep(stats{due: 1, erased: 1})
		ev.assertDeleted(pending, before)
		ev.assertIntact(kept)
		ev.assertIntact(fresh)
		if ev.logs.count("erasure done task=delete-after-download") != 2 {
			t.Fatalf("summary lines:\n%s", ev.logs.all())
		}
	})
}

func TestSweepResumesAfterFailure(t *testing.T) {
	cases := []struct {
		name  string
		fault string
		// relock makes the fault hit the read under the locks.
		relock bool
		// keysGone tells whether the file keys are destroyed after the
		// failed sweep.
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
		t.Run(c.name, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e)
				fx := ev.due(ev.a, 2)
				before := ev.get(fx)
				if c.relock {
					ev.f.onCall("lock", func() { ev.f.set(c.fault, 1, nil) })
				} else {
					ev.f.set(c.fault, 1, nil)
				}
				ev.sweep(stats{due: 1, failed: 1})
				d := ev.get(fx)
				if d.Status != store.TransferAvailable || !ev.keyExists(ev.a, d.DownloadTokenKeyID) {
					t.Fatalf("after a failed sweep: status %s, token key kept %v", d.Status, d.DownloadTokenKeyID != "")
				}
				if gone := d.Files[0].DEKKeyID == ""; gone != c.keysGone {
					t.Fatalf("file keys destroyed = %v, want %v", gone, c.keysGone)
				}
				if ev.logs.count("left for the next run") != 1 {
					t.Fatalf("logs:\n%s", ev.logs.all())
				}
				if !ev.s.LastRun(TaskDeleteAfterDownload).IsZero() {
					// A run that left a transfer for the next one did not
					// succeed.
					t.Fatal("LastRun recorded after a failed erasure")
				}
				ev.sweep(stats{due: 1, erased: 1})
				ev.assertDeleted(fx, before)
				if ev.s.LastRun(TaskDeleteAfterDownload).IsZero() {
					t.Fatal("LastRun not recorded once everything was erased")
				}
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
		ev.sweep(stats{due: 1, failed: 1})
		ev.assertIntact(fx)
		if ev.logs.count("step=final transaction") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		ev.sweep(stats{due: 1, erased: 1})
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
		ev.sweep(stats{due: 1, skipped: 1})
		ev.assertIntact(fx)
	})
	runEach(t, "deleted before the read", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.due(ev.a, 1)
		ev.f.onCall("transfer", func() { ev.deleteOutside(fx) })
		ev.sweep(stats{due: 1, skipped: 1})
		if ev.f.called("lock") != 0 {
			t.Fatal("files locked for a transfer no longer due")
		}
	})
	runEach(t, "deleted before the locks", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.due(ev.a, 1)
		ev.f.onCall("lock", func() { ev.deleteOutside(fx) })
		ev.sweep(stats{due: 1, skipped: 1})
		if ev.f.called("remove") != 0 {
			t.Fatal("files removed for a transfer no longer due")
		}
	})
	runEach(t, "deleted before the final transaction", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.due(ev.a, 1)
		ev.f.onCall("finish", func() { ev.deleteOutside(fx) })
		ev.sweep(stats{due: 1, skipped: 1})
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
		ev.sweep(stats{due: 1, skipped: 1})
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
		ev.sweep(stats{due: 1, erased: 1})
		if ev.logs.count("WARN lifecycle: deleted data may remain") != 1 {
			t.Fatalf("busy scrub not warned:\n%s", ev.logs.all())
		}
		ev.due(ev.b, 1)
		ev.f.set("scrub", 1, nil)
		ev.sweep(stats{due: 1, erased: 1})
		if ev.logs.count("ERROR lifecycle: scrub of the deleted data failed") != 1 {
			t.Fatalf("failed scrub not logged:\n%s", ev.logs.all())
		}
	})
}

func TestSweepPages(t *testing.T) {
	runEach(t, "progress", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.s.pageSizes[kindDelete] = 2
		for range 3 {
			ev.due(ev.a, 1)
		}
		ev.sweep(stats{due: 3, erased: 3})
		if n := ev.f.called("due"); n != 2 {
			t.Fatalf("listed %d times, want 2 (full page, then a short one)", n)
		}
	})
	// A full page of transfers that stay listed (failing) never hides the
	// transfers after it: the cursor moves on.
	runEach(t, "failing page", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.s.pageSizes[kindDelete] = 2
		var fxs []fixture
		for i := range 3 {
			fx := ev.available(ev.a, 1, true)
			at := t0.Add(time.Duration(i) * time.Minute)
			ev.download(fx, at, at.Add(time.Minute))
			fxs = append(fxs, fx)
		}
		last := ev.get(fxs[2])
		ev.f.set("lock", 2, nil)
		ev.sweep(stats{due: 3, erased: 1, failed: 2})
		ev.assertDeleted(fxs[2], last)
		if n := ev.f.called("due"); n != 2 {
			t.Fatalf("listed %d times, want 2", n)
		}
		ev.sweep(stats{due: 2, erased: 2})
	})
	runEach(t, "failing page of expirations", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.s.pageSizes[kindExpire] = 1
		first := ev.available(ev.a, 1, false)
		second := ev.available(ev.b, 1, false)
		rej := ev.rejected(ev.a, 1)
		before, rejBefore := ev.get(second), ev.get(rej)
		ev.clock.set(week)
		// The first page holds one of the two expired transfers; whichever
		// it is, it fails, and the next pages are still reached.
		ev.f.set("lock", 1, nil)
		ev.sweepKind(kindExpire, stats{due: 3, erased: 2, failed: 1})
		ev.assertErased(rej, rejBefore, store.TransferRejected)
		erasedOne := ev.get(first).Status == store.TransferExpired
		if erasedOne == (ev.get(second).Status == store.TransferExpired) {
			t.Fatalf("want exactly one expired transfer erased: %s, %s", ev.get(first).Status, ev.get(second).Status)
		}
		if n := ev.f.called("dueExpirations") + ev.f.called("rejectedKeyed"); n != 5 {
			t.Fatalf("listed %d times, want 5 (3 + 2 pages of one)", n)
		}
		ev.sweepKind(kindExpire, stats{due: 1, erased: 1})
		ev.assertErased(second, before, store.TransferExpired)
	})
	// Candidates found not due (active uploads) fill the first page: the
	// abandoned upload after them is still reached.
	runEach(t, "page of active uploads", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.s.pageSizes[kindAbandoned] = 2
		ev.uploading(ev.a, 0, 1, t0.Add(-50*time.Hour), t0.Add(-time.Hour))
		ev.uploading(ev.b, 0, 1, t0.Add(-49*time.Hour), t0.Add(-time.Hour))
		idle := ev.uploading(ev.a, 0, 1, t0.Add(-48*time.Hour), t0.Add(-25*time.Hour))
		before := ev.get(idle)
		ev.clock.set(t0)
		ev.sweepKind(kindAbandoned, stats{due: 3, erased: 1, skipped: 2})
		ev.assertErased(idle, before, store.TransferExpired)
	})
}

func TestSweepErrors(t *testing.T) {
	for _, c := range []struct {
		k     kind
		fault string
	}{{kindDelete, "due"}, {kindExpire, "dueExpirations"}, {kindAbandoned, "abandoned"}} {
		runEach(t, "listing "+string(c.k.task()), func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e)
			ev.f.set(c.fault, 1, nil)
			if err := ev.s.RunTask(context.Background(), c.k.task()); !errors.Is(err, errFault) {
				t.Fatalf("RunTask = %v, want the listing error", err)
			}
			if !ev.s.LastRun(c.k.task()).IsZero() {
				t.Fatal("LastRun recorded after a failure")
			}
		})
	}
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
		st, err := ev.runSweep(ctx, kindDelete)
		if !errors.Is(err, context.Canceled) || st.due != 1 {
			t.Fatalf("sweep = %+v, %v; want one transfer then context.Canceled", st, err)
		}
		// The canceled final transaction failed or committed; either way
		// the next sweep completes the work.
		if st.erased == 1 {
			if ev.f.called("scrub") != 1 {
				t.Fatal("deleted transfer not scrubbed after the cancellation")
			}
			ev.sweep(stats{due: 1, erased: 1})
		} else {
			ev.sweep(stats{due: 2, erased: 2})
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
	due := func(store.Transfer) bool { return true }
	if err := r.finish(context.Background(), kindDelete, tenant.ID("bad"), "trf_x", t0, due); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("finish = %v, want ErrInvalid", err)
	}
	if err := r.deleteEnded(context.Background(), tenant.ID("bad"), "trf_x"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("deleteEnded = %v, want ErrInvalid", err)
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
		st, err := ev.runSweep(context.Background(), kindDelete)
		if err != nil && st.failed == 0 {
			t.Fatal(err)
		}
		switch st {
		case stats{due: 1, erased: 1}:
			_, rerr := f.ReadAt(make([]byte, 8), 0)
			t.Logf("open file removed at once (%s); reading it afterwards: %v", runtime.GOOS, rerr)
		case stats{due: 1, failed: 1}:
			d := ev.get(fx)
			if d.Status != store.TransferAvailable || d.Files[0].DEKKeyID != "" {
				t.Fatalf("status %s, file key kept %v; want available with the key destroyed",
					d.Status, d.Files[0].DEKKeyID != "")
			}
			if ev.logs.count("step=remove files") != 1 {
				t.Fatalf("logs:\n%s", ev.logs.all())
			}
			_ = f.Close()
			ev.sweep(stats{due: 1, erased: 1})
		default:
			t.Fatalf("Sweep stats = %+v\nlogs:\n%s", st, ev.logs.all())
		}
		ev.assertDeleted(fx, before)
	})
}

func TestExpire(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		// Available at t0 - 1h for 7 days, with a download state.
		availA := ev.available(ev.a, 2, false)
		if err := ev.files.WriteState(ev.a.ID, storage.StateName(availA.id), []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		availB := ev.available(ev.b, 1, true)
		// Still scanning since t0 - 1h: its provisional expiry (7 days) is
		// never enforced; it is erased store.ScanningMaxAge after its
		// finalization (a stuck analysis).
		stuck := ev.scanning(ev.a, 1, t0.Add(-time.Hour))
		// Rejected, with a file kept with its key (scan_error).
		rej := ev.rejected(ev.b, 2)
		rejEnded := ev.get(rej).EndedAt
		// Finalized later: not stuck yet when the first one is.
		later := ev.scanning(ev.a, 1, t0)
		laterBefore := ev.get(later)
		// Uploading transfers never expire here.
		upl := ev.uploading(ev.a, 1, 0, t0.Add(-time.Hour), time.Time{})
		befores := map[string]store.TransferDetails{}
		for _, fx := range []fixture{availA, availB, stuck, rej} {
			befores[fx.id] = ev.get(fx)
		}
		if ev.usedBytes(ev.a) == 0 || ev.usedBytes(ev.b) == 0 {
			t.Fatal("no quota used before the expiry")
		}

		// The rejected transfer is erased at once, whatever its age.
		ev.runTask(TaskExpire)
		ev.assertErased(rej, befores[rej.id], store.TransferRejected)
		if got := ev.get(rej).EndedAt; !got.Equal(rejEnded) {
			t.Fatalf("EndedAt of the rejected transfer changed: %v, want %v", got, rejEnded)
		}
		ev.assertIntact(availA)

		// A week later: the available transfers expire; the scanning ones,
		// past their provisional expiry, are untouched.
		ev.clock.set(week)
		ev.sweepKind(kindExpire, stats{due: 2, erased: 2})
		ev.assertErased(availA, befores[availA.id], store.TransferExpired)
		ev.assertErased(availB, befores[availB.id], store.TransferExpired)
		if got := ev.get(availA).EndedAt; !got.Equal(week) {
			t.Fatalf("EndedAt = %v, want %v", got, week)
		}
		scanningIntact := func(fx fixture, before store.TransferDetails) {
			t.Helper()
			if d := ev.get(fx); d.Status != store.TransferScanning || d.Files[0].DEKKeyID != before.Files[0].DEKKeyID {
				t.Fatalf("a scanning transfer not stuck yet was touched: %s", d.Status)
			}
		}
		scanningIntact(stuck, befores[stuck.id])
		scanningIntact(later, laterBefore)

		// Just before the maximum age: still untouched.
		ev.clock.set(stuckAt.Add(-time.Millisecond))
		ev.sweepKind(kindExpire, stats{})
		scanningIntact(stuck, befores[stuck.id])
		if ev.logs.count("still scanning") != 0 {
			t.Fatalf("stuck warning before the maximum age:\n%s", ev.logs.all())
		}

		// At the maximum age: the stuck transfer is erased, with a warning.
		ev.clock.set(stuckAt)
		ev.sweepKind(kindExpire, stats{due: 1, erased: 1})
		ev.assertErased(stuck, befores[stuck.id], store.TransferExpired)
		scanningIntact(later, laterBefore)
		want := "WARN lifecycle: transfer expired while still scanning (stuck analysis) tenant=" + string(ev.a.ID) +
			" transfer=" + stuck.id + " finalized_age=" + store.ScanningMaxAge.String()
		if ev.logs.count(want) != 1 {
			t.Fatalf("stuck warning missing (%q):\n%s", want, ev.logs.all())
		}
		if d := ev.get(upl); d.Status != store.TransferUploading || d.Files[0].DEKKeyID == "" {
			t.Fatalf("an uploading transfer was touched: %s", d.Status)
		}
		// Only the quota of the transfers still open remains.
		if got, want := ev.usedBytes(ev.b), int64(0); got != want {
			t.Fatalf("quota of B = %d, want %d", got, want)
		}
		if got, want := ev.usedBytes(ev.a), laterBefore.TotalBytes+ev.get(upl).TotalBytes; got != want {
			t.Fatalf("quota of A = %d, want %d", got, want)
		}
		ev.sweepKind(kindExpire, stats{})
	})
}

// TestExpireScanningMaxAgeOption checks the override of
// store.ScanningMaxAge.
func TestExpireScanningMaxAgeOption(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.s = ev.newSweeper(Options{ScanningMaxAge: 2 * time.Hour})
		stuck := ev.scanning(ev.a, 1, t0.Add(-time.Hour))
		before := ev.get(stuck)
		ev.clock.set(t0.Add(time.Hour - time.Millisecond))
		ev.sweepKind(kindExpire, stats{})
		ev.clock.set(t0.Add(time.Hour))
		ev.sweepKind(kindExpire, stats{due: 1, erased: 1})
		ev.assertErased(stuck, before, store.TransferExpired)
	})
}

// TestExpireMadeAvailableMeanwhile: the antivirus concludes a stuck
// transfer after its files were erased; it is expired anyway.
func TestExpireMadeAvailableMeanwhile(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		stuck := ev.scanning(ev.a, 1, t0.Add(-time.Hour))
		before := ev.get(stuck)
		ev.clock.set(stuckAt)
		ev.f.onCall("finish", func() {
			ctx := context.Background()
			token, err := id.NewDownloadToken()
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256([]byte(token))
			ev.tx(ev.a, func(tx *store.ScopedTx) error {
				wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
				if err != nil {
					return err
				}
				return ev.db.Transfers().MarkAvailableTx(ctx, tx, stuck.id, hash[:], wk, stuckAt)
			})
			stuck.tokenHash = hash[:]
			before.DownloadTokenKeyID = ev.get(stuck).DownloadTokenKeyID
		})
		ev.sweepKind(kindExpire, stats{due: 1, erased: 1})
		ev.assertErased(stuck, before, store.TransferExpired)
	})
}

func TestAbandonedUploads(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		created := t0.Add(-48 * time.Hour)
		// Created two days ago, last checkpoint 25 hours ago: expired (TTL
		// 24 h of the default upload options).
		idle := ev.uploading(ev.a, 1, 2, created, t0.Add(-25*time.Hour))
		// Same age, but a checkpoint written an hour ago: active.
		active := ev.uploading(ev.b, 1, 1, created, t0.Add(-time.Hour))
		// Young: below the candidate age.
		young := ev.uploading(ev.a, 0, 1, t0, t0)
		ev.s.uploadTTL = time.Hour
		ev.clock.set(t0)
		before := ev.get(idle)
		usedA := ev.usedBytes(ev.a)

		ev.sweepKind(kindAbandoned, stats{due: 2, erased: 1, skipped: 1})
		ev.assertErased(idle, before, store.TransferExpired)
		if got := ev.usedBytes(ev.a); got != usedA-before.TotalBytes {
			t.Fatalf("quota of A = %d, want %d", got, usedA-before.TotalBytes)
		}
		for _, fx := range []fixture{active, young} {
			if d := ev.get(fx); d.Status != store.TransferUploading || d.Files[0].DEKKeyID == "" {
				t.Fatalf("active upload touched: %s", d.Status)
			}
		}
	})
}

func TestAbandonedUploadsChangedMeanwhile(t *testing.T) {
	finalize := func(ev *env, fx fixture) {
		ev.tx(fx.tn, func(tx *store.ScopedTx) error {
			return ev.db.Transfers().FinalizeTx(context.Background(), tx, fx.id, t0)
		})
	}
	runEach(t, "activity failure", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.uploading(ev.a, 1, 0, t0.Add(-48*time.Hour), time.Time{})
		ev.f.set("activity", 1, nil)
		ev.sweepKind(kindAbandoned, stats{due: 1, failed: 1})
		if ev.logs.count("step=upload activity") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		ev.sweepKind(kindAbandoned, stats{due: 1, erased: 1})
	})
	runEach(t, "finalized before the locks", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.uploading(ev.a, 1, 0, t0.Add(-48*time.Hour), time.Time{})
		ev.f.onCall("lock", func() { finalize(ev, fx) })
		ev.sweepKind(kindAbandoned, stats{due: 1, skipped: 1})
		if d := ev.get(fx); d.Status != store.TransferScanning || d.Files[0].DEKKeyID == "" {
			t.Fatalf("finalized transfer touched: %s", d.Status)
		}
	})
	runEach(t, "finalized before the final transaction", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.uploading(ev.a, 1, 0, t0.Add(-48*time.Hour), time.Time{})
		ev.f.onCall("finish", func() { finalize(ev, fx) })
		ev.sweepKind(kindAbandoned, stats{due: 1, skipped: 1})
		if d := ev.get(fx); d.Status != store.TransferScanning {
			t.Fatalf("status %s, want scanning", d.Status)
		}
	})
}

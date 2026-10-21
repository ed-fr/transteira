package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/upload"
)

// orphanSet is the content of a tenant directory built by orphanFixture.
type orphanSet struct {
	kept, removed []string
}

// orphanFixture fills the directory of tn with one entry per rule, old
// (past the grace period) unless said otherwise.
func (ev *env) orphanFixture(tn *tenant.Tenant) orphanSet {
	ev.t.Helper()
	ctx := context.Background()
	old := ev.clock.Now().Add(-OrphanGrace - time.Minute)
	fresh := ev.clock.Now().Add(-OrphanGrace + time.Minute)
	var set orphanSet
	keep := func(file string, mod time.Time) {
		ev.touch(tn, file, mod)
		set.kept = append(set.kept, file)
	}
	drop := func(file string, mod time.Time) {
		ev.touch(tn, file, mod)
		set.removed = append(set.removed, file)
	}
	write := func(file string, mod time.Time, kept bool) {
		ev.write(tn, file, mod)
		if kept {
			set.kept = append(set.kept, file)
		} else {
			set.removed = append(set.removed, file)
		}
	}
	// An available transfer: its files and its state are kept.
	avail := ev.available(tn, 1, false)
	ad := ev.get(avail)
	keep(ad.Files[0].StorageName+".ttef", old)
	write(storage.StateName(avail.id)+".dlstate", old, true)
	// A file whose key was destroyed (failed removal): removed.
	gone := ev.available(tn, 1, false)
	gd := ev.get(gone)
	ev.tx(tn, func(tx *store.ScopedTx) error { return ev.vault.DestroyTx(ctx, tx, gd.Files[0].DEKKeyID) })
	drop(gd.Files[0].StorageName+".ttef", old)
	// An upload: the checkpoint of its incomplete file is kept, the one of
	// its completed file removed.
	upl := ev.uploading(tn, 1, 1, old, old)
	ud := ev.get(upl)
	keep(ud.Files[0].StorageName+".ttef", old)
	write(ud.Files[0].StorageName+".ckpt", old, false)
	keep(ud.Files[1].StorageName+".ckpt", old)
	// A checkpoint of a finalized transfer: removed.
	scan := ev.scanning(tn, 1, old)
	write(ev.get(scan).Files[0].StorageName+".ckpt", old, false)
	// No row: removed when old, kept when fresh.
	write(storage.NewName()+".ttef", old, false)
	write(storage.NewName()+".ckpt", old, false)
	write(storage.NewName()+".dlstate", old, false)
	write(storage.NewName()+".ckpt.0123456789abcdef.tmp", old, false)
	write(storage.NewName()+".ttef", fresh, true)
	write(storage.NewName()+".dlstate", fresh, true)
	// Unknown entries: never removed.
	write("notes.txt", old, true)
	if err := os.Mkdir(ev.path(tn, storage.NewName()+".ttef"), 0o700); err != nil {
		ev.t.Fatal(err)
	}
	return set
}

// check asserts the content of the directory of tn.
func (ev *env) checkOrphans(tn *tenant.Tenant, set orphanSet) {
	ev.t.Helper()
	for _, f := range set.kept {
		if !ev.exists(tn, f) {
			ev.t.Errorf("%s removed", f)
		}
	}
	for _, f := range set.removed {
		if ev.exists(tn, f) {
			ev.t.Errorf("%s kept", f)
		}
	}
}

func TestOrphans(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		setA := ev.orphanFixture(ev.a)
		setB := ev.orphanFixture(ev.b)
		// A directory without tenant row: left in place.
		stray := tenant.ID(id.New(id.Tenant))
		strayFile := filepath.Join(ev.root, string(stray), storage.NewName()+".ttef")
		if err := os.MkdirAll(filepath.Dir(strayFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(strayFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		old := ev.clock.Now().Add(-48 * time.Hour)
		if err := os.Chtimes(strayFile, old, old); err != nil {
			t.Fatal(err)
		}

		ev.runTask(TaskOrphans)
		ev.checkOrphans(ev.a, setA)
		ev.checkOrphans(ev.b, setB)
		if _, err := os.Stat(strayFile); err != nil {
			t.Fatalf("file of an unknown tenant removed: %v", err)
		}
		for _, want := range []string{
			"lifecycle: directory of an unknown tenant left in place tenant=" + string(stray),
			"lifecycle: unknown entries left in a tenant directory tenant=" + string(ev.a.ID) + " count=2",
			"lifecycle: orphan files removed data=4 checkpoints=6 states=2 temps=2 unknown=4",
		} {
			if ev.logs.count(want) != 1 {
				t.Fatalf("missing %q:\n%s", want, ev.logs.all())
			}
		}
		// Idempotent.
		ev.runTask(TaskOrphans)
		ev.checkOrphans(ev.a, setA)
	})
}

func TestOrphansRecheckUnderLock(t *testing.T) {
	runEach(t, "keyed after all", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.available(ev.a, 1, false)
		name := ev.get(fx).Files[0].StorageName
		ev.touch(ev.a, name+".ttef", ev.clock.Now().Add(-48*time.Hour))
		// A stale listing says the key is gone; the read under the lock
		// says otherwise.
		ev.repo.refsHook = func(refs map[string]store.StorageRef) {
			r := refs[name]
			r.Keyed = false
			refs[name] = r
		}
		ev.runTask(TaskOrphans)
		ev.assertIntact(fx)
	})
	runEach(t, "row gone", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		fx := ev.available(ev.a, 1, false)
		d := ev.get(fx)
		ev.deleteOutside(fx)
		name := d.Files[0].StorageName
		ev.write(ev.a, name+".ttef", ev.clock.Now().Add(-48*time.Hour))
		ev.f.set("transfer", 1, store.ErrNotFound)
		ev.runTask(TaskOrphans)
		if ev.exists(ev.a, name+".ttef") {
			t.Fatal("orphan of a deleted row kept")
		}
	})
}

func TestOrphansFailures(t *testing.T) {
	setup := func(t *testing.T, e storetest.Engine) (*env, string) {
		t.Helper()
		ev := newEnv(t, e)
		fx := ev.available(ev.a, 1, false)
		d := ev.get(fx)
		ev.tx(ev.a, func(tx *store.ScopedTx) error {
			return ev.vault.DestroyTx(context.Background(), tx, d.Files[0].DEKKeyID)
		})
		file := d.Files[0].StorageName + ".ttef"
		ev.touch(ev.a, file, ev.clock.Now().Add(-48*time.Hour))
		return ev, file
	}
	for _, c := range []struct {
		fault string
		err   error
		// skipped tells a tenant skipped without error.
		skipped bool
	}{
		{"tenantDirs", nil, false},
		{"tenantIDs", nil, false},
		{"list", nil, false},
		{"storageRefs", nil, false},
		{"storageRefs", store.ErrTooManyRows, true},
		{"availableIDs", nil, false},
		{"availableIDs", store.ErrTooManyRows, true},
		{"lock", upload.ErrBusy, false},
		{"transfer", nil, false},
		{"removeData", nil, false},
	} {
		name := c.fault
		if c.err != nil {
			name += " " + c.err.Error()
		}
		runEach(t, name, func(t *testing.T, e storetest.Engine) {
			ev, file := setup(t, e)
			ev.f.set(c.fault, 1, c.err)
			err := ev.s.RunTask(context.Background(), TaskOrphans)
			if c.skipped {
				if err != nil || ev.logs.count("tenant skipped by the orphan removal: too many rows") != 1 {
					t.Fatalf("RunTask = %v\nlogs:\n%s", err, ev.logs.all())
				}
			} else if want := c.err; (want == nil && !errors.Is(err, errFault)) || (want != nil && !errors.Is(err, want)) {
				t.Fatalf("RunTask = %v", err)
			}
			if !ev.exists(ev.a, file) {
				t.Fatal("orphan removed despite the failure")
			}
			ev.runTask(TaskOrphans)
			if ev.exists(ev.a, file) {
				t.Fatal("orphan kept by the next run")
			}
		})
	}
	for _, c := range []struct{ fault, file string }{
		{"removeCheckpoint", ".ckpt"}, {"state", ".dlstate"}, {"removeTemp", ".ckpt.0123456789abcdef.tmp"},
	} {
		runEach(t, c.fault, func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e)
			file := storage.NewName() + c.file
			ev.write(ev.a, file, ev.clock.Now().Add(-48*time.Hour))
			ev.f.set(c.fault, 1, nil)
			if err := ev.s.RunTask(context.Background(), TaskOrphans); !errors.Is(err, errFault) {
				t.Fatalf("RunTask = %v", err)
			}
			ev.runTask(TaskOrphans)
			if ev.exists(ev.a, file) {
				t.Fatal("orphan kept by the next run")
			}
		})
	}
	runEach(t, "canceled in a directory", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		for range 2 {
			ev.write(ev.a, storage.NewName()+".ckpt.0123456789abcdef.tmp", ev.clock.Now().Add(-48*time.Hour))
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ev.f.onCall("removeTemp", cancel)
		if err := ev.s.RunTask(ctx, TaskOrphans); !errors.Is(err, context.Canceled) {
			t.Fatalf("RunTask = %v", err)
		}
		if n := ev.f.called("removeTemp"); n != 1 {
			t.Fatalf("%d removals, want 1", n)
		}
	})
	runEach(t, "canceled between tenants", func(t *testing.T, e storetest.Engine) {
		ev, _ := setup(t, e)
		ev.write(ev.b, storage.NewName()+".ttef", ev.clock.Now().Add(-48*time.Hour))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ev.f.onCall("list", cancel)
		if err := ev.s.RunTask(ctx, TaskOrphans); !errors.Is(err, context.Canceled) {
			t.Fatalf("RunTask = %v", err)
		}
		if n := ev.f.called("list"); n != 1 {
			t.Fatalf("%d directories listed, want 1", n)
		}
		if ev.logs.count("orphan removal incomplete") != 0 {
			t.Fatalf("a canceled run was logged as failed:\n%s", ev.logs.all())
		}
	})
}

package lifecycle

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// ended stores a transfer of tn deleted at the current time of the clock.
func (ev *env) ended(tn *tenant.Tenant) fixture {
	ev.t.Helper()
	fx := ev.available(tn, 1, false)
	ev.deleteOutside(fx)
	return fx
}

// challenge stores a challenge of tn created at createdAt, expired 15
// minutes later, and returns its ID.
func (ev *env) challenge(tn *tenant.Tenant, createdAt time.Time) string {
	ev.t.Helper()
	tok, err := id.NewToken(id.ChallengeTokenPrefix, 16)
	if err != nil {
		ev.t.Fatal(err)
	}
	err = ev.db.Challenges().Create(context.Background(), tn.ID, store.Challenge{
		ID: tok, Email: alice, CodeMAC: []byte{1}, AttemptsRemaining: 2, ClientIP: netip.MustParseAddr("192.0.2.1"),
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(15 * time.Minute),
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return tok
}

// challengeExists reports whether the challenge chID of tn exists.
func (ev *env) challengeExists(tn *tenant.Tenant, chID string) bool {
	ev.t.Helper()
	_, err := ev.db.Challenges().Get(context.Background(), tn.ID, chID)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		ev.t.Fatal(err)
	}
	return true
}

// gone reports whether the row of fx was deleted.
func (ev *env) gone(fx fixture) bool {
	ev.t.Helper()
	_, err := ev.db.Transfers().Get(context.Background(), fx.tn.ID, fx.id)
	if errors.Is(err, store.ErrNotFound) {
		return true
	}
	if err != nil {
		ev.t.Fatal(err)
	}
	return false
}

func TestPurgeRows(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		start := ev.clock.Now()
		oldA := ev.ended(ev.a)
		oldB := ev.ended(ev.b)
		// A rejected transfer still holding a file key: refused until the
		// expiry task erased it.
		rej := ev.rejected(ev.a, 1)
		ev.clock.set(start.Add(time.Hour))
		recentA := ev.ended(ev.a)
		// A challenge consumed long ago, and a live one.
		ch := ev.challenge(ev.a, start.Add(-2*time.Hour))

		// One second before the retention of the old ones ends: nothing.
		ev.clock.set(start.Add(EndedRetention - time.Second))
		ev.runTask(TaskPurgeRows)
		for _, fx := range []fixture{oldA, oldB, rej, recentA} {
			if ev.gone(fx) {
				t.Fatalf("transfer %s purged before its retention", fx.id)
			}
		}
		if ev.challengeExists(ev.a, ch) {
			t.Fatal("stale challenge kept")
		}
		if ev.logs.count("rows purged transfers=0 challenges=1") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}

		ev.clock.set(start.Add(EndedRetention))
		ev.runTask(TaskPurgeRows)
		if !ev.gone(oldA) || !ev.gone(oldB) || ev.gone(recentA) || ev.gone(rej) {
			t.Fatalf("purge at the retention: %v %v %v %v", ev.gone(oldA), ev.gone(oldB), ev.gone(recentA), ev.gone(rej))
		}
		if ev.logs.count("rows purged transfers=2 challenges=0 sessions=0 password_failures=0 verified_addresses=0 invitations=0") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		// The token hash no longer resolves: the link answers 404.
		if _, err := ev.db.Transfers().GetByDownloadTokenHash(ctx, oldA.tn.ID, oldA.tokenHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("token lookup = %v, want ErrNotFound", err)
		}
		ev.runTask(TaskExpire)
		ev.runTask(TaskPurgeRows)
		if !ev.gone(rej) {
			t.Fatal("rejected transfer kept once erased")
		}
		scrubs := ev.f.called("scrub")
		ev.runTask(TaskPurgeRows)
		if ev.f.called("scrub") != scrubs {
			t.Fatal("scrub after a purge that deleted nothing")
		}
	})
}

func TestPurgeEndedPages(t *testing.T) {
	runEach(t, "progress", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.s.purgeBatch = 2
		for range 3 {
			ev.ended(ev.a)
		}
		ev.clock.set(ev.clock.Now().Add(EndedRetention))
		n, err := ev.s.purgeEnded(context.Background(), ev.a.ID, ev.clock.Now())
		if err != nil || n != 3 || ev.f.called("listEnded") != 2 {
			t.Fatalf("purgeEnded = %d, %v after %d listings", n, err, ev.f.called("listEnded"))
		}
	})
	runEach(t, "no progress", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.s.purgeBatch = 2
		ev.rejected(ev.a, 1)
		ev.rejected(ev.a, 1)
		ev.clock.set(ev.clock.Now().Add(time.Second))
		ev.ended(ev.a)
		ev.clock.set(ev.clock.Now().Add(EndedRetention))
		// The two oldest are refused (keys remain): a full page without
		// progress ends the purge.
		ev.f.set("deleteEnded", 1, store.ErrNotFound)
		n, err := ev.s.purgeEnded(context.Background(), ev.a.ID, ev.clock.Now())
		if err != nil || n != 0 || ev.f.called("listEnded") != 1 {
			t.Fatalf("purgeEnded = %d, %v after %d listings", n, err, ev.f.called("listEnded"))
		}
	})
}

func TestPurgeRowsFailures(t *testing.T) {
	runEach(t, "tenants", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.f.set("tenantIDs", 1, nil)
		if err := ev.s.RunTask(context.Background(), TaskPurgeRows); !errors.Is(err, errFault) {
			t.Fatalf("RunTask = %v", err)
		}
	})
	for _, fault := range []string{"listEnded", "deleteEnded", "purge:challenges", "purge:invitations"} {
		runEach(t, fault, func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e)
			fx := ev.ended(ev.a)
			ev.clock.set(ev.clock.Now().Add(EndedRetention))
			ev.f.set(fault, 1, nil)
			if err := ev.s.RunTask(context.Background(), TaskPurgeRows); !errors.Is(err, errFault) {
				t.Fatalf("RunTask = %v", err)
			}
			if ev.logs.count("purge failed, left for the next run") != 1 {
				t.Fatalf("logs:\n%s", ev.logs.all())
			}
			// The other purges and tenants went on; the next run completes.
			ev.runTask(TaskPurgeRows)
			if !ev.gone(fx) {
				t.Fatal("ended transfer kept")
			}
		})
	}
	runEach(t, "canceled between tenants", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ev.f.onCall("purge:invitations", cancel)
		if err := ev.s.RunTask(ctx, TaskPurgeRows); !errors.Is(err, context.Canceled) {
			t.Fatalf("RunTask = %v", err)
		}
		if n := ev.f.called("listEnded"); n != 1 {
			t.Fatalf("%d tenants purged, want 1", n)
		}
	})
	runEach(t, "canceled in a page", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.ended(ev.a)
		ev.ended(ev.a)
		ev.clock.set(ev.clock.Now().Add(EndedRetention))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ev.f.onCall("deleteEnded", cancel)
		ev.f.set("deleteEnded", 1, store.ErrNotFound)
		if err := ev.s.RunTask(ctx, TaskPurgeRows); !errors.Is(err, context.Canceled) {
			t.Fatalf("RunTask = %v", err)
		}
		if ev.f.called("deleteEnded") != 1 {
			t.Fatalf("%d deletions after the cancellation", ev.f.called("deleteEnded")-1)
		}
		if ev.logs.count("purge failed") != 0 {
			t.Fatalf("a canceled purge was logged as failed:\n%s", ev.logs.all())
		}
	})
}

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
		if ev.logs.count("rows purged transfers=2 challenges=0 sessions=0 password_failures=0 sender_access=0 verified_addresses=0 invitations=0") != 1 {
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
		ev.adminRows(ev.clock.Now())
		ev.f.set("tenantIDs", 1, nil)
		if err := ev.s.RunTask(context.Background(), TaskPurgeRows); !errors.Is(err, errFault) {
			t.Fatalf("RunTask = %v", err)
		}
		// The global purges ran anyway.
		if ev.f.called("listEnded") != 0 || ev.logs.count(systemCounts) != 1 {
			t.Fatalf("after a failed tenant listing: %d tenants purged, logs:\n%s", ev.f.called("listEnded"), ev.logs.all())
		}
		if !ev.s.LastRun(TaskPurgeRows).IsZero() {
			t.Fatal("LastRun moved after a failure")
		}
	})
	for _, fault := range []string{
		"listEnded", "deleteEnded", "purge:challenges", "purge:invitations",
		"purgeSystem:admin_sessions", "purgeSystem:audit_events", "purgeSystem:usage_counters",
	} {
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

// testPHC is a well-formed argon2id hash for the test administrators.
const testPHC = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"

// adminRows stores, relative to now, one row of each global purge that is
// stale at now and one that is still live at now but stale twelve hours
// later: sessions, activation links, login failures and audit events.
func (ev *env) adminRows(now time.Time) {
	ev.t.Helper()
	ctx := context.Background()
	a, err := ev.db.Admins().Create(ctx, store.Admin{
		Username: "root" + id.New(id.AdminSession)[3:9], Email: "root@example.com", Role: store.RoleSuperAdmin, PasswordHash: testPHC,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	session := func(lastSeen time.Time) {
		ev.t.Helper()
		tok := id.New(id.AdminSession)
		err := ev.db.AdminSessions().Create(ctx, store.AdminSession{
			ID: tok, TokenHash: hash32(tok), AdminID: a.ID, State: store.SessionAuthenticated,
			CreatedAt: now.Add(-time.Hour), LastSeenAt: lastSeen, ExpiresAt: now.Add(11 * time.Hour),
		})
		if err != nil {
			ev.t.Fatal(err)
		}
	}
	session(now.Add(-DefaultAdminSessionIdleTimeout - time.Minute))
	session(now.Add(-time.Minute))
	activation := func(used bool) {
		ev.t.Helper()
		tok := id.New(id.AdminActivation)
		err := ev.db.AdminActivations().Create(ctx, store.AdminActivation{
			ID: tok, AdminID: a.ID, TokenHash: hash32(tok), CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		})
		if err != nil {
			ev.t.Fatal(err)
		}
		if used {
			if _, err := ev.db.AdminActivations().Consume(ctx, hash32(tok), now.Add(-time.Minute)); err != nil {
				ev.t.Fatal(err)
			}
		}
	}
	activation(true)
	activation(false)
	failure := func(ip string, at time.Time) {
		ev.t.Helper()
		_, err := ev.db.AdminLoginFailures().RecordFailure(ctx, []store.AdminLoginRule{{
			Key: store.AdminLoginIPKey(netip.MustParseAddr(ip)), MaxFailures: 5,
			Window: AdminLoginFailureWindow, LockDuration: AdminLoginFailureWindow,
		}}, at)
		if err != nil {
			ev.t.Fatal(err)
		}
	}
	failure("192.0.2.10", now.Add(-AdminLoginFailureWindow-time.Minute))
	failure("192.0.2.11", now.Add(-time.Minute))
	audit := func(at time.Time) {
		ev.t.Helper()
		_, err := ev.db.AuditEvents().Append(ctx, store.AuditEvent{
			At: at, ActorKind: store.ActorSystem, Actor: "lifecycle", Action: "admin.login", ObjectKind: "admin", ObjectID: "adm_1",
		})
		if err != nil {
			ev.t.Fatal(err)
		}
	}
	audit(now.AddDate(0, -AuditRetentionMonths, 0).Add(-time.Minute))
	audit(now.AddDate(0, -AuditRetentionMonths, 0).Add(time.Hour))
}

// hash32 returns a 32-byte token hash derived from s.
func hash32(s string) []byte {
	h := make([]byte, 32)
	copy(h, s)
	return h
}

// systemCounts is the log of a purge-rows run that deleted one row of
// each global kind.
const systemCounts = "admin_sessions=1 admin_activations=1 admin_login_failures=1 audit_events=1"

func TestPurgeRowsSystem(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		now := ev.clock.Now()
		ev.adminRows(now)
		ev.runTask(TaskPurgeRows)
		if ev.logs.count("rows purged transfers=0 challenges=0 sessions=0 password_failures=0 sender_access=0 verified_addresses=0 invitations=0 "+systemCounts) != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		if ev.f.called("scrub") != 1 {
			t.Fatalf("%d scrubs after a global purge, want 1", ev.f.called("scrub"))
		}
		// The live rows were kept: twelve hours later, they are stale.
		ev.clock.set(now.Add(12 * time.Hour))
		ev.runTask(TaskPurgeRows)
		if ev.logs.count(systemCounts) != 2 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		ev.runTask(TaskPurgeRows)
		if ev.logs.count("rows purged") != 2 || ev.f.called("scrub") != 2 {
			t.Fatalf("a run that purged nothing logged or scrubbed:\n%s", ev.logs.all())
		}
	})
}

func TestPurgeRowsSystemOptions(t *testing.T) {
	runEach(t, "overrides", func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.s = ev.newSweeper(Options{AdminSessionIdleTimeout: 2 * time.Hour, AuditRetentionMonths: 11})
		now := ev.clock.Now()
		ev.adminRows(now)
		ev.runTask(TaskPurgeRows)
		// No session is idle for two hours; both audit events are older
		// than 11 months.
		if ev.logs.count("admin_sessions=0 admin_activations=1 admin_login_failures=1 audit_events=2") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
	})
}

func TestPurgeRowsUsageCounters(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		cutoff := store.DayOf(ev.clock.Now()).AddDate(0, -UsageRetentionMonths, 0)
		add := func(tn *tenant.Tenant, day time.Time) {
			t.Helper()
			if err := ev.db.TenantUsage().Add(ctx, tn.ID, day, store.UsageCounts{Transfers: 1}); err != nil {
				t.Fatal(err)
			}
		}
		add(ev.a, cutoff.AddDate(0, 0, -1))
		add(ev.a, cutoff)
		add(ev.b, cutoff.AddDate(0, 0, -1))
		ev.runTask(TaskPurgeRows)
		if ev.logs.count("usage_counters=2") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		for tn, want := range map[*tenant.Tenant]int{ev.a: 1, ev.b: 0} {
			got, err := ev.db.TenantUsage().Range(ctx, tn.ID, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != want || (want == 1 && !got[0].Day.Equal(cutoff)) {
				t.Fatalf("%s keeps %v, want %d day(s) from %v", tn.FQDN, got, want, cutoff)
			}
		}
	})
}

package quota

import (
	"context"
	"errors"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Compile-time checks: the real dependencies implement the interfaces.
var (
	_ Notifier = (*notify.Notifier)(nil)
	_ Mailer   = (*mail.Retrier)(nil)
	_ Auditor  = (*audit.Writer)(nil)
	_ repo     = storeRepo{}
)

func TestNext(t *testing.T) {
	const q = 1000
	cases := []struct {
		cur     int
		used    int64
		quota   int64
		refused bool
		want    int
	}{
		// From 0.
		{0, 0, q, false, 0},
		{0, 799, q, false, 0},
		{0, 800, q, false, 80},
		{0, 949, q, true, 80},
		{0, 950, q, false, 80},
		{0, 950, q, true, 100},
		{0, 999, q, false, 80},
		{0, 1000, q, false, 100},
		{0, 5000, q, false, 100},
		{0, -5, q, true, 0},
		// From 80: re-arms only below 75 %.
		{80, 800, q, false, 80},
		{80, 750, q, false, 80},
		{80, 749, q, false, 0},
		{80, 950, q, false, 80},
		{80, 950, q, true, 100},
		{80, 949, q, true, 80},
		{80, 1000, q, false, 100},
		// From 100: back to 80 only below 95 %.
		{100, 1000, q, false, 100},
		{100, 950, q, false, 100},
		{100, 949, q, false, 80},
		{100, 750, q, false, 80},
		{100, 749, q, false, 0},
		{100, 0, q, true, 0},
		// No quota.
		{0, 10, 0, true, 0},
		{100, 10, -1, false, 0},
		// Unknown stored level counts as 0.
		{42, 800, q, false, 80},
		{42, 10, q, false, 0},
		// Huge values do not overflow.
		{0, math.MaxInt64, math.MaxInt64, false, 100},
		{0, (math.MaxInt64/100 + 1) * 80, math.MaxInt64, false, 80},
		{0, math.MaxInt64 / 100 * 79, math.MaxInt64, false, 0},
	}
	for _, c := range cases {
		if got := Next(c.cur, c.used, c.quota, c.refused); got != c.want {
			t.Errorf("Next(%d, %d, %d, %v) = %d, want %d", c.cur, c.used, c.quota, c.refused, got, c.want)
		}
	}
}

func TestNewValidation(t *testing.T) {
	n, m, a := &fakeNotifier{}, &fakeMailer{}, failAuditor{}
	if _, err := New(nil, n, m, a, Options{AdminLink: adminLink}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("nil db: %v", err)
	}
	r := storeRepo{}
	for name, f := range map[string]func() error{
		"no notifier": func() error { _, err := newMonitor(r, nil, m, a, Options{AdminLink: adminLink}); return err },
		"no mailer":   func() error { _, err := newMonitor(r, n, nil, a, Options{AdminLink: adminLink}); return err },
		"no auditor":  func() error { _, err := newMonitor(r, n, m, nil, Options{AdminLink: adminLink}); return err },
		"no link":     func() error { _, err := newMonitor(r, n, m, a, Options{}); return err },
		"bad url":     func() error { _, err := newMonitor(r, n, m, a, Options{AdminLink: "http://%zz"}); return err },
		"bad scheme": func() error {
			_, err := newMonitor(r, n, m, a, Options{AdminLink: "ftp://admin.example.com"})
			return err
		},
		"relative": func() error { _, err := newMonitor(r, n, m, a, Options{AdminLink: "/admin"}); return err },
	} {
		if err := f(); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("%s: %v", name, err)
		}
	}
	mon, err := newMonitor(r, n, m, a, Options{AdminLink: "http://admin.example.com/admin"})
	if err != nil {
		t.Fatal(err)
	}
	if mon.sweepInterval != DefaultSweepInterval || mon.maxPending != DefaultMaxPending || mon.now == nil || mon.logger == nil {
		t.Fatalf("defaults not applied: %+v", mon)
	}
}

func TestNewOverStore(t *testing.T) {
	db, err := store.Open(context.Background(), storetest.SQLite(t).Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := New(db, &fakeNotifier{}, &fakeMailer{}, audit.New(db), Options{AdminLink: adminLink}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitions(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		tn := ev.tenant(1000)
		ev.admin(store.RoleDelegatedAdmin, "dana@entity-a.example.com", "fr", tn.ID)

		ev.sweep()
		if ev.level(tn) != 0 || len(ev.notifier.all()) != 0 {
			t.Fatal("alert below 80 %")
		}

		// 80 %: warning.
		ev.use(tn, 800)
		ev.check(tn, false)
		calls := ev.notifier.all()
		if ev.level(tn) != 80 || len(calls) != 1 || ev.mailer.count() != 1 {
			t.Fatalf("level %d, calls %d, sends %d", ev.level(tn), len(calls), ev.mailer.count())
		}
		c := calls[0]
		want := mail.QuotaAlertData{TenantName: tn.Name, UsedBytes: 800, QuotaBytes: 1000, AdminLink: adminLink}
		if c.tid != tn.ID || c.level != notify.QuotaWarning || c.data != want ||
			!slices.Equal(c.recipients, []notify.Contact{{Email: "dana@entity-a.example.com", Language: "fr"}}) {
			t.Fatalf("alert %+v", c)
		}
		evs := ev.audits(tn, audit.ActionQuotaWarning)
		if len(evs) != 1 {
			t.Fatalf("warning events: %d", len(evs))
		}
		if a := evs[0]; a.ActorKind != store.ActorSystem || a.Actor != "quota" || a.ObjectKind != audit.ObjectTenant ||
			a.ObjectID != string(tn.ID) {
			t.Fatalf("event %+v", a)
		}
		d := details(t, evs[0])
		if d["usedBytes"] != float64(800) || d["quotaBytes"] != float64(1000) || d["percent"] != float64(80) {
			t.Fatalf("details %v", d)
		}

		// Same level: nothing more.
		ev.check(tn, false)
		ev.sweep()
		if len(ev.notifier.all()) != 1 {
			t.Fatal("duplicate warning")
		}

		// Hysteresis: 75.5 % keeps 80, 72.7 % re-arms silently.
		ev.setQuota(tn, 1060)
		ev.sweep()
		if ev.level(tn) != 80 {
			t.Fatalf("level %d at 75.5 %%", ev.level(tn))
		}
		ev.setQuota(tn, 1100)
		ev.sweep()
		if ev.level(tn) != 0 || len(ev.notifier.all()) != 1 || len(ev.audits(tn, audit.ActionQuotaWarning)) != 1 {
			t.Fatal("re-arm must be silent")
		}
		ev.wantLog("alert level lowered")

		// Re-armed: a new warning.
		ev.setQuota(tn, 1000)
		ev.sweep()
		if ev.level(tn) != 80 || len(ev.notifier.all()) != 2 {
			t.Fatal("no second warning after re-arm")
		}

		// 95 %: only a refusal raises to 100.
		ev.use(tn, 150)
		ev.check(tn, false)
		if ev.level(tn) != 80 {
			t.Fatal("95 % without refusal raised the level")
		}
		ev.check(tn, true)
		calls = ev.notifier.all()
		if ev.level(tn) != 100 || len(calls) != 3 || calls[2].level != notify.QuotaReached {
			t.Fatalf("refusal at 95 %%: level %d, calls %d", ev.level(tn), len(calls))
		}
		if len(ev.audits(tn, audit.ActionQuotaReached)) != 1 {
			t.Fatal("no quota.reached event")
		}

		// Below 95 %: back to 80 silently; reached again: a new alert.
		ev.setQuota(tn, 1010)
		ev.sweep()
		if ev.level(tn) != 80 || len(ev.notifier.all()) != 3 {
			t.Fatal("100 must drop to 80 silently")
		}
		ev.setQuota(tn, 950)
		ev.sweep()
		if ev.level(tn) != 100 || len(ev.notifier.all()) != 4 || len(ev.audits(tn, audit.ActionQuotaReached)) != 2 {
			t.Fatal("no alert when the quota is reached")
		}
	})
}

func TestStraightToReached(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		tn := ev.tenant(1000)
		ev.admin(store.RoleDelegatedAdmin, "dana@entity-a.example.com", "", tn.ID)
		ev.use(tn, 1200)
		ev.check(tn, false)
		calls := ev.notifier.all()
		if ev.level(tn) != 100 || len(calls) != 1 || calls[0].level != notify.QuotaReached {
			t.Fatalf("level %d, calls %+v", ev.level(tn), calls)
		}
		if len(ev.audits(tn, audit.ActionQuotaWarning)) != 0 || len(ev.audits(tn, audit.ActionQuotaReached)) != 1 {
			t.Fatal("expected only quota.reached")
		}
		if d := details(t, ev.audits(tn, audit.ActionQuotaReached)[0]); d["percent"] != float64(120) {
			t.Fatalf("details %v", d)
		}
	})
}

func TestRecipients(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		noAdmin := ev.tenant(1000)
		other := ev.tenant(1000)
		// Neither a delegated admin of another tenant nor a disabled or
		// non-activated account is a contact.
		ev.admin(store.RoleDelegatedAdmin, "olga@entity-b.example.com", "fr", other.ID)
		if _, err := ev.db.Admins().Create(context.Background(), store.Admin{
			Username: "pending", Email: "pending@example.com", Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{noAdmin.ID},
		}); err != nil {
			t.Fatal(err)
		}

		// No administrator at all: logged, audited, no mail.
		ev.use(noAdmin, 900)
		ev.check(noAdmin, false)
		if ev.level(noAdmin) != 80 || len(ev.notifier.all()) != 0 || len(ev.audits(noAdmin, audit.ActionQuotaWarning)) != 1 {
			t.Fatal("no contact: level must be stored and audited without mail")
		}
		ev.wantLog("no administrator to notify")

		// Fallback to the super admins.
		ev.admin(store.RoleSuperAdmin, "root@example.com", "", nil...)
		ev.use(noAdmin, 200)
		ev.check(noAdmin, false)
		calls := ev.notifier.all()
		if len(calls) != 1 || !slices.Equal(calls[0].recipients, []notify.Contact{{Email: "root@example.com"}}) {
			t.Fatalf("fallback: %+v", calls)
		}
	})
}

func TestNoSMTPAndNotifierErrors(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		tn := ev.tenant(1000)
		ev.admin(store.RoleDelegatedAdmin, "dana@entity-a.example.com", "", tn.ID)
		ev.notifier.err = notify.ErrNoSMTP
		ev.use(tn, 800)
		ev.check(tn, false)
		if ev.level(tn) != 80 || ev.mailer.count() != 0 || len(ev.audits(tn, audit.ActionQuotaWarning)) != 1 {
			t.Fatal("no SMTP: level must be stored and audited, nothing sent")
		}
		ev.wantLog("the tenant has no SMTP settings")

		ev.notifier.err = errBoom
		ev.use(tn, 200)
		ev.check(tn, false)
		if ev.level(tn) != 100 || ev.mailer.count() != 0 {
			t.Fatal("notifier failure")
		}
		ev.wantLog("failed to build the alert mails")
	})
}

func TestLostCompareAndSet(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		tn := ev.tenant(1000)
		ev.admin(store.RoleDelegatedAdmin, "dana@entity-a.example.com", "", tn.ID)
		ev.use(tn, 800)
		// Another process raised the level first: this evaluation reads a
		// stale 0 and loses the swap.
		if ok, err := ev.db.QuotaAlerts().CompareAndSet(context.Background(), tn.ID, 0, 80, t0); err != nil || !ok {
			t.Fatal(ok, err)
		}
		ev.fault.staleLevel = 0
		ev.check(tn, false)
		if len(ev.notifier.all()) != 0 || len(ev.audits(tn, audit.ActionQuotaWarning)) != 0 {
			t.Fatal("a lost swap must not alert")
		}
		// A swap lost without store involvement behaves the same.
		ev.fault.staleLevel = -1
		ev.fault.casFalse = true
		ev.use(tn, 300)
		ev.check(tn, false)
		if len(ev.notifier.all()) != 0 {
			t.Fatal("a lost swap must not alert")
		}
	})
}

func TestTenantsNotActive(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		tn := ev.tenant(1000)
		ev.use(tn, 900)
		if err := ev.db.Tenants().SetStatus(context.Background(), tn.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		ev.check(tn, true)
		ev.sweep()
		ev.mon.Check("ten_01JAB00000000000000UNKNWN", false)
		ev.mon.ProcessPending(context.Background())
		if ev.level(tn) != 0 || len(ev.notifier.all()) != 0 {
			t.Fatal("a tenant being deleted must not be evaluated")
		}
		ev.wantLog("tenant gone")
	})
}

func TestFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		tn := ev.tenant(1000)
		ev.admin(store.RoleDelegatedAdmin, "dana@entity-a.example.com", "", tn.ID)
		ev.use(tn, 800)
		f := ev.fault

		steps := []struct {
			name string
			set  func()
			log  string
		}{
			{"tenant", func() { f.tenantErr = errBoom }, "failed to read the tenant"},
			{"used", func() { f.usedErr = errBoom }, "failed to read the storage used"},
			{"level", func() { f.levelErr = errBoom }, "failed to read the alert level"},
			{"cas", func() { f.casErr = errBoom }, "failed to store the alert level"},
		}
		for _, s := range steps {
			*f = faultRepo{repo: f.repo, staleLevel: -1}
			s.set()
			ev.check(tn, false)
			ev.wantLog(s.log)
			if ev.level(tn) != 0 || len(ev.notifier.all()) != 0 {
				t.Fatalf("%s: level changed or alert sent", s.name)
			}
		}
		// Deleted between the read and the swap: nothing logged as error.
		*f = faultRepo{repo: f.repo, staleLevel: -1, casErr: store.ErrNotFound}
		ev.check(tn, false)

		// Sweep failures.
		*f = faultRepo{repo: f.repo, staleLevel: -1, activeErr: errBoom}
		if err := ev.mon.Sweep(context.Background()); !errors.Is(err, errBoom) {
			t.Fatalf("sweep: %v", err)
		}
		*f = faultRepo{repo: f.repo, staleLevel: -1, usedAllErr: errBoom}
		if err := ev.mon.Sweep(context.Background()); !errors.Is(err, errBoom) {
			t.Fatalf("sweep: %v", err)
		}

		// Contacts failures: level stored and audited, no mail.
		*f = faultRepo{repo: f.repo, staleLevel: -1, contactsErr: errBoom}
		ev.check(tn, false)
		ev.wantLog("failed to list the administrators to notify")
		if ev.level(tn) != 80 || len(ev.notifier.all()) != 0 {
			t.Fatal("contacts failure")
		}
		other := ev.tenant(1000)
		ev.use(other, 800)
		*f = faultRepo{repo: f.repo, staleLevel: -1, superErr: errBoom}
		ev.check(other, false)
		if ev.level(other) != 80 || len(ev.notifier.all()) != 0 {
			t.Fatal("super admin contacts failure")
		}
	})
}

func TestAuditFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		ev.mon.auditor = failAuditor{}
		tn := ev.tenant(1000)
		ev.admin(store.RoleDelegatedAdmin, "dana@entity-a.example.com", "", tn.ID)
		ev.use(tn, 800)
		ev.check(tn, false)
		ev.wantLog("failed to record the audit event")
		if len(ev.notifier.all()) != 1 {
			t.Fatal("an audit failure must not prevent the mail")
		}
	})
}

func TestCheckCoalescing(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), Options{MaxPending: 1})
	a, b := ev.tenant(1000), ev.tenant(1000)
	ev.admin(store.RoleDelegatedAdmin, "dana@entity-a.example.com", "", a.ID, b.ID)
	ev.use(a, 960)
	ev.use(b, 960)

	var nilMon *Monitor
	nilMon.Check(a.ID, true)
	ev.mon.Check("", true)

	ev.mon.Check(a.ID, true)
	ev.mon.Check(a.ID, false) // coalesced, the refusal is kept
	ev.mon.Check(b.ID, true)  // dropped: the bound is reached
	if ev.mon.Pending() != 1 {
		t.Fatalf("pending %d", ev.mon.Pending())
	}
	ev.wantLog("evaluation request dropped")
	ev.mon.ProcessPending(context.Background())
	if ev.level(a) != 100 || ev.level(b) != 0 || ev.mon.Pending() != 0 {
		t.Fatalf("levels %d %d", ev.level(a), ev.level(b))
	}

	// A canceled context stops the processing.
	ev.mon.Check(b.ID, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ev.mon.ProcessPending(ctx)
	if ev.level(b) != 0 {
		t.Fatal("evaluated with a canceled context")
	}
	if err := ev.mon.Sweep(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("sweep: %v", err)
	}
	// Canceled during the sweep: the remaining tenants are skipped.
	ctx2, cancel2 := context.WithCancel(context.Background())
	ev.fault.afterUsedAll = cancel2
	if err := ev.mon.Sweep(ctx2); !errors.Is(err, context.Canceled) {
		t.Fatalf("sweep: %v", err)
	}
	ev.fault.afterUsedAll = nil
	if ev.level(b) != 0 {
		t.Fatal("evaluated after the cancellation")
	}

	// After Close, Check is ignored.
	if err := ev.mon.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	ev.mon.ProcessPending(context.Background())
	ev.mon.Check(b.ID, true)
	if ev.mon.Pending() != 0 {
		t.Fatal("Check after Close")
	}
}

func TestRunLifecycle(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), Options{SweepInterval: 20 * time.Millisecond})
	tn := ev.tenant(1000)
	ev.admin(store.RoleDelegatedAdmin, "dana@entity-a.example.com", "", tn.ID)
	ctx := context.Background()

	if err := ev.mon.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ev.mon.Start(ctx); !errors.Is(err, ErrStarted) {
		t.Fatalf("second start: %v", err)
	}
	// Periodic sweeps.
	waitFor(t, "periodic sweeps", func() bool { return ev.fault.sweepCount() >= 3 })
	// A check is processed in the background.
	ev.use(tn, 800)
	ev.mon.Check(tn.ID, false)
	waitFor(t, "background alert", func() bool { return ev.mailer.count() == 1 })

	if err := ev.mon.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ev.mon.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ev.mon.Start(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("start after close: %v", err)
	}

	// Close without start.
	ev2 := newEnv(t, storetest.SQLite(t), Options{})
	if err := ev2.mon.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestAlertSurvivesCancel checks that a cancellation (Close) arriving
// right after the level moved in the database does not lose the audit
// event nor the mail: no later evaluation would send them.
func TestAlertSurvivesCancel(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		tn := ev.tenant(1000)
		ev.admin(store.RoleDelegatedAdmin, "dana@entity-a.example.com", "", tn.ID)
		ev.use(tn, 800)
		ctx, cancel := context.WithCancel(context.Background())
		ev.fault.afterCAS = cancel
		ev.mon.Check(tn.ID, false)
		ev.mon.ProcessPending(ctx)
		if ev.level(tn) != 80 || len(ev.audits(tn, audit.ActionQuotaWarning)) != 1 ||
			len(ev.notifier.all()) != 1 || ev.mailer.count() != 1 {
			t.Fatalf("level %d, alerts %d, sends %d", ev.level(tn), len(ev.notifier.all()), ev.mailer.count())
		}
	})
}

// TestStartIgnoresCancel checks that the monitor keeps evaluating the
// checks after the start context is canceled (the shutdown signal), until
// Close.
func TestStartIgnoresCancel(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), Options{})
	tn := ev.tenant(1000)
	ev.admin(store.RoleDelegatedAdmin, "dana@entity-a.example.com", "", tn.ID)
	sig, stop := context.WithCancel(context.Background())
	if err := ev.mon.Start(sig); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "initial sweep", func() bool { return ev.fault.sweepCount() == 1 })
	stop()
	ev.use(tn, 800)
	ev.mon.Check(tn.ID, false)
	waitFor(t, "alert after the signal", func() bool { return ev.mailer.count() == 1 })
	if err := ev.mon.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunSweepFailureLogged(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), Options{})
	ev.fault.activeErr = errBoom
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ev.mon.Run(ctx)
	}()
	waitFor(t, "sweep failure", func() bool { return ev.fault.sweepCount() >= 1 })
	cancel()
	<-done
	ev.wantLog("sweep failed")
}

func TestCloseTimeout(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), Options{})
	ev.fault.block = make(chan struct{})
	if err := ev.mon.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "blocked sweep", func() bool { return ev.fault.sweepCount() == 1 })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ev.mon.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("close: %v", err)
	}
	close(ev.fault.block)
	if err := ev.mon.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRepo(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		r := storeRepo{db: ev.db}
		ctx := context.Background()
		if _, err := r.usedBytes(ctx, "bad"); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("usedBytes: %v", err)
		}
		a, b, c := ev.tenant(10), ev.tenant(10), ev.tenant(10)
		if err := ev.db.Tenants().SetStatus(ctx, b.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		old := listPageSize
		listPageSize = 1
		t.Cleanup(func() { listPageSize = old })
		ts, err := r.activeTenants(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var ids []tenant.ID
		for _, x := range ts {
			ids = append(ids, x.ID)
		}
		want := []tenant.ID{a.ID, c.ID}
		slices.Sort(want)
		if !slices.Equal(ids, want) {
			t.Fatalf("active tenants %v, want %v", ids, want)
		}
		_ = ev.db.Close()
		if _, err := r.activeTenants(ctx); err == nil {
			t.Fatal("list on a closed database")
		}
	})
}

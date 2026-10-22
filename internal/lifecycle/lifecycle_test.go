package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	s := New(Deps{}, Options{UploadTTL: -time.Hour})
	if s.now == nil || s.logger == nil || s.endedRetention != EndedRetention || s.orphanGrace != OrphanGrace ||
		s.scanningMaxAge != store.ScanningMaxAge ||
		s.uploadTTL != 0 || s.backupKeep != DefaultBackupKeep || s.purgeBatch != store.PurgeBatchSize ||
		s.keyBatch != store.MaxPageSize || s.pageSizes != [kindCount]int{store.DeletionSweepLimit, store.ExpirySweepLimit, store.AbandonedSweepLimit} {
		t.Fatalf("defaults not applied: %+v", s)
	}
	want := map[Task]time.Duration{
		TaskDeleteAfterDownload: DefaultInterval, TaskExpire: DefaultInterval,
		TaskAbandonedUploads: DefaultAbandonedInterval, TaskTenantDeletions: DefaultTenantDeletionsInterval,
		TaskPurgeRows: DefaultPurgeInterval, TaskOrphans: DefaultOrphansInterval, TaskBackup: 0,
	}
	for i, tk := range s.tasks {
		if tk.name != allTasks[i] || tk.interval != want[tk.name] || tk.atStart != (tk.name != TaskBackup) {
			t.Errorf("task %d = %s every %v (at start %v)", i, tk.name, tk.interval, tk.atStart)
		}
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
	s = New(Deps{}, Options{
		Interval: time.Second, AbandonedInterval: 2 * time.Second, PurgeInterval: 3 * time.Second,
		OrphansInterval: 4 * time.Second, EndedRetention: time.Hour, OrphanGrace: time.Minute, BackupKeep: 2,
		ScanningMaxAge: 5 * time.Hour, TenantDeletionsInterval: 5 * time.Second,
	})
	if s.tasks[1].interval != time.Second || s.tasks[2].interval != 2*time.Second || s.tasks[3].interval != 5*time.Second ||
		s.tasks[4].interval != 3*time.Second || s.tasks[5].interval != 4*time.Second || s.endedRetention != time.Hour || s.orphanGrace != time.Minute || s.backupKeep != 2 ||
		s.scanningMaxAge != 5*time.Hour {
		t.Fatalf("options not applied: %+v", s)
	}
}

func TestNextBackup(t *testing.T) {
	t.Parallel()
	at := 2*time.Hour + 30*time.Minute
	paris := time.FixedZone("UTC+2", 2*3600)
	cases := []struct {
		now, want time.Time
	}{
		{time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC), time.Date(2026, 10, 21, 2, 30, 0, 0, time.UTC)},
		{time.Date(2026, 10, 21, 2, 30, 0, 0, time.UTC), time.Date(2026, 10, 22, 2, 30, 0, 0, time.UTC)},
		{time.Date(2026, 10, 21, 23, 59, 0, 0, time.UTC), time.Date(2026, 10, 22, 2, 30, 0, 0, time.UTC)},
		// 03:00 in UTC+2 is 01:00 UTC: today.
		{time.Date(2026, 10, 21, 3, 0, 0, 0, paris), time.Date(2026, 10, 21, 2, 30, 0, 0, time.UTC)},
		{time.Date(2026, 12, 31, 12, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 2, 30, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		if got := nextBackup(c.now, at); !got.Equal(c.want) {
			t.Errorf("nextBackup(%v) = %v, want %v", c.now, got, c.want)
		}
	}
}

func TestRunTask(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	if err := ev.s.RunTask(context.Background(), "nope"); !errors.Is(err, ErrUnknownTask) {
		t.Fatalf("RunTask(nope) = %v, want ErrUnknownTask", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ev.s.RunTask(ctx, TaskPurgeRows); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunTask(canceled) = %v", err)
	}
	if err := ev.s.RunTask(context.Background(), TaskBackup); !errors.Is(err, ErrBackupDisabled) {
		t.Fatalf("RunTask(backup) without a directory = %v", err)
	}
	for _, tk := range allTasks[:6] {
		ev.runTask(tk)
		if !ev.s.LastRun(tk).Equal(ev.clock.Now()) {
			t.Errorf("LastRun(%s) = %v", tk, ev.s.LastRun(tk))
		}
	}
	if !ev.s.LastRun(TaskBackup).IsZero() {
		t.Fatal("LastRun(backup) recorded without a backup")
	}
}

// startEnv starts the sweeper of ev with fake timers and returns them with
// the channel of the scheduled runs.
func startEnv(t *testing.T, ev *env, ctx context.Context) (*fakeTimers, <-chan runResult) {
	t.Helper()
	ft := newFakeTimers()
	ev.s.newTimer = ft.new
	results := make(chan runResult, 32)
	ev.s.afterRun = func(tk Task, err error) { results <- runResult{tk, err} }
	if err := ev.s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return ft, results
}

// next returns the next scheduled run.
func next(t *testing.T, ev *env, results <-chan runResult) runResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(waitFor):
		t.Fatalf("no run\nlogs:\n%s", ev.logs.all())
		return runResult{}
	}
}

// waitTimers waits until n timers were created.
func waitTimers(t *testing.T, ft *fakeTimers, n int) map[Task]int {
	t.Helper()
	got := map[Task]int{}
	for range n {
		select {
		case tk := <-ft.created:
			got[tk]++
		case <-time.After(waitFor):
			t.Fatalf("timers created: %v, want %d", got, n)
		}
	}
	return got
}

func TestStartClose(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		dir := t.TempDir()
		ev.s = ev.newSweeper(Options{BackupDir: dir, BackupTime: 11 * time.Hour})
		ev.clock.set(t0)
		fx := ev.due(ev.a, 1)
		before := ev.get(fx)

		ft, results := startEnv(t, ev, context.Background())
		if err := ev.s.Start(context.Background()); !errors.Is(err, ErrStarted) {
			t.Fatalf("second Start = %v, want ErrStarted", err)
		}
		// Every task but the backup runs at once, in order.
		for _, tk := range allTasks[:6] {
			if r := next(t, ev, results); r.task != tk || r.err != nil {
				t.Fatalf("first runs: got %s (%v), want %s", r.task, r.err, tk)
			}
		}
		sqlite := e.Driver == "sqlite"
		nTimers := 6
		if sqlite {
			nTimers = 7
		}
		created := waitTimers(t, ft, nTimers)
		if created[TaskBackup] != boolInt(sqlite) {
			t.Fatalf("backup timers %d on %s", created[TaskBackup], e.Driver)
		}
		if got := ev.logs.count("backups are made by the dedicated PostgreSQL container"); got != boolInt(!sqlite) {
			t.Fatalf("PostgreSQL backup notice logged %d times", got)
		}
		if ft.lastDelay(TaskExpire) != DefaultInterval || ft.lastDelay(TaskOrphans) != DefaultOrphansInterval {
			t.Fatalf("delays %v %v", ft.lastDelay(TaskExpire), ft.lastDelay(TaskOrphans))
		}
		if sqlite && ft.lastDelay(TaskBackup) != time.Hour {
			t.Fatalf("backup delay %v, want 1h (10:00 to 11:00 UTC)", ft.lastDelay(TaskBackup))
		}

		// The fake clock passes the grace period; the next timer deletes it.
		ev.clock.set(t0.Add(grace))
		ft.c[TaskDeleteAfterDownload] <- t0
		if r := next(t, ev, results); r.task != TaskDeleteAfterDownload || r.err != nil {
			t.Fatalf("second run = %+v", r)
		}
		ev.assertDeleted(fx, before)
		// A failure is logged and the loop goes on.
		ev.f.set("tenantIDs", 1, nil)
		ft.c[TaskPurgeRows] <- t0
		if r := next(t, ev, results); r.task != TaskPurgeRows || !errors.Is(r.err, errFault) {
			t.Fatalf("failed run = %+v", r)
		}
		if ev.logs.count("ERROR lifecycle: task failed task=purge-rows") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		if sqlite {
			ev.clock.set(t0.Add(time.Hour))
			ft.c[TaskBackup] <- t0
			if r := next(t, ev, results); r.task != TaskBackup || r.err != nil {
				t.Fatalf("backup run = %+v", r)
			}
			waitTimers(t, ft, 3) // delete, purge, backup again
			if ft.lastDelay(TaskBackup) != 24*time.Hour {
				t.Fatalf("next backup delay %v, want 24h", ft.lastDelay(TaskBackup))
			}
		}

		if err := ev.s.Close(context.Background()); err != nil {
			t.Fatalf("Close: %v", err)
		}
		for _, tk := range allTasks[:6] {
			if ft.stops(tk) == 0 {
				t.Errorf("timer of %s not stopped", tk)
			}
		}
		if err := ev.s.Close(context.Background()); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if err := ev.s.Start(context.Background()); !errors.Is(err, ErrClosed) {
			t.Fatalf("Start after Close = %v, want ErrClosed", err)
		}
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestStartWithoutBackupDir(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ft, results := startEnv(t, ev, context.Background())
	for range 6 {
		next(t, ev, results)
	}
	if got := waitTimers(t, ft, 6); got[TaskBackup] != 0 {
		t.Fatalf("backup scheduled without a directory: %v", got)
	}
}

func TestCloseTimeout(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.s.newTimer = newFakeTimers().new
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
		t.Fatalf("Close = %v, want context.Canceled while a run is in progress", err)
	}
	close(release)
	if err := ev.s.Close(context.Background()); err != nil {
		t.Fatalf("Close after the run: %v", err)
	}
	if ev.logs.count("task failed") != 0 {
		t.Fatalf("a run interrupted by Close was logged as failed:\n%s", ev.logs.all())
	}
}

func TestStartStopsWithContext(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx, cancel := context.WithCancel(context.Background())
	ft, results := startEnv(t, ev, ctx)
	for range 6 {
		next(t, ev, results)
	}
	waitTimers(t, ft, 6)
	cancel()
	if err := ev.s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, tk := range allTasks[:6] {
		if ft.stops(tk) != 1 {
			t.Errorf("timer of %s stopped %d times", tk, ft.stops(tk))
		}
	}
}

func TestRealTimer(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.s = ev.newSweeper(Options{Interval: 5 * time.Millisecond})
	runs := make(chan Task, 64)
	ev.s.afterRun = func(tk Task, _ error) {
		select {
		case runs <- tk:
		default:
		}
	}
	if err := ev.s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	expires := 0
	for expires < 3 {
		select {
		case tk := <-runs:
			if tk == TaskExpire {
				expires++
			}
		case <-time.After(waitFor):
			t.Fatal("the real timers do not drive the runs")
		}
	}
}

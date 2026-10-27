package diskalert

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

const adminLink = "https://admin.example.com/admin"

var (
	errBoom = errors.New("boom")
	_       = repo(storeRepo{})
	_       = Mailer((*mail.Retrier)(nil))
	_       = Auditor((*audit.Writer)(nil))

	smtp = mail.Settings{Host: "relay.example.com", Port: 25, Security: mail.SecurityNone, FromAddress: "noreply@example.com", FromName: "TransTeira"}
)

// fakeMailer records the jobs it is given.
type fakeMailer struct {
	mu    sync.Mutex
	sends [][]mail.Job
}

func (f *fakeMailer) Send(_ context.Context, jobs []mail.Job, _ ...slog.Attr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends = append(f.sends, jobs)
}

func (f *fakeMailer) calls() [][]mail.Job {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sends)
}

// disk is a fake filesystem whose usage the test sets.
type disk struct {
	mu          sync.Mutex
	total, free uint64
	err         error
	calls       atomic.Int32
}

func (d *disk) set(total, free uint64, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.total, d.free, d.err = total, free, err
}

func (d *disk) measure(string) (uint64, uint64, error) {
	d.calls.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.total, d.free, d.err
}

// faultRepo wraps a repo and injects failures.
type faultRepo struct {
	repo
	settingsErr, casErr, contactsErr, claimErr error
	casLost, claimLost                         bool
}

func (f *faultRepo) settings(ctx context.Context) (store.SystemSettingsRow, error) {
	if f.settingsErr != nil {
		return store.SystemSettingsRow{}, f.settingsErr
	}
	return f.repo.settings(ctx)
}

func (f *faultRepo) compareAndSet(ctx context.Context, old, level int, now time.Time) (bool, error) {
	if f.casErr != nil {
		return false, f.casErr
	}
	if f.casLost {
		return false, nil
	}
	return f.repo.compareAndSet(ctx, old, level, now)
}

func (f *faultRepo) claimMail(ctx context.Context, now time.Time) (bool, error) {
	if f.claimErr != nil {
		return false, f.claimErr
	}
	if f.claimLost {
		return false, nil
	}
	return f.repo.claimMail(ctx, now)
}

func (f *faultRepo) superAdminContacts(ctx context.Context) ([]store.AdminContact, error) {
	if f.contactsErr != nil {
		return nil, f.contactsErr
	}
	return f.repo.superAdminContacts(ctx)
}

// faultAuditor wraps an Auditor and may fail.
type faultAuditor struct {
	Auditor
	err error
}

func (f *faultAuditor) Record(ctx context.Context, ev audit.Event) error {
	if f.err != nil {
		return f.err
	}
	return f.Auditor.Record(ctx, ev)
}

// env is a monitor over a real database.
type env struct {
	t       *testing.T
	db      *store.DB
	disk    *disk
	mailer  *fakeMailer
	fault   *faultRepo
	auditor *faultAuditor
	logs    *syncBuffer
	// published receives the events of the monitors.
	published *events.Recorder
	m         *Monitor
	n         int
	// clock is the time of the monitors, in Unix milliseconds.
	clock atomic.Int64
}

// now is the clock of the monitors of the environment.
func (ev *env) now() time.Time { return time.UnixMilli(ev.clock.Load()) }

// advance moves the clock of the monitors forward by d.
func (ev *env) advance(d time.Duration) { ev.clock.Add(d.Milliseconds()) }

// syncBuffer is a bytes.Buffer safe for concurrent writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func openDB(t *testing.T, e storetest.Engine) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return db
}

func newEnv(t *testing.T, e storetest.Engine, withMail bool) *env {
	t.Helper()
	ev := &env{
		t: t, db: openDB(t, e), disk: &disk{total: 1000, free: 1000}, mailer: &fakeMailer{}, logs: &syncBuffer{},
		published: &events.Recorder{},
	}
	ev.fault = &faultRepo{repo: storeRepo{db: ev.db}}
	ev.auditor = &faultAuditor{Auditor: audit.New(ev.db)}
	ev.clock.Store(time.Now().UnixMilli())
	ev.m = ev.monitor(withMail)
	return ev
}

// monitor returns a new monitor of the environment.
func (ev *env) monitor(withMail bool) *Monitor {
	ev.t.Helper()
	opts := Options{
		DataDir: ev.t.TempDir(), AdminLink: adminLink, Measure: ev.disk.measure, Now: ev.now,
		Logger: slog.New(slog.NewTextHandler(ev.logs, nil)), Events: ev.published,
	}
	if withMail {
		opts.Mailer, opts.SMTP = ev.mailer, smtp
	}
	m, err := newMonitor(ev.fault, ev.auditor, opts)
	if err != nil {
		ev.t.Fatal(err)
	}
	return m
}

func (ev *env) admin(role store.AdminRole, email, lang string) {
	ev.t.Helper()
	ev.n++
	_, err := ev.db.Admins().Create(context.Background(), store.Admin{
		Username: fmt.Sprintf("admin%d", ev.n), Email: email, Role: role, PasswordHash: "$argon2id$test", Language: lang,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
}

func (ev *env) setEmail(email, lang string) {
	ev.t.Helper()
	if _, err := ev.db.SystemSettings().UpdateTx(context.Background(), func(_ *store.SystemTx, s *store.SystemSettingsRow) error {
		s.AlertEmail, s.AlertEmailLanguage = email, lang
		return nil
	}); err != nil {
		ev.t.Fatal(err)
	}
}

func (ev *env) level() int {
	ev.t.Helper()
	row, err := ev.db.SystemSettings().Get(context.Background())
	if err != nil {
		ev.t.Fatal(err)
	}
	return row.DiskAlertLevel
}

// events returns the audit events of action, newest first.
func (ev *env) events(action audit.Action) []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{Action: string(action)})
	if err != nil {
		ev.t.Fatal(err)
	}
	return page.Items
}

// used sets the disk to used per mille and evaluates.
func (ev *env) used(perMille uint64) {
	ev.disk.set(1000, 1000-perMille, nil)
	ev.m.Evaluate(context.Background())
}

func TestNext(t *testing.T) {
	const raised, normal = store.DiskAlertLevelRaised, store.DiskAlertLevelNormal
	cases := []struct {
		level            int
		ratio, threshold float64
		want             int
	}{
		{normal, 0, 0.85, normal},
		{normal, 0.8499, 0.85, normal},
		{normal, 0.85, 0.85, raised},
		{normal, 1, 0.85, raised},
		{raised, 0.85, 0.85, raised},
		{raised, 0.81, 0.85, raised},
		{raised, 0.8, 0.85, raised},
		{raised, 0.7999, 0.85, normal},
		{raised, 0.1, 0.85, normal},
		{raised, 0.5, 0.5, raised},
		{raised, 0.4499, 0.5, normal},
		{normal, 0.99, 0.99, raised},
		{7, 0.84, 0.85, normal}, // unknown level counts as normal
		{7, 0.9, 0.85, raised},
	}
	for _, c := range cases {
		if got := Next(c.level, c.ratio, c.threshold); got != c.want {
			t.Errorf("Next(%d, %v, %v) = %d, want %d", c.level, c.ratio, c.threshold, got, c.want)
		}
	}
}

func TestNew(t *testing.T) {
	db := openDB(t, storetest.SQLite(t))
	aud := audit.New(db)
	dir := t.TempDir()
	if _, err := New(nil, aud, Options{DataDir: dir, AdminLink: adminLink}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatal(err)
	}
	for name, o := range map[string]Options{
		"no data dir":   {AdminLink: adminLink},
		"relative link": {DataDir: dir, AdminLink: "/admin"},
		"ftp link":      {DataDir: dir, AdminLink: "ftp://admin.example.com"},
		"bad link":      {DataDir: dir, AdminLink: "https://%zz"},
		"bad smtp":      {DataDir: dir, AdminLink: adminLink, Mailer: &fakeMailer{}, SMTP: mail.Settings{Host: "relay.example.com"}},
	} {
		if _, err := New(db, aud, o); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := New(db, nil, Options{DataDir: dir, AdminLink: adminLink}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatal(err)
	}
	m, err := New(db, aud, Options{DataDir: dir, AdminLink: adminLink})
	if err != nil || m.interval != DefaultInterval || m.measure == nil || m.now == nil || m.logger == nil || m.render == nil {
		t.Fatalf("defaults: %v %+v", err, m)
	}
	// The default measure works on the real data directory.
	m.Evaluate(context.Background())
	if m.failure != "" {
		t.Fatalf("real measure failed: %s", m.failure)
	}
	if clamp(math.MaxUint64) != math.MaxInt64 || clamp(5) != 5 {
		t.Fatal("clamp")
	}
}

func TestRaiseAndClear(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.admin(store.RoleSuperAdmin, "root@example.com", "fr")
		ev.admin(store.RoleSuperAdmin, "second@example.com", "")
		// The alert address duplicates a super admin, ignoring case: the
		// super admin keeps its language.
		ev.setEmail("ROOT@example.com", "en")

		ev.used(500)
		ev.used(849)
		if ev.level() != store.DiskAlertLevelNormal || len(ev.mailer.calls()) != 0 {
			t.Fatal("alert below the threshold")
		}

		ev.used(900)
		if ev.level() != store.DiskAlertLevelRaised {
			t.Fatal("not raised")
		}
		raised := ev.events(audit.ActionDiskAlertRaised)
		if len(raised) != 1 {
			t.Fatalf("%d raised events", len(raised))
		}
		a := raised[0]
		if a.TenantID != "" || a.ActorKind != store.ActorSystem || a.Actor != "disk" || a.ObjectKind != audit.ObjectSystem ||
			a.ObjectID != "disk" || string(a.Details) != `{"thresholdPercent":85,"usedPercent":90}` {
			t.Fatalf("event %+v details %s", a, a.Details)
		}
		calls := ev.mailer.calls()
		if len(calls) != 1 || len(calls[0]) != 2 {
			t.Fatalf("mails %+v", calls)
		}
		langs := map[string]string{}
		for _, j := range calls[0] {
			if j.TenantID != MailTenantID || j.Template != mail.TemplateDiskAlert || j.Settings != smtp || len(j.Message.To) != 1 {
				t.Fatalf("job %+v", j)
			}
			langs[j.Message.To[0]] = j.Message.Language
			if !strings.Contains(j.Message.Text, adminLink) {
				t.Fatalf("no admin link in %q", j.Message.Text)
			}
		}
		if langs["root@example.com"] != "fr" || langs["second@example.com"] != "en" {
			t.Fatalf("recipients %v", langs)
		}
		if !strings.Contains(ev.logs.String(), "level=WARN") {
			t.Fatalf("no warning: %s", ev.logs.String())
		}

		// Raised stays raised, without a second mail, down to 80 %.
		ev.used(950)
		ev.used(800)
		if ev.level() != store.DiskAlertLevelRaised || len(ev.mailer.calls()) != 1 || len(ev.events(audit.ActionDiskAlertRaised)) != 1 {
			t.Fatal("re-alerted while raised")
		}
		// A restarted monitor sends nothing again.
		ev.m = ev.monitor(true)
		ev.used(900)
		if len(ev.mailer.calls()) != 1 {
			t.Fatal("re-alerted after a restart")
		}

		ev.used(799)
		if ev.level() != store.DiskAlertLevelNormal || len(ev.mailer.calls()) != 1 {
			t.Fatal("not cleared, or mailed on clear")
		}
		cleared := ev.events(audit.ActionDiskAlertCleared)
		if len(cleared) != 1 || string(cleared[0].Details) != `{"thresholdPercent":85,"usedPercent":79.9}` {
			t.Fatalf("cleared events %+v", cleared)
		}

		// A new crossing within the hour of the last mail is audited and
		// logged, never mailed: toggling the threshold cannot flood.
		ev.advance(MailInterval - time.Minute)
		ev.used(990)
		if ev.level() != store.DiskAlertLevelRaised || len(ev.events(audit.ActionDiskAlertRaised)) != 2 ||
			len(ev.mailer.calls()) != 1 || !strings.Contains(ev.logs.String(), "less than an hour ago") {
			t.Fatalf("second crossing within the hour: mails %d, logs %s", len(ev.mailer.calls()), ev.logs.String())
		}
		ev.used(500)

		// An hour after the last mail, a distinct alert address gets its
		// own mail in its language.
		ev.advance(time.Minute)
		ev.setEmail("ops@example.com", "fr")
		ev.used(990)
		calls = ev.mailer.calls()
		if len(calls) != 2 || len(calls[1]) != 3 || calls[1][2].Message.To[0] != "ops@example.com" || calls[1][2].Message.Language != "fr" {
			t.Fatalf("mails %+v", calls)
		}
		if n := len(ev.events(audit.ActionDiskAlertRaised)); n != 3 {
			t.Fatalf("%d raised events, want 3", n)
		}
	})
}

func TestNoSystemSMTP(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), false)
	ev.admin(store.RoleSuperAdmin, "root@example.com", "fr")
	ev.used(900)
	if ev.level() != store.DiskAlertLevelRaised || len(ev.events(audit.ActionDiskAlertRaised)) != 1 || len(ev.mailer.calls()) != 0 {
		t.Fatal("without SMTP: audit only")
	}
	if !strings.Contains(ev.logs.String(), "TT_SYSTEM_SMTP_HOST") {
		t.Fatalf("logs %s", ev.logs.String())
	}
}

func TestNoRecipient(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), true)
	ev.used(900)
	if len(ev.mailer.calls()) != 0 || !strings.Contains(ev.logs.String(), "no recipient") {
		t.Fatalf("logs %s", ev.logs.String())
	}
}

func TestConcurrentCrossing(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ev.disk.set(1000, 50, nil)
		monitors := []*Monitor{ev.m, ev.monitor(true), ev.monitor(true), ev.monitor(true)}
		var wg sync.WaitGroup
		for _, m := range monitors {
			for range 2 {
				wg.Go(func() { m.Evaluate(context.Background()) })
			}
		}
		wg.Wait()
		if n := len(ev.mailer.calls()); n != 1 {
			t.Fatalf("%d mails for one crossing", n)
		}
		if n := len(ev.events(audit.ActionDiskAlertRaised)); n != 1 {
			t.Fatalf("%d audit events for one crossing", n)
		}
	})
}

func TestMeasureFailures(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), true)
	ctx := context.Background()
	steps := []struct {
		total, free uint64
		err         error
	}{
		{0, 0, errBoom},
		{0, 0, errBoom},
		{0, 0, errors.New("other failure")},
		{1000, 100, nil}, // recovers and raises
		{0, 0, nil},      // empty filesystem
		{0, 0, nil},
		{1000, 2000, nil}, // free above total: nothing used, clears
	}
	for _, s := range steps {
		ev.disk.set(s.total, s.free, s.err)
		ev.m.Evaluate(ctx)
	}
	logs := ev.logs.String()
	if n := strings.Count(logs, "disk usage unavailable"); n != 3 {
		t.Fatalf("%d failure lines: %s", n, logs)
	}
	if n := strings.Count(logs, "disk usage available again"); n != 2 {
		t.Fatalf("%d recovery lines: %s", n, logs)
	}
	if ev.level() != store.DiskAlertLevelNormal || len(ev.events(audit.ActionDiskAlertRaised)) != 1 ||
		len(ev.events(audit.ActionDiskAlertCleared)) != 1 {
		t.Fatal("levels")
	}
}

func TestRepoFailures(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), true)
	ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
	ev.setEmail("ops@example.com", "fr")

	ev.fault.settingsErr = errBoom
	ev.used(900)
	ev.fault.settingsErr = nil
	ev.fault.casErr = errBoom
	ev.used(900)
	ev.fault.casErr = nil
	ev.fault.casLost = true
	ev.used(900)
	ev.fault.casLost = false
	if ev.level() != store.DiskAlertLevelNormal || len(ev.mailer.calls()) != 0 {
		t.Fatal("acted without moving the level")
	}
	logs := ev.logs.String()
	for _, want := range []string{"read the system settings", "store the disk alert level"} {
		if !strings.Contains(logs, want) {
			t.Errorf("no %q in %s", want, logs)
		}
	}

	// The audit and the contact failures are logged; the alert address
	// is still mailed.
	ev.auditor.err = errBoom
	ev.fault.contactsErr = errBoom
	ev.used(900)
	calls := ev.mailer.calls()
	if len(calls) != 1 || len(calls[0]) != 1 || calls[0][0].Message.To[0] != "ops@example.com" {
		t.Fatalf("mails %+v", calls)
	}
	logs = ev.logs.String()
	for _, want := range []string{"record the audit event", "list the super admins"} {
		if !strings.Contains(logs, want) {
			t.Errorf("no %q in %s", want, logs)
		}
	}
	ev.auditor.err, ev.fault.contactsErr = nil, nil

	// A rendering failure skips the recipients of its language only.
	ev.admin(store.RoleSuperAdmin, "other@example.com", "en")
	ev.used(100)
	ev.advance(MailInterval)
	ev.m.render = func(name, lang string, data any) (mail.Message, error) {
		if lang == "fr" {
			return mail.Message{}, errBoom
		}
		return mail.Render(name, lang, data)
	}
	ev.used(900)
	calls = ev.mailer.calls()
	if len(calls) != 2 || len(calls[1]) != 2 || !strings.Contains(ev.logs.String(), "render the alert mail") {
		t.Fatalf("render failure: mails %+v, logs %s", calls, ev.logs.String())
	}
	for _, j := range calls[1] {
		if j.Message.Language != "en" || j.Message.To[0] == "ops@example.com" {
			t.Fatalf("job %+v", j)
		}
	}
	// Every language failing sends nothing, and keeps the mail slot.
	ev.used(100)
	ev.advance(MailInterval)
	ev.m.render = func(string, string, any) (mail.Message, error) { return mail.Message{}, errBoom }
	ev.used(900)
	if len(ev.mailer.calls()) != 2 {
		t.Fatal("mailed although every language failed to render")
	}
	ev.m.render = mail.Render

	// A lost mail slot sends nothing; a failure to record it still mails.
	ev.used(100)
	ev.fault.claimLost = true
	ev.used(900)
	if len(ev.mailer.calls()) != 2 {
		t.Fatal("mailed without the mail slot")
	}
	ev.fault.claimLost = false
	ev.used(100)
	ev.fault.claimErr = errBoom
	ev.used(900)
	if len(ev.mailer.calls()) != 3 || !strings.Contains(ev.logs.String(), "record the time of the alert mail") {
		t.Fatalf("claim failure: %s", ev.logs.String())
	}
	ev.fault.claimErr = nil
	// The slot was never taken since the last real claim: the next
	// crossing still mails.
	ev.used(100)
	ev.used(900)
	if len(ev.mailer.calls()) != 4 {
		t.Fatal("not mailed after the failures")
	}
}

func TestStartCheckClose(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), true)
	var nilMonitor *Monitor
	nilMonitor.Check()
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	ev.m.Evaluate(canceled)
	if ev.disk.calls.Load() != 0 {
		t.Fatal("evaluated with a canceled context")
	}
	if err := ev.m.Close(context.Background()); err != nil {
		t.Fatalf("close before start: %v", err)
	}
	if err := ev.m.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("start after close: %v", err)
	}

	// The loop evaluates at start, on Check and on the ticker.
	m := ev.monitor(true)
	m.interval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel() // the context of Start does not stop the loop
	if err := m.Start(context.Background()); !errors.Is(err, ErrStarted) {
		t.Fatalf("second start: %v", err)
	}
	waitCalls(t, ev.disk, 1)
	m.Check()
	waitCalls(t, ev.disk, 2)
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A Check after Close is dropped.
	before := ev.disk.calls.Load()
	m.Check()
	time.Sleep(20 * time.Millisecond)
	if ev.disk.calls.Load() != before {
		t.Fatal("evaluated after Close")
	}

	ticked := ev.monitor(true)
	ticked.interval = time.Millisecond
	if err := ticked.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitCalls(t, ev.disk, before+3)
	if err := ticked.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCloseTimeout(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), true)
	release := make(chan struct{})
	entered := make(chan struct{})
	m := ev.monitor(true)
	m.measure = func(string) (uint64, uint64, error) {
		close(entered)
		<-release
		return 1000, 1000, nil
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-entered
	m.Check() // pending while the loop is busy: dropped by Close
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := m.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close: %v", err)
	}
	close(release)
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// waitCalls waits for the disk to be measured at least n times.
func waitCalls(t *testing.T, d *disk, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for d.calls.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d measures, want %d", d.calls.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

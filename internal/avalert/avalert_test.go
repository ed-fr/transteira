package avalert

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// The tests that run on every engine are deliberately not parallel: each
// PostgreSQL engine holds its own connection pool, and make test runs every
// package at once against a server limited to 100 connections.

const (
	adminLink = "https://admin.example.com/admin"
	grace     = time.Minute
	waitFor   = 10 * time.Second
)

var (
	errBoom = errors.New("boom")
	_       = repo(storeRepo{})
	_       = Mailer((*mail.Retrier)(nil))
	_       = Auditor((*audit.Writer)(nil))
	_       = Notifier((*notify.Notifier)(nil))

	smtp = mail.Settings{Host: "relay.example.com", Port: 25, Security: mail.SecurityNone, FromAddress: "noreply@example.com", FromName: "TransTeira"}
)

// syncBuffer is a log buffer safe for concurrent use.
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

// count returns the number of log lines containing msg.
func (s *syncBuffer) count(msg string) int { return strings.Count(s.String(), msg) }

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

// recipients returns the recipients of every job sent, sorted.
func (f *fakeMailer) recipients() []string {
	var out []string
	for _, jobs := range f.calls() {
		for _, j := range jobs {
			out = append(out, j.Message.To...)
		}
	}
	slices.Sort(out)
	return out
}

// notifyCall is a call of fakeNotifier.AntivirusUnavailable.
type notifyCall struct {
	tid        tenant.ID
	data       mail.AntivirusUnavailableData
	recipients []notify.Contact
}

// fakeNotifier records the alerts and builds one job per recipient; err
// maps a tenant to the error it returns.
type fakeNotifier struct {
	mu    sync.Mutex
	calls []notifyCall
	err   map[tenant.ID]error
}

func (n *fakeNotifier) AntivirusUnavailable(_ context.Context, t *tenant.Tenant, data mail.AntivirusUnavailableData,
	recipients []notify.Contact,
) ([]mail.Job, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, notifyCall{tid: t.ID, data: data, recipients: recipients})
	if err := n.err[t.ID]; err != nil {
		return nil, err
	}
	jobs := make([]mail.Job, len(recipients))
	for i, r := range recipients {
		jobs[i] = mail.Job{TenantID: string(t.ID), Template: mail.TemplateAntivirusUnavailable, Message: mail.Message{To: []string{r.Email}}}
	}
	return jobs, nil
}

func (n *fakeNotifier) all() []notifyCall {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.calls)
}

// fakePinger answers with err, after running hook when set.
type fakePinger struct {
	mu    sync.Mutex
	err   error
	calls int
	hook  func()
}

func (p *fakePinger) Ping(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.hook != nil {
		p.hook()
	}
	return p.err
}

func (p *fakePinger) set(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

// faultRepo wraps a repo and injects failures.
type faultRepo struct {
	repo
	settingsErr, superErr, contactsErr, tenantErr, waitingErr, claimErr error
	claimLost                                                           bool
	// missing is reported as deleted by tenant.
	missing tenant.ID
	// supers, when set, replaces the super admins of the store.
	supers []store.AdminContact
	// block, when set, makes waiting signal blocked (when set) and wait
	// on it.
	block, blocked chan struct{}
	// empty makes waiting report no transfer waiting.
	empty bool
	// onWaiting, when set, runs at the start of waiting.
	onWaiting func()
}

func (f *faultRepo) settings(ctx context.Context) (store.SystemSettingsRow, error) {
	if f.settingsErr != nil {
		return store.SystemSettingsRow{}, f.settingsErr
	}
	return f.repo.settings(ctx)
}

func (f *faultRepo) superAdminContacts(ctx context.Context) ([]store.AdminContact, error) {
	if f.superErr != nil {
		return nil, f.superErr
	}
	if f.supers != nil {
		return slices.Clone(f.supers), nil
	}
	return f.repo.superAdminContacts(ctx)
}

func (f *faultRepo) tenantContacts(ctx context.Context, tid tenant.ID) ([]store.AdminContact, error) {
	if f.contactsErr != nil {
		return nil, f.contactsErr
	}
	return f.repo.tenantContacts(ctx, tid)
}

func (f *faultRepo) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if f.tenantErr != nil {
		return nil, f.tenantErr
	}
	if tid == f.missing {
		return nil, store.ErrNotFound
	}
	return f.repo.tenant(ctx, tid)
}

func (f *faultRepo) waiting(ctx context.Context) ([]store.TenantScanning, error) {
	if f.onWaiting != nil {
		f.onWaiting()
	}
	if f.block != nil {
		if f.blocked != nil {
			close(f.blocked)
			f.blocked = nil
		}
		<-f.block
	}
	if f.waitingErr != nil {
		return nil, f.waitingErr
	}
	if f.empty {
		return nil, nil
	}
	return f.repo.waiting(ctx)
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

// env is a monitor over a real database with fake mail dependencies.
type env struct {
	t        *testing.T
	db       *store.DB
	system   *fakeMailer
	tenants  *fakeMailer
	notifier *fakeNotifier
	pinger   *fakePinger
	fault    *faultRepo
	auditor  *faultAuditor
	logs     *syncBuffer
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

// newEnv returns an environment on e whose monitor has system mail when
// withMail is set.
func newEnv(t *testing.T, e storetest.Engine, withMail bool) *env {
	t.Helper()
	ev := &env{
		t: t, db: openDB(t, e), system: &fakeMailer{}, tenants: &fakeMailer{}, notifier: &fakeNotifier{},
		pinger: &fakePinger{err: errBoom}, logs: &syncBuffer{}, published: &events.Recorder{},
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
		AdminLink: adminLink, Notifier: ev.notifier, TenantMailer: ev.tenants, Pinger: ev.pinger, Grace: grace,
		Now: ev.now, Logger: slog.New(slog.NewTextHandler(ev.logs, nil)), Events: ev.published,
	}
	if withMail {
		opts.SystemMailer, opts.SMTP = ev.system, smtp
	}
	m, err := newMonitor(ev.fault, ev.auditor, opts)
	if err != nil {
		ev.t.Fatal(err)
	}
	return m
}

// tenant creates an active tenant.
func (ev *env) tenant() *tenant.Tenant {
	ev.t.Helper()
	ev.n++
	tn, err := ev.db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: fmt.Sprintf("Entity %d", ev.n), FQDN: fmt.Sprintf("transfer.entity-%d.example.com", ev.n),
		DefaultLanguage: "en", MaxTransferBytes: 1 << 30, StorageQuotaBytes: 10 << 30,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return tn
}

// admin creates an activated administrator.
func (ev *env) admin(role store.AdminRole, email, lang string, tids ...tenant.ID) {
	ev.t.Helper()
	ev.n++
	_, err := ev.db.Admins().Create(context.Background(), store.Admin{
		Username: fmt.Sprintf("admin%d", ev.n), Email: email, Role: role, TenantIDs: tids,
		PasswordHash: "$argon2id$test", Language: lang,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
}

// alertEmail sets the alert address of the system settings.
func (ev *env) alertEmail(email, lang string) {
	ev.t.Helper()
	_, err := ev.db.SystemSettings().UpdateTx(context.Background(), func(_ *store.SystemTx, s *store.SystemSettingsRow) error {
		s.AlertEmail, s.AlertEmailLanguage = email, lang
		return nil
	})
	if err != nil {
		ev.t.Fatal(err)
	}
}

// scanning stores n transfers of tn waiting for the antivirus.
func (ev *env) scanning(tn *tenant.Tenant, n int) {
	ev.t.Helper()
	ctx := context.Background()
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	for range n {
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			wk := store.WrappedKey{ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeDEK, KeyID: "mk_0123456789abcdef", Blob: []byte("k")}
			if err := ev.db.WrappedKeys().CreateTx(ctx, tx, wk); err != nil {
				return err
			}
			upl, err := id.NewUploadToken()
			if err != nil {
				return err
			}
			name := make([]byte, store.StorageNameLen/2)
			_, _ = rand.Read(name)
			f := store.TransferFile{
				ID: id.New(id.File), Name: "file.bin", Size: 10, DEKKeyID: wk.ID, StorageName: hex.EncodeToString(name),
				UploadID: upl, SHA256: strings.Repeat("ab", 32), CiphertextSize: 100, UploadedAt: time.Now(),
			}
			tr := store.Transfer{ID: id.New(id.Transfer), SenderEmail: "alice@entity-a.example.com", SenderKind: store.DepositorInternal, ExpiryDays: 7}
			if err := ev.db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@example.com"}, []store.TransferFile{f}); err != nil {
				return err
			}
			return ev.db.Transfers().FinalizeTx(ctx, tx, tr.ID, time.Now())
		})
		if err != nil {
			ev.t.Fatal(err)
		}
	}
}

// events returns the global audit events of action, newest first.
func (ev *env) events(action audit.Action) []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{Action: string(action)})
	if err != nil {
		ev.t.Fatal(err)
	}
	return page.Items
}

// details decodes the details of an audit event.
func details(t *testing.T, e store.AuditEvent) map[string]float64 {
	t.Helper()
	var out map[string]float64
	if err := json.Unmarshal(e.Details, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// outage reports an outage, evaluates it, lets the grace period expire
// and evaluates again.
func (ev *env) outage() {
	ev.t.Helper()
	ctx := context.Background()
	ev.m.ClamdDown()
	if next := ev.m.Evaluate(ctx); !next.Equal(ev.now().Add(grace)) {
		ev.t.Fatalf("Evaluate during the grace period = %v, want the end of the grace period", next)
	}
	ev.advance(grace)
	if next := ev.m.Evaluate(ctx); !next.Equal(ev.now().Add(grace)) {
		ev.t.Fatalf("Evaluate after the grace period = %v, want a new evaluation after the grace period", next)
	}
}

// busy creates a tenant with a transfer waiting for the antivirus.
func (ev *env) busy() *tenant.Tenant {
	ev.t.Helper()
	tn := ev.tenant()
	ev.scanning(tn, 1)
	return tn
}

// recover reports the end of the outage and evaluates it.
func (ev *env) recover() {
	ev.t.Helper()
	ev.m.ClamdUp()
	if next := ev.m.Evaluate(context.Background()); !next.IsZero() {
		ev.t.Fatalf("Evaluate after the recovery = %v, want zero", next)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	n, m, a := &fakeNotifier{}, &fakeMailer{}, &faultAuditor{}
	valid := Options{AdminLink: adminLink, Notifier: n, TenantMailer: m}
	for name, c := range map[string]struct {
		a    Auditor
		opts Options
	}{
		"auditor":      {nil, valid},
		"notifier":     {a, Options{AdminLink: adminLink, TenantMailer: m}},
		"mailer":       {a, Options{AdminLink: adminLink, Notifier: n}},
		"link":         {a, Options{AdminLink: "/admin", Notifier: n, TenantMailer: m}},
		"link scheme":  {a, Options{AdminLink: "ftp://admin.example.com", Notifier: n, TenantMailer: m}},
		"link parse":   {a, Options{AdminLink: "http://[::1", Notifier: n, TenantMailer: m}},
		"system smtp":  {a, Options{AdminLink: adminLink, Notifier: n, TenantMailer: m, SystemMailer: m}},
		"system smtp2": {a, Options{AdminLink: adminLink, Notifier: n, TenantMailer: m, SystemMailer: m, SMTP: mail.Settings{Host: "x"}}},
	} {
		if _, err := newMonitor(&faultRepo{}, c.a, c.opts); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("%s: %v, want ErrInvalidOptions", name, err)
		}
	}
	if _, err := New(nil, a, valid); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("New(nil db) = %v", err)
	}
	mon, err := newMonitor(&faultRepo{}, a, valid)
	if err != nil || mon.grace != DefaultGrace || mon.now == nil || mon.logger == nil || mon.pinger != nil {
		t.Fatalf("defaults: %+v, %v", mon, err)
	}
	// A nil monitor ignores the reports.
	var nilMon *Monitor
	nilMon.ClamdDown()
	nilMon.ClamdUp()
	if got := seconds(-time.Second); got != 0 {
		t.Errorf("seconds(-1s) = %d", got)
	}
	if got := seconds(90*time.Second + time.Millisecond); got != 90 {
		t.Errorf("seconds(90.001s) = %d", got)
	}
}

// TestRaiseAndClear raises the alert after the grace period: audited, the
// super admins and the alert address mailed through the system mail, the
// administrators of every active tenant with waiting transfers mailed
// through the tenant queue; then clears it when clamd answers again.
func TestRaiseAndClear(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		// The store-backed monitor of the application builds too.
		if _, err := New(ev.db, ev.auditor, Options{AdminLink: adminLink, Notifier: ev.notifier, TenantMailer: ev.tenants}); err != nil {
			t.Fatal(err)
		}
		a, b, c := ev.tenant(), ev.tenant(), ev.tenant()
		ev.admin(store.RoleSuperAdmin, "root@example.com", "fr")
		ev.admin(store.RoleDelegatedAdmin, "anna@entity-a.example.com", "en", a.ID)
		ev.alertEmail("ROOT@example.com", "en") // a duplicate of the super admin, ignoring case
		ev.scanning(a, 2)
		ev.scanning(b, 1) // b has no delegated admin: the super admins
		_ = c             // c has nothing waiting
		start := ev.now()
		ev.outage()

		raised := ev.events(audit.ActionAntivirusAlertRaised)
		if len(raised) != 1 || raised[0].Actor != actor || raised[0].ObjectID != objectID || raised[0].TenantID != "" {
			t.Fatalf("raised events: %+v", raised)
		}
		if d := details(t, raised[0]); d["outageSeconds"] != 60 || d["waitingTransfers"] != 3 || d["tenants"] != 2 {
			t.Errorf("raised details: %v", d)
		}
		sys := ev.system.calls()
		if len(sys) != 1 || len(sys[0]) != 1 {
			t.Fatalf("system mails: %+v", sys)
		}
		j := sys[0][0]
		if j.TenantID != MailTenantID || j.Template != mail.TemplateAntivirusAlert || j.Settings != smtp ||
			j.Message.To[0] != "root@example.com" || j.Message.Language != "fr" ||
			!strings.Contains(j.Message.Text, "3 ;") || !strings.Contains(j.Message.Text, adminLink) {
			t.Errorf("system mail: %+v", j)
		}
		calls := ev.notifier.all()
		if len(calls) != 2 {
			t.Fatalf("tenant notifications: %+v", calls)
		}
		for _, call := range calls {
			want := map[tenant.ID]struct {
				to string
				n  int
			}{a.ID: {"anna@entity-a.example.com", 2}, b.ID: {"root@example.com", 1}}[call.tid]
			if len(call.recipients) != 1 || call.recipients[0].Email != want.to || call.data.WaitingTransfers != want.n ||
				!call.data.Since.Equal(start) || call.data.AdminLink != adminLink || call.data.TenantName == "" {
				t.Errorf("tenant %s notification: %+v", call.tid, call)
			}
		}
		if got := ev.tenants.recipients(); !slices.Equal(got, []string{"anna@entity-a.example.com", "root@example.com"}) {
			t.Errorf("tenant mails to %v", got)
		}
		if ev.logs.count("antivirus alert: clamd has been unreachable") != 1 {
			t.Errorf("logs: %s", ev.logs)
		}

		// Once per incident: more reports and evaluations change nothing.
		ev.m.ClamdDown()
		ev.advance(time.Hour)
		ev.m.Evaluate(context.Background())
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 1 || len(ev.system.calls()) != 1 || len(ev.notifier.all()) != 2 {
			t.Error("the alert was raised twice in one incident")
		}

		ev.recover()
		cleared := ev.events(audit.ActionAntivirusAlertCleared)
		if len(cleared) != 1 || details(t, cleared[0])["outageSeconds"] != 3660 {
			t.Fatalf("cleared events: %+v", cleared)
		}
		if len(ev.system.calls()) != 1 || len(ev.tenants.calls()) != 2 || ev.logs.count("antivirus alert cleared") != 1 {
			t.Error("the recovery mailed someone")
		}
		if strings.Contains(ev.logs.String(), "@") {
			t.Errorf("logs hold an address: %s", ev.logs)
		}
	})
}

// TestRecoveryWithinGrace forgets an outage shorter than the grace period:
// nothing audited, nothing mailed.
func TestRecoveryWithinGrace(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ctx := context.Background()
		ev.m.ClamdDown()
		ev.m.Evaluate(ctx)
		ev.advance(grace - time.Second)
		if next := ev.m.Evaluate(ctx); next.IsZero() {
			t.Fatal("pending incident without a deadline")
		}
		ev.recover()
		ev.advance(grace)
		ev.m.Evaluate(ctx)
		// Down and up between two evaluations: nothing either.
		ev.m.ClamdDown()
		ev.m.ClamdUp()
		ev.advance(grace)
		ev.m.Evaluate(ctx)
		if n := len(ev.events(audit.ActionAntivirusAlertRaised)) + len(ev.events(audit.ActionAntivirusAlertCleared)); n != 0 {
			t.Errorf("%d audit events", n)
		}
		if len(ev.system.calls()) != 0 || len(ev.tenants.calls()) != 0 || ev.pinger.calls != 0 {
			t.Error("a short outage mailed or pinged")
		}
		if ev.logs.count("antivirus outage ended before the alert: clamd answers again") != 1 {
			t.Errorf("logs: %s", ev.logs)
		}
	})
}

// TestMailInterval mails at most once an hour, across incidents and
// restarts, while every raise and clear stays audited.
func TestMailInterval(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		a := ev.tenant()
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ev.scanning(a, 1)
		ev.outage()
		ev.recover()
		ev.outage() // a second incident within the hour
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 2 || len(ev.system.calls()) != 1 || len(ev.tenants.calls()) != 1 {
			t.Fatalf("second incident: %d raised, %d system and %d tenant mails",
				len(ev.events(audit.ActionAntivirusAlertRaised)), len(ev.system.calls()), len(ev.tenants.calls()))
		}
		if ev.logs.count("antivirus alert not mailed yet: an alert mail was sent less than an hour ago") != 1 {
			t.Errorf("logs: %s", ev.logs)
		}
		ev.recover()
		// A restart keeps the interval: the slot is in the database.
		ev.m = ev.monitor(true)
		ev.outage()
		if len(ev.system.calls()) != 1 {
			t.Error("a restart reset the mail interval")
		}
		ev.recover()
		ev.advance(time.Hour)
		ev.outage()
		if len(ev.system.calls()) != 2 || len(ev.tenants.calls()) != 2 || len(ev.events(audit.ActionAntivirusAlertCleared)) != 3 {
			t.Errorf("an hour later: %d system and %d tenant mails", len(ev.system.calls()), len(ev.tenants.calls()))
		}
	})
}

// TestIncidentChange ends a raised incident and starts a new one when
// clamd came back and failed again between two evaluations.
func TestIncidentChange(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, false)
		ev.busy()
		ev.outage()
		ev.m.ClamdUp()
		ev.advance(time.Second)
		ev.m.ClamdDown()
		if next := ev.m.Evaluate(context.Background()); !next.Equal(ev.now().Add(grace)) {
			t.Fatalf("new incident deadline = %v", next)
		}
		if len(ev.events(audit.ActionAntivirusAlertCleared)) != 1 || len(ev.events(audit.ActionAntivirusAlertRaised)) != 1 {
			t.Error("the first incident was not cleared")
		}
		ev.advance(grace)
		ev.m.Evaluate(context.Background())
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 2 {
			t.Error("the second incident was not raised")
		}
	})
}

// TestPingPostpones postpones the alert while clamd answers a ping, and
// raises it once the ping fails too.
func TestPingPostpones(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.busy()
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ctx := context.Background()
		ev.pinger.set(nil)
		ev.m.ClamdDown()
		ev.m.Evaluate(ctx)
		ev.advance(grace)
		if next := ev.m.Evaluate(ctx); !next.Equal(ev.now().Add(grace)) {
			t.Fatalf("postponed deadline = %v", next)
		}
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 0 || ev.logs.count("antivirus alert postponed") != 1 {
			t.Fatalf("postponed: %s", ev.logs)
		}
		ev.pinger.set(errBoom)
		ev.advance(grace)
		ev.m.Evaluate(ctx)
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 1 || len(ev.system.calls()) != 1 {
			t.Error("not raised once the ping failed")
		}
		// Without a pinger, the reports of the worker alone raise.
		ev.recover()
		ev.m.pinger = nil
		ev.advance(time.Hour)
		ev.outage()
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 2 {
			t.Error("not raised without a pinger")
		}
	})
}

// TestWithoutSystemMail logs the alert and audits it without system mail;
// the tenants are still mailed.
func TestWithoutSystemMail(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, false)
		a := ev.tenant()
		ev.admin(store.RoleDelegatedAdmin, "anna@entity-a.example.com", "en", a.ID)
		ev.scanning(a, 1)
		ev.outage()
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 1 || len(ev.system.calls()) != 0 || len(ev.tenants.calls()) != 1 {
			t.Error("without system mail")
		}
		if ev.logs.count("TT_SYSTEM_SMTP_HOST") != 1 {
			t.Errorf("logs: %s", ev.logs)
		}
		// Nobody to mail at all: nothing claimed, nothing sent.
		ev.recover()
		ev.advance(2 * time.Hour)
		ev.fault.tenantErr = errBoom
		ev.outage()
		if len(ev.tenants.calls()) != 1 {
			t.Error("mailed a tenant that could not be read")
		}
		ev.fault.tenantErr = nil
		ev.recover()
		ev.outage()
		if len(ev.tenants.calls()) != 2 {
			t.Error("the slot was taken although nothing was mailed")
		}
	})
}

// TestFailWaitingAndAudit checks that the super admins are still mailed when the waiting transfers cannot be counted, and a failed audit is logged.
func TestFailWaitingAndAudit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ev.fault.waitingErr = errBoom
		ev.auditor.err = errBoom
		ev.outage()
		if len(ev.system.calls()) != 1 || len(ev.notifier.all()) != 0 {
			t.Fatal("the super admins were not mailed")
		}
		// The counts are unknown: left out of the mail, never shown as 0.
		if text := ev.system.calls()[0][0].Message.Text; !strings.Contains(text, "could not be determined") ||
			strings.Contains(text, "waiting for analysis: 0") {
			t.Errorf("system mail: %s", text)
		}
		ev.auditor.err = nil
		ev.recover()
		ev.advance(time.Hour)
		ev.outage()
		raised := ev.events(audit.ActionAntivirusAlertRaised)
		if len(raised) != 1 || string(raised[0].Details) != `{"outageSeconds":60}` {
			t.Errorf("raised events with unknown counts: %+v", raised)
		}
		ev.recover()
		logs := ev.logs.String()
		for _, want := range []string{"failed to count the transfers", "failed to record the audit event"} {
			if !strings.Contains(logs, want) {
				t.Errorf("logs lack %q: %s", want, logs)
			}
		}
	})
}

// TestFailRecipients checks that the alert address is still mailed when the super admins cannot be listed, and nobody when neither can be read.
func TestFailRecipients(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.busy()
		ev.alertEmail("ops@example.com", "fr")
		ev.fault.superErr = errBoom
		ev.outage()
		// The alert address is still reached.
		if got := ev.system.recipients(); !slices.Equal(got, []string{"ops@example.com"}) {
			t.Errorf("system mails to %v", got)
		}
		ev.recover()
		ev.advance(time.Hour)
		ev.fault.settingsErr = errBoom
		ev.outage()
		if len(ev.system.calls()) != 1 || ev.logs.count("no recipient") != 1 || ev.logs.count("failed to read the alert address") != 1 {
			t.Errorf("no recipient: %s", ev.logs)
		}
	})
}

// TestFailRender checks that a language that fails to render skips its recipients only.
func TestFailRender(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.busy()
		ev.fault.supers = []store.AdminContact{
			{Email: "root@example.com", Language: "fr"},
			{Email: "other@example.com", Language: "de"}, // unsupported: the default language
			{Email: "third@example.com", Language: "fr"},
		}
		ev.m.render = func(name, lang string, data any) (mail.Message, error) {
			if lang == "fr" {
				return mail.Message{}, errBoom
			}
			return mail.Render(name, lang, data)
		}
		ev.outage()
		if got := ev.system.recipients(); !slices.Equal(got, []string{"other@example.com"}) {
			t.Errorf("system mails to %v", got)
		}
		if ev.logs.count("failed to render the alert mail") != 1 {
			t.Errorf("logs: %s", ev.logs)
		}
		// Every language failing: nothing to send.
		ev.recover()
		ev.advance(time.Hour)
		ev.m.render = func(string, string, any) (mail.Message, error) { return mail.Message{}, errBoom }
		ev.outage()
		if len(ev.system.calls()) != 1 {
			t.Error("mailed without a rendered message")
		}
	})
}

// TestFailClaim checks that an unreadable mail slot mails anyway, a lost one mails nobody.
func TestFailClaim(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.busy()
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ev.fault.claimErr = errBoom
		ev.outage()
		if len(ev.system.calls()) != 1 || ev.logs.count("failed to record the time of the alert mail") != 1 {
			t.Error("an unreadable slot must not stop the alert")
		}
		ev.recover()
		ev.fault.claimErr, ev.fault.claimLost = nil, true
		ev.outage()
		if len(ev.system.calls()) != 1 {
			t.Error("mailed with the slot lost")
		}
	})
}

// TestFailTenants checks that a tenant that cannot be notified is logged and skipped.
func TestFailTenants(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		a, b, c, d, gone := ev.tenant(), ev.tenant(), ev.tenant(), ev.tenant(), ev.tenant()
		ev.admin(store.RoleDelegatedAdmin, "anna@entity-a.example.com", "en", a.ID)
		ev.admin(store.RoleDelegatedAdmin, "bruno@entity-b.example.com", "en", b.ID)
		for _, tn := range []*tenant.Tenant{a, b, c, d, gone} {
			ev.scanning(tn, 1)
		}
		ev.notifier.err = map[tenant.ID]error{a.ID: notify.ErrNoSMTP, b.ID: errBoom}
		// c has no administrator at all (no super admin either); d is
		// being deleted; gone is deleted.
		if err := ev.db.Tenants().SetStatus(context.Background(), d.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		ev.fault.missing = gone.ID
		ev.outage()
		if len(ev.tenants.calls()) != 0 || len(ev.notifier.all()) != 2 {
			t.Errorf("tenant calls: %+v", ev.notifier.all())
		}
		logs := ev.logs.String()
		for _, want := range []string{"it has no SMTP settings", "failed to build the alert mails", "no administrator to notify"} {
			if !strings.Contains(logs, want) {
				t.Errorf("logs lack %q: %s", want, logs)
			}
		}
		ev.recover()
		ev.advance(time.Hour)
		ev.fault.contactsErr = errBoom
		ev.outage()
		if ev.logs.count("failed to list the administrators to notify") != 3 {
			t.Errorf("logs: %s", ev.logs)
		}
		ev.recover()
		ev.advance(time.Hour)
		ev.fault.contactsErr = nil
		ev.fault.superErr = errBoom
		ev.outage()
		if ev.logs.count("failed to list the administrators to notify") != 4 {
			t.Errorf("super admin fallback failure: %s", ev.logs)
		}
	})
}

// TestNothingWaiting closes the outage itself when no transfer is left to
// analyze, since the worker would never report its end: a pending outage
// is not raised, a raised one clears once clamd answers a ping; the next
// failure report of the worker starts a new outage.
func TestNothingWaiting(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ev.busy()
		ctx := context.Background()
		ev.fault.empty = true
		ev.m.ClamdDown()
		ev.m.Evaluate(ctx)
		ev.advance(grace)
		if next := ev.m.Evaluate(ctx); !next.IsZero() || ev.m.phase != idle {
			t.Fatalf("pending outage with nothing waiting: next %v, phase %d", next, ev.m.phase)
		}
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 0 || ev.logs.count("no transfer waits for analysis any more") != 1 {
			t.Fatalf("raised with nothing waiting: %s", ev.logs)
		}
		// The worker still reports the outage: it stays closed until a new
		// failure report.
		if next := ev.m.Evaluate(ctx); !next.IsZero() {
			t.Fatalf("closed outage reopened without a report: %v", next)
		}
		ev.fault.empty = false
		ev.advance(time.Minute)
		ev.m.ClamdDown()
		if next := ev.m.Evaluate(ctx); !next.Equal(ev.now().Add(grace)) {
			t.Fatalf("new outage deadline = %v", next)
		}
		ev.advance(grace)
		ev.m.Evaluate(ctx)
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 1 || len(ev.system.calls()) != 1 {
			t.Fatal("the new outage was not raised")
		}
		// Raised, then the transfers go away: while clamd does not answer,
		// the alert stays; once it answers a ping, it clears.
		ev.fault.empty = true
		ev.advance(grace)
		if next := ev.m.Evaluate(ctx); !next.Equal(ev.now().Add(grace)) || ev.m.phase != raised {
			t.Fatalf("raised alert with clamd still silent: next %v, phase %d", next, ev.m.phase)
		}
		ev.pinger.set(nil)
		ev.advance(grace)
		if next := ev.m.Evaluate(ctx); !next.IsZero() || ev.m.phase != idle {
			t.Fatalf("raised alert with nothing waiting and clamd answering: next %v, phase %d", next, ev.m.phase)
		}
		cleared := ev.events(audit.ActionAntivirusAlertCleared)
		if len(cleared) != 1 || details(t, cleared[0])["outageSeconds"] != 180 {
			t.Fatalf("cleared events: %+v", cleared)
		}
		// The worker reports its end later: nothing more happens.
		ev.recover()
		if len(ev.events(audit.ActionAntivirusAlertCleared)) != 1 {
			t.Error("cleared twice")
		}
	})
}

// TestPostponementCap raises the alert after MaxPostponements
// postponements by a ping while the worker keeps failing (clamd answering
// PING but not the analyses).
func TestPostponementCap(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ev.busy()
		ctx := context.Background()
		ev.pinger.set(nil)
		ev.m.ClamdDown()
		ev.m.Evaluate(ctx)
		for i := range MaxPostponements {
			ev.advance(grace)
			ev.m.ClamdDown() // the worker keeps failing
			ev.m.Evaluate(ctx)
			if len(ev.events(audit.ActionAntivirusAlertRaised)) != 0 {
				t.Fatalf("raised after %d postponements", i)
			}
		}
		ev.advance(grace)
		ev.m.Evaluate(ctx)
		raised := ev.events(audit.ActionAntivirusAlertRaised)
		if len(raised) != 1 || details(t, raised[0])["outageSeconds"] != float64(4*grace/time.Second) || len(ev.system.calls()) != 1 {
			t.Errorf("not raised after the cap: %+v", raised)
		}
		if ev.logs.count("antivirus alert postponed") != MaxPostponements {
			t.Errorf("logs: %s", ev.logs)
		}
	})
}

// TestMailRetry mails an alert raised within the hour of the previous mail
// once the hourly slot frees, while the outage lasts and transfers wait.
func TestMailRetry(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ev.busy()
		ctx := context.Background()
		ev.outage()
		ev.recover()
		ev.advance(10 * time.Minute)
		ev.outage() // within the hour: not mailed yet
		if len(ev.system.calls()) != 1 || !ev.m.mailPending {
			t.Fatalf("second outage: %d mails, pending %v", len(ev.system.calls()), ev.m.mailPending)
		}
		// Still within the hour: retried, not mailed.
		ev.advance(grace)
		ev.m.Evaluate(ctx)
		if len(ev.system.calls()) != 1 || !ev.m.mailPending {
			t.Fatal("mailed within the hour")
		}
		// Nothing waits for a while: no retry, the alert stays raised.
		ev.fault.empty = true
		ev.advance(time.Hour)
		ev.m.Evaluate(ctx)
		if len(ev.system.calls()) != 1 || ev.m.phase != raised {
			t.Fatal("mailed with nothing waiting")
		}
		// Transfers wait again: the slot is free, the alert is mailed once.
		ev.fault.empty = false
		ev.advance(grace)
		ev.m.Evaluate(ctx)
		ev.advance(grace)
		ev.m.Evaluate(ctx)
		if len(ev.system.calls()) != 2 || len(ev.tenants.calls()) != 2 || ev.m.mailPending {
			t.Errorf("retry: %d system and %d tenant mails, pending %v", len(ev.system.calls()), len(ev.tenants.calls()), ev.m.mailPending)
		}
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 2 {
			t.Error("the retry audited the raise again")
		}
	})
}

// TestDisabledSystemMailLoggedOnce warns about the missing system SMTP
// server when the alert is raised, not at each mail retry.
func TestDisabledSystemMailLoggedOnce(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, false)
		a := ev.busy()
		ev.admin(store.RoleDelegatedAdmin, "anna@entity-a.example.com", "en", a.ID)
		ev.fault.claimLost = true
		ev.outage()
		for range 3 {
			ev.advance(grace)
			ev.m.Evaluate(context.Background())
		}
		if n := ev.logs.count("TT_SYSTEM_SMTP_HOST"); n != 1 {
			t.Errorf("%d warnings about the system SMTP server, want 1", n)
		}
		if n := ev.logs.count("antivirus alert not mailed yet"); n != 4 {
			t.Errorf("%d retries, want 4", n)
		}
	})
}

// TestCloseDuringCount decides nothing when the monitor is closed while
// it counts the transfers waiting.
func TestCloseDuringCount(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ev.busy()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ev.m.ClamdDown()
		ev.m.Evaluate(ctx)
		ev.advance(grace)
		ev.fault.onWaiting = cancel
		if next := ev.m.Evaluate(ctx); !next.IsZero() || ev.m.phase != pending {
			t.Errorf("Evaluate closed during the count: next %v, phase %d", next, ev.m.phase)
		}
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 0 || len(ev.system.calls()) != 0 {
			t.Error("raised while closing")
		}
	})
}

// TestReportDuringDismiss keeps the outage open when the worker reports a
// failure while the monitor finds nothing waiting: a transfer may have
// arrived since the count.
func TestReportDuringDismiss(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ctx := context.Background()
		ev.fault.empty = true
		ev.m.ClamdDown()
		ev.m.Evaluate(ctx)
		ev.advance(grace)
		ev.fault.onWaiting = ev.m.ClamdDown
		if next := ev.m.Evaluate(ctx); !next.Equal(ev.now().Add(grace)) || ev.m.phase != pending {
			t.Fatalf("outage closed despite a new report: next %v, phase %d", next, ev.m.phase)
		}
		// Without a new report, the next evaluation closes it.
		ev.fault.onWaiting = nil
		ev.advance(grace)
		if next := ev.m.Evaluate(ctx); !next.IsZero() || ev.m.phase != idle {
			t.Fatalf("outage not closed: next %v, phase %d", next, ev.m.phase)
		}
		// Raised, the same holds once clamd answers.
		ev.fault.empty = false
		ev.busy()
		ev.m.ClamdDown()
		ev.m.Evaluate(ctx)
		ev.advance(grace)
		ev.m.Evaluate(ctx)
		if ev.m.phase != raised {
			t.Fatal("not raised")
		}
		ev.fault.empty = true
		ev.pinger.set(nil)
		ev.fault.onWaiting = ev.m.ClamdDown
		ev.advance(grace)
		ev.m.Evaluate(ctx)
		if ev.m.phase != raised || len(ev.events(audit.ActionAntivirusAlertCleared)) != 0 {
			t.Error("raised alert cleared despite a new report")
		}
	})
}

// TestCloseDuringPing decides nothing when the monitor is closed during
// the confirmation ping.
func TestCloseDuringPing(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		ev.busy()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ev.m.ClamdDown()
		ev.m.Evaluate(ctx)
		ev.advance(grace)
		ev.pinger.hook = cancel
		if next := ev.m.Evaluate(ctx); !next.IsZero() || ev.m.phase != pending {
			t.Errorf("Evaluate closed during the ping: next %v, phase %d", next, ev.m.phase)
		}
		if len(ev.events(audit.ActionAntivirusAlertRaised)) != 0 || len(ev.system.calls()) != 0 {
			t.Error("raised while closing")
		}
	})
}

// TestRun drives the monitor through Start, the reports of the worker and
// Close, with the real clock.
func TestRun(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, true)
		ev.busy()
		ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
		m, err := newMonitor(ev.fault, ev.auditor, Options{
			AdminLink: adminLink, Notifier: ev.notifier, TenantMailer: ev.tenants, SystemMailer: ev.system, SMTP: smtp,
			Grace: 50 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(ev.logs, nil)),
		})
		if err != nil {
			t.Fatal(err)
		}
		// A report before the start is evaluated when the loop starts.
		m.ClamdDown()
		if err := m.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := m.Start(context.Background()); !errors.Is(err, ErrStarted) {
			t.Errorf("second Start = %v", err)
		}
		eventually(t, "the alert", func() bool { return len(ev.system.calls()) == 1 })
		m.ClamdUp()
		eventually(t, "the clear", func() bool { return len(ev.events(audit.ActionAntivirusAlertCleared)) == 1 })
		// A short outage, with the reports racing the loop.
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for range 50 {
					m.ClamdDown()
					m.ClamdUp()
				}
			})
		}
		wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(ctx); err != nil {
			t.Errorf("second Close = %v", err)
		}
		if err := m.Start(context.Background()); !errors.Is(err, ErrClosed) {
			t.Errorf("Start after Close = %v", err)
		}
		if n := len(ev.events(audit.ActionAntivirusAlertRaised)); n != 1 {
			t.Errorf("%d raised events, want 1", n)
		}
		// Evaluate does nothing once its context is done.
		done, stop := context.WithCancel(context.Background())
		stop()
		m.ClamdDown()
		if next := m.Evaluate(done); !next.IsZero() {
			t.Errorf("Evaluate(done) = %v", next)
		}
	})
}

// TestCloseTimeout returns the error of the context when Run is still
// busy, and Close before Start returns at once.
func TestCloseTimeout(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, false)
		if err := ev.monitor(false).Close(context.Background()); err != nil {
			t.Errorf("Close before Start = %v", err)
		}
		ev.fault.block, ev.fault.blocked = make(chan struct{}), make(chan struct{})
		blocked := ev.fault.blocked
		m, err := newMonitor(ev.fault, ev.auditor, Options{
			AdminLink: adminLink, Notifier: ev.notifier, TenantMailer: ev.tenants, Grace: time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		m.ClamdDown()
		if err := m.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		<-blocked // the evaluation waits on block
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if err := m.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Close = %v, want the deadline", err)
		}
		close(ev.fault.block)
		if err := m.Close(context.Background()); err != nil {
			t.Errorf("Close after unblocking = %v", err)
		}
	})
}

// eventually waits until cond holds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

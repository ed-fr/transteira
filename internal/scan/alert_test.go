package scan

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/avalert"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

var _ OutageObserver = (*avalert.Monitor)(nil)

// fakeObserver counts the outage reports of the worker.
type fakeObserver struct {
	mu         sync.Mutex
	downs, ups int
}

func (o *fakeObserver) ClamdDown() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.downs++
}

func (o *fakeObserver) ClamdUp() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ups++
}

func (o *fakeObserver) counts() (downs, ups int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.downs, o.ups
}

// recordMailer records the jobs of the alert mails.
type recordMailer struct {
	mu   sync.Mutex
	jobs []mail.Job
}

func (r *recordMailer) Send(_ context.Context, jobs []mail.Job, _ ...slog.Attr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jobs = append(r.jobs, jobs...)
}

func (r *recordMailer) snapshot() []mail.Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.jobs)
}

// TestOutageObserver reports every failure to reach clamd, and the end of
// the outage once, whatever the number of transfers and retries.
func TestOutageObserver(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		obs := &fakeObserver{}
		ev.w.observer = obs
		ev.clamd.Stop()
		trf1 := ev.scanning(ev.a, clean(10))
		trf2 := ev.scanning(ev.b, clean(10))
		ev.start()
		// The scanner counts a scan when it starts, before its failure is
		// reported: wait on the reports themselves.
		ev.waitUntil("6 failure reports", func() bool { downs, _ := obs.counts(); return downs >= 6 })
		if _, ups := obs.counts(); ups != 0 {
			t.Fatalf("during the outage: %d up reports, want 0", ups)
		}
		ev.clamd.Restart(t)
		ev.waitStatus(ev.a, trf1, store.TransferAvailable)
		ev.waitStatus(ev.b, trf2, store.TransferAvailable)
		if _, ups := obs.counts(); ups != 1 {
			t.Errorf("after the recovery: %d up reports, want 1", ups)
		}
	})
}

// alertEnv is a worker env whose outages feed a real antivirus alert
// monitor over the same database, with recorded mailers and the real
// notifier.
type alertEnv struct {
	*env
	system, tenants *recordMailer
	alerts          *avalert.Monitor
}

// newAlertEnv builds an alertEnv with the grace period of the alert; a
// super admin and a delegated admin of tenant A exist.
func newAlertEnv(t *testing.T, e storetest.Engine, grace time.Duration) *alertEnv {
	t.Helper()
	ctx := context.Background()
	ev := &alertEnv{env: newEnv(t, e, Options{}), system: &recordMailer{}, tenants: &recordMailer{}}
	for _, a := range []store.Admin{
		{Username: "root", Email: "root@example.com", Role: store.RoleSuperAdmin, PasswordHash: "$argon2id$test", Language: "fr"},
		{
			Username: "anna", Email: "anna@entity-a.example.com", Role: store.RoleDelegatedAdmin, PasswordHash: "$argon2id$test",
			Language: "en", TenantIDs: []tenant.ID{ev.a.ID},
		},
	} {
		if _, err := ev.db.Admins().Create(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	notifier := notify.New(ev.vault, ev.db.SMTPSettings(), nil, notify.Options{Overrides: notify.StoreOverrides(ev.db.TenantEmailTemplates())})
	m, err := avalert.New(ev.db, audit.New(ev.db), avalert.Options{
		AdminLink: "https://admin.example.com/admin", Notifier: notifier, TenantMailer: ev.tenants,
		SystemMailer: ev.system, Pinger: ev.client, Grace: grace, Logger: slog.New(ev.logs),
		SMTP: mail.Settings{Host: "relay.example.com", Port: 25, Security: mail.SecurityNone, FromAddress: "noreply@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	ev.alerts = m
	ev.w.observer = m
	return ev
}

// events returns the global audit events of action.
func (ev *alertEnv) events(action audit.Action) int {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{Action: string(action)})
	if err != nil {
		ev.t.Fatal(err)
	}
	return len(page.Items)
}

// TestAlertAfterGrace keeps the transfers scanning while clamd is down and
// raises the antivirus alert once the outage outlasts the grace period:
// the super admin by system mail, the administrators of each tenant with
// waiting transfers by its own template; the recovery clears it.
func TestAlertAfterGrace(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newAlertEnv(t, e, 2*time.Second)
		ev.clamd.Stop()
		trf := ev.scanning(ev.a, clean(10))
		ev.scanning(ev.b, clean(10))
		ev.scanning(ev.c, clean(10)) // no SMTP settings: logged and skipped
		ev.start()
		ev.waitUntil("the alert mails", func() bool { return len(ev.system.snapshot()) == 1 && len(ev.tenants.snapshot()) == 2 })
		sys := ev.system.snapshot()[0]
		if sys.Template != mail.TemplateAntivirusAlert || sys.Message.To[0] != "root@example.com" ||
			!strings.Contains(sys.Message.Text, "3 ;") {
			t.Errorf("system mail: %+v", sys)
		}
		got := map[string]string{}
		for _, j := range ev.tenants.snapshot() {
			if j.Template != mail.TemplateAntivirusUnavailable {
				t.Errorf("tenant mail template %s", j.Template)
			}
			got[j.TenantID] = j.Message.To[0]
		}
		// A has a delegated admin; B has none: its mail goes to the super
		// admin, through the SMTP settings of B.
		if got[string(ev.a.ID)] != "anna@entity-a.example.com" || got[string(ev.b.ID)] != "root@example.com" {
			t.Errorf("tenant mails: %v", got)
		}
		if ev.events(audit.ActionAntivirusAlertRaised) != 1 || ev.get(ev.a, trf).Status != store.TransferScanning {
			t.Error("the alert was not audited, or a transfer left scanning")
		}
		if len(ev.queue.snapshot()) != 0 {
			t.Error("transfer mails sent during the outage")
		}
		ev.clamd.Restart(t)
		ev.waitStatus(ev.a, trf, store.TransferAvailable)
		ev.waitUntil("the clear", func() bool { return ev.events(audit.ActionAntivirusAlertCleared) == 1 })
		if len(ev.system.snapshot()) != 1 || len(ev.tenants.snapshot()) != 2 {
			t.Error("the recovery mailed someone")
		}
	})
}

// TestNoAlertWithinGrace mails nobody when clamd answers again before the
// end of the grace period (a restart or a signature reload).
func TestNoAlertWithinGrace(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newAlertEnv(t, e, 2*time.Second)
		ev.clamd.Stop()
		trf := ev.scanning(ev.a, clean(10))
		ev.start()
		ev.waitUntil("the outage", func() bool { return ev.logs.count("antivirus unavailable") == 1 })
		ev.clamd.Restart(t)
		ev.waitStatus(ev.a, trf, store.TransferAvailable)
		ev.waitUntil("the end of the outage", func() bool { return ev.logs.count("antivirus outage ended before the alert") == 1 })
		if len(ev.system.snapshot()) != 0 || len(ev.tenants.snapshot()) != 0 ||
			ev.events(audit.ActionAntivirusAlertRaised)+ev.events(audit.ActionAntivirusAlertCleared) != 0 {
			t.Error("a short outage alerted")
		}
	})
}

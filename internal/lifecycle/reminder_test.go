package lifecycle

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

const (
	erin  = "erin@customer.example.net"
	frank = "frank@other.example.org"
	gina  = "gina@tenant-b.example.net"
)

// fakeReminders is a ReminderNotifier and a MailQueue recording what they
// are given; failAddr makes the enqueue of that address fail, failBuild the
// build.
type fakeReminders struct {
	mu        sync.Mutex
	hosts     map[string]string // recipient address -> FQDN of the tenant it was built for
	links     map[string]string // recipient address -> link
	verified  []bool
	queued    []string
	failAddr  string
	failBuild error
}

func newFakeReminders() *fakeReminders {
	return &fakeReminders{hosts: map[string]string{}, links: map[string]string{}}
}

func (f *fakeReminders) ExpiryReminderJobs(_ context.Context, t *tenant.Tenant, _ notify.TransferView, links []notify.RecipientLink, verification bool) ([]mail.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failBuild != nil {
		return nil, f.failBuild
	}
	f.verified = append(f.verified, verification)
	jobs := make([]mail.Job, 0, len(links))
	for _, l := range links {
		f.hosts[l.Email], f.links[l.Email] = t.FQDN, l.Link
		jobs = append(jobs, mail.Job{TenantID: string(t.ID), Template: mail.TemplateExpiryReminder, Message: mail.Message{To: []string{l.Email}}})
	}
	return jobs, nil
}

func (f *fakeReminders) Enqueue(j mail.Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAddr != "" && j.Message.To[0] == f.failAddr {
		return errFault
	}
	f.queued = append(f.queued, j.Message.To[0])
	return nil
}

// mailed returns the addresses queued so far.
func (f *fakeReminders) mailed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queued...)
}

// withReminders arms the reminder task of ev's sweeper.
func (ev *env) withReminders() *fakeReminders {
	f := newFakeReminders()
	ev.s.notifier, ev.s.mailer, ev.s.opener = f, f, ev.vault
	return f
}

// perRecipient stores an available per-recipient transfer of tn with one
// link per recipient, finalized at t0 for expiryDays days with one file.
func (ev *env) perRecipient(tn *tenant.Tenant, expiryDays int, verification bool, recipients ...string) (fixture, []store.RecipientLink) {
	ev.t.Helper()
	return ev.perRecipientOpts(tn, expiryDays, verification, false, recipients...)
}

// perRecipientOpts is perRecipient with the "delete after the first
// download" option.
func (ev *env) perRecipientOpts(tn *tenant.Tenant, expiryDays int, verification, deleteAfter bool, recipients ...string) (fixture, []store.RecipientLink) {
	ev.t.Helper()
	ctx := context.Background()
	trfID := id.New(id.Transfer)
	var links []store.RecipientLink
	ev.tx(tn, func(tx *store.ScopedTx) error {
		f, err := ev.storeFile(ctx, tx, tn)
		if err != nil {
			return err
		}
		f.Name = "file.bin"
		tr := store.Transfer{
			ID: trfID, SenderEmail: alice, SenderKind: store.DepositorInternal, ExpiryDays: expiryDays,
			LinkMode: store.LinkModePerRecipient, RecipientVerification: verification, DeleteAfterFirstDownload: deleteAfter,
		}
		if err := ev.db.Transfers().CreateTx(ctx, tx, tr, recipients, []store.TransferFile{f}); err != nil {
			return err
		}
		if err := ev.db.Transfers().FinalizeTx(ctx, tx, trfID, t0); err != nil {
			return err
		}
		tokens := make([]store.LinkToken, 0, len(recipients))
		for range recipients {
			token, err := id.NewDownloadToken()
			if err != nil {
				return err
			}
			hash := sha256.Sum256([]byte(token))
			wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
			if err != nil {
				return err
			}
			tokens = append(tokens, store.LinkToken{Hash: hash[:], KeyID: wk})
		}
		links, err = ev.db.Transfers().MarkAvailableLinksTx(ctx, tx, trfID, tokens, t0)
		return err
	})
	return fixture{tn: tn, id: trfID}, links
}

// links returns the links of fx by recipient address.
func (ev *env) links(fx fixture) map[string]store.RecipientLink {
	ev.t.Helper()
	ls, err := ev.db.RecipientLinks().ListByTransfer(context.Background(), fx.tn.ID, fx.id)
	if err != nil {
		ev.t.Fatal(err)
	}
	out := make(map[string]store.RecipientLink, len(ls))
	for _, l := range ls {
		out[l.Email] = l
	}
	return out
}

// reminderWindow moves the clock to 10 hours before the expiry of a 7-day
// transfer finalized at t0.
func (ev *env) reminderWindow() {
	ev.clock.set(t0.Add(7*24*time.Hour - 10*time.Hour))
}

// reminderAudits counts the audit events transfer.reminder_sent of tn.
func (ev *env) reminderAudits(tn *tenant.Tenant) (events int, recipients float64) {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{TenantID: tn.ID, Action: string(audit.ActionTransferReminderSent)})
	if err != nil {
		ev.t.Fatal(err)
	}
	for _, e := range page.Items {
		events++
		if !strings.Contains(string(e.Details), `"recipients"`) {
			ev.t.Fatalf("details = %s", e.Details)
		}
		var n float64
		if _, err := fmt.Sscanf(string(e.Details), `{"recipients":%f}`, &n); err != nil {
			ev.t.Fatalf("details = %s: %v", e.Details, err)
		}
		recipients += n
	}
	return events, recipients
}

func TestExpiryReminderSentOnce(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		fx, ls := ev.perRecipient(ev.a, 7, true, dave, erin)
		// erin started to download: no reminder for her.
		ev.tx(ev.a, func(tx *store.ScopedTx) error {
			return ev.db.RecipientLinks().ClaimTx(context.Background(), tx, ls[1].ID, "", t0.Add(time.Hour))
		})

		// Too early: more than 24 hours before the expiry.
		ev.clock.set(t0.Add(3 * 24 * time.Hour))
		ev.runTask(TaskExpiryReminder)
		if got := f.mailed(); len(got) != 0 {
			t.Fatalf("mailed %v too early", got)
		}

		ev.reminderWindow()
		ev.runTask(TaskExpiryReminder)
		if got := f.mailed(); len(got) != 1 || got[0] != dave {
			t.Fatalf("mailed %v, want only %s", got, dave)
		}
		if !f.verified[0] || !strings.Contains(f.links[dave], hostA) || !strings.Contains(f.links[dave], "dl_") {
			t.Fatalf("verification %v, link %q", f.verified, f.links[dave])
		}
		got := ev.links(fx)
		if got[dave].ReminderSentAt.IsZero() || !got[erin].ReminderSentAt.IsZero() {
			t.Fatalf("reminder marks: dave %v erin %v", got[dave].ReminderSentAt, got[erin].ReminderSentAt)
		}
		if ev.get(fx).ExpiryReminderAt.IsZero() {
			t.Fatal("transfer not marked as reminded")
		}
		if n, r := ev.reminderAudits(ev.a); n != 1 || r != 1 {
			t.Fatalf("audit events %d, recipients %v", n, r)
		}

		// Once per link and expiry.
		ev.runTask(TaskExpiryReminder)
		if got := f.mailed(); len(got) != 1 {
			t.Fatalf("mailed %v after the second run", got)
		}
		if ev.logs.count("ERROR") != 0 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
	})
}

func TestExpiryReminderSkipsBlocklisted(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		fx, _ := ev.perRecipient(ev.a, 7, false, dave, frank, erin)
		bl := ev.db.Blocklist()
		ctx := context.Background()
		if _, err := bl.Create(ctx, ev.a.ID, store.BlocklistEntry{Kind: store.BlockEmail, Value: dave, CreatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		if _, err := bl.Create(ctx, ev.a.ID, store.BlocklistEntry{Kind: store.BlockDomain, Value: "other.example.org", CreatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		ev.reminderWindow()
		ev.runTask(TaskExpiryReminder)
		if got := f.mailed(); len(got) != 1 || got[0] != erin {
			t.Fatalf("mailed %v, want only %s", got, erin)
		}
		if f.verified[0] {
			t.Fatal("verification flag set for a transfer without verification")
		}
		ls := ev.links(fx)
		if !ls[dave].ReminderSentAt.IsZero() || !ls[frank].ReminderSentAt.IsZero() || ls[erin].ReminderSentAt.IsZero() {
			t.Fatal("reminder marks do not follow the blocklist")
		}
		if ev.get(fx).ExpiryReminderAt.IsZero() {
			t.Fatal("transfer not marked as reminded")
		}
	})
}

func TestExpiryReminderAllBlocklisted(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		fx, _ := ev.perRecipient(ev.a, 7, false, dave)
		if _, err := ev.db.Blocklist().Create(context.Background(), ev.a.ID, store.BlocklistEntry{Kind: store.BlockEmail, Value: dave, CreatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		ev.reminderWindow()
		ev.runTask(TaskExpiryReminder)
		if len(f.mailed()) != 0 || ev.get(fx).ExpiryReminderAt.IsZero() {
			t.Fatalf("mailed %v, reminded at %v", f.mailed(), ev.get(fx).ExpiryReminderAt)
		}
		if n, _ := ev.reminderAudits(ev.a); n != 0 {
			t.Fatalf("%d audit events for no reminder", n)
		}
	})
}

func TestExpiryReminderShortLifetime(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		fx, _ := ev.perRecipient(ev.a, 1, false, dave)
		if ev.get(fx).ExpiryReminderAt.IsZero() {
			t.Fatal("a 1-day transfer must be marked at availability")
		}
		ev.clock.set(t0.Add(18 * time.Hour))
		ev.runTask(TaskExpiryReminder)
		if len(f.mailed()) != 0 {
			t.Fatalf("mailed %v for a short-lived transfer", f.mailed())
		}
	})
}

func TestExpiryReminderIgnoresSharedTransfers(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		ev.available(ev.a, 1, false)
		ev.clock.set(t0.Add(7*24*time.Hour - time.Hour))
		ev.runTask(TaskExpiryReminder)
		if len(f.mailed()) != 0 {
			t.Fatalf("mailed %v for a shared transfer", f.mailed())
		}
	})
}

func TestExpiryReminderResetOnFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		fx, _ := ev.perRecipient(ev.a, 7, false, dave, erin)
		ev.reminderWindow()

		f.failAddr = erin
		err := ev.s.RunTask(context.Background(), TaskExpiryReminder)
		if err == nil {
			t.Fatal("run succeeded despite an enqueue failure")
		}
		if got := f.mailed(); len(got) != 1 || got[0] != dave {
			t.Fatalf("mailed %v", got)
		}
		ls := ev.links(fx)
		if ls[dave].ReminderSentAt.IsZero() || !ls[erin].ReminderSentAt.IsZero() {
			t.Fatalf("marks: dave %v erin %v, want erin reset", ls[dave].ReminderSentAt, ls[erin].ReminderSentAt)
		}
		if !ev.s.LastRun(TaskExpiryReminder).IsZero() {
			t.Fatal("LastRun moved by a failed run")
		}
		if ev.logs.count("ERROR lifecycle: expiry reminder failed") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		if !ev.get(fx).ExpiryReminderAt.IsZero() {
			t.Fatal("reminder pass of the transfer not reset: it would never be retried")
		}

		// The next run retries erin only.
		f.failAddr = ""
		ev.clock.set(ev.clock.Now().Add(DefaultReminderInterval))
		ev.runTask(TaskExpiryReminder)
		if got := f.mailed(); len(got) != 2 || got[1] != erin {
			t.Fatalf("mailed %v, want dave then erin", got)
		}
		ls = ev.links(fx)
		if ls[dave].ReminderSentAt.IsZero() || ls[erin].ReminderSentAt.IsZero() || ev.get(fx).ExpiryReminderAt.IsZero() {
			t.Fatal("marks not set after the retry")
		}
		if n, r := ev.reminderAudits(ev.a); n != 2 || r != 3 {
			t.Fatalf("audit events %d, recipients %v", n, r)
		}
		// Nothing more afterwards.
		ev.runTask(TaskExpiryReminder)
		if got := f.mailed(); len(got) != 2 {
			t.Fatalf("mailed %v after the retry", got)
		}
	})
}

func TestExpiryReminderResetOnBuildFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		fx, _ := ev.perRecipient(ev.a, 7, false, dave, erin)
		ev.reminderWindow()
		f.failBuild = errFault
		if err := ev.s.RunTask(context.Background(), TaskExpiryReminder); err == nil {
			t.Fatal("run succeeded despite a build failure")
		}
		for addr, l := range ev.links(fx) {
			if !l.ReminderSentAt.IsZero() {
				t.Fatalf("mark of %s not reset", addr)
			}
		}
		if !ev.get(fx).ExpiryReminderAt.IsZero() {
			t.Fatal("reminder pass of the transfer not reset")
		}
		// The next run sends both.
		f.failBuild = nil
		ev.runTask(TaskExpiryReminder)
		if got := f.mailed(); len(got) != 2 {
			t.Fatalf("mailed %v on the retry", got)
		}
	})
}

// failingOpener fails the first n unsealings, then unseals with inner.
type failingOpener struct {
	inner Opener
	mu    sync.Mutex
	n     int
}

func (o *failingOpener) Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error) {
	o.mu.Lock()
	fail := o.n > 0
	if fail {
		o.n--
	}
	o.mu.Unlock()
	if fail {
		return nil, errFault
	}
	return o.inner.Open(ctx, tid, p, wkID)
}

func TestExpiryReminderRetryAfterOpenFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		ev.s.opener = &failingOpener{inner: ev.vault, n: 1}
		fx, _ := ev.perRecipient(ev.a, 7, false, dave)
		ev.reminderWindow()
		if err := ev.s.RunTask(context.Background(), TaskExpiryReminder); err == nil {
			t.Fatal("run succeeded despite an unsealing failure")
		}
		if len(f.mailed()) != 0 || !ev.links(fx)[dave].ReminderSentAt.IsZero() || !ev.get(fx).ExpiryReminderAt.IsZero() {
			t.Fatalf("mailed %v, marks not reset", f.mailed())
		}
		ev.runTask(TaskExpiryReminder)
		if got := f.mailed(); len(got) != 1 || got[0] != dave {
			t.Fatalf("mailed %v on the retry", got)
		}
	})
}

// TestExpiryReminderSkipsErasedRecipient checks that a link whose sealed
// token was destroyed (erased recipient) is neither mailed nor marked.
func TestExpiryReminderSkipsErasedRecipient(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		fx, _ := ev.perRecipient(ev.a, 7, false, dave, erin)
		ev.tx(ev.a, func(tx *store.ScopedTx) error {
			_, err := ev.db.RecipientLinks().DestroyRecipientKeyTx(context.Background(), tx, fx.id, dave)
			return err
		})
		ev.reminderWindow()
		ev.runTask(TaskExpiryReminder)
		if got := f.mailed(); len(got) != 1 || got[0] != erin {
			t.Fatalf("mailed %v, want only %s", got, erin)
		}
		if ls := ev.links(fx); !ls[dave].ReminderSentAt.IsZero() {
			t.Fatal("erased recipient marked")
		}
		if n, r := ev.reminderAudits(ev.a); n != 1 || r != 1 {
			t.Fatalf("audit events %d, recipients %v", n, r)
		}
	})
}

// TestExpiryReminderPages checks that the run walks every page of due
// transfers, and stops at a cancellation between two transfers.
func TestExpiryReminderPages(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		ev.s.reminderPage = 1
		ev.perRecipient(ev.a, 7, false, dave)
		ev.perRecipient(ev.b, 7, false, gina)
		ev.perRecipient(ev.a, 7, false, erin)
		ev.reminderWindow()
		ev.runTask(TaskExpiryReminder)
		if got := f.mailed(); len(got) != 3 {
			t.Fatalf("mailed %v", got)
		}

		ev.s.reminderPage = 2
		ev.perRecipient(ev.a, 7, false, frank)
		ev.perRecipient(ev.b, 7, false, gina)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ev.f.onCall("getTenant", cancel)
		if err := ev.s.RunTask(ctx, TaskExpiryReminder); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled run = %v", err)
		}
	})
}

// TestExpiryReminderNoLongerDue skips, without failing, a transfer whose
// reminder pass was recorded between the listing and its transaction.
func TestExpiryReminderNoLongerDue(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		fx, _ := ev.perRecipient(ev.a, 7, false, dave)
		ev.reminderWindow()
		ev.f.onCall("prepareReminder", func() {
			ev.tx(ev.a, func(tx *store.ScopedTx) error {
				return ev.db.Transfers().MarkExpiryReminderTx(context.Background(), tx, fx.id, ev.clock.Now())
			})
		})
		ev.runTask(TaskExpiryReminder)
		if len(f.mailed()) != 0 || !ev.links(fx)[dave].ReminderSentAt.IsZero() {
			t.Fatalf("mailed %v for a transfer no longer due", f.mailed())
		}
	})
}

// rawSQLite opens the SQLite file of e directly, to inject faults the
// store cannot produce.
func rawSQLite(t *testing.T, e storetest.Engine) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", e.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

// TestPrepareReminderStoreFaults checks that every store failure of the
// committed part of the reminder surfaces, leaving nothing marked.
func TestPrepareReminderStoreFaults(t *testing.T) {
	cases := []struct{ name, fault string }{
		{"targets", `DROP TABLE recipient_links`},
		{"blocklist", `DROP TABLE blocklist_entries`},
		{"mark links", `CREATE TRIGGER f BEFORE UPDATE OF reminder_sent_at ON recipient_links BEGIN SELECT RAISE(ABORT, 'fault'); END`},
		{"mark transfer", `CREATE TRIGGER f BEFORE UPDATE OF expiry_reminder_at ON transfers BEGIN SELECT RAISE(ABORT, 'fault'); END`},
		{"audit", `CREATE TRIGGER f BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'fault'); END`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := storetest.SQLite(t)
			ev := newEnv(t, e)
			fx, _ := ev.perRecipient(ev.a, 7, false, dave)
			ev.reminderWindow()
			if _, err := rawSQLite(t, e).Exec(c.fault); err != nil {
				t.Fatal(err)
			}
			_, err := ev.repo.inner.prepareReminder(context.Background(), ev.a.ID, fx.id, ev.clock.Now())
			if err == nil || errors.Is(err, errNotDue) {
				t.Fatalf("prepareReminder = %v, want a store error", err)
			}
		})
	}
	t.Run("arguments", func(t *testing.T) {
		ev := newEnv(t, storetest.SQLite(t))
		ctx := context.Background()
		if _, err := ev.repo.inner.prepareReminder(ctx, "not a tenant", id.New(id.Transfer), t0); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("malformed tenant: %v", err)
		}
		if _, err := ev.repo.inner.prepareReminder(ctx, ev.a.ID, id.New(id.Transfer), t0); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown transfer: %v", err)
		}
	})
}

// TestFinishLinkKeysFault checks that a failure to destroy the sealed
// tokens of the links aborts the end of the transfer, which stays
// available with its keys.
func TestFinishLinkKeysFault(t *testing.T) {
	e := storetest.SQLite(t)
	ev := newEnv(t, e)
	fx, ls := ev.perRecipient(ev.a, 7, false, dave)
	if _, err := rawSQLite(t, e).Exec(`CREATE TRIGGER f BEFORE DELETE ON wrapped_keys
		WHEN OLD.id IN (SELECT token_key_id FROM recipient_links) BEGIN SELECT RAISE(ABORT, 'fault'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.s.EraseTransfer(context.Background(), ev.a.ID, fx.id, MarkDeleted); err == nil {
		t.Fatal("EraseTransfer succeeded despite the fault")
	}
	if d := ev.get(fx); d.Status != store.TransferAvailable {
		t.Fatalf("status = %s", d.Status)
	}
	if !ev.keyExists(ev.a, ls[0].TokenKeyID) {
		t.Fatal("link key destroyed despite the rollback")
	}
}

func TestExpiryReminderFaults(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.withReminders()
		ev.perRecipient(ev.a, 7, false, dave)
		ev.reminderWindow()
		for _, name := range []string{"dueReminders", "getTenant", "prepareReminder"} {
			ev.f.set(name, 1, nil)
			if err := ev.s.RunTask(context.Background(), TaskExpiryReminder); !errors.Is(err, errFault) && (err == nil || !strings.Contains(err.Error(), "reminder not sent")) {
				t.Fatalf("fault %s: run = %v", name, err)
			}
		}
		// A reset that fails is only logged.
		f := ev.withReminders()
		f.failAddr = dave
		ev.f.set("resetReminder", 1, nil)
		if err := ev.s.RunTask(context.Background(), TaskExpiryReminder); err == nil {
			t.Fatal("run succeeded")
		}
		if ev.logs.count("lifecycle: reminder mark not reset") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
	})
}

func TestExpiryReminderDisabledWithoutDeps(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.perRecipient(ev.a, 7, false, dave)
		ev.reminderWindow()
		ev.runTask(TaskExpiryReminder)
		if ev.f.called("dueReminders") != 0 {
			t.Fatal("the task listed reminders without its dependencies")
		}
	})
}

func TestExpiryReminderTenantsNeverMix(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		fxA, _ := ev.perRecipient(ev.a, 7, false, dave, erin)
		fxB, _ := ev.perRecipient(ev.b, 7, true, gina)
		ev.reminderWindow()
		ev.runTask(TaskExpiryReminder)
		if len(f.mailed()) != 3 {
			t.Fatalf("mailed %v", f.mailed())
		}
		for _, a := range []string{dave, erin} {
			if f.hosts[a] != hostA || !strings.HasPrefix(f.links[a], "https://"+hostA+"/") {
				t.Fatalf("%s mailed for %s with %s", a, f.hosts[a], f.links[a])
			}
		}
		if f.hosts[gina] != hostB || !strings.HasPrefix(f.links[gina], "https://"+hostB+"/") {
			t.Fatalf("%s mailed for %s with %s", gina, f.hosts[gina], f.links[gina])
		}
		// Marks, and audit events, stay with their own tenant.
		if len(ev.links(fxA)) != 2 || len(ev.links(fxB)) != 1 || ev.get(fxB).ExpiryReminderAt.IsZero() {
			t.Fatal("marks wrong")
		}
		if n, r := ev.reminderAudits(ev.a); n != 1 || r != 2 {
			t.Fatalf("tenant A audit: %d events, %v recipients", n, r)
		}
		if n, r := ev.reminderAudits(ev.b); n != 1 || r != 1 {
			t.Fatalf("tenant B audit: %d events, %v recipients", n, r)
		}
		// A link built for A is not the link of B.
		if f.links[dave] == f.links[gina] {
			t.Fatal("same link for two recipients")
		}
	})
}

func TestExpiryReminderSkipsDeletingTenant(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		f := ev.withReminders()
		fx, _ := ev.perRecipient(ev.a, 7, false, dave)
		ev.startDeletion(ev.a)
		ev.reminderWindow()
		ev.runTask(TaskExpiryReminder)
		if len(f.mailed()) != 0 || !ev.get(fx).ExpiryReminderAt.IsZero() {
			t.Fatalf("mailed %v for a tenant being deleted", f.mailed())
		}
	})
}

// linkKeys returns the sealed token keys of the links.
func linkKeys(ls []store.RecipientLink) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.TokenKeyID
	}
	return out
}

// assertKeysGone checks that no sealed token of ls is stored any more.
func (ev *env) assertKeysGone(tn *tenant.Tenant, keys []string) {
	ev.t.Helper()
	for _, k := range keys {
		if ev.keyExists(tn, k) {
			ev.t.Fatalf("link token key %s still stored", k)
		}
	}
}

// TestCryptoEraseLinkTokens checks that every end of a per-recipient
// transfer destroys the sealed tokens of its links (the store refuses with
// ErrKeysRemain otherwise).
func TestCryptoEraseLinkTokens(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, ev *env)
	}{
		{"expire", func(t *testing.T, ev *env) {
			fx, ls := ev.perRecipient(ev.a, 7, false, dave, erin)
			ev.clock.set(t0.Add(8 * 24 * time.Hour))
			ev.sweepKind(kindExpire, stats{due: 1, erased: 1})
			if d := ev.get(fx); d.Status != store.TransferExpired {
				t.Fatalf("status = %s", d.Status)
			}
			ev.assertKeysGone(ev.a, linkKeys(ls))
		}},
		{"delete-after-download", func(t *testing.T, ev *env) {
			fx, ls := ev.perRecipientOpts(ev.a, 7, false, true, dave)
			ev.tx(ev.a, func(tx *store.ScopedTx) error {
				l := ev.db.RecipientLinks()
				if err := l.ClaimTx(context.Background(), tx, ls[0].ID, "", t0.Add(time.Hour)); err != nil {
					return err
				}
				if _, err := l.CompleteTx(context.Background(), tx, ls[0].ID, t0.Add(time.Hour)); err != nil {
					return err
				}
				_, err := ev.db.Transfers().MarkFirstDownloadTx(context.Background(), tx, fx.id, t0.Add(time.Hour), t0.Add(time.Hour+grace))
				return err
			})
			ev.clock.set(t0.Add(2 * time.Hour))
			ev.sweep(stats{due: 1, erased: 1})
			if d := ev.get(fx); d.Status != store.TransferDeleted {
				t.Fatalf("status = %s", d.Status)
			}
			ev.assertKeysGone(ev.a, linkKeys(ls))
		}},
		{"admin-delete", func(t *testing.T, ev *env) {
			fx, ls := ev.perRecipient(ev.a, 7, false, dave, erin)
			if res, err := ev.s.EraseTransfer(context.Background(), ev.a.ID, fx.id, MarkDeleted); err != nil || res != Erased {
				t.Fatalf("EraseTransfer = %v, %v", res, err)
			}
			if d := ev.get(fx); d.Status != store.TransferDeleted {
				t.Fatalf("status = %s", d.Status)
			}
			ev.assertKeysGone(ev.a, linkKeys(ls))
		}},
		{"data-subject", func(t *testing.T, ev *env) {
			fx, ls := ev.perRecipient(ev.a, 7, false, dave, erin)
			if res, err := ev.s.EraseTransfer(context.Background(), ev.a.ID, fx.id, DeleteRow); err != nil || res != Erased {
				t.Fatalf("EraseTransfer = %v, %v", res, err)
			}
			if _, err := ev.db.Transfers().Get(context.Background(), ev.a.ID, fx.id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("Get after the row deletion = %v", err)
			}
			ev.assertKeysGone(ev.a, linkKeys(ls))
		}},
		{"tenant", func(t *testing.T, ev *env) {
			_, ls := ev.perRecipient(ev.a, 7, false, dave, erin)
			ev.startDeletion(ev.a)
			if err := ev.s.EraseTenant(context.Background(), ev.a.ID); err != nil {
				t.Fatalf("EraseTenant: %v\nlogs:\n%s", err, ev.logs.all())
			}
			if _, err := ev.db.Tenants().Get(context.Background(), ev.a.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("tenant after erasure = %v", err)
			}
			ev.assertKeysGone(ev.a, linkKeys(ls))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) { c.run(t, newEnv(t, e)) })
		})
	}
}

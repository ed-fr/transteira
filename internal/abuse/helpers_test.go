package abuse

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
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

const (
	adminLink = "https://admin.example.com/admin"
	alice     = "alice@entity-a.example.com"
	ext       = "bob@partner.example.org"
)

var (
	// t0 is a Thursday, 11:00 in Paris (UTC+2).
	t0      = time.Date(2026, time.October, 22, 9, 0, 0, 0, time.UTC)
	errBoom = errors.New("boom")
)

func i64p(n int64) *int64 { return &n }
func intp(n int) *int     { return &n }

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

// fakeNotifier records the mails and builds one job per recipient.
type fakeNotifier struct {
	mu         sync.Mutex
	alerts     []mail.AbuseAlertData
	reports    []mail.AbuseReportData
	recipients [][]notify.Contact
	err        error
}

func (n *fakeNotifier) AbuseAlert(_ context.Context, t *tenant.Tenant, data mail.AbuseAlertData, rc []notify.Contact) ([]mail.Job, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.alerts = append(n.alerts, data)
	n.recipients = append(n.recipients, rc)
	return n.jobs(t, rc)
}

func (n *fakeNotifier) AbuseReport(_ context.Context, t *tenant.Tenant, data mail.AbuseReportData, rc []notify.Contact) ([]mail.Job, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.reports = append(n.reports, data)
	n.recipients = append(n.recipients, rc)
	return n.jobs(t, rc)
}

func (n *fakeNotifier) jobs(t *tenant.Tenant, rc []notify.Contact) ([]mail.Job, error) {
	if n.err != nil {
		return nil, n.err
	}
	jobs := make([]mail.Job, len(rc))
	for i := range rc {
		jobs[i] = mail.Job{TenantID: string(t.ID)}
	}
	return jobs, nil
}

func (n *fakeNotifier) alertData() []mail.AbuseAlertData {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]mail.AbuseAlertData(nil), n.alerts...)
}

// fakeMailer counts the sends.
type fakeMailer struct {
	mu    sync.Mutex
	sends int
}

func (m *fakeMailer) Send(context.Context, []mail.Job, ...slog.Attr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sends++
}

func (m *fakeMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sends
}

// recorder records the published events.
type recorder struct {
	mu  sync.Mutex
	evs []events.Event
}

func (r *recorder) Publish(ev events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
}

func (r *recorder) all() []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]events.Event(nil), r.evs...)
}

// failAuditor refuses every event.
type failAuditor struct{}

func (failAuditor) RecordScoped(context.Context, tenant.ID, audit.Event) error { return errBoom }

// faultRepo wraps a repo and injects failures.
type faultRepo struct {
	repo
	settingsErr, settingsTxErr, activityErr, extActivityErr, historyErr, domainsErr, alertErr, contactsErr, superErr error
	// activityTxErr fails the activity of the given kinds inside a
	// transaction (main: the daily activity of the internal kinds, ext:
	// the external quota).
	activityTxErr     error
	activityTxErrExt  bool
	activityTxErrMain bool
}

func (f *faultRepo) settings(ctx context.Context, tid tenant.ID) (store.AbuseSettings, error) {
	if f.settingsErr != nil {
		return store.AbuseSettings{}, f.settingsErr
	}
	return f.repo.settings(ctx, tid)
}

func (f *faultRepo) settingsTx(ctx context.Context, tx *store.ScopedTx) (store.AbuseSettings, error) {
	if f.settingsTxErr != nil {
		return store.AbuseSettings{}, f.settingsTxErr
	}
	return f.repo.settingsTx(ctx, tx)
}

func (f *faultRepo) activityTx(ctx context.Context, tx *store.ScopedTx, email string, start, end time.Time, kinds []store.DepositorKind) (int64, int, error) {
	ext := slices.Equal(kinds, externalKinds)
	if f.activityTxErr != nil && ((!ext && f.activityTxErrMain) || (ext && f.activityTxErrExt)) {
		return 0, 0, f.activityTxErr
	}
	return f.repo.activityTx(ctx, tx, email, start, end, kinds)
}

func (f *faultRepo) activity(ctx context.Context, tid tenant.ID, email string, start, end time.Time, kinds []store.DepositorKind) (int64, int, error) {
	ext := slices.Equal(kinds, externalKinds)
	if !ext && f.activityErr != nil {
		return 0, 0, f.activityErr
	}
	if ext && f.extActivityErr != nil {
		return 0, 0, f.extActivityErr
	}
	return f.repo.activity(ctx, tid, email, start, end, kinds)
}

func (f *faultRepo) history(ctx context.Context, tid tenant.ID, email string, since time.Time) ([]store.SenderTransferVolume, error) {
	if f.historyErr != nil {
		return nil, f.historyErr
	}
	return f.repo.history(ctx, tid, email, since)
}

func (f *faultRepo) internalDomains(ctx context.Context, tid tenant.ID) ([]string, error) {
	if f.domainsErr != nil {
		return nil, f.domainsErr
	}
	return f.repo.internalDomains(ctx, tid)
}

func (f *faultRepo) tryAlert(ctx context.Context, tid tenant.ID, email string, rule store.AbuseRule, day string, blocked bool, now time.Time) (bool, error) {
	if f.alertErr != nil {
		return false, f.alertErr
	}
	return f.repo.tryAlert(ctx, tid, email, rule, day, blocked, now)
}

func (f *faultRepo) tenantContacts(ctx context.Context, tid tenant.ID) ([]store.AdminContact, error) {
	if f.contactsErr != nil {
		return nil, f.contactsErr
	}
	return f.repo.tenantContacts(ctx, tid)
}

func (f *faultRepo) superAdminContacts(ctx context.Context) ([]store.AdminContact, error) {
	if f.superErr != nil {
		return nil, f.superErr
	}
	return f.repo.superAdminContacts(ctx)
}

// env is a detector over a real database with fake mail dependencies.
type env struct {
	t        *testing.T
	db       *store.DB
	notifier *fakeNotifier
	mailer   *fakeMailer
	events   *recorder
	logs     *syncBuffer
	fault    *faultRepo
	det      *Detector
	now      time.Time
	n        int
}

// newEnv opens and migrates a database on e and builds a detector whose
// repo is wrapped by env.fault (no fault by default), with t0 as clock.
func newEnv(t *testing.T, e storetest.Engine) *env {
	t.Helper()
	ctx := context.Background()
	ev := &env{t: t, notifier: &fakeNotifier{}, mailer: &fakeMailer{}, events: &recorder{}, logs: &syncBuffer{}, now: t0}
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return ev.now }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ev.db = db
	ev.fault = &faultRepo{repo: storeRepo{db: db}}
	ev.det, err = newDetector(ev.fault, ev.notifier, ev.mailer, audit.New(db), Options{
		AdminLink: adminLink, Events: ev.events, Now: func() time.Time { return ev.now },
		Logger: slog.New(slog.NewTextHandler(ev.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// tenant creates an active tenant with the internal domain
// entity-a.example.com and the settings s.
func (ev *env) tenant(s store.AbuseSettings) *tenant.Tenant {
	ev.t.Helper()
	ctx := context.Background()
	ev.n++
	tn, err := ev.db.Tenants().Create(ctx, &tenant.Tenant{
		Name: fmt.Sprintf("Entity %d", ev.n), FQDN: fmt.Sprintf("transfer.entity-%d.example.com", ev.n),
		DefaultLanguage: "en", MaxTransferBytes: 1 << 34, StorageQuotaBytes: 1 << 40,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	if _, err := ev.db.NetworkRules().Replace(ctx, tn.ID, nil, []string{"entity-a.example.com"}); err != nil {
		ev.t.Fatal(err)
	}
	if _, err := ev.db.AbuseSettings().Put(ctx, tn.ID, s); err != nil {
		ev.t.Fatal(err)
	}
	return tn
}

// settings returns the default settings in Europe/Paris changed by fn.
func settings(fn func(s *store.AbuseSettings)) store.AbuseSettings {
	s := store.DefaultAbuseSettings()
	s.TimeZone = "Europe/Paris"
	if fn != nil {
		fn(&s)
	}
	return s
}

// transfer stores a transfer of tn by sender of kind, declaring size
// bytes, created at at, and returns its ID.
func (ev *env) transfer(tn *tenant.Tenant, sender string, kind store.DepositorKind, size int64, at time.Time) string {
	ev.t.Helper()
	ctx := context.Background()
	tr := store.Transfer{ID: id.New(id.Transfer), SenderEmail: sender, SenderKind: kind, ExpiryDays: 7, CreatedAt: at}
	if kind == store.DepositorExternal {
		h := sha256.Sum256([]byte(randomHex(16)))
		inv := store.Invitation{ID: id.New(id.Invitation), TokenHash: h[:], Email: sender, InvitedBy: alice, Language: "en"}
		if err := ev.db.Invitations().Create(ctx, tn.ID, inv); err != nil {
			ev.t.Fatal(err)
		}
		tr.InvitationID = inv.ID
	}
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		wk := store.WrappedKey{ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeDEK, KeyID: "mk_0123456789abcdef", Blob: []byte("k")}
		if err := ev.db.WrappedKeys().CreateTx(ctx, tx, wk); err != nil {
			return err
		}
		upl, err := id.NewUploadToken()
		if err != nil {
			return err
		}
		f := store.TransferFile{
			ID: id.New(id.File), Name: "file.bin", Size: size, DEKKeyID: wk.ID,
			StorageName: randomHex(store.StorageNameLen / 2), UploadID: upl,
		}
		return ev.db.Transfers().CreateTx(ctx, tx, tr, []string{"carol@entity-a.example.com"}, []store.TransferFile{f})
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return tr.ID
}

// check runs CheckCreateTx in a transaction of tn.
func (ev *env) check(tn *tenant.Tenant, f Facts) (*Block, error) {
	ev.t.Helper()
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	var b *Block
	err = s.Tx(context.Background(), func(tx *store.ScopedTx) error {
		var err error
		b, err = ev.det.CheckCreateTx(context.Background(), tx, tn, f)
		return err
	})
	return b, err
}

// randomHex returns n random bytes in hex.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// admin creates an activated administrator.
func (ev *env) admin(role store.AdminRole, email string, tids ...tenant.ID) {
	ev.t.Helper()
	ev.n++
	_, err := ev.db.Admins().Create(context.Background(), store.Admin{
		Username: fmt.Sprintf("admin%d", ev.n), Email: email, Role: role, TenantIDs: tids,
		PasswordHash: "$argon2id$test", Language: "fr",
	})
	if err != nil {
		ev.t.Fatal(err)
	}
}

// audits returns the audit events of tn with action.
func (ev *env) audits(tn *tenant.Tenant, action audit.Action) []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{TenantID: tn.ID, Action: string(action)})
	if err != nil {
		ev.t.Fatal(err)
	}
	return page.Items
}

// details decodes the details of an audit event.
func details(t *testing.T, e store.AuditEvent) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(e.Details, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// wantLog fails unless the logs contain s.
func (ev *env) wantLog(s string) {
	ev.t.Helper()
	if !strings.Contains(ev.logs.String(), s) {
		ev.t.Fatalf("logs lack %q:\n%s", s, ev.logs.String())
	}
}

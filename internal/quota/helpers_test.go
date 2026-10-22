package quota

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

const adminLink = "https://admin.example.com/admin"

var (
	t0      = time.Date(2026, time.October, 22, 9, 0, 0, 0, time.UTC)
	errBoom = errors.New("boom")
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

// alertCall is a call of fakeNotifier.QuotaAlert.
type alertCall struct {
	tid        tenant.ID
	data       mail.QuotaAlertData
	level      notify.QuotaLevel
	recipients []notify.Contact
}

// fakeNotifier records the alerts and builds one job per recipient.
type fakeNotifier struct {
	mu    sync.Mutex
	calls []alertCall
	err   error
}

func (n *fakeNotifier) QuotaAlert(_ context.Context, t *tenant.Tenant, data mail.QuotaAlertData, level notify.QuotaLevel,
	recipients []notify.Contact,
) ([]mail.Job, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, alertCall{tid: t.ID, data: data, level: level, recipients: recipients})
	if n.err != nil {
		return nil, n.err
	}
	jobs := make([]mail.Job, len(recipients))
	for i := range recipients {
		jobs[i] = mail.Job{TenantID: string(t.ID)}
	}
	return jobs, nil
}

func (n *fakeNotifier) all() []alertCall {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]alertCall(nil), n.calls...)
}

// fakeMailer records the sent jobs.
type fakeMailer struct {
	mu    sync.Mutex
	sends [][]mail.Job
}

func (m *fakeMailer) Send(_ context.Context, jobs []mail.Job, _ ...slog.Attr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sends = append(m.sends, jobs)
}

func (m *fakeMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sends)
}

// failAuditor refuses every event.
type failAuditor struct{}

func (failAuditor) RecordScoped(context.Context, tenant.ID, audit.Event) error { return errBoom }

// faultRepo wraps a repo and injects failures.
type faultRepo struct {
	repo
	tenantErr, activeErr, usedErr, usedAllErr, levelErr, casErr, contactsErr, superErr error
	// staleLevel, when >= 0, is returned by level instead of the stored one.
	staleLevel int
	// casFalse makes compareAndSet lose without touching the store.
	casFalse bool
	// afterUsedAll, when set, runs at the end of usedBytesAll.
	afterUsedAll func()
	// afterCAS, when set, runs after a compareAndSet of the store.
	afterCAS func()
	// block, when set, makes activeTenants wait on it.
	block chan struct{}
	// sweeps counts the calls of activeTenants.
	mu     sync.Mutex
	sweeps int
}

func (f *faultRepo) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if f.tenantErr != nil {
		return nil, f.tenantErr
	}
	return f.repo.tenant(ctx, tid)
}

func (f *faultRepo) activeTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	f.mu.Lock()
	f.sweeps++
	f.mu.Unlock()
	if f.block != nil {
		<-f.block
	}
	if f.activeErr != nil {
		return nil, f.activeErr
	}
	return f.repo.activeTenants(ctx)
}

func (f *faultRepo) sweepCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sweeps
}

func (f *faultRepo) usedBytes(ctx context.Context, tid tenant.ID) (int64, error) {
	if f.usedErr != nil {
		return 0, f.usedErr
	}
	return f.repo.usedBytes(ctx, tid)
}

func (f *faultRepo) usedBytesAll(ctx context.Context) (map[tenant.ID]int64, error) {
	if f.usedAllErr != nil {
		return nil, f.usedAllErr
	}
	m, err := f.repo.usedBytesAll(ctx)
	if f.afterUsedAll != nil {
		f.afterUsedAll()
	}
	return m, err
}

func (f *faultRepo) level(ctx context.Context, tid tenant.ID) (int, error) {
	if f.levelErr != nil {
		return 0, f.levelErr
	}
	if f.staleLevel >= 0 {
		return f.staleLevel, nil
	}
	return f.repo.level(ctx, tid)
}

func (f *faultRepo) compareAndSet(ctx context.Context, tid tenant.ID, old, level int, now time.Time) (bool, error) {
	if f.casErr != nil {
		return false, f.casErr
	}
	if f.casFalse {
		return false, nil
	}
	ok, err := f.repo.compareAndSet(ctx, tid, old, level, now)
	if f.afterCAS != nil {
		f.afterCAS()
	}
	return ok, err
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

// env is a monitor over a real database with fake mail dependencies.
type env struct {
	t        *testing.T
	db       *store.DB
	notifier *fakeNotifier
	mailer   *fakeMailer
	logs     *syncBuffer
	fault    *faultRepo
	mon      *Monitor
	n        int
}

// newEnv opens and migrates a database on e and builds a monitor whose
// repo is wrapped by env.fault (no fault by default).
func newEnv(t *testing.T, e storetest.Engine, opts Options) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return t0 }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ev := &env{
		t: t, db: db, notifier: &fakeNotifier{}, mailer: &fakeMailer{}, logs: &syncBuffer{},
		fault: &faultRepo{repo: storeRepo{db: db}, staleLevel: -1},
	}
	if opts.AdminLink == "" {
		opts.AdminLink = adminLink
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return t0 }
	}
	opts.Logger = slog.New(slog.NewTextHandler(ev.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ev.mon, err = newMonitor(ev.fault, ev.notifier, ev.mailer, audit.New(db), opts)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// tenant creates an active tenant with the quota.
func (ev *env) tenant(quota int64) *tenant.Tenant {
	ev.t.Helper()
	ev.n++
	tn, err := ev.db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: fmt.Sprintf("Entity %d", ev.n), FQDN: fmt.Sprintf("transfer.entity-%d.example.com", ev.n),
		DefaultLanguage: "en", MaxTransferBytes: 1 << 30, StorageQuotaBytes: quota,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return tn
}

// setQuota changes the quota of tn.
func (ev *env) setQuota(tn *tenant.Tenant, quota int64) {
	ev.t.Helper()
	c := *tn
	c.StorageQuotaBytes = quota
	if _, err := ev.db.Tenants().Update(context.Background(), &c); err != nil {
		ev.t.Fatal(err)
	}
}

// use stores an uploading transfer of tn declaring size bytes.
func (ev *env) use(tn *tenant.Tenant, size int64) {
	ev.t.Helper()
	ctx := context.Background()
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
		tr := store.Transfer{ID: id.New(id.Transfer), SenderEmail: "alice@entity-a.example.com", SenderKind: store.DepositorInternal, ExpiryDays: 7}
		return ev.db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@example.com"}, []store.TransferFile{f})
	})
	if err != nil {
		ev.t.Fatal(err)
	}
}

// randomHex returns n random bytes in hex.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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

// level returns the stored level of tn.
func (ev *env) level(tn *tenant.Tenant) int {
	ev.t.Helper()
	a, err := ev.db.QuotaAlerts().Get(context.Background(), tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	return a.Level
}

// check runs Check then ProcessPending.
func (ev *env) check(tn *tenant.Tenant, refused bool) {
	ev.mon.Check(tn.ID, refused)
	ev.mon.ProcessPending(context.Background())
}

// sweep runs a sweep that must succeed.
func (ev *env) sweep() {
	ev.t.Helper()
	if err := ev.mon.Sweep(context.Background()); err != nil {
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

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

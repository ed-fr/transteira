package apitoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Test values.
const (
	hostA     = "transfer.entity-a.example.com"
	hostB     = "transfer.entity-b.example.com"
	missingTn = tenant.ID("ten_01JAB00000000000000000000Z")
)

var (
	testStart = time.Date(2026, time.October, 22, 9, 0, 0, 0, time.UTC)
	adminIP   = netip.MustParseAddr("192.0.2.10")
	errBoom   = errors.New("boom")
)

// fakeClock is a manual clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// syncBuffer is a log sink safe for concurrent writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// faultRepo wraps a repo and fails the operations given an error.
type faultRepo struct {
	repo
	tenantErr, listErr, createErr, updateErr, revokeErr, hashErr, touchErr, auditErr error
	// tenantStatus overrides the status of the tenants read ("" keeps it).
	tenantStatus tenant.Status
	// hashOverride replaces the hash of the tokens found by hash.
	hashOverride []byte
	// touches counts the last-use writes.
	mu      sync.Mutex
	touches int
}

func (f *faultRepo) getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if f.tenantErr != nil {
		return nil, f.tenantErr
	}
	t, err := f.repo.getTenant(ctx, tid)
	if err == nil && f.tenantStatus != "" {
		t.Status = f.tenantStatus
	}
	return t, err
}

func (f *faultRepo) list(ctx context.Context, tid tenant.ID) ([]store.APIToken, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.repo.list(ctx, tid)
}

func (f *faultRepo) create(ctx context.Context, tid tenant.ID, t store.APIToken) (store.APIToken, error) {
	if f.createErr != nil {
		return store.APIToken{}, f.createErr
	}
	return f.repo.create(ctx, tid, t)
}

func (f *faultRepo) update(ctx context.Context, tid tenant.ID, tokID string, u store.APITokenUpdate) (store.APIToken, error) {
	if f.updateErr != nil {
		return store.APIToken{}, f.updateErr
	}
	return f.repo.update(ctx, tid, tokID, u)
}

func (f *faultRepo) revoke(ctx context.Context, tid tenant.ID, tokID string, now time.Time) (store.APIToken, bool, error) {
	if f.revokeErr != nil {
		return store.APIToken{}, false, f.revokeErr
	}
	return f.repo.revoke(ctx, tid, tokID, now)
}

func (f *faultRepo) getByHash(ctx context.Context, tid tenant.ID, hash []byte) (store.APIToken, error) {
	if f.hashErr != nil {
		return store.APIToken{}, f.hashErr
	}
	t, err := f.repo.getByHash(ctx, tid, hash)
	if err == nil && f.hashOverride != nil {
		t.TokenHash = f.hashOverride
	}
	return t, err
}

func (f *faultRepo) touch(ctx context.Context, tid tenant.ID, tokID string, at time.Time) error {
	f.mu.Lock()
	f.touches++
	f.mu.Unlock()
	if f.touchErr != nil {
		return f.touchErr
	}
	return f.repo.touch(ctx, tid, tokID, at)
}

func (f *faultRepo) audit(ctx context.Context, tid tenant.ID, ev audit.Event) error {
	if f.auditErr != nil {
		return f.auditErr
	}
	return f.repo.audit(ctx, tid, ev)
}

func (f *faultRepo) touchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.touches
}

// env is a service over a migrated database with tenants A and B.
type env struct {
	db    *store.DB
	clock *fakeClock
	logs  *syncBuffer
	repo  *faultRepo
	svc   *Service
	a, b  *tenant.Tenant
	// super is a super admin; delegA a delegated admin of A.
	super, delegA adminauth.Principal
}

// newEnv returns a fresh environment on engine e.
func newEnv(t *testing.T, e storetest.Engine) *env {
	t.Helper()
	ctx := context.Background()
	clock := &fakeClock{now: testStart}
	db, err := store.Open(ctx, e.Config(), store.WithClock(clock.Now))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ev := &env{db: db, clock: clock, logs: &syncBuffer{}}
	for _, h := range []string{hostA, hostB} {
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
			Name: "Entity " + h, FQDN: h, DefaultLanguage: "fr", MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.a == nil {
			ev.a = tn
		} else {
			ev.b = tn
		}
	}
	svc, err := New(db, Options{Now: clock.Now, Logger: slog.New(slog.NewTextHandler(ev.logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ev.repo = &faultRepo{repo: svc.repo}
	svc.repo = ev.repo
	ev.svc = svc
	ev.super = principal(store.RoleSuperAdmin, "root")
	ev.delegA = principal(store.RoleDelegatedAdmin, "admin.a", ev.a.ID)
	return ev
}

// principal returns an authenticated principal.
func principal(role store.AdminRole, username string, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: id.New(id.AdminSession), State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: id.New(id.Admin), Username: username, Role: role, TenantIDs: tids},
	}
}

// auditRows returns the audit events of tenant tid, oldest first, with
// their details decoded.
func (ev *env) auditRows(t *testing.T, tid tenant.ID) []auditRow {
	t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{TenantID: tid, Limit: store.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]auditRow, 0, len(page.Items))
	for i := len(page.Items) - 1; i >= 0; i-- {
		e := page.Items[i]
		r := auditRow{AuditEvent: e}
		if len(e.Details) > 0 {
			if err := json.Unmarshal(e.Details, &r.details); err != nil {
				t.Fatal(err)
			}
		}
		out = append(out, r)
	}
	return out
}

// auditRow is an audit event with its decoded details.
type auditRow struct {
	store.AuditEvent
	details map[string]any
}

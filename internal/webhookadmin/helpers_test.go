package webhookadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/webhook"
)

// Test values.
const (
	hostA = "transfer.entity-a.example.com"
	hostB = "transfer.entity-b.example.com"
	// deniedHost resolves to a denied network for the fake validator.
	deniedHost = "internal.example.com"
	// longHost makes the fake validator return an oversized hint.
	longHost = "long.example.com"
)

var (
	testStart = time.Date(2026, time.October, 27, 9, 0, 0, 0, time.UTC)
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

// fakeValidator accepts https URLs, refuses deniedHost as not allowed and
// anything else as invalid; longHost gets an oversized hint.
type fakeValidator struct{}

func (fakeValidator) ValidateURL(_ context.Context, raw string) (string, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "":
		return "", webhook.ErrURLInvalid
	case u.Host == deniedHost:
		return "", webhook.ErrURLNotAllowed
	case u.Host == longHost:
		return "https://" + strings.Repeat("h", store.MaxWebhookURLHintLen), nil
	}
	return u.Scheme + "://" + u.Host, nil
}

// fakeTester records the targets it is given and answers result.
type fakeTester struct {
	mu      sync.Mutex
	targets []webhook.Target
	result  webhook.Result
}

func (f *fakeTester) SendTest(_ context.Context, t webhook.Target, _ time.Time) webhook.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets = append(f.targets, t)
	return f.result
}

func (f *fakeTester) last() webhook.Target {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.targets[len(f.targets)-1]
}

// faultVault wraps a vault and fails the n-th call (1-based, 0 never) of
// the operations given a counter.
type faultVault struct {
	Vault
	mu                                           sync.Mutex
	sealAt, openAt, wrapAt, destroyAt, sealCalls int
	openCalls, wrapCalls, destroyCalls           int
	scrubErr                                     error
	// openMissing is the number of next Open and OpenSystem calls that
	// fail with store.ErrNotFound, as when a concurrent change destroyed
	// the key.
	openMissing int
}

// missing reports whether the current open call finds no key.
func (f *faultVault) missing() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.openMissing == 0 {
		return false
	}
	f.openMissing--
	return true
}

func (f *faultVault) fail(at int, calls *int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	*calls++
	return at != 0 && *calls == at
}

func (f *faultVault) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sealAt, f.openAt, f.wrapAt, f.destroyAt = 0, 0, 0, 0
	f.sealCalls, f.openCalls, f.wrapCalls, f.destroyCalls = 0, 0, 0, 0
	f.scrubErr, f.openMissing = nil, 0
}

func (f *faultVault) SealTx(ctx context.Context, tx *store.ScopedTx, p crypto.Purpose, b []byte) (string, error) {
	if f.fail(f.sealAt, &f.sealCalls) {
		return "", errBoom
	}
	return f.Vault.SealTx(ctx, tx, p, b)
}

func (f *faultVault) Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error) {
	if f.fail(f.openAt, &f.openCalls) {
		return nil, errBoom
	}
	if f.missing() {
		return nil, fmt.Errorf("open: %w", store.ErrNotFound)
	}
	return f.Vault.Open(ctx, tid, p, wkID)
}

func (f *faultVault) OpenSystem(ctx context.Context, p crypto.Purpose, ssID string) ([]byte, error) {
	if f.fail(f.openAt, &f.openCalls) {
		return nil, errBoom
	}
	if f.missing() {
		return nil, fmt.Errorf("open system: %w", store.ErrNotFound)
	}
	return f.Vault.OpenSystem(ctx, p, ssID)
}

func (f *faultVault) WrapSystem(p crypto.Purpose, b []byte) (store.SystemSecret, error) {
	if f.fail(f.wrapAt, &f.wrapCalls) {
		return store.SystemSecret{}, errBoom
	}
	return f.Vault.WrapSystem(p, b)
}

func (f *faultVault) DestroyTx(ctx context.Context, tx *store.ScopedTx, wkID string) error {
	if f.fail(f.destroyAt, &f.destroyCalls) {
		return errBoom
	}
	return f.Vault.DestroyTx(ctx, tx, wkID)
}

func (f *faultVault) Scrub(ctx context.Context) error {
	f.mu.Lock()
	err := f.scrubErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return f.Vault.Scrub(ctx)
}

// faults are the owner operations to fail.
type faults struct {
	mu                                sync.Mutex
	listErr, subscribedErr, createErr error
	auditErr, tenantErr, getErr       error
	tenantStatus                      tenant.Status
}

func (f *faults) get(p *error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *p
}

func (f *faults) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listErr, f.subscribedErr, f.createErr, f.auditErr, f.tenantErr, f.getErr = nil, nil, nil, nil, nil, nil
	f.tenantStatus = ""
}

// faultOwner wraps an owner and fails the operations of its faults.
type faultOwner struct {
	owner
	f *faults
}

func (o *faultOwner) list(ctx context.Context) ([]store.Webhook, error) {
	if err := o.f.get(&o.f.listErr); err != nil {
		return nil, err
	}
	return o.owner.list(ctx)
}

func (o *faultOwner) subscribed(ctx context.Context, t events.Type) ([]store.Webhook, error) {
	if err := o.f.get(&o.f.subscribedErr); err != nil {
		return nil, err
	}
	return o.owner.subscribed(ctx, t)
}

func (o *faultOwner) get(ctx context.Context, whkID string) (store.Webhook, error) {
	if err := o.f.get(&o.f.getErr); err != nil {
		return store.Webhook{}, err
	}
	return o.owner.get(ctx, whkID)
}

func (o *faultOwner) create(ctx context.Context, w store.Webhook, u, secret []byte) (store.Webhook, error) {
	if err := o.f.get(&o.f.createErr); err != nil {
		return store.Webhook{}, err
	}
	return o.owner.create(ctx, w, u, secret)
}

func (o *faultOwner) audit(ctx context.Context, ev audit.Event) error {
	if err := o.f.get(&o.f.auditErr); err != nil {
		return err
	}
	return o.owner.audit(ctx, ev)
}

// env is a service over a migrated database with tenants A and B.
type env struct {
	db     *store.DB
	clock  *fakeClock
	logs   *syncBuffer
	vault  *faultVault
	tester *fakeTester
	faults *faults
	svc    *Service
	a, b   *tenant.Tenant
	// super is a super admin; delegA a delegated admin of A, delegB of B.
	super, delegA, delegB adminauth.Principal
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
	kr, err := masterkey.New(masterkeytest.Key(t, "webhookadmin"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := &env{
		db: db, clock: clock, logs: &syncBuffer{}, vault: &faultVault{Vault: masterkey.NewVault(db, kr, nil)},
		tester: &fakeTester{result: webhook.Result{Success: true, HTTPStatus: 200, Duration: 180 * time.Millisecond}},
		faults: &faults{},
	}
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
	svc, err := New(db, ev.vault, Options{
		Validator: fakeValidator{}, Tester: ev.tester, Now: clock.Now,
		Logger: slog.New(slog.NewTextHandler(ev.logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	tenantOwner, systemOwner, getTenant := svc.tenantOwner, svc.systemOwner, svc.getTenant
	svc.tenantOwner = func(tid tenant.ID) owner { return &faultOwner{owner: tenantOwner(tid), f: ev.faults} }
	svc.systemOwner = &faultOwner{owner: systemOwner, f: ev.faults}
	svc.getTenant = func(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
		if err := ev.faults.get(&ev.faults.tenantErr); err != nil {
			return nil, err
		}
		tn, err := getTenant(ctx, tid)
		ev.faults.mu.Lock()
		defer ev.faults.mu.Unlock()
		if err == nil && ev.faults.tenantStatus != "" {
			tn.Status = ev.faults.tenantStatus
		}
		return tn, err
	}
	ev.svc = svc
	ev.super = principal(store.RoleSuperAdmin, "root")
	ev.delegA = principal(store.RoleDelegatedAdmin, "admin.a", ev.a.ID)
	ev.delegB = principal(store.RoleDelegatedAdmin, "admin.b", ev.b.ID)
	return ev
}

// principal returns an authenticated principal.
func principal(role store.AdminRole, username string, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: id.New(id.AdminSession), State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: id.New(id.Admin), Username: username, Role: role, TenantIDs: tids},
	}
}

// auditRow is an audit event with its decoded details.
type auditRow struct {
	store.AuditEvent
	details map[string]any
}

// auditRows returns the audit events of tenant tid ("" for the global
// events only), oldest first, with their details decoded.
func (ev *env) auditRows(t *testing.T, tid tenant.ID) []auditRow {
	t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{TenantID: tid, Limit: store.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]auditRow, 0, len(page.Items))
	for i := len(page.Items) - 1; i >= 0; i-- {
		e := page.Items[i]
		if tid == "" && e.TenantID != "" {
			continue
		}
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

// lastAudit returns the last audit event of tid.
func (ev *env) lastAudit(t *testing.T, tid tenant.ID) auditRow {
	t.Helper()
	rows := ev.auditRows(t, tid)
	if len(rows) == 0 {
		t.Fatal("no audit event")
	}
	return rows[len(rows)-1]
}

// genericInput returns a valid creation of a generic tenant webhook.
func genericInput() CreateInput {
	return CreateInput{
		Name: "SIEM collector", Kind: store.WebhookGeneric, URL: "https://siem.example.com/hooks/transteira?key=EXAMPLE",
		Events: []events.Type{events.VirusDetected, events.QuotaReached},
	}
}

// teamsInput returns a valid creation of a Teams webhook receiving evs.
func teamsInput(evs ...events.Type) CreateInput {
	return CreateInput{
		Name: "Security channel", Kind: store.WebhookTeams, URL: "https://hooks.example.com/webhookb2/EXAMPLE", Events: evs,
	}
}

package tenantadmin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Test hosts.
const (
	adminHost = "admin.example.com"
	hostA     = "transfer.entity-a.example.com"
	hostB     = "transfer.entity-b.example.com"
)

var (
	testStart = time.Date(2026, time.October, 22, 9, 0, 0, 0, time.UTC)
	clientIP  = netip.MustParseAddr("192.0.2.10")
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

// memAssets is an in-memory AssetStore.
type memAssets struct {
	mu     sync.Mutex
	data   map[string][]byte
	putErr error
	getErr error
	delErr error
}

func assetKey(tid tenant.ID, kind branding.Kind) string { return string(tid) + "/" + kind.String() }

func (m *memAssets) Put(tid tenant.ID, kind branding.Kind, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	m.data[assetKey(tid, kind)] = bytes.Clone(data)
	return nil
}

func (m *memAssets) Get(tid tenant.ID, kind branding.Kind) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	d, ok := m.data[assetKey(tid, kind)]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return bytes.Clone(d), nil
}

func (m *memAssets) Delete(tid tenant.ID, kind branding.Kind) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.delErr != nil {
		return m.delErr
	}
	delete(m.data, assetKey(tid, kind))
	return nil
}

func (m *memAssets) has(tid tenant.ID, kind branding.Kind) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[assetKey(tid, kind)]
	return ok
}

// fakeEraser erases a tenant like the lifecycle sweeper would: keys, then
// the tenant row. err makes the next call fail after the keys are erased
// (an interrupted deletion).
// cancelable counts the calls made with a context that can be canceled.
type fakeEraser struct {
	db         *store.DB
	mu         sync.Mutex
	calls      []tenant.ID
	cancelable int
	err        error
	// started checks the audit trail when the eraser is called.
	started func(tid tenant.ID)
}

func (e *fakeEraser) EraseTenant(ctx context.Context, tid tenant.ID) error {
	if e.started != nil {
		e.started(tid)
	}
	e.mu.Lock()
	e.calls = append(e.calls, tid)
	if ctx.Done() != nil {
		e.cancelable++
	}
	fail := e.err
	e.err = nil
	e.mu.Unlock()
	keys := e.db.WrappedKeys()
	for {
		ids, err := keys.ListIDs(ctx, tid, "", 100)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			break
		}
		for _, k := range ids {
			if err := keys.Delete(ctx, tid, k); err != nil {
				return err
			}
		}
	}
	if fail != nil {
		return fail
	}
	err := e.db.Tenants().Delete(ctx, tid)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

func (e *fakeEraser) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.calls)
}

// fakeMailer records the messages; err is returned by Send.
type fakeMailer struct {
	mu   sync.Mutex
	sent []sentMail
	err  error
}

type sentMail struct {
	settings mail.Settings
	msg      mail.Message
}

func (m *fakeMailer) Send(_ context.Context, s mail.Settings, msg mail.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentMail{s, msg})
	return m.err
}

func (m *fakeMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// guardedMailer dials the server through a netpolicy.DialGuard before delegating to
// inner, as the SMTP sender of the application does once wired with
// DialGuard.DialContext.
type guardedMailer struct {
	guard *netpolicy.DialGuard
	inner Mailer
}

func (g guardedMailer) Send(ctx context.Context, s mail.Settings, msg mail.Message) error {
	conn, err := g.guard.DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return fmt.Errorf("%w: connect: %w", mail.ErrSMTP, err)
	}
	_ = conn.Close()
	return g.inner.Send(ctx, s, msg)
}

// fakeResolver answers from maps.
type fakeResolver struct {
	mu      sync.Mutex
	txt     map[string][]string
	txtErr  map[string]error
	ips     map[string][]netip.Addr
	ipErr   error
	lookups []string
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{txt: map[string][]string{}, txtErr: map[string]error{}, ips: map[string][]netip.Addr{}}
}

func (r *fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups = append(r.lookups, name)
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("lookup without deadline")
	}
	if err, ok := r.txtErr[name]; ok {
		return nil, err
	}
	recs, ok := r.txt[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return recs, nil
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ipErr != nil {
		return nil, r.ipErr
	}
	return r.ips[host], nil
}

// fakeCache records the invalidations.
type fakeCache struct {
	mu      sync.Mutex
	tenants []tenant.ID
	hosts   []string
}

func (c *fakeCache) InvalidateTenant(tid tenant.ID) {
	c.mu.Lock()
	c.tenants = append(c.tenants, tid)
	c.mu.Unlock()
}

func (c *fakeCache) Invalidate(host string) {
	c.mu.Lock()
	c.hosts = append(c.hosts, host)
	c.mu.Unlock()
}

func (c *fakeCache) sawHost(h string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range c.hosts {
		if x == h {
			return true
		}
	}
	return false
}

// faultRepo wraps a repo and fails the methods named in errs.
type faultRepo struct {
	repo
	mu   sync.Mutex
	errs map[string]error
	// after lets a method succeed n times before failing.
	after map[string]int
}

func (f *faultRepo) fail(method string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err, ok := f.errs[method]
	if !ok {
		return nil
	}
	if f.after[method] > 0 {
		f.after[method]--
		return nil
	}
	return err
}

func (f *faultRepo) getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if err := f.fail("getTenant"); err != nil {
		return nil, err
	}
	return f.repo.getTenant(ctx, tid)
}

func (f *faultRepo) listTenants(ctx context.Context, o store.TenantListOptions) (store.Page[*tenant.Tenant], error) {
	if err := f.fail("listTenants"); err != nil {
		return store.Page[*tenant.Tenant]{}, err
	}
	return f.repo.listTenants(ctx, o)
}

func (f *faultRepo) createTenant(ctx context.Context, t *tenant.Tenant) (*tenant.Tenant, error) {
	if err := f.fail("createTenant"); err != nil {
		return nil, err
	}
	return f.repo.createTenant(ctx, t)
}

func (f *faultRepo) updateTenant(ctx context.Context, t *tenant.Tenant) (*tenant.Tenant, error) {
	if err := f.fail("updateTenant"); err != nil {
		return nil, err
	}
	return f.repo.updateTenant(ctx, t)
}

func (f *faultRepo) setTenantStatus(ctx context.Context, tid tenant.ID, st tenant.Status) error {
	if err := f.fail("setTenantStatus"); err != nil {
		return err
	}
	return f.repo.setTenantStatus(ctx, tid, st)
}

func (f *faultRepo) usedBytes(ctx context.Context, tid tenant.ID) (int64, error) {
	if err := f.fail("usedBytes"); err != nil {
		return 0, err
	}
	return f.repo.usedBytes(ctx, tid)
}

func (f *faultRepo) networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error) {
	if err := f.fail("networkRules"); err != nil {
		return store.NetworkRuleSet{}, err
	}
	return f.repo.networkRules(ctx, tid)
}

func (f *faultRepo) replaceNetworkRules(ctx context.Context, tid tenant.ID, c []netip.Prefix, d []string) (store.NetworkRuleSet, error) {
	if err := f.fail("replaceNetworkRules"); err != nil {
		return store.NetworkRuleSet{}, err
	}
	return f.repo.replaceNetworkRules(ctx, tid, c, d)
}

func (f *faultRepo) smtp(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error) {
	if err := f.fail("smtp"); err != nil {
		return store.SMTPConfig{}, err
	}
	return f.repo.smtp(ctx, tid)
}

func (f *faultRepo) putSMTP(ctx context.Context, tid tenant.ID, c store.SMTPConfig, u passwordUpdate) error {
	if err := f.fail("putSMTP"); err != nil {
		return err
	}
	return f.repo.putSMTP(ctx, tid, c, u)
}

func (f *faultRepo) openSecret(ctx context.Context, tid tenant.ID, wk string) ([]byte, error) {
	if err := f.fail("openSecret"); err != nil {
		return nil, err
	}
	return f.repo.openSecret(ctx, tid, wk)
}

func (f *faultRepo) template(ctx context.Context, tid tenant.ID, k, l string) (store.EmailTemplate, error) {
	if err := f.fail("template"); err != nil {
		return store.EmailTemplate{}, err
	}
	return f.repo.template(ctx, tid, k, l)
}

func (f *faultRepo) listTemplates(ctx context.Context, tid tenant.ID) ([]store.EmailTemplateSummary, error) {
	if err := f.fail("listTemplates"); err != nil {
		return nil, err
	}
	return f.repo.listTemplates(ctx, tid)
}

func (f *faultRepo) putTemplate(ctx context.Context, tid tenant.ID, t store.EmailTemplate) (store.EmailTemplate, error) {
	if err := f.fail("putTemplate"); err != nil {
		return store.EmailTemplate{}, err
	}
	return f.repo.putTemplate(ctx, tid, t)
}

func (f *faultRepo) deleteTemplate(ctx context.Context, tid tenant.ID, k, l string) error {
	if err := f.fail("deleteTemplate"); err != nil {
		return err
	}
	return f.repo.deleteTemplate(ctx, tid, k, l)
}

func (f *faultRepo) legal(ctx context.Context, tid tenant.ID, d, l string) (store.LegalDocument, error) {
	if err := f.fail("legal"); err != nil {
		return store.LegalDocument{}, err
	}
	return f.repo.legal(ctx, tid, d, l)
}

func (f *faultRepo) putLegal(ctx context.Context, tid tenant.ID, d store.LegalDocument) (store.LegalDocument, error) {
	if err := f.fail("putLegal"); err != nil {
		return store.LegalDocument{}, err
	}
	return f.repo.putLegal(ctx, tid, d)
}

func (f *faultRepo) deleteLegal(ctx context.Context, tid tenant.ID, d, l string) error {
	if err := f.fail("deleteLegal"); err != nil {
		return err
	}
	return f.repo.deleteLegal(ctx, tid, d, l)
}

func (f *faultRepo) listLegal(ctx context.Context, tid tenant.ID) ([]store.LegalDocumentKey, error) {
	if err := f.fail("listLegal"); err != nil {
		return nil, err
	}
	return f.repo.listLegal(ctx, tid)
}

func (f *faultRepo) audit(ctx context.Context, ev audit.Event) error {
	if err := f.fail("audit"); err != nil {
		return err
	}
	return f.repo.audit(ctx, ev)
}

// env is a service over a migrated database with tenants A and B, a super
// admin and a delegated admin of each tenant.
type env struct {
	db       *store.DB
	svc      *Service
	clock    *fakeClock
	assets   *memAssets
	eraser   *fakeEraser
	mailer   *fakeMailer
	resolver *fakeResolver
	cache    *fakeCache
	vault    *masterkey.Vault
	logs     *bytes.Buffer
	a, b     *tenant.Tenant
	super    adminauth.Principal
	adminA   adminauth.Principal
	adminB   adminauth.Principal
}

// envOption customizes the options of the service of an env.
type envOption func(*Options)

// newEnv builds an env on engine e.
func newEnv(t *testing.T, e storetest.Engine, opts ...envOption) *env {
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
	kr, err := masterkey.New(masterkeytest.Key(t, "tenantadmin"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := &env{
		db: db, clock: clock, assets: &memAssets{data: map[string][]byte{}}, eraser: &fakeEraser{db: db},
		mailer: &fakeMailer{}, resolver: newFakeResolver(), cache: &fakeCache{},
		vault: masterkey.NewVault(db, kr, nil), logs: &bytes.Buffer{},
	}
	o := Options{
		AdminHosts: []string{adminHost}, SMTPDenyNetworks: mustPrefixes("127.0.0.0/8", "169.254.0.0/16", "::1/128"),
		Vault: ev.vault, Assets: ev.assets, Eraser: ev.eraser, Mailer: ev.mailer, Resolver: ev.resolver,
		Cache: ev.cache, Logger: slog.New(slog.NewTextHandler(ev.logs, nil)), Now: clock.Now,
	}
	for _, f := range opts {
		f(&o)
	}
	ev.svc, err = New(db, o)
	if err != nil {
		t.Fatal(err)
	}
	ev.a = ev.newTenant(t, "Entity A", hostA)
	ev.b = ev.newTenant(t, "Entity B", hostB)
	ev.super = principal(store.RoleSuperAdmin, "root")
	ev.adminA = principal(store.RoleDelegatedAdmin, "alice", ev.a.ID)
	ev.adminB = principal(store.RoleDelegatedAdmin, "bob", ev.b.ID)
	return ev
}

// newTenant creates a tenant directly in the store.
func (ev *env) newTenant(t *testing.T, name, fqdn string) *tenant.Tenant {
	t.Helper()
	tn, err := ev.db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: name, FQDN: fqdn, DefaultLanguage: "en", MaxTransferBytes: 10 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn
}

// faults replaces the repo of the service with a faultRepo failing the
// given methods with errBoom.
func (ev *env) faults(methods ...string) *faultRepo {
	inner := ev.svc.repo
	if prev, ok := inner.(*faultRepo); ok {
		inner = prev.repo
	}
	f := &faultRepo{repo: inner, errs: map[string]error{}, after: map[string]int{}}
	for _, m := range methods {
		f.errs[m] = errBoom
	}
	ev.svc.repo = f
	return f
}

// auditEvents returns the audit events of tenant tid with action.
func (ev *env) auditEvents(t *testing.T, tid tenant.ID, action audit.Action) []store.AuditEvent {
	t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{TenantID: tid, Action: string(action)})
	if err != nil {
		t.Fatal(err)
	}
	return page.Items
}

// principal returns an authenticated principal.
func principal(role store.AdminRole, username string, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: id.New(id.AdminSession), State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: id.New(id.Admin), Username: username, Role: role, TenantIDs: tids},
	}
}

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, x := range s {
		out[i] = netip.MustParsePrefix(x)
	}
	return out
}

func ptr[T any](v T) *T { return &v }

// wantErr fails unless errors.Is(err, target).
func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want %v", what, err, target)
	}
}

// wantInvalid fails unless err is an *InvalidError on field.
func wantInvalid(t *testing.T, what string, err error, field string) {
	t.Helper()
	_ = invalidOf(t, what, err, field)
}

// invalidOf returns err as an *InvalidError on field, or fails.
func invalidOf(t *testing.T, what string, err error, field string) *InvalidError {
	t.Helper()
	var ie *InvalidError
	if !errors.As(err, &ie) || !errors.Is(err, ErrInvalid) || ie.Field != field || ie.Error() == "" {
		t.Fatalf("%s: got %v, want an invalid %q", what, err, field)
	}
	return ie
}

// mustNoErr fails on err.
func mustNoErr(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// containsString reports whether s holds sub.
func containsString(s, sub string) bool { return strings.Contains(s, sub) }

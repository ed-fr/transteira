package provisioning

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// Fixed values of the tests.
const adminHost = "admin.example.com"

var (
	testStart = time.Date(2026, time.November, 1, 9, 0, 0, 0, time.UTC)
	mspIP     = netip.MustParseAddr("198.51.100.20")
	otherIP   = netip.MustParseAddr("203.0.113.9")
	errBoom   = errors.New("boom")
)

// clock is a settable clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeConfirmer is a TOTP re-confirmation answering acc or err.
type fakeConfirmer struct {
	mu    sync.Mutex
	acc   adminauth.Account
	err   error
	calls int
}

func (f *fakeConfirmer) ConfirmTOTP(context.Context, adminauth.Principal, string, string, netip.Addr) (adminauth.Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.acc, f.err
}

func (f *fakeConfirmer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// recordingPublisher records the published events.
type recordingPublisher struct {
	mu  sync.Mutex
	evs []events.Event
}

func (p *recordingPublisher) Publish(ev events.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.evs = append(p.evs, ev)
}

func (p *recordingPublisher) all() []events.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.evs)
}

// tenantEvents returns the published events but the
// provisioning_token.created ones of the token creations.
func (p *recordingPublisher) tenantEvents() []events.Event {
	return slices.DeleteFunc(p.all(), func(ev events.Event) bool { return ev.Type == events.ProvisioningTokenCreated })
}

// recordingNotifier records the notices to the super admins.
type recordingNotifier struct {
	mu          sync.Mutex
	provisioned []tenantadmin.ProvisioningNotice
	completed   []tenantadmin.ProvisioningNotice
	tokens      []tenantadmin.ProvisioningTokenNotice
}

func (n *recordingNotifier) TenantProvisioned(_ context.Context, x tenantadmin.ProvisioningNotice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.provisioned = append(n.provisioned, x)
}

func (n *recordingNotifier) TenantSetupCompleted(_ context.Context, x tenantadmin.ProvisioningNotice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.completed = append(n.completed, x)
}

func (n *recordingNotifier) TokenCreated(_ context.Context, x tenantadmin.ProvisioningTokenNotice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tokens = append(n.tokens, x)
}

func (n *recordingNotifier) tokenNotices() []tenantadmin.ProvisioningTokenNotice {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.tokens)
}

func (n *recordingNotifier) provisionedCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.provisioned)
}

// inviteMailer records the invitation mails of the delegated admins.
type inviteMailer struct {
	mu    sync.Mutex
	mails []adminauth.InvitationMail
}

func (m *inviteMailer) SendInvitation(_ context.Context, im adminauth.InvitationMail) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mails = append(m.mails, im)
}

func (m *inviteMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.mails)
}

// nopHasher is a PasswordHasher for accounts that never log in.
type nopHasher struct{}

func (nopHasher) HashPassword(context.Context, []byte) (string, error)         { return "$fake$00", nil }
func (nopHasher) VerifyPassword(context.Context, string, []byte) (bool, error) { return false, nil }

// nopAssets, nopEraser and nopMailer are the unused dependencies of the
// tenant administration.
type (
	nopAssets struct{}
	nopEraser struct{}
	nopMailer struct{}
)

func (nopAssets) Put(tenant.ID, branding.Kind, []byte) error              { return nil }
func (nopAssets) Get(tenant.ID, branding.Kind) ([]byte, error)            { return nil, io.EOF }
func (nopAssets) Delete(tenant.ID, branding.Kind) error                   { return nil }
func (nopEraser) EraseTenant(context.Context, tenant.ID) error            { return nil }
func (nopMailer) Send(context.Context, mail.Settings, mail.Message) error { return nil }

// env is a provisioning service over a migrated database, wired to a real
// tenant administration and account service.
type env struct {
	db       *store.DB
	svc      *Service
	clock    *clock
	confirm  *fakeConfirmer
	pub      *recordingPublisher
	notifier *recordingNotifier
	mailer   *inviteMailer
	tenants  *tenantadmin.Service
	logs     *bytes.Buffer
	super    adminauth.Principal
}

// envConfig changes the wiring of an env.
type envConfig struct {
	noMailer bool
}

// newEnv builds an env on engine e.
func newEnv(t *testing.T, e storetest.Engine, cfgs ...func(*envConfig)) *env {
	t.Helper()
	var cfg envConfig
	for _, f := range cfgs {
		f(&cfg)
	}
	ctx := context.Background()
	clk := &clock{now: testStart}
	db, err := store.Open(ctx, e.Config(), store.WithClock(clk.Now))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	kr, err := masterkey.New(masterkeytest.Key(t, "provisioning"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kr.Close)
	vault := masterkey.NewVault(db, kr, nil)
	ev := &env{
		db: db, clock: clk, pub: &recordingPublisher{}, notifier: &recordingNotifier{}, mailer: &inviteMailer{},
		logs: &bytes.Buffer{},
	}
	aopts := adminauth.Options{AdminBaseURL: "https://" + adminHost, Now: clk.Now}
	if !cfg.noMailer {
		aopts.Mailer = ev.mailer
	}
	admins, err := adminauth.New(db, kr, vault, nopHasher{}, securitylog.New(io.Discard), aopts)
	if err != nil {
		t.Fatal(err)
	}
	ev.tenants, err = tenantadmin.New(db, tenantadmin.Options{
		AdminHosts: []string{adminHost}, Vault: vault, Assets: nopAssets{}, Eraser: nopEraser{}, Mailer: nopMailer{},
		Admins: admins, Now: clk.Now, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev.super = principal(store.RoleSuperAdmin, "root")
	ev.confirm = &fakeConfirmer{acc: ev.super.Admin}
	ev.svc, err = New(db, Options{
		Confirmer: ev.confirm, Tenants: ev.tenants, AdminHosts: []string{"Admin.Example.com."}, Events: ev.pub,
		Notifier: ev.notifier, Logger: slog.New(slog.NewTextHandler(ev.logs, nil)), Now: clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// principal returns an authenticated admin principal.
func principal(role store.AdminRole, username string, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: id.New(id.AdminSession), State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: id.New(id.Admin), Username: username, Role: role, TenantIDs: tids, TOTPEnabled: true},
	}
}

// goodCreate returns a valid token creation.
func goodCreate() TokenCreate {
	return TokenCreate{
		Name: "Managed service provider", AllowedCIDRs: []string{"198.51.100.0/24"},
		AllowedFQDNSuffixes: []string{".Transfer.Example.com."}, MaxStorageQuotaBytes: 1 << 40, MaxTenants: 5,
	}
}

// mustToken creates a token from in and returns it with its secret.
func (ev *env) mustToken(t *testing.T, in TokenCreate) CreatedToken {
	t.Helper()
	tok, err := ev.svc.CreateToken(context.Background(), ev.super, in, "123456", "", mspIP)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	return tok
}

// mustAuth authenticates secret from mspIP.
func (ev *env) mustAuth(t *testing.T, secret string) Principal {
	t.Helper()
	p, err := ev.svc.Authenticate(context.Background(), secret, mspIP)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return p
}

// request returns a valid provisioning request under fqdn.
func request(fqdn, username string) TenantRequest {
	return TenantRequest{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "fr", StorageQuotaBytes: 1 << 30,
		DelegatedAdmin: adminauth.DelegatedAdmin{Username: username, Email: username + "@entity.example.com", Language: "fr"},
	}
}

// auditEvents returns the audit events with action, oldest first.
func (ev *env) auditEvents(t *testing.T, action audit.Action) []store.AuditEvent {
	t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{Action: string(action), Limit: store.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(page.Items)
	return page.Items
}

// faultRepo wraps a repo and fails the methods named in errs.
type faultRepo struct {
	repo
	errs map[string]error
	// hash replaces the hash of the token read by tokenByHash when set.
	hash []byte
}

func (f *faultRepo) fail(m string) error { return f.errs[m] }

func (f *faultRepo) createToken(ctx context.Context, t store.ProvisioningToken, then func(*store.SystemTx, store.ProvisioningToken) error) (store.ProvisioningToken, error) {
	if err := f.fail("createToken"); err != nil {
		return store.ProvisioningToken{}, err
	}
	return f.repo.createToken(ctx, t, then)
}

func (f *faultRepo) listTokens(ctx context.Context) ([]store.ProvisioningToken, error) {
	if err := f.fail("listTokens"); err != nil {
		return nil, err
	}
	return f.repo.listTokens(ctx)
}

func (f *faultRepo) revokeToken(ctx context.Context, tokID string, now time.Time, then func(*store.SystemTx, store.ProvisioningToken, bool) error) (store.ProvisioningToken, bool, error) {
	if err := f.fail("revokeToken"); err != nil {
		return store.ProvisioningToken{}, false, err
	}
	return f.repo.revokeToken(ctx, tokID, now, then)
}

func (f *faultRepo) tokenByHash(ctx context.Context, hash []byte) (store.ProvisioningToken, error) {
	if err := f.fail("tokenByHash"); err != nil {
		return store.ProvisioningToken{}, err
	}
	tok, err := f.repo.tokenByHash(ctx, hash)
	if f.hash != nil {
		tok.TokenHash = f.hash
	}
	return tok, err
}

func (f *faultRepo) touch(ctx context.Context, tokID string, at time.Time) error {
	if err := f.fail("touch"); err != nil {
		return err
	}
	return f.repo.touch(ctx, tokID, at)
}

func (f *faultRepo) listTenants(ctx context.Context, tokID string) ([]store.ProvisionedTenant, error) {
	if err := f.fail("listTenants"); err != nil {
		return nil, err
	}
	return f.repo.listTenants(ctx, tokID)
}

func (f *faultRepo) getTenant(ctx context.Context, tokID string, tid tenant.ID) (store.ProvisionedTenant, error) {
	if err := f.fail("getTenant"); err != nil {
		return store.ProvisionedTenant{}, err
	}
	return f.repo.getTenant(ctx, tokID, tid)
}

func (f *faultRepo) record(ctx context.Context, ev audit.Event) error {
	if err := f.fail("record"); err != nil {
		return err
	}
	return f.repo.record(ctx, ev)
}

func (f *faultRepo) recordTx(ctx context.Context, tx *store.SystemTx, ev audit.Event) error {
	if err := f.fail("recordTx"); err != nil {
		return err
	}
	return f.repo.recordTx(ctx, tx, ev)
}

// faults replaces the repo of the service with a faultRepo failing the
// given methods with errBoom, and returns it.
func (ev *env) faults(methods ...string) *faultRepo {
	inner := ev.svc.repo
	if prev, ok := inner.(*faultRepo); ok {
		inner = prev.repo
	}
	f := &faultRepo{repo: inner, errs: map[string]error{}}
	for _, m := range methods {
		f.errs[m] = errBoom
	}
	ev.svc.repo = f
	return f
}

// wantErr fails unless errors.Is(err, target).
func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Errorf("%s: got %v, want %v", what, err, target)
	}
}

// wantField fails unless err is an *InvalidError on field.
func wantField(t *testing.T, what string, err error, field string) {
	t.Helper()
	var ie *InvalidError
	if !errors.As(err, &ie) || ie.Field != field || !errors.Is(err, ErrInvalid) {
		t.Errorf("%s: got %v, want an invalid %q", what, err, field)
	}
}

// wantScope fails unless err is a *ScopeError on field.
func wantScope(t *testing.T, what string, err error, field string) {
	t.Helper()
	var se *ScopeError
	if !errors.As(err, &se) || se.Field != field || !errors.Is(err, ErrScopeExceeded) {
		t.Errorf("%s: got %v, want a scope error on %q", what, err, field)
	}
}

// wantReason fails unless err is an *AuthError of reason.
func wantReason(t *testing.T, what string, err error, reason string) {
	t.Helper()
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Reason != reason || !errors.Is(err, ErrInvalidToken) || ae.Error() != ErrInvalidToken.Error() {
		t.Errorf("%s: got %v, want an auth error %q", what, err, reason)
	}
}

package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/upload"
)

// The tests that run on every engine are deliberately not parallel: each
// PostgreSQL engine holds its own connection pool, and make test runs every
// package at once against a server limited to 100 connections.

// Fixed values of the tests. Domains are fictitious.
const (
	hostA     = "transfer.entity-a.example.com"
	hostB     = "transfer.entity-b.example.com"
	alice     = "alice@entity-a.example.com" // internal user
	carol     = "carol@entity-a.example.com" // another internal user
	bob       = "bob@partner.example.org"    // external user
	dave      = "dave@customer.example.net"  // recipient
	emptySHA  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	maxBytes  = 1 << 30
	quota     = 10 << 30
	uploadTTL = 24 * time.Hour
)

var (
	testStart  = time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)
	internalIP = netip.MustParseAddr("10.1.2.3")
	externalIP = netip.MustParseAddr("203.0.113.7")
	errFault   = errors.New("injected fault")
)

// fakeClock is a settable clock.
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
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeSeclog captures the security events; err makes Log fail.
type fakeSeclog struct {
	mu     sync.Mutex
	events []securitylog.Event
	err    error
}

func (l *fakeSeclog) Log(ev securitylog.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
	return l.err
}

// reasons returns the reasons of the deposit_refused events.
func (l *fakeSeclog) reasons() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, ev := range l.events {
		if ev.Type == securitylog.DepositRefused {
			out = append(out, ev.Fields[0].Value)
		}
	}
	return out
}

// fakeHasher hashes passwords into a fixed PHC-looking string. When block
// is set, its first call signals entered then waits for block to be closed;
// later calls do not wait.
type fakeHasher struct {
	mu      sync.Mutex
	err     error
	entered chan struct{}
	block   chan struct{}
}

func (h *fakeHasher) HashPassword(_ context.Context, pw []byte) (string, error) {
	h.mu.Lock()
	block := h.block
	h.block = nil
	h.mu.Unlock()
	if block != nil {
		close(h.entered)
		<-block
	}
	if h.err != nil {
		return "", h.err
	}
	return "$fake$" + hex.EncodeToString(pw), nil
}

// fakeUploads is an upload engine without disk: RemoveFile destroys the data
// key for real (so that the rows can be deleted) and records the order of
// the operations.
type fakeUploads struct {
	t     *testing.T
	db    *store.DB
	vault *masterkey.Vault

	mu        sync.Mutex
	ops       []string
	offsets   map[string]int64
	activity  time.Time // last activity reported, createdAt when zero
	actErr    error
	seenAct   []time.Time // activity passed to Offset
	offsetErr error
	lockErr   error
	removeErr error
	emptyErr  error
	emptyDEKs [][]byte
	onLock    func()
	locked    int
}

func (u *fakeUploads) record(op string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ops = append(u.ops, op)
}

func (u *fakeUploads) opsSnapshot() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.ops)
}

func (u *fakeUploads) TransferActivity(_ context.Context, _ tenant.ID, _ []store.TransferFile, createdAt time.Time) (time.Time, time.Time, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.actErr != nil {
		return time.Time{}, time.Time{}, u.actErr
	}
	last := createdAt
	if !u.activity.IsZero() {
		last = u.activity
	}
	return last, last.Add(uploadTTL), nil
}

func (u *fakeUploads) Offset(_ context.Context, _ tenant.ID, f store.TransferFile, _, activity time.Time) (int64, time.Time, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.seenAct = append(u.seenAct, activity)
	if u.offsetErr != nil {
		return 0, time.Time{}, u.offsetErr
	}
	return u.offsets[f.ID], activity.Add(uploadTTL), nil
}

func (u *fakeUploads) LockFiles(_ []string) (func(), error) {
	if u.lockErr != nil {
		return nil, u.lockErr
	}
	u.mu.Lock()
	u.locked++
	u.ops = append(u.ops, "lock")
	hook := u.onLock
	u.onLock = nil
	u.mu.Unlock()
	if hook != nil {
		hook()
	}
	return func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		u.locked--
		u.ops = append(u.ops, "unlock")
	}, nil
}

// RemoveFiles destroys the keys like the real engine, then fails with
// removeErr when set (a disk failure: the keys stay destroyed).
func (u *fakeUploads) RemoveFiles(ctx context.Context, tid tenant.ID, files []store.TransferFile) error {
	for _, f := range files {
		// The transfer row must still exist when the key is destroyed (T-110).
		if _, err := u.db.Transfers().Get(ctx, tid, f.TransferID); err != nil {
			u.t.Errorf("RemoveFiles: transfer row already gone: %v", err)
		}
		if f.DEKKeyID != "" {
			if err := u.vault.Destroy(ctx, tid, f.DEKKeyID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
	}
	if u.removeErr != nil {
		return u.removeErr
	}
	for _, f := range files {
		u.record("remove:" + f.ID)
	}
	return nil
}

func (u *fakeUploads) WriteEmpty(_ context.Context, _ tenant.ID, fileID string, dek []byte, storageName string) (string, int64, error) {
	if len(dek) != 32 || len(storageName) != store.StorageNameLen {
		u.t.Errorf("WriteEmpty: dek %d bytes, storage name %q", len(dek), storageName)
	}
	u.mu.Lock()
	u.emptyDEKs = append(u.emptyDEKs, dek)
	u.mu.Unlock()
	if u.emptyErr != nil {
		return "", 0, u.emptyErr
	}
	u.record("empty:" + fileID)
	return emptySHA, 48, nil
}

// faultRepo wraps a repo and fails the named methods, after skip[name]
// successful calls.
type faultRepo struct {
	inner repo
	mu    sync.Mutex
	fail  map[string]error
	skip  map[string]int
}

func (r *faultRepo) check(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	err, ok := r.fail[name]
	if !ok {
		return nil
	}
	if r.skip[name] > 0 {
		r.skip[name]--
		return nil
	}
	return err
}

func (r *faultRepo) blocked(ctx context.Context, tid tenant.ID, email, sum string) (bool, error) {
	if err := r.check("blocked"); err != nil {
		return false, err
	}
	return r.inner.blocked(ctx, tid, email, sum)
}

func (r *faultRepo) networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error) {
	if err := r.check("networkRules"); err != nil {
		return store.NetworkRuleSet{}, err
	}
	return r.inner.networkRules(ctx, tid)
}

func (r *faultRepo) invitation(ctx context.Context, tid tenant.ID, invID string) (store.Invitation, error) {
	if err := r.check("invitation"); err != nil {
		return store.Invitation{}, err
	}
	return r.inner.invitation(ctx, tid, invID)
}

func (r *faultRepo) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if err := r.check("tenant"); err != nil {
		return nil, err
	}
	return r.inner.tenant(ctx, tid)
}

func (r *faultRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	if err := r.check("transfer"); err != nil {
		return store.TransferDetails{}, err
	}
	return r.inner.transfer(ctx, tid, trfID)
}

func (r *faultRepo) transferByKey(ctx context.Context, tid tenant.ID, sender, key string, since time.Time) (store.TransferDetails, error) {
	if err := r.check("transferByKey"); err != nil {
		return store.TransferDetails{}, err
	}
	return r.inner.transferByKey(ctx, tid, sender, key, since)
}

func (r *faultRepo) completeUpload(ctx context.Context, tid tenant.ID, fileID, sum string, size int64, now time.Time) error {
	if err := r.check("completeUpload"); err != nil {
		return err
	}
	return r.inner.completeUpload(ctx, tid, fileID, sum, size, now)
}

func (r *faultRepo) tx(ctx context.Context, tid tenant.ID, fn func(txRepo) error) error {
	return r.inner.tx(ctx, tid, func(tx txRepo) error { return fn(faultTx{inner: tx, r: r}) })
}

// faultTx wraps a txRepo with the failures of its faultRepo.
type faultTx struct {
	inner txRepo
	r     *faultRepo
}

func (t faultTx) usedBytes(ctx context.Context) (int64, error) {
	if err := t.r.check("usedBytes"); err != nil {
		return 0, err
	}
	return t.inner.usedBytes(ctx)
}

func (t faultTx) countUploading(ctx context.Context, sender string, since time.Time) (int, error) {
	if err := t.r.check("countUploading"); err != nil {
		return 0, err
	}
	return t.inner.countUploading(ctx, sender, since)
}

func (t faultTx) listUploading(ctx context.Context, sender string, since time.Time, limit int) ([]store.Transfer, error) {
	if err := t.r.check("listUploading"); err != nil {
		return nil, err
	}
	return t.inner.listUploading(ctx, sender, since, limit)
}

func (t faultTx) listFiles(ctx context.Context, trfID string) ([]store.TransferFile, error) {
	if err := t.r.check("listFiles"); err != nil {
		return nil, err
	}
	return t.inner.listFiles(ctx, trfID)
}

func (t faultTx) newDEK(ctx context.Context) (string, []byte, error) {
	if err := t.r.check("newDEK"); err != nil {
		return "", nil, err
	}
	return t.inner.newDEK(ctx)
}

func (t faultTx) createTransfer(ctx context.Context, tr store.Transfer, rcpts []string, files []store.TransferFile) error {
	if err := t.r.check("createTransfer"); err != nil {
		return err
	}
	return t.inner.createTransfer(ctx, tr, rcpts, files)
}

func (t faultTx) finalize(ctx context.Context, trfID string, now time.Time) error {
	if err := t.r.check("finalize"); err != nil {
		return err
	}
	return t.inner.finalize(ctx, trfID, now)
}

func (t faultTx) deleteTransfer(ctx context.Context, trfID string) error {
	if err := t.r.check("deleteTransfer"); err != nil {
		return err
	}
	return t.inner.deleteTransfer(ctx, trfID)
}

// env is a service over a migrated database with tenants A and B sharing
// the same network rules (so that only the tenant differs in the isolation
// tests).
type env struct {
	db      *store.DB
	vault   *masterkey.Vault
	svc     *Service
	clock   *fakeClock
	seclog  *fakeSeclog
	uploads *fakeUploads
	hasher  *fakeHasher
	a, b    *tenant.Tenant
	// inv is an active invitation of bob by alice in A.
	inv store.Invitation
	// finalized records the OnFinalized calls ("tenant/transfer").
	mu        sync.Mutex
	finalized []string
}

// newEnv builds an env on engine e.
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
	kr, err := masterkey.New(masterkeytest.Key(t, "transfer"), nil)
	if err != nil {
		t.Fatal(err)
	}
	vault := masterkey.NewVault(db, kr, nil)
	ev := &env{
		db: db, vault: vault, clock: clock, seclog: &fakeSeclog{}, hasher: &fakeHasher{},
		uploads: &fakeUploads{t: t, db: db, vault: vault},
	}
	ev.svc = New(db, vault, ev.uploads, ev.seclog, Options{
		MaxRecipients: 3, MaxOpenTransfers: 1000, Hasher: ev.hasher, Now: clock.Now,
		OnFinalized: func(tid tenant.ID, trfID string) {
			ev.mu.Lock()
			defer ev.mu.Unlock()
			ev.finalized = append(ev.finalized, string(tid)+"/"+trfID)
		},
	})
	ev.a = ev.newTenant(t, hostA, "en")
	ev.b = ev.newTenant(t, hostB, "fr")
	ev.inv = ev.invite(t, ev.a, bob, alice)
	return ev
}

// newTenant creates a tenant whose internal users are 10.0.0.0/8 with the
// domain entity-a.example.com.
func (ev *env) newTenant(t *testing.T, fqdn, lang string) *tenant.Tenant {
	t.Helper()
	ctx := context.Background()
	tn, err := ev.db.Tenants().Create(ctx, &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: lang,
		MaxTransferBytes: maxBytes, StorageQuotaBytes: quota,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", fqdn, err)
	}
	_, err = ev.db.NetworkRules().Replace(ctx, tn.ID,
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"entity-a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

// setQuota changes the storage quota of tn.
func (ev *env) setQuota(t *testing.T, tn *tenant.Tenant, q int64) {
	t.Helper()
	c := tn.Clone()
	c.StorageQuotaBytes = q
	if _, err := ev.db.Tenants().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

// invite creates an active invitation of email by inviter in tn.
func (ev *env) invite(t *testing.T, tn *tenant.Tenant, email, inviter string) store.Invitation {
	t.Helper()
	h := sha256.Sum256([]byte(id.New(id.Invitation)))
	inv := store.Invitation{ID: id.New(id.Invitation), TokenHash: h[:], Email: email, InvitedBy: inviter}
	if err := ev.db.Invitations().Create(context.Background(), tn.ID, inv); err != nil {
		t.Fatal(err)
	}
	got, err := ev.db.Invitations().Get(context.Background(), tn.ID, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// block adds a blocklist entry to tn.
func (ev *env) block(t *testing.T, tn *tenant.Tenant, kind store.BlocklistKind, value string) {
	t.Helper()
	_, err := ev.db.Blocklist().Create(context.Background(), tn.ID, store.BlocklistEntry{Kind: kind, Value: value, CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
}

// faults replaces the repo of the service by a faultRepo and returns it.
func (ev *env) faults() *faultRepo {
	r := &faultRepo{inner: ev.svc.repo, fail: map[string]error{}, skip: map[string]int{}}
	ev.svc.repo = r
	return r
}

// internal returns alice of A from the internal network.
func internalSender() Sender {
	return Sender{Depositor: store.Depositor{Email: alice, Kind: store.DepositorInternal}, ClientIP: internalIP}
}

// external returns bob with his invitation, from outside.
func (ev *env) external() Sender {
	return Sender{
		Depositor: store.Depositor{Email: bob, Kind: store.DepositorExternal, InvitationID: ev.inv.ID},
		ClientIP:  externalIP,
	}
}

// request returns a valid request with two files of 100 and 200 bytes.
func request() CreateRequest {
	return CreateRequest{
		Recipients: []string{dave},
		ExpiryDays: 7,
		Files: []FileDeclaration{
			{Name: "plans.pdf", Size: 100, MediaType: "application/pdf"},
			{Name: "survey.mp4", Size: 200},
		},
	}
}

// mustCreate creates a transfer of A.
func (ev *env) mustCreate(t *testing.T, sender Sender, req CreateRequest) Details {
	t.Helper()
	d, err := ev.svc.Create(context.Background(), ev.a, sender, req, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return d
}

// complete marks every incomplete file of the transfer of A as uploaded
// with sum (its own SHA-256 when sum is "").
func (ev *env) complete(t *testing.T, trfID, sum string) {
	t.Helper()
	ctx := context.Background()
	d, err := ev.db.Transfers().Get(ctx, ev.a.ID, trfID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Files {
		if f.Completed() {
			continue
		}
		s := sum
		if s == "" {
			h := sha256.Sum256([]byte(f.ID))
			s = hex.EncodeToString(h[:])
		}
		if err := ev.db.TransferFiles().CompleteUpload(ctx, ev.a.ID, f.ID, s, f.Size+48, ev.clock.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

// usedBytes returns the storage used by tn.
func (ev *env) usedBytes(t *testing.T, tn *tenant.Tenant) int64 {
	t.Helper()
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	err = s.Tx(context.Background(), func(tx *store.ScopedTx) error {
		var err error
		n, err = ev.db.Transfers().UsedBytesTx(context.Background(), tx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// busy is the error of a fake engine whose files are locked.
var busy = upload.ErrBusy

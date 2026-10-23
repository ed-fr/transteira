package keyrotation

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// The tests that run on every engine are deliberately not parallel: each
// PostgreSQL engine holds its own connection pool.

var (
	testNow  = time.Date(2026, 10, 23, 9, 30, 0, 0, time.UTC)
	clientIP = netip.MustParseAddr("192.0.2.10")
	errFault = errors.New("injected fault")
	keySeq   atomic.Int64
)

// superAdmin is the principal of an authenticated super admin.
var superAdmin = adminauth.Principal{
	SessionID: "as_01JABCM8Q9R0S1T2V3V4W5X6Y7", State: store.SessionAuthenticated,
	Admin: adminauth.Account{ID: "adm_01JABCM8Q9R0S1T2V3V4W5X6Y7", Username: "root", Role: store.RoleSuperAdmin},
}

// fakeConfirm is a Confirmer returning err, or the account of the
// principal (with role when set). during, when set, runs at each call,
// between the advisory and the authoritative state checks of Start.
type fakeConfirm struct {
	mu     sync.Mutex
	err    error
	role   store.AdminRole
	calls  int
	during func()
}

func (c *fakeConfirm) ConfirmTOTP(_ context.Context, p adminauth.Principal, code, recoveryCode string, ip netip.Addr) (adminauth.Account, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.during != nil {
		c.during()
	}
	if c.err != nil {
		return adminauth.Account{}, c.err
	}
	if (code == "") == (recoveryCode == "") || !ip.IsValid() {
		return adminauth.Account{}, errors.New("fakeConfirm: bad input")
	}
	acc := p.Admin
	if c.role != "" {
		acc.Role = c.role
	}
	return acc, nil
}

func (c *fakeConfirm) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// faultAudit records through a real writer unless err is set.
type faultAudit struct {
	w   *audit.Writer
	mu  sync.Mutex
	err error
}

func (a *faultAudit) Record(ctx context.Context, ev audit.Event) error {
	a.mu.Lock()
	err := a.err
	a.mu.Unlock()
	if err != nil {
		return err
	}
	return a.w.Record(ctx, ev)
}

func (a *faultAudit) set(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = err
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
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

// env is a database with keys wrapped under k1, and a service rotating
// from k1 to k2.
type env struct {
	e       storetest.Engine
	db      *store.DB
	k1, k2  *crypto.MasterKey
	keys    *masterkey.Keyring
	confirm *fakeConfirm
	audit   *faultAudit
	logs    *syncBuffer
	svc     *Service
	secrets [][]byte
	tid     tenant.ID
	// opts are the rotation options of the services built by newService.
	opts masterkey.Options
}

func newKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	return masterkeytest.Key(t, fmt.Sprintf("keyrotation %d", keySeq.Add(1)))
}

// keyring builds a keyring sharing keys destroyed at the end of the test
// (it is never closed).
func keyring(t *testing.T, current, next *crypto.MasterKey) *masterkey.Keyring {
	t.Helper()
	kr, err := masterkey.New(current, next)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// newEnv builds an env on e with n keys wrapped under k1, and its service
// (BatchSize 2).
func newEnv(t *testing.T, e storetest.Engine, n int) *env {
	t.Helper()
	ctx := t.Context()
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ev := &env{
		e: e, db: db, k1: newKey(t), k2: newKey(t), confirm: &fakeConfirm{},
		audit: &faultAudit{w: audit.New(db)}, logs: &syncBuffer{},
		opts: masterkey.Options{BatchSize: 2, Now: func() time.Time { return testNow }},
	}
	old := keyring(t, ev.k1, nil)
	if _, err := masterkey.Check(ctx, db, old, nil, testNow); err != nil {
		t.Fatal(err)
	}
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
		Name: "Entity A", FQDN: "transfer.entity-a.example.com", DefaultLanguage: "en",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev.tid = tn.ID
	v := masterkey.NewVault(db, old, nil)
	for range n {
		secret := make([]byte, 24)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Seal(ctx, tn.ID, crypto.PurposeDEK, secret); err != nil {
			t.Fatal(err)
		}
		ev.secrets = append(ev.secrets, secret)
	}
	ev.keys = keyring(t, ev.k1, ev.k2)
	ev.svc = ev.newService(t)
	return ev
}

// newService returns a service over the env (another instance, after a
// restart), closed at the end of the test.
func (ev *env) newService(t *testing.T) *Service {
	t.Helper()
	svc := New(ev.db, ev.keys, ev.confirm, ev.audit, Options{
		Rotation: ev.opts, Logger: slog.New(slog.NewTextHandler(ev.logs, nil)),
	})
	t.Cleanup(func() { _ = svc.Close(context.WithoutCancel(t.Context())) })
	return svc
}

// wait waits for the worker of svc to stop.
func wait(t *testing.T, svc *Service) {
	t.Helper()
	select {
	case <-svc.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("the rotation worker did not stop")
	}
}

// event is an audit event as the tests read it.
type event struct {
	store.AuditEvent
	details map[string]any
}

// events returns the audit events of action, oldest first.
func (ev *env) events(t *testing.T, action audit.Action) []event {
	t.Helper()
	page, err := ev.db.AuditEvents().List(t.Context(), store.AuditFilter{Limit: store.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	var out []event
	for i := len(page.Items) - 1; i >= 0; i-- {
		it := page.Items[i]
		if it.Action != string(action) {
			continue
		}
		e := event{AuditEvent: it}
		if len(it.Details) > 0 {
			if err := json.Unmarshal(it.Details, &e.details); err != nil {
				t.Fatal(err)
			}
		}
		out = append(out, e)
	}
	return out
}

// gate blocks the worker in its progress hook until released.
type gate struct {
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGate() *gate { return &gate{reached: make(chan struct{}), release: make(chan struct{})} }

// hook is a masterkey.Options.OnProgress blocking at the first batch.
func (g *gate) hook(store.Rotation) {
	first := false
	g.once.Do(func() { first = true })
	if first {
		close(g.reached)
		<-g.release
	}
}

// rawSQLite opens the SQLite file of e directly, to inject faults.
func rawSQLite(t *testing.T, e storetest.Engine) *sql.DB {
	t.Helper()
	if e.Driver != config.DriverSQLite {
		t.Fatal("rawSQLite needs SQLite")
	}
	raw, err := sql.Open("sqlite", e.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

// execRaw runs stmt on the SQLite file of ev.
func (ev *env) execRaw(t *testing.T, stmt string) {
	t.Helper()
	if _, err := rawSQLite(t, ev.e).ExecContext(t.Context(), stmt); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}

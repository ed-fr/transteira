package masterkey_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// The tests that run on every engine are deliberately not parallel: each
// PostgreSQL engine holds its own connection pool, and make test runs every
// package at once against a server limited to 100 connections.

// testNow is the clock of the tests.
var testNow = time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)

// keySeq makes the labels of newKey unique.
var keySeq atomic.Int64

// newKey returns a new master key, distinct from every other key of the
// tests, destroyed when the test ends.
func newKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	return masterkeytest.Key(t, fmt.Sprintf("masterkey %d", keySeq.Add(1)))
}

// vault returns a vault over db with the keys of kr.
func vault(db *store.DB, kr *masterkey.Keyring) *masterkey.Vault {
	return masterkey.NewVault(db, kr, nil)
}

// keyring builds a keyring that shares the given keys with other keyrings of
// the test (it is never closed).
func keyring(t *testing.T, current, next *crypto.MasterKey) *masterkey.Keyring {
	t.Helper()
	kr, err := masterkey.New(current, next)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return kr
}

// openDB opens and migrates the engine's database.
func openDB(t *testing.T, e storetest.Engine) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// newTenant creates a tenant served by fqdn.
func newTenant(t *testing.T, db *store.DB, fqdn string) tenant.ID {
	t.Helper()
	tn, err := db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "fr",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn.ID
}

// rawSQLite opens the SQLite file of e directly, to inject faults.
func rawSQLite(t *testing.T, e storetest.Engine) *sql.DB {
	t.Helper()
	return rawDB(t, e)
}

// rawDB opens the database of e directly with the runtime role, bypassing
// the store.
func rawDB(t *testing.T, e storetest.Engine) *sql.DB {
	t.Helper()
	driver := "sqlite"
	if e.Driver == config.DriverPostgres {
		driver = "pgx"
	}
	raw, err := sql.Open(driver, e.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

// execRaw runs statements on raw.
func execRaw(t *testing.T, raw *sql.DB, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := raw.ExecContext(context.Background(), s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

// sealed is a wrapped key created by a test with its expected plaintext.
type sealed struct {
	tid     tenant.ID
	purpose crypto.Purpose
	id      string
	secret  []byte
}

// seal stores a random secret of purpose p for tid through v.
func seal(t *testing.T, v *masterkey.Vault, tid tenant.ID, p crypto.Purpose) sealed {
	t.Helper()
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	wkID, err := v.Seal(context.Background(), tid, p, secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed{tid: tid, purpose: p, id: wkID, secret: secret}
}

// expectOpens checks that every key opens through v with its plaintext. It
// never prints key material.
func expectOpens(t *testing.T, v *masterkey.Vault, keys []sealed) {
	t.Helper()
	for _, k := range keys {
		got, err := v.Open(context.Background(), k.tid, k.purpose, k.id)
		if err != nil {
			t.Errorf("Open(%s): %v", k.id, err)
			continue
		}
		if !bytes.Equal(got, k.secret) {
			t.Errorf("Open(%s) returned another plaintext", k.id)
		}
	}
}

// keyIDOf returns the master key ID recorded on a row.
func keyIDOf(t *testing.T, db *store.DB, k sealed) string {
	t.Helper()
	row, err := db.WrappedKeys().Get(context.Background(), k.tid, k.id)
	if err != nil {
		t.Fatalf("Get(%s): %v", k.id, err)
	}
	return row.KeyID
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// execSystem runs statements on the database of e in one transaction of
// the system scope (on PostgreSQL, app.system_scope = 'on'), bypassing the
// store: a direct write to the key tables.
func execSystem(t *testing.T, e storetest.Engine, stmts ...string) {
	t.Helper()
	ctx := context.Background()
	tx, err := rawDB(t, e).BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if e.Driver == config.DriverPostgres {
		stmts = append([]string{`SELECT set_config('app.system_scope', 'on', true)`}, stmts...)
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// plantStraggler stores a key of tid wrapped under old, a retired master
// key, as a process still running with it after the rotation would have
// (the database refuses it, so old is unregistered for the insert).
func plantStraggler(t *testing.T, e storetest.Engine, db *store.DB, old *crypto.MasterKey, tid tenant.ID) sealed {
	t.Helper()
	var k sealed
	whileUnregistered(t, e, db, old, func() { k = seal(t, vault(db, keyring(t, old, nil)), tid, crypto.PurposeDEK) })
	return k
}

// plantSystemStraggler is plantStraggler for a system secret.
func plantSystemStraggler(t *testing.T, e storetest.Engine, db *store.DB, old *crypto.MasterKey) sealedSystem {
	t.Helper()
	var s sealedSystem
	whileUnregistered(t, e, db, old, func() { s = sealSystem(t, db, vault(db, keyring(t, old, nil))) })
	return s
}

// whileUnregistered runs plant while old, a retired master key, is removed
// from master_keys, then records it as retired again.
func whileUnregistered(t *testing.T, e storetest.Engine, db *store.DB, old *crypto.MasterKey, plant func()) {
	t.Helper()
	records, err := db.MasterKeys().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var rec store.MasterKeyRecord
	for _, r := range records {
		if r.ID == old.ID() {
			rec = r
		}
	}
	if rec.Status != store.MasterKeyRetired {
		t.Fatalf("master key %s is not retired: %+v", old.ID(), records)
	}
	execSystem(t, e, `DELETE FROM master_keys WHERE id = '`+old.ID()+`'`)
	plant()
	execSystem(t, e, fmt.Sprintf(`INSERT INTO master_keys (id, status, created_at, retired_at) VALUES ('%s', 'retired', %d, %d)`,
		old.ID(), rec.CreatedAt.UnixMilli(), rec.RetiredAt.UnixMilli()))
}

// sealedSystem is a system secret created by a test with its expected
// plaintext.
type sealedSystem struct {
	id      string
	purpose crypto.Purpose
	secret  []byte
}

// sealSystem wraps a random admin TOTP secret through v and stores it in
// db.
func sealSystem(t *testing.T, db *store.DB, v *masterkey.Vault) sealedSystem {
	t.Helper()
	return sealSystemPurpose(t, db, v, crypto.PurposeAdminTOTP)
}

// sealSystemPurpose wraps a random secret of purpose p through v and
// stores it in db.
func sealSystemPurpose(t *testing.T, db *store.DB, v *masterkey.Vault, p crypto.Purpose) sealedSystem {
	t.Helper()
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	row, err := v.WrapSystem(p, secret)
	if err != nil {
		t.Fatalf("WrapSystem: %v", err)
	}
	if err := db.SystemSecrets().Create(context.Background(), row); err != nil {
		t.Fatalf("Create system secret: %v", err)
	}
	return sealedSystem{id: row.ID, purpose: p, secret: secret}
}

// sealWebhooks stores a generic webhook of tid and an instance-wide generic
// webhook, their URLs and signing secrets sealed through v (wrapped keys
// of purpose secret, system secrets of purpose webhook), and returns the
// four sealed values.
func sealWebhooks(t *testing.T, db *store.DB, v *masterkey.Vault, tid tenant.ID) ([]sealed, []sealedSystem) {
	t.Helper()
	ctx := context.Background()
	keys := []sealed{seal(t, v, tid, crypto.PurposeSecret), seal(t, v, tid, crypto.PurposeSecret)}
	hook := func(urlKey, secretKey string, ev events.Type) store.Webhook {
		return store.Webhook{
			ID: id.New(id.Webhook), Name: "SIEM collector", Kind: store.WebhookGeneric, URLKeyID: urlKey,
			URLHint: "https://siem.example.com", SecretKeyID: secretKey, Events: []events.Type{ev},
			Enabled: true, CreatedBy: "admin.a",
		}
	}
	sc, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.Tx(ctx, func(tx *store.ScopedTx) error {
		_, err := db.Webhooks().CreateTx(ctx, tx, hook(keys[0].id, keys[1].id, events.VirusDetected))
		return err
	}); err != nil {
		t.Fatalf("create tenant webhook: %v", err)
	}
	secrets := []sealedSystem{
		sealSystemPurpose(t, db, v, crypto.PurposeWebhook), sealSystemPurpose(t, db, v, crypto.PurposeWebhook),
	}
	sys, err := db.System("tests: instance-wide webhook")
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.Tx(ctx, func(tx *store.SystemTx) error {
		_, err := db.SystemWebhooks().CreateTx(ctx, tx, hook(secrets[0].id, secrets[1].id, events.DiskAlertRaised))
		return err
	}); err != nil {
		t.Fatalf("create system webhook: %v", err)
	}
	return keys, secrets
}

// expectSystemOpens checks that every system secret opens through v with
// its plaintext. It never prints key material.
func expectSystemOpens(t *testing.T, v *masterkey.Vault, secrets []sealedSystem) {
	t.Helper()
	for _, s := range secrets {
		got, err := v.OpenSystem(context.Background(), s.purpose, s.id)
		if err != nil {
			t.Errorf("OpenSystem(%s): %v", s.id, err)
			continue
		}
		if !bytes.Equal(got, s.secret) {
			t.Errorf("OpenSystem(%s) returned another plaintext", s.id)
		}
	}
}

// secretKeyIDOf returns the master key ID recorded on a system secret.
func secretKeyIDOf(t *testing.T, db *store.DB, s sealedSystem) string {
	t.Helper()
	row, err := db.SystemSecrets().Get(context.Background(), s.id)
	if err != nil {
		t.Fatalf("Get(%s): %v", s.id, err)
	}
	return row.KeyID
}

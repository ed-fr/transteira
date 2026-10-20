// Package isolation_test holds adversarial tenant-isolation tests of the
// data layer (CLAUDE.md sections 5, 17, 24.2; threat model T-74, T-75).
//
// Every test runs on every engine returned by storetest.Engines: SQLite
// always, PostgreSQL when TT_TEST_POSTGRES_DSN is set (mandatory with
// TT_TEST_REQUIRE_POSTGRES=1, as in make check). The tests only use the
// exported API of the store, plus raw database connections where they
// deliberately bypass the application layer (rls_test.go).
package isolation_test

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Fixed fictitious host names of the two tenants of every scenario.
const (
	fqdnA = "transfer.entity-a.example.com"
	fqdnB = "transfer.entity-b.example.org"
)

// epoch is the start of the deterministic test clock.
var epoch = time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)

// steppingClock returns a deterministic, concurrency-safe clock advancing by
// one millisecond at every call, so that identifiers (ULIDs) are created in
// a strictly increasing order.
func steppingClock() func() time.Time {
	var n atomic.Int64
	return func() time.Time { return epoch.Add(time.Duration(n.Add(1)) * time.Millisecond) }
}

// openDB opens and migrates the engine's database with a deterministic clock.
func openDB(t *testing.T, e storetest.Engine) *store.DB {
	t.Helper()
	ctx := t.Context()
	db, err := store.Open(ctx, e.Config(), store.WithClock(steppingClock()))
	if err != nil {
		t.Fatalf("store.Open(%s): %v", e.Name, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate(%s): %v", e.Name, err)
	}
	return db
}

// newTenant creates a tenant served by fqdn.
func newTenant(t *testing.T, db *store.DB, fqdn string) *tenant.Tenant {
	t.Helper()
	tn, err := db.Tenants().Create(t.Context(), &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "en",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatalf("Tenants.Create(%s): %v", fqdn, err)
	}
	return tn
}

// fixture is a database holding two tenants, A and B, each with network
// rules and blocklist entries of every kind.
type fixture struct {
	e      storetest.Engine
	db     *store.DB
	a, b   *tenant.Tenant
	rulesA store.NetworkRuleSet
	rulesB store.NetworkRuleSet
	// blockA and blockB are the entries of each tenant, in creation order.
	blockA []store.BlocklistEntry
	blockB []store.BlocklistEntry
}

// sha256 fingerprints used in the fixtures (fictitious values).
const (
	shaShared = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaOnlyB  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// newFixture builds a fixture. Entries of A and B are created alternately,
// so that B's identifiers interleave with A's (useful for cursor attacks).
func newFixture(t *testing.T, e storetest.Engine) *fixture {
	t.Helper()
	ctx := t.Context()
	f := &fixture{e: e, db: openDB(t, e)}
	f.a = newTenant(t, f.db, fqdnA)
	f.b = newTenant(t, f.db, fqdnB)

	var err error
	f.rulesA, err = f.db.NetworkRules().Replace(ctx, f.a.ID,
		[]netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}, []string{"entity-a.example.com"})
	if err != nil {
		t.Fatalf("Replace(A): %v", err)
	}
	f.rulesB, err = f.db.NetworkRules().Replace(ctx, f.b.ID,
		[]netip.Prefix{netip.MustParsePrefix("10.2.0.0/16"), netip.MustParsePrefix("2001:db8:b::/48")},
		[]string{"entity-b.example.org", "partner.example.net"})
	if err != nil {
		t.Fatalf("Replace(B): %v", err)
	}

	type pair struct{ a, b store.BlocklistEntry }
	pairs := []pair{
		{
			store.BlocklistEntry{Kind: store.BlockEmail, Value: "spam-a@example.net", CreatedBy: "admin-a@entity-a.example.com"},
			store.BlocklistEntry{Kind: store.BlockEmail, Value: "spam-b@example.net", Comment: "secret note of B", CreatedBy: "admin-b@entity-b.example.org"},
		},
		{
			store.BlocklistEntry{Kind: store.BlockDomain, Value: "bad-a.example.net"},
			store.BlocklistEntry{Kind: store.BlockDomain, Value: "bad-b.example.net"},
		},
		{
			store.BlocklistEntry{Kind: store.BlockSHA256, Value: shaShared},
			store.BlocklistEntry{Kind: store.BlockSHA256, Value: shaOnlyB},
		},
		{
			store.BlocklistEntry{Kind: store.BlockEmail, Value: "other-a@example.net"},
			// Same value as one of A's entries: per-tenant uniqueness only.
			store.BlocklistEntry{Kind: store.BlockSHA256, Value: shaShared},
		},
	}
	for _, p := range pairs {
		ea, err := f.db.Blocklist().Create(ctx, f.a.ID, p.a)
		if err != nil {
			t.Fatalf("Blocklist.Create(A, %s): %v", p.a.Value, err)
		}
		f.blockA = append(f.blockA, ea)
		eb, err := f.db.Blocklist().Create(ctx, f.b.ID, p.b)
		if err != nil {
			t.Fatalf("Blocklist.Create(B, %s): %v", p.b.Value, err)
		}
		f.blockB = append(f.blockB, eb)
	}
	return f
}

// listAll returns every blocklist entry of tid, following cursors.
func listAll(ctx context.Context, t *testing.T, db *store.DB, tid tenant.ID) []store.BlocklistEntry {
	t.Helper()
	var out []store.BlocklistEntry
	cursor := ""
	for {
		p, err := db.Blocklist().List(ctx, tid, store.BlocklistFilter{Cursor: cursor, Limit: 1})
		if err != nil {
			t.Fatalf("Blocklist.List(%s): %v", tid, err)
		}
		out = append(out, p.Items...)
		if p.NextCursor == "" {
			return out
		}
		cursor = p.NextCursor
	}
}

// assertBIntact checks, through B's own scope, that B's rules and entries
// are exactly those of the fixture.
func (f *fixture) assertBIntact(ctx context.Context, t *testing.T) {
	t.Helper()
	got, err := f.db.NetworkRules().Get(ctx, f.b.ID)
	if err != nil {
		t.Fatalf("NetworkRules.Get(B): %v", err)
	}
	if !equalRules(got, f.rulesB) {
		t.Errorf("B's network rules changed: got %+v, want %+v", got, f.rulesB)
	}
	assertSameEntries(t, "B", listAll(ctx, t, f.db, f.b.ID), f.blockB)
}

// assertAIntact is assertBIntact for A.
func (f *fixture) assertAIntact(ctx context.Context, t *testing.T) {
	t.Helper()
	got, err := f.db.NetworkRules().Get(ctx, f.a.ID)
	if err != nil {
		t.Fatalf("NetworkRules.Get(A): %v", err)
	}
	if !equalRules(got, f.rulesA) {
		t.Errorf("A's network rules changed: got %+v, want %+v", got, f.rulesA)
	}
	assertSameEntries(t, "A", listAll(ctx, t, f.db, f.a.ID), f.blockA)
}

// equalRules compares two rule sets.
func equalRules(x, y store.NetworkRuleSet) bool {
	if len(x.CIDRs) != len(y.CIDRs) || len(x.Domains) != len(y.Domains) {
		return false
	}
	for i := range x.CIDRs {
		if x.CIDRs[i] != y.CIDRs[i] {
			return false
		}
	}
	for i := range x.Domains {
		if x.Domains[i] != y.Domains[i] {
			return false
		}
	}
	return true
}

// assertSameEntries checks that got and want hold the same entries, in the
// same order.
func assertSameEntries(t *testing.T, who string, got, want []store.BlocklistEntry) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d entries %+v, want %d %+v", who, len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: entry %d = %+v, want %+v", who, i, got[i], want[i])
		}
	}
}

// idSet returns the identifiers of entries.
func idSet(entries []store.BlocklistEntry) map[string]bool {
	m := make(map[string]bool, len(entries))
	for _, e := range entries {
		m[e.ID] = true
	}
	return m
}

// assertNotFound checks that err is exactly a store.ErrNotFound and nothing
// that could reveal more (no conflict, no invalid argument).
func assertNotFound(t *testing.T, op string, err error) {
	t.Helper()
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("%s: err = %v, want store.ErrNotFound", op, err)
	}
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrInvalid) {
		t.Errorf("%s: err = %v also matches another sentinel", op, err)
	}
}

// rawDB opens a connection to the engine's database that bypasses the
// store, with a single connection so that consecutive transactions are
// guaranteed to reuse the same session.
func rawDB(t *testing.T, e storetest.Engine) *sql.DB {
	t.Helper()
	driver := "pgx"
	if e.Driver == config.DriverSQLite {
		driver = "sqlite"
	}
	raw, err := sql.Open(driver, e.DSN)
	if err != nil {
		t.Fatalf("sql.Open(%s): %v", e.Name, err)
	}
	raw.SetMaxOpenConns(1)
	raw.SetMaxIdleConns(1)
	raw.SetConnMaxLifetime(0)
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.PingContext(t.Context()); err != nil {
		t.Fatalf("raw ping (%s): %v", e.Name, err)
	}
	return raw
}

// rawCount counts the rows of table owned by tid, bypassing the store. On
// PostgreSQL it runs in a transaction with app.system_scope = 'on', the
// documented system bypass of the policies.
func rawCount(t *testing.T, e storetest.Engine, table, column string, tid tenant.ID) int {
	t.Helper()
	ctx := t.Context()
	raw := rawDB(t, e)
	tx, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := `SELECT count(*) FROM ` + table + ` WHERE ` + column + ` = ?`
	if e.Driver == config.DriverPostgres {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.system_scope', 'on', true)`); err != nil {
			t.Fatalf("set system scope: %v", err)
		}
		q = `SELECT count(*) FROM ` + table + ` WHERE ` + column + ` = $1`
	}
	var n int
	if err := tx.QueryRowContext(ctx, q, string(tid)).Scan(&n); err != nil {
		t.Fatalf("raw count %s: %v", table, err)
	}
	return n
}

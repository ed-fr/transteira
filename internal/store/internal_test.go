package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// brokenFS lists migrations but cannot read them.
type brokenFS struct{ fstest.MapFS }

func (brokenFS) ReadFile(string) ([]byte, error) { return nil, errInjected }

func TestLoadMigrationsReadError(t *testing.T) {
	t.Parallel()
	fsys := brokenFS{fstest.MapFS{"m/0001_a.sql": {}}}
	if _, err := loadMigrations(fsys, "m"); !errors.Is(err, errBadMigrations) || !errors.Is(err, errInjected) {
		t.Errorf("err = %v", err)
	}
}

func TestOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, err := Open(ctx, &config.Config{DBDriver: "oracle"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unsupported driver: %v", err)
	}
	for _, dsn := range []string{"", ":memory:", "file::memory:?cache=shared", "file:x?mode=memory"} {
		if _, err := Open(ctx, &config.Config{DBDriver: config.DriverSQLite, DBDSN: config.NewSecret(dsn)}); !errors.Is(err, errInMemory) {
			t.Errorf("Open(%q) = %v, want errInMemory", dsn, err)
		}
	}
	missingDir := filepath.Join(t.TempDir(), "missing", "db.sqlite")
	if _, err := Open(ctx, &config.Config{DBDriver: config.DriverSQLite, DBDSN: config.NewSecret(missingDir)}); err == nil {
		t.Error("Open in a missing directory succeeded")
	}
	// Unreachable PostgreSQL: the error must not reveal the password.
	pgDSN := "postgres://u:s3cret-pw@127.0.0.1:1/db?sslmode=disable&connect_timeout=2"
	_, err := Open(ctx, &config.Config{DBDriver: config.DriverPostgres, DBDSN: config.NewSecret(pgDSN)})
	if err == nil || strings.Contains(err.Error(), "s3cret-pw") {
		t.Errorf("Open(unreachable postgres) = %v", err)
	}

	e := storetest.SQLite(t)
	// A DSN that already carries parameters keeps them.
	db, err := Open(ctx, &config.Config{DBDriver: config.DriverSQLite, DBDSN: config.NewSecret(e.DSN + "?_time_format=sqlite")})
	if err != nil {
		t.Fatalf("Open with params: %v", err)
	}
	if db.Driver() != config.DriverSQLite || db.Ping(ctx) != nil {
		t.Errorf("Driver = %q, Ping = %v", db.Driver(), db.Ping(ctx))
	}
	// The pragmas are applied on both pools.
	for name, pool := range map[string]*sql.DB{"write": db.write, "read": db.read} {
		var mode string
		var fk int
		if err := pool.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
			t.Errorf("%s pool journal_mode = %q, %v", name, mode, err)
		}
		if err := pool.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
			t.Errorf("%s pool foreign_keys = %d, %v", name, fk, err)
		}
		var limit int64
		if err := pool.QueryRowContext(ctx, "PRAGMA journal_size_limit").Scan(&limit); err != nil || limit != 0 {
			t.Errorf("%s pool journal_size_limit = %d, %v", name, limit, err)
		}
		// secure_delete overwrites deleted content: cryptographic erasure.
		var secure int
		if err := pool.QueryRowContext(ctx, "PRAGMA secure_delete").Scan(&secure); err != nil || secure != 1 {
			t.Errorf("%s pool secure_delete = %d, %v", name, secure, err)
		}
	}
	if _, err := db.read.ExecContext(ctx, "CREATE TABLE x (a INT)"); err == nil {
		t.Error("the read pool accepted a write")
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := db.Ping(ctx); err == nil {
		t.Error("Ping after Close succeeded")
	}
}

func TestOpenFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "open.db")
	plan := &faultPlan{}
	faultPlans.Store(path, plan)
	t.Cleanup(func() { faultPlans.Delete(path) })

	plan.add(faultOpen, "_txlock=immediate", 0)
	if _, err := openSQLite(ctx, faultDriverName, path, nil); !errors.Is(err, errInjected) {
		t.Errorf("writer open fault: %v", err)
	}
	plan.reset()
	plan.add(faultOpen, "_query_only=1", 0)
	if _, err := openSQLite(ctx, faultDriverName, path, nil); !errors.Is(err, errInjected) {
		t.Errorf("reader open fault: %v", err)
	}
	plan.reset()

	// openPostgres over the SQLite driver: exercises the pool set-up and the
	// shared-pool Close without a PostgreSQL server.
	db, err := openPostgres(ctx, faultDriverName, path, config.Secret{}, pgLikeDialect(nil), nil)
	if err != nil {
		t.Fatalf("openPostgres: %v", err)
	}
	if db.read != db.write || db.ownerDSN.IsSet() || db.driverName != faultDriverName {
		t.Errorf("postgres DB = %+v", db)
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestClassifyAndWrap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		want error
	}{
		{&pgconn.PgError{Code: pgUniqueViolation}, ErrConflict},
		{&pgconn.PgError{Code: pgForeignKeyViolation}, ErrNotFound},
		{&pgconn.PgError{Code: pgKeyRetired}, ErrKeyRetired},
		{&pgconn.PgError{Code: "42501"}, nil},
		{fmt.Errorf("x: %w", &pgconn.PgError{Code: pgUniqueViolation}), ErrConflict},
		{errors.New("plain"), nil},
	}
	for _, tt := range tests {
		if got := classify(tt.err); !errors.Is(got, tt.want) || (tt.want == nil && got != nil) {
			t.Errorf("classify(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
	pgDup := &pgconn.PgError{Code: pgUniqueViolation, Message: "duplicate key", Detail: "Key (fqdn)=(secret.example.com)"}
	if err := wrap("op", pgDup); !errors.Is(err, ErrConflict) || strings.Contains(err.Error(), "secret") {
		t.Errorf("wrap(pg dup) = %v", err)
	}
	if err := wrap("op", ErrNotFound); err != ErrNotFound { //nolint:errorlint // identity is the point
		t.Errorf("wrap(sentinel) = %v", err)
	}
	if err := wrap("op", errInjected); !errors.Is(err, errInjected) || !strings.HasPrefix(err.Error(), "store: op: ") {
		t.Errorf("wrap(other) = %v", err)
	}
}

func TestClassifySQLite(t *testing.T) {
	t.Parallel()
	db, _ := openFault(t)
	ctx := context.Background()
	// Raw statements on the writer, outside the registry, to obtain real
	// driver errors.
	if _, err := db.write.ExecContext(ctx, `CREATE TABLE c (a TEXT PRIMARY KEY, b TEXT UNIQUE, f TEXT REFERENCES tenants (id), n TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.write.ExecContext(ctx, `INSERT INTO c (a, b, n) VALUES ('1', '1', 'x')`); err != nil {
		t.Fatal(err)
	}
	for _, trig := range []string{
		`CREATE TRIGGER c_other BEFORE INSERT ON c WHEN NEW.a = '5' BEGIN SELECT RAISE(ABORT, 'other'); END`,
		`CREATE TRIGGER c_retired BEFORE INSERT ON c WHEN NEW.a = '6' BEGIN SELECT RAISE(ABORT, '` + retiredKeyMessage + `'); END`,
	} {
		if _, err := db.write.ExecContext(ctx, trig); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]error{
		`INSERT INTO c (a, b, n) VALUES ('1', '2', 'x')`:         ErrConflict, // primary key
		`INSERT INTO c (a, b, n) VALUES ('2', '1', 'x')`:         ErrConflict, // unique
		`INSERT INTO c (a, b, f, n) VALUES ('3', '3', 'z', 'x')`: ErrNotFound, // foreign key
		`INSERT INTO c (a, b) VALUES ('4', '4')`:                 nil,         // not null
		`INSERT INTO c (a, b, n) VALUES ('5', '5', 'x')`:         nil,         // another trigger
		`INSERT INTO c (a, b, n) VALUES ('6', '6', 'x')`:         ErrKeyRetired,
	}
	for q, want := range cases {
		_, err := db.write.ExecContext(ctx, q)
		var se *sqlite.Error
		if !errors.As(err, &se) {
			t.Fatalf("%s: err = %v, want a sqlite error", q, err)
		}
		if got := classify(err); got != want { //nolint:errorlint // sentinels compared by identity
			t.Errorf("classify(%s) = %v, want %v", q, got, want)
		}
	}
}

func TestExecutorsRejectBadInput(t *testing.T) {
	t.Parallel()
	db, _ := openFault(t)
	ctx := context.Background()
	for _, tid := range []tenant.ID{"", "ten_x", tenant.ID("trf_" + strings.Repeat("0", 26))} {
		if _, err := db.Scoped(tid); !errors.Is(err, ErrInvalid) {
			t.Errorf("Scoped(%q) = %v", tid, err)
		}
	}
	if _, err := db.System(" "); !errors.Is(err, ErrInvalid) {
		t.Errorf("System(blank) = %v", err)
	}
	tid := tenant.ID(id.New(id.Tenant))
	s, err := db.Scoped(tid)
	if err != nil || s.Tenant() != tid {
		t.Fatalf("Scoped = %v, %v", s, err)
	}
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		if tx.Tenant() != tid {
			t.Errorf("ScopedTx.Tenant() = %q, want %q", tx.Tenant(), tid)
		}
		if _, err := tx.Exec(ctx, TenantQuery{}); !errors.Is(err, errQueryUnregistered) {
			t.Errorf("Exec(zero query) = %v", err)
		}
		if _, err := tx.Query(ctx, TenantQuery{}); !errors.Is(err, errQueryUnregistered) { //nolint:sqlclosecheck,rowserrcheck // no rows on error
			t.Errorf("Query(zero query) = %v", err)
		}
		if err := tx.QueryRow(ctx, TenantQuery{}).Scan(); !errors.Is(err, errQueryUnregistered) {
			t.Errorf("QueryRow(zero query) = %v", err)
		}
		// A system query smuggled into a TenantQuery is refused at run time.
		smuggled := TenantQuery{tenant: qTenantGet.system}
		if _, err := tx.Exec(ctx, smuggled, "x"); !errors.Is(err, errQueryUnregistered) {
			t.Errorf("Exec(system query as tenant query) = %v", err)
		}
		if err := tx.QueryRow(ctx, smuggled).Scan(); !errors.Is(err, errQueryUnregistered) {
			t.Errorf("QueryRow(system query as tenant query) = %v", err)
		}
		var n int
		if err := tx.QueryRow(ctx, qRulesList).Scan(&n, &n); !errors.Is(err, ErrNotFound) {
			t.Errorf("QueryRow(no row) = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sys, _ := db.System("test")
	err = sys.ReadTx(ctx, func(tx *SystemTx) error {
		if _, err := tx.Exec(ctx, SystemQuery{}); !errors.Is(err, errQueryUnregistered) {
			t.Errorf("Exec(zero query) = %v", err)
		}
		if _, err := tx.Query(ctx, SystemQuery{}); !errors.Is(err, errQueryUnregistered) { //nolint:sqlclosecheck,rowserrcheck // no rows on error
			t.Errorf("Query(zero query) = %v", err)
		}
		if err := tx.QueryRow(ctx, SystemQuery{}).Scan(); !errors.Is(err, errQueryUnregistered) {
			t.Errorf("QueryRow(zero query) = %v", err)
		}
		if _, err := tx.Exec(ctx, qTenantGet); !errors.Is(err, errQueryArgCount) {
			t.Errorf("Exec(missing system argument) = %v", err)
		}
		if err := tx.QueryRow(ctx, qTenantGet, "a", "b").Scan(); !errors.Is(err, errQueryArgCount) {
			t.Errorf("QueryRow(extra system argument) = %v", err)
		}
		smuggled := SystemQuery{system: qRulesList.tenant}
		if _, err := tx.Exec(ctx, smuggled, "ten_x"); !errors.Is(err, errQueryUnregistered) {
			t.Errorf("Exec(tenant query as system query) = %v", err)
		}
		if err := tx.QueryRow(ctx, smuggled, "ten_x").Scan(); !errors.Is(err, errQueryUnregistered) {
			t.Errorf("QueryRow(tenant query as system query) = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunTxRollback(t *testing.T) {
	t.Parallel()
	db, _ := openFault(t)
	ctx := context.Background()
	a, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := db.Scoped(a.ID)
	boom := errors.New("boom")
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		if _, err := tx.Exec(ctx, qRuleInsert, ruleKindDomain, "x.example.com"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Tx err = %v", err)
	}
	func() {
		defer func() { _ = recover() }()
		_ = s.Tx(ctx, func(tx *ScopedTx) error {
			_, _ = tx.Exec(ctx, qRuleInsert, ruleKindDomain, "y.example.com")
			panic("boom")
		})
	}()
	set, err := db.NetworkRules().Get(ctx, a.ID)
	if err != nil || len(set.Domains) != 0 {
		t.Errorf("rolled back writes are visible: %+v, %v", set, err)
	}
}

// TestScopeStatements runs the repositories on SQLite with the
// PostgreSQL-only plumbing statements replaced by harmless ones, so that the
// code paths executing them are covered without a PostgreSQL server; then
// makes each of them fail.
func TestScopeStatements(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	db, _ := openFault(t, WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	ctx := context.Background()
	d := *sqliteDialect
	d.scopeTenant = "SELECT ?"
	d.scopeSystem = "SELECT 1"
	d.migrationLock = "SELECT 1"
	d.lockTenant = "SELECT ?"
	db.dialect = &d
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	a, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := db.NetworkRules().Replace(ctx, a.ID, nil, []string{"a.example.com"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if !strings.Contains(logs.String(), "system scope") || !strings.Contains(logs.String(), reasonTenantAdmin) {
		t.Errorf("system scope not logged: %q", logs.String())
	}

	d.lockTenant = "SELECT bogus("
	if _, err := db.NetworkRules().Replace(ctx, a.ID, nil, nil); err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("failing tenant lock: %v", err)
	}
	d.scopeTenant = "SELECT bogus("
	if _, err := db.NetworkRules().Get(ctx, a.ID); err == nil || !strings.Contains(err.Error(), "set transaction scope") {
		t.Errorf("failing tenant scope: %v", err)
	}
	d.migrationLock = "SELECT bogus("
	if _, err := db.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "lock migrations") {
		t.Errorf("failing migration lock: %v", err)
	}
}

// TestDriverFaults injects a driver failure into each step of every
// operation and checks that it surfaces as an error (and never as success).
func TestDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t, WithClock(func() time.Time { return time.Unix(1_700_000_000, 0) }))
	a, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.NetworkRules().Replace(ctx, a.ID, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"a.example.com"}); err != nil {
		t.Fatal(err)
	}
	blk, err := db.Blocklist().Create(ctx, a.ID, BlocklistEntry{Kind: BlockDomain, Value: "evil.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	newT := func() *tenant.Tenant {
		return &tenant.Tenant{Name: "N", FQDN: "n.example.com", DefaultLanguage: "en", MaxTransferBytes: 1, StorageQuotaBytes: 1}
	}
	upd := a.Clone()

	ops := map[string]func() error{
		"tenants.create": func() error { _, err := db.Tenants().Create(ctx, newT()); return err },
		"tenants.get":    func() error { _, err := db.Tenants().Get(ctx, a.ID); return err },
		"tenants.byfqdn": func() error { _, err := db.Tenants().TenantByFQDN(ctx, a.FQDN); return err },
		"tenants.list":   func() error { _, err := db.Tenants().List(ctx, TenantListOptions{}); return err },
		"tenants.update": func() error { _, err := db.Tenants().Update(ctx, upd); return err },
		"tenants.delete": func() error { return db.Tenants().Delete(ctx, tenant.ID(id.New(id.Tenant))) },
		"rules.get":      func() error { _, err := db.NetworkRules().Get(ctx, a.ID); return err },
		"rules.replace": func() error {
			_, err := db.NetworkRules().Replace(ctx, a.ID, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"a.example.com"})
			return err
		},
		"block.list":     func() error { _, err := db.Blocklist().List(ctx, a.ID, BlocklistFilter{}); return err },
		"block.listkind": func() error { _, err := db.Blocklist().List(ctx, a.ID, BlocklistFilter{Kind: BlockDomain}); return err },
		"block.create": func() error {
			_, err := db.Blocklist().Create(ctx, a.ID, BlocklistEntry{Kind: BlockEmail, Value: "x@example.com"})
			return err
		},
		"block.delete": func() error { return db.Blocklist().Delete(ctx, a.ID, blk.ID) },
		"block.match":  func() error { _, err := db.Blocklist().Match(ctx, a.ID, "x@evil.example.com", ""); return err },
		"migrate":      func() error { _, err := db.Migrate(ctx); return err },
		"status":       func() error { _, err := db.Status(ctx); return err },
	}
	// Each fault, applied to the n-th matching call for n = 0..3, so that
	// the second statement of a transaction fails too.
	faults := []struct{ op, match string }{
		{faultBegin, ""},
		{faultCommit, ""},
		{faultExec, ""},
		{faultExec, "INSERT"},
		{faultExec, "schema_migrations"},
		{faultQuery, ""},
		{faultQuery, "schema_migrations"},
		{faultNext, ""},
		{faultScanNil, ""},
		{faultRows, ""},
	}
	for name, op := range ops {
		for _, f := range faults {
			for after := 0; after < 4; after++ {
				plan.reset()
				plan.add(f.op, f.match, after)
				_ = op() // must not panic; errors are checked below
			}
		}
		plan.reset()
		if err := op(); err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
			t.Errorf("%s fails without faults: %v", name, err)
		}
	}

	// Specific expectations.
	plan.reset()
	plan.add(faultBegin, "", 0)
	if _, err := db.Tenants().Get(ctx, a.ID); !errors.Is(err, errInjected) {
		t.Errorf("begin fault: %v", err)
	}
	plan.reset()
	plan.add(faultCommit, "", 0)
	if err := db.Blocklist().Delete(ctx, a.ID, "blk_none"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete of a missing entry fails before commit: %v", err)
	}
	if _, err := db.Blocklist().Create(ctx, a.ID, BlocklistEntry{Kind: BlockEmail, Value: "c@example.com"}); !errors.Is(err, errInjected) {
		t.Errorf("commit fault: %v", err)
	}
	plan.reset()
	plan.add(faultScanNil, "FROM tenants", 0)
	if _, err := db.Tenants().List(ctx, TenantListOptions{}); err == nil {
		t.Error("scan fault ignored")
	}
	plan.reset()
	// The map order above is random and block.delete may have emptied the
	// blocklist: scan an entry deterministically.
	if _, err := db.Blocklist().Create(ctx, a.ID, BlocklistEntry{Kind: BlockDomain, Value: "scan.example.com"}); err != nil {
		t.Fatal(err)
	}
	plan.add(faultScanNil, "FROM blocklist_entries", 0)
	if _, err := db.Blocklist().List(ctx, a.ID, BlocklistFilter{}); err == nil {
		t.Error("blocklist scan fault ignored")
	}
	plan.reset()
	plan.add(faultNext, "FROM blocklist_entries", 0)
	if _, err := db.Blocklist().Match(ctx, a.ID, "x@evil.example.com", ""); !errors.Is(err, errInjected) {
		t.Errorf("rows fault: %v", err)
	}
	plan.reset()
	plan.add(faultRows, "DELETE", 0)
	if err := db.Tenants().Delete(ctx, a.ID); !errors.Is(err, errInjected) {
		t.Errorf("rows affected fault: %v", err)
	}
	plan.reset()

	// Corrupt stored data is reported, never returned.
	if _, err := db.write.ExecContext(ctx, `INSERT INTO tenant_network_rules (tenant_id, kind, value) VALUES (?, 'cidr', 'not-a-cidr')`, string(a.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.NetworkRules().Get(ctx, a.ID); !errors.Is(err, ErrInvalid) {
		t.Errorf("corrupt cidr: %v", err)
	}

	// ID generation failure.
	db.newID = func(id.Prefix) (string, error) { return "", errInjected }
	if _, err := db.Tenants().Create(ctx, newT()); !errors.Is(err, errInjected) {
		t.Errorf("tenant id failure: %v", err)
	}
	if _, err := db.Blocklist().Create(ctx, a.ID, BlocklistEntry{Kind: BlockEmail, Value: "d@example.com"}); !errors.Is(err, errInjected) {
		t.Errorf("blocklist id failure: %v", err)
	}
}

func TestPageLimit(t *testing.T) {
	t.Parallel()
	for in, want := range map[int]int{-1: DefaultPageSize, 0: DefaultPageSize, 1: 1, MaxPageSize: MaxPageSize, MaxPageSize + 1: MaxPageSize} {
		if got := pageLimit(in); got != want {
			t.Errorf("pageLimit(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestTimeHelpers(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 10, 19, 1, 2, 3, 456_789_000, time.FixedZone("x", 3600))
	got := fromMillis(toMillis(ts))
	if !got.Equal(ts.Truncate(time.Millisecond)) || got.Location() != time.UTC {
		t.Errorf("round trip = %v", got)
	}
}

func TestMigrateFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fresh := func() (*DB, *faultPlan) {
		path := filepath.Join(t.TempDir(), "m.db")
		plan := &faultPlan{}
		faultPlans.Store(path, plan)
		t.Cleanup(func() { faultPlans.Delete(path) })
		db, err := openSQLite(ctx, faultDriverName, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db, plan
	}
	db, plan := fresh()
	plan.add(faultExec, "CREATE TABLE tenants", 0)
	if _, err := db.Migrate(ctx); !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "apply migration 0001_init") {
		t.Errorf("failing migration: %v", err)
	}
	plan.reset()
	plan.add(faultExec, "INSERT INTO schema_migrations", 0)
	if _, err := db.Migrate(ctx); !errors.Is(err, errInjected) {
		t.Errorf("failing bookkeeping: %v", err)
	}
	plan.reset()
	// Nothing was half-applied: a clean run applies everything.
	if n, err := db.Migrate(ctx); err != nil || n != len(mustMigrations(t, db)) {
		t.Errorf("Migrate after faults = %d, %v", n, err)
	}

	db.migrationsFS = fstest.MapFS{}
	if _, err := db.Migrate(ctx); !errors.Is(err, errBadMigrations) {
		t.Errorf("Migrate without migrations: %v", err)
	}
	if _, err := db.Status(ctx); !errors.Is(err, errBadMigrations) {
		t.Errorf("Status without migrations: %v", err)
	}
}

// Tenant queries whose tenant slot is not the first placeholder, declared
// for the tests only.
var (
	qTestRuleInsertLast = tenantQuery(`INSERT INTO tenant_network_rules (kind, value, tenant_id) VALUES (?, ?, ?)`)
	qTestRuleCount      = tenantQuery(`SELECT count(*) FROM tenant_network_rules WHERE kind = ? AND value = ? AND tenant_id = ?`)
	qTestRuleDelete     = tenantQuery(`DELETE FROM tenant_network_rules WHERE value = ? AND tenant_id = ? AND kind = ?`)
)

func TestTenantSlotInjection(t *testing.T) {
	t.Parallel()
	db, _ := openFault(t)
	ctx := context.Background()
	mk := func(fqdn string) tenant.ID {
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: fqdn, FQDN: fqdn, DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		return tn.ID
	}
	a, b := mk("a.example.com"), mk("b.example.com")
	sa, _ := db.Scoped(a)
	sb, _ := db.Scoped(b)
	count := func(s *Scoped) int {
		var n int
		if err := s.ReadTx(ctx, func(tx *ScopedTx) error {
			return tx.QueryRow(ctx, qTestRuleCount, ruleKindDomain, "x.example.com").Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := sa.Tx(ctx, func(tx *ScopedTx) error {
		_, err := tx.Exec(ctx, qTestRuleInsertLast, ruleKindDomain, "x.example.com")
		return err
	}); err != nil {
		t.Fatalf("insert with a last tenant slot: %v", err)
	}
	if count(sa) != 1 || count(sb) != 0 {
		t.Fatalf("counts A=%d B=%d, want 1 and 0", count(sa), count(sb))
	}
	// B deleting the same value leaves A's row alone.
	if err := sb.Tx(ctx, func(tx *ScopedTx) error {
		_, err := tx.Exec(ctx, qTestRuleDelete, "x.example.com", ruleKindDomain)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if count(sa) != 1 {
		t.Fatal("B's delete removed A's row")
	}
	if err := sa.Tx(ctx, func(tx *ScopedTx) error {
		_, err := tx.Exec(ctx, qTestRuleDelete, "x.example.com", ruleKindDomain)
		return err
	}); err != nil || count(sa) != 0 {
		t.Fatalf("A's delete: %v, count %d", err, count(sa))
	}
	// Too few arguments to reach the slot: rejected before the driver.
	err := sa.ReadTx(ctx, func(tx *ScopedTx) error {
		if _, err := tx.Exec(ctx, qTestRuleDelete); !errors.Is(err, errQueryArgCount) {
			t.Errorf("Exec(missing args) = %v", err)
		}
		if _, err := tx.Query(ctx, qTestRuleCount, ruleKindDomain); !errors.Is(err, errQueryArgCount) { //nolint:sqlclosecheck,rowserrcheck // no rows on error
			t.Errorf("Query(missing args) = %v", err)
		}
		if _, err := tx.Exec(ctx, qTestRuleDelete, "a", "b", "c"); !errors.Is(err, errQueryArgCount) {
			t.Errorf("Exec(extra args) = %v", err)
		}
		if err := tx.QueryRow(ctx, qTestRuleCount).Scan(); !errors.Is(err, errQueryArgCount) {
			t.Errorf("QueryRow(missing args) = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

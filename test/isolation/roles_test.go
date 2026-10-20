package isolation_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// envPostgresSuperuserDSN optionally points to a PostgreSQL superuser of
// the test server (the bootstrap user of test/docker-compose.test.yml). It
// is only needed by the tests that create their own roles, which the owner
// and runtime roles (NOCREATEROLE) cannot do. Those tests are skipped
// without it and must then be checked manually.
const envPostgresSuperuserDSN = "TT_TEST_POSTGRES_SUPERUSER_DSN"

// TestScopedTxExposesNoRawSQL checks, structurally, that a tenant-scoped
// transaction offers no way to run arbitrary SQL through the store API:
// every exported method takes a store.TenantQuery (which only the store
// package can register) and no string statement. Hence code using the
// store cannot change app.tenant_id or app.system_scope in the middle of a
// scoped transaction; only raw SQL could (see TestResidualRiskInjectedSetConfig).
func TestScopedTxExposesNoRawSQL(t *testing.T) {
	t.Parallel()
	tq := reflect.TypeFor[store.TenantQuery]()
	typ := reflect.TypeFor[*store.ScopedTx]()
	if typ.NumMethod() == 0 {
		t.Fatal("ScopedTx has no exported method")
	}
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		takesQuery := false
		for j := 1; j < m.Type.NumIn(); j++ {
			in := m.Type.In(j)
			if in == tq {
				takesQuery = true
			}
			if in.Kind() == reflect.String {
				t.Errorf("ScopedTx.%s takes a string argument %v: it could carry raw SQL", m.Name, in)
			}
		}
		if !takesQuery {
			t.Errorf("ScopedTx.%s does not take a store.TenantQuery", m.Name)
		}
	}
	// The same holds for the scoped executor itself.
	for i := range reflect.TypeFor[*store.Scoped]().NumMethod() {
		m := reflect.TypeFor[*store.Scoped]().Method(i)
		for j := 1; j < m.Type.NumIn(); j++ {
			if m.Type.In(j).Kind() == reflect.String {
				t.Errorf("Scoped.%s takes a string argument", m.Name)
			}
		}
	}
}

// TestResidualRiskInjectedSetConfig documents the residual risk accepted in
// threat model T-75: SQL run with the runtime role (an injection) can call
// set_config itself and switch app.tenant_id or app.system_scope, so the
// RLS layer protects against application mistakes, not against SQL
// injection (mitigated by T-76: parameterised registered queries only).
//
// The test asserts that the bypass IS possible, so that the risk stays
// visible: if a future change closes it (e.g. a BYPASSRLS-free design
// without settings the session can write), update the threat model and
// invert this test.
func TestResidualRiskInjectedSetConfig(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	a, b := string(f.a.ID), string(f.b.ID)

	cases := []struct {
		name     string
		injected string
		args     []any
	}{
		{"switch app.tenant_id to B", `SELECT set_config('app.tenant_id', $1, true)`, []any{b}},
		{"enable app.system_scope", `SELECT set_config('app.system_scope', 'on', true)`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				if n := countRows(ctx, t, tx, `SELECT count(*) FROM blocklist_entries WHERE tenant_id = $1`, b); n != 0 {
					t.Fatalf("before injection, A sees %d of B's rows", n)
				}
				if _, err := tx.ExecContext(ctx, tc.injected, tc.args...); err != nil {
					return err
				}
				if n := countRows(ctx, t, tx, `SELECT count(*) FROM blocklist_entries WHERE tenant_id = $1`, b); n != len(f.blockB) {
					t.Errorf("residual risk T-75 changed: after %q, A's transaction sees %d of B's %d rows; "+
						"update the threat model and this test", tc.injected, n, len(f.blockB))
				}
				return nil
			})
			if err != nil {
				t.Fatalf("injected set_config: %v", err)
			}
		})
	}
}

// TestTenantScopeCannotWriteTenantsRow checks that a tenant-scoped
// transaction may read its own tenants row but never modify or delete it:
// on the tenants table the tenant scope has a SELECT-only policy, writes
// need the system scope. A refused write is either an RLS error or zero
// affected rows.
func TestTenantScopeCannotWriteTenantsRow(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	a := string(f.a.ID)

	err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		if n := countRows(ctx, t, tx, `SELECT count(*) FROM tenants WHERE id = $1`, a); n != 1 {
			t.Errorf("tenant scope sees %d own tenants rows, want 1", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	stmts := []struct {
		name string
		stmt string
		args []any
	}{
		{"raise own quota", `UPDATE tenants SET storage_quota_bytes = 9223372036854775807 WHERE id = $1`, []any{a}},
		{"change own FQDN", `UPDATE tenants SET fqdn = 'transfer.entity-b2.example.org' WHERE id = $1`, []any{a}},
		{"rename own id", `UPDATE tenants SET id = $1 WHERE id = $2`, []any{a + "X", a}},
		{"delete own row", `DELETE FROM tenants WHERE id = $1`, []any{a}},
		{"update every visible row", `UPDATE tenants SET name = 'pwned'`, nil},
	}
	for _, s := range stmts {
		t.Run(s.name, func(t *testing.T) {
			var n int64
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				res, err := tx.ExecContext(ctx, s.stmt, s.args...)
				if err != nil {
					return err
				}
				n, err = res.RowsAffected()
				return err
			})
			if err != nil {
				assertRLSViolation(t, s.name, err)
			} else if n != 0 {
				t.Errorf("%s: tenant scope modified %d tenants rows", s.name, n)
			}
		})
	}
	got, err := f.db.Tenants().Get(ctx, f.a.ID)
	if err != nil || *got != *f.a {
		t.Errorf("tenant A changed: %+v, %v; want %+v", got, err, f.a)
	}
}

// withParam returns dsn (URL form) with an extra query parameter.
func withParam(t *testing.T, dsn, key, value string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parsing DSN: %v", err)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// pgConfig builds a PostgreSQL configuration from two DSNs.
func pgConfig(runtime, owner string) *config.Config {
	return &config.Config{DBDriver: config.DriverPostgres, DBDSN: config.NewSecret(runtime), DBMigrateDSN: config.NewSecret(owner)}
}

// pgEngine returns a fresh PostgreSQL engine or skips the test.
func pgEngine(t *testing.T) storetest.Engine {
	t.Helper()
	e, ok := storetest.Postgres(t)
	if !ok {
		t.Skip("PostgreSQL not available (set TT_TEST_POSTGRES_DSN and TT_TEST_POSTGRES_MIGRATE_DSN, see test/README.md)")
	}
	return e
}

// TestMigrateTwoRoles runs the migrations against a real two-role
// PostgreSQL: they succeed, a second run applies nothing and the runtime
// role passes Verify; a single-role set-up is refused.
func TestMigrateTwoRoles(t *testing.T) {
	t.Parallel()

	t.Run("owner migrates, runtime verified, idempotent", func(t *testing.T) {
		t.Parallel()
		e := pgEngine(t)
		ctx := t.Context()
		db, err := store.Open(ctx, e.Config(), store.WithClock(steppingClock()))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		n, err := db.Migrate(ctx)
		if err != nil || n < 1 {
			t.Fatalf("first Migrate = %d, %v; want >= 1, nil", n, err)
		}
		n, err = db.Migrate(ctx)
		if err != nil || n != 0 {
			t.Fatalf("second Migrate = %d, %v; want 0, nil", n, err)
		}
		if err := db.Verify(ctx); err != nil {
			t.Fatalf("Verify after migrations: %v", err)
		}
		// A store reopened on the migrated schema works for both tenants.
		db2, err := store.Open(ctx, e.Config())
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		_ = db2.Close()
	})

	t.Run("same role for migrations and runtime is refused", func(t *testing.T) {
		t.Parallel()
		e := pgEngine(t)
		ctx := t.Context()
		for _, owner := range []string{e.DSN, withParam(t, e.DSN, "application_name", "transteira-migrate")} {
			db, err := store.Open(ctx, pgConfig(e.DSN, owner))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			n, err := db.Migrate(ctx)
			_ = db.Close()
			if err == nil {
				t.Errorf("Migrate with the runtime role as owner succeeded (%d applied)", n)
			} else if !strings.Contains(err.Error(), "same role") {
				t.Errorf("Migrate err = %v, want a same-role refusal", err)
			}
		}
	})

	t.Run("owner role used at runtime is refused", func(t *testing.T) {
		t.Parallel()
		e := pgEngine(t)
		ctx := t.Context()
		db, err := store.Open(ctx, pgConfig(e.MigrateDSN, e.MigrateDSN))
		if err == nil {
			_ = db.Close()
			t.Fatal("Open with the owner role as runtime role succeeded")
		}
		if !errors.Is(err, store.ErrUnsafeDatabase) {
			t.Errorf("Open err = %v, want ErrUnsafeDatabase", err)
		}
	})
}

// TestVerifyRefusesCreateOnSchema grants the runtime role CREATE on the
// schema (with which it could create objects, e.g. functions or tables
// shadowing the application's) and checks that Verify and Open refuse it,
// and that Migrate, which re-applies the minimal grants, repairs it.
func TestVerifyRefusesCreateOnSchema(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()

	var runtimeRole string
	if err := raw.QueryRowContext(ctx, `SELECT current_user`).Scan(&runtimeRole); err != nil {
		t.Fatal(err)
	}
	owner := rawOwner(t, f.e)
	if _, err := owner.ExecContext(ctx, `GRANT CREATE ON SCHEMA `+pgx.Identifier{f.e.Schema}.Sanitize()+
		` TO `+pgx.Identifier{runtimeRole}.Sanitize()); err != nil {
		t.Fatalf("granting CREATE: %v", err)
	}
	if err := f.db.Verify(ctx); !errors.Is(err, store.ErrUnsafeDatabase) {
		t.Errorf("Verify with CREATE on the schema err = %v, want ErrUnsafeDatabase", err)
	}
	if db, err := store.Open(ctx, f.e.Config()); !errors.Is(err, store.ErrUnsafeDatabase) {
		if db != nil {
			_ = db.Close()
		}
		t.Errorf("Open with CREATE on the schema err = %v, want ErrUnsafeDatabase", err)
	}
	if _, err := f.db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate (re-applying grants): %v", err)
	}
	if err := f.db.Verify(ctx); err != nil {
		t.Errorf("Verify after Migrate repaired the grants: %v", err)
	}
}

// rawOwner opens a connection with the owner role on the engine's schema.
func rawOwner(t *testing.T, e storetest.Engine) *sql.DB {
	t.Helper()
	owner, err := sql.Open("pgx", e.MigrateDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return owner
}

// TestVerifyRefusesMemberOfOwner makes the runtime role a member of the
// owner role (through which it could SET ROLE or inherit ownership and
// drop the policies) and checks that Verify and Open refuse it. It needs a
// superuser to create a dedicated role pair (TT_TEST_POSTGRES_SUPERUSER_DSN);
// without it the test is skipped and the check is manual:
//
//	GRANT <owner> TO <runtime>;  -- then start TransTeira: it must refuse
func TestVerifyRefusesMemberOfOwner(t *testing.T) {
	t.Parallel()
	superDSN := os.Getenv(envPostgresSuperuserDSN)
	if superDSN == "" {
		t.Skipf("%s not set: creating roles needs a superuser; manual check: GRANT owner TO runtime, then Open must fail", envPostgresSuperuserDSN)
	}
	ctx := t.Context()
	super, err := sql.Open("pgx", superDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close() })

	suffix := randHex(t, 6)
	ownerRole, appRole, schema := "tt_own_"+suffix, "tt_app_"+suffix, "tt_m_"+suffix
	ownerPwd, appPwd := randHex(t, 16), randHex(t, 16)
	q := func(s string) string { return pgx.Identifier{s}.Sanitize() }
	exec := func(stmt string) {
		t.Helper()
		if _, err := super.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	exec(`CREATE ROLE ` + q(ownerRole) + ` LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '` + ownerPwd + `'`)
	exec(`CREATE ROLE ` + q(appRole) + ` LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '` + appPwd + `'`)
	t.Cleanup(func() {
		ctx := context.Background()
		for _, stmt := range []string{
			`DROP SCHEMA IF EXISTS ` + q(schema) + ` CASCADE`,
			`DROP OWNED BY ` + q(appRole) + `, ` + q(ownerRole),
			`DROP ROLE IF EXISTS ` + q(appRole),
			`DROP ROLE IF EXISTS ` + q(ownerRole),
		} {
			if _, err := super.ExecContext(ctx, stmt); err != nil {
				t.Errorf("cleanup %s: %v", stmt, err)
			}
		}
	})
	var dbName string
	if err := super.QueryRowContext(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	exec(`GRANT CONNECT, TEMPORARY ON DATABASE ` + q(dbName) + ` TO ` + q(ownerRole) + `, ` + q(appRole))
	exec(`CREATE SCHEMA ` + q(schema) + ` AUTHORIZATION ` + q(ownerRole))

	roleDSN := func(role, pwd string) string {
		u, err := url.Parse(superDSN)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword(role, pwd)
		return withParam(t, u.String(), "search_path", schema)
	}
	cfg := pgConfig(roleDSN(appRole, appPwd), roleDSN(ownerRole, ownerPwd))
	db, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open with a sound role pair: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate with a sound role pair: %v", err)
	}

	for _, grant := range []string{
		`GRANT ` + q(ownerRole) + ` TO ` + q(appRole),
		// Without inheritance the member can still SET ROLE to the owner.
		`GRANT ` + q(ownerRole) + ` TO ` + q(appRole) + ` WITH INHERIT FALSE, SET TRUE`,
	} {
		exec(grant)
		if err := db.Verify(ctx); !errors.Is(err, store.ErrUnsafeDatabase) {
			t.Errorf("after %q, Verify err = %v, want ErrUnsafeDatabase", grant, err)
		}
		if db2, err := store.Open(ctx, cfg); !errors.Is(err, store.ErrUnsafeDatabase) {
			if db2 != nil {
				_ = db2.Close()
			}
			t.Errorf("after %q, Open err = %v, want ErrUnsafeDatabase", grant, err)
		}
		exec(`REVOKE ` + q(ownerRole) + ` FROM ` + q(appRole))
	}
	if err := db.Verify(ctx); err != nil {
		t.Errorf("Verify after revoking the membership: %v", err)
	}
}

// randHex returns n random bytes in hexadecimal.
func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

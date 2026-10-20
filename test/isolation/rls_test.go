package isolation_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// PostgreSQL SQLSTATE codes expected by the RLS tests.
const (
	pgInsufficientPrivilege = "42501" // includes "new row violates row-level security policy"
)

// pgFixture returns a fixture on a fresh PostgreSQL schema and a raw
// single-connection pool on the same schema, with the application role. It
// skips the test when PostgreSQL is not available (storetest fails it
// instead when TT_TEST_REQUIRE_POSTGRES=1).
func pgFixture(t *testing.T) (*fixture, *sql.DB) {
	t.Helper()
	e, ok := storetest.Postgres(t)
	if !ok {
		t.Skip("PostgreSQL not available (set TT_TEST_POSTGRES_DSN and TT_TEST_POSTGRES_MIGRATE_DSN, see test/README.md)")
	}
	f := newFixture(t, e)
	return f, rawDB(t, e)
}

// inTenantTx runs fn in a raw transaction where app.tenant_id is set,
// transaction-locally, to tenant (no setting at all when tenant is nil).
// The transaction is always rolled back.
func inTenantTx(ctx context.Context, t *testing.T, raw *sql.DB, tenant *string, fn func(tx *sql.Tx) error) error {
	t.Helper()
	tx, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if tenant != nil {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, *tenant); err != nil {
			t.Fatalf("set_config: %v", err)
		}
	}
	return fn(tx)
}

// countRows runs a count(*) query.
func countRows(ctx context.Context, t *testing.T, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, query string, args ...any,
) int {
	t.Helper()
	var n int
	if err := q.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// affected runs a statement and returns the number of affected rows.
func affected(ctx context.Context, t *testing.T, tx *sql.Tx, stmt string, args ...any) int64 {
	t.Helper()
	res, err := tx.ExecContext(ctx, stmt, args...)
	if err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// assertRLSViolation checks that err is a PostgreSQL row-level security
// violation.
func assertRLSViolation(t *testing.T, what string, err error) {
	t.Helper()
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != pgInsufficientPrivilege {
		t.Errorf("%s: err = %v, want SQLSTATE %s (row-level security violation)", what, err, pgInsufficientPrivilege)
	}
}

// TestRLSRoleCannotBypass verifies the premise of every RLS test: the
// runtime role is neither superuser nor BYPASSRLS nor owner, and every
// tenant-scoped table (any table with a tenant_id column, plus tenants)
// has row-level security enabled, forced and at least one policy. New
// tables are covered automatically.
func TestRLSRoleCannotBypass(t *testing.T) {
	t.Parallel()
	_, raw := pgFixture(t)
	ctx := t.Context()

	var super, bypass bool
	var role string
	if err := raw.QueryRowContext(ctx,
		`SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).
		Scan(&role, &super, &bypass); err != nil {
		t.Fatalf("reading role attributes: %v", err)
	}
	if super || bypass {
		t.Fatalf("role %s has SUPERUSER=%v BYPASSRLS=%v: row-level security is meaningless, every RLS test would pass vacuously", role, super, bypass)
	}

	// The runtime role owns nothing in its search path, cannot create
	// objects in the schema and is not a member of the schema owner: any of
	// these would let SQL run with it drop or bypass the policies.
	var owned int
	var canCreate, memberOfOwner bool
	if err := raw.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		         WHERE n.nspname = ANY (current_schemas(false)) AND pg_has_role(current_user, c.relowner, 'USAGE'))
		     + (SELECT count(*) FROM pg_namespace WHERE nspname = ANY (current_schemas(false))
		         AND pg_has_role(current_user, nspowner, 'USAGE')),
		       has_schema_privilege(current_user, current_schema(), 'CREATE'),
		       (SELECT pg_has_role(current_user, nspowner, 'MEMBER') FROM pg_namespace WHERE nspname = current_schema())`).
		Scan(&owned, &canCreate, &memberOfOwner); err != nil {
		t.Fatalf("reading runtime role privileges: %v", err)
	}
	if owned != 0 || canCreate || memberOfOwner {
		t.Fatalf("runtime role %s: owns %d objects, CREATE on schema=%v, member of owner=%v; want none", role, owned, canCreate, memberOfOwner)
	}

	rows, err := raw.QueryContext(ctx, `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
		       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')
		  AND (c.relname = 'tenants' OR EXISTS (
		        SELECT 1 FROM pg_attribute a
		        WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped))
		ORDER BY c.relname`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	seen := 0
	for rows.Next() {
		var name string
		var enabled, forced bool
		var policies int
		if err := rows.Scan(&name, &enabled, &forced, &policies); err != nil {
			t.Fatal(err)
		}
		seen++
		if !enabled || !forced || policies == 0 {
			t.Errorf("table %s: RLS enabled=%v forced=%v policies=%d; want enabled, forced, >= 1 policy", name, enabled, forced, policies)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen < 3 {
		t.Errorf("found %d tenant-scoped tables, want at least tenants, tenant_network_rules, blocklist_entries", seen)
	}
}

// TestRLSOwnerCannotDisablePolicies checks the two-role model (threat model
// T-75): the runtime role owns no table, so SQL run with it (including an
// injected statement) cannot ALTER TABLE ... NO FORCE ROW LEVEL SECURITY and
// escape the policies. Only the owner role used by migrations could.
func TestRLSOwnerCannotDisablePolicies(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	a := string(f.a.ID)

	for _, table := range []string{"tenants", "tenant_network_rules", "blocklist_entries"} {
		stmts := []string{
			`ALTER TABLE ` + table + ` NO FORCE ROW LEVEL SECURITY`,
			`ALTER TABLE ` + table + ` DISABLE ROW LEVEL SECURITY`,
		}
		// Policy names are discovered, so that renaming or splitting the
		// policies keeps every one of them covered.
		policies := policyNames(ctx, t, raw, table)
		if len(policies) == 0 {
			t.Errorf("table %s has no policy", table)
		}
		for _, p := range policies {
			stmts = append(stmts, `DROP POLICY `+pgx.Identifier{p}.Sanitize()+` ON `+table,
				`ALTER POLICY `+pgx.Identifier{p}.Sanitize()+` ON `+table+` USING (true)`)
		}
		for _, stmt := range stmts {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, stmt)
				return err
			})
			if err == nil {
				t.Errorf("the runtime role can run %q: it must not own application tables", stmt)
				continue
			}
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != pgInsufficientPrivilege {
				t.Errorf("%s: err = %v, want SQLSTATE 42501 (must be owner)", stmt, err)
			}
		}
	}
	// Whatever happened, it was rolled back: the policies still apply.
	err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		if n := countRows(ctx, t, tx, `SELECT count(*) FROM blocklist_entries WHERE tenant_id = $1`, string(f.b.ID)); n != 0 {
			t.Errorf("A's raw transaction sees %d of B's entries", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRLSBlocksCrossTenantRawSQL bypasses the application layer entirely:
// a raw transaction scoped to A runs SELECT, UPDATE, DELETE and INSERT
// statements aimed at B's rows. Row-level security alone must stop them.
func TestRLSBlocksCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	a, b := string(f.a.ID), string(f.b.ID)
	bEntry := f.blockB[0].ID

	t.Run("select", func(t *testing.T) {
		_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
			checks := []struct {
				query string
				args  []any
				want  int
			}{
				{`SELECT count(*) FROM blocklist_entries WHERE tenant_id = $1`, []any{b}, 0},
				{`SELECT count(*) FROM blocklist_entries WHERE id = $1`, []any{bEntry}, 0},
				{`SELECT count(*) FROM blocklist_entries`, nil, len(f.blockA)},
				{`SELECT count(*) FROM blocklist_entries WHERE tenant_id <> $1`, []any{a}, 0},
				{`SELECT count(*) FROM tenant_network_rules WHERE tenant_id = $1`, []any{b}, 0},
				{`SELECT count(*) FROM tenant_network_rules`, nil, len(f.rulesA.CIDRs) + len(f.rulesA.Domains)},
				{`SELECT count(*) FROM tenants WHERE id = $1`, []any{b}, 0},
				{`SELECT count(*) FROM tenants`, nil, 1},
				// A tautology does not help.
				{`SELECT count(*) FROM blocklist_entries WHERE true OR tenant_id = $1`, []any{b}, len(f.blockA)},
			}
			for _, c := range checks {
				if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
					t.Errorf("%s = %d, want %d", c.query, n, c.want)
				}
			}
			return nil
		})
	})

	t.Run("update and delete affect zero rows", func(t *testing.T) {
		_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
			stmts := []struct {
				stmt string
				args []any
			}{
				{`UPDATE blocklist_entries SET comment = 'pwned' WHERE tenant_id = $1`, []any{b}},
				{`UPDATE blocklist_entries SET comment = 'pwned' WHERE id = $1`, []any{bEntry}},
				{`DELETE FROM blocklist_entries WHERE tenant_id = $1`, []any{b}},
				{`DELETE FROM blocklist_entries WHERE id = $1`, []any{bEntry}},
				{`UPDATE tenant_network_rules SET value = '0.0.0.0/0' WHERE tenant_id = $1`, []any{b}},
				{`DELETE FROM tenant_network_rules WHERE tenant_id = $1`, []any{b}},
				{`UPDATE tenants SET name = 'pwned' WHERE id = $1`, []any{b}},
				{`DELETE FROM tenants WHERE id = $1`, []any{b}},
			}
			for _, s := range stmts {
				if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
					t.Errorf("%s affected %d rows of B", s.stmt, n)
				}
			}
			return nil
		})
		f.assertBIntact(ctx, t)
	})

	// Each violating statement runs in its own transaction: the error
	// aborts the transaction.
	violations := []struct {
		name string
		stmt string
		args []any
	}{
		{"insert blocklist entry for B", `INSERT INTO blocklist_entries (id, tenant_id, kind, value, created_at) VALUES ($1, $2, 'email', 'evil@example.net', 0)`, []any{"blk_01JZZZZZZZZZZZZZZZZZZZZZZZ", b}},
		{"insert network rule for B", `INSERT INTO tenant_network_rules (tenant_id, kind, value) VALUES ($1, 'cidr', '0.0.0.0/0')`, []any{b}},
		{"insert a tenant", `INSERT INTO tenants (id, name, fqdn, default_language, max_transfer_bytes, storage_quota_bytes, created_at, updated_at) VALUES ('ten_01JZZZZZZZZZZZZZZZZZZZZZZZ', 'x', 'transfer.entity-x.example.com', 'en', 1, 1, 0, 0)`, nil},
		{"move A's entries to B", `UPDATE blocklist_entries SET tenant_id = $1`, []any{b}},
		{"move A's rules to B", `UPDATE tenant_network_rules SET tenant_id = $1`, []any{b}},
	}
	for _, v := range violations {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			assertRLSViolation(t, v.name, err)
		})
	}
	f.assertAIntact(ctx, t)
	f.assertBIntact(ctx, t)
}

// TestRLSWithoutSettingSeesNothing checks that a raw session that never set
// app.tenant_id, or set it to an empty or bogus value, sees no row at all,
// and that only the exact value 'on' of app.system_scope bypasses the
// policies.
func TestRLSWithoutSettingSeesNothing(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	tables := []string{"tenants", "tenant_network_rules", "blocklist_entries"}

	for _, table := range tables {
		if n := countRows(ctx, t, raw, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("fresh session without app.tenant_id sees %d rows of %s", n, table)
		}
	}
	for _, v := range []string{"", " ", "%", string(f.a.ID) + " ", "ten_%"} {
		err := inTenantTx(ctx, t, raw, &v, func(tx *sql.Tx) error {
			for _, table := range tables {
				if n := countRows(ctx, t, tx, `SELECT count(*) FROM `+table); n != 0 {
					t.Errorf("app.tenant_id=%q sees %d rows of %s", v, n, table)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Only the exact value 'on' bypasses; app.tenant_id = A plus any other
	// system_scope value still sees A only.
	a := string(f.a.ID)
	for _, v := range []string{"", "off", "ON", "On", "true", "1", "yes", " on", "on "} {
		err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `SELECT set_config('app.system_scope', $1, true)`, v); err != nil {
				t.Fatal(err)
			}
			if n := countRows(ctx, t, tx, `SELECT count(*) FROM blocklist_entries WHERE tenant_id = $1`, string(f.b.ID)); n != 0 {
				t.Errorf("app.system_scope=%q bypasses RLS (%d of B's rows visible)", v, n)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestRLSSettingIsTransactionLocal proves, on a single pooled connection,
// that the tenant set by set_config(..., true) does not survive its
// transaction, whether committed or rolled back.
func TestRLSSettingIsTransactionLocal(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	a := string(f.a.ID)

	var pidBefore int
	if err := raw.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pidBefore); err != nil {
		t.Fatal(err)
	}
	for _, commit := range []bool{true, false} {
		tx, err := raw.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.system_scope', 'on', true)`, a); err != nil {
			t.Fatal(err)
		}
		if n := countRows(ctx, t, tx, `SELECT count(*) FROM blocklist_entries`); n != len(f.blockA)+len(f.blockB) {
			t.Fatalf("system scope inside the transaction sees %d rows, want %d", n, len(f.blockA)+len(f.blockB))
		}
		if commit {
			err = tx.Commit()
		} else {
			err = tx.Rollback()
		}
		if err != nil {
			t.Fatal(err)
		}
		// Next transaction and next autocommit statement on the same session.
		_ = inTenantTx(ctx, t, raw, nil, func(tx *sql.Tx) error {
			if n := countRows(ctx, t, tx, `SELECT count(*) FROM blocklist_entries`); n != 0 {
				t.Errorf("commit=%v: next transaction on the same connection sees %d rows (setting leaked)", commit, n)
			}
			return nil
		})
		if n := countRows(ctx, t, raw, `SELECT count(*) FROM blocklist_entries`); n != 0 {
			t.Errorf("commit=%v: next statement on the same connection sees %d rows (setting leaked)", commit, n)
		}
		var setting sql.NullString
		if err := raw.QueryRowContext(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&setting); err != nil {
			t.Fatal(err)
		}
		if setting.Valid && setting.String != "" {
			t.Errorf("commit=%v: app.tenant_id = %q after the transaction", commit, setting.String)
		}
	}
	var pidAfter int
	if err := raw.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pidAfter); err != nil {
		t.Fatal(err)
	}
	if pidAfter != pidBefore {
		t.Fatalf("the pool changed connection (pid %d -> %d): the leak test proves nothing", pidBefore, pidAfter)
	}
}

// policyNames returns the names of the row-level security policies of table
// in the current schema (pg_policies is readable by any role).
func policyNames(ctx context.Context, t *testing.T, raw *sql.DB, table string) []string {
	t.Helper()
	rows, err := raw.QueryContext(ctx,
		`SELECT policyname::text FROM pg_policies WHERE schemaname = current_schema() AND tablename = $1 ORDER BY policyname`, table)
	if err != nil {
		t.Fatalf("listing policies of %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return names
}

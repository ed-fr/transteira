package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/tenant"
)

// errRollback aborts the oracle's transactions.
var errRollback = errors.New("rollback")

// nonDeterministic lists SQLite functions whose result could differ between
// the two runs of the oracle for reasons unrelated to isolation.
var nonDeterministic = []string{"random", "now", "changes", "last_insert_rowid", "total_changes", "julianday", "strftime", "datetime", "date", "time", "unixepoch"}

// oracleFixture is a migrated SQLite database with tenants A and B, each
// owning network rules and blocklist entries.
type oracleFixture struct {
	db   *DB
	a, b tenant.ID
}

// newOracleFixture builds the two-tenant fixture.
func newOracleFixture(t *testing.T) *oracleFixture {
	t.Helper()
	ctx := context.Background()
	db, err := openSQLite(ctx, sqliteDriverName, filepath.Join(t.TempDir(), "oracle.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	mk := func(name string) tenant.ID {
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: name, FQDN: name + ".example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.NetworkRules().Replace(ctx, tn.ID, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{name + ".example.com"}); err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{"x@" + name + ".example.net", "shared@example.net"} {
			if _, err := db.Blocklist().Create(ctx, tn.ID, BlocklistEntry{Kind: BlockEmail, Value: v, Comment: "note of " + name}); err != nil {
				t.Fatal(err)
			}
		}
		return tn.ID
	}
	return &oracleFixture{db: db, a: mk("tenant-a"), b: mk("tenant-b")}
}

// fingerprint returns every row of tenant tid, in a stable textual form.
func (f *oracleFixture) fingerprint(ctx context.Context, tx *sql.Tx, tid tenant.ID) (string, error) {
	var parts []string
	for _, q := range []string{
		`SELECT tenant_id || '|' || kind || '|' || value FROM tenant_network_rules WHERE tenant_id = ? ORDER BY 1`,
		`SELECT id || '|' || tenant_id || '|' || kind || '|' || value || '|' || comment || '|' || created_by || '|' || created_at FROM blocklist_entries WHERE tenant_id = ? ORDER BY 1`,
		`SELECT id || '|' || name || '|' || fqdn || '|' || updated_at FROM tenants WHERE id = ?`,
	} {
		rows, err := tx.QueryContext(ctx, q, string(tid))
		if err != nil {
			return "", err
		}
		got, err := collect(rows, func(r *sql.Rows) (string, error) {
			var s string
			err := r.Scan(&s)
			return s, err
		})
		if err != nil {
			return "", err
		}
		parts = append(parts, got...)
	}
	return strings.Join(parts, "\n"), nil
}

// outcome is the observable result of a statement in tenant A's scope.
type outcome struct {
	failed bool
	rows   []string
	n      int64
	// fpA is tenant A's data after the statement: a write that depends on
	// tenant B's rows shows up here.
	fpA string
}

// run executes q in tenant A's scope with args. With deleteB, tenant B's
// rows are deleted first in the same transaction. The transaction is always
// rolled back. It also returns B's fingerprint after the statement.
func (f *oracleFixture) run(ctx context.Context, q TenantQuery, args []any, deleteB bool) (outcome, string, error) {
	var (
		out outcome
		fpB string
	)
	s, _ := f.db.Scoped(f.a)
	err := s.Tx(ctx, func(tx *ScopedTx) error {
		if deleteB {
			for _, del := range []string{`DELETE FROM blocklist_entries WHERE tenant_id = ?`, `DELETE FROM tenant_network_rules WHERE tenant_id = ?`} {
				if _, err := tx.tx.ExecContext(ctx, del, string(f.b)); err != nil {
					return err
				}
			}
		}
		if strings.EqualFold(strings.Fields(q.tenant.text)[0], "SELECT") {
			rows, err := tx.Query(ctx, q, args...)
			if err != nil {
				out.failed = true
			} else {
				cols, _ := rows.Columns()
				out.rows, err = collect(rows, func(r *sql.Rows) (string, error) {
					vals := make([]any, len(cols))
					ptrs := make([]any, len(cols))
					for i := range vals {
						ptrs[i] = &vals[i]
					}
					err := r.Scan(ptrs...)
					return fmt.Sprint(vals...), err
				})
				out.failed = err != nil
				slices.Sort(out.rows)
			}
		} else {
			res, err := tx.Exec(ctx, q, args...)
			out.failed = err != nil
			if err == nil {
				out.n, _ = res.RowsAffected()
			}
		}
		var err error
		if out.fpA, err = f.fingerprint(ctx, tx.tx, f.a); err != nil {
			return err
		}
		if fpB, err = f.fingerprint(ctx, tx.tx, f.b); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		return out, fpB, err
	}
	return out, fpB, nil
}

// errLeak reports an isolation failure found by the oracle.
var errLeak = errors.New("isolation leak")

// oracleCheck executes statement s (tenant slot slot, n placeholders) in
// tenant A's scope, with every argument set to tenant B's ID, once on the
// full fixture and once after deleting B's rows. It returns an error
// wrapping errLeak when B's rows are modified, or when the result or A's
// data after the statement differ between the two runs (B's rows were read).
func oracleCheck(t *testing.T, s string, slot, n int) error {
	t.Helper()
	fx := newOracleFixture(t)
	q := TenantQuery{tenant: &query{kind: kindTenant, text: s, numbered: rebindNumbered(s), slot: slot, placeholders: n}}
	args := make([]any, n-1)
	for i := range args {
		args[i] = string(fx.b)
	}
	ctx := context.Background()
	tx, err := fx.db.write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	before, err := fx.fingerprint(ctx, tx, fx.b)
	_ = tx.Rollback()
	if err != nil {
		return err
	}
	withB, fpAfter, err := fx.run(ctx, q, args, false)
	if err != nil {
		return err
	}
	if fpAfter != before {
		return fmt.Errorf("%w: %q modified tenant B's rows:\nbefore %s\nafter  %s", errLeak, s, before, fpAfter)
	}
	withoutB, _, err := fx.run(ctx, q, args, true)
	if err != nil {
		return err
	}
	if withB.failed != withoutB.failed || withB.n != withoutB.n || !slices.Equal(withB.rows, withoutB.rows) ||
		withB.fpA != withoutB.fpA {
		return fmt.Errorf("%w: %q depends on tenant B's rows:\nwith B    %+v\nwithout B %+v", errLeak, s, withB, withoutB)
	}
	return nil
}

// oracleSeeds are statements on the real tables, including known attacks.
var oracleSeeds = []string{
	"SELECT * FROM blocklist_entries WHERE tenant_id = ?",
	"SELECT count(*) FROM blocklist_entries x WHERE x.tenant_id = ? AND value LIKE ?",
	"SELECT value FROM blocklist_entries WHERE kind = 'email' AND tenant_id = ? ORDER BY id LIMIT 5",
	"UPDATE blocklist_entries SET comment = ? WHERE tenant_id = ?",
	"UPDATE tenant_network_rules SET value = ? WHERE tenant_id = ? AND kind = 'cidr'",
	"DELETE FROM blocklist_entries WHERE value = 'shared@example.net' AND tenant_id = ?",
	"DELETE FROM tenant_network_rules WHERE tenant_id = ?",
	"INSERT INTO tenant_network_rules (kind, value, tenant_id) VALUES ('cidr', ?, ?)",
	`UPDATE blocklist_entries SET "tenant_id" = ? WHERE tenant_id = ?`,
	"SELECT value FROM blocklist_entries WHERE value <> ?2 AND tenant_id = ?",
	"SELECT b.value FROM blocklist_entries a, blocklist_entries b WHERE a.tenant_id = ?",
	"SELECT count(*) FROM blocklist_entries WHERE tenant_id = ? AND (?, 'cidr', '10.0.0.0/8') IN tenant_network_rules",
	"UPDATE blocklist_entries SET comment = ((?, 'cidr', '10.0.0.0/8') IN tenant_network_rules) WHERE tenant_id = ?",
	"INSERT INTO blocklist_entries (id, tenant_id, kind, value, comment, created_at) VALUES ('blk_x', ?, 'email', 'z@example.net', ((?, 'cidr', '10.0.0.0/8') IN tenant_network_rules), 0)",
}

// FuzzTenantQueryIsolation is a differential oracle for the validator: any
// statement it accepts must pass oracleCheck.
func FuzzTenantQueryIsolation(f *testing.F) {
	for _, q := range registeredQueries() {
		if q.kind == kindTenant && !q.reviewed {
			f.Add(q.text)
		}
	}
	for _, s := range oracleSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		slot, n, err := validateTenantQuery(s, true)
		if err != nil {
			return
		}
		lower := strings.ToLower(s)
		for _, w := range nonDeterministic {
			if strings.Contains(lower, w) {
				return
			}
		}
		if err := oracleCheck(t, s, slot, n); err != nil {
			t.Fatal(err)
		}
	})
}

// TestOracleCatchesLeaks bypasses the single-table rule (reviewed mode) to
// show that the oracle flags the "expr IN table" leaks, read and write
// side, that the validator now rejects, and accepts a harmless statement.
func TestOracleCatchesLeaks(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"SELECT count(*) FROM blocklist_entries WHERE tenant_id = ? AND (?, 'cidr', '10.0.0.0/8') IN tenant_network_rules",
		"UPDATE blocklist_entries SET comment = ((?, 'cidr', '10.0.0.0/8') IN tenant_network_rules) WHERE tenant_id = ?",
		"INSERT INTO blocklist_entries (id, tenant_id, kind, value, comment, created_at) VALUES ('blk_x', ?, 'email', 'z@example.net', ((?, 'cidr', '10.0.0.0/8') IN tenant_network_rules), 0)",
	} {
		if _, _, err := validateTenantQuery(s, true); !errors.Is(err, errQuerySingleTable) {
			t.Errorf("validator accepts %q: %v", s, err)
		}
		slot, n, err := validateTenantQuery(s, false)
		if err != nil {
			t.Fatalf("bypass of %q: %v", s, err)
		}
		if err := oracleCheck(t, s, slot, n); !errors.Is(err, errLeak) {
			t.Errorf("oracle missed the leak of %q: %v", s, err)
		}
	}
	if err := oracleCheck(t, "UPDATE blocklist_entries SET comment = ? WHERE tenant_id = ?", 1, 2); err != nil {
		t.Errorf("oracle flags a harmless statement: %v", err)
	}
}

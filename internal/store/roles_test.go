package store

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
)

// pgIdentity tells the runtime connections (query_only=1) from the owner
// connections on SQLite, standing in for current_user / current_schema().
const pgIdentity = `SELECT CASE WHEN query_only THEN 'app' ELSE 'owner' END, 'main' FROM pragma_query_only`

// grantLog records the calls of a test grants function.
type grantLog struct {
	mu    sync.Mutex
	calls []string
}

// grants returns a grants function recording its arguments.
func (g *grantLog) grants(schema, role string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, schema+"/"+role)
	return []string{"SELECT 1", "SELECT 2"}
}

// pgLikeDialect returns a dialect behaving like PostgreSQL (owner
// migrations, role verification, scope statements) with SQL that SQLite
// understands, so that the PostgreSQL code paths run without a server.
func pgLikeDialect(g *grantLog) *dialect {
	if g == nil {
		g = &grantLog{}
	}
	d := *sqliteDialect // keeps the name: the SQLite migrations apply
	d.scopeTenant = "SELECT ?"
	d.scopeSystem = "SELECT 1"
	d.migrationLock = "SELECT 1"
	d.ownerMigrations = true
	d.identity = pgIdentity
	d.grants = g.grants
	d.verifyRole = "SELECT 0, 0"
	d.verifyOwnership = "SELECT 0"
	d.verifyMembership = "SELECT 0"
	d.verifyCreate = "SELECT 0"
	d.verifyTemp = "SELECT 0"
	d.verifyRLS = "SELECT name FROM sqlite_master WHERE 0"
	return &d
}

// openPGLike opens a SQLite database through the fault driver with a
// PostgreSQL-like dialect: the runtime pool is read-only (query_only), the
// owner DSN is the same file with an "owner=1" marker.
func openPGLike(ctx context.Context, t *testing.T, d *dialect) (*DB, *faultPlan, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pg.db")
	plan := &faultPlan{}
	faultPlans.Store(path, plan)
	t.Cleanup(func() { faultPlans.Delete(path) })
	db, err := openPostgres(ctx, faultDriverName, path+"?_query_only=1", config.NewSecret(path+"?owner=1"), d, nil)
	if err == nil {
		t.Cleanup(func() { _ = db.Close() })
	}
	return db, plan, err
}

func TestMigrateWithOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	g := &grantLog{}
	db, _, err := openPGLike(ctx, t, pgLikeDialect(g))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if n, err := db.Migrate(ctx); err != nil || n != len(mustMigrations(t, db)) {
		t.Fatalf("Migrate = %d, %v", n, err)
	}
	if n, err := db.Migrate(ctx); err != nil || n != 0 {
		t.Fatalf("second Migrate = %d, %v", n, err)
	}
	if strings.Join(g.calls, ",") != "main/app,main/app" {
		t.Errorf("grants calls = %v, want the runtime role on every Migrate", g.calls)
	}
	st, err := db.Status(ctx)
	if err != nil || st[0].State != MigrationApplied {
		t.Errorf("Status = %+v, %v", st, err)
	}
}

func TestMigrateWithOwnerFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name    string
		edit    func(d *dialect)
		fault   func(p *faultPlan)
		noOwner bool
		want    string
	}{
		{name: "no owner dsn", noOwner: true, want: "TT_DB_MIGRATE_DSN"},
		{name: "runtime identity", edit: func(d *dialect) { d.identity = "SELECT bogus(" }, want: "read role"},
		{name: "owner unreachable", fault: func(p *faultPlan) { p.add(faultOpen, "owner=1", 0) }, want: "migration role"},
		{name: "owner identity", fault: func(p *faultPlan) { p.add(faultQuery, "pragma_query_only", 1) }, want: "read role"},
		{name: "same role", edit: func(d *dialect) { d.identity = "SELECT 'app', 'main'" }, want: "same role"},
		{
			name: "owner without schema",
			edit: func(d *dialect) {
				d.identity = `SELECT CASE WHEN query_only THEN 'app' ELSE 'owner' END, CASE WHEN query_only THEN 'main' END FROM pragma_query_only`
			},
			want: "no usable schema",
		},
		{name: "migration fails", fault: func(p *faultPlan) { p.add(faultExec, "CREATE TABLE tenants", 0) }, want: "apply migration"},
		{name: "grant fails", edit: func(d *dialect) { d.grants = func(string, string) []string { return []string{"SELECT bogus("} } }, want: "grant runtime role"},
		{name: "final identity", fault: func(p *faultPlan) { p.add(faultQuery, "pragma_query_only", 2) }, want: "read role"},
		{
			name: "different schemas",
			edit: func(d *dialect) {
				d.identity = `SELECT CASE WHEN query_only THEN 'app' ELSE 'owner' END, CASE WHEN query_only THEN 'other' ELSE 'main' END FROM pragma_query_only`
			},
			want: "different schemas",
		},
		{
			name: "runtime role owns the tables",
			edit: func(d *dialect) { d.verifyOwnership = "SELECT count(*) FROM sqlite_master WHERE name = 'tenants'" },
			want: "owns 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := pgLikeDialect(nil)
			db, plan, err := openPGLike(ctx, t, d)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if tt.noOwner {
				db.DropMigrationCredentials()
			}
			if tt.edit != nil {
				tt.edit(d)
			}
			if tt.fault != nil {
				tt.fault(plan)
			}
			_, err = db.Migrate(ctx)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Migrate err = %v, want it to mention %q", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "owner=1") {
				t.Errorf("error leaks the DSN: %v", err)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name string
		edit func(d *dialect)
		want string
	}{
		{"superuser", func(d *dialect) { d.verifyRole = "SELECT 1, 0" }, "superuser or has BYPASSRLS"},
		{"bypassrls", func(d *dialect) { d.verifyRole = "SELECT 0, 1" }, "superuser or has BYPASSRLS"},
		{"owner", func(d *dialect) { d.verifyOwnership = "SELECT 3" }, "owns 3"},
		{"missing rls", func(d *dialect) { d.verifyRLS = "SELECT 'blocklist_entries' UNION ALL SELECT 'tenants'" }, "blocklist_entries, tenants"},
		{"role query", func(d *dialect) { d.verifyRole = "SELECT bogus(" }, "verify role attributes"},
		{"ownership query", func(d *dialect) { d.verifyOwnership = "SELECT bogus(" }, "verify ownership"},
		{"member of an unsafe role", func(d *dialect) { d.verifyMembership = "SELECT 2" }, "member of 2 role(s)"},
		{"membership query", func(d *dialect) { d.verifyMembership = "SELECT bogus(" }, "verify role membership"},
		{"may create", func(d *dialect) { d.verifyCreate = "SELECT 1" }, "has CREATE on the database or on a schema"},
		{"create query", func(d *dialect) { d.verifyCreate = "SELECT bogus(" }, "verify schema privileges"},
		{"temp query", func(d *dialect) { d.verifyTemp = "SELECT bogus(" }, "verify temporary privilege"},
		{"rls query", func(d *dialect) { d.verifyRLS = "SELECT bogus(" }, "verify row-level security"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := pgLikeDialect(nil)
			tt.edit(d)
			_, _, err := openPGLike(ctx, t, d)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("open err = %v, want it to mention %q", err, tt.want)
			}
			if !strings.Contains(tt.name, "query") && !errors.Is(err, ErrUnsafeDatabase) {
				t.Errorf("refusal %v does not wrap ErrUnsafeDatabase", err)
			}
		})
	}

	// A scan failure while listing the tables.
	d := pgLikeDialect(nil)
	db, plan, err := openPGLike(ctx, t, d)
	if err != nil {
		t.Fatal(err)
	}
	d.verifyRLS = "SELECT 'tenants'"
	plan.add(faultScanNil, "SELECT 'tenants'", 0)
	if err := db.Verify(ctx); err == nil || !strings.Contains(err.Error(), "verify row-level security") {
		t.Errorf("scan fault: %v", err)
	}

	// TEMP on the database is only a warning.
	var logs bytes.Buffer
	d = pgLikeDialect(nil)
	d.verifyTemp = "SELECT 1"
	tdb, _, err := openPGLike(ctx, t, d)
	if err != nil {
		t.Fatalf("open with TEMP: %v", err)
	}
	tdb.logger = slog.New(slog.NewTextHandler(&logs, nil))
	if err := tdb.Verify(ctx); err != nil || !strings.Contains(logs.String(), "temporary tables") {
		t.Errorf("Verify with TEMP = %v, logs %q", err, logs.String())
	}

	// SQLite has nothing to verify.
	lite, _ := openFault(t)
	if err := lite.Verify(ctx); err != nil {
		t.Errorf("Verify(sqlite) = %v", err)
	}
}

func TestPostgresGrants(t *testing.T) {
	t.Parallel()
	got := strings.Join(postgresGrants(`tt_"x`, "transteira_app"), ";\n")
	for _, want := range []string{
		`REVOKE ALL ON SCHEMA "tt_""x" FROM "transteira_app"`,
		`GRANT USAGE ON SCHEMA "tt_""x" TO "transteira_app"`,
		`REVOKE ALL ON ALL TABLES IN SCHEMA "tt_""x" FROM "transteira_app"`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "tt_""x" TO "transteira_app"`,
		`REVOKE INSERT, UPDATE, DELETE ON TABLE "tt_""x".schema_migrations FROM "transteira_app"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("grants miss %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{"TRUNCATE", "REFERENCES", "TRIGGER", "CREATE", "ALL PRIVILEGES"} {
		if strings.Contains(got, "GRANT "+forbidden) || strings.Contains(got, ", "+forbidden) {
			t.Errorf("grants must not give %s:\n%s", forbidden, got)
		}
	}
}

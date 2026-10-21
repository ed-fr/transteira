package store

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// openEngine opens the engine's database without migrating it.
func openEngine(t *testing.T, e storetest.Engine, opts ...Option) *DB {
	t.Helper()
	db, err := Open(context.Background(), e.Config(), opts...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestMigrateAndStatus(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		db := openEngine(t, e, WithClock(func() time.Time { return now }))
		known, err := db.migrations()
		if err != nil {
			t.Fatal(err)
		}

		st, err := db.Status(ctx)
		if err != nil {
			t.Fatalf("Status(fresh): %v", err)
		}
		if len(st) != len(known) || st[0].State != MigrationPending || !st[0].AppliedAt.IsZero() {
			t.Fatalf("Status(fresh) = %+v", st)
		}

		n, err := db.Migrate(ctx)
		if err != nil || n != len(known) {
			t.Fatalf("Migrate = %d, %v; want %d", n, err, len(known))
		}
		n, err = db.Migrate(ctx)
		if err != nil || n != 0 {
			t.Fatalf("second Migrate = %d, %v; want 0 (idempotent)", n, err)
		}
		st, err = db.Status(ctx)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		for i, s := range st {
			if s.State != MigrationApplied || s.Version != i+1 || s.Name != known[i].name || !s.AppliedAt.Equal(now) {
				t.Errorf("Status[%d] = %+v", i, s)
			}
		}

		// A modified migration is reported and blocks Migrate.
		if _, err := ownerExec(t, db, e, `UPDATE schema_migrations SET checksum = 'x' WHERE version = 1`); err != nil {
			t.Fatal(err)
		}
		st, _ = db.Status(ctx)
		if st[0].State != MigrationModified {
			t.Errorf("Status after tampering = %+v", st[0])
		}
		if _, err := db.Migrate(ctx); !errors.Is(err, ErrMigrationModified) {
			t.Errorf("Migrate(modified) err = %v", err)
		}
		if _, err := ownerExec(t, db, e, `UPDATE schema_migrations SET checksum = '`+known[0].checksum+`' WHERE version = 1`); err != nil {
			t.Fatal(err)
		}

		// A version unknown to the binary (newer database) blocks Migrate.
		if _, err := ownerExec(t, db, e, `INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (9999, 'future', 'c', 0)`); err != nil {
			t.Fatal(err)
		}
		st, err = db.Status(ctx)
		if err != nil {
			t.Fatalf("Status(newer db): %v", err)
		}
		last := st[len(st)-1]
		if last.State != MigrationUnknown || last.Version != 9999 || last.Name != "future" {
			t.Errorf("Status(newer db) last = %+v", last)
		}
		if _, err := db.Migrate(ctx); !errors.Is(err, ErrSchemaTooNew) {
			t.Errorf("Migrate(newer db) err = %v", err)
		}
	})
}

// ownerExec runs a raw statement as the role owning the schema: the owner
// role on PostgreSQL (the runtime role cannot modify schema_migrations), the
// write pool on SQLite.
func ownerExec(t *testing.T, db *DB, e storetest.Engine, q string) (sql.Result, error) {
	t.Helper()
	if e.MigrateDSN == "" {
		return db.write.ExecContext(context.Background(), q)
	}
	owner, err := sql.Open("pgx", e.MigrateDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	return owner.ExecContext(context.Background(), q)
}

func TestCheckApplied(t *testing.T) {
	t.Parallel()
	known := []migration{{version: 1, checksum: "a"}, {version: 2, checksum: "b"}}
	if err := checkApplied(known, []appliedMigration{{version: 1, checksum: "a"}}); err != nil {
		t.Errorf("prefix: %v", err)
	}
	if err := checkApplied(known, []appliedMigration{{version: 2, checksum: "b"}}); !errors.Is(err, ErrSchemaTooNew) {
		t.Errorf("gap: %v", err)
	}
	if err := checkApplied(known, []appliedMigration{{version: 1, checksum: "a"}, {version: 2, checksum: "b"}, {version: 3}}); !errors.Is(err, ErrSchemaTooNew) {
		t.Errorf("newer: %v", err)
	}
	if err := checkApplied(known, []appliedMigration{{version: 1, checksum: "z"}}); !errors.Is(err, ErrMigrationModified) {
		t.Errorf("modified: %v", err)
	}
}

func TestLoadMigrations(t *testing.T) {
	t.Parallel()
	good := fstest.MapFS{
		"m/0001_init.sql":      {Data: []byte("CREATE TABLE a (x INT);\r\n")},
		"m/0002_add_thing.sql": {Data: []byte("CREATE TABLE b (x INT);\n")},
	}
	ms, err := loadMigrations(good, "m")
	if err != nil || len(ms) != 2 || ms[1].name != "add_thing" || ms[0].body != "CREATE TABLE a (x INT);\n" {
		t.Fatalf("loadMigrations = %+v, %v", ms, err)
	}
	crlf, _ := loadMigrations(fstest.MapFS{"m/0001_init.sql": {Data: []byte("CREATE TABLE a (x INT);\n")}}, "m")
	if crlf[0].checksum != ms[0].checksum {
		t.Error("checksum must not depend on line endings")
	}
	bad := map[string]fstest.MapFS{
		"missing dir": {},
		"empty dir":   {"m": {Mode: fs.ModeDir}},
		"bad name":    {"m/init.sql": {}},
		"stray file":  {"m/0001_a.sql": {}, "m/README": {}},
		"gap":         {"m/0001_a.sql": {}, "m/0003_c.sql": {}},
		"starts at 2": {"m/0002_b.sql": {}},
		"directory":   {"m/0001_a.sql/x": {}},
	}
	for name, fsys := range bad {
		if _, err := loadMigrations(fsys, "m"); !errors.Is(err, errBadMigrations) {
			t.Errorf("%s: err = %v, want errBadMigrations", name, err)
		}
	}
}

// TestEmbeddedMigrationsMatch checks that both engines ship the same
// migrations (versions and names) and that each defines the same tables
// with the same columns.
func TestEmbeddedMigrationsMatch(t *testing.T) {
	t.Parallel()
	lite, err := loadMigrations(migrationFiles, "migrations/sqlite")
	if err != nil {
		t.Fatal(err)
	}
	pg, err := loadMigrations(migrationFiles, "migrations/postgres")
	if err != nil {
		t.Fatal(err)
	}
	if len(lite) != len(pg) {
		t.Fatalf("sqlite has %d migrations, postgres %d", len(lite), len(pg))
	}
	for i := range lite {
		if lite[i].version != pg[i].version || lite[i].name != pg[i].name {
			t.Errorf("migration %d: sqlite %04d_%s, postgres %04d_%s", i, lite[i].version, lite[i].name, pg[i].version, pg[i].name)
		}
		if a, b := schemaOf(lite[i].body), schemaOf(pg[i].body); !mapsEqual(a, b) {
			t.Errorf("migration %04d: sqlite schema %v, postgres schema %v", lite[i].version, a, b)
		}
	}
}

// createTable matches a CREATE TABLE statement and its body.
var createTable = regexp.MustCompile(`(?is)CREATE TABLE\s+(\w+)\s*\((.*?)\n\)`)

// rebuiltTable matches the temporary copy of a table rebuilt by a SQLite
// migration ("name_NNNN", NNNN the migration version): SQLite cannot alter a
// check in place, PostgreSQL alters the table instead. TestLiveSchemaMatches
// compares the resulting schemas.
var rebuiltTable = regexp.MustCompile(`_\d{4}$`)

// schemaOf extracts "table -> sorted columns" from migration SQL. Table
// constraints (PRIMARY KEY, UNIQUE, CHECK, FOREIGN KEY, CONSTRAINT) are not
// columns, and SQLite rebuild copies are skipped.
func schemaOf(body string) map[string]string {
	out := map[string]string{}
	for _, m := range createTable.FindAllStringSubmatch(body, -1) {
		if rebuiltTable.MatchString(m[1]) {
			continue
		}
		var cols []string
		for _, line := range strings.Split(m[2], "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || strings.HasPrefix(f[0], "--") {
				continue
			}
			switch strings.ToUpper(f[0]) {
			case "PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "CONSTRAINT":
				continue
			}
			cols = append(cols, f[0])
		}
		slices.Sort(cols)
		out[m[1]] = strings.Join(cols, ",")
	}
	return out
}

// mapsEqual compares two string maps.
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestLiveSchemaMatches compares the migrated schemas of the engines by
// introspection, and checks that every table holding a tenant_id column has
// an index whose first column is tenant_id. Without PostgreSQL it checks
// SQLite only.
func TestLiveSchemaMatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schemas := map[string]map[string]string{}
	for _, e := range storetest.Engines(t) {
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatalf("%s: Migrate: %v", e.Name, err)
		}
		cols, tenantIndexed := introspect(t, db, e)
		schemas[e.Name] = cols
		for table, c := range cols {
			if slices.Contains(strings.Split(c, ","), tenantColumn) && !tenantIndexed[table] {
				t.Errorf("%s: table %s has no index starting with tenant_id", e.Name, table)
			}
		}
		if len(cols) < 3 {
			t.Errorf("%s: introspection found %v", e.Name, cols)
		}
	}
	if pg, ok := schemas["postgres"]; ok && !mapsEqual(pg, schemas["sqlite"]) {
		t.Errorf("schemas differ:\nsqlite   %v\npostgres %v", schemas["sqlite"], pg)
	}
}

// introspect returns "table -> sorted columns" (schema_migrations
// excluded) and the tables having an index that starts with tenant_id.
func introspect(t *testing.T, db *DB, e storetest.Engine) (cols map[string]string, tenantIndexed map[string]bool) {
	t.Helper()
	ctx := context.Background()
	cols = map[string]string{}
	tenantIndexed = map[string]bool{}
	var colQuery, idxQuery string
	switch e.Driver {
	case "postgres":
		colQuery = `SELECT table_name, column_name FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name <> 'schema_migrations'
			ORDER BY table_name, column_name`
		idxQuery = `SELECT c.relname FROM pg_index i
			JOIN pg_class c ON c.oid = i.indrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = current_schema()
			JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0]
			WHERE a.attname = 'tenant_id'`
	default:
		colQuery = `SELECT m.name, p.name FROM sqlite_master m JOIN pragma_table_info(m.name) p
			WHERE m.type = 'table' AND m.name <> 'schema_migrations' ORDER BY m.name, p.name`
		idxQuery = `SELECT m.name FROM sqlite_master m JOIN pragma_index_list(m.name) il
			JOIN pragma_index_info(il.name) ii
			WHERE m.type = 'table' AND ii.seqno = 0 AND ii.name = 'tenant_id'`
	}
	// System scope: on PostgreSQL the catalog is not subject to RLS anyway.
	err := db.runTx(ctx, db.read, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, colQuery)
		if err != nil {
			return err
		}
		perTable := map[string][]string{}
		for rows.Next() {
			var tb, c string
			if err := rows.Scan(&tb, &c); err != nil {
				return err
			}
			perTable[tb] = append(perTable[tb], c)
		}
		_ = rows.Close()
		for tb, c := range perTable {
			slices.Sort(c)
			cols[tb] = strings.Join(c, ",")
		}
		rows, err = tx.QueryContext(ctx, idxQuery)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var tb string
			if err := rows.Scan(&tb); err != nil {
				return err
			}
			tenantIndexed[tb] = true
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("%s: introspection: %v", e.Name, err)
	}
	return cols, tenantIndexed
}

// mustMigrations returns the migrations embedded for db's engine.
func mustMigrations(t *testing.T, db *DB) []migration {
	t.Helper()
	known, err := db.migrations()
	if err != nil {
		t.Fatal(err)
	}
	return known
}

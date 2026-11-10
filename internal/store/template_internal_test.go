package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Under the race detector, migrating a new SQLite database (pure Go
// transpiled engine) costs seconds of CPU, and the package opens hundreds
// of them. Tests that only need an up-to-date schema copy a database
// migrated once per test binary instead (see CopyMigratedSQLite); the
// migrator itself keeps its dedicated tests on empty databases.

// templateDir holds the template databases of this test binary. TestMain
// removes it.
var (
	templateDirOnce sync.Once
	templateDir     string
	errTemplateDir  error
)

// templateRoot returns the directory of the template databases.
func templateRoot() (string, error) {
	templateDirOnce.Do(func() {
		templateDir, errTemplateDir = os.MkdirTemp("", "transteira-store-templates-")
	})
	return templateDir, errTemplateDir
}

// TestMain runs the tests, then removes the template databases.
func TestMain(m *testing.M) {
	code := m.Run()
	if templateDir != "" {
		_ = os.RemoveAll(templateDir)
	}
	os.Exit(code)
}

// sqliteTemplate is a SQLite database file built once per test binary.
type sqliteTemplate struct {
	once sync.Once
	path string
	err  error
}

// get builds the template on first use: build receives a migrated database
// and may add rows to it, then the database is compacted into a single
// file (VACUUM INTO: no WAL to copy along) named name.
func (s *sqliteTemplate) get(name string, build func(context.Context, *DB) error) (string, error) {
	s.once.Do(func() {
		s.path, s.err = buildSQLiteTemplate(name, build)
	})
	return s.path, s.err
}

// buildSQLiteTemplate migrates a new SQLite database, runs build on it and
// writes the result to the template file name.
func buildSQLiteTemplate(name string, build func(context.Context, *DB) error) (string, error) {
	root, err := templateRoot()
	if err != nil {
		return "", err
	}
	ctx := context.Background()
	work, err := os.MkdirTemp(root, "build-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(work) }()
	db, err := openSQLite(ctx, sqliteDriverName, filepath.Join(work, "build.db"), nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Migrate(ctx); err != nil {
		return "", err
	}
	if build != nil {
		if err := build(ctx, db); err != nil {
			return "", err
		}
	}
	path := filepath.Join(root, name)
	if _, err := db.write.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return "", fmt.Errorf("template %s: %w", name, err)
	}
	return path, nil
}

// copyTemplate copies the template file src to dst, which must not exist.
func copyTemplate(t testing.TB, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatalf("copying template: %v", err)
	}
}

// migratedSQLite is the template of an empty, fully migrated database.
var migratedSQLite sqliteTemplate

// CopyMigratedSQLite writes a fully migrated, empty SQLite database at
// path, which must not exist yet. A later Migrate on it applies nothing.
// It is exported for the external tests of the package.
func CopyMigratedSQLite(t testing.TB, path string) {
	t.Helper()
	src, err := migratedSQLite.get("migrated.db", nil)
	if err != nil {
		t.Fatalf("building the migrated SQLite template: %v", err)
	}
	copyTemplate(t, src, path)
}

// openMigratedEngine is openEngine on a database whose SQLite file starts
// as a migrated copy: a later Migrate applies nothing there (it still
// migrates PostgreSQL). Tests of the migrator use openEngine.
func openMigratedEngine(t *testing.T, e storetest.Engine, opts ...Option) *DB {
	t.Helper()
	if e.Driver == config.DriverSQLite {
		CopyMigratedSQLite(t, e.DSN)
	}
	return openEngine(t, e, opts...)
}

func TestCopyMigratedSQLite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "copy.db")
	CopyMigratedSQLite(t, path)
	db, err := openSQLite(ctx, sqliteDriverName, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if n, err := db.Migrate(ctx); err != nil || n != 0 {
		t.Fatalf("Migrate(copy) = %d, %v; want 0, nil", n, err)
	}
	st, err := db.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range st {
		if s.State != MigrationApplied {
			t.Errorf("migration %04d_%s is %s", s.Version, s.Name, s.State)
		}
	}
}

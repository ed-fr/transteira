package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// quickCheckFile opens the SQLite file path read-only and returns the
// answer of PRAGMA quick_check.
func quickCheckFile(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=query_only(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var res string
	if err := db.QueryRowContext(context.Background(), "PRAGMA quick_check").Scan(&res); err != nil {
		t.Fatalf("quick_check of %s: %v", path, err)
	}
	return res
}

// checkCopy fails unless path is a sound SQLite copy, private to its owner
// (the mode is not checked on Windows).
func checkCopy(t *testing.T, path string) {
	t.Helper()
	if res := quickCheckFile(t, path); res != "ok" {
		t.Fatalf("quick_check of %s = %q", path, res)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode of %s = %v, %v; want 0600", path, fi.Mode().Perm(), err)
		}
	}
}

// migratedEnv points the configuration at a new, migrated SQLite database
// and returns its path.
func migratedEnv(t *testing.T) string {
	t.Helper()
	dsn := setMigrateEnv(t)
	if code, _, errOut := runCmd("migrate"); code != exitOK {
		t.Fatalf("migrate = %d, %q", code, errOut)
	}
	return dsn
}

func TestBackupCommand(t *testing.T) {
	migratedEnv(t)
	backups := os.Getenv("TT_BACKUP_DIR")

	// Into TT_BACKUP_DIR, with the "-manual" marker.
	code, out, errOut := runCmd("backup")
	if code != exitOK || !strings.Contains(out, "Database copy written to "+backups) || !strings.Contains(out, " bytes).") {
		t.Fatalf("backup = %d, %q, %q", code, out, errOut)
	}
	matches, err := filepath.Glob(filepath.Join(backups, "transteira-*-manual.db"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("manual copies = %v, %v", matches, err)
	}
	if !strings.Contains(out, matches[0]) {
		t.Fatalf("printed path %q is not %s", out, matches[0])
	}
	checkCopy(t, matches[0])

	// At an explicit path, never overwritten.
	file := filepath.Join(t.TempDir(), "before-upgrade.db")
	code, out, errOut = runCmd("backup", "--out", file)
	if code != exitOK || !strings.Contains(out, file) {
		t.Fatalf("backup --out = %d, %q, %q", code, out, errOut)
	}
	checkCopy(t, file)
	before, _ := os.ReadFile(file)
	code, out, errOut = runCmd("backup", "--out", file)
	if code != exitError || out != "" || !strings.Contains(errOut, "already exists") {
		t.Fatalf("backup --out over an existing file = %d, %q, %q", code, out, errOut)
	}
	if after, _ := os.ReadFile(file); !bytes.Equal(before, after) {
		t.Fatal("the existing file was modified")
	}

	// A relative path is resolved against the working directory.
	t.Chdir(t.TempDir())
	if code, _, errOut := runCmd("backup", "-out", "relative.db"); code != exitOK {
		t.Fatalf("backup -out relative.db = %d, %q", code, errOut)
	}
	checkCopy(t, "relative.db")

	// A failing standard output.
	var stderr bytes.Buffer
	if code := run([]string{"backup", "-out", filepath.Join(t.TempDir(), "x.db")}, failWriter{}, &stderr); code != exitError {
		t.Fatalf("backup with a failing stdout = %d, %q", code, stderr.String())
	}
}

// TestBackupCommandWhileOpen: the copy is consistent, WAL content
// included, while another connection (the running server) holds the
// database open.
func TestBackupCommandWhileOpen(t *testing.T) {
	dsn := migratedEnv(t)
	live, err := sql.Open("sqlite", dsn+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Close() }()
	ctx := context.Background()
	for _, q := range []string{"CREATE TABLE probe (v INTEGER)", "INSERT INTO probe VALUES (42)"} {
		if _, err := live.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(t.TempDir(), "live.db")
	if code, _, errOut := runCmd("backup", "--out", file); code != exitOK {
		t.Fatalf("backup = %d, %q", code, errOut)
	}
	checkCopy(t, file)
	cp, err := sql.Open("sqlite", file+"?_pragma=query_only(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cp.Close() }()
	var v int
	if err := cp.QueryRowContext(ctx, "SELECT v FROM probe").Scan(&v); err != nil || v != 42 {
		t.Fatalf("row of the copy = %d, %v", v, err)
	}
}

func TestBackupCommandPostgres(t *testing.T) {
	setMigrateEnv(t)
	t.Setenv("TT_DB_DRIVER", "postgres")
	t.Setenv("TT_DB_DSN", "postgres://transteira@db.invalid/transteira")
	code, out, errOut := runCmd("backup")
	if code != exitUsage || out != "" || !strings.Contains(errOut, "PostgreSQL") ||
		!strings.Contains(errOut, "db-backup") || !strings.Contains(errOut, "docs/operations/backup.md") {
		t.Fatalf("backup on PostgreSQL = %d, %q, %q", code, out, errOut)
	}
}

func TestBackupCommandErrors(t *testing.T) {
	t.Run("configuration", func(t *testing.T) {
		setMigrateEnv(t)
		t.Setenv("TT_DB_DRIVER", "bogus")
		if code, _, errOut := runCmd("backup"); code != exitError || !strings.Contains(errOut, "TT_DB_DRIVER") {
			t.Fatalf("backup = %d, %q", code, errOut)
		}
	})
	t.Run("missing database", func(t *testing.T) {
		dsn := setMigrateEnv(t)
		code, _, errOut := runCmd("backup")
		if code != exitError || !strings.Contains(errOut, "does not exist") {
			t.Fatalf("backup = %d, %q", code, errOut)
		}
		if !fileMissing(dsn) {
			t.Fatal("the backup created the missing database")
		}
	})
	t.Run("open", func(t *testing.T) {
		dsn := setMigrateEnv(t)
		if err := os.Mkdir(dsn, 0o700); err != nil { // a directory, not a database
			t.Fatal(err)
		}
		if code, _, errOut := runCmd("backup"); code != exitError || !strings.Contains(errOut, "backup:") {
			t.Fatalf("backup = %d, %q", code, errOut)
		}
	})
	t.Run("stat", func(t *testing.T) {
		migratedEnv(t)
		t.Cleanup(func() { statFile = os.Stat })
		statFile = func(string) (os.FileInfo, error) { return nil, errors.New("stat failed") }
		if code, out, errOut := runCmd("backup"); code != exitError || out != "" || !strings.Contains(errOut, "backup: stat failed") {
			t.Fatalf("backup = %d, %q, %q", code, out, errOut)
		}
	})
	t.Run("output path", func(t *testing.T) {
		migratedEnv(t)
		t.Cleanup(func() { absPath = filepath.Abs })
		absPath = func(string) (string, error) { return "", errors.New("no working directory") }
		if code, out, errOut := runCmd("backup", "--out", "x.db"); code != exitError || out != "" ||
			!strings.Contains(errOut, "backup: no working directory") {
			t.Fatalf("backup = %d, %q, %q", code, out, errOut)
		}
	})
	t.Run("backup directory", func(t *testing.T) {
		migratedEnv(t)
		if err := os.WriteFile(os.Getenv("TT_BACKUP_DIR"), nil, 0o600); err != nil { // a file, not a directory
			t.Fatal(err)
		}
		if code, _, errOut := runCmd("backup"); code != exitError || !strings.Contains(errOut, "is not a directory") {
			t.Fatalf("backup = %d, %q", code, errOut)
		}
	})
}

func TestSQLitePath(t *testing.T) {
	t.Parallel()
	const want = "/var/lib/transteira/db/transteira.db"
	for _, dsn := range []string{want, "file:" + want + "?_pragma=busy_timeout(1)", want + "?mode=rw"} {
		if got := sqlitePath(dsn); got != want {
			t.Errorf("sqlitePath(%q) = %q, want %q", dsn, got, want)
		}
	}
}

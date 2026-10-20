package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setMigrateEnv points the configuration at a new SQLite database and
// returns its path. The master key path only has to lie outside the data
// volumes: the key is not read by migrate.
func setMigrateEnv(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dbDir := filepath.Join(root, "db")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dsn := filepath.Join(dbDir, "transteira.db")
	t.Setenv("TT_DB_DRIVER", "sqlite")
	t.Setenv("TT_DB_DSN", dsn)
	t.Setenv("TT_DB_DSN_FILE", "")
	t.Setenv("TT_MASTER_KEY_FILE", filepath.Join(root, "secrets", "master.key"))
	t.Setenv("TT_MASTER_KEY_NEW_FILE", "")
	t.Setenv("TT_DATA_DIR", filepath.Join(root, "data"))
	t.Setenv("TT_BACKUP_DIR", filepath.Join(root, "backups"))
	t.Setenv("TT_LOG_DIR", filepath.Join(root, "logs"))
	return dsn
}

// runCmd runs the binary entry point and returns its exit code and output.
func runCmd(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestMigrateCommand(t *testing.T) {
	dsn := setMigrateEnv(t)

	code, out, errOut := runCmd("migrate", "--status")
	if code != exitOK || !strings.Contains(out, "0001") || !strings.Contains(out, "pending") || strings.Contains(out, "Applied") {
		t.Fatalf("migrate --status (fresh) = %d, %q, %q", code, out, errOut)
	}
	code, out, errOut = runCmd("migrate")
	if code != exitOK || !strings.Contains(out, "Applied 1 migration(s) on sqlite") || !strings.Contains(out, "applied") {
		t.Fatalf("migrate = %d, %q, %q", code, out, errOut)
	}
	code, out, _ = runCmd("migrate")
	if code != exitOK || !strings.Contains(out, "Applied 0 migration(s)") {
		t.Fatalf("second migrate = %d, %q (must be idempotent)", code, out)
	}
	code, out, _ = runCmd("migrate", "--status")
	if code != exitOK || !strings.Contains(out, "init") || !strings.Contains(out, "applied") || strings.Contains(out, "Applied") {
		t.Fatalf("migrate --status = %d, %q", code, out)
	}
	var stderr bytes.Buffer
	if code := run([]string{"migrate", "--status"}, failWriter{}, &stderr); code != exitError {
		t.Errorf("migrate --status with a failing stdout = %d", code)
	}

	// A database migrated by a newer binary is refused, but its status can
	// still be printed.
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(context.Background(), `INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (9999, 'future', 'x', 0)`); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()
	code, _, errOut = runCmd("migrate")
	if code != exitError || !strings.Contains(errOut, "newer than this binary") {
		t.Errorf("migrate (newer db) = %d, %q", code, errOut)
	}
	code, out, _ = runCmd("migrate", "--status")
	if code != exitOK || !strings.Contains(out, "unknown") {
		t.Errorf("migrate --status (newer db) = %d, %q", code, out)
	}
}

func TestMigrateCommandErrors(t *testing.T) {
	setMigrateEnv(t)
	t.Setenv("TT_DB_DRIVER", "oracle")
	if code, _, errOut := runCmd("migrate"); code != exitError || !strings.Contains(errOut, "TT_DB_DRIVER") {
		t.Errorf("migrate with a bad config = %d, %q", code, errOut)
	}
	t.Setenv("TT_DB_DRIVER", "sqlite")
	t.Setenv("TT_DB_DSN", filepath.Join(t.TempDir(), "missing", "db.sqlite"))
	if code, _, errOut := runCmd("migrate"); code != exitError || !strings.Contains(errOut, "opening sqlite database") {
		t.Errorf("migrate with an unreachable database = %d, %q", code, errOut)
	}
}

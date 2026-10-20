package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckMasterKeyPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	c := &Config{
		DBDriver: DriverSQLite, DBDSN: NewSecret(filepath.Join(root, "db", "transteira.db")),
		DataDir: filepath.Join(root, "data"), BackupDir: filepath.Join(root, "backups"), LogDir: filepath.Join(root, "logs"),
	}
	keys := filepath.Join(root, "secrets", "old.key")
	if got, err := c.CheckMasterKeyPath(keys + string(filepath.Separator)); err != nil || got != keys {
		t.Errorf("CheckMasterKeyPath(outside) = %q, %v", got, err)
	}
	for _, tt := range []struct{ path, want string }{
		{"relative.key", "must be an absolute path"},
		{filepath.Join(c.DataDir, "old.key"), EnvDataDir},
		{filepath.Join(c.BackupDir, "x", "old.key"), EnvBackupDir},
		{filepath.Join(c.LogDir, "old.key"), EnvLogDir},
		{filepath.Join(root, "db", "old.key"), "the folder of " + EnvDBDSN},
	} {
		if _, err := c.CheckMasterKeyPath(tt.path); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("CheckMasterKeyPath(%s) = %v, want an error naming %q", tt.path, err, tt.want)
		}
	}
}

//go:build !windows

package lifecycle

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSyncDirErrors: a missing directory is an error, while a file system
// that cannot sync a directory (EINVAL, as procfs answers) is not.
func TestSyncDirErrors(t *testing.T) {
	t.Parallel()
	if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("syncDir of a missing directory succeeded")
	}
	if _, err := os.Stat("/proc/self"); err != nil {
		t.Skip("no procfs to return EINVAL on fsync:", err)
	}
	if err := syncDir("/proc"); err != nil {
		t.Fatalf("syncDir on procfs = %v, want nil (EINVAL ignored)", err)
	}
}

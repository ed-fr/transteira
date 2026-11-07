package upload

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/cli/client"
)

// TestCutsWithProgress completes an upload whose PATCH requests each store
// some bytes then drop, more times in a row than the attempt limit: only
// failures without progress count.
func TestCutsWithProgress(t *testing.T) {
	dir := t.TempDir()
	cuts := 3 * client.DefaultMaxAttempts / 2
	data := pattern(cuts*1000+5000, 9)
	writeFile(t, filepath.Join(dir, "f.bin"), data)
	fs := newFakeServer(t)
	n := 0
	fs.cut = func(*fakeUpload, int64) int64 {
		if n < cuts {
			n++
			return 1000
		}
		return -1
	}
	res, err := Run(context.Background(), fs.client(t, testToken, nil), baseOptions(t, filepath.Join(dir, "f.bin")))
	if err != nil {
		t.Fatal(err)
	}
	up := fs.only().uploads[0]
	if n != cuts || !bytes.Equal(up.data.Bytes(), data) || res.Files[0].SHA256 != sum(data) {
		t.Fatalf("cuts %d, content differs", n)
	}
}

// TestStateFileRefused refuses a state file that is not a regular file.
func TestStateFileRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadState(filepath.Join(dir, "missing.json")); err != nil {
		t.Fatalf("missing: %v", err)
	}
	if _, err := loadState(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: %v", err)
	}
	notDir := filepath.Join(dir, "file")
	writeFile(t, notDir, []byte("x"))
	if _, err := loadState(filepath.Join(notDir, "state.json")); err == nil {
		t.Fatal("path under a file accepted")
	}
	if runtime.GOOS == "windows" {
		return // symbolic links need a privilege
	}
	real := filepath.Join(dir, "real.json")
	writeFile(t, real, []byte("{}"))
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink: %v", err)
	}
}

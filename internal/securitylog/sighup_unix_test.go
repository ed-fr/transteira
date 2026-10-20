//go:build unix

package securitylog

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestHandleSIGHUP simulates logrotate: rename the file, send SIGHUP, and
// check that the next lines go to a new file at the original path.
func TestHandleSIGHUP(t *testing.T) { //nolint:paralleltest // sends a process-wide signal
	dir := t.TempDir()
	path := filepath.Join(dir, "security.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	t.Cleanup(l.HandleSIGHUP(t.Context())) // runs before Close (LIFO)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("file not reopened after SIGHUP")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := l.Log(Event{Type: RateLimited, IP: netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(got), "ip=192.0.2.1 ") {
		t.Errorf("new file content %q, err %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != FileMode {
		t.Errorf("mode %v, err %v", info.Mode().Perm(), err)
	}
}

// TestOpenTightensExistingMode checks that Open removes the bits outside
// FileMode from an existing world-readable file.
func TestOpenTightensExistingMode(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "security.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil { // bypasses the umask
		t.Fatal(err)
	}
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != FileMode {
		t.Errorf("mode %v, err %v", info.Mode().Perm(), err)
	}
}

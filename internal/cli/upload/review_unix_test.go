//go:build unix

package upload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStateFilePrivate refuses a state file others can access or that
// belongs to another user.
func TestStateFilePrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	writeFile(t, path, []byte("{}"))
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := loadState(path); err == nil || !strings.Contains(err.Error(), "accessible to other users") {
			t.Fatalf("mode %o: %v", mode, err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// Another owner: simulated, since chown needs a privilege.
	old := getuid
	getuid = func() int { return old() + 1 }
	t.Cleanup(func() { getuid = old })
	if _, err := loadState(path); err == nil || !strings.Contains(err.Error(), "belongs to another user") {
		t.Fatalf("owner: %v", err)
	}
	getuid = old
	// A private state file of the user is read (and here found invalid).
	if _, err := loadState(path); err == nil || !strings.Contains(err.Error(), "is invalid") {
		t.Fatalf("private: %v", err)
	}
}

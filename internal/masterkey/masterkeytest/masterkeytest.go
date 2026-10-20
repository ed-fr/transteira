// Package masterkeytest provides master keys and master key files for
// tests: random ones, and deterministic ones derived from a label so that a
// test can look for the key bytes in its outputs. It is excluded from the
// coverage thresholds, like storetest.
package masterkeytest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
)

// Raw returns the deterministic key bytes of label.
func Raw(label string) [crypto.MasterKeySize]byte {
	return sha256.Sum256([]byte("transteira test master key " + label))
}

// Text returns the file content (standard base64, no newline) of the
// deterministic key of label.
func Text(label string) string {
	raw := Raw(label)
	return base64.StdEncoding.EncodeToString(raw[:])
}

// Key returns the deterministic master key of label, destroyed when the
// test ends.
func Key(t testing.TB, label string) *crypto.MasterKey {
	t.Helper()
	k, err := crypto.ParseMasterKey([]byte(Text(label)))
	if err != nil {
		t.Fatalf("masterkeytest: ParseMasterKey(%s): %v", label, err)
	}
	t.Cleanup(k.Destroy)
	return k
}

// WriteKeyFile writes a new random master key to dir/master.key and returns
// the path and the key ID. dir must lie outside the data volumes of the
// configuration under test (t.TempDir() does).
func WriteKeyFile(t testing.TB, dir string) (path, id string) {
	t.Helper()
	raw := make([]byte, crypto.MasterKeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("masterkeytest: random: %v", err)
	}
	return write(t, filepath.Join(dir, "master.key"), base64.StdEncoding.EncodeToString(raw))
}

// WriteLabeledKeyFile writes the deterministic key of label to
// dir/<label>.key and returns the path and the key ID.
func WriteLabeledKeyFile(t testing.TB, dir, label string) (path, id string) {
	t.Helper()
	return write(t, filepath.Join(dir, label+".key"), Text(label))
}

// write stores text (and a trailing newline, tolerated by the parser) at
// path and returns path and the key ID.
func write(t testing.TB, path, text string) (string, string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text+"\n"), 0o600); err != nil {
		t.Fatalf("masterkeytest: %v", err)
	}
	k, err := crypto.ParseMasterKey([]byte(text))
	if err != nil {
		t.Fatalf("masterkeytest: %v", err)
	}
	defer k.Destroy()
	return path, k.ID()
}

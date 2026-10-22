package storage

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRemoveTenantDir(t *testing.T) {
	s, dir := newTestStore(t)
	a, b := newTenant(), newTenant()
	name := NewName()
	writeFile(t, s, a, name, []byte("data"))
	if err := s.WriteCheckpoint(a, name, []byte("ck")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteState(a, NewName(), []byte("st")); err != nil {
		t.Fatal(err)
	}
	// Entries the package does not know (branding assets), and a subdirectory.
	adir := filepath.Join(dir, string(a))
	if err := os.WriteFile(filepath.Join(adir, "logo.png"), []byte("png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(adir, "sub", "deeper"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adir, "sub", "deeper", "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := NewName()
	writeFile(t, s, b, other, []byte("other"))

	for range 2 { // idempotent
		if err := s.RemoveTenantDir(a); err != nil {
			t.Fatalf("RemoveTenantDir: %v", err)
		}
	}
	if _, err := os.Lstat(adir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("tenant directory still present: %v", err)
	}
	if got := listDir(t, filepath.Join(dir, string(b))); !slices.Equal(got, []string{other + fileExt}) {
		t.Fatalf("other tenant touched: %v", got)
	}
	if err := s.RemoveTenantDir(newTenant()); err != nil {
		t.Fatalf("missing directory: %v", err)
	}
	if err := s.RemoveTenantDir("ten_bad"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid tenant: got %v", err)
	}
	if err := s.RemoveTenantDir("../x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("traversal: got %v", err)
	}
}

func TestRemoveTenantDirSymlink(t *testing.T) {
	s, dir := newTestStore(t)
	outside := t.TempDir()
	keep := filepath.Join(outside, "keep")
	if err := os.WriteFile(keep, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	tid := newTenant()
	if err := os.Symlink(outside, filepath.Join(dir, string(tid))); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if err := s.RemoveTenantDir(tid); err != nil {
		t.Fatalf("RemoveTenantDir: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, string(tid))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("link still present: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("link target touched: %v", err)
	}
}

func TestRemoveTenantDirFault(t *testing.T) {
	s, dir := newTestStore(t)
	saved := removeTree
	t.Cleanup(func() { removeTree = saved })
	removeTree = func(*os.Root, string) error {
		return &fs.PathError{Op: "remove", Path: filepath.Join(dir, "x"), Err: errFault}
	}
	err := s.RemoveTenantDir(newTenant())
	if !errors.Is(err, errFault) {
		t.Fatalf("got %v", err)
	}
	noLeak(t, err, dir)
}

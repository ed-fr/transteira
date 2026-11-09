package storage

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/ed-fr/transteira/internal/tenant"
)

func TestSecretFiles(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	if entries, err := s.ListSecretFiles(tid); err != nil || len(entries) != 0 {
		t.Fatalf("missing directory: %v, %v", entries, err)
	}
	name := NewName()
	f, err := s.CreateSecretFile(tid, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("old content"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	// A second creation truncates the leftover.
	f, err = s.CreateSecretFile(tid, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("new"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	r, size, err := s.OpenSecretFile(tid, name)
	if err != nil || size != 3 {
		t.Fatalf("OpenSecretFile = %d, %v", size, err)
	}
	b, _ := io.ReadAll(r)
	_ = r.Close()
	if string(b) != "new" {
		t.Fatalf("content = %q", b)
	}
	// Entries: the file, an unknown name, a subdirectory.
	sdir := filepath.Join(dir, string(tid), secretsDir)
	if err := os.WriteFile(filepath.Join(sdir, "junk"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(sdir, NewName()), 0o750); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ListSecretFiles(tid)
	if err != nil || len(entries) != 3 {
		t.Fatalf("ListSecretFiles = %v, %v", entries, err)
	}
	kinds := map[Kind]int{}
	for _, e := range entries {
		kinds[e.Kind]++
		if e.Kind == KindSecretFile && (e.Name != name || e.Size != 3) {
			t.Errorf("entry %+v", e)
		}
	}
	if kinds[KindSecretFile] != 1 || kinds[KindUnknown] != 2 {
		t.Errorf("kinds = %v", kinds)
	}
	// The tenant listing skips the secrets directory.
	if entries, err := s.List(tid); err != nil || len(entries) != 0 {
		t.Fatalf("List = %v, %v", entries, err)
	}
	if KindSecretFile.String() != "secret" {
		t.Errorf("String = %q", KindSecretFile.String())
	}
	if _, _, err := s.OpenSecretFile(tid, NewName()); !errors.Is(err, ErrNotFound) {
		t.Errorf("open missing: %v", err)
	}
	for _, c := range []struct {
		tid  tenant.ID
		name string
	}{{"bad", name}, {tid, "../x"}} {
		if _, err := s.CreateSecretFile(c.tid, c.name); !errors.Is(err, ErrInvalid) {
			t.Errorf("CreateSecretFile(%q, %q) = %v", c.tid, c.name, err)
		}
		if _, _, err := s.OpenSecretFile(c.tid, c.name); !errors.Is(err, ErrInvalid) {
			t.Errorf("OpenSecretFile(%q, %q) = %v", c.tid, c.name, err)
		}
	}
	if _, err := s.ListSecretFiles("bad"); !errors.Is(err, ErrInvalid) {
		t.Errorf("ListSecretFiles(bad) = %v", err)
	}
}

func TestSecretFilesNotADirectory(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	if err := os.MkdirAll(filepath.Join(dir, string(tid)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, string(tid), secretsDir), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListSecretFiles(tid); !errors.Is(err, ErrInvalid) {
		t.Fatalf("file as secrets directory: %v", err)
	}
	// The tenant listing reports the stray file as unknown.
	if entries, err := s.List(tid); err != nil || len(entries) != 1 || entries[0].Kind != KindUnknown {
		t.Fatalf("List = %v, %v", entries, err)
	}
	if _, err := s.CreateSecretFile(tid, NewName()); err == nil {
		t.Fatal("create under a file: no error")
	}
}

func TestSecretFilesFaults(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	f, err := s.CreateSecretFile(tid, name)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	sdir := filepath.Join(string(tid), secretsDir)
	pathErr := &fs.PathError{Op: "x", Path: filepath.Join(dir, "x"), Err: errFault}
	reset := func() {
		s.ops.lstat = s.root.Lstat
		s.ops.openFile = s.root.OpenFile
		s.ops.stat = (*os.File).Stat
		s.ops.readDir = readAllDir
		s.ops.mkdir = s.root.Mkdir
	}
	check := func(label string, want error) {
		t.Helper()
		_, err := s.ListSecretFiles(tid)
		if !errors.Is(err, want) {
			t.Fatalf("%s: got %v", label, err)
		}
		noLeak(t, err, dir)
		reset()
	}
	s.ops.lstat = func(string) (fs.FileInfo, error) { return nil, pathErr }
	check("lstat of the directory", errFault)
	s.ops.readDir = func(*os.File) ([]fs.DirEntry, error) { return nil, pathErr }
	check("readDir", errFault)
	s.ops.lstat = func(n string) (fs.FileInfo, error) {
		if n == sdir {
			return s.root.Lstat(n)
		}
		return nil, pathErr
	}
	check("entry lstat", errFault)
	// Directory removed between lstat and open; entry removed meanwhile.
	s.ops.openFile = func(string, int, fs.FileMode) (*os.File, error) { return nil, fs.ErrNotExist }
	if entries, err := s.ListSecretFiles(tid); err != nil || len(entries) != 0 {
		t.Fatalf("directory removed: %v, %v", entries, err)
	}
	reset()
	s.ops.lstat = func(n string) (fs.FileInfo, error) {
		if n == sdir {
			return s.root.Lstat(n)
		}
		return nil, fs.ErrNotExist
	}
	if entries, err := s.ListSecretFiles(tid); err != nil || len(entries) != 0 {
		t.Fatalf("entry removed: %v, %v", entries, err)
	}
	reset()

	// Creation failures: the tenant directory, the secrets directory, the
	// file.
	other := newTenant()
	s.ops.mkdir = func(string, fs.FileMode) error { return errFault }
	if _, err := s.CreateSecretFile(other, name); !errors.Is(err, errFault) {
		t.Errorf("tenant directory: %v", err)
	}
	s.ops.mkdir = func(n string, p fs.FileMode) error {
		if n == string(other) {
			return s.root.Mkdir(n, p)
		}
		return errFault
	}
	if _, err := s.CreateSecretFile(other, name); !errors.Is(err, errFault) {
		t.Errorf("secrets directory: %v", err)
	}
	reset()
	s.ops.openFile = func(string, int, fs.FileMode) (*os.File, error) { return nil, pathErr }
	if _, err := s.CreateSecretFile(tid, name); !errors.Is(err, errFault) {
		t.Errorf("open for writing: %v", err)
	}
	if _, _, err := s.OpenSecretFile(tid, name); !errors.Is(err, errFault) {
		t.Errorf("open for reading: %v", err)
	}
	reset()
}

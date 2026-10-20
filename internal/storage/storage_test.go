package storage

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

var errFault = errors.New("injected fault")

func newTenant() tenant.ID { return tenant.ID(id.New(id.Tenant)) }

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

// noLeak fails if err mentions the absolute data directory.
func noLeak(t *testing.T, err error, dir string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, p := range []string{dir, filepath.Dir(dir), filepath.ToSlash(dir)} {
		if strings.Contains(err.Error(), p) {
			t.Fatalf("error %q leaks path %q", err, p)
		}
	}
}

func writeFile(t *testing.T, s *Store, tid tenant.ID, name string, data []byte) {
	t.Helper()
	f, err := s.Create(tid, name)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestNew(t *testing.T) {
	if _, err := New("relative/dir"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative path: got %v", err)
	}

	base := t.TempDir()
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(file, "sub")); err == nil {
		t.Fatal("data directory under a regular file: expected an error")
	}

	// Existing directory is reused.
	s, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewOpenRootFailure(t *testing.T) {
	orig := openRoot
	t.Cleanup(func() { openRoot = orig })
	openRoot = func(string) (*os.Root, error) { return nil, errFault }
	if _, err := New(t.TempDir()); !errors.Is(err, errFault) {
		t.Fatalf("got %v", err)
	}
}

func TestNewName(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		n := NewName()
		if !ValidName(n) {
			t.Fatalf("NewName returned invalid name %q", n)
		}
		if seen[n] {
			t.Fatalf("duplicate name %q", n)
		}
		seen[n] = true
	}
}

func TestValidName(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef"
	if !ValidName(valid) {
		t.Fatal("valid name refused")
	}
	for _, n := range []string{
		"",
		valid[:31],
		valid + "0",
		"0123456789ABCDEF0123456789abcdef",
		"0123456789abcdeg0123456789abcdef",
		"../3456789abcdef0123456789abcdef",
		"/123456789abcdef0123456789abcdef",
		"0123456789abcdef0123456789abcde/",
		"0123456789abcdef\x00123456789abcdef",
		"0123456789abcdef0123456789abcd.f",
	} {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true", n)
		}
	}
}

func TestValidationBeforeFilesystem(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	badTenants := []tenant.ID{
		"",
		"..",
		"../" + tid,
		tenant.ID(dir),
		tenant.ID(strings.ToLower(string(tid))),
		tenant.ID(id.New(id.Prefix("ses"))),
		tid + "/x",
		"ten_",
	}
	badNames := []string{
		"",
		"..",
		"../" + name[3:],
		filepath.Join(dir, name),
		strings.ToUpper(name),
		name + ".ttef",
		name[:30],
	}
	calls := map[string]func(tenant.ID, string) error{
		"Create": func(t tenant.ID, n string) error {
			_, err := s.Create(t, n)
			return err
		},
		"OpenAppend": func(t tenant.ID, n string) error {
			_, _, err := s.OpenAppend(t, n)
			return err
		},
		"OpenRead": func(t tenant.ID, n string) error {
			_, _, err := s.OpenRead(t, n)
			return err
		},
		"Remove":           s.Remove,
		"RemoveCheckpoint": s.RemoveCheckpoint,
		"WriteCheckpoint": func(t tenant.ID, n string) error {
			return s.WriteCheckpoint(t, n, []byte("x"))
		},
		"ReadCheckpoint": func(t tenant.ID, n string) error {
			_, _, err := s.ReadCheckpoint(t, n)
			return err
		},
		"CheckpointModTime": func(t tenant.ID, n string) error {
			_, err := s.CheckpointModTime(t, n)
			return err
		},
		"SyncDir": func(t tenant.ID, _ string) error { return s.SyncDir(t) },
	}
	for op, call := range calls {
		for _, bt := range badTenants {
			if err := call(bt, name); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s(tenant %q): got %v", op, bt, err)
			}
		}
		if op == "SyncDir" {
			continue
		}
		for _, bn := range badNames {
			err := call(tid, bn)
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%s(name %q): got %v", op, bn, err)
			}
			noLeak(t, err, dir)
		}
	}
	if got := listDir(t, dir); len(got) != 0 {
		t.Fatalf("file system touched: %v", got)
	}
}

func TestCreateAndOpen(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()

	writeFile(t, s, tid, name, []byte("hello"))
	if _, err := os.Stat(filepath.Join(dir, string(tid), name+".ttef")); err != nil {
		t.Fatalf("expected layout <dataDir>/<tenant>/<name>.ttef: %v", err)
	}

	_, err := s.Create(tid, name)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second Create: got %v", err)
	}
	noLeak(t, err, dir)

	// OpenAppend returns the current size and writes at the end.
	f, size, err := s.OpenAppend(tid, name)
	if err != nil {
		t.Fatal(err)
	}
	if size != 5 {
		t.Fatalf("size = %d, want 5", size)
	}
	if _, err := f.Write([]byte(" world")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	r, size, err := s.OpenRead(tid, name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if size != 11 {
		t.Fatalf("size = %d, want 11", size)
	}
	var ra io.ReaderAt = r
	buf := make([]byte, 5)
	if _, err := ra.ReadAt(buf, 6); err != nil || string(buf) != "world" {
		t.Fatalf("ReadAt = %q, %v", buf, err)
	}
	var rsc io.ReadSeekCloser = r
	all, err := io.ReadAll(rsc)
	if err != nil || string(all) != "hello world" {
		t.Fatalf("ReadAll = %q, %v", all, err)
	}

	// Another tenant does not see the file.
	if _, _, err := s.OpenRead(newTenant(), name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other tenant: got %v", err)
	}
}

func TestOpenMissing(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	_, _, err := s.OpenRead(tid, NewName())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenRead: got %v", err)
	}
	noLeak(t, err, dir)
	if _, _, err := s.OpenAppend(tid, NewName()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenAppend: got %v", err)
	}
}

func TestOpenNotRegular(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	if err := os.MkdirAll(filepath.Join(dir, string(tid), name+".ttef"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, string(tid), name+".ckpt"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.OpenRead(tid, name); !errors.Is(err, ErrInvalid) {
		t.Fatalf("OpenRead on a directory: got %v", err)
	}
	if _, _, err := s.ReadCheckpoint(tid, name); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ReadCheckpoint on a directory: got %v", err)
	}
}

func TestOpenFaults(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	writeFile(t, s, tid, name, []byte("abc"))

	s.ops.stat = func(*os.File) (fs.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: filepath.Join(dir, "x"), Err: errFault}
	}
	_, _, err := s.OpenRead(tid, name)
	if !errors.Is(err, errFault) {
		t.Fatalf("stat fault: got %v", err)
	}
	noLeak(t, err, dir)

	s.ops.stat = (*os.File).Stat
	s.ops.seek = func(*os.File, int64, int) (int64, error) { return 0, errFault }
	if _, _, err := s.OpenAppend(tid, name); !errors.Is(err, errFault) {
		t.Fatalf("seek fault: got %v", err)
	}
}

func TestCreateFaults(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()

	s.ops.mkdir = func(string, fs.FileMode) error { return errFault }
	_, err := s.Create(tid, NewName())
	if !errors.Is(err, errFault) {
		t.Fatalf("mkdir fault: got %v", err)
	}
	noLeak(t, err, dir)
	if err := s.WriteCheckpoint(tid, NewName(), nil); !errors.Is(err, errFault) {
		t.Fatalf("WriteCheckpoint mkdir fault: got %v", err)
	}

	// A tenant path that exists as a regular file: mkdir reports it as
	// existing, the open then fails.
	s.ops.mkdir = s.root.Mkdir
	if err := os.WriteFile(filepath.Join(dir, string(tid)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(tid, NewName()); err == nil {
		t.Fatal("tenant path is a file: expected an error")
	}
}

func TestModesHook(t *testing.T) {
	s, _ := newTestStore(t)
	var dirPerm, filePerm []fs.FileMode
	mkdir, openFile := s.ops.mkdir, s.ops.openFile
	s.ops.mkdir = func(n string, p fs.FileMode) error {
		dirPerm = append(dirPerm, p)
		return mkdir(n, p)
	}
	s.ops.openFile = func(n string, flag int, p fs.FileMode) (*os.File, error) {
		if flag&os.O_CREATE != 0 {
			filePerm = append(filePerm, p)
		}
		return openFile(n, flag, p)
	}
	tid := newTenant()
	name := NewName()
	writeFile(t, s, tid, name, nil)
	if err := s.WriteCheckpoint(tid, name, []byte("c")); err != nil {
		t.Fatal(err)
	}
	for _, p := range dirPerm {
		if p != 0o750 {
			t.Errorf("directory mode %o, want 0750", p)
		}
	}
	if len(filePerm) != 2 {
		t.Fatalf("expected two file creations, got %d", len(filePerm))
	}
	for _, p := range filePerm {
		if p != 0o640 {
			t.Errorf("file mode %o, want 0640", p)
		}
	}
}

func TestModesUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not meaningful on Windows")
	}
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	writeFile(t, s, tid, name, nil)
	if err := s.WriteCheckpoint(tid, name, []byte("c")); err != nil {
		t.Fatal(err)
	}
	check := func(p string, want fs.FileMode) {
		t.Helper()
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		// The umask may only remove bits.
		if got := info.Mode().Perm(); got&^want != 0 {
			t.Errorf("%s: mode %o is wider than %o", filepath.Base(p), got, want)
		}
	}
	check(dir, 0o750)
	check(filepath.Join(dir, string(tid)), 0o750)
	check(filepath.Join(dir, string(tid), name+".ttef"), 0o640)
	check(filepath.Join(dir, string(tid), name+".ckpt"), 0o640)
}

func TestRemove(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	writeFile(t, s, tid, name, []byte("data"))
	if err := s.WriteCheckpoint(tid, name, []byte("ckpt")); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := s.Remove(tid, name); err != nil {
			t.Fatalf("Remove #%d: %v", i, err)
		}
	}
	if got := listDir(t, filepath.Join(dir, string(tid))); len(got) != 0 {
		t.Fatalf("leftovers: %v", got)
	}
	// Missing tenant directory is fine as well.
	if err := s.Remove(newTenant(), NewName()); err != nil {
		t.Fatal(err)
	}

	s.ops.remove = func(n string) error {
		return &fs.PathError{Op: "remove", Path: filepath.Join(dir, n), Err: errFault}
	}
	err := s.Remove(tid, name)
	if !errors.Is(err, errFault) {
		t.Fatalf("remove fault: got %v", err)
	}
	noLeak(t, err, dir)
	if err := s.RemoveCheckpoint(tid, name); !errors.Is(err, errFault) {
		t.Fatalf("RemoveCheckpoint fault: got %v", err)
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()

	_, _, err := s.ReadCheckpoint(tid, name)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing checkpoint: got %v", err)
	}
	noLeak(t, err, dir)

	before := time.Now().Add(-time.Minute)
	if err := s.WriteCheckpoint(tid, name, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteCheckpoint(tid, name, []byte("second")); err != nil {
		t.Fatal(err)
	}
	data, mod, err := s.ReadCheckpoint(tid, name)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Fatalf("data = %q", data)
	}
	if mod.Before(before) || mod.After(time.Now().Add(time.Minute)) {
		t.Fatalf("modTime %v out of range", mod)
	}
	if _, err := os.Stat(filepath.Join(dir, string(tid), name+".ckpt")); err != nil {
		t.Fatalf("expected <name>.ckpt: %v", err)
	}

	// Maximum size accepted, one more byte refused.
	maxData := bytes.Repeat([]byte{1}, MaxCheckpointSize)
	if err := s.WriteCheckpoint(tid, name, maxData); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteCheckpoint(tid, name, append(maxData, 1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized write: got %v", err)
	}

	for range 2 {
		if err := s.RemoveCheckpoint(tid, name); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.ReadCheckpoint(tid, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after RemoveCheckpoint: got %v", err)
	}
}

func TestReadCheckpointBounds(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	if err := os.MkdirAll(filepath.Join(dir, string(tid)), 0o750); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte{1}, MaxCheckpointSize+1)
	if err := os.WriteFile(filepath.Join(dir, string(tid), name+".ckpt"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadCheckpoint(tid, name); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized checkpoint: got %v", err)
	}

	s.ops.readAll = func(io.Reader) ([]byte, error) { return nil, errFault }
	if _, _, err := s.ReadCheckpoint(tid, name); !errors.Is(err, errFault) {
		t.Fatalf("read fault: got %v", err)
	}
}

// TestCheckpointAtomic simulates a crash at each step before the rename:
// the previous checkpoint must stay intact and no temporary file remain.
func TestCheckpointAtomic(t *testing.T) {
	faults := map[string]func(*Store, string){
		"open": func(s *Store, _ string) {
			s.ops.openFile = func(string, int, fs.FileMode) (*os.File, error) { return nil, errFault }
		},
		"write": func(s *Store, _ string) {
			s.ops.write = func(f *os.File, b []byte) (int, error) {
				_, _ = f.Write(b[:1]) // partial write
				return 1, errFault
			}
		},
		"sync": func(s *Store, _ string) {
			s.ops.sync = func(*os.File) error { return errFault }
		},
		"close": func(s *Store, _ string) {
			s.ops.close = func(f *os.File) error {
				_ = f.Close()
				return errFault
			}
		},
		"rename": func(s *Store, dir string) {
			s.ops.rename = func(o, n string) error {
				return &os.LinkError{Op: "rename", Old: filepath.Join(dir, o), New: filepath.Join(dir, n), Err: errFault}
			}
		},
	}
	for step, inject := range faults {
		t.Run(step, func(t *testing.T) {
			s, dir := newTestStore(t)
			tid := newTenant()
			name := NewName()
			if err := s.WriteCheckpoint(tid, name, []byte("old")); err != nil {
				t.Fatal(err)
			}
			inject(s, dir)
			err := s.WriteCheckpoint(tid, name, []byte("new checkpoint"))
			if !errors.Is(err, errFault) {
				t.Fatalf("got %v", err)
			}
			noLeak(t, err, dir)

			got, err := os.ReadFile(filepath.Join(dir, string(tid), name+".ckpt"))
			if err != nil || string(got) != "old" {
				t.Fatalf("previous checkpoint = %q, %v", got, err)
			}
			for _, n := range listDir(t, filepath.Join(dir, string(tid))) {
				if strings.HasSuffix(n, ".tmp") {
					t.Fatalf("temporary file left: %s", n)
				}
			}
		})
	}
}

func TestSync(t *testing.T) {
	s, dir := newTestStore(t)
	f, err := s.Create(newTenant(), NewName())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := s.Sync(f); err != nil {
		t.Fatal(err)
	}
	s.ops.sync = func(*os.File) error {
		return &fs.PathError{Op: "sync", Path: filepath.Join(dir, "f"), Err: errFault}
	}
	err = s.Sync(f)
	if !errors.Is(err, errFault) {
		t.Fatalf("got %v", err)
	}
	noLeak(t, err, dir)
}

func TestSyncDir(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	if err := s.ensureTenantDir(tid); err != nil {
		t.Fatal(err)
	}

	if s.dirSync != (runtime.GOOS != "windows") {
		t.Fatalf("dirSync = %v on %s", s.dirSync, runtime.GOOS)
	}
	// Real behavior of the current platform.
	if err := s.SyncDir(tid); err != nil {
		t.Fatalf("SyncDir: %v", err)
	}

	s.dirSync = false
	s.ops.openFile = func(string, int, fs.FileMode) (*os.File, error) { return nil, errFault }
	if err := s.SyncDir(tid); err != nil {
		t.Fatalf("unsupported platform must be a no-op, got %v", err)
	}

	s.dirSync = true
	err := s.SyncDir(tid)
	if !errors.Is(err, errFault) {
		t.Fatalf("open fault: got %v", err)
	}
	noLeak(t, err, dir)

	s.ops.openFile = s.root.OpenFile
	syncErr := error(nil)
	s.ops.sync = func(*os.File) error { return syncErr }
	if err := s.SyncDir(tid); err != nil {
		t.Fatalf("sync ok: got %v", err)
	}
	syncErr = &fs.PathError{Op: "sync", Path: dir, Err: syscall.EINVAL}
	if err := s.SyncDir(tid); err != nil {
		t.Fatalf("EINVAL must be ignored, got %v", err)
	}
	syncErr = errFault
	if err := s.SyncDir(tid); !errors.Is(err, errFault) {
		t.Fatalf("sync fault: got %v", err)
	}
	// WriteCheckpoint reports a directory sync failure.
	if err := s.WriteCheckpoint(tid, NewName(), nil); err == nil {
		t.Fatal("WriteCheckpoint: expected the sync error")
	}
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable (Windows needs Developer Mode or privileges): %v", err)
	}
}

// TestSymlinkEscape checks that symbolic links leading outside the data
// directory are never followed (os.Root guarantee).
func TestSymlinkEscape(t *testing.T) {
	s, dir := newTestStore(t)
	outside := filepath.Join(filepath.Dir(dir), "outside")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}

	// Tenant directory replaced by a link to the outside.
	tid := newTenant()
	symlinkOrSkip(t, outside, filepath.Join(dir, string(tid)))
	if _, err := s.Create(tid, NewName()); err == nil {
		t.Fatal("Create through an escaping tenant link succeeded")
	}
	if err := s.WriteCheckpoint(tid, NewName(), []byte("x")); err == nil {
		t.Fatal("WriteCheckpoint through an escaping tenant link succeeded")
	}
	if got := listDir(t, outside); len(got) != 0 {
		t.Fatalf("files written outside the data directory: %v", got)
	}

	// Stored file replaced by a link to an outside file.
	tid2 := newTenant()
	name := NewName()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, string(tid2)), 0o750); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, secret, filepath.Join(dir, string(tid2), name+".ttef"))
	symlinkOrSkip(t, secret, filepath.Join(dir, string(tid2), name+".ckpt"))
	_, _, err := s.OpenRead(tid2, name)
	if err == nil {
		t.Fatal("OpenRead through an escaping link succeeded")
	}
	noLeak(t, err, dir)
	if _, _, err := s.OpenAppend(tid2, name); err == nil {
		t.Fatal("OpenAppend through an escaping link succeeded")
	}
	if _, _, err := s.ReadCheckpoint(tid2, name); err == nil {
		t.Fatal("ReadCheckpoint through an escaping link succeeded")
	}
}

func TestWrapUnwrapsPaths(t *testing.T) {
	err := wrap("op", "n", &fs.PathError{Op: "open", Path: "/secret/path", Err: errFault})
	if err.Error() != "storage: op n: injected fault" || !errors.Is(err, errFault) {
		t.Fatalf("PathError: %q", err)
	}
	err = wrap("op", "", &os.LinkError{Op: "rename", Old: "/a", New: "/b", Err: errFault})
	if err.Error() != "storage: op: injected fault" {
		t.Fatalf("LinkError: %q", err)
	}
	err = wrap("op", "n", &fs.PathError{Op: "open", Path: "/secret", Err: fs.ErrNotExist})
	if err.Error() != "storage: op n: "+ErrNotFound.Error() || !errors.Is(err, ErrNotFound) {
		t.Fatalf("not exist: %q", err)
	}
}

func TestCheckpointModTime(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	_, err := s.CheckpointModTime(tid, name)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing checkpoint: %v", err)
	}
	noLeak(t, err, dir)
	if err := s.WriteCheckpoint(tid, name, []byte("state")); err != nil {
		t.Fatal(err)
	}
	_, want, err := s.ReadCheckpoint(tid, name)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.CheckpointModTime(tid, name)
	if err != nil || !got.Equal(want) {
		t.Fatalf("CheckpointModTime = %v, %v, want %v", got, err, want)
	}
	// A directory in place of the checkpoint is refused.
	other := NewName()
	if err := os.Mkdir(filepath.Join(dir, string(tid), other+".ckpt"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckpointModTime(tid, other); !errors.Is(err, ErrInvalid) {
		t.Fatalf("directory checkpoint: %v", err)
	}
	// Other stat errors are wrapped without the path.
	s.ops.statPath = func(n string) (fs.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: filepath.Join(dir, n), Err: errFault}
	}
	_, err = s.CheckpointModTime(tid, name)
	if !errors.Is(err, errFault) {
		t.Fatalf("stat fault: %v", err)
	}
	noLeak(t, err, dir)
}

func TestRenameRetriesFor(t *testing.T) {
	if renameRetriesFor("windows") != windowsRenameRetries || renameRetriesFor("linux") != 0 {
		t.Fatal("unexpected retry policy")
	}
	s, _ := newTestStore(t)
	if s.renameRetries != renameRetriesFor(runtime.GOOS) {
		t.Fatalf("renameRetries = %d on %s", s.renameRetries, runtime.GOOS)
	}
}

// TestCheckpointRenameRetry covers the Windows retry of a rename refused
// because a reader holds the checkpoint, through the ops hooks.
func TestCheckpointRenameRetry(t *testing.T) {
	cases := []struct {
		name     string
		failures int   // refused attempts before the real rename
		err      error // error of a refused attempt
		retries  int
		wantErr  bool
		attempts int
	}{
		{name: "sharing violation then success", failures: 2, err: errSharingViolation, retries: 5, attempts: 3},
		{name: "access denied then success", failures: 5, err: &os.LinkError{Op: "rename", Err: errAccessDenied}, retries: 5, attempts: 6},
		{name: "still held after the retries", failures: 100, err: errSharingViolation, retries: 5, wantErr: true, attempts: 6},
		{name: "other error is not retried", failures: 100, err: errFault, retries: 5, wantErr: true, attempts: 1},
		{name: "no retry outside Windows", failures: 100, err: errSharingViolation, retries: 0, wantErr: true, attempts: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, dir := newTestStore(t)
			s.renameRetries = c.retries
			tid := newTenant()
			name := NewName()
			if err := s.WriteCheckpoint(tid, name, []byte("old")); err != nil {
				t.Fatal(err)
			}
			attempts, sleeps := 0, 0
			s.ops.sleep = func(d time.Duration) {
				if d != renameBackoff {
					t.Errorf("backoff = %v", d)
				}
				sleeps++
			}
			s.ops.rename = func(o, n string) error {
				attempts++
				if attempts <= c.failures {
					return c.err
				}
				return s.root.Rename(o, n)
			}
			err := s.WriteCheckpoint(tid, name, []byte("new"))
			if (err != nil) != c.wantErr {
				t.Fatalf("WriteCheckpoint = %v", err)
			}
			if attempts != c.attempts || sleeps != attempts-1 {
				t.Fatalf("attempts = %d, sleeps = %d, want %d attempts", attempts, sleeps, c.attempts)
			}
			want := "new"
			if c.wantErr {
				want = "old"
			}
			if got, _, _ := s.ReadCheckpoint(tid, name); string(got) != want {
				t.Fatalf("checkpoint = %q, want %q", got, want)
			}
			for _, n := range listDir(t, filepath.Join(dir, string(tid))) {
				if strings.HasSuffix(n, ".tmp") {
					t.Fatalf("temporary file left: %s", n)
				}
			}
		})
	}
}

// TestCheckpointReplacedWhileOpen replaces a checkpoint that another handle
// holds open: on Windows the rename is refused while the handle is open
// and retried. The handle is closed from the backoff hook, on the first
// retry, so the test does not depend on timing. Elsewhere the rename never
// fails on an open target, so the test only runs on Windows.
func TestCheckpointReplacedWhileOpen(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("an open target blocks a rename on Windows only")
	}
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	if err := s.WriteCheckpoint(tid, name, []byte("old")); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, string(tid), name+".ckpt"))
	if err != nil {
		t.Fatal(err)
	}
	retries := 0
	s.ops.sleep = func(time.Duration) {
		if retries++; retries == 1 {
			_ = f.Close()
		}
	}
	if err := s.WriteCheckpoint(tid, name, []byte("new")); err != nil {
		t.Fatalf("WriteCheckpoint while open: %v", err)
	}
	if retries != 1 {
		t.Fatalf("retries = %d, want 1", retries)
	}
	if got, _, _ := s.ReadCheckpoint(tid, name); string(got) != "new" {
		t.Fatalf("checkpoint = %q", got)
	}
}

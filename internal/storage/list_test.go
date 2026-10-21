package storage

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// tempName returns a temporary file name as writeAtomic produces it.
func tempName(name, ext string) string {
	return name + ext + ".0123456789abcdef" + tmpExt
}

func entriesByFile(t *testing.T, entries []Entry) map[string]Entry {
	t.Helper()
	m := make(map[string]Entry, len(entries))
	for _, e := range entries {
		m[e.File] = e
	}
	return m
}

func TestKindString(t *testing.T) {
	for k, want := range map[Kind]string{
		KindUnknown: "unknown", KindData: "data", KindCheckpoint: "checkpoint",
		KindState: "state", KindTemp: "temp", Kind(42): "unknown",
	} {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", k, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	n := "0123456789abcdef0123456789abcdef"
	cases := []struct {
		file, name string
		kind       Kind
	}{
		{n + ".ttef", n, KindData},
		{n + ".ckpt", n, KindCheckpoint},
		{n + ".dlstate", n, KindState},
		{tempName(n, ".ckpt"), n, KindTemp},
		{tempName(n, ".dlstate"), n, KindTemp},
		{n, n, KindUnknown},
		{n + ".txt", n + ".txt", KindUnknown},
		{n + ".ttef.0123456789abcdef.tmp", n + ".ttef.0123456789abcdef.tmp", KindUnknown},
		{n + ".ckpt.0123456789abcde.tmp", n + ".ckpt.0123456789abcde.tmp", KindUnknown},
		{n + ".ckpt.0123456789ABCDEF.tmp", n + ".ckpt.0123456789ABCDEF.tmp", KindUnknown},
		{n + ".ckpt.0123456789abcdef", n + ".ckpt.0123456789abcdef", KindUnknown},
		{n + ".ckpt.0123456789abcdef.tmp.x", n + ".ckpt.0123456789abcdef.tmp.x", KindUnknown},
		{"0123456789ABCDEF0123456789abcdef.ttef", "0123456789ABCDEF0123456789abcdef.ttef", KindUnknown},
		{"short.ttef", "short.ttef", KindUnknown},
		{"", "", KindUnknown},
	}
	for _, c := range cases {
		name, kind := classify(c.file)
		if name != c.name || kind != c.kind {
			t.Errorf("classify(%q) = %q, %v; want %q, %v", c.file, name, kind, c.name, c.kind)
		}
	}
}

func TestListKinds(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	data, ckpt, state, tmp := NewName(), NewName(), NewName(), NewName()
	writeFile(t, s, tid, data, []byte("abcde"))
	if err := s.WriteCheckpoint(tid, ckpt, []byte("ck")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteState(tid, state, []byte("st")); err != nil {
		t.Fatal(err)
	}
	tdir := filepath.Join(dir, string(tid))
	tmpCkpt := tempName(tmp, ckptExt)
	tmpState := tempName(tmp, stateExt)
	for _, f := range []string{tmpCkpt, tmpState, "README", data + ".bak"} {
		if err := os.WriteFile(filepath.Join(tdir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sub := NewName() + ".ttef" // a directory with a data-like name
	if err := os.Mkdir(filepath.Join(tdir, sub), 0o750); err != nil {
		t.Fatal(err)
	}

	entries, err := s.List(tid)
	if err != nil {
		t.Fatal(err)
	}
	got := entriesByFile(t, entries)
	if len(got) != 8 {
		t.Fatalf("got %d entries: %v", len(got), entries)
	}
	want := map[string]struct {
		name string
		kind Kind
	}{
		data + ".ttef":     {data, KindData},
		ckpt + ".ckpt":     {ckpt, KindCheckpoint},
		state + ".dlstate": {state, KindState},
		tmpCkpt:            {tmp, KindTemp},
		tmpState:           {tmp, KindTemp},
		"README":           {"README", KindUnknown},
		data + ".bak":      {data + ".bak", KindUnknown},
		sub:                {sub, KindUnknown},
	}
	for f, w := range want {
		e, ok := got[f]
		if !ok {
			t.Fatalf("missing entry %q", f)
		}
		if e.Name != w.name || e.Kind != w.kind {
			t.Errorf("%q: got %q %v, want %q %v", f, e.Name, e.Kind, w.name, w.kind)
		}
		if e.ModTime.IsZero() || time.Since(e.ModTime) > time.Hour {
			t.Errorf("%q: implausible ModTime %v", f, e.ModTime)
		}
	}
	if e := got[data+".ttef"]; e.Size != 5 {
		t.Errorf("data size = %d, want 5", e.Size)
	}

	// Names of known kinds go back to the removal methods.
	if err := s.Remove(tid, got[data+".ttef"].Name); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveTemp(tid, got[tmpCkpt].File); err != nil {
		t.Fatal(err)
	}
	entries, err = s.List(tid)
	if err != nil {
		t.Fatal(err)
	}
	got = entriesByFile(t, entries)
	if _, ok := got[data+".ttef"]; ok {
		t.Error("data file still listed after Remove")
	}
	if _, ok := got[tmpCkpt]; ok {
		t.Error("temp file still listed after RemoveTemp")
	}
}

func TestListSymlinks(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	writeFile(t, s, tid, name, []byte("abc"))
	tdir := filepath.Join(dir, string(tid))
	target := filepath.Join(tdir, name+".ttef")
	link := NewName() + ".ttef"
	symlinkOrSkip(t, target, filepath.Join(tdir, link))

	entries, err := s.List(tid)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := entriesByFile(t, entries)[link]
	if !ok || e.Kind != KindUnknown || e.Name != link {
		t.Fatalf("symlink entry: %+v (found %v)", e, ok)
	}

	// A tenant directory that is a link (even inside the data directory) is
	// refused, never followed, and skipped by TenantDirs.
	tid2 := newTenant()
	symlinkOrSkip(t, tdir, filepath.Join(dir, string(tid2)))
	if _, err := s.List(tid2); !errors.Is(err, ErrInvalid) {
		t.Fatalf("List through a tenant link: got %v", err)
	}
	ids, err := s.TenantDirs()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids, []tenant.ID{tid}) {
		t.Fatalf("TenantDirs = %v, want [%s]", ids, tid)
	}
}

func TestListMissingAndInvalid(t *testing.T) {
	s, dir := newTestStore(t)
	entries, err := s.List(newTenant())
	if err != nil || entries == nil || len(entries) != 0 {
		t.Fatalf("missing directory: %v, %v", entries, err)
	}
	if _, err := s.List("ten_bad"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid tenant: got %v", err)
	}
	// A regular file in place of the tenant directory.
	tid := newTenant()
	if err := os.WriteFile(filepath.Join(dir, string(tid)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(tid); !errors.Is(err, ErrInvalid) {
		t.Fatalf("file as tenant directory: got %v", err)
	}
}

func TestListFaults(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	writeFile(t, s, tid, NewName(), []byte("abc"))
	tdir := string(tid)
	pathErr := &fs.PathError{Op: "x", Path: filepath.Join(dir, "x"), Err: errFault}
	reset := func() {
		s.ops.lstat = s.root.Lstat
		s.ops.openFile = s.root.OpenFile
		s.ops.stat = (*os.File).Stat
		s.ops.readDir = readAllDir
	}

	check := func(label string, want error) {
		t.Helper()
		_, err := s.List(tid)
		if !errors.Is(err, want) {
			t.Fatalf("%s: got %v", label, err)
		}
		noLeak(t, err, dir)
		reset()
	}

	s.ops.lstat = func(string) (fs.FileInfo, error) { return nil, pathErr }
	check("lstat of the tenant directory", errFault)

	s.ops.openFile = func(string, int, fs.FileMode) (*os.File, error) { return nil, pathErr }
	check("open", errFault)

	s.ops.stat = func(*os.File) (fs.FileInfo, error) { return nil, pathErr }
	check("stat", errFault)

	s.ops.readDir = func(*os.File) ([]fs.DirEntry, error) { return nil, pathErr }
	check("readDir", errFault)

	// Handle that is not the directory seen by lstat (replaced meanwhile).
	other, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.ops.stat = func(*os.File) (fs.FileInfo, error) { return other, nil }
	check("replaced directory", ErrInvalid)

	// Entry lstat failure.
	s.ops.lstat = func(name string) (fs.FileInfo, error) {
		if name == tdir {
			return s.root.Lstat(name)
		}
		return nil, pathErr
	}
	check("entry lstat", errFault)

	// Directory removed between lstat and open: empty list.
	s.ops.openFile = func(string, int, fs.FileMode) (*os.File, error) { return nil, fs.ErrNotExist }
	if entries, err := s.List(tid); err != nil || len(entries) != 0 {
		t.Fatalf("directory removed during List: %v, %v", entries, err)
	}
	reset()

	// Entry removed during List: omitted.
	s.ops.lstat = func(name string) (fs.FileInfo, error) {
		if name == tdir {
			return s.root.Lstat(name)
		}
		return nil, fs.ErrNotExist
	}
	if entries, err := s.List(tid); err != nil || len(entries) != 0 {
		t.Fatalf("entry removed during List: %v, %v", entries, err)
	}
	reset()
}

func TestTenantDirs(t *testing.T) {
	s, dir := newTestStore(t)
	ids, err := s.TenantDirs()
	if err != nil || len(ids) != 0 {
		t.Fatalf("empty data directory: %v, %v", ids, err)
	}
	a, b := newTenant(), newTenant()
	writeFile(t, s, a, NewName(), nil)
	if err := s.WriteState(b, NewName(), nil); err != nil {
		t.Fatal(err)
	}
	// Skipped: a file with a tenant name, an invalid directory name.
	if err := os.WriteFile(filepath.Join(dir, string(newTenant())), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"lost+found", "ten_bad", "ten_" + "01hzzzzzzzzzzzzzzzzzzzzzzz"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	ids, err = s.TenantDirs()
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(ids)
	want := []tenant.ID{a, b}
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Fatalf("TenantDirs = %v, want %v", ids, want)
	}
}

func TestTenantDirsFaults(t *testing.T) {
	s, dir := newTestStore(t)
	pathErr := &fs.PathError{Op: "x", Path: filepath.Join(dir, "x"), Err: errFault}
	s.ops.openFile = func(string, int, fs.FileMode) (*os.File, error) { return nil, pathErr }
	_, err := s.TenantDirs()
	if !errors.Is(err, errFault) {
		t.Fatalf("open: got %v", err)
	}
	noLeak(t, err, dir)

	s.ops.openFile = s.root.OpenFile
	s.ops.readDir = func(*os.File) ([]fs.DirEntry, error) { return nil, pathErr }
	if _, err := s.TenantDirs(); !errors.Is(err, errFault) {
		t.Fatalf("readDir: got %v", err)
	}
}

func TestRemoveTemp(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	if err := s.WriteCheckpoint(tid, name, []byte("ck")); err != nil {
		t.Fatal(err)
	}
	tmp := tempName(name, ckptExt)
	tdir := filepath.Join(dir, string(tid))
	if err := os.WriteFile(filepath.Join(tdir, tmp), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 { // idempotent
		if err := s.RemoveTemp(tid, tmp); err != nil {
			t.Fatal(err)
		}
	}
	if got := listDir(t, tdir); !slices.Equal(got, []string{name + ".ckpt"}) {
		t.Fatalf("directory after RemoveTemp: %v", got)
	}
	// Missing tenant directory.
	if err := s.RemoveTemp(newTenant(), tmp); err != nil {
		t.Fatalf("missing tenant directory: %v", err)
	}

	// Only temporary names are accepted, before touching the file system.
	s.ops.remove = func(string) error { t.Fatal("file system touched"); return nil }
	for _, f := range []string{name + ".ckpt", name + ".ttef", name + ".dlstate", "../" + tmp, tmp + "/x", ""} {
		if err := s.RemoveTemp(tid, f); !errors.Is(err, ErrInvalid) {
			t.Fatalf("RemoveTemp(%q): got %v", f, err)
		}
	}
	if err := s.RemoveTemp("ten_bad", tmp); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid tenant: got %v", err)
	}

	s.ops.remove = func(string) error { return &fs.PathError{Op: "remove", Path: filepath.Join(dir, "x"), Err: errFault} }
	err := s.RemoveTemp(tid, tmp)
	if !errors.Is(err, errFault) {
		t.Fatalf("remove fault: got %v", err)
	}
	noLeak(t, err, dir)
}

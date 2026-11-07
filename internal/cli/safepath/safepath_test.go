package safepath

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/filename"
)

// openDir opens a fresh target directory inside a temporary parent and
// returns it with its path.
func openDir(t *testing.T) (*Dir, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, dir
}

// write creates rel through a part holding content and commits it.
func write(t *testing.T, d *Dir, rel, content string, force bool) error {
	t.Helper()
	p, err := d.Part(rel)
	if err != nil {
		return err
	}
	if _, err := p.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := p.Commit(force); err != nil {
		_ = p.Abort()
		return err
	}
	return nil
}

// readFile returns the content of rel in dir.
func readFile(t *testing.T, dir, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// needSymlinks skips a test on Windows, where creating symbolic links needs
// a privilege.
func needSymlinks(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege on Windows")
	}
}

// needPermissions skips a test that relies on directory permissions.
func needPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions are not enforced")
	}
}

// chmod changes the mode of path and restores 0o755 at cleanup.
func chmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o755) })
}

func TestEntries(t *testing.T) {
	files := []filename.ArchiveFile{
		{Path: "", Name: "a.txt"},
		{Path: "", Name: "A.TXT"},
		{Path: "../etc", Name: "passwd"},
		{Path: "/abs", Name: "x"},
		{Path: `C:\Windows`, Name: "y"},
		{Path: "", Name: "CON"},
		{Path: "", Name: "nul.txt"},
		{Path: "", Name: "trail."},
		{Path: "", Name: ".."},
		{Path: "", Name: `C:evil`},
		{Path: "", Name: "Why?.pdf"},
		{Path: "dir", Name: "é.txt"}, // NFD
	}
	want := []string{
		"a.txt", "A (2).TXT", "passwd", "x", "y", "file", "file (2)", "file (3)",
		"file (4)", "file (5)", "Why_.pdf", "dir/é.txt",
	}
	got := Entries(files)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
	for _, e := range got {
		if _, err := checkRel(e); err != nil {
			t.Errorf("checkRel(%q): %v", e, err)
		}
	}
	if len(Entries(nil)) != 0 {
		t.Fatal("entries of no file")
	}
}

func TestEntriesTempCollision(t *testing.T) {
	long := strings.Repeat("l", 250) + ".bin"
	files := []filename.ArchiveFile{
		{Name: "a.txt"},
		{Name: ".A.TXT.part"},    // the temporary file of a.txt
		{Name: "file (2).txt"},   // the first rename candidate
		{Path: "sub", Name: "b"}, // b's temporary is a folder
		{Path: "sub/.b.part", Name: "z"},
		{Name: long},           // hashed temporary name
		{Name: tempName(long)}, // equal to it
	}
	got := Entries(files)
	want := []string{
		"file (3).txt", ".A.TXT.part", "file (2).txt", "sub/file (4)", "sub/.b.part/z",
		"file (5).bin", tempName(long),
	}
	tempsAndFinals(t, got)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRenamed(t *testing.T) {
	if got := renamed(2, ".txt"); got != "file (2).txt" {
		t.Fatal(got)
	}
	if got := renamed(2, "."+strings.Repeat("x", 250)); got != "file (2)" {
		t.Fatal(got)
	}
	// A rename keeping an over-long extension is never produced.
	files := []filename.ArchiveFile{
		{Name: "a." + strings.Repeat("x", 249)},
		{Name: tempName("a." + strings.Repeat("x", 249))},
	}
	got := Entries(files)
	if got[0] != "file (2)" {
		t.Fatalf("got %q", got[0])
	}
	tempsAndFinals(t, got)
}

// tempsAndFinals asserts that no entry equals, folded, a folder, another
// entry or the temporary file of an entry, and that every entry and
// temporary path passes checkRel.
func tempsAndFinals(t *testing.T, entries []string) {
	t.Helper()
	finals := map[string]bool{}
	folders := map[string]bool{}
	for _, e := range entries {
		if _, err := checkRel(e); err != nil {
			t.Fatalf("entry %q: %v", e, err)
		}
		if _, err := checkRel(tempRel(e)); err != nil {
			t.Fatalf("temporary of %q: %v", e, err)
		}
		if finals[fold(e)] {
			t.Fatalf("duplicate entry %q", e)
		}
		finals[fold(e)] = true
		for i := range len(e) {
			if e[i] == '/' {
				folders[fold(e[:i])] = true
			}
		}
	}
	for _, e := range entries {
		if folders[fold(e)] {
			t.Fatalf("entry %q is a folder", e)
		}
		if tr := fold(tempRel(e)); finals[tr] || folders[tr] {
			t.Fatalf("temporary of %q is taken", e)
		}
	}
}

func TestTempName(t *testing.T) {
	if got := tempName("a.txt"); got != ".a.txt.part" {
		t.Fatal(got)
	}
	long := strings.Repeat("a", 255)
	got := tempName(long)
	if len(got) != 1+32+len(partSuffix) || got != tempName(long) || got == tempName(long[1:]+"b") {
		t.Fatalf("tempName(long) = %q", got)
	}
	exact := strings.Repeat("a", filename.MaxBytes-len(".")-len(partSuffix))
	if got := tempName(exact); got != "."+exact+partSuffix {
		t.Fatal(got)
	}
	if got := tempRel("d/e/f"); got != "d/e/.f.part" {
		t.Fatal(got)
	}
}

func TestCheckRel(t *testing.T) {
	bad := []string{
		"", ".", "..", "../x", "a/../b", "/abs", "a//b", "a/", `a\b`, `C:\x`, "C:x",
		"CON", "a/nul.txt", "trail.", "trail ", " lead", "a?b", `a"b`, "a<b", "a|b",
		"a*b", "e\u0301", "\xff", strings.Repeat("a", 256),
		strings.Repeat("a/", filename.MaxPathSegments+1) + "a",
		strings.Repeat(strings.Repeat("a", 250)+"/", 6) + "a",
	}
	for _, rel := range bad {
		if _, err := checkRel(rel); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("checkRel(%q) = %v", rel, err)
		}
	}
	good := []string{"a", ".env", "a/b/c.txt", "é", strings.Repeat("a/", filename.MaxPathSegments) + "a"}
	for _, rel := range good {
		if _, err := checkRel(rel); err != nil {
			t.Errorf("checkRel(%q) = %v", rel, err)
		}
	}
}

func TestOpen(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing directory opened")
	}
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f); err == nil {
		t.Fatal("file opened as a directory")
	}
}

func TestWriteAndCommit(t *testing.T) {
	d, dir := openDir(t)
	if err := write(t, d, "a/b/c.txt", "hello", false); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "a/b/c.txt"); got != "hello" {
		t.Fatal(got)
	}
	if _, err := os.Lstat(filepath.Join(dir, "a", "b", ".c.txt.part")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("part file left behind")
	}
	ok, err := d.Exists("a/b/c.txt")
	if err != nil || !ok {
		t.Fatalf("Exists = %v, %v", ok, err)
	}
	for _, rel := range []string{"a/b/missing", "missing/x", "a/missing/x"} {
		if ok, err := d.Exists(rel); err != nil || ok {
			t.Fatalf("Exists(%q) = %v, %v", rel, ok, err)
		}
	}
	if ok, err := d.Exists("a"); err != nil || !ok {
		t.Fatalf("Exists(folder) = %v, %v", ok, err)
	}

	// Existing file: refused without force, replaced with force.
	if err := write(t, d, "a/b/c.txt", "other", false); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite without force: %v", err)
	}
	if got := readFile(t, dir, "a/b/c.txt"); got != "hello" {
		t.Fatal(got)
	}
	if err := write(t, d, "a/b/c.txt", "forced", true); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "a/b/c.txt"); got != "forced" {
		t.Fatal(got)
	}

	// A refused Commit keeps the part: commit again with force.
	p, err := d.Part("a/b/c.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.Write([]byte("retry"))
	if err := p.Commit(false); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	if err := p.Commit(true); err != nil {
		t.Fatal(err)
	}
	if err := p.Abort(); err != nil {
		t.Fatalf("Abort after Commit: %v", err)
	}
	if got := readFile(t, dir, "a/b/c.txt"); got != "retry" {
		t.Fatal(got)
	}

	// Existing directory: never replaced.
	if err := write(t, d, "a/b", "x", true); !errors.Is(err, ErrExists) {
		t.Fatalf("directory replaced: %v", err)
	}
	// A file where a folder is expected.
	if _, err := d.Part("a/b/c.txt/d"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("file as folder: %v", err)
	}
	if _, err := d.Exists("a/b/c.txt/d"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Exists file as folder: %v", err)
	}
	// Unsafe paths.
	for _, rel := range []string{"../x", "/etc/passwd", "a/../../x", "CON"} {
		if _, err := d.Part(rel); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Part(%q) = %v", rel, err)
		}
		if _, err := d.Exists(rel); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Exists(%q) = %v", rel, err)
		}
	}
}

func TestModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permissions")
	}
	d, dir := openDir(t)
	if d.fileMode() != 0o644 || d.dirMode() != 0o755 {
		t.Fatal("default modes")
	}
	d.Private = true
	if err := write(t, d, "p/f", "x", false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "p", "f"))
	if err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private file: %v %v", fi, err)
	}
	fi, err = os.Stat(filepath.Join(dir, "p"))
	if err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private folder: %v %v", fi, err)
	}
}

func TestResumeAndTruncate(t *testing.T) {
	d, dir := openDir(t)
	p, err := d.Part("r/f.bin")
	if err != nil {
		t.Fatal(err)
	}
	if p.Size() != 0 {
		t.Fatal(p.Size())
	}
	_, _ = p.Write([]byte("0123456789"))
	if err := p.Sync(); err != nil {
		t.Fatal(err)
	}
	// Interrupted: the file is left, reopened later.
	if err := p.f.Close(); err != nil {
		t.Fatal(err)
	}
	p, err = d.Part("r/f.bin")
	if err != nil {
		t.Fatal(err)
	}
	if p.Size() != 10 {
		t.Fatalf("resumed size %d", p.Size())
	}
	for _, n := range []int64{-1, 11} {
		if err := p.Truncate(n); !errors.Is(err, ErrRange) {
			t.Fatalf("Truncate(%d) = %v", n, err)
		}
	}
	if err := p.Truncate(4); err != nil || p.Size() != 4 {
		t.Fatalf("Truncate: %v, size %d", err, p.Size())
	}
	_, _ = p.Write([]byte("ab"))
	if p.Size() != 6 {
		t.Fatal(p.Size())
	}
	if err := p.Commit(false); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "r/f.bin"); got != "0123ab" {
		t.Fatal(got)
	}
	if err := p.Truncate(0); err == nil {
		t.Fatal("Truncate after Commit")
	}
}

func TestAbort(t *testing.T) {
	d, dir := openDir(t)
	p, err := d.Part("x.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.Write([]byte("bad"))
	if err := p.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := p.Abort(); err != nil {
		t.Fatalf("second Abort: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("left %v (%v)", entries, err)
	}
	// Commit after Abort: the part is gone.
	if err := p.Commit(false); err == nil {
		t.Fatal("Commit after Abort")
	}
	// Sync or close failure is reported by Commit.
	p, err = d.Part("y.bin")
	if err != nil {
		t.Fatal(err)
	}
	_ = p.f.Close()
	if err := p.Commit(false); err == nil {
		t.Fatal("Commit of a closed file")
	}
	_ = p.Abort()
}

func TestTempIsDirectory(t *testing.T) {
	d, dir := openDir(t)
	if err := os.Mkdir(filepath.Join(dir, ".f.part"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Part("f"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("temporary directory: %v", err)
	}
}

func TestSymlinks(t *testing.T) {
	needSymlinks(t)
	d, dir := openDir(t)
	outside := filepath.Join(filepath.Dir(dir), "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"out":         outside,                          // folder outside
		"in":          "real",                           // folder inside
		"outfile":     filepath.Join(outside, "victim"), // final file outside
		"infile":      "real/target",                    // final file inside
		".tmp.part":   filepath.Join(outside, "tmp"),    // temporary file outside
		".tmpin.part": "real/tmp",                       // temporary file inside
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{"out/x", "in/x", "in/sub/x", "tmp", "tmpin"} {
		if _, err := d.Part(rel); !errors.Is(err, ErrSymlink) {
			t.Errorf("Part(%q) = %v", rel, err)
		}
	}
	for _, rel := range []string{"out/x", "in/x"} {
		if _, err := d.Exists(rel); !errors.Is(err, ErrSymlink) {
			t.Errorf("Exists(%q) = %v", rel, err)
		}
	}
	for _, rel := range []string{"outfile", "infile"} {
		if ok, err := d.Exists(rel); err != nil || !ok {
			t.Errorf("Exists(%q) = %v, %v", rel, ok, err)
		}
		if err := write(t, d, rel, "x", true); !errors.Is(err, ErrSymlink) {
			t.Errorf("write(%q) = %v", rel, err)
		}
	}
	// A folder replaced by a link between Part and Commit.
	p, err := d.Part("swap/x")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "swap"), filepath.Join(dir, "real", "swapped")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "swap")); err != nil {
		t.Fatal(err)
	}
	if err := p.Commit(true); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Commit through a swapped link: %v", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("written outside: %v (%v)", entries, err)
	}
}

func TestPermissionErrors(t *testing.T) {
	needPermissions(t)
	d, dir := openDir(t)
	for _, f := range []string{"ro/a", "locked/b/c"} {
		if err := write(t, d, f, "x", false); err != nil {
			t.Fatal(err)
		}
	}
	ro := filepath.Join(dir, "ro")
	locked := filepath.Join(dir, "locked")

	// Commit and Abort in a read-only folder.
	p, err := d.Part("ro/new")
	if err != nil {
		t.Fatal(err)
	}
	chmod(t, ro, 0o555)
	if err := p.Commit(false); err == nil {
		t.Fatal("rename in a read-only folder")
	}
	if err := p.Abort(); err == nil {
		t.Fatal("remove in a read-only folder")
	}
	// Mkdir and OpenFile in a read-only folder.
	if _, err := d.Part("ro/sub/x"); err == nil {
		t.Fatal("mkdir in a read-only folder")
	}
	if _, err := d.Part("ro/other"); err == nil {
		t.Fatal("create in a read-only folder")
	}

	// Lstat failures in a folder without search permission.
	p, err = d.Part("locked/b/late")
	if err != nil {
		t.Fatal(err)
	}
	chmod(t, filepath.Join(locked, "b"), 0o000)
	if _, err := d.Exists("locked/b/c"); err == nil || errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Exists of a final in a locked folder: %v", err)
	}
	if _, err := d.Part("locked/b/c"); err == nil {
		t.Fatal("Part in a locked folder")
	}
	if err := p.Commit(false); err == nil {
		t.Fatal("Commit in a locked folder")
	}
	chmod(t, locked, 0o000)
	if _, err := d.Part("locked/b/x"); err == nil {
		t.Fatal("Part below a locked folder")
	}
}

// checkConfined asserts that nothing was created in parent besides the
// target directory.
func checkConfined(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "target" {
		t.Fatalf("written outside the target: %v", entries)
	}
}

// fuzzWrite writes every entry of files into a fresh target and checks the
// invariants.
func fuzzWrite(t *testing.T, files []filename.ArchiveFile) {
	got := Entries(files)
	if len(got) != len(files) {
		t.Fatalf("%d entries for %d files", len(got), len(files))
	}
	tempsAndFinals(t, got)
	parent := t.TempDir()
	dir := filepath.Join(parent, "target")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	for _, e := range got {
		if strings.HasPrefix(e, "/") || strings.Contains(e, `\`) || filepath.IsAbs(e) || filepath.VolumeName(e) != "" {
			t.Fatalf("unsafe entry %q", e)
		}
		if err := write(t, d, e, e, false); err != nil {
			t.Fatalf("write(%q): %v", e, err)
		}
	}
	for _, e := range got {
		if readFile(t, dir, e) != e {
			t.Fatalf("content of %q", e)
		}
	}
	checkConfined(t, parent)
}

func FuzzSafeName(f *testing.F) {
	for _, s := range []string{
		"a.txt", "../x", "/etc/passwd", `C:\x`, "CON", "nul.txt", "trail.", ".",
		"..", "e\u0301", "a?b", strings.Repeat("z", 300), ".a.txt.part", "\x00",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		fuzzWrite(t, []filename.ArchiveFile{
			{Name: name}, {Name: name}, {Name: "." + name + ".part"}, {Name: tempName(name)},
		})
	})
}

func FuzzSafePath(f *testing.F) {
	for _, s := range [][2]string{
		{"a/b", "c"},
		{"../..", "x"},
		{"/abs", "y"},
		{`C:\Windows`, "z"},
		{"a/./b", "c"},
		{"CON/x", "y"},
		{"a", ".b.part"},
		{".b.part", "z"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, path, name string) {
		fuzzWrite(t, []filename.ArchiveFile{
			{Path: path, Name: name},
			{Path: path, Name: "." + name + ".part"},
			{Path: "", Name: path},
			{Path: path + "/" + name, Name: name},
		})
	})
}

func TestPartClose(t *testing.T) {
	root := t.TempDir()
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	p, err := d.Part("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	q, err := d.Part("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if q.Size() != 3 {
		t.Fatalf("resumed size %d, want 3", q.Size())
	}
	if err := q.Commit(false); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := p.Commit(false); err == nil {
		t.Fatal("Commit of a closed part whose file was renamed: want an error")
	}
}

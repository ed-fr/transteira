package safepath

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// hook replaces *target with v for the duration of the test.
func hook[T any](t *testing.T, target *T, v T) {
	t.Helper()
	old := *target
	*target = v
	t.Cleanup(func() { *target = old })
}

// realLink and realOpen are the operations the hooks replace.
var (
	realLink = linkFile
	realOpen = openFile
)

// TestCommitNoReplaceRace creates the final file between the checks of
// Commit and the link: it is kept and Commit reports ErrExists.
func TestCommitNoReplaceRace(t *testing.T) {
	d, dir := openDir(t)
	hook(t, &linkFile, func(r *os.Root, oldname, newname string) error {
		if err := os.WriteFile(filepath.Join(dir, newname), []byte("theirs"), 0o600); err != nil {
			t.Fatal(err)
		}
		return realLink(r, oldname, newname)
	})
	p, err := d.Part("f.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.Write([]byte("ours"))
	if err := p.Commit(false); !errors.Is(err, ErrExists) {
		t.Fatalf("Commit = %v, want ErrExists", err)
	}
	if got := readFile(t, dir, "f.txt"); got != "theirs" {
		t.Fatalf("file created after the check replaced: %q", got)
	}
	if got := readFile(t, dir, ".f.txt.part"); got != "ours" {
		t.Fatalf("part file not kept: %q", got)
	}
}

// TestCommitLinkUnsupported falls back to the rename when the filesystem
// has no hard links, and still refuses a file seen by the second check.
func TestCommitLinkUnsupported(t *testing.T) {
	d, dir := openDir(t)
	hook(t, &linkFile, func(*os.Root, string, string) error {
		return &os.LinkError{Op: "link", Err: syscall.EPERM}
	})
	if err := write(t, d, "f.txt", "one", false); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dir, "f.txt"); got != "one" {
		t.Fatal(got)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".f.txt.part")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("part file left behind")
	}

	// A file appearing during the failed link is caught by the check again.
	hook(t, &linkFile, func(_ *os.Root, _, newname string) error {
		_ = os.WriteFile(filepath.Join(dir, newname), []byte("theirs"), 0o600)
		return errors.ErrUnsupported
	})
	if err := write(t, d, "g.txt", "two", false); !errors.Is(err, ErrExists) {
		t.Fatalf("Commit = %v, want ErrExists", err)
	}
	if got := readFile(t, dir, "g.txt"); got != "theirs" {
		t.Fatal(got)
	}
}

// TestCommitRemoveTempFails reports a temporary file left after the link,
// the final file being in place.
func TestCommitRemoveTempFails(t *testing.T) {
	d, dir := openDir(t)
	boom := errors.New("boom")
	hook(t, &removeFile, func(*os.Root, string) error { return boom })
	p, err := d.Part("f.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.Write([]byte("data"))
	if err := p.Commit(false); !errors.Is(err, boom) {
		t.Fatalf("Commit = %v", err)
	}
	if got := readFile(t, dir, "f.txt"); got != "data" {
		t.Fatal(got)
	}
	if err := p.Abort(); err != nil {
		t.Fatalf("Abort after a committed link: %v", err)
	}
	if got := readFile(t, dir, "f.txt"); got != "data" {
		t.Fatal("Abort removed the final file")
	}
}

// TestOpenPartSwapped refuses a part file replaced while it was opened.
func TestOpenPartSwapped(t *testing.T) {
	needSymlinks(t)
	d, dir := openDir(t)
	if err := os.WriteFile(filepath.Join(dir, "other"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Opened through a link to another file, the name then a link.
	hook(t, &openFile, func(r *os.Root, name string, flag int, perm fs.FileMode) (*os.File, error) {
		f, err := realOpen(r, name, flag, perm)
		if err == nil {
			_ = os.Remove(filepath.Join(dir, name))
			if err := os.Symlink("other", filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		return f, err
	})
	if _, err := d.Part("a.txt"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("symlink swapped in: %v", err)
	}
	// Opened as a regular file, the name then another regular file.
	hook(t, &openFile, func(r *os.Root, name string, flag int, perm fs.FileMode) (*os.File, error) {
		f, err := realOpen(r, name, flag, perm)
		if err == nil {
			_ = os.Remove(filepath.Join(dir, name))
			_ = os.WriteFile(filepath.Join(dir, name), nil, 0o600)
		}
		return f, err
	})
	if _, err := d.Part("b.txt"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("file swapped: %v", err)
	}
	// The name removed after the open.
	hook(t, &openFile, func(r *os.Root, name string, flag int, perm fs.FileMode) (*os.File, error) {
		f, err := realOpen(r, name, flag, perm)
		if err == nil {
			_ = os.Remove(filepath.Join(dir, name))
		}
		return f, err
	})
	if _, err := d.Part("c.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("removed part: %v", err)
	}
	// The opened file cannot be inspected.
	hook(t, &openFile, func(r *os.Root, name string, flag int, perm fs.FileMode) (*os.File, error) {
		f, err := realOpen(r, name, flag, perm)
		if err == nil {
			_ = f.Close()
		}
		return f, err
	})
	if _, err := d.Part("d.txt"); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("Stat failure: %v", err)
	}
}

// TestPartReadAt reads back what a part file holds.
func TestPartReadAt(t *testing.T) {
	d, _ := openDir(t)
	p, err := d.Part("f.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Abort() }()
	_, _ = p.Write([]byte("hello world"))
	b, err := io.ReadAll(io.NewSectionReader(p, 6, 5))
	if err != nil || string(b) != "world" {
		t.Fatalf("ReadAt = %q, %v", b, err)
	}
}

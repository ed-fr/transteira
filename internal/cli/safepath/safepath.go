// Package safepath writes downloaded files into a target directory without
// ever escaping it (threat T-330).
//
// The names and folders of the files come from the server or, for an
// end-to-end encrypted transfer, from metadata decrypted on the client:
// both are attacker-controlled. Entries turns them into relative paths that
// are safe on Windows, macOS and Linux, following the rules of the download
// archive (filename.ArchiveEntries). Dir then writes each file through an
// os.Root opened on the target directory: a path can never resolve outside
// of it, symbolic links met on the way are refused even when they point
// inside, a file is first written to a temporary ".part" file next to its
// final place, and it only replaces an existing file when the caller asks.
//
// Without that request, the final file is created with a hard link from
// the temporary file, which the operating system refuses when anything
// already has the name: a file created there after the checks is never
// replaced. On a filesystem without hard links (FAT, exFAT, some network
// shares), Commit falls back to a check followed by a rename, which leaves
// a short window in which a file created concurrently by another local
// process may be replaced.
package safepath

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/ed-fr/transteira/internal/filename"
)

// Sentinel errors, to be tested with errors.Is.
var (
	// ErrExists: the final path already exists and the caller did not ask
	// to replace it, or it is a directory, which is never replaced.
	ErrExists = errors.New("safepath: file already exists")
	// ErrSymlink: a component of the path, the temporary file or the final
	// file is a symbolic link.
	ErrSymlink = errors.New("safepath: symbolic link refused")
	// ErrUnsafePath: the relative path is not one Entries can produce, or
	// one of its folders is not a directory.
	ErrUnsafePath = errors.New("safepath: unsafe path")
	// ErrRange: Truncate was asked for a size outside of the part file.
	ErrRange = errors.New("safepath: truncate size out of range")
)

// windowsUnsafe are the characters filename.Validate accepts but Windows
// refuses in a name; filename.ArchiveEntries replaces them with "_".
const windowsUnsafe = `<>"|?*`

// partSuffix ends the name of every temporary file.
const partSuffix = ".part"

// Operations on the root, replaceable in tests (failures that a real
// filesystem cannot produce on demand).
var (
	linkFile   = (*os.Root).Link
	removeFile = (*os.Root).Remove
	openFile   = (*os.Root).OpenFile
)

// maxRelBytes is the longest relative path Entries can produce: a folder
// path, a separator and a name.
const maxRelBytes = filename.MaxPathBytes + 1 + filename.MaxBytes

// Entries returns the relative path, segments joined by "/", where each of
// files is to be written, in the order of files.
//
// The paths are those of filename.ArchiveEntries (invalid name: "file";
// invalid folder: the root; characters refused by Windows replaced with
// "_"; folders merged case-insensitively; duplicates numbered "name (2).ext"),
// so every segment passes filename.Validate: never "." nor "..", no "/",
// "\" or ":", no drive letter, no trailing dot or space, no Windows
// reserved name, at most 255 bytes, NFC. Dir.Part and Dir.Exists check
// these rules again and refuse any other path with ErrUnsafePath.
//
// On top of that, no path equals, case-insensitively, the temporary file
// of another one (".name.part", see Dir.Part), nor a folder: a file whose
// temporary name is taken by another file or folder is renamed
// "file (n).ext", so that writing one file can never resume into, or
// replace, another.
func Entries(files []filename.ArchiveFile) []string {
	out := filename.ArchiveEntries(files)
	taken := map[string]bool{} // final paths and folders, folded
	temps := map[string]bool{} // temporary paths, folded
	for _, e := range out {
		taken[fold(e)] = true
		for i := range len(e) {
			if e[i] == '/' {
				taken[fold(e[:i])] = true
			}
		}
		temps[fold(tempRel(e))] = true
	}
	n := 1
	for i, e := range out {
		if !taken[fold(tempRel(e))] {
			continue
		}
		dir, name := splitRel(e)
		ext := ""
		if j := strings.LastIndexByte(name, '.'); j > 0 {
			ext = name[j:]
		}
		for {
			n++
			c := dir + renamed(n, ext)
			if taken[fold(c)] || temps[fold(c)] || taken[fold(tempRel(c))] {
				continue
			}
			taken[fold(c)] = true
			temps[fold(tempRel(c))] = true
			out[i] = c
			break
		}
	}
	return out
}

// renamed returns "file (n)ext", without the extension when it would not
// fit in filename.MaxBytes.
func renamed(n int, ext string) string {
	base := filename.Fallback + " (" + strconv.Itoa(n) + ")"
	if len(base)+len(ext) > filename.MaxBytes {
		return base
	}
	return base + ext
}

// fold is the case-insensitive comparison key of a path, as in
// filename.ArchiveEntries.
func fold(s string) string {
	return norm.NFC.String(strings.ToLower(strings.ToUpper(s)))
}

// splitRel splits a relative slash path into its folder, "/" included ("" at
// the root), and its name.
func splitRel(rel string) (string, string) {
	i := strings.LastIndexByte(rel, '/')
	return rel[:i+1], rel[i+1:]
}

// tempRel returns the relative slash path of the temporary file of rel.
func tempRel(rel string) string {
	dir, name := splitRel(rel)
	return dir + tempName(name)
}

// tempName returns the name of the temporary file of the final name name:
// ".name.part", or ".<32 hex digits of SHA-256(name)>.part" when that would
// exceed filename.MaxBytes. It is deterministic, so that a download resumes
// across runs.
func tempName(name string) string {
	if t := "." + name + partSuffix; len(t) <= filename.MaxBytes {
		return t
	}
	sum := sha256.Sum256([]byte(name))
	return "." + hex.EncodeToString(sum[:16]) + partSuffix
}

// checkRel returns the segments of rel, or ErrUnsafePath when rel is not a
// relative slash path whose every segment passes filename.Validate
// unchanged and holds none of the characters Windows refuses.
func checkRel(rel string) ([]string, error) {
	segs := strings.Split(rel, "/")
	if len(rel) > maxRelBytes || len(segs) > filename.MaxPathSegments+1 {
		return nil, fmt.Errorf("%w: path too long", ErrUnsafePath)
	}
	for _, s := range segs {
		v, err := filename.Validate(s)
		if err != nil || v != s || strings.ContainsAny(s, windowsUnsafe) {
			return nil, fmt.Errorf("%w: %q", ErrUnsafePath, rel)
		}
	}
	return segs, nil
}

// Dir is a target directory opened for writing. It is not safe for
// concurrent use.
type Dir struct {
	root *os.Root
	// Private makes the files created afterwards 0o600 and the folders
	// 0o700, instead of 0o644 and 0o755 (before the umask).
	Private bool
}

// Open opens the existing directory dir as the root of all the writes.
func Open(dir string) (*Dir, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("safepath: open target directory: %w", err)
	}
	return &Dir{root: root}, nil
}

// Close releases the directory. Parts still open stay usable until they
// are committed or aborted.
func (d *Dir) Close() error {
	return d.root.Close()
}

// fileMode returns the permissions of a new file.
func (d *Dir) fileMode() fs.FileMode {
	if d.Private {
		return 0o600
	}
	return 0o644
}

// dirMode returns the permissions of a new folder.
func (d *Dir) dirMode() fs.FileMode {
	if d.Private {
		return 0o700
	}
	return 0o755
}

// lstat returns the information of p inside the root, without following a
// final symbolic link, and whether it exists.
func (d *Dir) lstat(p string) (fs.FileInfo, bool, error) {
	fi, err := d.root.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return fi, true, nil
}

// parents checks the folders of the path made of segs, one level at a
// time: each must be a real directory, never a symbolic link. A missing
// folder is created when create is set; otherwise parents reports it as
// missing and stops.
func (d *Dir) parents(segs []string, create bool) (bool, error) {
	for i := 1; i < len(segs); i++ {
		p := filepath.Join(segs[:i]...)
		fi, ok, err := d.lstat(p)
		switch {
		case err != nil:
			return false, err
		case !ok && !create:
			return true, nil
		case !ok:
			if err := d.root.Mkdir(p, d.dirMode()); err != nil {
				return false, err
			}
		case fi.Mode()&fs.ModeSymlink != 0:
			return false, fmt.Errorf("%w: %q", ErrSymlink, filepath.ToSlash(p))
		case !fi.IsDir():
			return false, fmt.Errorf("%w: %q is not a directory", ErrUnsafePath, filepath.ToSlash(p))
		}
	}
	return false, nil
}

// Exists reports whether something (file, folder or link) is at the
// relative path rel, so that the caller can refuse before downloading. It
// returns ErrUnsafePath for a path Entries cannot produce, and ErrSymlink
// when a folder on the way is a symbolic link.
func (d *Dir) Exists(rel string) (bool, error) {
	segs, err := checkRel(rel)
	if err != nil {
		return false, err
	}
	missing, err := d.parents(segs, false)
	if err != nil || missing {
		return false, err
	}
	_, ok, err := d.lstat(filepath.Join(segs...))
	return ok, err
}

// Part opens, or creates, the temporary file of the relative path rel (see
// Entries for the name), creating the missing folders. An existing
// temporary file is kept, so that the download resumes from Part.Size
// (HTTP Range). rel must be a path returned by Entries: any other is
// refused with ErrUnsafePath, and a symbolic link on the way, or as the
// temporary file, with ErrSymlink.
func (d *Dir) Part(rel string) (*Part, error) {
	segs, err := checkRel(rel)
	if err != nil {
		return nil, err
	}
	if _, err := d.parents(segs, true); err != nil {
		return nil, err
	}
	last := len(segs) - 1
	tmp := filepath.Join(append(segs[:last:last], tempName(segs[last]))...)
	fi, ok, err := d.lstat(tmp)
	if err != nil {
		return nil, err
	}
	var size int64
	if ok {
		if !fi.Mode().IsRegular() {
			if fi.Mode()&fs.ModeSymlink != 0 {
				return nil, fmt.Errorf("%w: %q", ErrSymlink, filepath.ToSlash(tmp))
			}
			return nil, fmt.Errorf("%w: %q is not a regular file", ErrUnsafePath, filepath.ToSlash(tmp))
		}
		size = fi.Size()
	}
	f, err := d.openPart(tmp)
	if err != nil {
		return nil, err
	}
	return &Part{d: d, f: f, segs: segs, tmp: tmp, final: filepath.Join(segs...), size: size}, nil
}

// openPart opens, or creates, the temporary file tmp and checks that the
// file opened is the regular file now at that name, not one reached
// through a symbolic link swapped in after the first check: os.Root
// follows a symbolic link that stays inside the root, so O_NOFOLLOW alone
// cannot refuse it.
func (d *Dir) openPart(tmp string) (*os.File, error) {
	f, err := openFile(d.root, tmp, os.O_RDWR|os.O_CREATE, d.fileMode())
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err == nil {
		var now fs.FileInfo
		if now, err = d.root.Lstat(tmp); err == nil && (!now.Mode().IsRegular() || !os.SameFile(opened, now)) {
			err = fmt.Errorf("%w: %q changed while it was opened", ErrSymlink, filepath.ToSlash(tmp))
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// Part is the temporary file of one download. Writes go to its end; it
// becomes the final file on Commit. It is not safe for concurrent use.
type Part struct {
	d         *Dir
	f         *os.File
	segs      []string
	tmp       string
	final     string
	size      int64
	closed    bool
	committed bool
}

// Size returns the current size of the part file: what was already there
// when it was opened, plus what was written since, or the size given to
// Truncate.
func (p *Part) Size() int64 {
	return p.size
}

// Write appends b at the end of the part file (at offset Size).
func (p *Part) Write(b []byte) (int, error) {
	n, err := p.f.WriteAt(b, p.size)
	p.size += int64(n)
	return n, err
}

// Truncate cuts the part file to n bytes, between 0 and Size, and makes the
// next Write start there (resume of a decrypted stream at a chunk boundary).
func (p *Part) Truncate(n int64) error {
	if n < 0 || n > p.size {
		return ErrRange
	}
	if err := p.f.Truncate(n); err != nil {
		return err
	}
	p.size = n
	return nil
}

// ReadAt reads the part file at offset off (to hash what a previous run
// wrote before resuming), through the file opened by Dir.Part: the target
// directory is never resolved again by name.
func (p *Part) ReadAt(b []byte, off int64) (int, error) {
	return p.f.ReadAt(b, off)
}

// Sync flushes the part file to stable storage.
func (p *Part) Sync() error {
	return p.f.Sync()
}

// Commit flushes and closes the part file, then gives it its final path.
// If something already exists there, it returns ErrExists unless force is
// set; a directory is never replaced (ErrExists) nor a symbolic link
// (ErrSymlink), whatever force. Without force, the final name is created
// with a hard link, so that a file created there after the checks is not
// replaced either (ErrExists); see the package documentation for the
// fallback on a filesystem without hard links. On a refusal the part file
// is kept: call Commit again with force, or Abort. The caller checks the
// SHA-256 of the content before calling Commit.
func (p *Part) Commit(force bool) error {
	if !p.closed {
		p.closed = true
		if err := errors.Join(p.f.Sync(), p.f.Close()); err != nil {
			return err
		}
	}
	if _, err := p.d.parents(p.segs, false); err != nil {
		return err
	}
	if err := p.checkFinal(force); err != nil {
		return err
	}
	if !force {
		err := linkFile(p.d.root, p.tmp, p.final)
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %q", ErrExists, filepath.ToSlash(p.final))
		}
		if err == nil {
			p.committed = true
			if err := removeFile(p.d.root, p.tmp); err != nil {
				return fmt.Errorf("removing the temporary file of %q: %w", filepath.ToSlash(p.final), err)
			}
			return nil
		}
		// No hard link on this filesystem: check again, then rename
		// (residual window, see the package documentation).
		if err := p.checkFinal(false); err != nil {
			return err
		}
	}
	if err := p.d.root.Rename(p.tmp, p.final); err != nil {
		return err
	}
	p.committed = true
	return nil
}

// checkFinal refuses what is at the final path: a symbolic link or a
// directory always, anything else unless force is set.
func (p *Part) checkFinal(force bool) error {
	fi, ok, err := p.d.lstat(p.final)
	if err != nil || !ok {
		return err
	}
	rel := filepath.ToSlash(p.final)
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%w: %q", ErrSymlink, rel)
	case fi.IsDir():
		return fmt.Errorf("%w: %q is a directory", ErrExists, rel)
	case !force:
		return fmt.Errorf("%w: %q", ErrExists, rel)
	}
	return nil
}

// Close flushes and closes the part file and keeps it on disk, so that a
// later run resumes from it. It does nothing once the file is closed (by
// Close, Commit or Abort), so it can be deferred; after Close only Commit
// and Abort remain usable.
func (p *Part) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	return errors.Join(p.f.Sync(), p.f.Close())
}

// Abort closes and removes the part file (corrupted download, hash
// mismatch, authentication failure). It does nothing after a successful
// Commit, so it can be deferred.
func (p *Part) Abort() error {
	if p.committed {
		return nil
	}
	var err error
	if !p.closed {
		p.closed = true
		err = p.f.Close()
	}
	if rerr := p.d.root.Remove(p.tmp); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		err = errors.Join(err, rerr)
	}
	return err
}

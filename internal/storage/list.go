package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Kind classifies an entry of a tenant directory.
type Kind int

const (
	// KindUnknown is any entry the store did not create: an invalid name, an
	// unknown extension, a directory, a symbolic link or any other non
	// regular file. Such entries are reported, never followed nor removed.
	KindUnknown Kind = iota
	// KindData is an encrypted stored file (<name>.ttef).
	KindData
	// KindCheckpoint is an upload resume checkpoint (<name>.ckpt).
	KindCheckpoint
	// KindState is a download state file (<name>.dlstate).
	KindState
	// KindTemp is a leftover temporary file of an atomic write of a
	// checkpoint or state (<name>.ckpt.<16 hex>.tmp or
	// <name>.dlstate.<16 hex>.tmp), normally removed by the write itself
	// and left behind only by a crash.
	KindTemp
)

// String returns the lowercase name of the kind, for logs.
func (k Kind) String() string {
	switch k {
	case KindData:
		return "data"
	case KindCheckpoint:
		return "checkpoint"
	case KindState:
		return "state"
	case KindTemp:
		return "temp"
	default:
		return "unknown"
	}
}

// tmpSuffixLen is the length of the random hex suffix of a temporary file
// name (8 random bytes, see writeAtomic).
const tmpSuffixLen = 16

// Entry describes one entry of a tenant directory, as returned by
// [Store.List].
type Entry struct {
	// Name is the storage name, without extension, of a known entry: it can
	// be passed back to [Store.Remove], [Store.RemoveCheckpoint] or
	// [Store.RemoveState]. For a KindUnknown entry it is the raw directory
	// entry name, for logging only.
	Name string
	// File is the raw directory entry name (with extensions). For a
	// KindTemp entry it is the value to pass to [Store.RemoveTemp].
	File string
	// Kind classifies the entry.
	Kind Kind
	// ModTime is the modification time of the entry itself (a symbolic
	// link is not followed).
	ModTime time.Time
	// Size is the size in bytes of the entry itself.
	Size int64
}

// TenantDirs returns the identifiers of the tenant directories present
// under the data directory, in directory order. Entries that are not
// directories (including symbolic links, which are never followed) or whose
// name is not a well-formed tenant ID are skipped silently: this package
// logs nothing.
func (s *Store) TenantDirs() ([]tenant.ID, error) {
	entries, err := s.readDir(".")
	if err != nil {
		return nil, wrap("list tenants", "", err)
	}
	ids := make([]tenant.ID, 0, len(entries))
	for _, e := range entries {
		tid := tenant.ID(e.Name())
		if !e.Type().IsDir() || tid.Validate() != nil {
			continue
		}
		ids = append(ids, tid)
	}
	return ids, nil
}

// List returns the entries of the directory of tenant tid, classified by
// [Kind], in directory order. A missing tenant directory yields an empty
// list without error. The tenant directory itself must be a real directory:
// a symbolic link in its place is refused with ErrInvalid, never followed.
// Entries are inspected without following symbolic links. An entry removed
// while List runs is omitted.
func (s *Store) List(tid tenant.ID) ([]Entry, error) {
	if tid.Validate() != nil {
		return nil, fmt.Errorf("%w: tenant id", ErrInvalid)
	}
	dir := string(tid)
	info, err := s.ops.lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, wrap("list", "", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("storage: list: %w: tenant directory is not a directory", ErrInvalid)
	}
	entries, err := s.readDirChecked(dir, info)
	if errors.Is(err, ErrNotFound) { // removed since lstat
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		file := e.Name()
		fi, err := s.ops.lstat(filepath.Join(dir, file))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, wrap("list", "", err)
		}
		ent := Entry{Name: file, File: file, Kind: KindUnknown, ModTime: fi.ModTime(), Size: fi.Size()}
		if fi.Mode().IsRegular() {
			if name, kind := classify(file); kind != KindUnknown {
				ent.Name, ent.Kind = name, kind
			}
		}
		out = append(out, ent)
	}
	return out, nil
}

// readDirChecked reads the directory dir after checking that the opened
// handle is the directory described by want (obtained with lstat), so that
// a directory replaced by a symbolic link between the two calls is refused
// rather than followed.
func (s *Store) readDirChecked(dir string, want fs.FileInfo) ([]fs.DirEntry, error) {
	f, err := s.ops.openFile(dir, os.O_RDONLY, 0)
	if err != nil {
		return nil, wrap("list", "", err)
	}
	defer func() { _ = f.Close() }()
	got, err := s.ops.stat(f)
	if err != nil {
		return nil, wrap("list", "", err)
	}
	if !os.SameFile(want, got) {
		return nil, fmt.Errorf("storage: list: %w: tenant directory replaced", ErrInvalid)
	}
	entries, err := s.ops.readDir(f)
	if err != nil {
		return nil, wrap("list", "", err)
	}
	return entries, nil
}

// readDir returns the entries of the directory dir, relative to the root.
func (s *Store) readDir(dir string) ([]fs.DirEntry, error) {
	f, err := s.ops.openFile(dir, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return s.ops.readDir(f)
}

// classify returns the storage name and kind of the directory entry name
// file, assumed to be a regular file. It returns KindUnknown for any name
// the store does not produce.
func classify(file string) (string, Kind) {
	if len(file) < NameLen || !ValidName(file[:NameLen]) {
		return file, KindUnknown
	}
	name, rest := file[:NameLen], file[NameLen:]
	switch rest {
	case fileExt:
		return name, KindData
	case ckptExt:
		return name, KindCheckpoint
	case stateExt:
		return name, KindState
	}
	for _, ext := range []string{ckptExt, stateExt} {
		suffix, ok := strings.CutPrefix(rest, ext+".")
		if !ok {
			continue
		}
		hexPart, ok := strings.CutSuffix(suffix, tmpExt)
		if ok && validHex(hexPart, tmpSuffixLen) {
			return name, KindTemp
		}
	}
	return file, KindUnknown
}

// validHex reports whether s is exactly n lowercase hexadecimal characters.
func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// RemoveTemp deletes the leftover temporary file file of tenant tid, the
// [Entry.File] of a KindTemp entry returned by [Store.List]. file must have
// the exact temporary name format of the atomic writes, otherwise
// RemoveTemp fails with ErrInvalid before touching the file system. A
// missing file is not an error, so RemoveTemp is idempotent.
func (s *Store) RemoveTemp(tid tenant.ID, file string) error {
	if tid.Validate() != nil {
		return fmt.Errorf("%w: tenant id", ErrInvalid)
	}
	name, kind := classify(file)
	if kind != KindTemp {
		return fmt.Errorf("%w: temporary file name", ErrInvalid)
	}
	return s.removeIfExists("remove temporary file", filepath.Join(string(tid), file), name)
}

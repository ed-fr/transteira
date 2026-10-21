package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Errors returned by the store. Callers test them with errors.Is.
var (
	// ErrInvalid reports a malformed tenant identifier or storage name, an
	// oversized checkpoint or state, or an entry that is not a regular file.
	ErrInvalid = errors.New("storage: invalid argument")
	// ErrNotFound reports a missing file, checkpoint or state.
	ErrNotFound = errors.New("storage: not found")
	// ErrExists reports a file that already exists.
	ErrExists = errors.New("storage: already exists")
)

const (
	// DirMode is the permission of tenant directories (and of dataDir when
	// New creates it).
	DirMode fs.FileMode = 0o750
	// FileMode is the permission of stored files and checkpoints.
	FileMode fs.FileMode = 0o640
	// MaxCheckpointSize bounds the size of a checkpoint. A sealed crypto
	// State carries the pending partial chunk (up to the chunk size minus one
	// byte, 64 KiB by default) plus the caller's extra data (at most 1 KiB)
	// and a small fixed overhead, so the bound is twice the default chunk
	// size. internal/upload checks that its worst case fits.
	MaxCheckpointSize = 128 << 10

	// MaxStateSize bounds the size of a state file. The download layer keeps
	// in it the byte ranges already served per file of a transfer, merged
	// into disjoint intervals; it checks that its encoding fits.
	MaxStateSize = 64 << 10

	// NameLen is the length of a storage name: 128 bits in lowercase hex.
	NameLen = 32

	fileExt  = ".ttef"
	ckptExt  = ".ckpt"
	stateExt = ".dlstate"
	tmpExt   = ".tmp"
)

// openRoot opens the data directory; tests replace it to cover its failure,
// which cannot be provoked once MkdirAll has succeeded.
var openRoot = os.OpenRoot

// ops are the file system primitives used by the Store. They default to
// the os.Root and *os.File methods; tests replace them to inject faults so
// that every error branch is covered on every platform.
type ops struct {
	openFile func(name string, flag int, perm fs.FileMode) (*os.File, error)
	mkdir    func(name string, perm fs.FileMode) error
	remove   func(name string) error
	rename   func(oldname, newname string) error
	stat     func(f *os.File) (fs.FileInfo, error)
	seek     func(f *os.File, offset int64, whence int) (int64, error)
	write    func(f *os.File, b []byte) (int, error)
	sync     func(f *os.File) error
	close    func(f *os.File) error
	readAll  func(r io.Reader) ([]byte, error)
	statPath func(name string) (fs.FileInfo, error)
	sleep    func(d time.Duration)
}

// Store gives confined access to the files of every tenant under one data
// directory. It is safe for concurrent use. Callers serialize operations on
// a given storage name (upload lock).
type Store struct {
	root *os.Root
	ops  ops
	// dirSync reports whether the platform supports fsync on directories.
	dirSync bool
	// renameRetries is the number of extra attempts of a checkpoint rename
	// refused because the target is open (Windows only, see renameRetryable).
	renameRetries int
}

// Rename retry policy of WriteCheckpoint on Windows.
const (
	// windowsRenameRetries is the number of extra rename attempts.
	windowsRenameRetries = 5
	// renameBackoff is the pause before each extra attempt.
	renameBackoff = 10 * time.Millisecond
)

// Windows error codes of a rename over a file another handle holds open
// (ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION).
const (
	errAccessDenied     syscall.Errno = 5
	errSharingViolation syscall.Errno = 32
)

// New opens the data directory dataDir, creating it with mode 0750 if it
// does not exist. dataDir must be an absolute path.
func New(dataDir string) (*Store, error) {
	if !filepath.IsAbs(dataDir) {
		return nil, fmt.Errorf("%w: data directory must be an absolute path", ErrInvalid)
	}
	if err := os.MkdirAll(dataDir, DirMode); err != nil {
		return nil, fmt.Errorf("storage: create data directory: %w", err)
	}
	root, err := openRoot(dataDir)
	if err != nil {
		return nil, fmt.Errorf("storage: open data directory: %w", err)
	}
	return &Store{
		root: root,
		ops: ops{
			openFile: root.OpenFile,
			mkdir:    root.Mkdir,
			remove:   root.Remove,
			rename:   root.Rename,
			stat:     (*os.File).Stat,
			seek:     (*os.File).Seek,
			write:    (*os.File).Write,
			sync:     (*os.File).Sync,
			close:    (*os.File).Close,
			readAll:  io.ReadAll,
			statPath: root.Stat,
			sleep:    time.Sleep,
		},
		dirSync:       runtime.GOOS != "windows",
		renameRetries: renameRetriesFor(runtime.GOOS),
	}, nil
}

// renameRetriesFor returns the number of extra checkpoint rename attempts
// on the platform goos.
func renameRetriesFor(goos string) int {
	if goos == "windows" {
		return windowsRenameRetries
	}
	return 0
}

// Close releases the data directory handle. Files already opened remain
// usable.
func (s *Store) Close() error { return s.root.Close() }

// NewName returns a new random storage name: 32 lowercase hexadecimal
// characters encoding 128 bits from crypto/rand.
func NewName() string {
	var b [NameLen / 2]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (it panics instead).
	return hex.EncodeToString(b[:])
}

// ValidName reports whether name is a well-formed storage name.
func ValidName(name string) bool {
	if len(name) != NameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// check validates the identifiers that make up a path.
func check(tid tenant.ID, name string) error {
	if tid.Validate() != nil {
		return fmt.Errorf("%w: tenant id", ErrInvalid)
	}
	if !ValidName(name) {
		return fmt.Errorf("%w: storage name", ErrInvalid)
	}
	return nil
}

// rel returns the path of a validated name with extension ext, relative to
// the data directory.
func rel(tid tenant.ID, name, ext string) string {
	return filepath.Join(string(tid), name+ext)
}

// wrap turns a file system error into a package error that never contains
// a path: path errors are unwrapped to their cause, and existence errors
// mapped to the package sentinels.
func wrap(op, name string, err error) error {
	prefix := "storage: " + op
	if name != "" {
		prefix += " " + name
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s: %w", prefix, ErrNotFound)
	case errors.Is(err, fs.ErrExist):
		return fmt.Errorf("%s: %w", prefix, ErrExists)
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		err = le.Err
	}
	return fmt.Errorf("%s: %w", prefix, err)
}

// ensureTenantDir creates the tenant directory if it does not exist.
func (s *Store) ensureTenantDir(tid tenant.ID) error {
	err := s.ops.mkdir(string(tid), DirMode)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return wrap("create tenant directory", "", err)
	}
	return nil
}

// Create creates a new, empty stored file for writing. It fails with
// ErrExists if the file already exists. The tenant directory is created on
// demand.
func (s *Store) Create(tid tenant.ID, name string) (*os.File, error) {
	if err := check(tid, name); err != nil {
		return nil, err
	}
	if err := s.ensureTenantDir(tid); err != nil {
		return nil, err
	}
	f, err := s.ops.openFile(rel(tid, name, fileExt), os.O_CREATE|os.O_EXCL|os.O_WRONLY, FileMode)
	if err != nil {
		return nil, wrap("create", name, err)
	}
	return f, nil
}

// openRegular opens an existing entry and checks that it is a regular file.
// It returns the file and its information.
func (s *Store) openRegular(op, path, name string, flag int) (*os.File, fs.FileInfo, error) {
	f, err := s.ops.openFile(path, flag, 0)
	if err != nil {
		return nil, nil, wrap(op, name, err)
	}
	info, err := s.ops.stat(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, wrap(op, name, err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("storage: %s %s: %w: not a regular file", op, name, ErrInvalid)
	}
	return f, info, nil
}

// OpenAppend opens an existing stored file for writing, positioned at its
// end, and returns its current size, to be passed as existingSize to
// crypto.ResumeWriter.
//
// The file is deliberately not opened with O_APPEND: the position is set
// once with Seek, so the returned size and the write position are the same
// value, and the descriptor stays usable with positional APIs.
func (s *Store) OpenAppend(tid tenant.ID, name string) (*os.File, int64, error) {
	if err := check(tid, name); err != nil {
		return nil, 0, err
	}
	f, info, err := s.openRegular("open for append", rel(tid, name, fileExt), name, os.O_WRONLY)
	if err != nil {
		return nil, 0, err
	}
	size := info.Size()
	if _, err := s.ops.seek(f, size, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, 0, wrap("open for append", name, err)
	}
	return f, size, nil
}

// OpenRead opens an existing stored file for reading and returns its size.
// The *os.File implements io.ReadSeekCloser and io.ReaderAt (for
// crypto.NewReaderAt).
func (s *Store) OpenRead(tid tenant.ID, name string) (*os.File, int64, error) {
	if err := check(tid, name); err != nil {
		return nil, 0, err
	}
	f, info, err := s.openRegular("open", rel(tid, name, fileExt), name, os.O_RDONLY)
	if err != nil {
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// removeIfExists removes path, treating a missing entry as success.
func (s *Store) removeIfExists(op, path, name string) error {
	if err := s.ops.remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return wrap(op, name, err)
	}
	return nil
}

// Remove deletes a stored file and its checkpoint. Missing entries are not
// an error, so Remove is idempotent. It never removes a state file, even
// one of the same name: states are removed with [Store.RemoveState].
// Following threat model T-110, callers destroy the file key in the
// database before calling Remove.
func (s *Store) Remove(tid tenant.ID, name string) error {
	if err := check(tid, name); err != nil {
		return err
	}
	ckptErr := s.removeIfExists("remove checkpoint", rel(tid, name, ckptExt), name)
	fileErr := s.removeIfExists("remove", rel(tid, name, fileExt), name)
	return errors.Join(fileErr, ckptErr)
}

// WriteCheckpoint atomically replaces the checkpoint of name with data
// (at most MaxCheckpointSize bytes): after a crash, either the previous or
// the new checkpoint is present, never a partial one. The temporary file is
// removed on any failure.
func (s *Store) WriteCheckpoint(tid tenant.ID, name string, data []byte) error {
	return s.writeAtomic("write checkpoint", tid, name, ckptExt, data, MaxCheckpointSize)
}

// writeAtomic atomically replaces the entry name+ext of tenant tid with
// data, at most maxSize bytes: temporary file created with O_EXCL in the
// same directory, fsync, rename over the entry, then fsync of the
// directory. The temporary file is removed on any failure. op names the
// operation in errors.
func (s *Store) writeAtomic(op string, tid tenant.ID, name, ext string, data []byte, maxSize int) error {
	if err := check(tid, name); err != nil {
		return err
	}
	if len(data) > maxSize {
		return fmt.Errorf("storage: %s %s: %w: too large", op, name, ErrInvalid)
	}
	if err := s.ensureTenantDir(tid); err != nil {
		return err
	}
	var suffix [8]byte
	_, _ = rand.Read(suffix[:]) // never fails
	tmp := rel(tid, name, ext+"."+hex.EncodeToString(suffix[:])+tmpExt)

	f, err := s.ops.openFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, FileMode)
	if err != nil {
		return wrap(op, name, err)
	}
	err = s.writeSyncClose(f, data)
	if err == nil {
		err = s.rename(tmp, rel(tid, name, ext))
	}
	if err != nil {
		_ = s.ops.remove(tmp)
		return wrap(op, name, err)
	}
	return s.SyncDir(tid)
}

// rename renames oldname over newname. On Windows, replacing a file that
// another handle holds open (a concurrent ReadCheckpoint or ReadState) fails with
// ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION: the rename is then
// retried up to renameRetries times, renameBackoff apart.
func (s *Store) rename(oldname, newname string) error {
	err := s.ops.rename(oldname, newname)
	for i := 0; i < s.renameRetries && renameRetryable(err); i++ {
		s.ops.sleep(renameBackoff)
		err = s.ops.rename(oldname, newname)
	}
	return err
}

// renameRetryable reports whether a failed rename may succeed once the
// other handles on the target are closed.
func renameRetryable(err error) bool {
	return errors.Is(err, errAccessDenied) || errors.Is(err, errSharingViolation)
}

// writeSyncClose writes data to f, flushes it to stable storage and closes
// it. f is closed in every case.
func (s *Store) writeSyncClose(f *os.File, data []byte) error {
	_, err := s.ops.write(f, data)
	if err == nil {
		err = s.ops.sync(f)
	}
	if cerr := s.ops.close(f); err == nil {
		err = cerr
	}
	return err
}

// ReadCheckpoint returns the checkpoint of name and its modification time,
// which is the last activity of the upload (used for its expiration). It
// fails with ErrNotFound when there is no checkpoint and with ErrInvalid
// when it exceeds MaxCheckpointSize.
func (s *Store) ReadCheckpoint(tid tenant.ID, name string) ([]byte, time.Time, error) {
	return s.readBounded("read checkpoint", tid, name, ckptExt, MaxCheckpointSize)
}

// readBounded returns the content of the entry name+ext of tenant tid and
// its modification time. It fails with ErrNotFound when the entry is
// missing and with ErrInvalid when it is not a regular file or exceeds
// maxSize bytes. op names the operation in errors.
func (s *Store) readBounded(op string, tid tenant.ID, name, ext string, maxSize int) ([]byte, time.Time, error) {
	if err := check(tid, name); err != nil {
		return nil, time.Time{}, err
	}
	f, info, err := s.openRegular(op, rel(tid, name, ext), name, os.O_RDONLY)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() { _ = f.Close() }()
	data, err := s.ops.readAll(io.LimitReader(f, int64(maxSize)+1))
	if err != nil {
		return nil, time.Time{}, wrap(op, name, err)
	}
	if len(data) > maxSize {
		return nil, time.Time{}, fmt.Errorf("storage: %s %s: %w: too large", op, name, ErrInvalid)
	}
	return data, info.ModTime(), nil
}

// CheckpointModTime returns the modification time of the checkpoint of
// name (the last activity of its upload) without opening it, so that it
// never holds a handle a concurrent WriteCheckpoint would have to wait for.
// It fails with ErrNotFound when there is no checkpoint and with ErrInvalid
// when the entry is not a regular file.
func (s *Store) CheckpointModTime(tid tenant.ID, name string) (time.Time, error) {
	if err := check(tid, name); err != nil {
		return time.Time{}, err
	}
	info, err := s.ops.statPath(rel(tid, name, ckptExt))
	if err != nil {
		return time.Time{}, wrap("checkpoint time", name, err)
	}
	if !info.Mode().IsRegular() {
		return time.Time{}, fmt.Errorf("storage: checkpoint time %s: %w: not a regular file", name, ErrInvalid)
	}
	return info.ModTime(), nil
}

// RemoveCheckpoint deletes the checkpoint of name. A missing checkpoint is
// not an error.
func (s *Store) RemoveCheckpoint(tid tenant.ID, name string) error {
	if err := check(tid, name); err != nil {
		return err
	}
	return s.removeIfExists("remove checkpoint", rel(tid, name, ckptExt), name)
}

// stateDomain prefixes the key hashed by StateName, so that a state name
// can never coincide with another hash of the same key.
const stateDomain = "transteira.storage.state\x00"

// StateName returns the storage name of the state file of the server
// generated identifier key (for example a transfer ID): the first 128 bits,
// in lowercase hex, of the SHA-256 of key under a fixed domain prefix. It is
// deterministic, so that every request on the same transfer finds the same
// state, and always a valid storage name, so that the state goes through
// the same path checks as every other entry. The name is not secret (it
// derives from an identifier the server already knows); it only gives a key
// of any shape a confined, fixed-format file name. A state file and a
// stored file of the same name are distinct entries (different
// extensions): [Store.Remove] never touches a state file, and
// [Store.RemoveState] never touches a stored file or checkpoint.
func StateName(key string) string {
	sum := sha256.Sum256([]byte(stateDomain + key))
	return hex.EncodeToString(sum[:NameLen/2])
}

// WriteState atomically replaces the state file of name with data (at most
// MaxStateSize bytes), exactly as [Store.WriteCheckpoint] does for
// checkpoints: after a crash, either the previous or the new state is
// present, never a partial one. name is a storage name, normally obtained
// with [StateName]. The download layer keeps the byte ranges served for a
// transfer in it, written at most once per request; callers serialize the
// writes of a given state (read-modify-write).
func (s *Store) WriteState(tid tenant.ID, name string, data []byte) error {
	return s.writeAtomic("write state", tid, name, stateExt, data, MaxStateSize)
}

// ReadState returns the state file of name. It fails with ErrNotFound when
// there is none and with ErrInvalid when it is not a regular file or
// exceeds MaxStateSize.
func (s *Store) ReadState(tid tenant.ID, name string) ([]byte, error) {
	data, _, err := s.readBounded("read state", tid, name, stateExt, MaxStateSize)
	return data, err
}

// RemoveState deletes the state file of name. A missing state is not an
// error, so RemoveState is idempotent. It removes neither a stored file nor
// a checkpoint of the same name.
func (s *Store) RemoveState(tid tenant.ID, name string) error {
	if err := check(tid, name); err != nil {
		return err
	}
	return s.removeIfExists("remove state", rel(tid, name, stateExt), name)
}

// Sync flushes the content of f, obtained from this Store, to stable
// storage. Callers sync a stored file before writing its checkpoint.
func (s *Store) Sync(f *os.File) error {
	if err := s.ops.sync(f); err != nil {
		return wrap("sync", "", err)
	}
	return nil
}

// SyncDir flushes the tenant directory entries (creations, renames,
// removals) to stable storage. It is a no-op on Windows, which does not
// support fsync on directories, and on file systems that report it as
// unsupported (EINVAL).
func (s *Store) SyncDir(tid tenant.ID) error {
	if tid.Validate() != nil {
		return fmt.Errorf("%w: tenant id", ErrInvalid)
	}
	if !s.dirSync {
		return nil
	}
	d, err := s.ops.openFile(string(tid), os.O_RDONLY, 0)
	if err != nil {
		return wrap("sync directory", "", err)
	}
	err = s.ops.sync(d)
	_ = d.Close()
	if err != nil && !errors.Is(err, syscall.EINVAL) {
		return wrap("sync directory", "", err)
	}
	return nil
}

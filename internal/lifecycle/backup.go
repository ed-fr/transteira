package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store"
)

// Names of the database copies in Options.BackupDir.
const (
	// backupStamp is the UTC time format of the copy names.
	backupStamp = "20060102T150405Z"
	// backupDirMode and backupFileMode restrict the copies to the service
	// account: they hold the wrapped keys of the files.
	backupDirMode  = 0o700
	backupFileMode = 0o600
)

var (
	// sqliteDriver is the database/sql driver of SQLite (modernc.org/sqlite,
	// registered by the store); a variable so that the tests can make
	// sql.Open fail.
	sqliteDriver = config.DriverSQLite
	// backupName matches the name of a finished copy.
	backupName = regexp.MustCompile(`^transteira-\d{8}T\d{6}Z\.db$`)
	// backupTemp matches the name of a copy being written, or of a journal
	// file its check may have left (even once the copy itself is gone).
	backupTemp = regexp.MustCompile(`^\.transteira-\d{8}T\d{6}Z\.db\.tmp(-wal|-shm|-journal)?$`)
	// errBackupDirSymlink reports a backup directory that is a symbolic
	// link.
	errBackupDirSymlink = errors.New("is a symbolic link")
	// errBackupDirNotDir reports a backup path that is not a directory.
	errBackupDirNotDir = errors.New("is not a directory")
)

// backupFS is the file system of TaskBackup; the tests replace its
// functions to inject failures.
type backupFS struct {
	lstat       func(path string) (fs.FileInfo, error)
	mkdirAll    func(path string, perm fs.FileMode) error
	createEmpty func(path string) error
	chmod       func(path string, perm fs.FileMode) error
	rename      func(from, to string) error
	remove      func(path string) error
	readDir     func(path string) ([]fs.DirEntry, error)
	syncFile    func(path string) error
	syncDir     func(path string) error
	checkCopy   func(ctx context.Context, path string) error
	// restrictDir tells whether the mode of an existing backup directory is
	// checked and restricted (Unix; Windows has no such permission bits).
	restrictDir bool
}

// osFS returns the real file system of TaskBackup.
func osFS() backupFS {
	return backupFS{
		lstat: os.Lstat, mkdirAll: os.MkdirAll, createEmpty: createEmpty, chmod: os.Chmod, rename: os.Rename,
		remove: os.Remove, readDir: os.ReadDir, syncFile: syncFile, syncDir: syncDir, checkCopy: quickCheck,
		restrictDir: runtime.GOOS != "windows",
	}
}

// createEmpty creates the empty file path with mode backupFileMode, failing
// when it exists: the copy is then written into it, so that it is never
// readable by others, whatever the process umask.
func createEmpty(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, backupFileMode) //nolint:gosec // TT_BACKUP_DIR joined with a generated name
	if err != nil {
		return err
	}
	return f.Close()
}

// syncFile flushes the content of the file at path to stable storage.
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // TT_BACKUP_DIR joined with a generated name
	if err != nil {
		return err
	}
	err = f.Sync()
	return errors.Join(err, f.Close())
}

// quickCheck opens the SQLite database at path without writing to it and
// runs PRAGMA quick_check, which must answer "ok". The DSN is the plain
// path followed by the driver's query string: a path holding "?" or "#"
// could change its meaning, so it is refused (TT_BACKUP_DIR rejects both
// characters, and the file name is generated).
func quickCheck(ctx context.Context, path string) error {
	if strings.ContainsAny(path, "?#") {
		return fmt.Errorf("unsafe copy path %q", path)
	}
	db, err := sql.Open(sqliteDriver, path+"?_pragma=query_only(1)")
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	var res string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&res); err != nil {
		return err
	}
	return checkResult(res)
}

// checkResult returns an error unless res, the first row of PRAGMA
// quick_check, is "ok".
func checkResult(res string) error {
	if res != "ok" {
		return fmt.Errorf("quick_check reported %q", res)
	}
	return nil
}

// backup is TaskBackup, with SQLite (spec 23): the backup directory is
// checked (see prepareBackupDir), a temporary file is created empty with
// mode 0600, VACUUM INTO fills it, PRAGMA quick_check checks the copy,
// then fsync, atomic rename to transteira-YYYYMMDDTHHMMSSZ.db and fsync of
// the directory; then only the newest Options.BackupKeep copies are kept
// (never the one just written), and the temporary files left by an
// interrupted copy are removed. On failure the temporary file is removed
// and the error returned (logged as an ERROR by the scheduler). The copy
// runs under ctx: Close interrupts it.
func (s *Sweeper) backup(ctx context.Context) error {
	switch {
	case s.backupDir == "":
		return ErrBackupDisabled
	case !s.repo.backupSupported():
		return fmt.Errorf("lifecycle: backup: %w", store.ErrBackupUnsupported)
	}
	dir := s.backupDir
	if err := s.prepareBackupDir(ctx, dir); err != nil {
		return err
	}
	stamp := s.now().UTC().Format(backupStamp)
	tmp := filepath.Join(dir, ".transteira-"+stamp+".db.tmp")
	final := filepath.Join(dir, "transteira-"+stamp+".db")
	if err := s.writeCopy(ctx, tmp, final); err != nil {
		s.removeTemp(tmp)
		return fmt.Errorf("lifecycle: backup: %w", err)
	}
	if err := s.fs.syncDir(dir); err != nil {
		return fmt.Errorf("lifecycle: backup: sync the directory: %w", err)
	}
	s.logger.InfoContext(ctx, "lifecycle: database copy written", slog.String("file", filepath.Base(final)))
	return s.rotate(dir, filepath.Base(final))
}

// prepareBackupDir checks the backup directory dir on every run: it is
// created with mode 0700 when missing; a symbolic link, or anything but a
// directory, is refused; on Unix, a directory accessible to its group or
// to others is restricted to mode 0700, since the copies hold the wrapped
// keys of the files.
func (s *Sweeper) prepareBackupDir(ctx context.Context, dir string) error {
	fi, err := s.fs.lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := s.fs.mkdirAll(dir, backupDirMode); err != nil {
			return fmt.Errorf("lifecycle: create the backup directory: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("lifecycle: backup directory: %w", err)
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("lifecycle: backup directory %w", errBackupDirSymlink)
	case !fi.IsDir():
		return fmt.Errorf("lifecycle: backup directory %w", errBackupDirNotDir)
	case s.fs.restrictDir && fi.Mode().Perm()&0o077 != 0:
		if err := s.fs.chmod(dir, backupDirMode); err != nil {
			return fmt.Errorf("lifecycle: restrict the backup directory: %w", err)
		}
		s.logger.WarnContext(ctx, "lifecycle: backup directory restricted to mode 0700",
			slog.String("mode", fi.Mode().Perm().String()))
	}
	return nil
}

// writeCopy writes the checked copy at tmp, then renames it to final.
func (s *Sweeper) writeCopy(ctx context.Context, tmp, final string) error {
	s.removeTemp(tmp) // a leftover of a crash within the same second
	if err := s.fs.createEmpty(tmp); err != nil {
		return fmt.Errorf("create the copy: %w", err)
	}
	if err := s.repo.backup(ctx, tmp); err != nil {
		return err
	}
	if err := s.fs.chmod(tmp, backupFileMode); err != nil {
		return fmt.Errorf("restrict the copy: %w", err)
	}
	if err := s.fs.checkCopy(ctx, tmp); err != nil {
		return fmt.Errorf("check the copy: %w", err)
	}
	if err := s.fs.syncFile(tmp); err != nil {
		return fmt.Errorf("sync the copy: %w", err)
	}
	if err := s.fs.rename(tmp, final); err != nil {
		return fmt.Errorf("rename the copy: %w", err)
	}
	return nil
}

// removeTemp removes the temporary copy tmp and the journal files its check
// may have left, ignoring the missing ones.
func (s *Sweeper) removeTemp(tmp string) {
	for _, p := range []string{tmp, tmp + "-wal", tmp + "-shm", tmp + "-journal"} {
		_ = s.fs.remove(p)
	}
}

// tempBase returns the name of the temporary copy that the temporary file
// name (matching backupTemp) belongs to.
func tempBase(name string) string {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		name = strings.TrimSuffix(name, suffix)
	}
	return name
}

// rotate keeps the newest Options.BackupKeep copies of dir, fresh (the copy
// just written) always among them, even when the clock stepped backwards
// and older-looking names sort after it; it removes the older copies and
// the temporary files left by an interrupted copy, journal files included.
// It only touches the names matching backupName and backupTemp.
func (s *Sweeper) rotate(dir, fresh string) error {
	entries, err := s.fs.readDir(dir)
	if err != nil {
		return fmt.Errorf("lifecycle: backup rotation: %w", err)
	}
	var copies []string
	var errs []error
	for _, e := range entries {
		switch name := e.Name(); {
		case !e.Type().IsRegular():
		case name == fresh:
		case backupName.MatchString(name):
			copies = append(copies, name)
		case backupTemp.MatchString(name):
			s.removeTemp(filepath.Join(dir, tempBase(name)))
		}
	}
	// The names sort by date; the newest come last. fresh takes one of the
	// BackupKeep places.
	slices.Sort(copies)
	for len(copies) > s.backupKeep-1 {
		if err := s.fs.remove(filepath.Join(dir, copies[0])); err != nil {
			errs = append(errs, err)
		}
		copies = copies[1:]
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("lifecycle: backup rotation: %w", err)
	}
	return nil
}

// nextBackupDelay returns the delay until the next run of TaskBackup.
func (s *Sweeper) nextBackupDelay() time.Duration {
	now := s.now()
	return nextBackup(now, s.backupTime).Sub(now)
}

package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// backupEnv returns a SQLite env whose sweeper writes its copies to a new
// directory (not created yet), keeping keep copies.
func backupEnv(t *testing.T, keep int) (*env, string) {
	t.Helper()
	ev := newEnv(t, storetest.SQLite(t))
	dir := filepath.Join(t.TempDir(), "backups")
	ev.s = ev.newSweeper(Options{BackupDir: dir, BackupKeep: keep})
	return ev, dir
}

// names returns the sorted names of the entries of dir.
func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

func TestBackup(t *testing.T) {
	ev, dir := backupEnv(t, 2)
	ev.available(ev.a, 1, false)
	ev.runTask(TaskBackup)
	name := "transteira-" + ev.clock.Now().UTC().Format(backupStamp) + ".db"
	if got := names(t, dir); !slices.Equal(got, []string{name}) {
		t.Fatalf("backup directory = %v", got)
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]fs.FileMode{dir: backupDirMode, filepath.Join(dir, name): backupFileMode} {
			if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
				t.Fatalf("mode of %s = %v, %v; want %v", path, fi.Mode().Perm(), err, want)
			}
		}
	}
	// The copy reopens, passes quick_check and holds the data.
	path := filepath.Join(dir, name)
	if err := quickCheck(context.Background(), path); err != nil {
		t.Fatalf("quick_check of the copy: %v", err)
	}
	db, err := sql.Open(sqliteDriver, path+"?_pragma=query_only(1)")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	err = db.QueryRow("SELECT count(*) FROM transfers").Scan(&n)
	_ = db.Close()
	if err != nil || n != 1 {
		t.Fatalf("transfers in the copy = %d, %v", n, err)
	}
	if ev.logs.count("database copy written file="+name) != 1 {
		t.Fatalf("logs:\n%s", ev.logs.all())
	}

	// Rotation: older copies, a stale temporary file, unrelated entries.
	for _, f := range []string{
		"transteira-20260101T000000Z.db", "transteira-20250101T000000Z.db",
		".transteira-20260102T000000Z.db.tmp", ".transteira-20260102T000000Z.db.tmp-wal",
		// Journal files whose temporary copy is already gone.
		".transteira-20260103T000000Z.db.tmp-shm", ".transteira-20260104T000000Z.db.tmp-journal",
		// An interrupted manual copy and its journal.
		".transteira-20260105T000000Z-manual.db.tmp", ".transteira-20260105T000000Z-manual.db.tmp-wal",
		".transteira-20260106T000000Z-manual.db.tmp-journal",
		"notes.txt", "transteira-latest.db",
	} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "transteira-20240101T000000Z.db"), 0o700); err != nil {
		t.Fatal(err)
	}
	ev.clock.set(ev.clock.Now().Add(24 * time.Hour))
	ev.runTask(TaskBackup)
	next := "transteira-" + ev.clock.Now().UTC().Format(backupStamp) + ".db"
	want := []string{name, next, "notes.txt", "transteira-20240101T000000Z.db", "transteira-latest.db"}
	slices.Sort(want)
	if got := names(t, dir); !slices.Equal(got, want) {
		t.Fatalf("after rotation = %v, want %v", got, want)
	}
}

func TestBackupUnavailable(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.s = ev.newSweeper(Options{BackupDir: t.TempDir()})
	ev.f.set("backupUnsupported", 1, nil)
	if err := ev.s.RunTask(context.Background(), TaskBackup); !errors.Is(err, store.ErrBackupUnsupported) {
		t.Fatalf("RunTask = %v, want ErrBackupUnsupported", err)
	}
	if pg, ok := storetest.Postgres(t); ok {
		ev := newEnv(t, pg)
		ev.s = ev.newSweeper(Options{BackupDir: t.TempDir()})
		if err := ev.s.RunTask(context.Background(), TaskBackup); !errors.Is(err, store.ErrBackupUnsupported) {
			t.Fatalf("RunTask on PostgreSQL = %v", err)
		}
	}
}

func TestBackupFailures(t *testing.T) {
	cases := []struct {
		name string
		set  func(ev *env, fsys *backupFS)
		// kept tells that the copy was written despite the error.
		kept bool
	}{
		{"mkdir", func(_ *env, f *backupFS) {
			f.mkdirAll = func(string, fs.FileMode) error { return errFault }
		}, false},
		{"lstat", func(_ *env, f *backupFS) {
			f.lstat = func(string) (fs.FileInfo, error) { return nil, errFault }
		}, false},
		{"create", func(_ *env, f *backupFS) {
			f.createEmpty = func(string) error { return errFault }
		}, false},
		{"vacuum", func(ev *env, _ *backupFS) { ev.f.set("backup", 1, nil) }, false},
		{"chmod", func(_ *env, f *backupFS) {
			f.chmod = func(string, fs.FileMode) error { return errFault }
		}, false},
		{"check", func(_ *env, f *backupFS) {
			f.checkCopy = func(context.Context, string) error { return errFault }
		}, false},
		{"sync", func(_ *env, f *backupFS) {
			f.syncFile = func(string) error { return errFault }
		}, false},
		{"rename", func(_ *env, f *backupFS) {
			f.rename = func(string, string) error { return errFault }
		}, false},
		{"sync dir", func(_ *env, f *backupFS) {
			f.syncDir = func(string) error { return errFault }
		}, true},
		{"read dir", func(_ *env, f *backupFS) {
			f.readDir = func(string) ([]fs.DirEntry, error) { return nil, errFault }
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, dir := backupEnv(t, 1)
			c.set(ev, &ev.s.fs)
			if err := ev.s.RunTask(context.Background(), TaskBackup); !errors.Is(err, errFault) {
				t.Fatalf("RunTask = %v", err)
			}
			got, _ := os.ReadDir(dir)
			if kept := len(got) == 1 && !strings.HasPrefix(got[0].Name(), "."); kept != c.kept || (!c.kept && len(got) != 0) {
				t.Fatalf("backup directory after the failure: %v", got)
			}
		})
	}
	t.Run("remove", func(t *testing.T) {
		ev, dir := backupEnv(t, 1)
		old := filepath.Join(dir, "transteira-20200101T000000Z.db")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(old, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		ev.s.fs.remove = func(p string) error {
			if p == old {
				return errFault
			}
			return os.Remove(p)
		}
		if err := ev.s.RunTask(context.Background(), TaskBackup); !errors.Is(err, errFault) {
			t.Fatalf("RunTask = %v", err)
		}
		if len(names(t, dir)) != 2 {
			t.Fatalf("backup directory = %v", names(t, dir))
		}
	})
}

func TestBackupHelpers(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")
	if err := syncFile(missing); err == nil {
		t.Fatal("syncFile of a missing file succeeded")
	}
	existing := filepath.Join(t.TempDir(), "copy.db.tmp")
	if err := createEmpty(existing); err != nil {
		t.Fatalf("createEmpty: %v", err)
	}
	if err := createEmpty(existing); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("createEmpty over an existing file = %v, want fs.ErrExist", err)
	}
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("syncDir: %v", err)
	}
	if err := checkResult("*** in database main ***"); err == nil {
		t.Fatal("checkResult accepted a corruption report")
	}
	notDB := filepath.Join(t.TempDir(), "not.db")
	if err := os.WriteFile(notDB, []byte(strings.Repeat("not a database ", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := quickCheck(context.Background(), notDB); err == nil {
		t.Fatal("quickCheck accepted a file that is not a database")
	}
}

// fakeInfo is a fs.FileInfo of a given mode.
type fakeInfo struct{ mode fs.FileMode }

func (fakeInfo) Name() string        { return "backups" }
func (fakeInfo) Size() int64         { return 0 }
func (i fakeInfo) Mode() fs.FileMode { return i.mode }
func (fakeInfo) ModTime() time.Time  { return time.Time{} }
func (i fakeInfo) IsDir() bool       { return i.mode.IsDir() }
func (fakeInfo) Sys() any            { return nil }

func TestBackupDirectory(t *testing.T) {
	t.Run("symbolic link", func(t *testing.T) {
		ev, dir := backupEnv(t, 1)
		target := t.TempDir()
		if err := os.Symlink(target, dir); err != nil {
			// No symlink privilege (Windows): the Lstat result is faked.
			ev.s.fs.lstat = func(string) (fs.FileInfo, error) { return fakeInfo{fs.ModeSymlink | 0o777}, nil }
		}
		if err := ev.s.RunTask(context.Background(), TaskBackup); !errors.Is(err, errBackupDirSymlink) {
			t.Fatalf("RunTask = %v, want errBackupDirSymlink", err)
		}
		if got := names(t, target); len(got) != 0 {
			t.Fatalf("copy written through the link: %v", got)
		}
	})
	t.Run("not a directory", func(t *testing.T) {
		ev, dir := backupEnv(t, 1)
		if err := os.WriteFile(dir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ev.s.RunTask(context.Background(), TaskBackup); !errors.Is(err, errBackupDirNotDir) {
			t.Fatalf("RunTask = %v, want errBackupDirNotDir", err)
		}
	})
	t.Run("open mode restricted", func(t *testing.T) {
		ev, dir := backupEnv(t, 1)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil { // whatever the umask
			t.Fatal(err)
		}
		ev.s.fs.restrictDir = true
		var chmodded []string
		chmod := ev.s.fs.chmod
		ev.s.fs.chmod = func(p string, m fs.FileMode) error {
			chmodded = append(chmodded, p)
			return chmod(p, m)
		}
		ev.runTask(TaskBackup)
		if len(chmodded) == 0 || chmodded[0] != dir {
			t.Fatalf("chmod calls = %v, want the directory first", chmodded)
		}
		if runtime.GOOS != "windows" {
			if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != backupDirMode {
				t.Fatalf("mode of the directory = %v, %v", fi.Mode().Perm(), err)
			}
		}
		if ev.logs.count("WARN lifecycle: backup directory restricted to mode 0700") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		// Already private: left alone.
		chmodded = nil
		ev.s.fs.lstat = func(string) (fs.FileInfo, error) { return fakeInfo{fs.ModeDir | 0o700}, nil }
		ev.clock.set(ev.clock.Now().Add(time.Hour))
		ev.runTask(TaskBackup)
		if slices.Contains(chmodded, dir) {
			t.Fatal("a private directory was chmodded")
		}
	})
	t.Run("restriction failure", func(t *testing.T) {
		ev, dir := backupEnv(t, 1)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		ev.s.fs.restrictDir = true
		ev.s.fs.lstat = func(string) (fs.FileInfo, error) { return fakeInfo{fs.ModeDir | 0o750}, nil }
		ev.s.fs.chmod = func(string, fs.FileMode) error { return errFault }
		if err := ev.s.RunTask(context.Background(), TaskBackup); !errors.Is(err, errFault) {
			t.Fatalf("RunTask = %v", err)
		}
		if got := names(t, dir); len(got) != 0 {
			t.Fatalf("copy written in an open directory: %v", got)
		}
	})
}

// TestBackupClockBackwards: the copy just written is never removed by the
// rotation, even when the clock stepped back and an older-looking copy
// sorts after it.
func TestBackupClockBackwards(t *testing.T) {
	ev, dir := backupEnv(t, 1)
	ev.runTask(TaskBackup)
	ev.clock.set(ev.clock.Now().Add(-24 * time.Hour))
	ev.runTask(TaskBackup)
	fresh := "transteira-" + ev.clock.Now().UTC().Format(backupStamp) + ".db"
	if got := names(t, dir); !slices.Equal(got, []string{fresh}) {
		t.Fatalf("backup directory = %v, want only the copy just written %s", got, fresh)
	}
}

// TestBackupErasedKeys (T-109): the copy taken after an erasure holds
// neither the destroyed wrapped keys nor any reference to them.
func TestBackupErasedKeys(t *testing.T) {
	ev, dir := backupEnv(t, 1)
	fx := ev.due(ev.a, 2)
	kept := ev.available(ev.b, 1, false)
	before, keptBefore := ev.get(fx), ev.get(kept)
	ev.sweep(stats{due: 1, erased: 1})
	ev.runTask(TaskBackup)

	path := filepath.Join(dir, "transteira-"+ev.clock.Now().UTC().Format(backupStamp)+".db")
	db, err := sql.Open(sqliteDriver, path+"?_pragma=query_only(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	destroyed := []string{before.DownloadTokenKeyID}
	for _, f := range before.Files {
		destroyed = append(destroyed, f.DEKKeyID)
	}
	for _, wk := range destroyed {
		if wk == "" {
			t.Fatal("fixture without key")
		}
		if n := count("SELECT count(*) FROM wrapped_keys WHERE id = ?", wk); n != 0 {
			t.Errorf("destroyed key %s present in the copy", wk)
		}
	}
	if n := count("SELECT count(*) FROM transfer_files WHERE transfer_id = ? AND dek_key_id IS NOT NULL", fx.id); n != 0 {
		t.Errorf("%d file key references of the erased transfer in the copy", n)
	}
	if n := count("SELECT count(*) FROM transfers WHERE id = ? AND download_token_key_id IS NULL", fx.id); n != 1 {
		t.Errorf("token key reference of the erased transfer in the copy")
	}
	// The keys of a live transfer are in the copy.
	if n := count("SELECT count(*) FROM wrapped_keys WHERE id = ?", keptBefore.Files[0].DEKKeyID); n != 1 {
		t.Errorf("live key missing from the copy")
	}
}

// TestQuickCheckFailures covers the refusal of an unsafe path and a
// failing sql.Open (the driver name is swapped; not parallel).
func TestQuickCheckFailures(t *testing.T) {
	for _, p := range []string{"/backups/copy.db?mode=rwc", "/backups/copy#.db"} {
		if err := quickCheck(context.Background(), p); err == nil || !strings.Contains(err.Error(), "unsafe") {
			t.Errorf("quickCheck(%q) = %v", p, err)
		}
	}
	saved := sqliteDriver
	sqliteDriver = "no-such-driver"
	defer func() { sqliteDriver = saved }()
	if err := quickCheck(context.Background(), filepath.Join(t.TempDir(), "copy.db")); err == nil {
		t.Fatal("quickCheck with an unknown driver succeeded")
	}
}

// TestBackupNow: a manual copy goes to the backup directory with the
// "-manual" marker and survives the rotation of the nightly copies.
func TestBackupNow(t *testing.T) {
	ev, dir := backupEnv(t, 1)
	ev.available(ev.a, 1, false)
	ctx := context.Background()
	path, err := ev.s.BackupNow(ctx, "")
	if err != nil {
		t.Fatalf("BackupNow: %v", err)
	}
	manual := "transteira-" + ev.clock.Now().UTC().Format(backupStamp) + "-manual.db"
	if path != filepath.Join(dir, manual) {
		t.Fatalf("BackupNow = %q, want %s in %s", path, manual, dir)
	}
	if err := quickCheck(ctx, path); err != nil {
		t.Fatalf("quick_check of the manual copy: %v", err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != backupFileMode {
			t.Fatalf("mode of the manual copy = %v, %v", fi.Mode().Perm(), err)
		}
	}
	if ev.logs.count("manual database copy written file="+manual) != 1 {
		t.Fatalf("logs:\n%s", ev.logs.all())
	}
	// Two nightly copies with TT_BACKUP_KEEP=1: the manual copy is kept.
	for range 2 {
		ev.clock.set(ev.clock.Now().Add(24 * time.Hour))
		ev.runTask(TaskBackup)
	}
	nightly := "transteira-" + ev.clock.Now().UTC().Format(backupStamp) + ".db"
	if got := names(t, dir); !slices.Equal(got, []string{manual, nightly}) {
		t.Fatalf("after rotation = %v, want %s and %s", got, manual, nightly)
	}
}

// TestBackupNowOut: a copy written at an explicit path, never over an
// existing file.
func TestBackupNowOut(t *testing.T) {
	ev, dir := backupEnv(t, 1)
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "before-upgrade.db")
	path, err := ev.s.BackupNow(ctx, out)
	if err != nil || path != out {
		t.Fatalf("BackupNow(out) = %q, %v", path, err)
	}
	if err := quickCheck(ctx, out); err != nil {
		t.Fatalf("quick_check of the copy: %v", err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != backupFileMode {
			t.Fatalf("mode of the copy = %v, %v", fi.Mode().Perm(), err)
		}
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the backup directory was touched: %v", err)
	}
	before, _ := os.ReadFile(out)
	if p, err := ev.s.BackupNow(ctx, out); !errors.Is(err, fs.ErrExist) || p != "" {
		t.Fatalf("BackupNow over an existing file = %q, %v, want \"\", fs.ErrExist", p, err)
	}
	if after, _ := os.ReadFile(out); !slices.Equal(before, after) {
		t.Fatal("the existing file was modified")
	}
	for _, bad := range []struct {
		out  string
		want error
	}{
		{"relative.db", errBackupOutRelative},
		{filepath.Join(t.TempDir(), "a?b.db"), errBackupOutUnsafe},
		{filepath.Join(t.TempDir(), "a#b.db"), errBackupOutUnsafe},
	} {
		if _, err := ev.s.BackupNow(ctx, bad.out); !errors.Is(err, bad.want) {
			t.Fatalf("BackupNow(%q) = %v, want %v", bad.out, err, bad.want)
		}
	}
}

func TestBackupNowFailures(t *testing.T) {
	t.Run("unsupported", func(t *testing.T) {
		ev, _ := backupEnv(t, 1)
		ev.f.set("backupUnsupported", 1, nil)
		if _, err := ev.s.BackupNow(context.Background(), ""); !errors.Is(err, store.ErrBackupUnsupported) {
			t.Fatalf("BackupNow = %v, want ErrBackupUnsupported", err)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		ev := newEnv(t, storetest.SQLite(t))
		ev.s = ev.newSweeper(Options{})
		if _, err := ev.s.BackupNow(context.Background(), ""); !errors.Is(err, ErrBackupDisabled) {
			t.Fatalf("BackupNow = %v, want ErrBackupDisabled", err)
		}
	})
	dirCases := []struct {
		name string
		set  func(ev *env, fsys *backupFS)
		// kept tells that the copy was written despite the error.
		kept bool
	}{
		{"lstat", func(_ *env, f *backupFS) {
			f.lstat = func(string) (fs.FileInfo, error) { return nil, errFault }
		}, false},
		{"vacuum", func(ev *env, _ *backupFS) { ev.f.set("backup", 1, nil) }, false},
		{"sync dir", func(_ *env, f *backupFS) {
			f.syncDir = func(string) error { return errFault }
		}, true},
	}
	for _, c := range dirCases {
		t.Run("dir "+c.name, func(t *testing.T) {
			ev, dir := backupEnv(t, 1)
			c.set(ev, &ev.s.fs)
			if _, err := ev.s.BackupNow(context.Background(), ""); !errors.Is(err, errFault) {
				t.Fatalf("BackupNow = %v", err)
			}
			got, _ := os.ReadDir(dir)
			if kept := len(got) == 1 && strings.HasSuffix(got[0].Name(), "-manual.db"); kept != c.kept || (!c.kept && len(got) != 0) {
				t.Fatalf("backup directory after the failure: %v", got)
			}
		})
	}
	outCases := []struct {
		name string
		set  func(ev *env, fsys *backupFS)
	}{
		{"create", func(_ *env, f *backupFS) {
			f.createEmpty = func(string) error { return errFault }
		}},
		{"vacuum", func(ev *env, _ *backupFS) { ev.f.set("backup", 1, nil) }},
		{"chmod", func(_ *env, f *backupFS) {
			f.chmod = func(string, fs.FileMode) error { return errFault }
		}},
		{"check", func(_ *env, f *backupFS) {
			f.checkCopy = func(context.Context, string) error { return errFault }
		}},
		{"sync", func(_ *env, f *backupFS) {
			f.syncFile = func(string) error { return errFault }
		}},
		{"sync dir", func(_ *env, f *backupFS) {
			f.syncDir = func(string) error { return errFault }
		}},
	}
	for _, c := range outCases {
		t.Run("out "+c.name, func(t *testing.T) {
			ev, _ := backupEnv(t, 1)
			c.set(ev, &ev.s.fs)
			outDir := t.TempDir()
			if _, err := ev.s.BackupNow(context.Background(), filepath.Join(outDir, "copy.db")); !errors.Is(err, errFault) {
				t.Fatalf("BackupNow = %v", err)
			}
			if got := names(t, outDir); len(got) != 0 {
				t.Fatalf("output directory after the failure: %v", got)
			}
		})
	}
}

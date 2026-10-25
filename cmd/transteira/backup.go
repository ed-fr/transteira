package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/store"
)

// postgresBackupHelp explains, with PostgreSQL, why the command does
// nothing and how to take a dump instead.
const postgresBackupHelp = `backup: the database is PostgreSQL: TransTeira does not copy it itself.
The dumps (pg_dump) are taken by the dedicated db-backup container of the
compose file, every night, into the backups volume. To take one now, for
example before an upgrade, run pg_dump in that container as it does
(--enable-row-security, system scope); see docs/operations/backup.md.
`

// absPath resolves --out and statFile reads the size of the copy;
// variables so that the tests can make them fail.
var (
	absPath  = filepath.Abs
	statFile = os.Stat
)

// runBackup writes an immediate, checked copy of a SQLite database (the
// same mechanism as the nightly copy): into TT_BACKUP_DIR, as
// transteira-<timestamp>-manual.db, which the rotation never deletes, or at
// the path given by --out, never overwritten. It prints the path and the
// size of the copy. It is safe while the server runs: VACUUM INTO reads a
// single snapshot of the WAL database. With PostgreSQL it explains how the
// dumps are made and exits with exitUsage.
func runBackup(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("backup", stderr)
	out := flags.String("out", "", "write the copy to this file (must not exist) instead of TT_BACKUP_DIR")
	if code, ok := parseFlags(flags, args, stderr); !ok {
		return code
	}
	cfg, err := config.FromEnvironment()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "backup: %v\n", err)
		return exitError
	}
	if cfg.DBDriver == config.DriverPostgres {
		_, _ = io.WriteString(stderr, postgresBackupHelp)
		return exitUsage
	}
	target := *out
	if target != "" {
		if target, err = absPath(target); err != nil {
			_, _ = fmt.Fprintf(stderr, "backup: %v\n", err)
			return exitError
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	path, err := backupDatabase(ctx, cfg, target, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "backup: %v\n", err)
		return exitError
	}
	fi, err := statFile(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "backup: %v\n", err)
		return exitError
	}
	if _, err := fmt.Fprintf(stdout, "Database copy written to %s (%d bytes).\n", path, fi.Size()); err != nil {
		_, _ = fmt.Fprintf(stderr, "backup: %v\n", err)
		return exitError
	}
	return exitOK
}

// backupDatabase opens the existing SQLite database of cfg, without
// migrating it, and writes the copy with lifecycle's BackupNow. Logs go to
// stderr.
func backupDatabase(ctx context.Context, cfg *config.Config, out string, stderr io.Writer) (string, error) {
	// Opening a missing SQLite file would create an empty database.
	if p := sqlitePath(cfg.DBDSN.Reveal()); fileMissing(p) {
		return "", fmt.Errorf("database %s does not exist", p)
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	db, err := store.Open(ctx, cfg, store.WithLogger(logger))
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()
	s := lifecycle.New(lifecycle.Deps{DB: db}, lifecycle.Options{
		BackupDir: cfg.BackupDir, BackupKeep: cfg.BackupKeep, Logger: logger,
	})
	path, err := s.BackupNow(ctx, out)
	if out != "" && errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("%s already exists: choose another file, it is never overwritten", out)
	}
	return path, err
}

// sqlitePath returns the file named by the SQLite DSN dsn (without the
// "file:" prefix and the query string).
func sqlitePath(dsn string) string {
	dsn = strings.TrimPrefix(dsn, "file:")
	if i := strings.IndexByte(dsn, '?'); i >= 0 {
		dsn = dsn[:i]
	}
	return dsn
}

// fileMissing reports whether path does not exist.
func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, fs.ErrNotExist)
}

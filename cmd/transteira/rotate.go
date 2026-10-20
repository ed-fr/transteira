package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
)

// rotateFlags are the options of rotate-master-key.
type rotateFlags struct {
	batch       int
	abandon     bool
	recoverFrom string
}

// runRotateMasterKey re-wraps every wrapped key from the master key of
// TT_MASTER_KEY_FILE to the one of TT_MASTER_KEY_NEW_FILE (see
// docs/operations/master-key.md). It opens the database like serve does,
// runs the startup key check, then the resumable rotation, printing its
// progress to stdout (logs go to stderr). SIGINT and SIGTERM interrupt it;
// running it again resumes the rotation.
//
// With -abandon it gives up the running rotation, when no key is wrapped
// under its target yet. With -recover-from it re-wraps the keys left under
// an old, retired master key (read from the given file by this command
// only) to the active key.
func runRotateMasterKey(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("rotate-master-key", stderr)
	var f rotateFlags
	fs.IntVar(&f.batch, "batch-size", masterkey.DefaultBatchSize, "number of keys re-wrapped per transaction")
	fs.BoolVar(&f.abandon, "abandon", false,
		"give up the running rotation: a clean-up rotation, or a rotation whose new key wraps nothing yet "+
			"(remove TT_MASTER_KEY_NEW_FILE and restart every process first)")
	fs.StringVar(&f.recoverFrom, "recover-from", "",
		"absolute path of an old, retired master key: re-wrap the keys left under it to the active key")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	switch {
	case f.batch <= 0:
		_, _ = fmt.Fprintln(stderr, "rotate-master-key: -batch-size must be positive")
		return exitUsage
	case f.abandon && f.recoverFrom != "":
		_, _ = fmt.Fprintln(stderr, "rotate-master-key: -abandon and -recover-from cannot be combined")
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := rotateMasterKey(ctx, f, stdout, stderr); err != nil {
		_, _ = fmt.Fprintf(stderr, "rotate-master-key: %v\n", err)
		return exitError
	}
	return exitOK
}

// rotateMasterKey runs the requested operation with the configuration of
// the environment.
func rotateMasterKey(ctx context.Context, f rotateFlags, stdout, stderr io.Writer) error {
	cfg, err := config.FromEnvironment()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	switch {
	case f.abandon:
		return abandonRotation(ctx, cfg, logger, stdout)
	case f.recoverFrom != "":
		return recoverKeys(ctx, cfg, f, logger, stdout)
	case cfg.MasterKeyNewFile == "":
		return masterkey.ErrNoNewKey
	}
	keys, err := masterkey.Load(cfg)
	if err != nil {
		return err
	}
	defer keys.Close()
	db, err := app.OpenDatabase(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if _, err := masterkey.Check(ctx, db, keys, nil, time.Now()); err != nil {
		return err
	}
	rot, err := masterkey.Rotate(ctx, db, keys, logger, options(f, stdout))
	if err != nil {
		return interrupted(rot, err)
	}
	_, err = fmt.Fprintf(stdout, "Rotation %s completed: %d key(s) re-wrapped from %s to %s.\n"+
		"Now set %s to the new key file, remove %s, restart, and update the vault (%s).\n",
		rot.ID, rot.RewrappedKeys, rot.FromKeyID, rot.ToKeyID,
		config.EnvMasterKeyFile, config.EnvMasterKeyNewFile, masterkey.DocLink)
	return err
}

// options returns the rotation options printing the progress to stdout,
// whatever the log level.
func options(f rotateFlags, stdout io.Writer) masterkey.Options {
	last := int64(-1)
	return masterkey.Options{
		BatchSize: f.batch,
		OnProgress: func(r store.Rotation) {
			if r.RewrappedKeys != last {
				last = r.RewrappedKeys
				_, _ = fmt.Fprintf(stdout, "Rotation %s: %d/%d key(s) re-wrapped\n", r.ID, r.RewrappedKeys, r.TotalKeys)
			}
		},
	}
}

// interrupted explains an interruption by a signal, which leaves the
// rotation resumable; other errors are returned as they are.
func interrupted(rot store.Rotation, err error) error {
	switch {
	case !errors.Is(err, context.Canceled):
		return err
	case rot.ID == "":
		return errors.New("interrupted before the rotation started: run the command again")
	}
	return fmt.Errorf("interrupted after %d key(s): run the command again to resume rotation %s",
		rot.RewrappedKeys, rot.ID)
}

// abandonRotation gives up the running rotation.
func abandonRotation(ctx context.Context, cfg *config.Config, logger *slog.Logger, stdout io.Writer) error {
	db, err := app.OpenDatabase(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	rot, err := masterkey.Abandon(ctx, db, time.Now())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Rotation %s from %s to %s abandoned; the active master key is unchanged.\n",
		rot.ID, rot.FromKeyID, rot.ToKeyID)
	return err
}

// recoverKeys re-wraps the keys left under the old key of -recover-from.
// The old key is loaded by this command only, never by the server, and
// follows the location rules of TT_MASTER_KEY_FILE.
func recoverKeys(ctx context.Context, cfg *config.Config, f rotateFlags, logger *slog.Logger, stdout io.Writer) error {
	path, err := cfg.CheckMasterKeyPath(f.recoverFrom)
	if err != nil {
		return fmt.Errorf("-recover-from: %w", err)
	}
	old, err := crypto.LoadMasterKey(path)
	if err != nil {
		return fmt.Errorf("-recover-from: %w", err)
	}
	defer old.Destroy()
	keys, err := masterkey.Load(cfg)
	if err != nil {
		return err
	}
	defer keys.Close()
	db, err := app.OpenDatabase(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	rot, err := masterkey.Recover(ctx, db, keys, old, logger, options(f, stdout))
	if err != nil {
		return interrupted(rot, err)
	}
	_, err = fmt.Fprintf(stdout, "Recovery %s completed: %d key(s) re-wrapped from the retired key %s to the active key %s.\n"+
		"Find out why keys were wrapped under the retired key (a process still running with it, an old backup), "+
		"then destroy the old key once no backup needs it (%s).\n",
		rot.ID, rot.RewrappedKeys, rot.FromKeyID, rot.ToKeyID, masterkey.DocLink)
	return err
}

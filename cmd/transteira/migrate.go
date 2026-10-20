package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"text/tabwriter"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store"
)

// runMigrate applies the pending schema migrations and prints the resulting
// status. With --status it only prints the status, without modifying the
// database.
func runMigrate(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("migrate", stderr)
	statusOnly := fs.Bool("status", false, "only print the migration status, without applying anything")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	cfg, err := config.FromEnvironment()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "migrate: %v\n", err)
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	db, err := store.Open(ctx, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "migrate: %v\n", err)
		return exitError
	}
	defer func() { _ = db.Close() }()

	if !*statusOnly {
		n, err := db.Migrate(ctx)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "migrate: %v\n", err)
			return exitError
		}
		_, _ = fmt.Fprintf(stdout, "Applied %d migration(s) on %s.\n\n", n, db.Driver())
	}
	st, err := db.Status(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "migrate: %v\n", err)
		return exitError
	}
	if err := printStatus(stdout, st); err != nil {
		_, _ = fmt.Fprintf(stderr, "migrate: %v\n", err)
		return exitError
	}
	return exitOK
}

// printStatus writes the migration status as an aligned table.
func printStatus(w io.Writer, st []store.MigrationStatus) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "VERSION\tNAME\tSTATE\tAPPLIED AT")
	for _, s := range st {
		applied := "-"
		if !s.AppliedAt.IsZero() {
			applied = s.AppliedAt.UTC().Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(tw, "%04d\t%s\t%s\t%s\n", s.Version, s.Name, s.State, applied)
	}
	return tw.Flush()
}

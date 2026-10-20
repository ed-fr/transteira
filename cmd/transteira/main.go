// Command transteira is the single TransTeira binary.
//
// It groups every server-side operation behind subcommands:
//
//	serve              Start the HTTP server (public, administration and API spaces).
//	migrate            Apply the versioned database schema migrations.
//	rotate-master-key  Re-encrypt the per-file keys with a new master key.
//	backup             Write a consistent copy of the database to the backup volume.
//	healthcheck        Probe the running server (Docker HEALTHCHECK without a shell).
//	version            Print the build version (--json for machine-readable output).
//	help               Show the usage summary.
//
// Exit codes are 0 (success), 1 (runtime error), 2 (usage error) and
// 3 (subcommand not implemented yet).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ed-fr/transteira/internal/version"
)

// Process exit codes returned by run.
const (
	// exitOK means the command completed successfully.
	exitOK = 0
	// exitError means the command failed at runtime.
	exitError = 1
	// exitUsage means the command line was invalid.
	exitUsage = 2
	// exitNotImplemented means the subcommand is declared but not available yet.
	exitNotImplemented = 3
)

// commandFunc runs a subcommand with its own arguments and returns an exit code.
type commandFunc func(args []string, stdout, stderr io.Writer) int

// command describes one subcommand of the binary.
type command struct {
	// name is the subcommand keyword typed on the command line.
	name string
	// summary is the one-line description shown in the usage listing.
	summary string
	// run executes the subcommand.
	run commandFunc
}

// commands returns the table of subcommands, in the order shown by the usage.
func commands() []command {
	return []command{
		{"serve", "Start the HTTP server", notImplemented("serve")},
		{"migrate", "Apply the database schema migrations (--status to only print them)", runMigrate},
		{"rotate-master-key", "Re-encrypt the per-file keys with a new master key", notImplemented("rotate-master-key")},
		{"backup", "Write a consistent copy of the database to the backup volume", notImplemented("backup")},
		{"healthcheck", "Probe the running server and exit non-zero when unhealthy", notImplemented("healthcheck")},
		{"version", "Print the build version (--json for JSON output)", runVersion},
		{"help", "Show this help", runHelp},
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches args to the matching subcommand and returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		return runHelp(nil, stdout, stderr)
	}
	name := args[0]
	for _, c := range commands() {
		if c.name == name {
			return c.run(args[1:], stdout, stderr)
		}
	}
	_, _ = fmt.Fprintf(stderr, "transteira: unknown command %q\n\n", name)
	usage(stderr)
	return exitUsage
}

// usage writes the list of subcommands to w.
func usage(w io.Writer) {
	cmds := commands()
	width := 0
	for _, c := range cmds {
		width = max(width, len(c.name))
	}
	var b strings.Builder
	b.WriteString("Usage: transteira <command> [flags]\n\nCommands:\n")
	for _, c := range cmds {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, c.name, c.summary)
	}
	b.WriteString("\nRun \"transteira <command> -h\" for the flags of a command.\n")
	_, _ = io.WriteString(w, b.String())
}

// runHelp prints the usage summary to stdout.
func runHelp(_ []string, stdout, _ io.Writer) int {
	usage(stdout)
	return exitOK
}

// newFlagSet returns a flag set for the named subcommand reporting to stderr.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("transteira "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseFlags parses args into fs. It returns ok=false with the exit code to
// use when parsing failed, help was requested or positional arguments remain.
func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) (code int, ok bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, false
		}
		return exitUsage, false
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "%s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		fs.Usage()
		return exitUsage, false
	}
	return exitOK, true
}

// runVersion prints the build information, as text or as JSON with --json.
func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("version", stderr)
	asJSON := fs.Bool("json", false, "print the build information as JSON")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	info := version.Get()
	var err error
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(info)
	} else {
		_, err = fmt.Fprintln(stdout, info.String())
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "version: %v\n", err)
		return exitError
	}
	return exitOK
}

// notImplemented returns a placeholder for a declared subcommand that reports
// it is not available yet. Its flags are still parsed so that -h works.
func notImplemented(name string) commandFunc {
	return func(args []string, _, stderr io.Writer) int {
		fs := newFlagSet(name, stderr)
		if code, ok := parseFlags(fs, args, stderr); !ok {
			return code
		}
		_, _ = fmt.Fprintf(stderr, "%s: not implemented yet\n", name)
		return exitNotImplemented
	}
}

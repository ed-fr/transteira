// Command transteira-cli is the TransTeira command-line client.
//
// It is a plain consumer of the public API (/api/v1) with an API token:
//
//	upload        Deposit files and folders as one transfer (tus, resumable
//	              across runs, optional end-to-end encryption).
//	download      Download the files of a link, including end-to-end
//	              encrypted transfers.
//	proof verify  Check a sealed proof of deposit or delivery.
//	config        "config check" resolves and reports the configuration,
//	              "config profiles" lists the profiles of the configuration file.
//	version       Print the build version.
//	help          Show the usage summary.
//
// Exit codes are 0 (success), 1 (failure), 2 (usage error) and 3 (the
// transfer was rejected by the antivirus). The behavior and the flags are
// described in docs/api/cli.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/term"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/version"
)

// Process exit codes returned by run.
const (
	// exitOK means the command completed successfully.
	exitOK = 0
	// exitError means the command failed.
	exitError = 1
	// exitUsage means the command line was invalid.
	exitUsage = 2
	// exitRejected means the transfer was rejected by the antivirus.
	exitRejected = 3
)

// prog is the program name used in messages.
const prog = "transteira-cli"

// Hooks replaced by the tests.
var (
	// newClient builds the HTTP client of a command.
	newClient = client.New
	// isTerminal reports whether a stream (an *os.File) is a terminal.
	isTerminal = func(v any) bool {
		fd, ok := fdOf(v)
		return ok && term.IsTerminal(fd)
	}
	// readPassword reads a line from the terminal without echo.
	readPassword = term.ReadPassword
)

// fdOf returns the file descriptor of v when it is an *os.File.
func fdOf(v any) (int, bool) {
	f, ok := v.(*os.File)
	if !ok {
		return -1, false
	}
	return int(f.Fd()), true
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	// Once the first Ctrl-C canceled the context, restore the default
	// behavior so that a second one kills the process.
	go func() { <-ctx.Done(); stop() }()
	code := runContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run is runContext without cancellation.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdin, stdout, stderr)
}

// commandFunc runs a subcommand with its own arguments and returns an exit code.
type commandFunc func(ctx context.Context, args []string, io streams) int

// streams groups the standard streams of a command.
type streams struct {
	in       io.Reader
	out, err io.Writer
}

// command describes one subcommand.
type command struct {
	name, summary string
	run           commandFunc
}

// commands returns the table of subcommands, in the order of the usage.
func commands() []command {
	return []command{
		{"upload", "Deposit files and folders as one transfer: upload [options] FILE|FOLDER...", runUpload},
		{"download", "Download a link: download [options] LINK|-  (\"-\" reads the link from the standard input)", runDownload},
		{"proof", "Check a sealed proof: proof verify FILE.pdf (--url URL | --keys-file FILE)", runProof},
		{"config", "config check (resolve and report the configuration), config profiles (list the profiles)", runConfig},
		{"version", "Print the build version (--json for JSON output)", runVersion},
		{"help", "Show this help", runHelp},
	}
}

// runContext dispatches args to the matching subcommand and returns the exit code.
func runContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	s := streams{in: stdin, out: stdout, err: stderr}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		return runHelp(ctx, nil, s)
	}
	for _, c := range commands() {
		if c.name == args[0] {
			return c.run(ctx, args[1:], s)
		}
	}
	_, _ = fmt.Fprintf(stderr, "%s: unknown command %q\n\n", prog, args[0])
	usage(stderr)
	return exitUsage
}

// usage writes the list of subcommands to w.
func usage(w io.Writer) {
	var b strings.Builder
	b.WriteString("Usage: " + prog + " <command> [options]\n\nCommands:\n")
	for _, c := range commands() {
		fmt.Fprintf(&b, "  %-9s %s\n", c.name, c.summary)
	}
	b.WriteString("\nRun \"" + prog + " <command> -h\" for the options of a command.\n")
	_, _ = io.WriteString(w, b.String())
}

// runHelp prints the usage summary to stdout.
func runHelp(_ context.Context, _ []string, s streams) int {
	usage(s.out)
	return exitOK
}

// runVersion prints the build version.
func runVersion(_ context.Context, args []string, s streams) int {
	fs := newFlagSet("version", s.err)
	asJSON := fs.Bool("json", false, "print the build information as JSON")
	if _, code, ok := parseFlags(fs, args, 0, 0, s.err); !ok {
		return code
	}
	info := version.Get()
	if *asJSON {
		return printJSON(s, info)
	}
	_, _ = fmt.Fprintln(s.out, strings.Replace(info.String(), "transteira ", prog+" ", 1))
	return exitOK
}

// newFlagSet returns a flag set for the named subcommand reporting to stderr.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(prog+" "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseFlags parses args into fs, accepting flags after the positional
// arguments, and checks that between minArgs and maxArgs (negative: no
// limit) positional arguments remain. It returns the positional arguments,
// or ok=false with the exit code to use when parsing failed, help was
// requested or the count is wrong.
func parseFlags(fs *flag.FlagSet, args []string, minArgs, maxArgs int, stderr io.Writer) (rest []string, code int, ok bool) {
	args, tail := splitTerminator(fs, args)
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, exitOK, false
			}
			return nil, exitUsage, false
		}
		if fs.NArg() == 0 {
			break
		}
		rest = append(rest, fs.Arg(0))
		args = fs.Args()[1:]
	}
	rest = append(rest, tail...)
	if len(rest) < minArgs || (maxArgs >= 0 && len(rest) > maxArgs) {
		_, _ = fmt.Fprintf(stderr, "%s: wrong number of arguments\n", fs.Name())
		fs.Usage()
		return nil, exitUsage, false
	}
	return rest, exitOK, true
}

// fail prints a command error and returns the exit code.
func fail(s streams, err error) int {
	_, _ = fmt.Fprintf(s.err, "%s: %s\n", prog, err)
	return exitError
}

// usageError prints a usage error and returns the usage exit code.
func usageError(s streams, format string, a ...any) int {
	_, _ = fmt.Fprintf(s.err, "%s: %s\n", prog, fmt.Sprintf(format, a...))
	return exitUsage
}

// splitTerminator splits args at the first "--" that is not the value of a
// flag: what follows is positional whatever it looks like.
func splitTerminator(fs *flag.FlagSet, args []string) (head, tail []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return args[:i], args[i+1:]
		}
		name := strings.TrimLeft(a, "-")
		if !strings.HasPrefix(a, "-") || strings.Contains(a, "=") || name == "" {
			continue
		}
		if fl := fs.Lookup(name); fl != nil {
			if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
				i++ // the next argument is the value of the flag
			}
		}
	}
	return args, nil
}

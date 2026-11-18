package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/secret"
)

// Hooks replaced by the tests.
var (
	// secretCreate is secret.Create.
	secretCreate = secret.Create
	// secretRead is secret.Read.
	secretRead = secret.Read
)

// secretUsage is the synopsis of the secret commands.
const secretUsage = "Usage: " + prog + " secret create [options] [-] < TEXT\n" +
	"       " + prog + " secret create [options] --file FILE\n" +
	"       " + prog + " secret read [options] LINK|-\n"

// secretCreateTextNote explains the text rule of secret create, which the
// example scripts of the integration guide do not share.
const secretCreateTextNote = "The text is sent without its leading UTF-8 byte order mark and its final line break,\n" +
	"unless --raw is given. The example scripts of the integration guide send the input\n" +
	"byte for byte: use --raw for a text prepared for them, or read by them.\n"

// runSecret implements "secret create" and "secret read".
func runSecret(ctx context.Context, args []string, s streams) int {
	if len(args) > 0 {
		switch args[0] {
		case "create":
			return runSecretCreate(ctx, args[1:], s)
		case "read":
			return runSecretRead(ctx, args[1:], s)
		}
	}
	_, _ = io.WriteString(s.err, secretUsage)
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" {
		return usageError(s, "unknown secret command %q", args[0])
	}
	return exitUsage
}

// secretCreateFlags holds the flags of secret create.
type secretCreateFlags struct {
	conn                   connFlags
	file, expires          string
	anonymous, raw, asJSON bool
}

// secretCreateJSON is the --json output of secret create.
type secretCreateJSON struct {
	ID        string    `json:"id"`
	Link      string    `json:"link"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// runSecretCreate implements "secret create": the text comes from the
// standard input or --file, never from an argument (threat T-406), and only
// the link is printed on the standard output.
func runSecretCreate(ctx context.Context, args []string, s streams) int {
	var f secretCreateFlags
	fs := newFlagSet("secret create", s.err)
	f.conn.add(fs, false)
	fs.StringVar(&f.file, "file", "", "read the text from this file (readable by you only) instead of the standard input")
	fs.StringVar(&f.expires, "expires", secret.DefaultDuration, "lifetime of the secret if nobody reads it: "+secret.DurationList)
	fs.BoolVar(&f.anonymous, "anonymous", false, "send no API token, even when one is configured")
	fs.BoolVar(&f.raw, "raw", false, "send the input byte for byte (by default a leading UTF-8 byte order mark and one final line break are dropped)")
	fs.BoolVar(&f.asJSON, "json", false, "print {id, link, expiresAt} as JSON instead of the link alone")
	fs.Usage = func() {
		_, _ = io.WriteString(s.err, secretUsage+secretCreateTextNote)
		fs.PrintDefaults()
	}
	rest, code, ok := parseFlags(fs, args, 0, -1, s.err)
	if !ok {
		return code
	}
	// "-" names the standard input, the default; anything else would be
	// the text itself.
	stdin := len(rest) == 1 && rest[0] == "-"
	switch {
	case len(rest) > 0 && !stdin:
		return usageError(s, "the text is never taken from the command line (shell history, process list): "+
			"pipe it on the standard input or use --file")
	case stdin && f.file != "":
		return usageError(s, "use only one of - (standard input) and --file")
	case !secret.ValidDuration(f.expires):
		return usageError(s, "invalid --expires %q: use %s", f.expires, secret.DurationList)
	case f.anonymous && f.conn.tokenFile != "":
		return usageError(s, "use only one of --anonymous and --token-file")
	}
	c, err := f.client(s)
	if err != nil {
		return fail(s, err)
	}
	text, err := f.readText(s)
	if err != nil {
		return fail(s, err)
	}
	created, err := secretCreate(ctx, c, secret.CreateOptions{Text: text, Duration: f.expires, Anonymous: f.anonymous})
	if err != nil {
		return failSecret(ctx, s, err, "no link was printed: run the command again (a new key is drawn)")
	}
	return f.report(s, created)
}

// client builds the client of secret create: the API token of the
// configuration is optional, and dropped with --anonymous.
func (f *secretCreateFlags) client(s streams) (*client.Client, error) {
	cfg, err := client.Load(f.conn.loadOptions(false))
	if err != nil {
		return nil, err
	}
	if f.anonymous {
		cfg.Token = ""
	}
	return newClient(cfg, f.conn.clientOptions(s)...)
}

// readText reads the text from --file or the standard input.
func (f *secretCreateFlags) readText(s streams) (string, error) {
	if f.file != "" {
		return secret.ReadTextFile(f.file, f.raw)
	}
	if isTerminal(s.in) {
		_, _ = fmt.Fprintf(s.err, "Type the text of the secret, then press Ctrl-D on an empty line "+
			"(Ctrl-Z then Enter on Windows). At most %d characters.\n", secret.MaxTextRunes)
	}
	return secret.ReadText(s.in, f.raw)
}

// report prints the new secret: the link alone (or the JSON object) on the
// standard output, a reminder on the error output when it is a terminal.
func (f *secretCreateFlags) report(s streams, c *secret.Created) int {
	if f.asJSON {
		return printJSON(s, secretCreateJSON{ID: c.ID, Link: c.Link, ExpiresAt: c.ExpiresAt})
	}
	if _, err := fmt.Fprintln(s.out, c.Link); err != nil {
		return fail(s, fmt.Errorf("writing the link: %w (the secret %s cannot be read without it; it expires by itself)", err, c.ID))
	}
	if stderrIsTerminal(s) {
		how := "anonymously"
		if !c.Anonymous {
			how = "with the API token"
		}
		_, _ = fmt.Fprintf(s.err, "%s: express secret %s created %s; it can be read once, until %s.\n"+
			"%s: the link above is the secret itself: send it through a private channel, never by a public one.\n",
			prog, c.ID, how, c.ExpiresAt.Local().Format(time.RFC1123), prog)
	}
	return exitOK
}

// failSecret prints the failure of a secret command; an interruption says
// what may have happened on the server.
func failSecret(ctx context.Context, s streams, err error, interrupted string) int {
	if ctx.Err() != nil {
		return fail(s, fmt.Errorf("interrupted: %s", interrupted))
	}
	return fail(s, err)
}

// secretReadFlags holds the flags of secret read.
type secretReadFlags struct {
	conn   connFlags
	output string
	force  bool
}

// runSecretRead implements "secret read": the status first (nothing is
// consumed when the secret cannot be read here), then the one-time reveal;
// only the text is written on the standard output (or into --output).
func runSecretRead(ctx context.Context, args []string, s streams) int {
	var f secretReadFlags
	fs := newFlagSet("secret read", s.err)
	f.conn.add(fs, false)
	fs.StringVar(&f.output, "output", "", "write the text to this new file (mode 0600) instead of the standard output")
	fs.BoolVar(&f.force, "force", false, "with --output, replace an existing file")
	fs.Usage = func() {
		_, _ = io.WriteString(s.err, secretUsage)
		fs.PrintDefaults()
	}
	rest, code, ok := parseFlags(fs, args, 1, 1, s.err)
	if !ok {
		return code
	}
	if f.force && f.output == "" {
		return usageError(s, "--force needs --output")
	}
	raw, fromArgs := rest[0], rest[0] != "-"
	if !fromArgs {
		line, err := readLine(s.in)
		if err != nil {
			return usageError(s, "reading the link from the standard input: %v", err)
		}
		raw = line
	}
	link, err := secret.ParseLink(raw)
	if err != nil {
		return usageError(s, "%s", err)
	}
	if fromArgs {
		_, _ = fmt.Fprintf(s.err, "%s: warning: the link, key included, is visible in the process list of this machine "+
			"and in the shell history; pass it on the standard input with \"-\"\n", prog)
	}
	c, err := f.client(s, link)
	if err != nil {
		return fail(s, err)
	}
	// The output is created before any request: a secret is never consumed
	// for a file that cannot be written.
	out, err := openTextOutput(f.output, f.force)
	if err != nil {
		return fail(s, err)
	}
	rv, err := secretRead(ctx, c, link)
	if err != nil {
		out.abort()
		return failSecret(ctx, s, err, "if the reveal reached the server, the secret is consumed")
	}
	noticeRevealed(s, rv)
	return out.commit(s, rv.Text)
}

// client builds the client of secret read: the server is the origin of the
// link, and no API token is sent.
func (f *secretReadFlags) client(s streams, l secret.Link) (*client.Client, error) {
	lo := f.conn.loadOptions(false)
	lo.URL = l.Origin
	cfg, err := client.Load(lo)
	if err != nil {
		return nil, err
	}
	cfg.Token = ""
	return newClient(cfg, f.conn.clientOptions(s)...)
}

// noticeRevealed writes the notices of a revealed secret on the error
// output: an express secret is third-party content (threat T-397).
func noticeRevealed(s streams, rv *secret.Revealed) {
	if rv.Express {
		who := "anonymously, by a third party the entity did not verify"
		if !rv.Anonymous {
			who = "with an API token of the entity, by a third-party integration"
		}
		_, _ = fmt.Fprintf(s.err, "%s: note: this express secret was created %s: the entity is not its author. "+
			"Be wary of links and instructions in it; to report abuse, open the link in a browser.\n", prog, who)
	}
	if rv.FileLost {
		_, _ = fmt.Fprintf(s.err, "%s: warning: the secret also had a file, which this client cannot download: it is lost\n", prog)
	}
}

// textOutput is where secret read writes the text: the standard output, or
// a file created before the reveal (with --force, a temporary file renamed
// over the target at the end).
type textOutput struct {
	path string
	file *os.File
	temp bool
}

// openTextOutput prepares the output: nothing for the standard output; a
// new 0600 file (never replacing one) for path; a 0600 temporary file next
// to path with force.
func openTextOutput(path string, force bool) (*textOutput, error) {
	if path == "" {
		return &textOutput{}, nil
	}
	if !force {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the path is chosen by the user who runs the client
		switch {
		case errors.Is(err, fs.ErrExist):
			return nil, fmt.Errorf("%s already exists: choose another file, or add --force to replace it", path)
		case err != nil:
			return nil, fmt.Errorf("output file: %w", err)
		}
		return &textOutput{path: path, file: f}, nil
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return nil, fmt.Errorf("%s is a folder", path)
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return nil, fmt.Errorf("output file: %w", err)
	}
	return &textOutput{path: path, file: f, temp: true}, nil
}

// abort removes the file prepared by openTextOutput.
func (o *textOutput) abort() {
	if o.file != nil {
		_ = o.file.Close()
		_ = os.Remove(o.file.Name())
	}
}

// commit writes the text and returns the exit code. On a terminal the text
// goes through secret.TerminalSafe and is followed by a line break. If the
// file cannot be written, the text, which cannot be read again, is written
// on the standard output as a last resort.
func (o *textOutput) commit(s streams, text string) int {
	if o.file == nil {
		return writeText(s, text)
	}
	if err := o.writeFile(text); err != nil {
		o.abort()
		_, _ = fmt.Fprintf(s.err, "%s: writing %s: %v; the secret is consumed, so its text follows on the standard output\n", prog, o.path, err)
		writeText(s, text)
		return exitError
	}
	return exitOK
}

// writeFile writes, flushes and closes the file, then renames a temporary
// file over the target.
func (o *textOutput) writeFile(text string) error {
	if _, err := o.file.WriteString(text); err != nil {
		return err
	}
	if err := o.file.Sync(); err != nil {
		return err
	}
	if err := o.file.Close(); err != nil {
		return err
	}
	if o.temp {
		return os.Rename(o.file.Name(), o.path)
	}
	return nil
}

// writeText writes the text on the standard output: exactly as revealed
// for a pipe or a file, made safe and ended by a line break on a terminal.
func writeText(s streams, text string) int {
	if isTerminal(s.out) {
		safe, changed := secret.TerminalSafe(text)
		if changed {
			_, _ = fmt.Fprintf(s.err, "%s: warning: the text holds control or bidirectional characters, shown escaped "+
				"(such as \\x1b); use --output FILE for the exact text\n", prog)
		}
		if !strings.HasSuffix(safe, "\n") {
			safe += "\n"
		}
		text = safe
	}
	if _, err := io.WriteString(s.out, text); err != nil {
		return fail(s, fmt.Errorf("writing the text: %w (the secret is consumed)", err))
	}
	return exitOK
}

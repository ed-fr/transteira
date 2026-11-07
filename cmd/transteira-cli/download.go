package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/download"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// downloadRun is download.Run, replaceable in tests.
var downloadRun = download.Run

// downloadFlags holds the flags of the download command.
type downloadFlags struct {
	conn                   connFlags
	output                 string
	files                  stringList
	archive, force, asJSON bool
	passwordFile           string
	passwordPrompt         bool
	keyFile                string
}

// runDownload implements "download".
func runDownload(ctx context.Context, args []string, s streams) int {
	var f downloadFlags
	fs := newFlagSet("download", s.err)
	f.conn.add(fs, false)
	fs.StringVar(&f.output, "output", ".", "folder to write into")
	fs.Var(&f.files, "file", "download only this file (name, path or identifier); repeatable")
	fs.BoolVar(&f.archive, "archive", false, "download the server-built ZIP instead of the files")
	fs.BoolVar(&f.force, "force", false, "overwrite existing files")
	fs.StringVar(&f.passwordFile, "password-file", "", "file holding the transfer password")
	fs.BoolVar(&f.passwordPrompt, "password-prompt", false, "ask the transfer password at the terminal, without echo (the default when it is needed)")
	fs.StringVar(&f.keyFile, "key-file", "", "file holding the end-to-end key")
	fs.BoolVar(&f.asJSON, "json", false, "print the result as JSON")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(s.err, "Usage: %s download [options] LINK|-\n", prog)
		fs.PrintDefaults()
	}
	rest, code, ok := parseFlags(fs, args, 1, 1, s.err)
	if !ok {
		return code
	}
	if f.passwordFile != "" && f.passwordPrompt {
		return usageError(s, "use only one of --password-file and --password-prompt")
	}
	raw := rest[0]
	if raw == "-" {
		line, err := readLine(s.in)
		if err != nil {
			return usageError(s, "reading the link from the standard input: %v", err)
		}
		raw = line
	} else if strings.Contains(raw, "#k=") {
		_, _ = fmt.Fprintf(s.err, "%s: warning: the key in the link is visible in the process list of this machine; "+
			"pass the link on the standard input with \"-\" or the key with --key-file\n", prog)
	}
	link, err := download.ParseLink(raw)
	if err != nil {
		return usageError(s, "%s", err)
	}
	opts := download.Options{
		Link: link, Output: f.output, Files: f.files.values, Archive: f.archive, Force: f.force,
	}
	if err := f.secrets(s, &opts); err != nil {
		return fail(s, err)
	}
	c, err := f.client(s, link)
	if err != nil {
		return fail(s, err)
	}
	if stderrIsTerminal(s) {
		pp := newProgressPrinter(s.err, 2*time.Second)
		opts.Progress = func(p download.Progress) { pp.print(p.File, p.Done, p.Total) }
	}
	opts.Warn = func(m string) { _, _ = fmt.Fprintf(s.err, "%s: warning: %s\n", prog, textsafe.SanitizeMessage(m)) }
	res, err := downloadRun(ctx, c, opts)
	if err != nil {
		if res != nil && !f.asJSON {
			printDownloadText(s, res, false)
		}
		if ctx.Err() != nil {
			_, _ = fmt.Fprintf(s.err, "%s: interrupted; partial files are kept: run the same command again to resume\n", prog)
			return exitError
		}
		return fail(s, err)
	}
	return f.report(s, res)
}

// readLine reads one line (at most download.MaxLinkBytes) from r.
func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, download.MaxLinkBytes+2)).ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", errors.New("no link given")
	}
	return strings.TrimSpace(line), nil
}

// secrets installs the password, code and key sources in opts.
func (f *downloadFlags) secrets(s streams, opts *download.Options) error {
	var password string
	if f.passwordFile != "" {
		pw, err := readSecretFile(f.passwordFile, "password")
		if err != nil {
			return err
		}
		password = pw
	}
	// A password file gives the same answer every time: stop at the
	// first refusal instead of burning the other attempts.
	opts.PasswordOnce = f.passwordFile != ""
	opts.Password = func() (string, error) {
		if f.passwordFile != "" {
			return password, nil
		}
		return promptSecret(s, "Transfer password", "--password-file")
	}
	opts.Code = func(masked string) (string, error) {
		return promptSecret(s, "Verification code sent to "+textsafe.SanitizeMessage(masked), "a terminal (the code cannot be given by option)")
	}
	opts.Key = func() (string, error) {
		return promptSecret(s, "End-to-end key", "--key-file or the link on the standard input")
	}
	if f.keyFile != "" {
		key, err := readSecretFile(f.keyFile, "key")
		if err != nil {
			return err
		}
		// The key file takes precedence over the fragment of the link; a
		// transfer served unencrypted is then refused (downgrade).
		opts.Link.Key, opts.Link.FromFragment = "", false
		opts.KeyProvided = true
		opts.Key = func() (string, error) { return key, nil }
	}
	return nil
}

// client builds the client of a download: the origin of the link when it has
// one, else the URL of the flags, the environment or the profile. No token
// is needed, and none is sent.
func (f *downloadFlags) client(s streams, link download.Link) (*client.Client, error) {
	lo := f.conn.loadOptions(false)
	if link.Origin != "" {
		lo.URL = link.Origin
	}
	cfg, err := client.Load(lo)
	if err != nil {
		return nil, err
	}
	cfg.Token = ""
	return newClient(cfg, f.conn.clientOptions(s)...)
}

// downloadJSON is the --json output of download.
type downloadJSON struct {
	Sender    string             `json:"sender,omitempty"`
	Message   string             `json:"message,omitempty"`
	ExpiresAt *time.Time         `json:"expiresAt,omitempty"`
	EndToEnd  bool               `json:"endToEnd"`
	Archive   string             `json:"archive,omitempty"`
	Files     []downloadFileJSON `json:"files"`
}

// downloadFileJSON is one file of the --json output of download.
type downloadFileJSON struct {
	ID         string `json:"id,omitempty"`
	Path       string `json:"path,omitempty"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256,omitempty"`
	ScanStatus string `json:"scanStatus,omitempty"`
	Skipped    bool   `json:"skipped,omitempty"`
}

// report prints a finished download.
func (f *downloadFlags) report(s streams, res *download.Result) int {
	warnScans(s, res)
	if !f.asJSON {
		printDownloadText(s, res, true)
		return exitOK
	}
	out := downloadJSON{
		Sender: res.Sender, Message: res.Message, EndToEnd: res.EndToEnd, Archive: res.Archive,
		Files: make([]downloadFileJSON, 0, len(res.Files)),
	}
	if !res.ExpiresAt.IsZero() {
		out.ExpiresAt = &res.ExpiresAt
	}
	for _, fr := range res.Files {
		out.Files = append(out.Files, downloadFileJSON{
			ID: fr.ID, Path: fr.Path, Size: fr.Size, SHA256: fr.SHA256,
			ScanStatus: fr.ScanStatus, Skipped: fr.Skipped,
		})
	}
	return printJSON(s, out)
}

// warnScans warns about every downloaded file the antivirus did not clear.
func warnScans(s streams, res *download.Result) {
	for _, fr := range res.Files {
		if fr.Skipped {
			continue
		}
		if w := scanWarning(fr.ScanStatus); w != "" {
			_, _ = fmt.Fprintf(s.err, "%s: warning: %s: %s\n", prog, textsafe.SanitizeMessage(fr.Path), w)
		}
	}
}

// printDownloadText writes the human readable result. In archive mode only
// the ZIP is written: the files and digests announced by the server are
// "Listed", not checked by the client. After a failure (complete false) the
// file lines are left out: the result does not say which files were
// written before the error.
func printDownloadText(s streams, res *download.Result, complete bool) {
	w := s.out
	if res.Sender != "" {
		_, _ = fmt.Fprintf(w, "From: %s\n", res.Sender)
	}
	if res.Message != "" {
		_, _ = fmt.Fprintf(w, "Message:\n%s\n", res.Message)
	}
	if res.Archive != "" {
		_, _ = fmt.Fprintf(w, "Archive: %s\n", res.Archive)
	}
	if !complete {
		return
	}
	for _, fr := range res.Files {
		verb, name := "Written", fr.Path
		switch {
		case fr.Skipped:
			verb = "Skipped"
		case res.Archive != "" || fr.Path == "":
			verb = "Listed"
		}
		if name == "" {
			name = fr.ID
		}
		_, _ = fmt.Fprintf(w, "%s: %s  %s  sha256:%s\n", verb, textsafe.SanitizeMessage(name), humanSize(fr.Size), fr.SHA256)
	}
}

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/upload"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// uploadRun is upload.Run, replaceable in tests.
var uploadRun = upload.Run

// uploadFlags holds the flags of the upload command.
type uploadFlags struct {
	conn                                    connFlags
	to                                      stringList
	from, message, messageFile              string
	expiry, maxDownloads                    int
	deleteAfter, verify, linkOnly, e2e      bool
	level, language, chunk, stateFile       string
	passwordFile                            string
	passwordPrompt, restart, noWait, asJSON bool
	keyOut                                  string
	keyWritten                              bool
}

// runUpload implements "upload".
func runUpload(ctx context.Context, args []string, s streams) int {
	f := uploadFlags{to: stringList{split: true}}
	fs := newFlagSet("upload", s.err)
	f.conn.add(fs, true)
	fs.Var(&f.to, "to", "recipient address; repeat it or separate addresses with commas")
	fs.StringVar(&f.from, "from", "", "sender address (overrides --sender, "+client.EnvSender+" and the profile)")
	fs.StringVar(&f.message, "message", "", "message to the recipients")
	fs.StringVar(&f.messageFile, "message-file", "", "file holding the message to the recipients")
	fs.IntVar(&f.expiry, "expiry", 7, "days of validity: 1, 7 or 30")
	fs.BoolVar(&f.deleteAfter, "delete-after-download", false, "delete the transfer after its first download")
	fs.IntVar(&f.maxDownloads, "max-downloads", 0, "maximum number of downloads (0: no limit)")
	fs.BoolVar(&f.verify, "verify-recipients", false, "each recipient gets a personal link and confirms the address by code")
	fs.StringVar(&f.level, "level", "", "confidentiality level key of the entity")
	fs.BoolVar(&f.linkOnly, "link-only", false, "send no mail; print the link to pass on yourself")
	fs.BoolVar(&f.e2e, "e2e", false, "end-to-end encryption")
	fs.StringVar(&f.keyOut, "key-out", "", "with --e2e, write the key to this new file (mode 0600) instead of printing it")
	fs.StringVar(&f.passwordFile, "password-file", "", "file holding the transfer password")
	fs.BoolVar(&f.passwordPrompt, "password-prompt", false, "ask the transfer password at the terminal, without echo")
	fs.StringVar(&f.language, "language", "", "language of the mails")
	fs.StringVar(&f.chunk, "chunk-size", "", "bytes per PATCH request: 100MiB (default), 1GiB, or a number of bytes")
	fs.StringVar(&f.stateFile, "state-file", "", "resume state file (default ./.transteira-upload-<hash>.json)")
	fs.BoolVar(&f.restart, "restart", false, "abandon the unfinished transfer of the state file and start again")
	fs.BoolVar(&f.noWait, "no-wait", false, "return once the files are sent, without waiting for the antivirus verdict")
	fs.BoolVar(&f.asJSON, "json", false, "print the result as JSON")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(s.err, "Usage: %s upload [options] FILE|FOLDER...\n", prog)
		fs.PrintDefaults()
	}
	paths, code, ok := parseFlags(fs, args, 1, -1, s.err)
	if !ok {
		return code
	}
	opts, err := f.options(s, paths)
	if err != nil {
		return usageError(s, "%s", err)
	}
	cfg, err := client.Load(f.conn.loadOptions(true))
	if err != nil {
		return fail(s, err)
	}
	c, err := newClient(cfg, f.conn.clientOptions(s)...)
	if err != nil {
		return fail(s, err)
	}
	if f.keyOut != "" {
		// Fail before sending anything when the key file cannot be created.
		if err := createKeyFile(f.keyOut); err != nil {
			if errors.Is(err, os.ErrExist) {
				return usageError(s, "%s already exists: --key-out never overwrites a file", f.keyOut)
			}
			return fail(s, err)
		}
		// An empty key file left by a failed or rejected upload is removed.
		defer func() {
			if !f.keyWritten {
				_ = os.Remove(f.keyOut)
			}
		}()
	}
	if stderrIsTerminal(s) {
		pp := newProgressPrinter(s.err, 2*time.Second)
		opts.Progress = func(p upload.Progress) {
			label := p.Phase
			if p.File != "" {
				label += " " + p.File
			}
			pp.print(label, p.Done, p.Total)
		}
	}
	opts.Warn = func(m string) { _, _ = fmt.Fprintf(s.err, "%s: warning: %s\n", prog, textsafe.SanitizeMessage(m)) }
	res, err := uploadRun(ctx, c, opts)
	if err != nil {
		return f.reportError(ctx, s, res, err)
	}
	return f.report(s, res, true)
}

// stderrIsTerminal reports whether the error output is a terminal.
func stderrIsTerminal(s streams) bool { return isTerminal(s.err) }

// options builds the upload options from the flags.
func (f *uploadFlags) options(s streams, paths []string) (upload.Options, error) {
	o := upload.Options{
		Paths: paths, Recipients: f.to.values, Sender: f.from, ExpiryDays: f.expiry,
		DeleteAfterFirstDownload: f.deleteAfter, VerifyRecipients: f.verify, LinkOnly: f.linkOnly, E2E: f.e2e,
		MaxDownloads: f.maxDownloads, Level: f.level, Language: f.language,
		StatePath: f.stateFile, Restart: f.restart, NoWait: f.noWait,
	}
	if f.message != "" && f.messageFile != "" {
		return o, errors.New("use only one of --message and --message-file")
	}
	o.Message = f.message
	if f.message != "" && f.e2e {
		_, _ = fmt.Fprintf(s.err, "%s: warning: --message is visible in the process list and the shell history; use --message-file for a confidential message\n", prog)
	}
	if f.messageFile != "" {
		msg, err := readMessageFile(f.messageFile)
		if err != nil {
			return o, err
		}
		o.Message = msg
	}
	if f.chunk != "" {
		n, err := parseSize(f.chunk)
		if err != nil {
			return o, err
		}
		o.ChunkSize = n
	}
	if f.keyOut != "" && !f.e2e {
		return o, errors.New("--key-out needs --e2e")
	}
	if f.passwordFile != "" && f.passwordPrompt {
		return o, errors.New("use only one of --password-file and --password-prompt")
	}
	switch {
	case f.passwordFile != "":
		pw, err := readSecretFile(f.passwordFile, "password")
		if err != nil {
			return o, err
		}
		o.Password, o.HasPassword = pw, true
	case f.passwordPrompt:
		pw, err := promptSecret(s, "Transfer password", "--password-file")
		if err != nil {
			return o, err
		}
		again, err := promptSecret(s, "Transfer password (again)", "--password-file")
		if err != nil {
			return o, err
		}
		if pw != again {
			return o, errors.New("the two passwords differ")
		}
		o.Password, o.HasPassword = pw, true
	}
	return o, nil
}

// reportError prints a failed upload (and what was sent, when known) and
// returns the exit code.
func (f *uploadFlags) reportError(ctx context.Context, s streams, res *upload.Result, err error) int {
	switch {
	case errors.Is(err, upload.ErrRejected):
		if res != nil {
			f.report(s, res, false)
		}
		_, _ = fmt.Fprintf(s.err, "%s: %s\n", prog, err)
		return exitRejected
	case errors.Is(err, upload.ErrInvalidOptions):
		return usageError(s, "%s", err)
	case ctx.Err() != nil:
		_, _ = fmt.Fprintf(s.err, "%s: interrupted; the state is kept: run the same command again to resume\n", prog)
		return exitError
	case errors.Is(err, upload.ErrStateMismatch):
		return fail(s, fmt.Errorf("%w; run again with --restart to abandon the unfinished transfer and start a new one", err))
	}
	return fail(s, err)
}

// uploadJSON is the --json output of upload.
type uploadJSON struct {
	TransferID string           `json:"transferId"`
	Status     string           `json:"status"`
	ExpiresAt  *time.Time       `json:"expiresAt,omitempty"`
	Link       string           `json:"link,omitempty"`
	Key        string           `json:"key,omitempty"`
	KeyFile    string           `json:"keyFile,omitempty"`
	Files      []uploadFileJSON `json:"files"`
}

// uploadFileJSON is one file of the --json output of upload.
type uploadFileJSON struct {
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	ScanStatus string `json:"scanStatus"`
}

// scanWarning returns the warning for a scan status, or "" when clean or
// still pending.
func scanWarning(status string) string {
	switch status {
	case "", "clean", "pending", "scanning":
		return ""
	case "infected":
		return "a virus was found: the file was deleted"
	case "scan_error":
		return "the antivirus could not analyze this file"
	case "not_scanned_too_large":
		return "NOT SCANNED: the file is too large for the antivirus"
	case "not_scanned_e2e":
		return "NOT SCANNED: end-to-end encrypted, the server cannot read it"
	case "not_scanned_disabled":
		return "NOT SCANNED: the antivirus is disabled"
	}
	return "scan status: " + textsafe.SanitizeMessage(status)
}

// report prints the result; writeKey is false for a rejected transfer.
func (f *uploadFlags) report(s streams, res *upload.Result, writeKey bool) int {
	if res == nil {
		return exitOK
	}
	link := res.Link
	key := res.Key
	keyFile := ""
	if key != "" && writeKey && f.keyOut != "" {
		if err := writeKeyFile(f.keyOut, key); err != nil {
			// Last resort, the transfer exists: show the key rather than losing it.
			_, _ = fmt.Fprintf(s.err, "%s: warning: %s; the key is printed instead\n", prog, err)
		} else {
			f.keyWritten = true
			keyFile, key = f.keyOut, ""
		}
	}
	if key != "" && !writeKey {
		key = ""
	}
	if f.linkOnly && link != "" && key != "" {
		link += "#k=" + key
		key = ""
	}
	if f.asJSON {
		out := uploadJSON{
			TransferID: res.TransferID, Status: res.Status, Link: link, Key: key, KeyFile: keyFile,
			Files: make([]uploadFileJSON, 0, len(res.Files)),
		}
		if !res.ExpiresAt.IsZero() {
			out.ExpiresAt = &res.ExpiresAt
		}
		for _, fr := range res.Files {
			out.Files = append(out.Files, uploadFileJSON{Name: fr.Name, Path: fr.Path, Size: fr.Size, SHA256: fr.SHA256, ScanStatus: fr.ScanStatus})
		}
		if code := printJSON(s, out); code != exitOK {
			return code
		}
	} else {
		printUploadText(s.out, res, link, key, keyFile)
	}
	for _, fr := range res.Files {
		if w := scanWarning(fr.ScanStatus); w != "" {
			_, _ = fmt.Fprintf(s.err, "%s: warning: %s: %s\n", prog, fr.Name, w)
		}
	}
	return exitOK
}

// printUploadText writes the human readable result.
func printUploadText(w io.Writer, res *upload.Result, link, key, keyFile string) {
	_, _ = fmt.Fprintf(w, "Transfer: %s\nStatus: %s\n", res.TransferID, textsafe.SanitizeMessage(res.Status))
	if !res.ExpiresAt.IsZero() {
		_, _ = fmt.Fprintf(w, "Expires: %s\n", res.ExpiresAt.Format(time.RFC3339))
	}
	_, _ = fmt.Fprintln(w, "Files:")
	for _, fr := range res.Files {
		name := fr.Name
		if fr.Path != "" {
			name = fr.Path + "/" + fr.Name
		}
		status := fr.ScanStatus
		if status == "" {
			status = "-"
		}
		_, _ = fmt.Fprintf(w, "  %s  %s  sha256:%s  scan:%s\n", name, humanSize(fr.Size), fr.SHA256, textsafe.SanitizeMessage(status))
	}
	if link != "" {
		_, _ = fmt.Fprintf(w, "Link: %s\n", link)
	}
	if keyFile != "" {
		_, _ = fmt.Fprintf(w, "Key written to %s: send it to the recipients through another channel (telephone, another messaging service).\n", keyFile)
	}
	if key != "" {
		_, _ = fmt.Fprintf(w, "Key: %s\nThis key is shown once. Send it to the recipients through another channel (telephone, another messaging service), never with the link.\n", key)
	}
}

// maxMessageBytes bounds the message file (5000 characters of up to 4 bytes).
const maxMessageBytes = 5000 * 4

// readMessageFile reads a message file, refusing one over maxMessageBytes.
func readMessageFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is chosen by the user
	if err != nil {
		return "", fmt.Errorf("message file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxMessageBytes+1))
	if err != nil {
		return "", fmt.Errorf("message file: %w", err)
	}
	if len(data) > maxMessageBytes {
		return "", fmt.Errorf("message file %s is too long (more than %d bytes)", path, maxMessageBytes)
	}
	return string(data), nil
}

// createKeyFile creates the empty key file with mode 0600; it never
// overwrites a file (os.ErrExist).
func createKeyFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the path is chosen by the user
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	return f.Close()
}

// writeKeyFile writes the key into the file created by createKeyFile.
func writeKeyFile(path, key string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // G304: the path is chosen by the user
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	if _, err := io.WriteString(f, key+"\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("key file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("key file %s: %w", path, err)
	}
	return nil
}

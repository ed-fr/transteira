package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/pdf"
	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/textsafe"
)

const (
	// keysFetchTimeout bounds the download of the public keys.
	keysFetchTimeout = 15 * time.Second
	// maxKeysBytes bounds the size of a public key list.
	maxKeysBytes = 1 << 20
	// keysPath is the path of the public keys on an instance.
	keysPath = "/api/v1/proof-keys"
)

// keysClient fetches the public keys; tests replace it to trust a test
// server certificate.
var keysClient = newKeysClient()

// newKeysClient returns the HTTP client of "proof verify --url": short
// timeout, and no redirect to a non-HTTPS address.
func newKeysClient() *http.Client {
	return &http.Client{
		Timeout: keysFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return checkKeysURL(req.URL)
		},
	}
}

// stdin is the input of the confirmation prompt; tests replace it.
var stdin io.Reader = os.Stdin

// stdinIsTerminal reports whether the confirmation can be asked; tests
// replace it.
var stdinIsTerminal = func() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// runProof dispatches "proof verify", "proof keys" and "proof retire-key".
func runProof(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "verify":
			return runProofVerify(args[1:], stdout, stderr)
		case "keys":
			return runProofKeys(args[1:], stdout, stderr)
		case "retire-key":
			return runProofRetireKey(args[1:], stdout, stderr)
		}
	}
	_, _ = fmt.Fprintln(stderr, "Usage: transteira proof <verify|keys|retire-key> [flags]\n\n"+
		"  verify      [--keys FILE | --url https://FQDN] [--json] <proof.pdf>  Verify a proof offline\n"+
		"  keys                                                              List the signing keys (database)\n"+
		"  retire-key  [--yes]                                               Retire the active signing key")
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		return exitOK
	}
	return exitUsage
}

// runProofVerify verifies a proof PDF against the public keys of an
// instance; it needs neither the database nor the master key.
func runProofVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("proof verify", stderr)
	keysFile := fs.String("keys", "", "file holding the saved answer of GET /api/v1/proof-keys")
	keysURL := fs.String("url", "", "https URL of the instance (https://FQDN), or of its proof keys")
	asJSON := fs.Bool("json", false, "print the verified statement as canonical JSON")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: transteira proof verify [--keys FILE | --url https://FQDN] [--json] <proof.pdf>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if (*keysFile == "") == (*keysURL == "") || fs.NArg() != 1 {
		fs.Usage()
		_, _ = fmt.Fprintln(stderr, "proof verify: give exactly one of --keys and --url, and one PDF file")
		return exitUsage
	}
	var keys []proof.PublicKey
	var err error
	if *keysFile != "" {
		keys, err = readKeysFile(*keysFile)
	} else {
		keys, err = fetchKeys(context.Background(), *keysURL)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof verify: public keys: %v\n", err)
		return exitError
	}
	st, data, err := verifyFile(fs.Arg(0), keys)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof verify: FAILED: %s\n", verifyMessage(err))
		return exitError
	}
	if *asJSON {
		_, err = stdout.Write(append(data, '\n'))
	} else {
		err = printStatement(stdout, st, data)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof verify: %v\n", err)
		return exitError
	}
	return exitOK
}

// verifyFile verifies the PDF at path and returns the statement and its
// canonical encoding.
func verifyFile(path string, keys []proof.PublicKey) (proof.Statement, []byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the file is chosen by the operator on the command line
	if err != nil {
		return proof.Statement{}, nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := proof.Verify(f, keys, proof.DefaultVerifyLimit)
	if err != nil {
		return proof.Statement{}, nil, err
	}
	data, err := st.Marshal()
	return st, data, err
}

// verifyMessage explains a verification error.
func verifyMessage(err error) string {
	switch {
	case errors.Is(err, pdf.ErrTooLarge):
		return "the file is too large to be a proof"
	case errors.Is(err, proof.ErrUnknownKey):
		return "the statement is signed by a key that is not among the public keys given (wrong instance, or an outdated key list): " + err.Error()
	case errors.Is(err, proof.ErrBadSignature):
		return "the signature does not match the statement: the document was altered, or is not from this instance"
	case errors.Is(err, proof.ErrKeyRetired):
		return "the statement postdates the retirement of its signing key: it must not be trusted"
	case errors.Is(err, proof.ErrInvalidProof):
		return "this is not a valid TransTeira proof: " + err.Error()
	}
	return err.Error()
}

// safeText renders s for the terminal: every character that could hide or
// reorder text (control, bidirectional, zero-width, invisible, unassigned
// or invalid UTF-8) becomes a visible escape such as \u202E, so that a
// signed name cannot visually spoof another one.
func safeText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, "\\x%02X", s[i])
		case textsafe.IsHidden(r) || r == '\n' || r == '\t' || (r != ' ' && !unicode.IsPrint(r)):
			if r > 0xFFFF {
				fmt.Fprintf(&b, "\\U%08X", r)
			} else {
				fmt.Fprintf(&b, "\\u%04X", r)
			}
		default:
			b.WriteRune(r)
		}
		i += n
	}
	return b.String()
}

// printStatement prints the verified fields of st, never the visible text
// of the PDF, then the SHA-256 of the signed statement. Every field is
// escaped by [safeText]; --json prints the canonical bytes unchanged.
func printStatement(w io.Writer, st proof.Statement, data []byte) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	q := safeText
	sum := sha256.Sum256(data)
	p("OK: signature valid")
	p("Only the fields below, read from the verified statement, are authoritative; do not rely on the text shown by a PDF viewer.")
	p("Kind:               %s", q(string(st.Kind)))
	p("Transfer:           %s", q(st.TransferID))
	p("Entity:             %s (%s)", q(st.Tenant.Name), q(st.Tenant.FQDN))
	p("Sender:             %s", q(st.SenderEmail))
	recipients := make([]string, len(st.Recipients))
	for i, r := range st.Recipients {
		recipients[i] = q(r)
	}
	p("Recipients:         %s", strings.Join(recipients, ", "))
	if st.ConfidentialityLevel != "" {
		p("Level:              %s", q(st.ConfidentialityLevel))
	}
	p("End-to-end:         %t", st.EndToEndEncrypted)
	p("Deposited:          %s", q(st.DepositedAt))
	p("Expires:            %s", q(st.ExpiresAt))
	if st.FirstDownloadedAt != nil {
		p("First downloaded:   %s", q(*st.FirstDownloadedAt))
	}
	for _, d := range st.RecipientDownloads {
		p("Downloaded by:      %s at %s", q(d.Email), q(d.FirstDownloadedAt))
	}
	p("Files (%d):", len(st.Files))
	for _, f := range st.Files {
		name := f.Name
		if f.Path != "" {
			name = f.Path + "/" + f.Name
		}
		p("  %s", q(name))
		p("    size %d bytes, scan %s", f.Size, q(string(f.ScanStatus)))
		p("    sha256 %s", q(f.SHA256))
	}
	p("Signing key:        %s", q(st.KeyID))
	p("Instance version:   %s", q(st.InstanceVersion))
	p("statement.json SHA-256: %s", hex.EncodeToString(sum[:]))
	_, err := io.WriteString(w, b.String())
	return err
}

// keyListJSON is the answer of GET /api/v1/proof-keys.
type keyListJSON struct {
	Items []struct {
		KeyID     string  `json:"keyId"`
		Algorithm string  `json:"algorithm"`
		PublicKey string  `json:"publicKey"`
		CreatedAt string  `json:"createdAt"`
		RetiredAt *string `json:"retiredAt"`
	} `json:"items"`
}

// parseKeyList decodes a ProofKeyList strictly.
func parseKeyList(data []byte) ([]proof.PublicKey, error) {
	var l keyListJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("malformed key list: %w", err)
	}
	if dec.More() {
		return nil, errors.New("malformed key list: trailing data")
	}
	keys := make([]proof.PublicKey, 0, len(l.Items))
	for _, it := range l.Items {
		if it.Algorithm != "Ed25519" {
			return nil, fmt.Errorf("key %s: unsupported algorithm %q", it.KeyID, it.Algorithm)
		}
		raw, err := base64.RawURLEncoding.DecodeString(it.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %s: the public key must be 32 bytes in base64url", it.KeyID)
		}
		k := proof.PublicKey{KeyID: it.KeyID, PublicKey: raw}
		if k.CreatedAt, err = time.Parse(time.RFC3339, it.CreatedAt); err != nil {
			return nil, fmt.Errorf("key %s: malformed createdAt", it.KeyID)
		}
		if it.RetiredAt != nil {
			if k.RetiredAt, err = time.Parse(time.RFC3339, *it.RetiredAt); err != nil {
				return nil, fmt.Errorf("key %s: malformed retiredAt", it.KeyID)
			}
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// readKeysFile reads a saved key list.
func readKeysFile(path string) ([]proof.PublicKey, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the file is chosen by the operator on the command line
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxKeysBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeysBytes {
		return nil, errors.New("key list too large")
	}
	return parseKeyList(data)
}

// checkKeysURL accepts HTTPS URLs, and HTTP only on localhost.
func checkKeysURL(u *url.URL) error {
	host := u.Hostname()
	switch {
	case host == "":
		return errors.New("the URL has no host")
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLocalHost(host):
		return nil
	}
	return fmt.Errorf("refusing %q: the keys must be fetched over https", u.Scheme+"://"+u.Host)
}

// isLocalHost reports whether host is localhost, a *.localhost name or a
// loopback address.
func isLocalHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// fetchKeys downloads the key list from raw, a base URL (the keys path is
// appended) or the full keys URL.
func fetchKeys(ctx context.Context, raw string) ([]proof.PublicKey, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("malformed URL: %w", err)
	}
	if err := checkKeysURL(u); err != nil {
		return nil, err
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = keysPath
	}
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := keysClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", u.Host, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeysBytes {
		return nil, errors.New("key list too large")
	}
	return parseKeyList(data)
}

// proofSigner opens the configuration, the master key and the database
// like rotate-master-key, and returns the signer with a cleanup function.
func proofSigner(ctx context.Context, stderr io.Writer) (*proof.Signer, func(), error) {
	cfg, err := config.FromEnvironment()
	if err != nil {
		return nil, nil, err
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	keys, err := masterkey.Load(cfg)
	if err != nil {
		return nil, nil, err
	}
	db, err := app.OpenDatabase(ctx, cfg, logger)
	if err != nil {
		keys.Close()
		return nil, nil, err
	}
	closeAll := func() { _ = db.Close(); keys.Close() }
	if _, err := masterkey.Check(ctx, db, keys, nil, time.Now()); err != nil {
		closeAll()
		return nil, nil, err
	}
	return proof.NewSigner(db, masterkey.NewVault(db, keys, nil), audit.New(db), nil, logger), closeAll, nil
}

// runProofKeys lists the signing keys.
func runProofKeys(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("proof keys", stderr)
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	ctx := context.Background()
	signer, closeAll, err := proofSigner(ctx, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof keys: %v\n", err)
		return exitError
	}
	defer closeAll()
	keys, err := signer.Keys(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof keys: %v\n", err)
		return exitError
	}
	if len(keys) == 0 {
		_, _ = fmt.Fprintln(stdout, "No signing key yet: the first one is created with the first proof.")
		return exitOK
	}
	w := bufio.NewWriter(stdout)
	_, _ = fmt.Fprintf(w, "%-32s  %-24s  %-24s  %s\n", "KEY", "CREATED", "RETIRED", "STATE")
	for _, k := range keys {
		retired, state := "-", "active"
		if !k.RetiredAt.IsZero() {
			retired, state = k.RetiredAt.UTC().Format(time.RFC3339), "retired"
		}
		_, _ = fmt.Fprintf(w, "%-32s  %-24s  %-24s  %s\n", k.KeyID, k.CreatedAt.UTC().Format(time.RFC3339), retired, state)
	}
	if err := w.Flush(); err != nil {
		_, _ = fmt.Fprintf(stderr, "proof keys: %v\n", err)
		return exitError
	}
	return exitOK
}

// runProofRetireKey retires the active signing key after confirmation.
func runProofRetireKey(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("proof retire-key", stderr)
	yes := fs.Bool("yes", false, "retire without asking for confirmation")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	if !*yes {
		if !stdinIsTerminal() {
			_, _ = fmt.Fprintln(stderr, "proof retire-key: not an interactive terminal: pass --yes to confirm")
			return exitUsage
		}
		_, _ = fmt.Fprint(stdout, "Retire the active proof signing key? Its private part is destroyed. [y/N] ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			_, _ = fmt.Fprintln(stdout, "Aborted.")
			return exitError
		}
	}
	ctx := context.Background()
	signer, closeAll, err := proofSigner(ctx, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof retire-key: %v\n", err)
		return exitError
	}
	defer closeAll()
	k, err := signer.Retire(ctx, proof.CLIActor)
	switch {
	case errors.Is(err, proof.ErrNoActiveKey):
		_, _ = fmt.Fprintln(stderr, "proof retire-key: there is no active signing key (the next proof creates one)")
		return exitError
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "proof retire-key: %v\n", err)
		return exitError
	}
	_, _ = fmt.Fprintf(stdout, "Signing key %s retired and its private part destroyed.\n"+
		"A new key is created at the next proof. The public key stays published, so the proofs it signed stay verifiable.\n", k.ID)
	return exitOK
}

// Package proofverify verifies a TransTeira proof of deposit or delivery
// offline: it reads the public keys of an instance (a saved file or a
// download over HTTPS), checks the signed statement of the PDF and prints
// its verified fields. It needs neither the database nor the master key and
// is shared by the server binary and the command line client.
package proofverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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

// NewKeysClient returns the HTTP client used to download the public keys:
// short timeout, and no redirect to a non-HTTPS address.
func NewKeysClient() *http.Client {
	return &http.Client{
		Timeout: keysFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return CheckKeysURL(req.URL)
		},
	}
}

// Options selects what [Verify] checks and where the public keys come from.
type Options struct {
	// File is the proof PDF to verify.
	File string
	// URL is the https URL of the instance (or of its proof keys); it is
	// used when KeysFile is empty.
	URL string
	// KeysFile is a saved answer of GET /api/v1/proof-keys.
	KeysFile string
	// Client downloads the keys; nil means [NewKeysClient].
	Client *http.Client
}

// KeysError reports that the public keys could not be obtained.
type KeysError struct{ Err error }

// Error implements error.
func (e *KeysError) Error() string { return "public keys: " + e.Err.Error() }

// Unwrap returns the underlying error.
func (e *KeysError) Unwrap() error { return e.Err }

// Verify loads the public keys (KeysFile if set, else URL) and verifies the
// PDF. A failure to obtain the keys is a [*KeysError]. It returns the
// verified statement and its canonical encoding.
func Verify(ctx context.Context, o Options) (proof.Statement, []byte, error) {
	var keys []proof.PublicKey
	var err error
	if o.KeysFile != "" {
		keys, err = ReadKeysFile(o.KeysFile)
	} else {
		client := o.Client
		if client == nil {
			client = NewKeysClient()
		}
		keys, err = FetchKeys(ctx, client, o.URL)
	}
	if err != nil {
		return proof.Statement{}, nil, &KeysError{Err: err}
	}
	return VerifyFile(o.File, keys)
}

// Failure renders an error of [Verify] as the text printed after the
// command name: "public keys: ..." or "FAILED: ...".
func Failure(err error) string {
	var ke *KeysError
	if errors.As(err, &ke) {
		return ke.Error()
	}
	return "FAILED: " + Message(err)
}

// VerifyFile verifies the PDF at path and returns the statement and its
// canonical encoding.
func VerifyFile(path string, keys []proof.PublicKey) (proof.Statement, []byte, error) {
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

// Message explains a verification error in one line for the operator.
func Message(err error) string {
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

// PrintStatement prints the verified fields of st, never the visible text
// of the PDF, then the SHA-256 of the signed statement. Every field is
// escaped by [safeText]; --json prints the canonical bytes unchanged.
func PrintStatement(w io.Writer, st proof.Statement, data []byte) error {
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
	if st.LinkOnly {
		p("Link only:          recipient not identified (no mail sent; anyone holding the link may have downloaded)")
	}
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

// ParseKeyList decodes a ProofKeyList strictly.
func ParseKeyList(data []byte) ([]proof.PublicKey, error) {
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

// ReadKeysFile reads a saved key list.
func ReadKeysFile(path string) ([]proof.PublicKey, error) {
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
	return ParseKeyList(data)
}

// CheckKeysURL accepts HTTPS URLs, and HTTP only on localhost.
func CheckKeysURL(u *url.URL) error {
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

// FetchKeys downloads the key list with client from raw, a base URL (the keys path is
// appended) or the full keys URL.
func FetchKeys(ctx context.Context, client *http.Client, raw string) ([]proof.PublicKey, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("malformed URL: %w", err)
	}
	if err := CheckKeysURL(u); err != nil {
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
	resp, err := client.Do(req)
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
	return ParseKeyList(data)
}

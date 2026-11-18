//go:build ignore

// express-secret.go: create and read TransTeira express secrets from a program (since 2.3).
//
// A single file, Go 1.24 or later, standard library only (crypto/hkdf, crypto/aes,
// crypto/cipher, crypto/sha256, crypto/rand, net/http). The build constraint keeps it out of the
// packages of the repository; run it with "go run express-secret.go ...", or build it with
// "go build -o express-secret express-secret.go". The format is
// docs/architecture/e2e-format.md section 3.3.9 (express profile of the one-time secrets: no
// passphrase, no file, link composed by the client); the self-test mode checks this file
// against internal/tte2/testdata/vectors.json.
//
// Usage:
//
//	go run express-secret.go create [-file FILE]     create an express secret, print its link
//	go run express-secret.go seal [-file FILE]       print the createExpressSecret body and the key
//	go run express-secret.go status                  print the state of a link (consumes nothing)
//	go run express-secret.go read                    reveal a secret (once) and print its text
//	go run express-secret.go self-test VECTORS.json  check the format against the vectors
//
// The text comes from standard input or from -file FILE, never from the command line (other
// users of the host can read the process list). It is used as is, as UTF-8, with no trimming
// (use printf, not echo, to avoid a trailing line break), and must hold 1 to 10 000 Unicode code
// points. The link of status and read comes from the file named by TT_LINK_FILE or, without it,
// from standard input.
//
// Environment:
//
//	TT_URL         tenant URL, e.g. https://transfer.entity-a.example.com (create)
//	TT_TOKEN_FILE  file holding an API token of the entity allowed to create express secrets
//	               (expressAllowed); without it the creation is anonymous (create)
//	TT_EXPIRES     1h, 1d or 7d (default 1d) (create, seal)
//	TT_LINK_FILE   status, read: file holding the link (default: standard input)
//	TT_CA_FILE     extra CA certificates (PEM) to trust, for an internal PKI (optional)
//
// The link https://<fqdn>/s/<token>#k=<key> is the secret: create prints it on standard output
// only, never in a log; write it to a private place. A new key is drawn for every secret, never
// reused, not even to retry a failed creation. The server never receives the text nor the key.
//
// seal prints {"fragmentKey": "...", "body": {...}}, where body is the complete request body of
// POST /api/v1/express-secrets (encryptedText, verifier, keyVerifier, expiresIn): see the
// integration guide (docs/api/integration.md) for the curl calls around it.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	keySize              = 32
	nonceSize            = 12
	tagSize              = 16
	sealedOverhead       = 1 + nonceSize + tagSize // 29 bytes: version, nonce, tag
	maxSecretRunes       = 10000
	maxSecretEncodedSize = (sealedOverhead + 4*maxSecretRunes) / 3 * 4 // 53 372
	infoSecret           = "transteira/tte2/v1/secret"
	infoKeyProof         = "transteira/tte2/v1/secret/key-proof"
	infoText             = "transteira/tte2/v1/secret/text"
	infoProof            = "transteira/tte2/v1/secret/proof"
	secretAAD            = "TTE2S"
)

var (
	base64URL   = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	origin      = regexp.MustCompile(`^https://[^/?#@\s]+$`)
	linkPattern = regexp.MustCompile(`^(https://[^/?#@\s]+)/s/(tts_[A-Za-z0-9]{43})(?:#k=([A-Za-z0-9_-]{43}))?$`)
	secretToken = regexp.MustCompile(`^tts_[A-Za-z0-9]{43}$`)
	durations   = map[string]bool{"1h": true, "1d": true, "7d": true}
)

// formatError is a format error named after the Go error of internal/tte2 (e.g. ErrAuth).
type formatError struct{ code, detail string }

func (e *formatError) Error() string { return e.code + ": " + e.detail }

// apiError is a non-2xx answer: the operation, the status and the problem (RFC 9457).
type apiError struct {
	op         string
	status     int
	problem    map[string]any
	retryAfter string
}

func (e *apiError) code() string { s, _ := e.problem["code"].(string); return s }

func (e *apiError) Error() string {
	detail, _ := e.problem["detail"].(string)
	return strings.TrimSpace(fmt.Sprintf("%s: %d %s %s", e.op, e.status, e.code(), detail))
}

// --- Encodings -----------------------------------------------------------------------------

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// fromB64url is strict base64url: alphabet only (the decoder would skip line breaks), no
// padding, canonical (no stray bits); nil otherwise.
func fromB64url(s string) []byte {
	if !base64URL.MatchString(s) {
		return nil
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// decodeKey decodes the key of a link fragment: 43 canonical base64url characters, 32 bytes.
func decodeKey(s string) ([]byte, error) {
	if k := fromB64url(s); len(s) == 43 && k != nil {
		return k, nil
	}
	return nil, &formatError{"ErrInvalidKey", "not 43 canonical base64url characters"}
}

// --- Derivations (sections 3.3.2, 3.3.4 and 3.3.9) -----------------------------------------

// derive is HKDF-SHA-256 of 32 bytes with an empty salt.
func derive(ikm []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, ikm, nil, info, keySize)
	if err != nil {
		panic(err) // only for an output longer than 255 hashes
	}
	return k
}

// rootKey is K' = HKDF(K, salt = empty, "transteira/tte2/v1/secret"): an express secret has no
// passphrase.
func rootKey(key []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, &formatError{"ErrInvalidKey", fmt.Sprintf("%d bytes", len(key))}
	}
	return derive(key, infoSecret), nil
}

func keyProof(key []byte) []byte { return derive(key, infoKeyProof) }

func proof(rk []byte) []byte { return derive(rk, infoProof) }

func verifier(p []byte) []byte { s := sha256.Sum256(p); return s[:] }

// --- Text (section 3.3.3) ------------------------------------------------------------------

func textAEAD(rk []byte) cipher.AEAD {
	block, err := aes.NewCipher(derive(rk, infoText))
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

func checkText(text string) error {
	if !utf8.ValidString(text) {
		return &formatError{"ErrInvalidSecret", "not valid UTF-8"}
	}
	if utf8.RuneCountInString(text) > maxSecretRunes {
		return &formatError{"ErrInvalidSecret", fmt.Sprintf("longer than %d characters", maxSecretRunes)}
	}
	return nil
}

// sealText seals the text: base64url(0x01 || nonce || AES-256-GCM(text, AAD "TTE2S") || tag).
// A nil nonce draws a random one.
func sealText(rk []byte, text string, nonce []byte) (string, error) {
	if err := checkText(text); err != nil {
		return "", err
	}
	if nonce == nil {
		nonce = make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
	}
	blob := append([]byte{1}, nonce...)
	return b64url(textAEAD(rk).Seal(blob, nonce, []byte(text), []byte(secretAAD))), nil
}

// openText opens a sealed text: strict framing (ErrEncoding), tag (ErrAuth), then the text
// rules.
func openText(rk []byte, sealed string) (string, error) {
	var blob []byte
	if len(sealed) <= maxSecretEncodedSize {
		blob = fromB64url(sealed)
	}
	if len(blob) < sealedOverhead || blob[0] != 1 {
		return "", &formatError{"ErrEncoding", "not a sealed secret text"}
	}
	plain, err := textAEAD(rk).Open(nil, blob[1:1+nonceSize], blob[1+nonceSize:], []byte(secretAAD))
	if err != nil {
		return "", &formatError{"ErrAuth", "wrong key, or altered"}
	}
	text := string(plain) // a leading U+FEFF is kept
	if err := checkText(text); err != nil {
		return "", err
	}
	return text, nil
}

// --- Creation ------------------------------------------------------------------------------

// body is the request body of createExpressSecret: exactly these four members.
type body struct {
	EncryptedText string `json:"encryptedText"`
	Verifier      string `json:"verifier"`
	KeyVerifier   string `json:"keyVerifier"`
	ExpiresIn     string `json:"expiresIn"`
}

// sealSecret seals text under a new key and returns the fragment key and the
// createExpressSecret body. It opens its own sealed text before returning, so that the
// verifiers never certify a text the recipient could not open.
func sealSecret(text, expiresIn string) (string, body, error) {
	switch n := utf8.RuneCountInString(text); {
	case text == "":
		return "", body{}, errors.New("empty text: an express secret holds 1 to 10 000 characters")
	case !utf8.ValidString(text):
		return "", body{}, errors.New("the text is not valid UTF-8")
	case n > maxSecretRunes:
		return "", body{}, fmt.Errorf("text of %d characters: at most %d", n, maxSecretRunes)
	case !durations[expiresIn]:
		return "", body{}, fmt.Errorf("TT_EXPIRES must be 1h, 1d or 7d, not %q", expiresIn)
	}
	key := make([]byte, keySize) // a new key for every secret, from the CSPRNG
	if _, err := rand.Read(key); err != nil {
		return "", body{}, err
	}
	rk, err := rootKey(key)
	if err != nil {
		return "", body{}, err
	}
	sealed, err := sealText(rk, text, nil)
	if err != nil {
		return "", body{}, err
	}
	if back, err := openText(rk, sealed); err != nil || back != text {
		return "", body{}, errors.New("self-check failed")
	}
	return b64url(key), body{
		EncryptedText: sealed,
		Verifier:      hex.EncodeToString(verifier(proof(rk))),
		KeyVerifier:   hex.EncodeToString(verifier(keyProof(key))),
		ExpiresIn:     expiresIn,
	}, nil
}

// readText reads the text, as is, from the file or standard input.
func readText(path string) (string, error) {
	var raw []byte
	var err error
	if path != "" {
		raw, err = os.ReadFile(path)
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	return string(raw), err
}

// client refuses redirects (a 3xx answer is an error, never followed) and trusts TT_CA_FILE in
// addition to the system store.
func client() (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if ca := os.Getenv("TT_CA_FILE"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("TT_CA_FILE holds no PEM certificate")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport:     transport,
		Timeout:       60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// call calls the API operation op and decodes its JSON answer into out; a non-2xx answer is an
// *apiError with the problem (RFC 9457). Errors name the operation, never the URL, whose path
// may hold a secret token.
func call(op, method, u string, headers map[string]string, in, out any) error {
	c, err := client()
	if err != nil {
		return err
	}
	var reqBody io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, reqBody)
	if err != nil {
		return fmt.Errorf("%s: invalid request", op)
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // *url.Error prints the URL, which may hold the token
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		problem := map[string]any{}
		_ = json.Unmarshal(data, &problem)
		return &apiError{op: op, status: res.StatusCode, problem: problem, retryAfter: res.Header.Get("Retry-After")}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: unexpected answer", op)
	}
	return nil
}

func create(file string) error {
	base := strings.TrimRight(os.Getenv("TT_URL"), "/")
	if !origin.MatchString(base) {
		return errors.New("TT_URL must be https://<fqdn of the entity>, without a path")
	}
	headers := map[string]string{}
	if path := os.Getenv("TT_TOKEN_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return errors.New("TT_TOKEN_FILE is empty")
		}
		headers["Authorization"] = "Bearer " + token
	}
	text, err := readText(file)
	if err != nil {
		return err
	}
	fragmentKey, b, err := sealSecret(text, envOr("TT_EXPIRES", "1d"))
	if err != nil {
		return err
	}
	var created struct {
		Token string `json:"token"`
	}
	if err := call("createExpressSecret", http.MethodPost, base+"/api/v1/express-secrets", headers, b, &created); err != nil {
		return err
	}
	if !secretToken.MatchString(created.Token) {
		return errors.New("createExpressSecret: unexpected answer")
	}
	// The client composes the link; the server never sees the fragment. Standard output only.
	_, err = fmt.Printf("%s/s/%s#k=%s\n", base, created.Token, fragmentKey)
	return err
}

func seal(file string) error {
	text, err := readText(file)
	if err != nil {
		return err
	}
	fragmentKey, b, err := sealSecret(text, envOr("TT_EXPIRES", "1d"))
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"fragmentKey": fragmentKey, "body": b})
}

// --- Status and reading --------------------------------------------------------------------

// readLink reads the link from TT_LINK_FILE or standard input, dropping surrounding white space,
// and returns its origin, token and key (empty when absent and not needed).
func readLink(needKey bool) (string, string, string, error) {
	var raw []byte
	var err error
	if path := os.Getenv("TT_LINK_FILE"); path != "" {
		raw, err = os.ReadFile(path)
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		return "", "", "", err
	}
	m := linkPattern.FindStringSubmatch(strings.TrimSpace(string(raw)))
	if m == nil || (needKey && m[3] == "") {
		form := "https://<fqdn>/s/<token>[#k=<key>]"
		if needKey {
			form = "https://<fqdn>/s/<token>#k=<key>"
		}
		return "", "", "", fmt.Errorf("expected %s in TT_LINK_FILE or on standard input", form)
	}
	return m[1], m[2], m[3], nil
}

// secretStatus is the answer of getSecretLink.
type secretStatus struct {
	ExpiresAt  string          `json:"expiresAt"`
	Passphrase json.RawMessage `json:"passphrase"`
	File       json.RawMessage `json:"file"`
	Express    bool            `json:"express"`
	Anonymous  bool            `json:"anonymous"`
}

// reasonWord matches the reasons of secret-gone (read, expired, deleted, locked, and those a
// later server may add): a reason of any other shape is not printed.
var reasonWord = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// goneReason returns the reason of a secret-gone problem, or "gone" when it is absent or is not
// a plain word.
func goneReason(e *apiError) string {
	if reason, _ := e.problem["reason"].(string); reasonWord.MatchString(reason) {
		return reason
	}
	return "gone"
}

// status prints pending <expiresAt>, read, expired, deleted, locked or closed. It consumes
// nothing. What it prints on the standard output is checked first (an RFC 3339 date, a plain
// word), since the server is the one named by the link.
func status() error {
	o, token, _, err := readLink(false)
	if err != nil {
		return err
	}
	var st secretStatus
	err = call("getSecretLink", http.MethodGet, o+"/api/v1/secret-links/"+token, nil, nil, &st)
	var ae *apiError
	switch {
	case err == nil:
		if _, err := time.Parse(time.RFC3339, st.ExpiresAt); err != nil {
			return errors.New("getSecretLink: unexpected answer")
		}
		fmt.Printf("pending %s\n", st.ExpiresAt)
	case errors.As(err, &ae) && ae.status == http.StatusGone && ae.code() == "secret-gone":
		fmt.Println(goneReason(ae))
	case errors.As(err, &ae) && ae.status == http.StatusForbidden && ae.code() == "express-secrets-disabled":
		fmt.Println("closed") // readable again if the service reopens before the expiry
	default:
		return err
	}
	return nil
}

// isTerminal reports whether standard output is a terminal.
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// unsafeRune reports the characters that could drive or deceive a terminal: the C0 controls,
// DEL and the C1 controls, whose escape sequences could drive it, and the bidirectional
// formatting characters, which could reorder what is shown.
func unsafeRune(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f) ||
		r == 0x061c || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// printable returns s for a one-line message: every unsafe character, line breaks included,
// replaced with U+FFFD.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return utf8.RuneError
		}
		return r
	}, s)
}

// terminalSafe replaces with U+FFFD the unsafe characters of a revealed text, except tab, line
// feed and a carriage return right before a line feed: a lone carriage return would send the
// cursor back to the start of the line and let the rest of the line overwrite what was shown.
func terminalSafe(text string) (string, bool) {
	changed := false
	var b strings.Builder
	b.Grow(len(text))
	for i, r := range text {
		keep := r == '\t' || r == '\n' || (r == '\r' && strings.HasPrefix(text[i+1:], "\n"))
		if !keep && unsafeRune(r) {
			changed = true
			r = utf8.RuneError
		}
		b.WriteRune(r)
	}
	return b.String(), changed
}

func read() error {
	o, token, fragment, err := readLink(true)
	if err != nil {
		return err
	}
	key, err := decodeKey(fragment)
	if err != nil {
		return err
	}
	u := o + "/api/v1/secret-links/" + token
	// The status call consumes nothing (404 unknown, 410 secret-gone with a reason, 403 closed).
	var st secretStatus
	if err := call("getSecretLink", http.MethodGet, u, nil, nil, &st); err != nil {
		return err
	}
	if len(st.Passphrase) > 0 && string(st.Passphrase) != "null" {
		return errors.New("this secret has a passphrase: it is not an express secret (use secret-create.mjs read)")
	}
	if len(st.File) > 0 && string(st.File) != "null" {
		return errors.New("this secret has a file, which this example cannot decrypt: open the link in a browser")
	}
	if st.Express {
		how := "with an API token of the entity"
		if st.Anonymous {
			how = "anonymously"
		}
		warn("this express secret was created " + how + ": its content was written by a third party, " +
			"not by the entity, which has not checked it. To report an abuse, use the link on the read page " +
			"or POST /api/v1/secret-links/<token>/abuse-reports.")
	}
	rk, err := rootKey(key)
	if err != nil {
		return err
	}
	// One-time: the answer is the only copy.
	var revealed struct {
		EncryptedText string `json:"encryptedText"`
	}
	proofs := map[string]string{"keyProof": hex.EncodeToString(keyProof(key)), "proof": hex.EncodeToString(proof(rk))}
	if err := call("revealSecret", http.MethodPost, u+"/reveal", nil, proofs, &revealed); err != nil {
		return err
	}
	text, err := openText(rk, revealed.EncryptedText)
	if err != nil {
		return err
	}
	if isTerminal() {
		var changed bool
		if text, changed = terminalSafe(text); changed {
			warn("control or bidirectional characters replaced with U+FFFD on the terminal: redirect the output to keep the text as is")
		}
	}
	_, err = os.Stdout.WriteString(text)
	return err
}

// --- Self-test against internal/tte2/testdata/vectors.json ---------------------------------

type secretVector struct {
	Name           string          `json:"name"`
	KeyHex         string          `json:"keyHex"`
	KeyFragment    string          `json:"keyFragment"`
	Passphrase     *string         `json:"passphrase"`
	Descriptor     json.RawMessage `json:"descriptor"`
	RootKeyHex     string          `json:"rootKeyHex"`
	KeyProofHex    string          `json:"keyProofHex"`
	KeyVerifierHex string          `json:"keyVerifierHex"`
	ProofHex       string          `json:"proofHex"`
	VerifierHex    string          `json:"verifierHex"`
	TextNonceHex   string          `json:"textNonceHex"`
	Text           string          `json:"text"`
	SealedText     string          `json:"sealedText"`
}

type negativeVector struct {
	Name          string          `json:"name"`
	Secret        string          `json:"secret"`
	KeyHex        *string         `json:"keyHex"`
	Passphrase    *string         `json:"passphrase"`
	Descriptor    json.RawMessage `json:"descriptor"`
	NoDescriptor  bool            `json:"noDescriptor"`
	Text          *string         `json:"text"`
	Sealed        *string         `json:"sealed"`
	KeyProofValid bool            `json:"keyProofValid"`
	ProofValid    bool            `json:"proofValid"`
	ExpectedError string          `json:"expectedError"`
}

func present(r json.RawMessage) bool { return len(r) > 0 && string(r) != "null" }

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// selfTest checks every secret vector of the express profile (no passphrase, no descriptor);
// the vectors with a passphrase are counted as skipped.
func selfTest(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var vectors struct {
		Secrets        []secretVector   `json:"secrets"`
		SecretNegative []negativeVector `json:"secretNegative"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		return err
	}
	failures := 0
	check := func(name string, got, want any) {
		if got != want {
			failures++
			fmt.Fprintf(os.Stderr, "FAIL %s: got %v, want %v\n", name, got, want)
		}
	}
	errCode := func(err error) string {
		var fe *formatError
		if err == nil {
			return "none"
		}
		if errors.As(err, &fe) {
			return fe.code
		}
		return err.Error()
	}
	byName := map[string]secretVector{}
	done, skipped := 0, 0
	for _, v := range vectors.Secrets {
		byName[v.Name] = v
		if v.Passphrase != nil || present(v.Descriptor) {
			skipped++
			continue
		}
		done++
		n := v.Name
		key, err := decodeKey(v.KeyFragment)
		if err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
		check(n+" keyFragment", hex.EncodeToString(key), v.KeyHex)
		check(n+" encoded key", b64url(unhex(v.KeyHex)), v.KeyFragment)
		rk, err := rootKey(key)
		if err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
		check(n+" rootKey", hex.EncodeToString(rk), v.RootKeyHex)
		kp := keyProof(key)
		check(n+" keyProof", hex.EncodeToString(kp), v.KeyProofHex)
		check(n+" keyVerifier", hex.EncodeToString(verifier(kp)), v.KeyVerifierHex)
		pr := proof(rk)
		check(n+" proof", hex.EncodeToString(pr), v.ProofHex)
		check(n+" verifier", hex.EncodeToString(verifier(pr)), v.VerifierHex)
		sealed, err := sealText(rk, v.Text, unhex(v.TextNonceHex))
		check(n+" sealedText", sealed, v.SealedText)
		check(n+" sealedText error", errCode(err), "none")
		text, err := openText(rk, v.SealedText)
		check(n+" open", text, v.Text)
		check(n+" open error", errCode(err), "none")
	}
	negDone, negSkipped := 0, 0
	for _, c := range vectors.SecretNegative {
		base, ok := byName[c.Secret]
		if !ok {
			return fmt.Errorf("%s: unknown secret %q", c.Name, c.Secret)
		}
		passphrase := c.Passphrase
		if passphrase == nil {
			passphrase = base.Passphrase
		}
		descriptor := !c.NoDescriptor && (present(c.Descriptor) || present(base.Descriptor))
		if (passphrase != nil && *passphrase != "") || descriptor {
			negSkipped++
			continue
		}
		negDone++
		keyHex := base.KeyHex
		if c.KeyHex != nil {
			keyHex = *c.KeyHex
		}
		key := unhex(keyHex)
		check(c.Name+" keyProofValid", hex.EncodeToString(verifier(keyProof(key))) == base.KeyVerifierHex, c.KeyProofValid)
		proofValid := false
		rk, err := rootKey(key)
		if err == nil {
			proofValid = hex.EncodeToString(verifier(proof(rk))) == base.VerifierHex
			switch {
			case c.Text != nil:
				_, err = sealText(rk, *c.Text, nil)
			case c.Sealed != nil:
				_, err = openText(rk, *c.Sealed)
			default:
				_, err = openText(rk, base.SealedText)
			}
		}
		check(c.Name+" error", errCode(err), c.ExpectedError)
		check(c.Name+" proofValid", proofValid, c.ProofValid)
	}
	if done == 0 || negDone == 0 {
		failures++
		fmt.Fprintln(os.Stderr, "FAIL no vector of the express profile")
	}
	if failures > 0 {
		return fmt.Errorf("self-test: %d failure(s)", failures)
	}
	fmt.Printf("self-test: ok (%d secrets, %d negative cases; skipped with a passphrase: %d secrets, %d negative cases)\n",
		done, negDone, skipped, negSkipped)
	return nil
}

// --- Main ----------------------------------------------------------------------------------

func envOr(name, fallback string) string { return cmpOr(os.Getenv(name), fallback) }

func cmpOr(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

// warn writes one line on the standard error. Every message goes through printable: an error
// can quote a problem of the server named by the link (code, detail, reason, delay), and a link
// received from a third party can name a hostile server.
func warn(msg string) { fmt.Fprintln(os.Stderr, "express-secret: "+printable(msg)) }

// hint explains the problems a script should handle (errors.md has them all).
func hint(e *apiError) string {
	create := e.op == "createExpressSecret"
	var h string
	switch e.code() {
	case "express-secrets-disabled":
		h = "the express service of this entity is closed: nothing was consumed, the secret can be read if the service reopens before it expires"
		if create {
			h = "express secrets are not open to anonymous use on this entity, or are disabled on the instance: use an API token allowed for them (TT_TOKEN_FILE) or ask the administrators"
		}
	case "express-token-not-allowed":
		h = "this API token may not create express secrets: ask an administrator of the entity to allow it (expressAllowed)"
	case "express-secret-limit-reached":
		h = "the entity holds too many unread express secrets: try later, or use an API token"
	case "invalid-credentials":
		h = "the API token is unknown, revoked or expired"
	case "ip-not-allowed":
		h = "this API token is not allowed from this address (allowedCidrs)"
	case "validation-failed":
		h = "the request was refused as malformed: do not retry it unchanged"
	case "secret-format-invalid":
		h = "the sealed text was refused: do not retry it unchanged"
	case "secret-proof-invalid":
		h = "the key of the link is wrong: the link was truncated or altered"
	case "secret-gone":
		reason, _ := e.problem["reason"].(string)
		h = "the secret is gone (" + cmpOr(reason, "unknown reason") + ")"
	case "not-found":
		h = "unknown link: mistyped, or made on another entity"
		if create {
			h = "no express secrets on this server (TransTeira 2.3 or later is needed)"
		}
	}
	wait := e.retryAfter
	if f, ok := e.problem["retryAfterSeconds"].(float64); ok && wait == "" {
		wait = fmt.Sprint(f)
	}
	if (e.status == http.StatusTooManyRequests || e.status == http.StatusServiceUnavailable) && wait != "" {
		if h != "" {
			h += "; "
		}
		h += "retry after " + wait + " seconds"
		if create {
			h += " (a new run draws a new key)"
		}
	}
	return h
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: go run express-secret.go create|seal [-file FILE] | status | read | self-test VECTORS.json")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	mode, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	file := fs.String("file", "", "read the text from `FILE` instead of standard input")
	var err error
	switch mode {
	case "create", "seal":
		if fs.Parse(args) != nil || fs.NArg() != 0 {
			usage()
		}
		if mode == "create" {
			err = create(*file)
		} else {
			err = seal(*file)
		}
	case "status", "read":
		if len(args) != 0 {
			usage()
		}
		if mode == "status" {
			err = status()
		} else {
			err = read()
		}
	case "self-test":
		if len(args) != 1 {
			usage()
		}
		err = selfTest(args[0])
	default:
		usage()
	}
	if err != nil {
		warn(err.Error())
		var ae *apiError
		if errors.As(err, &ae) {
			if h := hint(ae); h != "" {
				warn(h)
			}
		}
		os.Exit(1)
	}
}

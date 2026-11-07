package proofverify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/pdf"
	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/store"
)

// env is a signing key pair and its public key.
type env struct {
	pub  proof.PublicKey
	priv ed25519.PrivateKey
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &env{
		pub:  proof.PublicKey{KeyID: id.New(id.ProofKey), PublicKey: pub, CreatedAt: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)},
		priv: priv,
	}
}

// statement returns a valid delivery statement signed by keyID.
func statement(keyID string) proof.Statement {
	first := "2026-01-02T10:00:00.000Z"
	return proof.Statement{
		SchemaVersion: proof.SchemaVersion, Kind: store.ProofDelivery, InstanceVersion: "2.0.0",
		Tenant:     proof.StatementTenant{Name: "Entity A", FQDN: "transfer.entity-a.example.com"},
		TransferID: id.New(id.Transfer), SenderEmail: "alice@example.com", Recipients: []string{"bob@example.org"},
		ConfidentialityLevel: "internal",
		Files: []proof.StatementFile{
			{Name: "a.txt", Path: "docs", Size: 5, SHA256: strings.Repeat("ab", 32), ScanStatus: "clean"},
		},
		DepositedAt: "2026-01-01T10:00:00.000Z", ExpiresAt: "2026-01-08T10:00:00.000Z",
		FirstDownloadedAt:  &first,
		RecipientDownloads: []proof.RecipientDownload{{Email: "bob@example.org", FirstDownloadedAt: first}},
		KeyID:              keyID,
	}
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// writePDF renders st signed by priv and writes the PDF in a new file.
func writePDF(t *testing.T, st proof.Statement, priv ed25519.PrivateKey) string {
	t.Helper()
	data, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := proof.Render(st, data, ed25519.Sign(priv, data), "en", proof.KeysURL(st.Tenant.FQDN))
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "proof.pdf", doc)
}

// keyListJSONOf returns the ProofKeyList JSON of keys.
func keyListJSONOf(t *testing.T, keys ...proof.PublicKey) []byte {
	t.Helper()
	type item struct {
		KeyID     string  `json:"keyId"`
		Algorithm string  `json:"algorithm"`
		PublicKey string  `json:"publicKey"`
		CreatedAt string  `json:"createdAt"`
		RetiredAt *string `json:"retiredAt"`
	}
	var items []item
	for _, k := range keys {
		it := item{k.KeyID, "Ed25519", base64.RawURLEncoding.EncodeToString(k.PublicKey), k.CreatedAt.UTC().Format(time.RFC3339), nil}
		if !k.RetiredAt.IsZero() {
			r := k.RetiredAt.UTC().Format(time.RFC3339)
			it.RetiredAt = &r
		}
		items = append(items, it)
	}
	b, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyAndPrint(t *testing.T) {
	e := newEnv(t)
	st := statement(e.pub.KeyID)
	keys := writeFile(t, "keys.json", keyListJSONOf(t, e.pub))
	got, data, err := Verify(context.Background(), Options{File: writePDF(t, st, e.priv), KeysFile: keys})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := st.Marshal()
	if string(data) != string(want) {
		t.Errorf("data = %q", data)
	}
	var b strings.Builder
	if err := PrintStatement(&b, got, data); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, w := range []string{
		"OK: signature valid", "Only the fields below", "delivery", st.TransferID, "Entity A (transfer.entity-a.example.com)",
		"alice@example.com", "bob@example.org", "internal", "docs/a.txt", "size 5 bytes, scan clean", strings.Repeat("ab", 32),
		e.pub.KeyID, "2.0.0", "Downloaded by:      bob@example.org", "statement.json SHA-256: ", "First downloaded:",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "Link only") {
		t.Errorf("unexpected link-only line:\n%s", out)
	}

	// A deposit statement without level, download or folder, link only.
	dep := statement(e.pub.KeyID)
	dep.Kind, dep.ConfidentialityLevel, dep.FirstDownloadedAt, dep.RecipientDownloads = store.ProofDeposit, "", nil, nil
	dep.Files[0].Path = ""
	dep.LinkOnly = true
	b.Reset()
	if err := PrintStatement(&b, dep, want); err != nil {
		t.Fatal(err)
	}
	if o := b.String(); strings.Contains(o, "Level:") || strings.Contains(o, "First downloaded") ||
		!strings.Contains(o, "Link only:          recipient not identified") || !strings.Contains(o, "  a.txt") {
		t.Errorf("deposit output:\n%s", o)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestPrintStatementWriteError(t *testing.T) {
	if err := PrintStatement(failWriter{}, proof.Statement{}, nil); err == nil {
		t.Error("write error not returned")
	}
}

func TestPrintStatementEscapesSignedFields(t *testing.T) {
	st := statement("k")
	st.Files[0].Name = "invoice\u202Etxt.exe"
	st.Tenant.Name = "Entity\x1b[2J A"
	var b strings.Builder
	if err := PrintStatement(&b, st, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.ContainsRune(out, '\u202e') || strings.ContainsRune(out, '\x1b') ||
		!strings.Contains(out, "invoice\\u202Etxt.exe") || !strings.Contains(out, "Entity\\u001B[2J A") {
		t.Fatalf("output: %q", out)
	}
}

func TestSafeText(t *testing.T) {
	for in, want := range map[string]string{
		"plain é 😀 name.txt": "plain é 😀 name.txt",
		"a\u202eb":           "a\\u202Eb",
		"a\x07b\nc\td":       "a\\u0007b\\u000Ac\\u0009d",
		"a\xffb":             "a\\xFFb",
		"z\u200bw\u00a0":     "z\\u200Bw\\u00A0",
		"t\U000E0001":        "t\\U000E0001",
	} {
		if got := safeText(in); got != want {
			t.Errorf("safeText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerifyFailures(t *testing.T) {
	e := newEnv(t)
	keys := writeFile(t, "keys.json", keyListJSONOf(t, e.pub))
	good := statement(e.pub.KeyID)
	_, other, _ := ed25519.GenerateKey(rand.Reader)

	retired := e.pub
	retired.RetiredAt = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) // before the first download
	retiredKeys := writeFile(t, "retired.json", keyListJSONOf(t, retired))
	notPDF := writeFile(t, "x.pdf", []byte("not a pdf"))
	pdfBytes, _ := os.ReadFile(writePDF(t, good, e.priv))
	truncated := writeFile(t, "t.pdf", pdfBytes[:len(pdfBytes)/2])

	cases := map[string]struct {
		keys, pdf, msg string
	}{
		"bad signature": {keys, writePDF(t, good, other), "signature does not match"},
		"unknown key":   {keys, writePDF(t, statement(id.New(id.ProofKey)), e.priv), "not among the public keys"},
		"key retired":   {retiredKeys, writePDF(t, good, e.priv), "postdates the retirement"},
		"not a pdf":     {keys, notPDF, "not a valid TransTeira proof"},
		"truncated":     {keys, truncated, "FAILED"},
		"missing file":  {keys, filepath.Join(t.TempDir(), "none.pdf"), "FAILED"},
		"too large":     {keys, writeFile(t, "big.pdf", make([]byte, proof.DefaultVerifyLimit+1)), "too large"},
	}
	for name, c := range cases {
		_, _, err := Verify(context.Background(), Options{File: c.pdf, KeysFile: c.keys})
		if err == nil || !strings.Contains(Failure(err), c.msg) || !strings.HasPrefix(Failure(err), "FAILED: ") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := Message(pdf.ErrTooLarge); !strings.Contains(got, "too large") {
		t.Errorf("Message(ErrTooLarge) = %q", got)
	}
}

func TestKeysFiles(t *testing.T) {
	e := newEnv(t)
	good := string(keyListJSONOf(t, e.pub))
	b64 := base64.RawURLEncoding.EncodeToString(e.pub.PublicKey)
	for name, content := range map[string]string{
		"not json":      "nope",
		"unknown field": strings.Replace(good, `"items"`, `"extra":1,"items"`, 1),
		"trailing":      good + " {}",
		"algorithm":     strings.Replace(good, "Ed25519", "RSA", 1),
		"short key":     strings.Replace(good, b64, b64[:10], 1),
		"bad created":   strings.Replace(good, `"createdAt":"`, `"createdAt":"x`, 1),
		"bad retired":   strings.Replace(good, `"retiredAt":null`, `"retiredAt":"x"`, 1),
		"too large":     strings.Repeat(" ", maxKeysBytes+1),
	} {
		_, _, err := Verify(context.Background(), Options{File: "unused.pdf", KeysFile: writeFile(t, "k.json", []byte(content))})
		var ke *KeysError
		if !errors.As(err, &ke) || !strings.HasPrefix(Failure(err), "public keys: ") || errors.Unwrap(err) == nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ReadKeysFile(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("missing keys file accepted")
	}
	if _, err := ReadKeysFile(t.TempDir()); err == nil {
		t.Error("directory accepted as keys file")
	}
	// A retired key round-trips.
	r := e.pub
	r.RetiredAt = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	keys, err := ParseKeyList(keyListJSONOf(t, r))
	if err != nil || len(keys) != 1 || !keys[0].RetiredAt.Equal(r.RetiredAt) {
		t.Errorf("ParseKeyList = %v, %v", keys, err)
	}
}

func TestFetchKeys(t *testing.T) {
	e := newEnv(t)
	list := keyListJSONOf(t, e.pub)
	pdfPath := writePDF(t, statement(e.pub.KeyID), e.priv)

	var gotPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/proof-keys", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write(list)
	})
	mux.HandleFunc("/custom/keys", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(list) })
	mux.HandleFunc("/huge", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, maxKeysBytes+1)) })
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/keys", http.StatusFound)
	})
	mux.HandleFunc("/truncated", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("{"))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	client := NewKeysClient()
	client.Transport = srv.Client().Transport

	for _, u := range []string{srv.URL, srv.URL + "/", srv.URL + "/custom/keys#frag"} {
		if _, _, err := Verify(context.Background(), Options{File: pdfPath, URL: u, Client: client}); err != nil {
			t.Errorf("url %s: %v", u, err)
		}
	}
	if gotPath != "/api/v1/proof-keys" {
		t.Errorf("path = %q", gotPath)
	}
	for _, u := range []string{
		srv.URL + "/huge", srv.URL + "/missing", srv.URL + "/redirect", srv.URL + "/truncated",
		"http://example.com", "ftp://x", "https://", "://bad", "https://127.0.0.1:1",
	} {
		_, _, err := Verify(context.Background(), Options{File: pdfPath, URL: u, Client: client})
		var ke *KeysError
		if !errors.As(err, &ke) {
			t.Errorf("url %s: %v", u, err)
		}
	}
	// Control character in the URL host: the request cannot be built.
	if _, err := FetchKeys(context.Background(), client, "https://exa mple.com"); err == nil {
		t.Error("invalid host accepted")
	}
	// A nil client falls back to the default one (and refuses plain http).
	if _, _, err := Verify(context.Background(), Options{File: pdfPath, URL: "http://example.com"}); err == nil {
		t.Error("nil client: http accepted")
	}
	// A nil context makes the request impossible to build.
	if _, err := FetchKeys(nil, client, srv.URL); err == nil { //nolint:staticcheck // SA1012: nil is the point of the test
		t.Error("nil context accepted")
	}
	// Canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FetchKeys(ctx, client, srv.URL); err == nil {
		t.Error("canceled context accepted")
	}
	// Redirect loop.
	loop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, r.URL.Path+"x", http.StatusFound) }))
	defer loop.Close()
	client.Transport = loop.Client().Transport
	if _, err := FetchKeys(context.Background(), client, loop.URL+"/a"); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("redirect loop: %v", err)
	}
}

func TestCheckKeysURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://a.example.com": true, "http://localhost:8080": true, "http://app.localhost": true, "http://127.0.0.1": true,
		"http://a.example.com": false, "http://localhost.example.com": false, "file:///x": false, "https://": false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := CheckKeysURL(u) == nil; got != ok {
			t.Errorf("CheckKeysURL(%q) = %v", raw, got)
		}
	}
}

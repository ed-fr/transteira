package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/store"
)

// proofEnv is a migrated database with an active signing key.
type proofEnv struct {
	dsn, keyFile string
	pub          proof.PublicKey
	priv         ed25519.PrivateKey
}

// newProofEnv sets the environment and creates the active signing key
// through the proof package, like the first proof of an instance does.
func newProofEnv(t *testing.T) *proofEnv {
	t.Helper()
	dsn := setMigrateEnv(t)
	key := writeKeyFile(t)
	t.Setenv("TT_MASTER_KEY_FILE", key)
	t.Setenv("TT_LOG_LEVEL", "error")
	ctx := context.Background()
	db, vault := keyStore(t, dsn, key)
	kr, err := masterkey.Load(&config.Config{MasterKeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Close()
	if _, err := masterkey.Check(ctx, db, kr, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	signer := proof.NewSigner(db, vault, audit.New(db), nil, nil)
	if _, err := signer.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	k, err := db.ProofKeys().Active(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := vault.OpenSystem(ctx, crypto.PurposeProofSigning, k.PrivateKeySecretID)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := signer.Keys(ctx)
	if err != nil || len(keys) != 1 {
		t.Fatalf("Keys = %v, %v", keys, err)
	}
	return &proofEnv{dsn: dsn, keyFile: key, pub: keys[0], priv: ed25519.NewKeyFromSeed(seed)}
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

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
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

func TestProofVerify(t *testing.T) {
	e := newProofEnv(t)
	st := statement(e.pub.KeyID)
	pdf := writePDF(t, st, e.priv)
	keys := writeFile(t, "keys.json", keyListJSONOf(t, e.pub))

	code, out, errOut := runCmd("proof", "verify", "--keys", keys, pdf)
	if code != exitOK || errOut != "" {
		t.Fatalf("verify = %d, %q, %q", code, out, errOut)
	}
	for _, want := range []string{
		"OK: signature valid", "delivery", st.TransferID, "Entity A (transfer.entity-a.example.com)",
		"alice@example.com", "bob@example.org", "internal", "docs/a.txt", "size 5 bytes, scan clean", strings.Repeat("ab", 32),
		e.pub.KeyID, "2.0.0", "Downloaded by:      bob@example.org", "statement.json SHA-256: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	if !strings.Contains(out, "Only the fields below") {
		t.Errorf("authoritative notice missing:\n%s", out)
	}

	code, out, _ = runCmd("proof", "verify", "--json", "--keys", keys, pdf)
	want, _ := st.Marshal()
	if code != exitOK || out != string(want)+"\n" {
		t.Errorf("--json = %d, %q", code, out)
	}

	// A deposit statement without level, download or folder.
	dep := statement(e.pub.KeyID)
	dep.Kind, dep.ConfidentialityLevel, dep.FirstDownloadedAt, dep.RecipientDownloads = store.ProofDeposit, "", nil, nil
	dep.Files[0].Path = ""
	if code, out, _ = runCmd("proof", "verify", "--keys", keys, writePDF(t, dep, e.priv)); code != exitOK || strings.Contains(out, "Level:") {
		t.Errorf("deposit = %d, %q", code, out)
	}
}

func TestProofVerifyFailures(t *testing.T) {
	e := newProofEnv(t)
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
		"unknown key":   {keys, writePDF(t, statement("psk_"+strings.TrimPrefix(id.New(id.ProofKey), "psk_")), e.priv), "not among the public keys"},
		"key retired":   {retiredKeys, writePDF(t, good, e.priv), "postdates the retirement"},
		"not a pdf":     {keys, notPDF, "not a valid TransTeira proof"},
		"truncated":     {keys, truncated, "FAILED"},
		"missing file":  {keys, filepath.Join(t.TempDir(), "none.pdf"), "FAILED"},
	}
	for name, c := range cases {
		code, out, errOut := runCmd("proof", "verify", "--keys", c.keys, c.pdf)
		if code != exitError || out != "" || !strings.Contains(errOut, c.msg) {
			t.Errorf("%s = %d, %q, %q", name, code, out, errOut)
		}
	}

	big := make([]byte, proof.DefaultVerifyLimit+1)
	if code, _, errOut := runCmd("proof", "verify", "--keys", keys, writeFile(t, "big.pdf", big)); code != exitError || !strings.Contains(errOut, "too large") {
		t.Errorf("too large = %d, %q", code, errOut)
	}
}

func TestProofVerifyUsage(t *testing.T) {
	e := newProofEnv(t)
	keys := writeFile(t, "keys.json", keyListJSONOf(t, e.pub))
	pdf := writePDF(t, statement(e.pub.KeyID), e.priv)
	for name, args := range map[string][]string{
		"no keys":      {"proof", "verify", pdf},
		"both":         {"proof", "verify", "--keys", keys, "--url", "https://x.example.com", pdf},
		"no file":      {"proof", "verify", "--keys", keys},
		"two files":    {"proof", "verify", "--keys", keys, pdf, pdf},
		"unknown flag": {"proof", "verify", "--nope"},
		"no subcmd":    {"proof"},
		"bad subcmd":   {"proof", "frobnicate"},
		"keys extra":   {"proof", "keys", "extra"},
		"retire extra": {"proof", "retire-key", "extra"},
	} {
		if code, _, _ := runCmd(args...); code != exitUsage {
			t.Errorf("%s = %d, want usage", name, code)
		}
	}
	for _, args := range [][]string{{"proof", "-h"}, {"proof", "verify", "-h"}, {"proof", "keys", "-h"}, {"proof", "retire-key", "-h"}} {
		if code, _, _ := runCmd(args...); code != exitOK {
			t.Errorf("%v = %d, want 0", args, code)
		}
	}
}

func TestProofVerifyKeyFiles(t *testing.T) {
	e := newProofEnv(t)
	pdf := writePDF(t, statement(e.pub.KeyID), e.priv)
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
		code, _, errOut := runCmd("proof", "verify", "--keys", writeFile(t, "k.json", []byte(content)), pdf)
		if code != exitError || !strings.Contains(errOut, "public keys:") {
			t.Errorf("%s = %d, %q", name, code, errOut)
		}
	}
	if code, _, errOut := runCmd("proof", "verify", "--keys", filepath.Join(t.TempDir(), "none"), pdf); code != exitError || !strings.Contains(errOut, "public keys:") {
		t.Errorf("missing keys file = %d, %q", code, errOut)
	}
}

func TestProofVerifyURL(t *testing.T) {
	e := newProofEnv(t)
	pdf := writePDF(t, statement(e.pub.KeyID), e.priv)
	list := keyListJSONOf(t, e.pub)

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
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	old := keysClient
	t.Cleanup(func() { keysClient = old })
	keysClient = newKeysClient()
	keysClient.Transport = srv.Client().Transport

	for _, u := range []string{srv.URL, srv.URL + "/", srv.URL + "/custom/keys"} {
		code, out, errOut := runCmd("proof", "verify", "--url", u, pdf)
		if code != exitOK || !strings.Contains(out, "OK: signature valid") {
			t.Errorf("--url %s = %d, %q, %q", u, code, out, errOut)
		}
	}
	if gotPath != "/api/v1/proof-keys" {
		t.Errorf("path = %q", gotPath)
	}
	for _, u := range []string{srv.URL + "/huge", srv.URL + "/missing", srv.URL + "/redirect", "http://example.com", "ftp://x", "https://", "://bad", "https://127.0.0.1:1"} {
		if code, _, errOut := runCmd("proof", "verify", "--url", u, pdf); code != exitError || !strings.Contains(errOut, "public keys:") {
			t.Errorf("--url %s = %d, %q", u, code, errOut)
		}
	}
	// Redirect loop.
	loop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, r.URL.Path+"x", http.StatusFound) }))
	defer loop.Close()
	keysClient.Transport = loop.Client().Transport
	if code, _, errOut := runCmd("proof", "verify", "--url", loop.URL+"/a", pdf); code != exitError || !strings.Contains(errOut, "redirects") {
		t.Errorf("redirect loop = %d, %q", code, errOut)
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
		if got := checkKeysURL(u) == nil; got != ok {
			t.Errorf("checkKeysURL(%q) = %v", raw, got)
		}
	}
}

func TestProofKeysAndRetire(t *testing.T) {
	e := newProofEnv(t)

	code, out, errOut := runCmd("proof", "keys")
	if code != exitOK || errOut != "" || !strings.Contains(out, e.pub.KeyID) || !strings.Contains(out, "active") {
		t.Fatalf("keys = %d, %q, %q", code, out, errOut)
	}

	// Without --yes outside a terminal: usage error. With a terminal: the answer counts.
	oldTTY, oldIn := stdinIsTerminal, stdin
	t.Cleanup(func() { stdinIsTerminal, stdin = oldTTY, oldIn })
	stdinIsTerminal = func() bool { return false }
	if code, _, errOut = runCmd("proof", "retire-key"); code != exitUsage || !strings.Contains(errOut, "--yes") {
		t.Errorf("retire-key (no tty) = %d, %q", code, errOut)
	}
	stdinIsTerminal = func() bool { return true }
	stdin = strings.NewReader("n\n")
	if code, out, _ = runCmd("proof", "retire-key"); code != exitError || !strings.Contains(out, "Aborted") {
		t.Errorf("retire-key (no) = %d, %q", code, out)
	}
	if _, out, _ = runCmd("proof", "keys"); strings.Contains(out, "retired  ") && !strings.Contains(out, "active") {
		t.Errorf("key retired despite the refusal: %q", out)
	}
	stdin = strings.NewReader("yes\n")
	code, out, errOut = runCmd("proof", "retire-key")
	if code != exitOK || !strings.Contains(out, e.pub.KeyID+" retired") || !strings.Contains(out, "stays published") {
		t.Fatalf("retire-key (yes) = %d, %q, %q", code, out, errOut)
	}

	if code, out, _ = runCmd("proof", "keys"); code != exitOK || !strings.Contains(out, "retired") || strings.Contains(out, "active") {
		t.Errorf("keys after retire = %d, %q", code, out)
	}
	if code, _, errOut = runCmd("proof", "retire-key", "--yes"); code != exitError || !strings.Contains(errOut, "no active signing key") {
		t.Errorf("retire-key (none) = %d, %q", code, errOut)
	}

	// The retirement is audited by the command line.
	db, _ := keyStore(t, e.dsn, e.keyFile)
	page, err := db.AuditEvents().List(context.Background(), store.AuditFilter{Limit: store.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range page.Items {
		found = found || (ev.Action == string(audit.ActionProofKeyRetired) && ev.Actor == "cli")
	}
	if !found {
		t.Error("proof_key.retired not audited")
	}
}

func TestProofKeysEmptyAndErrors(t *testing.T) {
	setMigrateEnv(t)
	key := writeKeyFile(t)
	t.Setenv("TT_MASTER_KEY_FILE", key)
	t.Setenv("TT_LOG_LEVEL", "error")
	if code, _, errOut := runCmd("migrate"); code != exitOK {
		t.Fatalf("migrate = %d, %q", code, errOut)
	}
	if code, out, _ := runCmd("proof", "keys"); code != exitOK || !strings.Contains(out, "No signing key yet") {
		t.Errorf("keys (empty) = %d, %q", code, out)
	}
	if code, _, errOut := runCmd("proof", "retire-key", "--yes"); code != exitError || !strings.Contains(errOut, "no active signing key") {
		t.Errorf("retire (empty) = %d, %q", code, errOut)
	}
	// Missing master key file: runtime error for both.
	t.Setenv("TT_MASTER_KEY_FILE", filepath.Join(t.TempDir(), "none.key"))
	for _, sub := range [][]string{{"proof", "keys"}, {"proof", "retire-key", "--yes"}} {
		if code, _, errOut := runCmd(sub...); code != exitError || errOut == "" {
			t.Errorf("%v (no master key) = %d, %q", sub, code, errOut)
		}
	}
	// Invalid configuration.
	t.Setenv("TT_MASTER_KEY_FILE", key)
	t.Setenv("TT_DB_DRIVER", "nope")
	if code, _, _ := runCmd("proof", "keys"); code != exitError {
		t.Errorf("keys (bad config) = %d", code)
	}
}

func TestStdinIsTerminal(_ *testing.T) {
	_ = stdinIsTerminal() // under go test stdin is not a terminal; only exercise the code path
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

func TestProofVerifyEscapesSignedFields(t *testing.T) {
	e := newProofEnv(t)
	st := statement(e.pub.KeyID)
	st.Files[0].Name = "invoice\u202Etxt.exe"
	st.Tenant.Name = "Entity\x1b[2J A"
	keys := writeFile(t, "keys.json", keyListJSONOf(t, e.pub))
	code, out, _ := runCmd("proof", "verify", "--keys", keys, writePDF(t, st, e.priv))
	if code != exitOK || strings.ContainsRune(out, '\u202e') || strings.ContainsRune(out, '\x1b') ||
		!strings.Contains(out, "invoice\\u202Etxt.exe") || !strings.Contains(out, "Entity\\u001B[2J A") {
		t.Fatalf("verify = %d, %q", code, out)
	}
	// --json stays raw: the canonical bytes.
	code, out, _ = runCmd("proof", "verify", "--json", "--keys", keys, writePDF(t, st, e.priv))
	want, _ := st.Marshal()
	if code != exitOK || out != string(want)+"\n" {
		t.Fatalf("--json = %d, %q", code, out)
	}
}

func TestProofVerifyLinkOnly(t *testing.T) {
	e := newProofEnv(t)
	keys := writeFile(t, "keys.json", keyListJSONOf(t, e.pub))
	st := statement(e.pub.KeyID)
	code, out, _ := runCmd("proof", "verify", "--keys", keys, writePDF(t, st, e.priv))
	if code != exitOK || strings.Contains(out, "Link only") {
		t.Fatalf("verify = %d, %q", code, out)
	}
	st.LinkOnly = true
	code, out, _ = runCmd("proof", "verify", "--keys", keys, writePDF(t, st, e.priv))
	if code != exitOK || !strings.Contains(out, "Link only:          recipient not identified") {
		t.Fatalf("verify(link only) = %d, %q", code, out)
	}
}

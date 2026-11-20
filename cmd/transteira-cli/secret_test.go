package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/secret"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tte2"
)

const (
	testSecretToken = "tts_Xp4kQ7mZr2Lw9TfB3nHc8VyJd5Gs1KqA6eWu0RtNb7M" // gitleaks:allow (example token of the specification)
	testSecretLink  = testURL + "/s/" + testSecretToken + "#k=" + testKey
)

// fakeSecretCreate installs a secretCreate recording its options and the
// token of its client, and returning created and err.
func fakeSecretCreate(t *testing.T, created *secret.Created, err error) (*secret.CreateOptions, *string) {
	t.Helper()
	var got secret.CreateOptions
	var token string
	old := secretCreate
	secretCreate = func(_ context.Context, c *client.Client, o secret.CreateOptions) (*secret.Created, error) {
		got, token = o, c.Config().Token
		return created, err
	}
	t.Cleanup(func() { secretCreate = old })
	return &got, &token
}

// fakeSecretRead installs a secretRead recording its client and link, and
// returning rv and err.
func fakeSecretRead(t *testing.T, rv *secret.Revealed, err error) (*secret.Link, **client.Client) {
	t.Helper()
	var got secret.Link
	var gotClient *client.Client
	old := secretRead
	secretRead = func(_ context.Context, c *client.Client, l secret.Link) (*secret.Revealed, error) {
		got, gotClient = l, c
		return rv, err
	}
	t.Cleanup(func() { secretRead = old })
	return &got, &gotClient
}

// secretSetup returns --url and --token-file for a working configuration
// with a token (the secret commands take no --sender).
func secretSetup(t *testing.T) []string {
	t.Helper()
	return tokenSetup(t)[:4]
}

func sampleCreated() *secret.Created {
	return &secret.Created{
		ID: "sec_01JABCS3T4V5W6X7Y8Z9A0B1C2", Link: testSecretLink,
		ExpiresAt: time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC), Anonymous: true,
	}
}

// failWriter fails every write.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestSecretUsage(t *testing.T) {
	env(t)
	for _, args := range [][]string{{"secret"}, {"secret", "-h"}, {"secret", "--help"}} {
		if code, _, e := invoke(t, "", args...); code != exitUsage || !strings.Contains(e, "secret read") {
			t.Errorf("%v: %d %q", args, code, e)
		}
	}
	if code, _, e := invoke(t, "", "secret", "bogus"); code != exitUsage || !strings.Contains(e, "unknown secret command") {
		t.Errorf("bogus: %d %q", code, e)
	}
	for _, sub := range []string{"create", "read"} {
		if code, _, e := invoke(t, "", "secret", sub, "-h"); code != exitOK || !strings.Contains(e, "-url") {
			t.Errorf("%s -h: %d %q", sub, code, e)
		}
	}
	// The text rule of create, which the example scripts do not share, is in its help.
	if _, _, e := invoke(t, "", "secret", "create", "-h"); !strings.Contains(e, "example scripts of the integration guide send the input") {
		t.Errorf("create -h lacks the note on the text: %q", e)
	}
	if code, out, _ := invoke(t, "", "help"); code != exitOK || !strings.Contains(out, "secret create") {
		t.Errorf("help: %q", out)
	}
}

func TestSecretCreateUsage(t *testing.T) {
	env(t)
	got, _ := fakeSecretCreate(t, sampleCreated(), nil)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--url", testURL, "my secret"}, "never taken from the command line"},
		{[]string{"--url", testURL, "--expires", "30d"}, "invalid --expires"},
		{[]string{"--url", testURL, "--anonymous", "--token-file", "t"}, "only one of"},
		{[]string{"--url", testURL, "--file", "f", "-"}, "only one of - (standard input) and --file"},
		{[]string{"--url", testURL, "-", "-"}, "never taken from the command line"},
		{[]string{"--nope"}, "flag provided but not defined"},
	} {
		code, out, e := invoke(t, "text", append([]string{"secret", "create"}, tc.args...)...)
		if code != exitUsage || !strings.Contains(e, tc.want) || out != "" || strings.Contains(e, "my secret") {
			t.Errorf("%v: %d %q %q", tc.args, code, out, e)
		}
	}
	if got.Text != "" {
		t.Fatal("a secret was created")
	}
}

func TestSecretCreateText(t *testing.T) {
	dir := env(t)
	got, token := fakeSecretCreate(t, sampleCreated(), nil)
	base := []string{"secret", "create", "--url", testURL}

	code, out, e := invoke(t, "pass word\n", base...)
	if code != exitOK || out != testSecretLink+"\n" || e != "" {
		t.Fatalf("stdin: %d %q %q", code, out, e)
	}
	if got.Text != "pass word" || got.Duration != "1d" || got.Anonymous || *token != "" {
		t.Fatalf("options %+v token %q", *got, *token)
	}
	if code, _, e := invoke(t, "dash\n", append(base, "-")...); code != exitOK || got.Text != "dash" {
		t.Fatalf("dash: %d %q", code, e)
	}
	if code, _, _ := invoke(t, "\xef\xbb\xbfpass word\r\n", base...); code != exitOK || got.Text != "pass word" {
		t.Fatalf("bom: %d %+v", code, *got)
	}
	if code, _, _ := invoke(t, "\xef\xbb\xbfpass word\r\n", append(base, "--raw", "--expires", "7d")...); code != exitOK ||
		got.Text != "\ufeffpass word\r\n" || got.Duration != "7d" {
		t.Fatalf("raw: %d %+v", code, *got)
	}
	f := writeFile(t, dir, "text.txt", "from file\n")
	if code, _, e := invoke(t, "ignored", append(base, "--file", f, "--expires", "1h")...); code != exitOK || got.Text != "from file" || got.Duration != "1h" {
		t.Fatalf("file: %d %q %+v", code, e, *got)
	}
	// Refused texts: nothing is created.
	got.Text = ""
	for _, in := range []string{"", "\n", strings.Repeat("a", secret.MaxTextRunes+1), "\xff"} {
		if code, out, e := invoke(t, in, base...); code != exitError || out != "" || !strings.Contains(e, "invalid secret text") {
			t.Errorf("%.10q: %d %q", in, code, e)
		}
	}
	if code, _, e := invoke(t, "", append(base, "--file", filepath.Join(dir, "missing"))...); code != exitError || !strings.Contains(e, "text file") {
		t.Errorf("missing file: %d %q", code, e)
	}
	if got.Text != "" {
		t.Fatal("a refused text was sent")
	}
	// No server URL: refused before reading the text.
	if code, _, e := invoke(t, "x", "secret", "create"); code != exitError || !strings.Contains(e, "no server URL") {
		t.Errorf("no url: %d %q", code, e)
	}
}

func TestSecretCreateTokens(t *testing.T) {
	flags := secretSetup(t)
	_, token := fakeSecretCreate(t, sampleCreated(), nil)
	if code, _, e := invoke(t, "x", append([]string{"secret", "create"}, flags...)...); code != exitOK || *token != testToken {
		t.Fatalf("token: %d %q", code, e)
	}
	// --anonymous drops a token coming from the environment.
	t.Setenv("TT_TOKEN", testToken)
	got, token := fakeSecretCreate(t, sampleCreated(), nil)
	if code, _, e := invoke(t, "x", "secret", "create", "--url", testURL, "--anonymous"); code != exitOK || *token != "" || !got.Anonymous {
		t.Fatalf("anonymous: %d %q %q", code, e, *token)
	}
}

// TestSecretNoTokenResolution checks that a broken but unused token
// configuration does not fail "secret read" nor "secret create --anonymous".
func TestSecretNoTokenResolution(t *testing.T) {
	env(t)
	t.Setenv("TT_TOKEN", "not-a-token")
	t.Setenv("TT_TOKEN_FILE", "/nonexistent/token")
	got, _ := fakeSecretCreate(t, sampleCreated(), nil)
	if code, _, e := invoke(t, "x", "secret", "create", "--url", testURL, "--anonymous"); code != exitOK || !got.Anonymous {
		t.Fatalf("create --anonymous: %d %q", code, e)
	}
	read, _ := fakeSecretRead(t, &secret.Revealed{Text: "x"}, nil)
	if code, _, e := invoke(t, "", "secret", "read", testSecretLink); code != exitOK || read.Token != testSecretToken {
		t.Fatalf("read: %d %q", code, e)
	}
	// secret read has no --token-file.
	if code, _, e := invoke(t, "", "secret", "read", "--token-file", "t", testSecretLink); code != exitUsage || !strings.Contains(e, "token-file") {
		t.Fatalf("read --token-file: %d %q", code, e)
	}
	// Without --anonymous the broken token still fails secret create.
	if code, _, _ := invoke(t, "x", "secret", "create", "--url", testURL); code == exitOK {
		t.Fatal("create with a broken token succeeded")
	}
}

func TestSecretCreateOutput(t *testing.T) {
	env(t)
	fakeSecretCreate(t, sampleCreated(), nil)
	base := []string{"secret", "create", "--url", testURL}

	code, out, _ := invoke(t, "x", append(base, "--json")...)
	var j map[string]any
	if code != exitOK || json.Unmarshal([]byte(out), &j) != nil || j["link"] != testSecretLink ||
		j["id"] != "sec_01JABCS3T4V5W6X7Y8Z9A0B1C2" || j["expiresAt"] != "2026-11-18T09:00:00Z" || len(j) != 3 {
		t.Fatalf("json: %d %q", code, out)
	}

	// On a terminal: a reminder on the error output, never the link.
	old := isTerminal
	t.Cleanup(func() { isTerminal = old })
	isTerminal = func(v any) bool { _, isBuf := v.(*bytes.Buffer); return isBuf }
	code, out, e := invoke(t, "x", base...)
	if code != exitOK || out != testSecretLink+"\n" || !strings.Contains(e, "created anonymously") ||
		!strings.Contains(e, "private channel") || strings.Contains(e, testKey) {
		t.Fatalf("terminal: %d %q %q", code, out, e)
	}
	c := sampleCreated()
	c.Anonymous = false
	fakeSecretCreate(t, c, nil)
	if _, _, e := invoke(t, "x", base...); !strings.Contains(e, "with the API token") {
		t.Errorf("token reminder: %q", e)
	}
	// Standard input on a terminal: how to end the text.
	isTerminal = func(v any) bool { _, isReader := v.(*strings.Reader); return isReader }
	if _, _, e := invoke(t, "x", base...); !strings.Contains(e, "Ctrl-D") {
		t.Errorf("prompt: %q", e)
	}
	isTerminal = old

	// The link cannot be written.
	var errb bytes.Buffer
	if code := run(base, strings.NewReader("x"), failWriter{}, &errb); code != exitError || !strings.Contains(errb.String(), "writing the link") {
		t.Fatalf("write: %d %q", code, errb.String())
	}
}

func TestSecretCreateErrors(t *testing.T) {
	env(t)
	fakeSecretCreate(t, nil, secret.ErrTokenNotAllowed)
	code, out, e := invoke(t, "x", "secret", "create", "--url", testURL)
	if code != exitError || out != "" || !strings.Contains(e, "transteira-cli: the API token is not allowed") {
		t.Fatalf("error: %d %q %q", code, out, e)
	}
	// Interrupted.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var outb, errb bytes.Buffer
	if code := runContext(ctx, []string{"secret", "create", "--url", testURL}, strings.NewReader("x"), &outb, &errb); code != exitError ||
		!strings.Contains(errb.String(), "interrupted") {
		t.Fatalf("interrupted: %d %q", code, errb.String())
	}
	// Client errors.
	old := newClient
	newClient = func(client.Config, ...client.Option) (*client.Client, error) { return nil, errors.New("no client") }
	t.Cleanup(func() { newClient = old })
	if code, _, _ := invoke(t, "x", "secret", "create", "--url", testURL); code != exitError {
		t.Error("create client")
	}
	if code, _, _ := invoke(t, "", "secret", "read", testSecretLink); code != exitError {
		t.Error("read client")
	}
}

func TestSecretReadUsage(t *testing.T) {
	env(t)
	got, _ := fakeSecretRead(t, &secret.Revealed{Text: "x"}, nil)
	for _, tc := range []struct {
		stdin string
		args  []string
		want  string
	}{
		{"", nil, "wrong number of arguments"},
		{"", []string{"a", "b"}, "wrong number of arguments"},
		{"", []string{"-"}, "no link given"},
		{"", []string{"nonsense"}, "not a TransTeira secret link"},
		{"", []string{testURL + "/s/" + testSecretToken}, "not a TransTeira secret link"},
		{"", []string{"--force", testSecretLink}, "--force needs --output"},
	} {
		code, out, e := invoke(t, tc.stdin, append([]string{"secret", "read"}, tc.args...)...)
		if code != exitUsage || out != "" || !strings.Contains(e, tc.want) || strings.Contains(e, testKey) {
			t.Errorf("%v: %d %q", tc.args, code, e)
		}
	}
	if got.Token != "" {
		t.Fatal("a secret was read")
	}
	// A secret link given to download.
	if code, _, e := invoke(t, "", "download", testSecretLink); code != exitUsage || !strings.Contains(e, "secret read") {
		t.Errorf("download: %d %q", code, e)
	}
}

func TestSecretReadText(t *testing.T) {
	flags := secretSetup(t)[:2] // --url only: secret read has no --token-file
	got, gotClient := fakeSecretRead(t, &secret.Revealed{Text: "exact\ntext"}, nil)

	// Link on the standard input: no warning, only the text on stdout,
	// exactly, and no token in the client, whose server is the link's.
	code, out, e := invoke(t, testSecretLink+"\n", append([]string{"secret", "read", "-"}, flags...)...)
	if code != exitOK || out != "exact\ntext" || e != "" {
		t.Fatalf("stdin: %d %q %q", code, out, e)
	}
	if got.Token != testSecretToken || got.Key != testKey || (*gotClient).Config().Token != "" || (*gotClient).BaseURL() != testURL {
		t.Fatalf("link %+v", *got)
	}
	// Link on the command line: a warning, never the key; the link
	// decides the server.
	code, _, e = invoke(t, "", "secret", "read", "--url", "https://transfer.entity-b.example.com", testSecretLink)
	if code != exitOK || !strings.Contains(e, "process list") || strings.Contains(e, testKey) || (*gotClient).BaseURL() != testURL {
		t.Fatalf("argv: %d %q", code, e)
	}
}

func TestSecretReadNotices(t *testing.T) {
	env(t)
	for _, tc := range []struct {
		rv   secret.Revealed
		want []string
	}{
		{secret.Revealed{Text: "x", Express: true, Anonymous: true}, []string{"anonymously", "not its author", "report abuse"}},
		{secret.Revealed{Text: "x", Express: true}, []string{"API token of the entity", "not its author"}},
		{secret.Revealed{Text: "x", FileLost: true}, []string{"file", "lost"}},
	} {
		fakeSecretRead(t, &tc.rv, nil)
		code, out, e := invoke(t, testSecretLink, "secret", "read", "-")
		if code != exitOK || out != "x" {
			t.Fatalf("%+v: %d %q", tc.rv, code, out)
		}
		for _, w := range tc.want {
			if !strings.Contains(e, w) {
				t.Errorf("%+v: %q lacks %q", tc.rv, e, w)
			}
		}
	}
	fakeSecretRead(t, &secret.Revealed{Text: "x"}, nil)
	if _, _, e := invoke(t, testSecretLink, "secret", "read", "-"); e != "" {
		t.Errorf("2.1 secret: %q", e)
	}
}

func TestSecretReadTerminal(t *testing.T) {
	env(t)
	old := isTerminal
	t.Cleanup(func() { isTerminal = old })
	isTerminal = func(v any) bool { _, isBuf := v.(*bytes.Buffer); return isBuf }

	fakeSecretRead(t, &secret.Revealed{Text: "plain"}, nil)
	if code, out, e := invoke(t, testSecretLink, "secret", "read", "-"); code != exitOK || out != "plain\n" || e != "" {
		t.Fatalf("plain: %d %q %q", code, out, e)
	}
	fakeSecretRead(t, &secret.Revealed{Text: "a\x1b[2Jb\n"}, nil)
	if code, out, e := invoke(t, testSecretLink, "secret", "read", "-"); code != exitOK || out != `a\x1b[2Jb`+"\n" || !strings.Contains(e, "shown escaped") {
		t.Fatalf("escaped: %d %q %q", code, out, e)
	}
}

func TestSecretReadErrors(t *testing.T) {
	env(t)
	fakeSecretRead(t, nil, secret.ErrGone)
	if code, out, e := invoke(t, testSecretLink, "secret", "read", "-"); code != exitError || out != "" || !strings.Contains(e, "no longer available") {
		t.Fatalf("gone: %d %q", code, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var outb, errb bytes.Buffer
	if code := runContext(ctx, []string{"secret", "read", "-"}, strings.NewReader(testSecretLink), &outb, &errb); code != exitError ||
		!strings.Contains(errb.String(), "interrupted") {
		t.Fatalf("interrupted: %d %q", code, errb.String())
	}
	fakeSecretRead(t, &secret.Revealed{Text: "x"}, nil)
	errb.Reset()
	if code := run([]string{"secret", "read", "-"}, strings.NewReader(testSecretLink), failWriter{}, &errb); code != exitError ||
		!strings.Contains(errb.String(), "the secret is consumed") {
		t.Fatalf("write: %d %q", code, errb.String())
	}
	// Configuration errors: a CA file that does not exist, an unknown profile.
	if code, _, _ := invoke(t, testSecretLink, "secret", "read", "--ca-file", "/nonexistent.pem", "-"); code != exitError {
		t.Error("bad ca file")
	}
	if code, _, e := invoke(t, testSecretLink, "secret", "read", "--profile", "nope", "-"); code != exitError || !strings.Contains(e, "profile") {
		t.Errorf("bad profile: %q", e)
	}
	if code, _, _ := invoke(t, "x", "secret", "create", "--url", testURL, "--ca-file", "/nonexistent.pem"); code != exitError {
		t.Error("bad ca file (create)")
	}
}

func TestSecretReadOutputFile(t *testing.T) {
	dir := env(t)
	got, _ := fakeSecretRead(t, &secret.Revealed{Text: "into a file"}, nil)
	p := filepath.Join(dir, "out.txt")
	read := func(args ...string) (int, string, string) {
		return invoke(t, testSecretLink, append([]string{"secret", "read", "-"}, args...)...)
	}
	if code, out, e := read("--output", p); code != exitOK || out != "" || e != "" {
		t.Fatalf("new file: %d %q %q", code, out, e)
	}
	checkFile(t, p, "into a file")

	// An existing file is refused before anything is read.
	got.Token = ""
	if code, _, e := read("--output", p); code != exitError || !strings.Contains(e, "already exists") || got.Token != "" {
		t.Fatalf("exists: %d %q", code, e)
	}
	// --force replaces it, still private.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	fakeSecretRead(t, &secret.Revealed{Text: "replaced"}, nil)
	if code, _, e := read("--output", p, "--force"); code != exitOK {
		t.Fatalf("force: %d %q", code, e)
	}
	checkFile(t, p, "replaced")
	if code, _, e := read("--output", dir, "--force"); code != exitError || !strings.Contains(e, "is a folder") {
		t.Errorf("folder: %d %q", code, e)
	}
	missing := filepath.Join(dir, "no", "such", "dir", "f")
	for _, args := range [][]string{{"--output", missing}, {"--output", missing, "--force"}} {
		if code, _, e := read(args...); code != exitError || !strings.Contains(e, "output file") {
			t.Errorf("%v: %d %q", args, code, e)
		}
	}
	// A failed read leaves no file behind.
	fakeSecretRead(t, nil, secret.ErrWrongKey)
	for _, args := range [][]string{{"--output", filepath.Join(dir, "a.txt")}, {"--output", p, "--force"}} {
		if code, _, _ := read(args...); code != exitError {
			t.Errorf("%v: %d", args, code)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "out.txt" && e.Name() != "tok" && !e.IsDir() {
			t.Errorf("left behind: %s", e.Name())
		}
	}
	checkFile(t, p, "replaced")
}

// checkFile checks the content and, outside Windows, the 0600 mode of p.
func checkFile(t *testing.T, p, want string) {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil || string(data) != want {
		t.Fatalf("%s: %q %v", p, data, err)
	}
	info, _ := os.Stat(p)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("%s mode %04o", p, info.Mode().Perm())
	}
}

func TestTextOutputFallback(t *testing.T) {
	dir := t.TempDir()
	// The write fails: the text goes to the standard output.
	o, err := openTextOutput(filepath.Join(dir, "a.txt"), false)
	if err != nil {
		t.Fatal(err)
	}
	_ = o.file.Close()
	var out, errb bytes.Buffer
	if code := o.commit(streams{out: &out, err: &errb}, "lost?"); code != exitError || out.String() != "lost?" ||
		!strings.Contains(errb.String(), "the secret is consumed") {
		t.Fatalf("write: %d %q %q", code, out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "a.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("partial file kept: %v", err)
	}
	// The rename fails (a folder appeared at the target).
	target := filepath.Join(dir, "b")
	o, err = openTextOutput(target, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := o.commit(streams{out: &out, err: &errb}, "text"); code != exitError || out.String() != "text" {
		t.Fatalf("rename: %d %q", code, out.String())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temporary file kept: %v", entries)
	}
}

// expressServer is a minimal in-memory server of express secrets for an
// end-to-end run of the commands.
type expressServer struct {
	mu      sync.Mutex
	secrets map[string]map[string]string
	auth    []string
}

func (x *expressServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.auth = append(x.auth, r.Header.Get("Authorization")+"|"+r.Header.Get("Origin")+"|"+r.Header.Get("Sec-Fetch-Site"))
	w.Header().Set("Content-Type", "application/json")
	rest, _ := strings.CutPrefix(r.URL.Path, "/api/v1/secret-links/")
	var in map[string]string
	_ = json.NewDecoder(r.Body).Decode(&in)
	switch {
	case r.URL.Path == "/api/v1/express-secrets":
		tok, _ := id.NewSecretToken()
		x.secrets[tok] = in
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id.New(id.Secret), "token": tok, "state": "active", "expiresAt": "2026-11-18T09:00:00Z"})
	case r.Method == http.MethodGet && x.secrets[rest] != nil:
		_ = json.NewEncoder(w).Encode(map[string]any{"state": "active", "expiresAt": "2026-11-18T09:00:00Z", "file": nil, "express": true, "anonymous": true})
	case r.Method == http.MethodPost && x.secrets[strings.TrimSuffix(rest, "/reveal")] != nil:
		s := x.secrets[strings.TrimSuffix(rest, "/reveal")]
		kv, _ := tte2.ParseProof(s["keyVerifier"])
		kp, _ := tte2.ParseProof(in["keyProof"])
		v, _ := tte2.ParseProof(s["verifier"])
		p, _ := tte2.ParseProof(in["proof"])
		if !tte2.VerifierMatches(kv, kp) || !tte2.VerifierMatches(v, p) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		delete(x.secrets, strings.TrimSuffix(rest, "/reveal"))
		_ = json.NewEncoder(w).Encode(map[string]any{"encryptedText": s["encryptedText"]})
	default:
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusGone)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": 410, "code": "secret-gone", "reason": "read"})
	}
}

func TestSecretEndToEnd(t *testing.T) {
	flags := secretSetup(t)
	x := &expressServer{secrets: map[string]map[string]string{}}
	srv := httptest.NewUnstartedServer(x)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	old := newClient
	newClient = func(c client.Config, o ...client.Option) (*client.Client, error) {
		return old(c, append(o, client.WithRootCAs(pool))...)
	}
	t.Cleanup(func() { newClient = old })

	text := "multi-line\nsecret é😀"
	flags[1] = srv.URL
	code, link, e := invoke(t, text+"\n", append([]string{"secret", "create", "--expires", "1h"}, flags...)...)
	if code != exitOK || !strings.HasPrefix(link, srv.URL+"/s/tts_") || !strings.Contains(link, "#k=") || e != "" {
		t.Fatalf("create: %d %q %q", code, link, e)
	}
	code, out, e := invoke(t, link, "secret", "read", "-")
	if code != exitOK || out != text || !strings.Contains(e, "anonymously") {
		t.Fatalf("read: %d %q %q", code, out, e)
	}
	if code, _, e := invoke(t, link, "secret", "read", "-"); code != exitError || !strings.Contains(e, "already read") {
		t.Fatalf("second read: %d %q", code, e)
	}
	// The token went to the creation only; no browser header anywhere.
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.auth) != 4 || x.auth[0] != "Bearer "+testToken+"||" {
		t.Fatalf("headers %q", x.auth)
	}
	for _, a := range x.auth[1:] {
		if a != "||" {
			t.Fatalf("headers %q", x.auth)
		}
	}
}

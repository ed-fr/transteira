package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/upload"
)

const (
	testToken = "tt_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	testURL   = "https://transfer.entity-a.example.com"
	testLink  = testURL + "/d/dl_aaaaaaaaaaaaaaaaaaaaaa"
	testKey   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// env isolates the process environment from the developer's own.
func env(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, k := range []string{"TT_URL", "TT_TOKEN", "TT_TOKEN_FILE", "TT_SENDER", "TT_PROFILE", "TT_CLI_CONFIG", "TT_CA_FILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("AppData", dir)
	return dir
}

// writeFile writes a 0600 file.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// invoke runs the command line and returns the exit code and the outputs.
func invoke(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// tokenSetup returns the connection flags for a working configuration.
func tokenSetup(t *testing.T) []string {
	t.Helper()
	dir := env(t)
	tf := writeFile(t, dir, "tok", testToken+"\n")
	return []string{"--url", testURL, "--token-file", tf, "--sender", "me@entity-a.example.com"}
}

func TestUsage(t *testing.T) {
	env(t)
	if code, out, _ := invoke(t, ""); code != exitOK || !strings.Contains(out, "upload") {
		t.Errorf("no args: %d %q", code, out)
	}
	if code, _, _ := invoke(t, "", "help"); code != exitOK {
		t.Error("help")
	}
	if code, _, e := invoke(t, "", "bogus"); code != exitUsage || !strings.Contains(e, "unknown command") {
		t.Errorf("bogus: %d %q", code, e)
	}
	if code, _, _ := invoke(t, "", "version", "extra"); code != exitUsage {
		t.Error("version extra")
	}
	if code, out, _ := invoke(t, "", "version"); code != exitOK || !strings.HasPrefix(out, "transteira-cli ") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, out, _ := invoke(t, "", "version", "--json"); code != exitOK || !strings.Contains(out, `"version"`) {
		t.Errorf("version json: %d %q", code, out)
	}
	if code, _, _ := invoke(t, "", "upload", "-h"); code != exitOK {
		t.Error("upload -h")
	}
	if code, _, _ := invoke(t, "", "upload", "--nope"); code != exitUsage {
		t.Error("bad flag")
	}
	if code, _, _ := invoke(t, "", "upload"); code != exitUsage {
		t.Error("upload without file")
	}
	if code, _, _ := invoke(t, "", "config"); code != exitUsage {
		t.Error("config alone")
	}
	if code, _, _ := invoke(t, "", "config", "-h"); code != exitUsage {
		t.Error("config -h")
	}
	if code, _, _ := invoke(t, "", "config", "x"); code != exitUsage {
		t.Error("config x")
	}
	if code, _, _ := invoke(t, "", "proof"); code != exitUsage {
		t.Error("proof alone")
	}
	if code, _, _ := invoke(t, "", "proof", "x"); code != exitUsage {
		t.Error("proof x")
	}
}

func TestConfigCheck(t *testing.T) {
	flags := tokenSetup(t)
	code, out, _ := invoke(t, "", append([]string{"config", "check"}, flags...)...)
	if code != exitOK || !strings.Contains(out, testURL) || !strings.Contains(out, "token:") {
		t.Fatalf("check: %d %q", code, out)
	}
	if strings.Contains(out, testToken) {
		t.Fatal("token printed")
	}
	code, out, _ = invoke(t, "", append([]string{"config", "check", "--json"}, flags...)...)
	if code != exitOK || !strings.Contains(out, `"tokenSet": true`) || strings.Contains(out, testToken) {
		t.Fatalf("check json: %d %q", code, out)
	}
	// No token is fine for check.
	code, out, _ = invoke(t, "", "config", "check", "--url", testURL)
	if code != exitOK || !strings.Contains(out, "not set") {
		t.Fatalf("no token: %d %q", code, out)
	}
	if code, _, e := invoke(t, "", "config", "check"); code != exitError || !strings.Contains(e, "transteira-cli:") {
		t.Fatalf("no url: %d %q", code, e)
	}
	if code, _, _ := invoke(t, "", "config", "check", "--url", testURL, "--ca-file", "/nonexistent.pem"); code != exitError {
		t.Fatal("bad ca file")
	}
	if code, _, _ := invoke(t, "", "config", "check", "extra"); code != exitUsage {
		t.Fatal("extra arg")
	}
}

func TestConfigProfiles(t *testing.T) {
	dir := env(t)
	if code, out, _ := invoke(t, "", "config", "profiles"); code != exitOK || !strings.Contains(out, "No configuration file") {
		t.Fatalf("absent: %d %q", code, out)
	}
	cfg := writeFile(t, dir, "c.json", `{"default":"b","profiles":{"b":{"url":"`+testURL+`"},"a":{"sender":"x@example.com"}}}`)
	code, out, _ := invoke(t, "", "config", "profiles", "--config", cfg)
	if code != exitOK || !strings.Contains(out, "* b") || !strings.Contains(out, "  a") {
		t.Fatalf("list: %d %q", code, out)
	}
	t.Setenv("TT_CLI_CONFIG", cfg)
	code, out, _ = invoke(t, "", "config", "profiles", "--json")
	if code != exitOK || !strings.Contains(out, `"default": true`) {
		t.Fatalf("json: %d %q", code, out)
	}
	t.Setenv("TT_CLI_CONFIG", "")
	// The default location.
	if err := os.MkdirAll(filepath.Join(dir, "transteira"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "transteira"), "config.json", `{"profiles":{}}`)
	if runtime.GOOS == "linux" {
		if code, out, _ = invoke(t, "", "config", "profiles"); code != exitOK || !strings.Contains(out, "(no profile)") {
			t.Fatalf("default location: %d %q", code, out)
		}
	}
	if code, _, _ := invoke(t, "", "config", "profiles", "--config", filepath.Join(dir, "missing.json")); code != exitError {
		t.Fatal("explicit missing file")
	}
	bad := writeFile(t, dir, "bad.json", `{nope`)
	if code, _, _ := invoke(t, "", "config", "profiles", "--config", bad); code != exitError {
		t.Fatal("bad json")
	}
	big := writeFile(t, dir, "big.json", strings.Repeat(" ", client.MaxConfigFileBytes+10))
	if code, _, _ := invoke(t, "", "config", "profiles", "--config", big); code != exitError {
		t.Fatal("big file")
	}
	if code, _, _ := invoke(t, "", "config", "profiles", "--config", dir); code != exitError {
		t.Fatal("directory")
	}
	if runtime.GOOS != "windows" {
		open := writeFile(t, dir, "open.json", `{}`)
		if err := os.Chmod(open, 0o644); err != nil {
			t.Fatal(err)
		}
		if code, _, e := invoke(t, "", "config", "profiles", "--config", open); code != exitError || !strings.Contains(e, "chmod 600") {
			t.Fatalf("permissions: %d %q", code, e)
		}
	}
}

func TestProofUsage(t *testing.T) {
	env(t)
	if code, _, _ := invoke(t, "", "proof", "verify", "x.pdf"); code != exitUsage {
		t.Error("no source")
	}
	if code, _, _ := invoke(t, "", "proof", "verify", "--url", testURL, "--keys-file", "k"); code != exitUsage {
		t.Error("both sources")
	}
	if code, _, _ := invoke(t, "", "proof", "verify", "--keys-file", "k"); code != exitUsage {
		t.Error("no file")
	}
	code, _, e := invoke(t, "", "proof", "verify", filepath.Join(t.TempDir(), "missing.pdf"), "--keys-file", "k")
	if code != exitError || !strings.Contains(e, "proof verify") {
		t.Errorf("missing pdf: %d %q", code, e)
	}
	if code, _, _ := invoke(t, "", "proof", "verify", "-h"); code != exitOK {
		t.Error("-h")
	}
}

// fakeUpload installs an uploadRun returning res and err, and records the options.
func fakeUpload(t *testing.T, res *upload.Result, err error) *upload.Options {
	t.Helper()
	var got upload.Options
	old := uploadRun
	uploadRun = func(_ context.Context, _ *client.Client, o upload.Options) (*upload.Result, error) {
		got = o
		if o.Progress != nil {
			o.Progress(upload.Progress{Phase: upload.PhaseUpload, File: "a.txt", Done: 5, Total: 10})
			o.Progress(upload.Progress{Phase: upload.PhaseScan, Done: 1})
		}
		if o.Warn != nil {
			o.Warn("skipped link\x1b[31m")
		}
		return res, err
	}
	t.Cleanup(func() { uploadRun = old })
	return &got
}

func sampleResult() *upload.Result {
	return &upload.Result{
		TransferID: "tr_1", Status: "available", ExpiresAt: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
		Files: []upload.FileResult{
			{Name: "a.txt", Path: "dir", Size: 2048, SHA256: "ab", ScanStatus: "clean"},
			{Name: "big.iso", Size: 3, SHA256: "cd", ScanStatus: "not_scanned_too_large"},
		},
	}
}

func TestUploadText(t *testing.T) {
	flags := tokenSetup(t)
	got := fakeUpload(t, sampleResult(), nil)
	dir := t.TempDir()
	pw := writeFile(t, dir, "pw", "secret\r\n")
	msg := writeFile(t, dir, "msg", "hello")
	args := append([]string{
		"upload", "--to", "a@example.org,b@example.org", "--to", "c@example.org", "--from", "f@entity-a.example.com",
		"--expiry", "30", "--max-downloads", "3", "--delete-after-download", "--verify-recipients", "--level", "secret",
		"--language", "fr", "--chunk-size", "1GiB", "--state-file", "st.json", "--restart", "--no-wait",
		"--password-file", pw, "--message-file", msg, "x.bin", "y.bin",
	}, flags...)
	code, out, e := invoke(t, "", args...)
	if code != exitOK {
		t.Fatalf("code %d %q", code, e)
	}
	if len(got.Recipients) != 3 || got.Sender != "f@entity-a.example.com" || got.ExpiryDays != 30 || got.Password != "secret" ||
		got.Message != "hello" || got.ChunkSize != 1<<30 || len(got.Paths) != 2 || !got.Restart || !got.NoWait || !got.VerifyRecipients {
		t.Errorf("options: %+v", got)
	}
	for _, want := range []string{"Transfer: tr_1", "dir/a.txt", "sha256:cd", "scan:not_scanned_too_large"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q: %q", want, out)
		}
	}
	if !strings.Contains(e, "NOT SCANNED") || !strings.Contains(e, "warning: skipped link") || strings.Contains(e, "\x1b") {
		t.Errorf("stderr: %q", e)
	}
	// Flags after the files work too.
	args = append([]string{"upload", "x.bin", "--to", "a@example.org"}, flags...)
	if code, _, e := invoke(t, "", args...); code != exitOK {
		t.Fatalf("interspersed: %d %q", code, e)
	}
	if got.ExpiryDays != 7 {
		t.Errorf("default expiry %d", got.ExpiryDays)
	}
}

func TestUploadProgressOnTerminal(t *testing.T) {
	flags := tokenSetup(t)
	fakeUpload(t, sampleResult(), nil)
	old := isTerminal
	isTerminal = func(v any) bool { _, isBuf := v.(*bytes.Buffer); return isBuf }
	t.Cleanup(func() { isTerminal = old })
	code, _, e := invoke(t, "", append([]string{"upload", "--to", "a@example.org", "x"}, flags...)...)
	if code != exitOK || !strings.Contains(e, "upload a.txt: 5 B / 10 B (50%)") || !strings.Contains(e, "scan: 1 B") {
		t.Fatalf("progress: %d %q", code, e)
	}
}

func TestUploadJSONAndKeys(t *testing.T) {
	flags := tokenSetup(t)
	res := sampleResult()
	res.Key = testKey
	res.Link = testLink
	fakeUpload(t, res, nil)
	base := append([]string{"upload", "--e2e", "--to", "a@example.org", "x"}, flags...)

	code, out, _ := invoke(t, "", append(base, "--json")...)
	if code != exitOK || !strings.Contains(out, `"key": "`+testKey) || strings.Contains(out, "#k=") {
		t.Fatalf("json: %d %q", code, out)
	}
	code, out, _ = invoke(t, "", base...)
	if code != exitOK || !strings.Contains(out, "Key: "+testKey) || !strings.Contains(out, "another channel") || strings.Contains(out, "#k=") {
		t.Fatalf("text: %d %q", code, out)
	}

	keyOut := filepath.Join(t.TempDir(), "k.key")
	code, out, _ = invoke(t, "", append(base, "--key-out", keyOut)...)
	if code != exitOK || strings.Contains(out, testKey) || !strings.Contains(out, "Key written to") {
		t.Fatalf("key-out: %d %q", code, out)
	}
	data, err := os.ReadFile(keyOut)
	if err != nil || strings.TrimSpace(string(data)) != testKey {
		t.Fatalf("key file: %q %v", data, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(keyOut); st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", st.Mode().Perm())
		}
	}
	code, out, _ = invoke(t, "", append(append([]string{}, base...), "--key-out", keyOut, "--json")...)
	if code != exitUsage {
		t.Fatalf("existing key file: %d %q", code, out)
	}
	keyOut2 := filepath.Join(t.TempDir(), "k2.key")
	code, out, _ = invoke(t, "", append(append([]string{}, base...), "--key-out", keyOut2, "--json")...)
	if code != exitOK || !strings.Contains(out, `"keyFile"`) || strings.Contains(out, testKey) {
		t.Fatalf("json key-out: %d %q", code, out)
	}
	// Link only: the key goes into the link.
	code, out, _ = invoke(t, "", append(base, "--link-only")...)
	if code != exitOK || !strings.Contains(out, "Link: "+testLink+"#k="+testKey) || strings.Contains(out, "Key:") {
		t.Fatalf("link-only: %d %q", code, out)
	}
	// An uncreatable key file fails before anything is sent.
	bad := filepath.Join(t.TempDir(), "no", "dir", "k")
	got := fakeUpload(t, res, nil)
	code, out, _ = invoke(t, "", append(append([]string{}, base...), "--key-out", bad)...)
	if code != exitError || out != "" || got.Paths != nil {
		t.Fatalf("uncreatable: %d %q %v", code, out, got.Paths)
	}
	// A failed upload removes the empty key file.
	failKey := filepath.Join(t.TempDir(), "failed.key")
	fakeUpload(t, nil, errors.New("boom"))
	code, _, _ = invoke(t, "", append(append([]string{}, base...), "--key-out", failKey)...)
	if code != exitError {
		t.Fatalf("failed upload: %d", code)
	}
	if _, err := os.Lstat(failKey); err == nil {
		t.Error("empty key file left behind")
	}
}

func TestWriteKeyFileFailure(t *testing.T) {
	if err := writeKeyFile(filepath.Join(t.TempDir(), "missing"), "k"); err == nil {
		t.Error("expected an error")
	}
}

func TestMessageFileLimit(t *testing.T) {
	dir := t.TempDir()
	big := writeFile(t, dir, "big", strings.Repeat("a", maxMessageBytes+1))
	if _, err := readMessageFile(big); err == nil {
		t.Error("oversized message accepted")
	}
	ok := writeFile(t, dir, "ok", strings.Repeat("a", maxMessageBytes))
	if m, err := readMessageFile(ok); err != nil || len(m) != maxMessageBytes {
		t.Errorf("limit: %d %v", len(m), err)
	}
}

func TestE2EMessageWarning(t *testing.T) {
	flags := tokenSetup(t)
	fakeUpload(t, &upload.Result{TransferID: "t", Key: testKey}, nil)
	_, _, e := invoke(t, "", append([]string{"upload", "--e2e", "--message", "secret", "--to", "a@example.org", "x"}, flags...)...)
	if !strings.Contains(e, "--message-file") {
		t.Errorf("no warning: %q", e)
	}
}

func TestParseFlagsTerminator(t *testing.T) {
	var buf bytes.Buffer
	fs := newFlagSet("t", &buf)
	to := fs.String("to", "", "")
	v := fs.Bool("v", false, "")
	rest, code, ok := parseFlags(fs, []string{"a", "--to", "--", "-v", "--", "-weird.txt", "--to"}, 1, -1, &buf)
	if !ok || code != exitOK || *to != "--" || !*v {
		t.Fatalf("parse: %v %d %q %v", ok, code, *to, *v)
	}
	if want := []string{"a", "-weird.txt", "--to"}; !slices.Equal(rest, want) {
		t.Errorf("rest %v, want %v", rest, want)
	}
}

func TestUploadUsageErrors(t *testing.T) {
	flags := tokenSetup(t)
	dir := t.TempDir()
	pw := writeFile(t, dir, "pw", "x")
	base := append([]string{"upload", "--to", "a@example.org", "x"}, flags...)
	cases := map[string][]string{
		"chunk":       {"--chunk-size", "12 parsecs"},
		"key-out":     {"--key-out", filepath.Join(dir, "k")},
		"message":     {"--message", "a", "--message-file", pw},
		"pw both":     {"--password-file", pw, "--password-prompt"},
		"no tty":      {"--password-prompt"},
		"missing msg": {"--message-file", filepath.Join(dir, "nope")},
		"missing pw":  {"--password-file", filepath.Join(dir, "nope")},
	}
	for name, extra := range cases {
		if code, _, e := invoke(t, "", append(append([]string{}, base...), extra...)...); code != exitUsage {
			t.Errorf("%s: code %d %q", name, code, e)
		}
	}
	// Errors before the client: no URL, no token.
	env(t)
	if code, _, _ := invoke(t, "", "upload", "--to", "a@example.org", "x"); code != exitError {
		t.Error("no config")
	}
}

func TestUploadPromptPassword(t *testing.T) {
	flags := tokenSetup(t)
	got := fakeUpload(t, sampleResult(), nil)
	oldT, oldR := isTerminal, readPassword
	answers := []string{"pw1", "pw1"}
	isTerminal = func(v any) bool { _, isReader := v.(*strings.Reader); return isReader }
	readPassword = func(int) ([]byte, error) {
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
	t.Cleanup(func() { isTerminal, readPassword = oldT, oldR })
	code, _, e := invoke(t, "", append([]string{"upload", "--to", "a@example.org", "--password-prompt", "x"}, flags...)...)
	if code != exitOK || got.Password != "pw1" {
		t.Fatalf("prompt: %d %q %q", code, e, got.Password)
	}
	answers = []string{"a", "b"}
	if code, _, e := invoke(t, "", append([]string{"upload", "--to", "a@example.org", "--password-prompt", "x"}, flags...)...); code != exitUsage || !strings.Contains(e, "differ") {
		t.Fatalf("mismatch: %d %q", code, e)
	}
	readPassword = func(int) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
	if code, _, _ := invoke(t, "", append([]string{"upload", "--to", "a@example.org", "--password-prompt", "x"}, flags...)...); code != exitUsage {
		t.Fatal("read error")
	}
}

func TestUploadErrors(t *testing.T) {
	flags := tokenSetup(t)
	base := append([]string{"upload", "--to", "a@example.org", "x"}, flags...)

	fakeUpload(t, sampleResult(), upload.ErrRejected)
	code, out, e := invoke(t, "", base...)
	if code != exitRejected || !strings.Contains(out, "Transfer: tr_1") || !strings.Contains(e, "rejected") {
		t.Errorf("rejected: %d %q %q", code, out, e)
	}
	fakeUpload(t, nil, upload.ErrRejected)
	if code, _, _ := invoke(t, "", base...); code != exitRejected {
		t.Error("rejected nil result")
	}
	fakeUpload(t, nil, upload.ErrStateMismatch)
	if code, _, e := invoke(t, "", base...); code != exitError || !strings.Contains(e, "--restart") {
		t.Errorf("mismatch: %d %q", code, e)
	}
	fakeUpload(t, nil, upload.ErrInvalidOptions)
	if code, _, _ := invoke(t, "", base...); code != exitUsage {
		t.Error("invalid options")
	}
	fakeUpload(t, nil, errors.New("boom"))
	if code, _, e := invoke(t, "", base...); code != exitError || !strings.Contains(e, "transteira-cli: boom") {
		t.Errorf("boom: %d %q", code, e)
	}
	// Interruption.
	fakeUpload(t, nil, context.Canceled)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var errb bytes.Buffer
	if code := runContext(ctx, base, strings.NewReader(""), io.Discard, &errb); code != exitError || !strings.Contains(errb.String(), "run the same command again") {
		t.Errorf("interrupted: %d %q", code, errb.String())
	}
	// A nil result with success prints nothing.
	fakeUpload(t, nil, nil)
	if code, _, _ := invoke(t, "", base...); code != exitOK {
		t.Error("nil result")
	}
}

func TestClientErrors(t *testing.T) {
	flags := tokenSetup(t)
	old := newClient
	newClient = func(client.Config, ...client.Option) (*client.Client, error) { return nil, errors.New("no client") }
	t.Cleanup(func() { newClient = old })
	if code, _, _ := invoke(t, "", append([]string{"upload", "--to", "a@example.org", "x"}, flags...)...); code != exitError {
		t.Error("upload")
	}
	if code, _, _ := invoke(t, "", "download", testLink); code != exitError {
		t.Error("download")
	}
	if code, _, _ := invoke(t, "", append([]string{"config", "check"}, flags...)...); code != exitError {
		t.Error("check")
	}
}

func TestVerbose(t *testing.T) {
	flags := tokenSetup(t)
	var gotOpts int
	old := newClient
	newClient = func(c client.Config, o ...client.Option) (*client.Client, error) {
		gotOpts = len(o)
		return old(c, o...)
	}
	t.Cleanup(func() { newClient = old })
	fakeUpload(t, sampleResult(), nil)
	invoke(t, "", append([]string{"upload", "--verbose", "--to", "a@example.org", "x"}, flags...)...)
	if gotOpts != 1 {
		t.Errorf("logger option missing: %d", gotOpts)
	}
}

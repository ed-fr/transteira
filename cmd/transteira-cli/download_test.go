package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/download"
)

// fakeDownload installs a downloadRun returning res and err and records the
// options and the client URL.
func fakeDownload(t *testing.T, res *download.Result, err error, call func(download.Options)) *download.Options {
	t.Helper()
	var got download.Options
	old := downloadRun
	downloadRun = func(_ context.Context, c *client.Client, o download.Options) (*download.Result, error) {
		got = o
		if c.Config().Token != "" {
			t.Error("token sent to a download")
		}
		if o.Progress != nil {
			o.Progress(download.Progress{File: "a", Done: 1, Total: 2})
		}
		if o.Warn != nil {
			o.Warn("wrong code")
		}
		if call != nil {
			call(o)
		}
		return res, err
	}
	t.Cleanup(func() { downloadRun = old })
	return &got
}

func downloadResult() *download.Result {
	return &download.Result{
		Sender: "s@example.org", Message: "hi", ExpiresAt: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
		Files: []download.FileResult{
			{ID: "f1", Path: "in/a.txt", Size: 10, SHA256: "ab", ScanStatus: "clean"},
			{ID: "f2", Path: "in/b.txt", Size: 10, SHA256: "cd", ScanStatus: "not_scanned_e2e"},
			{ID: "f3", Path: "in/c.txt", Skipped: true, ScanStatus: "infected"},
		},
	}
}

// archiveResult is the result of an archive download: files listed by the
// server, without a path.
func archiveResult() *download.Result {
	return &download.Result{
		Sender:  "s@example.org",
		Files:   []download.FileResult{{ID: "fil_a", Size: 10, SHA256: "ab", ScanStatus: "clean"}},
		Archive: "in/all.zip",
	}
}

func TestDownloadArchiveText(t *testing.T) {
	env(t)
	fakeDownload(t, archiveResult(), nil, nil)
	code, out, _ := invoke(t, "", "download", "--archive", testLink)
	if code != exitOK || !strings.Contains(out, "Archive: in/all.zip") || !strings.Contains(out, "Listed: fil_a") || strings.Contains(out, "Written") {
		t.Fatalf("archive: %d %q", code, out)
	}
}

func TestDownloadLinkSources(t *testing.T) {
	env(t)
	got := fakeDownload(t, downloadResult(), nil, nil)
	code, out, e := invoke(t, "", "download", "--output", "o", "--file", "a,b", "--file", "c", "--archive", "--force", testLink)
	if code != exitOK || got.Link.Origin != testURL || got.Output != "o" || len(got.Files) != 2 || !got.Archive || !got.Force {
		t.Fatalf("link arg: %d %q %+v", code, e, got)
	}
	if got.Files[0] != "a,b" {
		t.Errorf("file names must not be split: %v", got.Files)
	}
	for _, want := range []string{"From: s@example.org", "Message:", "Written: in/a.txt", "Skipped: in/c.txt"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q: %q", want, out)
		}
	}
	if !strings.Contains(e, "NOT SCANNED") || strings.Contains(e, "in/c.txt") {
		t.Errorf("warnings: %q", e)
	}

	// Link on the standard input, key in it, no warning.
	code, _, e = invoke(t, testLink+"#k="+testKey+"\n", "download", "-")
	if code != exitOK || got.Link.Key != testKey || strings.Contains(e, "process list") {
		t.Fatalf("stdin: %d %q", code, e)
	}
	// Key on the command line: warning, and the key is never echoed.
	code, _, e = invoke(t, "", "download", testLink+"#k="+testKey)
	if code != exitOK || !strings.Contains(e, "process list") || strings.Contains(e, testKey) {
		t.Fatalf("argv key: %d %q", code, e)
	}
	// Bare token needs a URL.
	if code, _, _ := invoke(t, "", "download", "dl_aaaaaaaaaaaaaaaaaaaaaa"); code != exitError {
		t.Error("bare token without url")
	}
	if code, _, _ := invoke(t, "", "download", "--url", testURL, "dl_aaaaaaaaaaaaaaaaaaaaaa"); code != exitOK || got.Link.Origin != "" {
		t.Error("bare token with url")
	}
	// Bad links and usage.
	if code, _, _ := invoke(t, "", "download", "nonsense"); code != exitUsage {
		t.Error("bad link")
	}
	if code, _, _ := invoke(t, "", "download", "-"); code != exitUsage {
		t.Error("empty stdin")
	}
	if code, _, _ := invoke(t, "", "download"); code != exitUsage {
		t.Error("no link")
	}
	if code, _, _ := invoke(t, "", "download", "-h"); code != exitOK {
		t.Error("-h")
	}
	if code, _, _ := invoke(t, "", "download", "--password-file", "p", "--password-prompt", testLink); code != exitUsage {
		t.Error("both password sources")
	}
	// A line without newline is accepted.
	if code, _, _ := invoke(t, testLink, "download", "-"); code != exitOK {
		t.Error("no trailing newline")
	}
}

func TestDownloadJSONAndErrors(t *testing.T) {
	env(t)
	fakeDownload(t, downloadResult(), nil, nil)
	code, out, _ := invoke(t, "", "download", "--json", testLink)
	if code != exitOK || !strings.Contains(out, `"endToEnd": false`) || !strings.Contains(out, `"skipped": true`) {
		t.Fatalf("json: %d %q", code, out)
	}
	fakeDownload(t, downloadResult(), errors.New("integrity"), nil)
	code, out, e := invoke(t, "", "download", testLink)
	if code != exitError || !strings.Contains(e, "transteira-cli: integrity") || strings.Contains(out, "Written:") || !strings.Contains(out, "From:") {
		t.Fatalf("error: %d %q %q", code, out, e)
	}
	if code, out, _ := invoke(t, "", "download", "--json", testLink); code != exitError || out != "" {
		t.Errorf("json error prints nothing: %d %q", code, out)
	}
	fakeDownload(t, nil, errors.New("x"), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var errb strings.Builder
	if code := runContext(ctx, []string{"download", testLink}, strings.NewReader(""), &strings.Builder{}, &errb); code != exitError || !strings.Contains(errb.String(), "resume") {
		t.Errorf("interrupted: %d %q", code, errb.String())
	}
	// A result without expiry.
	fakeDownload(t, &download.Result{}, nil, nil)
	if code, _, _ := invoke(t, "", "download", "--json", testLink); code != exitOK {
		t.Error("empty result")
	}
}

func TestDownloadSecrets(t *testing.T) {
	dir := env(t)
	var pw, key, code string
	var errs [3]error
	fakeDownload(t, downloadResult(), nil, func(o download.Options) {
		pw, errs[0] = o.Password()
		code, errs[1] = o.Code("a***@example.org")
		key, errs[2] = o.Key()
	})
	// Not a terminal: every prompt fails with advice.
	invoke(t, "", "download", testLink)
	for i, want := range []string{"--password-file", "terminal", "--key-file"} {
		if errs[i] == nil || !strings.Contains(errs[i].Error(), want) {
			t.Errorf("prompt %d: %v", i, errs[i])
		}
	}
	// Files.
	pwFile := writeFile(t, dir, "pw", "hunter2\n")
	keyFile := writeFile(t, dir, "key", testKey+"\n")
	got := fakeDownload(t, downloadResult(), nil, func(o download.Options) {
		pw, errs[0] = o.Password()
		key, errs[2] = o.Key()
	})
	c, _, e := invoke(t, "", "download", "--password-file", pwFile, "--key-file", keyFile, testLink+"#k="+strings.Repeat("A", 43))
	if c != exitOK || pw != "hunter2" || key != testKey || got.Link.Key != "" || !got.KeyProvided || !got.PasswordOnce {
		t.Fatalf("files: %d %q pw=%q key=%q linkkey=%q", c, e, pw, key, got.Link.Key)
	}
	// Terminal prompts.
	oldT, oldR := isTerminal, readPassword
	isTerminal = func(v any) bool { _, ok := v.(*strings.Reader); return ok }
	readPassword = func(int) ([]byte, error) { return []byte("typed\n"), nil }
	t.Cleanup(func() { isTerminal, readPassword = oldT, oldR })
	got = fakeDownload(t, downloadResult(), nil, func(o download.Options) {
		pw, _ = o.Password()
		code, _ = o.Code("a***@example.org")
		key, _ = o.Key()
	})
	_, _, e = invoke(t, "", "download", testLink)
	if got.PasswordOnce || got.KeyProvided || got.CodeOnce {
		t.Errorf("prompts must allow retries and no key was given: %+v", got)
	}
	if pw != "typed" || code != "typed" || key != "typed" || !strings.Contains(e, "Verification code sent to a***@example.org") {
		t.Errorf("typed: %q %q %q %q", pw, code, key, e)
	}
	// Unreadable secret files.
	if c, _, _ := invoke(t, "", "download", "--password-file", filepath.Join(dir, "nope"), testLink); c != exitError {
		t.Error("missing password file")
	}
	if c, _, _ := invoke(t, "", "download", "--key-file", filepath.Join(dir, "nope"), testLink); c != exitError {
		t.Error("missing key file")
	}
}

func TestDownloadUsesProfileCA(t *testing.T) {
	dir := env(t)
	ca := writeFile(t, dir, "ca.pem", "not a certificate")
	fakeDownload(t, downloadResult(), nil, nil)
	// An invalid CA file is reported by the real client.
	if c, _, e := invoke(t, "", "download", "--ca-file", ca, testLink); c != exitError || !strings.Contains(e, "transteira-cli:") {
		t.Errorf("bad CA: %d %q", c, e)
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string]int64{"5": 5, "100MiB": 100 << 20, "1gib": 1 << 30, "2 KiB": 2048} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0", "-1", "x", "99999999999GiB", "1.5GiB"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) accepted", in)
		}
	}
	for n, want := range map[int64]string{5: "5 B", 2048: "2.0 KiB", 5 << 30: "5.0 GiB"} {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q", n, got)
		}
	}
	var l stringList
	_ = l.Set("a")
	_ = l.Set("b,c")
	if len(l.values) != 2 || l.values[1] != "b,c" {
		t.Errorf("non-split list %v", l.values)
	}
	l = stringList{split: true}
	_ = l.Set(" a , ,b")
	if l.String() != "a,b" {
		t.Errorf("split list %v", l.values)
	}

	dir := t.TempDir()
	for content, want := range map[string]string{"pw\n": "pw", "pw\r\n": "pw", "pw\n\n": "pw\n", "": ""} {
		p := writeFile(t, dir, "s", content)
		if got, err := readSecretFile(p, "password"); err != nil || got != want {
			t.Errorf("readSecretFile(%q) = %q, %v", content, got, err)
		}
	}
	if _, err := readSecretFile(dir, "password"); err == nil {
		t.Error("directory accepted")
	}
	big := writeFile(t, dir, "big", strings.Repeat("x", maxSecretFileBytes+1))
	if _, err := readSecretFile(big, "password"); err == nil {
		t.Error("big file accepted")
	}
	if os.PathSeparator == '/' {
		open := writeFile(t, dir, "open", "x")
		_ = os.Chmod(open, 0o644)
		if _, err := readSecretFile(open, "password"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("open file: %v", err)
		}
	}
	if _, err := readLine(strings.NewReader(strings.Repeat("a", 5000))); err != nil {
		t.Errorf("long line is cut, not an error: %v", err)
	}
	if _, err := readLine(strings.NewReader("")); err == nil {
		t.Error("empty input")
	}
	for status, warn := range map[string]bool{
		"clean": false, "": false, "pending": false, "infected": true, "scan_error": true,
		"not_scanned_too_large": true, "not_scanned_e2e": true, "not_scanned_disabled": true, "weird": true,
	} {
		if (scanWarning(status) != "") != warn {
			t.Errorf("scanWarning(%q)", status)
		}
	}
	if _, ok := fdOf(strings.NewReader("")); ok {
		t.Error("fdOf of a reader")
	}
	if isTerminal(strings.NewReader("")) {
		t.Error("reader is not a terminal")
	}
	pp := newProgressPrinter(&strings.Builder{}, time.Hour)
	pp.print("a", 1, 0)
	pp.print("a", 2, 0)
}

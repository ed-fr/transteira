package download

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/safepath"
)

// run downloads the fake link into a new directory, or into o.Output.
func run(t *testing.T, f *fake, o Options) (*Result, string, error) {
	t.Helper()
	if o.Output == "" {
		o.Output = t.TempDir()
	}
	c := f.client(t)
	if o.Link.Token == "" {
		o.Link = Link{Origin: f.srv.URL, Token: testToken}
	}
	res, err := Run(context.Background(), c, o)
	return res, o.Output, err
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// listDir returns the relative slash paths of every file under dir.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

func TestPlainMultiFileWithFolders(t *testing.T) {
	a, b, c := pattern("a", 300_000), pattern("b", 10), []byte{}
	f := newFake(t,
		plainFile("fil_a", "finance/2027", "budget.xlsx", a),
		plainFile("fil_b", "", "notes\u202e.txt", b),
		plainFile("fil_c", "finance", "empty.bin", c),
	)
	f.files[1].scan = "not_scanned_too_large"
	f.message = "Hello\r\n\u202eworld\x1b[31m"
	var progress []Progress
	res, out, err := run(t, f, Options{Progress: func(p Progress) { progress = append(progress, p) }})
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(out, "finance", "2027", "budget.xlsx")); !bytes.Equal(got, a) {
		t.Error("budget content differs")
	}
	if got := listDir(t, out); !slices.Equal(got, []string{"file", "finance/2027/budget.xlsx", "finance/empty.bin"}) {
		t.Errorf("files = %v", got)
	}
	if res.Sender != "alice@entity-a.example.com" || res.Message != "Hello\nworld[31m" || res.EndToEnd || res.Archive != "" {
		t.Errorf("result = %+v", res)
	}
	if res.ExpiresAt.IsZero() || len(res.Files) != 3 || res.Files[1].ScanStatus != "not_scanned_too_large" ||
		res.Files[0].Path != filepath.Join(out, "finance", "2027", "budget.xlsx") || res.Files[0].SHA256 != hexSHA(a) || res.Files[0].Size != int64(len(a)) {
		t.Errorf("files = %+v", res.Files)
	}
	if len(progress) == 0 || progress[len(progress)-1].File != "file" || progress[len(progress)-1].Done != 10 {
		t.Errorf("progress = %v", progress)
	}
}

func TestResumeAcrossRuns(t *testing.T) {
	data := pattern("resume", 500_000)
	f := newFake(t, plainFile("fil_a", "dir", "big.bin", data))
	out := t.TempDir()
	if err := os.MkdirAll(filepath.Join(out, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "dir", ".big.bin.part"), data[:123_456], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Output: out}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "dir", "big.bin")), data) {
		t.Error("content differs")
	}
	if !slices.Contains(f.log(), "GET "+apiPrefix+testToken+"/files/fil_a bytes=123456-") {
		t.Errorf("no range request: %v", f.log())
	}
	if got := listDir(t, out); !slices.Equal(got, []string{"dir/big.bin"}) {
		t.Errorf("files = %v", got)
	}
}

func TestResumeCompletePart(t *testing.T) {
	data := pattern("full", 1000)
	f := newFake(t, plainFile("fil_a", "", "a.bin", data))
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Output: out}); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.log() {
		if strings.Contains(r, "/files/") {
			t.Errorf("unexpected request %s", r)
		}
	}
	// A part file longer than the file starts over.
	if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), append(data, 'x'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Output: out, Force: true}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), data) {
		t.Error("content differs")
	}
}

func TestResumeCorruptedPart(t *testing.T) {
	data := pattern("bad", 5000)
	f := newFake(t, plainFile("fil_a", "", "a.bin", data))
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), bytes.Repeat([]byte{1}, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Output: out}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v", err)
	}
	if got := listDir(t, out); len(got) != 0 {
		t.Errorf("files left: %v", got)
	}
}

func TestResumeInProcess(t *testing.T) {
	data := pattern("cut", 1_000_000)
	f := newFake(t, plainFile("fil_a", "", "a.bin", data))
	f.cut["fil_a"] = 400_000
	var warnings []string
	_, out, err := run(t, f, Options{Warn: func(s string) { warnings = append(warnings, s) }})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), data) {
		t.Error("content differs")
	}
	log := f.log()
	last := log[len(log)-1]
	if !strings.HasPrefix(last, "GET "+apiPrefix+testToken+"/files/fil_a bytes=") || len(warnings) == 0 {
		t.Errorf("log = %v, warnings = %v", log, warnings)
	}
}

func TestRangeIgnoredStartsOver(t *testing.T) {
	data := pattern("ignored", 70_000)
	f := newFake(t, plainFile("fil_a", "", "a.bin", data))
	f.ignoreRange = true
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Output: out}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), data) {
		t.Error("content differs")
	}
}

func TestIntegrityMismatchRemovesPart(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "", "a.bin", pattern("x", 1000)))
	f.files[0].sha = hexSHA([]byte("other"))
	_, out, err := run(t, f, Options{})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v", err)
	}
	if got := listDir(t, out); len(got) != 0 {
		t.Errorf("files left: %v", got)
	}
	f.set(func() { f.files[0].sha = "not-hex" })
	if _, _, err := run(t, f, Options{}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v", err)
	}
}

func TestShortAnswer(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "", "a.bin", pattern("x", 1000)))
	f.files[0].listedSize = 2000 // the server lists more than it sends
	if _, _, err := run(t, f, Options{}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v", err)
	}
}

func TestExistingTarget(t *testing.T) {
	data := pattern("x", 100)
	f := newFake(t, plainFile("fil_a", "", "a.bin", data), plainFile("fil_b", "", "b.bin", data))
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "b.bin"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Output: out}); !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v", err)
	}
	if len(f.log()) != 1 { // the page only, nothing downloaded
		t.Errorf("requests = %v", f.log())
	}
	if _, _, err := run(t, f, Options{Output: out, Force: true}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "b.bin")), data) {
		t.Error("not replaced")
	}
	// A directory in the way is never replaced.
	out2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(out2, "a.bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Output: out2, Force: true}); !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v", err)
	}
}

func TestSymlinkFolderRefused(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "sub", "a.bin", []byte("x")))
	out, elsewhere := t.TempDir(), t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(out, "sub")); err != nil {
		t.Skip(err)
	}
	if _, _, err := run(t, f, Options{Output: out}); !errors.Is(err, safepath.ErrSymlink) {
		t.Fatalf("err = %v", err)
	}
	if got := listDir(t, elsewhere); len(got) != 0 {
		t.Errorf("written outside: %v", got)
	}
}

func TestFilter(t *testing.T) {
	f := newFake(t,
		plainFile("fil_a", "x", "a.bin", []byte("a")),
		plainFile("fil_b", "", "b.bin", []byte("b")),
		plainFile("fil_c", "", "c.bin", []byte("c")),
	)
	res, out, err := run(t, f, Options{Files: []string{"fil_b", "x/a.bin"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, out); !slices.Equal(got, []string{"b.bin", "x/a.bin"}) {
		t.Errorf("files = %v", got)
	}
	if !res.Files[2].Skipped || res.Files[0].Skipped || res.Files[2].Path != filepath.Join(out, "c.bin") {
		t.Errorf("results = %+v", res.Files)
	}
	if _, _, err := run(t, f, Options{Files: []string{"c.bin", "missing\x1b"}}); !errors.Is(err, ErrNoMatch) || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("err = %v", err)
	}
}

func TestPassword(t *testing.T) {
	data := []byte("secret file")
	f := newFake(t, plainFile("fil_a", "", "a.bin", data))
	f.password = "right"
	answers := []string{"wrong", "right"}
	var warnings []string
	res, out, err := run(t, f, Options{
		Password: func() (string, error) { a := answers[0]; answers = answers[1:]; return a, nil },
		Warn:     func(s string) { warnings = append(warnings, s) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), data) || len(res.Files) != 1 {
		t.Error("content differs")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "2 attempt(s) left") {
		t.Errorf("warnings = %v", warnings)
	}
	for _, w := range warnings {
		if strings.Contains(w, "wrong\"") || strings.Contains(w, "right") {
			t.Errorf("password leaked: %q", w)
		}
	}
}

func TestPasswordExhausted(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	f.password = "right"
	calls := 0
	_, _, err := run(t, f, Options{Password: func() (string, error) { calls++; return "wrong", nil }})
	if !errors.Is(err, ErrWrongPassword) || calls != 3 || strings.Contains(err.Error(), "wrong\"") {
		t.Fatalf("err = %v after %d calls", err, calls)
	}
	// Now locked out: 429 with the wait, no retry loop.
	calls = 0
	_, _, err = run(t, f, Options{Password: func() (string, error) { calls++; return "right", nil }})
	if !errors.Is(err, ErrTransferLocked) || calls != 1 || !strings.Contains(err.Error(), "15m0s") {
		t.Fatalf("err = %v after %d calls", err, calls)
	}
}

func TestPasswordPromptErrors(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	f.password = "right"
	if _, _, err := run(t, f, Options{}); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("nil prompt: %v", err)
	}
	if _, _, err := run(t, f, Options{Password: func() (string, error) { return "", nil }}); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("empty: %v", err)
	}
	boom := errors.New("boom")
	if _, _, err := run(t, f, Options{Password: func() (string, error) { return "", boom }}); !errors.Is(err, boom) {
		t.Fatalf("prompt error: %v", err)
	}
}

func TestPasswordUnexpectedProblems(t *testing.T) {
	// A server that keeps announcing attempts is bounded by maxTries.
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	f.password = "right"
	f.pwLeft = 1000
	calls := 0
	if _, _, err := run(t, f, Options{Password: func() (string, error) { calls++; return "wrong", nil }}); !errors.Is(err, ErrWrongPassword) || calls != maxTries {
		t.Fatalf("err = %v after %d calls", err, calls)
	}
}

func TestVerification(t *testing.T) {
	data := []byte("for you")
	f := newFake(t, plainFile("fil_a", "", "a.bin", data))
	f.code = "123456"
	f.password = "pw"
	codes := []string{"12345", "000000", " 123456 "}
	var masked []string
	var warnings []string
	_, out, err := run(t, f, Options{
		Code: func(m string) (string, error) {
			masked = append(masked, m)
			c := codes[0]
			codes = codes[1:]
			return c, nil
		},
		Password: func() (string, error) { return "pw", nil },
		Warn:     func(s string) { warnings = append(warnings, s) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), data) {
		t.Error("content differs")
	}
	if len(masked) != 3 || masked[0] != "c***@customer.example.net" || len(warnings) != 2 {
		t.Errorf("masked = %v, warnings = %v", masked, warnings)
	}
}

func TestVerificationFailures(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	f.code = "123456"
	if _, _, err := run(t, f, Options{}); !errors.Is(err, ErrCodeRequired) {
		t.Fatalf("nil prompt: %v", err)
	}
	if _, _, err := run(t, f, Options{Code: func(string) (string, error) { return "999999", nil }}); !errors.Is(err, ErrVerification) {
		t.Fatalf("exhausted: %v", err)
	}
	if _, _, err := run(t, f, Options{Code: func(string) (string, error) { return "abc", nil }}); !errors.Is(err, ErrVerification) {
		t.Fatalf("bad format: %v", err)
	}
	boom := errors.New("boom")
	if _, _, err := run(t, f, Options{Code: func(string) (string, error) { return "", boom }}); !errors.Is(err, boom) {
		t.Fatalf("prompt error: %v", err)
	}
	// Already verified on the server side: 204, no prompt, but the page
	// stays locked.
	f.set(func() { f.startAnswers = 204 })
	if _, _, err := run(t, f, Options{Code: func(string) (string, error) { t.Error("prompted"); return "", nil }}); err == nil {
		t.Fatal("still locked accepted")
	}
}

func TestArchive(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	f.archive = pattern("zip", 200_000)
	f.cut["archive"] = 50_000
	res, out, err := run(t, f, Options{Archive: true})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(out, "transfer-Xk4Lm9Qp.zip")
	if res.Archive != want || !bytes.Equal(readFile(t, want), f.archive) || len(res.Files) != 1 || res.Files[0].Path != "" {
		t.Errorf("result = %+v", res)
	}
	if got := listDir(t, out); !slices.Equal(got, []string{"transfer-Xk4Lm9Qp.zip"}) {
		t.Errorf("files = %v", got)
	}
	if _, _, err := run(t, f, Options{Archive: true, Output: out}); !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := run(t, f, Options{Archive: true, Output: out, Force: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Archive: true, Files: []string{"a.bin"}}); err == nil {
		t.Fatal("archive with files accepted")
	}
}

func TestArchiveGone(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	f.archive = []byte("zip")
	f.shortBody["archive"] = 1
	f.fail = func(path string) int {
		if strings.HasSuffix(path, "/archive") {
			return 410
		}
		return 0
	}
	_, out, err := run(t, f, Options{Archive: true})
	var p *client.Problem
	if !errors.As(err, &p) || p.Status != 410 {
		t.Fatalf("err = %v", err)
	}
	if got := listDir(t, out); len(got) != 0 {
		t.Errorf("files left: %v", got)
	}
}

func TestRunChecks(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	if _, err := Run(context.Background(), c, Options{}); !errors.Is(err, ErrInvalidLink) {
		t.Errorf("no token: %v", err)
	}
	if _, err := Run(context.Background(), c, Options{Link: Link{Origin: "https://other.example.com", Token: testToken}}); !errors.Is(err, client.ErrForeignOrigin) {
		t.Errorf("foreign: %v", err)
	}
	f.set(func() { f.fail = func(string) int { return 404 } })
	if _, err := Run(context.Background(), c, Options{Link: Link{Token: testToken}}); err == nil {
		t.Error("404 accepted")
	}
}

func TestOutputCreated(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	out := filepath.Join(t.TempDir(), "new", "dir")
	if _, _, err := run(t, f, Options{Output: out}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(out, "a.bin")), []byte("x")) {
		t.Error("content differs")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Output: file}); err == nil {
		t.Error("file as output accepted")
	}
}

func TestContentRange(t *testing.T) {
	for v, ok := range map[string]bool{
		"bytes 0-9/10": true, "bytes 5-9/10": true, "bytes 0-8/10": false, "bytes 9-5/10": false,
		"bytes -1-9/10": false, "bytes 0-9": false, "bytes 09/10": false, "items 0-9/10": false, "bytes 0-x/10": false,
	} {
		if _, _, got := parseContentRange(v); got != ok {
			t.Errorf("%q: %v", v, got)
		}
	}
}

func TestRedactErr(t *testing.T) {
	if redactErr(nil) != nil {
		t.Error("nil")
	}
	base := errors.New("open dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf")
	err := redactErr(base)
	if !errors.Is(err, base) || strings.Contains(err.Error(), testToken) {
		t.Errorf("err = %v", err)
	}
	plain := errors.New("plain")
	if err := redactErr(plain); err != plain { //nolint:errorlint // identity is the point
		t.Error("plain error rewrapped")
	}
}

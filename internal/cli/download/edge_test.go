package download

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/safepath"
)

// at returns a hook failing request n with status and code.
func at(n, status int, code string) func(int, *http.Request) (int, string) {
	return func(i int, _ *http.Request) (int, string) {
		if i == n {
			return status, code
		}
		return 0, ""
	}
}

func TestVerificationEdgeCases(t *testing.T) {
	code := func(string) (string, error) { return "999999", nil }
	cases := map[string]struct {
		hook func(int, *http.Request) (int, string)
		want error
	}{
		"start refused":     {at(2, 503, "mail-unavailable"), nil},
		"confirm cut":       {at(3, -1, ""), nil},
		"no attempts field": {at(3, 422, codeCodeInvalid), ErrVerification},
		"no code pending":   {at(3, 409, "state-conflict"), ErrVerification},
		"page fails after":  {func(i int, _ *http.Request) (int, string) { return map[bool]int{true: 404}[i == 4], "" }, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
			f.code = "999999"
			f.hook = c.hook
			_, _, err := run(t, f, Options{Code: code})
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// A server that keeps announcing attempts is bounded by maxTries.
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	f.code = "111111"
	calls := 0
	_, _, err := run(t, f, Options{Code: func(string) (string, error) {
		calls++
		f.set(func() { f.codeLeft = 1 << 30 })
		return "999999", nil
	}})
	if !errors.Is(err, ErrVerification) || calls != maxTries {
		t.Fatalf("err = %v after %d calls", err, calls)
	}
}

func TestUnlockEdgeCases(t *testing.T) {
	pw := func() (string, error) { return "wrong", nil }
	cases := map[string]struct {
		hook func(int, *http.Request) (int, string)
		want error
	}{
		"cut":                   {at(2, -1, ""), nil},
		"verification required": {at(2, 401, codeVerificationRequired), ErrVerification},
		"server error":          {at(2, 500, "internal"), nil},
		"locked without wait":   {at(2, 429, "transfer-locked"), ErrTransferLocked},
		"page fails after": {func(i int, r *http.Request) (int, string) {
			return map[bool]int{true: 404}[i == 3 && r.Method == "GET"], ""
		}, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
			f.password = "wrong"
			f.hook = c.hook
			_, _, err := run(t, f, Options{Password: pw})
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("err = %v", err)
			}
			if strings.Contains(err.Error(), "a few minutes") != (name == "locked without wait") {
				t.Errorf("err = %v", err)
			}
		})
	}
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	f.password = "pw"
	if _, _, err := run(t, f, Options{Password: func() (string, error) { return strings.Repeat("p", maxPasswordBytes+1), nil }}); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("long password: %v", err)
	}
}

func TestMisbehavingFileAnswers(t *testing.T) {
	data := []byte("0123456789")
	cases := map[string]func(f *fake){
		"bad content range": func(f *fake) { f.rangeOverride = "bytes 3-9/11" },
		"odd status":        func(f *fake) { f.okStatus = http.StatusNonAuthoritativeInfo },
		"foreign url":       func(f *fake) { f.files[0].url = "https://evil.example.com/x" },
		"gone":              func(f *fake) { f.hook = at(2, 410, "max-downloads-reached") },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, plainFile("fil_a", "", "a.bin", data))
			alter(f)
			out := t.TempDir()
			if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), data[:3], 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := run(t, f, Options{Output: out}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestBodyWithoutLength(t *testing.T) {
	data := pattern("nl", 100_000)
	f := newFake(t, plainFile("fil_a", "", "a.bin", data))
	f.noLength = true
	f.shortBody["fil_a"] = 40_000
	f.hook = func(n int, _ *http.Request) (int, string) {
		if n == 3 {
			delete(f.shortBody, "fil_a")
		}
		return 0, ""
	}
	_, out, err := run(t, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(out, "a.bin")); string(got) != string(data) {
		t.Error("content differs")
	}
	// The archive needs a length.
	g := newFake(t, plainFile("fil_a", "", "a.bin", data))
	g.archive = data
	g.noLength = true
	if _, _, err := run(t, g, Options{Archive: true}); err == nil {
		t.Fatal("archive without length accepted")
	}
}

func TestPartSymlinkRefused(t *testing.T) {
	key, enc := newKey(t)
	for name, f := range map[string]*fake{
		"plain": newFake(t, plainFile("fil_a", "", "a.bin", []byte("x"))),
		"e2e":   e2eFake(t, key, []string{"a.bin"}, [][]byte{[]byte("x")}),
	} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(out, ".a.bin.part")); err != nil {
				t.Skip(err)
			}
			link := Link{Token: testToken}
			if name == "e2e" {
				link.Key = enc
			}
			if _, _, err := run(t, f, Options{Output: out, Link: link}); !errors.Is(err, safepath.ErrSymlink) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	g := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	g.archive = []byte("zip")
	out := t.TempDir()
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(out, ".transfer-Xk4Lm9Qp.zip.part")); err != nil {
		t.Skip(err)
	}
	if _, _, err := run(t, g, Options{Output: out, Archive: true}); !errors.Is(err, safepath.ErrSymlink) {
		t.Fatalf("archive: %v", err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(out, "transfer-Xk4Lm9Qp.zip")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, g, Options{Output: out, Archive: true, Force: true}); !errors.Is(err, safepath.ErrSymlink) {
		t.Fatalf("archive target: %v", err)
	}
}

func TestE2EResumeEdgeCases(t *testing.T) {
	key, enc := newKey(t)
	plain := pattern("x", 3*testChunk)
	cases := map[string]func(f *fake){
		"header refused": func(f *fake) { f.hook = at(2, 404, "not-found") },
		"header cut": func(f *fake) {
			f.hook = func(_ int, r *http.Request) (int, string) {
				return map[bool]int{true: -1}[strings.Contains(r.URL.Path, "/files/")], ""
			}
		},
		"bad header range": func(f *fake) { f.rangeOverride = "bytes 0-30/9999" },
		"foreign url":      func(f *fake) { f.files[0].url = "https://evil.example.com/x" },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			f := e2eFake(t, key, []string{"a.bin"}, [][]byte{plain})
			alter(f)
			out := t.TempDir()
			if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), plain[:testChunk], 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := run(t, f, Options{Output: out, Link: Link{Token: testToken, Key: enc}}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// A full answer to the header request that is cut short.
	f := e2eFake(t, key, []string{"a.bin"}, [][]byte{plain})
	f.ignoreRange = true
	f.cut[f.files[0].id] = 10
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), plain[:testChunk], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, f, Options{Output: out, Link: Link{Token: testToken, Key: enc}}); err != nil {
		t.Fatal(err)
	}
	// A full answer to a range request cut while skipping to the chunk.
	g := e2eFake(t, key, []string{"a.bin"}, [][]byte{plain})
	g.ignoreRange = true
	g.hook = func(n int, _ *http.Request) (int, string) {
		if n == 3 {
			g.cut[g.files[0].id] = 1000
		}
		return 0, ""
	}
	out = t.TempDir()
	if err := os.WriteFile(filepath.Join(out, ".a.bin.part"), plain[:2*testChunk], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, g, Options{Output: out, Link: Link{Token: testToken, Key: enc}}); err != nil {
		t.Fatal(err)
	}
}

func TestProblemPassthrough(t *testing.T) {
	f := newFake(t, plainFile("fil_a", "", "a.bin", []byte("x")))
	f.hook = at(1, 410, "transfer-gone")
	_, _, err := run(t, f, Options{})
	var p *client.Problem
	if !errors.As(err, &p) || p.Code != "transfer-gone" {
		t.Fatalf("err = %v", err)
	}
}

func TestSanitizeLine(t *testing.T) {
	if got := sanitizeLine("a\nb\tc\u202e\xff"); got != "a b c�" {
		t.Errorf("got %q", got)
	}
}

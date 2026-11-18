package secret

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
)

func TestValidDuration(t *testing.T) {
	for _, d := range []string{"1h", "1d", "7d"} {
		if !ValidDuration(d) {
			t.Errorf("%s refused", d)
		}
	}
	for _, d := range []string{"", "12h", "3d", "30d", "1H", "7"} {
		if ValidDuration(d) {
			t.Errorf("%q accepted", d)
		}
	}
	if !ValidDuration(DefaultDuration) {
		t.Error("default duration")
	}
}

func TestCheckText(t *testing.T) {
	ok := []string{"a", " ", "\n", strings.Repeat("😀", MaxTextRunes), strings.Repeat("é", MaxTextRunes), "\ufeffBOM kept"}
	for _, s := range ok {
		if err := CheckText(s); err != nil {
			t.Errorf("%.10q: %v", s, err)
		}
	}
	for _, tc := range []struct{ text, want string }{
		{"", "empty"},
		{strings.Repeat("a", MaxTextRunes+1), "10001 characters"},
		{"bad \xff byte", "UTF-8"},
		{"lone surrogate \xed\xa0\x80", "UTF-8"},
	} {
		err := CheckText(tc.text)
		if !errors.Is(err, ErrInvalidText) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%.20q: %v", tc.text, err)
		}
	}
}

func TestReadText(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		keep     bool
	}{
		{"secret\n", "secret", false},
		{"secret\r\n", "secret", false},
		{"secret", "secret", false},
		{"two\n\n", "two\n", false},
		{"cr only\r", "cr only\r", false},
		{"  spaces kept  \n", "  spaces kept  ", false},
		{"secret\n", "secret\n", true},
		{"secret\r\n", "secret\r\n", true},
		{"\xef\xbb\xbfwith BOM\r\n", "with BOM", false},
		{"\xef\xbb\xbf\xef\xbb\xbftwo BOMs", "\ufefftwo BOMs", false},
		{"\xef\xbb\xbfraw\n", "\ufeffraw\n", true},
		{"\xef\xbb\xbf" + strings.Repeat("😀", MaxTextRunes) + "\r\n", strings.Repeat("😀", MaxTextRunes), false},
		{strings.Repeat("😀", MaxTextRunes) + "\r\n", strings.Repeat("😀", MaxTextRunes), false},
	} {
		got, err := ReadText(strings.NewReader(tc.in), tc.keep)
		if err != nil || got != tc.want {
			t.Errorf("%.20q keep=%v: %.20q %v", tc.in, tc.keep, got, err)
		}
	}
	for _, tc := range []struct {
		in   string
		keep bool
		want string
	}{
		{"", false, "empty"},
		{"\n", false, "empty"},
		{"\r\n", false, "empty"},
		{strings.Repeat("a", MaxTextRunes) + "\n", true, "10001 characters"},
		{"\xef\xbb\xbf" + strings.Repeat("😀", MaxTextRunes) + "\r\n!", false, "more than 10000"},
		{"\xef\xbb\xbf\n", false, "empty"},
		{"\xff\n", false, "UTF-8"},
	} {
		_, err := ReadText(strings.NewReader(tc.in), tc.keep)
		if !errors.Is(err, ErrInvalidText) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%.20q: %v", tc.in, err)
		}
	}
	// A huge input is not read to its end.
	r := &countingReader{}
	if _, err := ReadText(io.LimitReader(r, 1<<30), false); !errors.Is(err, ErrInvalidText) || r.n > maxInputBytes+1+512 {
		t.Errorf("read %d bytes: %v", r.n, err)
	}
	if _, err := ReadText(iotest.ErrReader(errors.New("boom")), false); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("reader error: %v", err)
	}
}

// countingReader produces "a" forever and counts what was read.
type countingReader struct{ n int }

func (c *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	c.n += len(p)
	return len(p), nil
}

func TestReadTextFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := write("ok.txt", "from a file\n", 0o600)
	if got, err := ReadTextFile(p, false); err != nil || got != "from a file" {
		t.Fatalf("ok: %q %v", got, err)
	}
	if got, err := ReadTextFile(p, true); err != nil || got != "from a file\n" {
		t.Fatalf("keep: %q %v", got, err)
	}
	if _, err := ReadTextFile(write("empty.txt", "\n", 0o600), false); !errors.Is(err, ErrInvalidText) || !strings.Contains(err.Error(), "empty.txt") {
		t.Errorf("empty: %v", err)
	}
	if _, err := ReadTextFile(filepath.Join(dir, "missing"), false); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if _, err := ReadTextFile(dir, false); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: %v", err)
	}
	if runtime.GOOS != "windows" {
		shared := write("shared.txt", "x", 0o644)
		if _, err := ReadTextFile(shared, false); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("shared: %v", err)
		}
		oldOS := goos
		goos = "windows"
		if got, err := ReadTextFile(shared, false); err != nil || got != "x" {
			t.Errorf("windows: %q %v", got, err)
		}
		goos = oldOS
	}

	old := openFile
	t.Cleanup(func() { openFile = old })
	openFile = func(string) (textFile, error) { return statFailFile{}, nil }
	if _, err := ReadTextFile("x", false); err == nil || !strings.Contains(err.Error(), "stat failed") {
		t.Errorf("stat: %v", err)
	}
}

// statFailFile is a textFile whose Stat fails.
type statFailFile struct{ io.ReadCloser }

func (statFailFile) Stat() (fs.FileInfo, error) { return nil, errors.New("stat failed") }
func (statFailFile) Close() error               { return nil }

func TestTerminalSafe(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		changed  bool
	}{
		{"plain text\twith tab\nand lines\r\nCRLF kept", "plain text\twith tab\nand lines\r\nCRLF kept", false},
		{"famille 👨\u200d👩\u200d👧 é", "famille 👨\u200d👩\u200d👧 é", false},
		{"\x1b]0;title\x07red", `\x1b]0;title\x07red`, true},
		{"over\rwrite", `over\x0dwrite`, true},
		{"end\r", `end\x0d`, true},
		{"csi \u009b31m del \x7f nul \x00", `csi \x9b31m del \x7f nul \x00`, true},
		{"abc\u202edef\u2066", `abc\u202edef\u2066`, true},
	} {
		got, changed := TerminalSafe(tc.in)
		if got != tc.want || changed != tc.changed {
			t.Errorf("%q: %q %v", tc.in, got, changed)
		}
	}
}

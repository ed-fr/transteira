package secret

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/textsafe"
	"github.com/ed-fr/transteira/internal/tte2"
)

// MaxTextRunes is the largest text of a secret, in Unicode code points
// (docs/architecture/e2e-format.md, section 3.3.9).
const MaxTextRunes = tte2.MaxSecretRunes

// utf8BOM is the UTF-8 byte order mark that some Windows tools put at the
// start of a text file.
const utf8BOM = "\xef\xbb\xbf"

// maxInputBytes bounds the input read by [ReadText]: 4 UTF-8 bytes per code
// point, a leading byte order mark and a final "\r\n". A longer input holds
// more than MaxTextRunes code points whatever its content.
const maxInputBytes = 4*MaxTextRunes + 3 + 2

// Durations of an express secret (ExpressSecretDuration of the API), from
// its creation.
const (
	// DefaultDuration is the duration used when none is chosen.
	DefaultDuration = "1d"
	// DurationList names the accepted durations, for messages.
	DurationList = "1h, 1d or 7d"
)

// ErrInvalidText is wrapped by every refusal of a secret text: empty, not
// valid UTF-8, longer than MaxTextRunes code points. The messages never
// quote the text.
var ErrInvalidText = errors.New("invalid secret text")

// Hooks replaced by the tests: the operating system (the permission check
// is skipped on Windows) and the opening of a text file.
var (
	goos     = runtime.GOOS
	openFile = func(path string) (textFile, error) {
		return os.Open(path) //nolint:gosec // G304: the path is chosen by the user who runs the client
	}
)

// textFile is the part of *os.File used by ReadTextFile.
type textFile interface {
	io.ReadCloser
	Stat() (fs.FileInfo, error)
}

// ValidDuration reports whether d is a duration of an express secret:
// "1h", "1d" or "7d".
func ValidDuration(d string) bool {
	switch d {
	case "1h", "1d", "7d":
		return true
	}
	return false
}

// CheckText checks the text of a secret: valid UTF-8 (so no lone
// surrogate), not empty, at most MaxTextRunes Unicode code points counted
// as they are (no normalization, no trimming, line breaks included). It
// wraps ErrInvalidText.
func CheckText(text string) error {
	if !utf8.ValidString(text) {
		return fmt.Errorf("%w: it is not valid UTF-8 (save it as UTF-8)", ErrInvalidText)
	}
	if text == "" {
		return fmt.Errorf("%w: it is empty", ErrInvalidText)
	}
	if n := utf8.RuneCountInString(text); n > MaxTextRunes {
		return fmt.Errorf("%w: %d characters (Unicode code points), more than the %d allowed", ErrInvalidText, n, MaxTextRunes)
	}
	return nil
}

// ReadText reads the text of a secret from r, until its end. Unless raw is
// set, a leading UTF-8 byte order mark and one final line break ("\n" or
// "\r\n") are dropped, nothing else: "echo text |", a here-string and a file
// saved by an editor all end with a line break, and Windows tools often
// start a UTF-8 file with a byte order mark, which would otherwise become an
// invisible first character of the secret. The result passes [CheckText].
// At most a little more than 4 bytes per allowed code point is read: a
// longer input is refused without being read to its end.
func ReadText(r io.Reader, raw bool) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInputBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading the text: %w", err)
	}
	if len(data) > maxInputBytes {
		return "", fmt.Errorf("%w: more than %d characters (Unicode code points)", ErrInvalidText, MaxTextRunes)
	}
	if !raw {
		data = trimNewline(bytes.TrimPrefix(data, []byte(utf8BOM)))
	}
	text := string(data)
	if err := CheckText(text); err != nil {
		return "", err
	}
	return text, nil
}

// trimNewline drops one final "\r\n" or "\n".
func trimNewline(data []byte) []byte {
	if d, ok := bytes.CutSuffix(data, []byte("\r\n")); ok {
		return d
	}
	return bytes.TrimSuffix(data, []byte("\n"))
}

// ReadTextFile reads the text of a secret from the file path, like
// [ReadText]. The file must be a regular file and, outside Windows, not
// accessible by the group or others (as the token and password files of the
// client): a secret readable by other users of the machine is refused.
func ReadTextFile(path string, raw bool) (string, error) {
	f, err := openFile(path)
	if err != nil {
		return "", fmt.Errorf("text file: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("text file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("text file %s is not a regular file: pipe the text on the standard input instead", path)
	}
	if goos != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("text file %s is accessible by other users (mode %04o): run chmod 600 %s",
			path, info.Mode().Perm(), path)
	}
	text, err := ReadText(f, raw)
	if err != nil {
		return "", fmt.Errorf("text file %s: %w", path, err)
	}
	return text, nil
}

// TerminalSafe returns text ready to be shown on a terminal: every control
// character other than line feed and tab (a carriage return is kept right
// before a line feed) and every bidirectional formatting character is
// replaced by a visible escape, `\x1b` or `\u202e` for example, so that a
// text written by a third party can neither drive the terminal (escape
// sequences, carriage returns that overwrite a line) nor reorder what is
// shown. changed reports whether anything was replaced. text must be valid
// UTF-8 (a revealed text always is).
func TerminalSafe(text string) (safe string, changed bool) {
	var b strings.Builder
	b.Grow(len(text))
	for i, r := range text {
		switch {
		case r == '\n' || r == '\t':
		case r == '\r' && strings.HasPrefix(text[i+1:], "\n"):
		case r < 0x100 && textsafe.IsControl(r):
			changed = true
			_, _ = fmt.Fprintf(&b, `\x%02x`, r)
			continue
		case textsafe.IsBidiControl(r):
			changed = true
			_, _ = fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), changed
}

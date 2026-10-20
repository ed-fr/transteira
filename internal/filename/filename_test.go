package filename

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// reasonOf returns the Reason carried by err, or "" when err is nil.
func reasonOf(t *testing.T, err error) Reason {
	t.Helper()
	if err == nil {
		return ""
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v is not a *ValidationError", err)
	}
	return ve.Reason
}

func TestValidateAccepts(t *testing.T) {
	cases := map[string]string{
		"report.pdf":               "report.pdf",
		"a":                        "a",
		"archive.tar.gz":           "archive.tar.gz",
		"Rapport annuel 2025.docx": "Rapport annuel 2025.docx",
		"e\u0301te\u0301.txt":      "été.txt", // NFD -> NFC
		"日本語のファイル.xlsx":            "日本語のファイル.xlsx",
		"Why?.pdf":                 "Why?.pdf",
		"a..b":                     "a..b",
		"CONSOLE.txt":              "CONSOLE.txt",
		"COM10.txt":                "COM10.txt",
		"LPT.txt":                  "LPT.txt",
		"xCON.txt":                 "xCON.txt",
		"COM":                      "COM",
		"COM⁴":                     "COM⁴", // superscript four is not reserved
		"con-fig":                  "con-fig",
		".env":                     ".env",
		".gitignore":               ".gitignore",
		".htaccess":                ".htaccess",
		"..env":                    "..env",
		".a.b":                     ".a.b",
		".con":                     ".con", // empty stem, not a device name
		"emoji 🎉.png":              "emoji 🎉.png",
		strings.Repeat("a", 255):   strings.Repeat("a", 255),
	}
	for in, want := range cases {
		got, err := Validate(in)
		if err != nil {
			t.Errorf("Validate(%q) error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Validate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]Reason{
		"":                       ReasonEmpty,
		"bad\xffname":            ReasonInvalidUTF8,
		strings.Repeat("a", 256): ReasonTooLong,
		strings.Repeat("é", 128): ReasonTooLong, // 256 bytes
		"a\x00b":                 ReasonControlCharacter,
		"a\tb":                   ReasonControlCharacter,
		"a\r\nb":                 ReasonControlCharacter,
		"a\x7fb":                 ReasonControlCharacter,
		"a\u0085b":               ReasonControlCharacter,
		"a\u009fb":               ReasonControlCharacter,
		"a\u2028b":               ReasonControlCharacter,
		"a\u2029b":               ReasonControlCharacter,
		"invoice\u202Efdp.exe":   ReasonBidiControl,
		"a\u202Ab":               ReasonBidiControl,
		"a\u2066b":               ReasonBidiControl,
		"a\u2069b":               ReasonBidiControl,
		"a\u200Eb":               ReasonBidiControl,
		"a\u200Fb":               ReasonBidiControl,
		"a\u061Cb":               ReasonBidiControl,
		"a\u200Bb":               ReasonInvisibleCharacter,
		"a\u200Cb":               ReasonInvisibleCharacter,
		"a\u200Db":               ReasonInvisibleCharacter,
		"a\u2060b":               ReasonInvisibleCharacter,
		"\uFEFFa":                ReasonInvisibleCharacter,
		"a\u00ADb":               ReasonInvisibleCharacter,
		"a\U000E0041b":           ReasonInvisibleCharacter,
		"a/b":                    ReasonPathSeparator,
		"../etc/passwd":          ReasonPathSeparator,
		`a\b`:                    ReasonPathSeparator,
		"C:file":                 ReasonPathSeparator,
		"file.txt:stream":        ReasonPathSeparator,
		".":                      ReasonDotName,
		"..":                     ReasonDotName,
		" a":                     ReasonLeadingTrailing,
		"a ":                     ReasonLeadingTrailing,
		"...":                    ReasonDotName,
		"....":                   ReasonDotName,
		"a.":                     ReasonLeadingTrailing,
		".env.":                  ReasonLeadingTrailing,
		". ":                     ReasonLeadingTrailing,
		" .env":                  ReasonLeadingTrailing,
		"a\u00A0":                ReasonLeadingTrailing,
		"\u3000a":                ReasonLeadingTrailing,
		"CON":                    ReasonReservedName,
		"con":                    ReasonReservedName,
		"Nul.txt":                ReasonReservedName,
		"aux.tar.gz":             ReasonReservedName,
		"PRN .log":               ReasonReservedName,
		"CONIN$":                 ReasonReservedName,
		"conout$.txt":            ReasonReservedName,
		"COM0":                   ReasonReservedName,
		"com1.txt":               ReasonReservedName,
		"COM9":                   ReasonReservedName,
		"LPT1":                   ReasonReservedName,
		"lpt9.doc":               ReasonReservedName,
		"COM¹":                   ReasonReservedName,
		"com².txt":               ReasonReservedName,
		"LPT³":                   ReasonReservedName,
		"a\u2215b":               ReasonPathSeparator,
		"a\u2044b":               ReasonPathSeparator,
		"a\uff0fb":               ReasonPathSeparator,
		"a\u29f8b":               ReasonPathSeparator,
		"a\uff3cb":               ReasonPathSeparator,
		"C\uff1afile":            ReasonPathSeparator,
		"a\ua789b":               ReasonPathSeparator,
		"a\ufe55b":               ReasonPathSeparator,
		"a\u2236b":               ReasonPathSeparator,
		"a\ufe68b":               ReasonPathSeparator,
		"a\u2216b":               ReasonPathSeparator,
		"a\u3164b":               ReasonInvisibleCharacter,
		"a\u115fb":               ReasonInvisibleCharacter,
		"a\u034fb":               ReasonInvisibleCharacter,
		"a\ufe0fb":               ReasonInvisibleCharacter,
		"a\U000e0100b":           ReasonInvisibleCharacter,
		"a\u180bb":               ReasonInvisibleCharacter,
		"a\u2800b":               ReasonInvisibleCharacter,
		"invoice.pdf   .exe":     ReasonSpaceRun,
		"a \u00a0\u3000b":        ReasonSpaceRun,
	}
	for in, want := range cases {
		_, err := Validate(in)
		if got := reasonOf(t, err); got != want {
			t.Errorf("Validate(%q) reason %q, want %q", in, got, want)
		}
	}
	if got, err := Validate("a  b.txt"); err != nil || got != "a  b.txt" {
		t.Errorf("Validate(two spaces) = %q, %v", got, err)
	}
	// 127 NFD "é" (3 bytes each) are 381 bytes, but 254 bytes once NFC: the
	// length limit applies after normalization, so this one is accepted.
	nfd := strings.Repeat("e\u0301", 127)
	if got, err := Validate(nfd); err != nil || len(got) != 254 {
		t.Errorf("Validate(127 NFD é) = %d bytes, %v; want 254 bytes", len(got), err)
	}
}

func TestValidationErrorMessage(t *testing.T) {
	_, err := Validate("a\u202Eb")
	if err == nil || err.Error() != "filename: invalid name: bidi-control" {
		t.Fatalf("message %v", err)
	}
	if strings.Contains(err.Error(), "\u202E") {
		t.Fatal("message contains the name")
	}
}

func TestArchiveName(t *testing.T) {
	seen := map[string]int{}
	steps := []struct{ in, want string }{
		{"a.txt", "a.txt"},
		{"a.txt", "a (2).txt"},
		{"A.TXT", "A (3).TXT"},
		{"a (4).txt", "a (4).txt"},
		{"a.txt", "a (5).txt"},
		{"b", "b"},
		{"B", "B (2)"},
		{"archive.tar.gz", "archive.tar.gz"},
		{"archive.tar.gz", "archive.tar (2).gz"},
		{"", Fallback},
		{"../x", Fallback + " (2)"},
		{"CON", Fallback + " (3)"},
		{"Why?.pdf", "Why_.pdf"},
		{`a<b>c"d|e*f`, "a_b_c_d_e_f"},
		{"e\u0301.txt", "é.txt"},
		{"É.TXT", "É (2).TXT"},
		{".env", ".env"},
		{".ENV", ".ENV (2)"},
		{"..env", "..env"},
		{"..env", ". (2).env"},
		{".a.b", ".a.b"},
		{".a.b", ".a (2).b"},
		{"q  .txt", "q  .txt"},
		{"q  .txt", "q (2).txt"},
	}
	for _, s := range steps {
		if got := ArchiveName(s.in, seen); got != s.want {
			t.Fatalf("ArchiveName(%q) = %q, want %q", s.in, got, s.want)
		}
	}
}

func TestArchiveNameLength(t *testing.T) {
	long := strings.Repeat("a", 251) + ".txt" // 255 bytes
	seen := map[string]int{}
	ArchiveName(long, seen)
	got := ArchiveName(long, seen)
	want := strings.Repeat("a", 247) + " (2).txt"
	if got != want {
		t.Fatalf("got %q (%d bytes)", got, len(got))
	}

	// Multi-byte stem: never split a character.
	multi := strings.Repeat("é", 125) + ".txt" // 254 bytes
	seen = map[string]int{}
	ArchiveName(multi, seen)
	got = ArchiveName(multi, seen)
	if len(got) > MaxBytes || !utf8.ValidString(got) || !strings.HasSuffix(got, " (2).txt") {
		t.Fatalf("got %q (%d bytes)", got, len(got))
	}

	// An extension leaving no room for a stem is dropped.
	hugeExt := "a." + strings.Repeat("x", 252) // 254 bytes
	seen = map[string]int{}
	ArchiveName(hugeExt, seen)
	got = ArchiveName(hugeExt, seen)
	if want := ("a." + strings.Repeat("x", 252))[:251] + " (2)"; got != want {
		t.Fatalf("got %q (%d bytes)", got, len(got))
	}

	// Truncation removes the trailing spaces and dots of the stem.
	spaced := strings.Repeat("a", 245) + "  .  b.txt" // 255 bytes
	seen = map[string]int{}
	ArchiveName(spaced, seen)
	if got := ArchiveName(spaced, seen); got != strings.Repeat("a", 245)+" (2).txt" {
		t.Fatalf("got %q", got)
	}

	// A stem that cannot be cut on a normalization boundary falls back.
	marks := strings.Repeat("\u0301", 12) + "." + strings.Repeat("x", 239) // 24 + 240 = 264 > 255
	marks = marks[:len(marks)-10]                                          // 254 bytes
	if _, err := Validate(marks); err != nil {
		t.Fatalf("Validate(marks): %v", err)
	}
	seen = map[string]int{}
	ArchiveName(marks, seen)
	if got := ArchiveName(marks, seen); got != Fallback+" (2)" {
		t.Fatalf("got %q", got)
	}
}

func TestArchiveNameAlwaysValid(t *testing.T) {
	seen := map[string]int{}
	for range 30 {
		got := ArchiveName(strings.Repeat("z", 255), seen)
		if v, err := Validate(got); err != nil || v != got {
			t.Fatalf("ArchiveName produced invalid %q: %v", got, err)
		}
	}
}

func FuzzValidate(f *testing.F) {
	for _, s := range []string{
		"q  .txt", "a\u3164b", "a\uff0fb", "x   y",
		"report.pdf", "", ".", "..", "CON.txt", "com¹", "a\u202Eb", "e\u0301",
		"a\u200Db", " a", "a.", "a/b", "C:x", strings.Repeat("é", 200), "\xff",
		"\u0301\u0301.txt", "a (2).txt", "Why?.pdf", ".env", "..env", " .x", "....",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		seen := map[string]int{}
		out, err := Validate(in)
		if err == nil {
			checkName(t, out)
			if again, err2 := Validate(out); err2 != nil || again != out {
				t.Fatalf("Validate is not idempotent on %q", out)
			}
		} else {
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.Reason == "" || out != "" {
				t.Fatalf("bad error %v / %q", err, out)
			}
		}
		for range 3 {
			a := ArchiveName(in, seen)
			checkName(t, a)
			if v, err := Validate(a); err != nil || v != a {
				t.Fatalf("ArchiveName(%q) = %q, invalid: %v", in, a, err)
			}
		}
	})
}

// checkName asserts the invariants of an accepted name.
func checkName(t *testing.T, s string) {
	t.Helper()
	if s == "" || len(s) > MaxBytes {
		t.Fatalf("length %d", len(s))
	}
	if !norm.NFC.IsNormalString(s) {
		t.Fatalf("%q is not NFC", s)
	}
	spaces := 0
	for _, r := range s {
		if _, bad := forbiddenRune(r); bad {
			t.Fatalf("%q contains forbidden %U", s, r)
		}
		if spaces = spaceRun(spaces, r); spaces > MaxSpaceRun {
			t.Fatalf("%q contains a run of %d spaces", s, spaces)
		}
	}
	first, _ := utf8.DecodeRuneInString(s)
	last, _ := utf8.DecodeLastRuneInString(s)
	if unicode.IsSpace(first) || unicode.IsSpace(last) || last == '.' {
		t.Fatalf("%q starts with a space or ends with a space or a dot", s)
	}
	if strings.Trim(s, ".") == "" {
		t.Fatalf("%q is made of dots only", s)
	}
}

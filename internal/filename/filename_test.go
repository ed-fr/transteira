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
		for _, a := range ArchiveEntries([]ArchiveFile{{Name: in}, {Name: in}, {Name: in}}) {
			checkName(t, a)
			if v, err := Validate(a); err != nil || v != a {
				t.Fatalf("archive entry of %q = %q, invalid: %v", in, a, err)
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

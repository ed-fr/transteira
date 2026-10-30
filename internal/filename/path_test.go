package filename

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

func TestValidatePathAccepts(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plans", "plans"},
		{"plans/2026/site-a", "plans/2026/site-a"},
		{"%2e%2e", "%2e%2e"},
		{"%2e%2e/%2f", "%2e%2e/%2f"},
		{"50 % remise", "50 % remise"},
		{".git/hooks", ".git/hooks"},
		{"..a/b..c", "..a/b..c"},
		{"e\u0301te\u0301/ca\u0300", "\u00e9t\u00e9/c\u00e0"},
		{"Why?/a<b>", "Why?/a<b>"},
		{strings.TrimSuffix(strings.Repeat("a/", MaxPathSegments), "/"), strings.TrimSuffix(strings.Repeat("a/", MaxPathSegments), "/")},
	}
	for _, c := range cases {
		got, err := ValidatePath(c.in)
		if err != nil || got != c.want {
			t.Errorf("ValidatePath(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	// Exactly MaxPathBytes bytes.
	long := strings.Repeat(strings.Repeat("x", 63)+"/", 15) + strings.Repeat("y", MaxPathBytes-15*64)
	if got, err := ValidatePath(long); err != nil || got != long {
		t.Fatalf("path of %d bytes refused: %v", len(long), err)
	}
}

func TestValidatePathRejects(t *testing.T) {
	cases := []struct {
		in   string
		want Reason
	}{
		{"..", ReasonDotName},
		{".", ReasonDotName},
		{"../x", ReasonDotName},
		{"a/../b", ReasonDotName},
		{"a/./b", ReasonDotName},
		{"a/..", ReasonDotName},
		{"/x", ReasonPathEmptySegment},
		{"x/", ReasonPathEmptySegment},
		{"/", ReasonPathEmptySegment},
		{"a//b", ReasonPathEmptySegment},
		{`a\b`, ReasonPathSeparator},
		{`..\x`, ReasonPathSeparator},
		{"C:", ReasonPathSeparator},
		{"C:/Windows", ReasonPathSeparator},
		{"a\uff0fb", ReasonPathSeparator},
		{"a/b\x00c", ReasonControlCharacter},
		{"a\nb", ReasonControlCharacter},
		{"a/\x7f", ReasonControlCharacter},
		{"a/\u0085", ReasonControlCharacter},
		{"a\u202Efdp.exe", ReasonBidiControl},
		{"a/b\u200Bc", ReasonInvisibleCharacter},
		{"a/con", ReasonReservedName},
		{"CON/x", ReasonReservedName},
		{"lpt1.d", ReasonReservedName},
		{"a /b", ReasonLeadingTrailing},
		{"a/ b", ReasonLeadingTrailing},
		{"a./b", ReasonLeadingTrailing},
		{"a/b   c", ReasonSpaceRun},
		{"\xff/a", ReasonInvalidUTF8},
		{strings.TrimSuffix(strings.Repeat("a/", MaxPathSegments+1), "/"), ReasonPathTooDeep},
		{strings.Repeat("a/", 600), ReasonPathTooLong},
		{strings.Repeat(strings.Repeat("x", 63)+"/", 15) + strings.Repeat("y", MaxPathBytes-15*64+1), ReasonPathTooLong},
		{strings.Repeat("x", 256), ReasonTooLong},
	}
	for _, c := range cases {
		got, err := ValidatePath(c.in)
		if r := reasonOf(t, err); r != c.want || got != "" {
			t.Errorf("ValidatePath(%q) = %q, reason %q; want %q", c.in, got, r, c.want)
		}
	}
}

func FuzzValidatePath(f *testing.F) {
	for _, s := range []string{
		"", "a", "a/b", "../x", "..", ".", "/x", "x/", "a//b", "a/./b", `a\b`, "C:",
		"a\x00b", "a\u202Eb", "%2e%2e", "e\u0301/x", "con/a", "a/" + strings.Repeat("b", 300),
		strings.Repeat("a/", 17), "\xff", " a/b", "a./b", "50 %/x",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := ValidatePath(in)
		if err != nil {
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.Reason == "" || out != "" {
				t.Fatalf("bad error %v / %q", err, out)
			}
			return
		}
		if out == "" {
			if in != "" {
				t.Fatalf("ValidatePath(%q) accepted as the root", in)
			}
			return
		}
		if !norm.NFC.IsNormalString(out) || len(out) > MaxPathBytes {
			t.Fatalf("%q is not NFC or too long", out)
		}
		segments := strings.Split(out, "/")
		if len(segments) > MaxPathSegments {
			t.Fatalf("%q is too deep", out)
		}
		for _, s := range segments {
			if s == "" || s == "." || s == ".." {
				t.Fatalf("%q holds the segment %q", out, s)
			}
			if v, err := Validate(s); err != nil || v != s {
				t.Fatalf("segment %q of %q invalid: %v", s, out, err)
			}
		}
		if again, err := ValidatePath(out); err != nil || again != out {
			t.Fatalf("ValidatePath is not idempotent on %q", out)
		}
	})
}

package textsafe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClasses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		fn    func(rune) bool
		yes   []rune
		never []rune
	}{
		{"IsControl", IsControl, []rune{0, '\t', '\n', '\r', 0x1f, 0x7f, 0x85, 0x9f}, []rune{' ', 'a', 0xa0, 0x2028}},
		{"IsLineSeparator", IsLineSeparator, []rune{0x2028, 0x2029}, []rune{'\n', 0x2027, 0x202a}},
		{
			"IsBidiControl", IsBidiControl,
			[]rune{0x061c, 0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069},
			[]rune{0x200d, 0x2029, 0x202f, 0x2065, 0x206a, 'a'},
		},
		{
			"IsFormat", IsFormat,
			[]rune{0xad, 0x061c, 0x200b, 0x200d, 0x202e, 0x2060, 0x2066, 0xfeff, 0xe0041},
			[]rune{'a', ' ', 0x034f, 0x3164},
		},
		{"IsInvisible", IsInvisible, []rune{
			0x115f, 0x1160, 0x3164, 0xffa0, 0x034f, 0x2800, 0xfe00, 0xfe0f, 0xe0100, 0xe01ef, 0x180b, 0x180d,
		}, []rune{'a', 0x180e, 0x180f, 0xfdff, 0xfe10, 0xe00ff, 0xe01f0, 0x2801, 0x115e, 0x1161}},
		{
			"IsHidden", IsHidden,
			[]rune{'\r', 0, 0x85, 0x2028, 0x200b, 0x202e, 0xfeff, 0x3164, 0xfe0f},
			[]rune{'\n', '\t', ' ', 'a', 0xe9, 0x3000, 0x0301},
		},
	}
	for _, tc := range tests {
		for _, r := range tc.yes {
			if !tc.fn(r) {
				t.Errorf("%s(%U) = false", tc.name, r)
			}
		}
		for _, r := range tc.never {
			if tc.fn(r) {
				t.Errorf("%s(%U) = true", tc.name, r)
			}
		}
	}
}

func TestSanitizeMessage(t *testing.T) {
	t.Parallel()
	in := "a\tb\nc\r\x00\x7f\u0085\u200b\u200f\u202a\u202e\u2066\u2069\ufeff\u00ad\u3164\u034f\ufe0f\u2800\u2028d\u00e9 e\u0301"
	if got, want := SanitizeMessage(in), "a\tb\ncd\u00e9 e\u0301"; got != want {
		t.Errorf("SanitizeMessage = %q, want %q", got, want)
	}
	if got := SanitizeMessage(""); got != "" {
		t.Errorf("SanitizeMessage(\"\") = %q", got)
	}
}

func FuzzSanitizeMessage(f *testing.F) {
	for _, s := range []string{"", "hello", "a\r\nb", "x\u202ey", "\u3164\u3164", "\ufeff\t\n", "e\u0301"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if !utf8.ValidString(in) {
			return
		}
		out := SanitizeMessage(in)
		if strings.IndexFunc(out, IsHidden) >= 0 {
			t.Fatalf("SanitizeMessage(%q) = %q keeps a hidden character", in, out)
		}
		if SanitizeMessage(out) != out {
			t.Fatalf("SanitizeMessage is not idempotent on %q", in)
		}
		if len(out) > len(in) {
			t.Fatalf("SanitizeMessage grew %q", in)
		}
	})
}

package audit_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/audit"
)

func TestRedactAddresses(t *testing.T) {
	fullWidth, small := string(rune(0xFF20)), string(rune(0xFE6B))
	cases := map[string]string{
		"":                                   "",
		"no address here":                    "no address here",
		"a@example.com":                      "[address]",
		"Contact: john.doe+tag@example.com.": "Contact: [address].",
		"(a@b.example) and c@d.example-":     "([address]) and [address]-",
		`"john doe"@example.com said`:        "[address] said",
		`x "a\"b"@example.com`:               "x [address]",
		`unterminated"@example.com`:          `unterminated"[address]`,
		`"a@b"@c`:                            `"[address]"[address]`,
		"jean.müller@exämple.de":             "[address]",
		"用户@例子.广告 ok":                        "[address] ok",
		"see https://x.example/p?to=a@example.com&k=1": "see https://x.example/p?to=[address]&k=1",
		"a@[192.0.2.1]":                  "[address]",
		"a@[IPv6:2001:db8::1]!":          "[address]!",
		"a@[not a literal]":              "[address][not a literal]",
		"a@[]":                           "[address][]",
		"a@[unclosed":                    "[address][unclosed",
		"lone @ sign":                    "lone [address] sign",
		"@handle":                        "[address]",
		"trailing@":                      "[address]",
		"a@@b":                           "[address][address]",
		"a@b@c":                          "[address][address]",
		"x" + fullWidth + "example.com":  "[address]",
		"x" + small + "example.com y":    "[address] y",
		"bad \xff utf8 a@b.example \xfe": "bad \xff utf8 [address] \xfe",
		"\xffa@b":                        "\xff[address]",
		"a@b\xff":                        "[address]\xff",
	}
	for in, want := range cases {
		if got := audit.RedactAddresses(in); got != want {
			t.Errorf("RedactAddresses(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzRedactAddresses(f *testing.F) {
	for _, seed := range []string{
		"", "a@example.com", `"q\"x"@example.com`, "a@[IPv6:2001:db8::1]", "@", "\"@", "\\\"@",
		"用户@例子.广告", "x" + string(rune(0xFF20)) + "y", "\xff@\xfe", "a@b@c.", "[a@[1]",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := audit.RedactAddresses(s)
		if strings.ContainsAny(got, "@"+string(rune(0xFF20))+string(rune(0xFE6B))) {
			t.Fatalf("RedactAddresses(%q) = %q still holds an at sign", s, got)
		}
		if utf8.ValidString(s) && !utf8.ValidString(got) {
			t.Fatalf("RedactAddresses(%q) = %q is not valid UTF-8", s, got)
		}
		if !strings.ContainsAny(s, "@"+string(rune(0xFF20))+string(rune(0xFE6B))) && got != s {
			t.Fatalf("RedactAddresses(%q) = %q changed a text without address", s, got)
		}
		if again := audit.RedactAddresses(got); again != got {
			t.Fatalf("RedactAddresses is not idempotent on %q: %q then %q", s, got, again)
		}
	})
}

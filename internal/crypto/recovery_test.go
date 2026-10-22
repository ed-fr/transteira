package crypto

import (
	"crypto/sha256"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// recoveryCodeRE is the canonical form of a recovery code.
var recoveryCodeRE = regexp.MustCompile(`^rc-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$`)

func TestRecoveryAlphabet(t *testing.T) {
	t.Parallel()
	if len(recoveryAlphabet) != 32 || strings.ContainsAny(recoveryAlphabet, "ILOU") {
		t.Fatalf("alphabet %q", recoveryAlphabet)
	}
	seen := map[rune]bool{}
	for _, c := range recoveryAlphabet {
		if seen[c] {
			t.Fatalf("duplicate symbol %q", c)
		}
		seen[c] = true
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(MaxRecoveryCodes)
	if err != nil || len(codes) != MaxRecoveryCodes {
		t.Fatalf("GenerateRecoveryCodes = %d, %v", len(codes), err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if !recoveryCodeRE.MatchString(c) {
			t.Fatalf("malformed code %q", c)
		}
		if seen[c] {
			t.Fatalf("duplicate code %q", c)
		}
		seen[c] = true
		if n, ok := NormalizeRecoveryCode(c); !ok || n != c {
			t.Fatalf("generated code %q does not normalize to itself: %q", c, n)
		}
	}
	for _, n := range []int{0, -1, MaxRecoveryCodes + 1} {
		if c, err := GenerateRecoveryCodes(n); !errors.Is(err, ErrRecoveryCodeCount) || c != nil {
			t.Fatalf("count %d: %v, %v", n, c, err)
		}
	}
	setRand(t, errReader{})
	if c, err := GenerateRecoveryCodes(1); !errors.Is(err, errBoom) || c != nil {
		t.Fatalf("rand failure: %v, %v", c, err)
	}
}

func TestGenerateRecoveryCodesMapping(t *testing.T) {
	// The 12 symbols are the 60 low bits of the big-endian uint64, 5 bits
	// each, least significant first; the 4 high bits are ignored.
	setRand(t, strings.NewReader("\xf0\x00\x00\x00\x00\x00\x00\x00"+"\x0f\xff\xff\xff\xff\xff\xff\xff"+
		"\x00\x00\x00\x00\x00\x00\x00\x01"))
	codes, err := GenerateRecoveryCodes(3)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"rc-0000-0000-0000", "rc-ZZZZ-ZZZZ-ZZZZ", "rc-1000-0000-0000"}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("code %d = %s, want %s", i, codes[i], want[i])
		}
	}
}

func TestGenerateRecoveryCodesUniform(t *testing.T) {
	t.Parallel()
	// Every symbol of the alphabet appears at every position over a large
	// sample (a broken mapping would leave some out).
	codes, err := GenerateRecoveryCodes(MaxRecoveryCodes)
	if err != nil {
		t.Fatal(err)
	}
	for range 99 {
		more, err := GenerateRecoveryCodes(MaxRecoveryCodes)
		if err != nil {
			t.Fatal(err)
		}
		codes = append(codes, more...)
	}
	for pos := range recoverySymbols {
		seen := map[byte]bool{}
		for _, c := range codes {
			body := strings.ReplaceAll(strings.TrimPrefix(c, RecoveryCodePrefix), "-", "")
			seen[body[pos]] = true
		}
		if len(seen) != 32 {
			t.Fatalf("position %d uses %d symbols", pos, len(seen))
		}
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	t.Parallel()
	const canon = "rc-0123-4567-89AB"
	for _, in := range []string{
		canon, "RC-0123-4567-89AB", "rc-0123-4567-89ab", "0123-4567-89AB", "012345 6789ab",
		"rc012345678 9AB", "rc 0123 4567 89AB", "  rc--0123--4567--89AB  ", "0123456789AB", "r-c-0123456789AB",
	} {
		got, ok := NormalizeRecoveryCode(in)
		if !ok || got != canon {
			t.Errorf("Normalize(%q) = %q, %v", in, got, ok)
		}
	}
	// A body starting with RC is not mistaken for the prefix.
	if got, ok := NormalizeRecoveryCode("RC23-4567-89AB"); !ok || got != "rc-RC23-4567-89AB" {
		t.Errorf("RC body: %q, %v", got, ok)
	}
	if got, ok := NormalizeRecoveryCode("rcRC23456789AB"); !ok || got != "rc-RC23-4567-89AB" {
		t.Errorf("prefixed RC body: %q, %v", got, ok)
	}
	for _, in := range []string{
		"", "rc-", "rc-0123-4567-89A", "rc-0123-4567-89ABC", "rc-0123-4567-89AI", "rc-0123-4567-89AL",
		"rc-0123-4567-89AO", "rc-0123-4567-89AU", "rc_0123_4567_89AB", "rc-0123-4567-89AB\n", "\trc-0123-4567-89AB",
		"rc-0123-4567-89Aé", "xx-0123-4567-89AB", "rc-0123-4567-89AB-rc", strings.Repeat(" ", 53) + "0123456789AB",
		"rc-0123-4567-89A" + "\x00", "ＲＣ-0123-4567-89AB",
	} {
		if got, ok := NormalizeRecoveryCode(in); ok || got != "" {
			t.Errorf("Normalize(%q) accepted: %q", in, got)
		}
	}
	// Exactly 64 bytes is still accepted.
	if _, ok := NormalizeRecoveryCode(strings.Repeat(" ", 52) + "0123456789AB"); !ok {
		t.Error("64-byte input refused")
	}
}

func TestRecoveryCodeMAC(t *testing.T) {
	t.Parallel()
	// Sample recovery codes.
	const code, other = "rc-0123-4567-89AB", "rc-0123-4567-89AC" // gitleaks:allow
	key := []byte("12345678901234567890")
	h, err := RecoveryCodeMAC(key, code)
	if err != nil || len(h) != sha256.Size {
		t.Fatalf("RecoveryCodeMAC = %x, %v", h, err)
	}
	if again, _ := RecoveryCodeMAC(key, code); string(again) != string(h) {
		t.Fatal("not deterministic")
	}
	if m, _ := RecoveryCodeMAC(key, other); string(m) == string(h) {
		t.Fatal("distinct codes share a MAC")
	}
	if m, _ := RecoveryCodeMAC([]byte("12345678901234567891"), code); string(m) == string(h) {
		t.Fatal("distinct keys share a MAC")
	}
	if plain := sha256.Sum256([]byte(code)); string(plain[:]) == string(h) {
		t.Fatal("the MAC is the unkeyed SHA-256")
	}
	if _, err := RecoveryCodeMAC(key[:15], code); !errors.Is(err, ErrRecoveryKey) {
		t.Fatalf("short key: %v", err)
	}
}

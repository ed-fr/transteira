package tenant

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeHostValid(t *testing.T) {
	t.Parallel()
	long63 := strings.Repeat("a", 63)
	// 4 labels of 61 bytes + "com" + 4 dots = 251 bytes.
	long251 := strings.Repeat(strings.Repeat("b", 61)+".", 4) + "com"
	tests := []struct {
		name, in, want string
	}{
		{"plain", "transfer.entity-a.example.com", "transfer.entity-a.example.com"},
		{"uppercase", "Transfer.Entity-A.EXAMPLE.com", "transfer.entity-a.example.com"},
		{"port", "transfer.example.com:8443", "transfer.example.com"},
		{"empty port", "transfer.example.com:", "transfer.example.com"},
		{"trailing dot", "transfer.example.com.", "transfer.example.com"},
		{"trailing dot and port", "transfer.example.com.:443", "transfer.example.com"},
		{"localhost subdomain", "entity-a.localhost", "entity-a.localhost"},
		{"digits in labels", "1transfer.2example.com", "1transfer.2example.com"},
		{"idn", "transfert.société.example", "transfert.xn--socit-esab.example"},
		{"idn uppercase", "TRANSFERT.SOCIÉTÉ.example", "transfert.xn--socit-esab.example"},
		{"punycode input", "transfert.xn--socit-esab.example", "transfert.xn--socit-esab.example"},
		{"punycode tld", "transfer.xn--p1ai", "transfer.xn--p1ai"},
		{"label of 63", long63 + ".example.com", long63 + ".example.com"},
		{"name of 251", long251, long251},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeHost(tc.in)
			if err != nil {
				t.Fatalf("NormalizeHost(%q) error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeHostInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in string
	}{
		{"empty", ""},
		{"only dot", "."},
		{"only port", ":80"},
		{"too long raw", strings.Repeat("a", maxRawHostLen+1)},
		{"name over 253", strings.Repeat(strings.Repeat("b", 62)+".", 4) + "com"},
		{"label over 63", strings.Repeat("a", 64) + ".example.com"},
		{"userinfo", "user@transfer.example.com"},
		{"userinfo with password", "user:pass@transfer.example.com"},
		{"ipv4", "192.0.2.1"},
		{"ipv4 port", "192.0.2.1:8080"},
		{"ipv4 trailing dot", "192.0.2.1."},
		{"short ipv4", "127.1"},
		{"bracketed ipv6", "[2001:db8::1]"},
		{"bracketed ipv6 port", "[2001:db8::1]:443"},
		{"bare ipv6", "2001:db8::1"},
		{"ipv4 mapped ipv6", "::ffff:192.0.2.1"},
		{"single label", "localhost"},
		{"single label port", "intranet:80"},
		{"leading hyphen", "-transfer.example.com"},
		{"trailing hyphen", "transfer-.example.com"},
		{"underscore", "trans_fer.example.com"},
		{"space", "transfer .example.com"},
		{"slash", "transfer.example.com/path"},
		{"empty label", "transfer..example.com"},
		{"leading dot", ".example.com"},
		{"two trailing dots", "example.com.."},
		{"non numeric port", "transfer.example.com:http"},
		{"port too long", "transfer.example.com:123456"},
		{"numeric tld", "transfer.example.123"},
		{"one letter tld", "transfer.example.c"},
		{"tld with hyphen", "transfer.example.c-m"},
		{"invalid punycode", "transfer.xn--zz.example"},
		{"invalid utf8", "transfer.\xff.example"},
		{"nul byte", "transfer\x00.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeHost(tc.in)
			if err == nil {
				t.Fatalf("NormalizeHost(%q) = %q, want error", tc.in, got)
			}
			if !errors.Is(err, ErrInvalidHost) {
				t.Fatalf("NormalizeHost(%q) error %v does not wrap ErrInvalidHost", tc.in, err)
			}
			if got != "" {
				t.Fatalf("NormalizeHost(%q) returned %q with an error", tc.in, got)
			}
			if len(err.Error()) > 200 {
				t.Fatalf("error message too long (%d bytes)", len(err.Error()))
			}
		})
	}
}

// TestNormalizeHostUnstable exercises the re-normalisation guard with a
// conversion function that is not idempotent. It must not run in parallel
// because it swaps a package variable.
func TestNormalizeHostUnstable(t *testing.T) {
	orig := toASCII
	t.Cleanup(func() { toASCII = orig })
	toASCII = func(s string) (string, error) { return "x" + s, nil }
	if _, err := NormalizeHost("transfer.example.com"); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("unstable conversion accepted: %v", err)
	}
	toASCII = func(s string) (string, error) {
		if strings.HasPrefix(s, "x") {
			return "", errors.New("boom")
		}
		return "x" + s, nil
	}
	if _, err := NormalizeHost("transfer.example.com"); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("failing second pass accepted: %v", err)
	}
}

func TestCheckDNSNameAndTLD(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in string
		ok bool
	}{
		{"example.com", true},
		{"example.xn--p1ai", true},
		{"example", false},
		{"example.c0m", false},
		{"example.-com", false},
		{"exa_mple.com", false},
		{"Example.com", false},
	}
	for _, tc := range tests {
		if err := checkDNSName(tc.in); (err == nil) != tc.ok {
			t.Errorf("checkDNSName(%q) = %v, want ok=%v", tc.in, err, tc.ok)
		}
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	if got := truncate("short"); got != "short" {
		t.Fatalf("truncate short = %q", got)
	}
	got := truncate(strings.Repeat("x", 500))
	if len(got) != errMsgMaxLen+3 || !strings.HasSuffix(got, "...") {
		t.Fatalf("truncate long = %q", got)
	}
}

func FuzzNormalizeHost(f *testing.F) {
	for _, s := range []string{
		"transfer.example.com", "Transfer.Example.COM:8443", "example.com.",
		"[::1]:80", "192.0.2.1", "société.example", "xn--socit-esab.example",
		"a@b.example", "", ".", "a..b", "-a.example", "transfer.localhost",
		"ＦＵＬＬＷＩＤＴＨ.example", "a200db.example", "ß.example",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := NormalizeHost(in)
		if err != nil {
			if !errors.Is(err, ErrInvalidHost) {
				t.Fatalf("error %v does not wrap ErrInvalidHost", err)
			}
			return
		}
		again, err := NormalizeHost(out)
		if err != nil || again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q (%v)", in, out, again, err)
		}
		if strings.ContainsAny(out, ":[]@/ ") || out != strings.ToLower(out) {
			t.Fatalf("output %q contains forbidden characters", out)
		}
		if len(out) > maxDNSNameLen || !strings.Contains(out, ".") {
			t.Fatalf("output %q violates DNS constraints", out)
		}
	})
}

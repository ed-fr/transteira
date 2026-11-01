package provisioning

import (
	"regexp"
	"strings"
	"testing"
)

// openAPISuffix is the pattern of OpenAPI FqdnSuffixes, which the store
// checks again: every normalized suffix must match it.
var openAPISuffix = regexp.MustCompile(`^\.([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*([a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)

func TestNormalizeFQDN(t *testing.T) {
	for raw, want := range map[string]string{
		"Entity-C.Transfer.Example.com.": "entity-c.transfer.example.com",
		"bücher.example.com":             "xn--bcher-kva.example.com",
		"a.b.example.com":                "a.b.example.com",
	} {
		if got, err := NormalizeFQDN(raw); err != nil || got != want {
			t.Errorf("NormalizeFQDN(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"", "a.example.com:443", "192.0.2.1", "[2001:db8::1]", "*.example.com", "a b.example.com", "user@a.example.com",
		"a.example.com/x", "localhost", "-a.example.com", strings.Repeat("a", 64) + ".example.com",
	} {
		if got, err := NormalizeFQDN(raw); err == nil {
			t.Errorf("NormalizeFQDN(%q) = %q, want an error", raw, got)
		}
	}
}

func TestNormalizeSuffix(t *testing.T) {
	admins := []string{"admin.example.com", "transfer.example.net"}
	for raw, want := range map[string]string{
		".Transfer.Example.com.": ".transfer.example.com",
		".clients.example.com":   ".clients.example.com",
		".bücher.example.org":    ".xn--bcher-kva.example.org",
		".example.org":           ".example.org",
		".a.admin.example.com":   ".a.admin.example.com", // under an admin host, not covering it
	} {
		if got, err := NormalizeSuffix(raw, admins); err != nil || got != want {
			t.Errorf("NormalizeSuffix(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for raw, wantErr := range map[string]error{
		"transfer.example.com":  errSuffixDot,
		"":                      errSuffixDot,
		".com":                  errMalformedHost, // a single label
		".":                     errMalformedHost,
		"..example.com":         errMalformedHost,
		".example.com:443":      errMalformedHost,
		".*.example.com":        errMalformedHost,
		".192.0.2.1":            errMalformedHost,
		".example.c0m":          errMalformedHost, // numeric top label
		".admin.example.com":    errSuffixAdminHost,
		".example.com":          errSuffixAdminHost, // parent of an admin host
		".Example.NET.":         errSuffixAdminHost,
		".transfer.example.net": errSuffixAdminHost,
	} {
		if got, err := NormalizeSuffix(raw, admins); err != wantErr { //nolint:errorlint // exact sentinel expected
			t.Errorf("NormalizeSuffix(%q) = %q, %v; want %v", raw, got, err, wantErr)
		}
	}
}

func TestMatchSuffix(t *testing.T) {
	suffixes := []string{".transfer.example.com", ".xn--bcher-kva.example"}
	for fqdn, want := range map[string]bool{
		"entity-c.transfer.example.com":    true,
		"a.b.transfer.example.com":         true,
		"x.xn--bcher-kva.example":          true,
		"transfer.example.com":             false, // the suffix itself
		"eviltransfer.example.com":         false, // not on a label boundary
		"entity.transfer.example.com.evil": false,
		"entity.transfer.example.org":      false,
		"":                                 false,
		".transfer.example.com":            false,
		"a..transfer.example.com":          false,
		"entity-c.transfer.example.com.":   false, // not normalized
	} {
		if got := MatchSuffix(fqdn, suffixes); got != want {
			t.Errorf("MatchSuffix(%q) = %v, want %v", fqdn, got, want)
		}
	}
	// A suffix stored without its dot, or a lone dot, never matches.
	for _, bad := range [][]string{{"example.com"}, {"."}, {""}, nil} {
		if MatchSuffix("evilexample.com", bad) || MatchSuffix("a.example.com", bad) {
			t.Errorf("MatchSuffix with %q matched", bad)
		}
	}
}

// FuzzMatchSuffix checks the invariants of the suffix matcher on arbitrary
// input (T-276): a match is always a normalized FQDN ending with the
// normalized suffix on a label boundary, with at least one label in front,
// and never the suffix itself nor an admin host.
func FuzzMatchSuffix(f *testing.F) {
	for _, s := range [][2]string{
		{"entity.transfer.example.com", ".transfer.example.com"},
		{"eviltransfer.example.com", ".transfer.example.com"},
		{"transfer.example.com", ".transfer.example.com"},
		{"ENTITY.Transfer.Example.COM.", ".TRANSFER.example.com."},
		{"bücher.example.com", ".example.com"},
		{"a.example.com:443", ".example.com"},
		{"x.admin.example.com", ".admin.example.com"},
		{"192.0.2.1", ".0.2.1"},
		{"", ""},
	} {
		f.Add(s[0], s[1])
	}
	admins := []string{"admin.example.com"}
	f.Fuzz(func(t *testing.T, rawFQDN, rawSuffix string) {
		fqdn, ferr := NormalizeFQDN(rawFQDN)
		suffix, serr := NormalizeSuffix(rawSuffix, admins)
		if serr == nil && (!openAPISuffix.MatchString(suffix) || len(suffix) > 254) {
			t.Fatalf("normalized suffix %q breaks the OpenAPI pattern", suffix)
		}
		if ferr != nil {
			fqdn = rawFQDN
		}
		if serr != nil {
			suffix = rawSuffix
		}
		if !MatchSuffix(fqdn, []string{suffix}) {
			return
		}
		front, ok := strings.CutSuffix(fqdn, suffix)
		if !ok || !strings.HasPrefix(suffix, ".") || front == "" || strings.HasSuffix(front, ".") || strings.HasPrefix(front, ".") {
			t.Fatalf("MatchSuffix(%q, %q) matched off a label boundary", fqdn, suffix)
		}
		if ferr == nil && serr == nil {
			if again, err := NormalizeFQDN(fqdn); err != nil || again != fqdn {
				t.Fatalf("normalized FQDN %q is not stable", fqdn)
			}
			if again, err := NormalizeSuffix(suffix, admins); err != nil || again != suffix {
				t.Fatalf("normalized suffix %q is not stable", suffix)
			}
			if fqdn == "admin.example.com" {
				t.Fatalf("an admin host matched suffix %q", suffix)
			}
		}
	})
}

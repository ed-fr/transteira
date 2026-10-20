package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// prefixes parses a comma-separated list through parsePrefixes.
func prefixes(t *testing.T, raw string) []netip.Prefix {
	t.Helper()
	p, err := parsePrefixes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// all8 returns every IPv4 /8 except the skipped one (-1 for none).
func all8(skip int) string {
	var items []string
	for i := range 256 {
		if i != skip {
			items = append(items, fmt.Sprintf("%d.0.0.0/8", i))
		}
	}
	return strings.Join(items, ",")
}

func TestValidateTrustedProxies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw  string
		ok   bool
		want string
	}{
		{"", true, ""},
		{"192.0.2.10", true, ""},
		{"10.0.0.0/8, 2001:db8::/32", true, ""},
		{"0.0.0.0/0", false, "minimum"},
		{"::/0", false, "minimum"},
		{"::ffff:0:0/96", false, "minimum"},
		{"10.0.0.0/7", false, "/8 minimum for IPv4"},
		{"2001:db8::/31", false, "/32 minimum for IPv6"},
		{"0.0.0.0/1,128.0.0.0/1,::/1,8000::/1", false, "minimum"},
		{all8(-1), false, "whole IPv4"},
		{all8(127), true, ""},
		{all8(0), true, ""},
		{all8(255), true, ""},
		// Overlapping and unordered prefixes covering everything.
		{"10.0.0.0/8," + all8(10) + ",10.1.0.0/16", false, "whole IPv4"},
	}
	for _, tc := range tests {
		err := ValidateTrustedProxies(prefixes(t, tc.raw))
		name := tc.raw
		if len(name) > 60 {
			name = name[:60] + "..."
		}
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s: unexpected error %v", name, err)
		case !tc.ok && (err == nil || !errors.Is(err, ErrTrustedProxiesTooBroad) || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error %v, want ErrTrustedProxiesTooBroad mentioning %q", name, err, tc.want)
		}
	}
}

func TestCoversAll(t *testing.T) {
	t.Parallel()
	v6 := netip.IPv6Unspecified()
	// The whole IPv6 space split into /32 is out of reach, so coversAll is
	// exercised directly with broader prefixes.
	tests := []struct {
		raw  string
		want bool
	}{
		{"", false},
		{"::/1,8000::/1", true},
		{"8000::/1,::/1", true},
		{"::/1", false},
		{"8000::/1", false},
		{"::/2,8000::/1", false},
		{"::/1,4000::/2,8000::/1", true},
		{"::/1,::/2,8000::/2,c000::/2", true},
		{"::/1,8000::/2", false},
	}
	for _, tc := range tests {
		if got := coversAll(prefixes(t, tc.raw), v6); got != tc.want {
			t.Errorf("coversAll(%s) = %v, want %v", tc.raw, got, tc.want)
		}
	}
	if !coversAll(prefixes(t, "0.0.0.0/0"), netip.IPv4Unspecified()) {
		t.Error("0.0.0.0/0 does not cover IPv4")
	}
}

func TestLastAddr(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"10.0.0.0/8":     "10.255.255.255",
		"192.0.2.0/27":   "192.0.2.31",
		"192.0.2.1/32":   "192.0.2.1",
		"2001:db8::/32":  "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
		"2001:db8::/127": "2001:db8::1",
	} {
		if got := lastAddr(netip.MustParsePrefix(raw)); got != netip.MustParseAddr(want) {
			t.Errorf("lastAddr(%s) = %s, want %s", raw, got, want)
		}
	}
}

func TestLoadRefusesBroadTrustedProxies(t *testing.T) {
	t.Parallel()
	verr := mustFail(t, map[string]string{EnvTrustedProxies: "0.0.0.0/1,128.0.0.0/1"})
	if len(verr.Problems) != 1 || verr.Problems[0].Variable != EnvTrustedProxies {
		t.Errorf("problems = %+v, want one on %s", verr.Problems, EnvTrustedProxies)
	}
	if !errors.Is(verr, ErrTrustedProxiesTooBroad) {
		t.Errorf("errors.Is(%v, ErrTrustedProxiesTooBroad) = false", verr)
	}
}

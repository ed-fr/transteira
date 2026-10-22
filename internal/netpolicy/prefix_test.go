package netpolicy

import (
	"errors"
	"net/netip"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		item    string
		want    string
		wantErr error
	}{
		{item: "192.0.2.1", want: "192.0.2.1/32"},
		{item: "2001:db8::1", want: "2001:db8::1/128"},
		{item: "::ffff:192.0.2.1", want: "192.0.2.1/32"},
		{item: "10.0.0.0/8", want: "10.0.0.0/8"},
		{item: "0.0.0.0/0", want: "0.0.0.0/0"},
		{item: "2001:db8::/32", want: "2001:db8::/32"},
		{item: "::ffff:10.0.0.0/104", want: "10.0.0.0/8"},
		{item: "::ffff:192.0.2.1/128", want: "192.0.2.1/32"},
		{item: "::ffff:0:0/96", want: "0.0.0.0/0"},
		{item: "::ffff:0:0/95", wantErr: ErrPrefixHostBits},
		{item: "::ffff:10.0.0.1/104", wantErr: ErrPrefixHostBits},
		{item: "10.0.0.1/8", wantErr: ErrPrefixHostBits},
		{item: "10.0.0.0/", wantErr: ErrPrefixSyntax},
		{item: "fe80::1%eth0", wantErr: ErrPrefixZone},
		{item: "fe80::%eth0/64", wantErr: ErrPrefixSyntax},
		{item: "example.com", wantErr: ErrPrefixSyntax},
		{item: "1.2.3.4.5", wantErr: ErrPrefixSyntax},
		{item: " 10.0.0.0/8", wantErr: ErrPrefixSyntax},
		{item: "", wantErr: ErrPrefixSyntax},
	}
	for _, tc := range tests {
		got, err := ParsePrefix(tc.item)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) || got.IsValid() {
				t.Errorf("ParsePrefix(%q) = %v, %v, want %v", tc.item, got, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got.String() != tc.want {
			t.Errorf("ParsePrefix(%q) = %v, %v, want %s", tc.item, got, err, tc.want)
		}
	}
}

func TestContains(t *testing.T) {
	t.Parallel()
	prefixes := []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fe80::/10")}
	for addr, want := range map[string]bool{
		"169.254.169.254":        true,
		"::ffff:169.254.169.254": true,
		"fe80::1%eth0":           true,
		"192.0.2.1":              false,
		"2001:db8::1":            false,
	} {
		if got := Contains(prefixes, netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
	if Contains([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, netip.Addr{}) {
		t.Error("an invalid address matched")
	}
}

func FuzzParsePrefix(f *testing.F) {
	for _, seed := range []string{
		"", "10.0.0.0/8", "2001:db8::/32", "0.0.0.0/0", "::/0", "fe80::1%eth0", "::ffff:10.0.0.0/104",
		"::ffff:0:0/95", "10.0.0.1/8", "::ffff:1.2.3.4", "1.2.3.4/33",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, item string) {
		p, err := ParsePrefix(item)
		if err != nil {
			if p.IsValid() {
				t.Fatalf("valid result with error for %q", item)
			}
			return
		}
		if !p.IsValid() || p != p.Masked() || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			t.Fatalf("invalid prefix %v from %q", p, item)
		}
		// Round trip: a parsed prefix must parse back to itself.
		if again, err := ParsePrefix(p.String()); err != nil || again != p {
			t.Fatalf("round trip of %v failed: %v, %v", p, again, err)
		}
		if !Contains([]netip.Prefix{p}, p.Addr()) {
			t.Fatalf("%v does not contain its own address", p)
		}
	})
}

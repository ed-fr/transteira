package netpolicy

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".com"
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"example.com", "example.com", true},
		{"  Example.COM ", "example.com", true},
		{"example.com.", "example.com", true},
		{"example.com..", "", false},
		{".example.com", "", false},
		{"", "", false},
		{"   ", "", false},
		{"bücher.example", "xn--bcher-kva.example", true},
		{"XN--BCHER-KVA.example", "xn--bcher-kva.example", true},
		{"-bad.example.com", "", false},
		{"a b.example.com", "", false},
		{"user@example.com", "", false},
		{"example.com:25", "", false},
		{"10.0.0.1", "", false},
		{long, "", false},
	}
	for _, tc := range tests {
		got, err := NormalizeDomain(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("NormalizeDomain(%q) = %q, %v", tc.in, got, err)
		}
		if err != nil && !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("error does not wrap ErrInvalidDomain: %v", err)
		}
	}
}

func TestEmailDomain(t *testing.T) {
	if d, err := EmailDomain("Bob@Example.COM."); err != nil || d != "example.com" {
		t.Errorf("got %q, %v", d, err)
	}
	if d, err := EmailDomain("a@b@c.example.com"); err != nil || d != "c.example.com" {
		t.Errorf("got %q, %v", d, err)
	}
	for _, in := range []string{"nodomain", "bob@", "bob@bad domain"} {
		if _, err := EmailDomain(in); !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("EmailDomain(%q) err = %v", in, err)
		}
	}
}

func TestRecipientDomainAllowed(t *testing.T) {
	tests := []struct {
		name            string
		domain          string
		allowed, denied []string
		want            bool
	}{
		{"empty lists accept all", "example.com", nil, nil, true},
		{"invalid domain accepted without rule", "bad domain", nil, nil, true},
		{"underscore domain accepted without rule", "foo_bar.example.com", nil, nil, true},
		{"single label accepted without rule", "localhost", nil, nil, true},
		{"invalid domain refused with allow list", "bad domain", []string{"example.com"}, nil, false},
		{"invalid domain refused with deny list", "foo_bar.example.com", nil, []string{"other.org"}, false},
		{"allow exact", "example.com", []string{"example.com"}, nil, true},
		{"allow mixed case and trailing dot", "Example.COM.", []string{"example.com"}, nil, true},
		{"allow subdomain", "a.b.example.com", []string{"example.com"}, nil, true},
		{"suffix is not subdomain", "badexample.com", []string{"example.com"}, nil, false},
		{"parent is not matched by subdomain rule", "example.com", []string{"a.example.com"}, nil, false},
		{"not in allow list", "other.org", []string{"example.com"}, nil, false},
		{"deny exact", "example.com", nil, []string{"example.com"}, false},
		{"deny subdomain", "x.example.com", nil, []string{"example.com"}, false},
		{"deny suffix is not subdomain", "badexample.com", nil, []string{"example.com"}, true},
		{"deny wins over allow", "x.example.com", []string{"example.com"}, []string{"x.example.com"}, false},
		{"allow with other deny", "example.com", []string{"example.com"}, []string{"other.org"}, true},
		{"idn equals punycode", "bücher.example", []string{"xn--bcher-kva.example"}, nil, true},
		{"punycode equals idn deny", "xn--bcher-kva.example", nil, []string{"xn--bcher-kva.example"}, false},
		{"empty rule never matches", "example.com", []string{""}, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RecipientDomainAllowed(tc.domain, tc.allowed, tc.denied); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func FuzzNormalizeDomain(f *testing.F) {
	for _, s := range []string{"example.com", "Example.COM.", "bücher.example", ".a.com", "xn--a.b", "a..b", "a@b.com", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := NormalizeDomain(s)
		if err != nil {
			return
		}
		if len(n) > 253 {
			t.Fatalf("too long: %q", n)
		}
		again, err := NormalizeDomain(n)
		if err != nil || again != n {
			t.Fatalf("not idempotent: %q -> %q (%v)", n, again, err)
		}
	})
}

func FuzzRecipientDomainAllowed(f *testing.F) {
	f.Add("example.com", "example.com", "other.org")
	f.Add("bücher.example", "xn--bcher-kva.example", "")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, domain, allow, deny string) {
		var allowed, denied []string
		if a, err := NormalizeDomain(allow); err == nil {
			allowed = []string{a}
		}
		if d, err := NormalizeDomain(deny); err == nil {
			denied = []string{d}
		}
		got := RecipientDomainAllowed(domain, allowed, denied)
		// Equivalent forms of the domain must give the same decision.
		if n, err := NormalizeDomain(domain); err == nil {
			if RecipientDomainAllowed(n, allowed, denied) != got ||
				RecipientDomainAllowed(strings.ToUpper(n)+".", allowed, denied) != got {
				t.Fatalf("decision differs for equivalent forms of %q", domain)
			}
		} else if got && len(allowed)+len(denied) > 0 {
			t.Fatalf("invalid domain %q accepted", domain)
		}
	})
}

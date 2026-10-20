package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzSameOrigin checks the Origin rule of CSRF on arbitrary Origin and
// Host values: it never panics, and accepts exactly "https://" followed by
// the request host, compared case-insensitively, with or without an
// explicit :443 on either side.
func FuzzSameOrigin(f *testing.F) {
	for _, seed := range [][2]string{
		{"https://transfer.entity-a.example.com", "transfer.entity-a.example.com"},
		{"https://TRANSFER.entity-a.example.com:443", "transfer.entity-a.example.com"},
		{"https://transfer.entity-a.example.com", "transfer.entity-a.example.com:443"},
		{"https://transfer.entity-a.localhost:8443", "transfer.entity-a.localhost:8443"},
		{"http://transfer.entity-a.example.com", "transfer.entity-a.example.com"},
		{"https://evil.example.net", "transfer.entity-a.example.com"},
		{"null", "transfer.entity-a.example.com"},
		{"https://", ""},
		{"https://transfer.entity-a.example.com/x", "transfer.entity-a.example.com"},
		{"HTTPS://transfer.entity-a.example.com", "transfer.entity-a.example.com"},
		{"https://transfer.entity-a.example.com:443:443", "transfer.entity-a.example.com"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, origin, host string) {
		r := httptest.NewRequest("POST", "/", nil)
		r.Host = host
		r.Header["Origin"] = []string{origin}
		got := sameOrigin(r)
		rest, ok := strings.CutPrefix(origin, "https://")
		trim := func(s string) string { return strings.TrimSuffix(s, ":443") }
		// The only acceptable Origin: https:// and the host, folded.
		exact := ok && rest != "" && strings.EqualFold(trim(rest), trim(host))
		if got != exact {
			t.Fatalf("sameOrigin(Origin %q, Host %q) = %v, want %v", origin, host, got, exact)
		}
		// Independent oracle on ASCII input: byte-wise lowercase comparison.
		if isASCII(origin) && isASCII(host) {
			lower := ok && rest != "" && asciiLower(trim(rest)) == asciiLower(trim(host))
			if got != lower {
				t.Fatalf("sameOrigin(Origin %q, Host %q) = %v, want %v (ASCII)", origin, host, got, lower)
			}
		}
		// No Origin header at all is always accepted.
		delete(r.Header, "Origin")
		if !sameOrigin(r) {
			t.Fatal("a request without Origin was refused")
		}
	})
}

// isASCII reports whether s holds ASCII bytes only.
func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// asciiLower lowercases the ASCII letters of s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// FuzzSameSite checks the Sec-Fetch-Site rule: it never panics, and accepts
// only a single value exactly equal to "same-origin" (or no header).
func FuzzSameSite(f *testing.F) {
	for _, seed := range []string{"same-origin", "same-site", "cross-site", "none", "Same-Origin", "same-origin ", ""} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, value string, twice bool) {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header["Sec-Fetch-Site"] = []string{value}
		if twice {
			r.Header["Sec-Fetch-Site"] = append(r.Header["Sec-Fetch-Site"], value)
		}
		if got, want := sameSite(r), !twice && value == "same-origin"; got != want {
			t.Fatalf("sameSite(%q, twice=%v) = %v, want %v", value, twice, got, want)
		}
	})
}

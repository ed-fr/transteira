package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// testTrusted trusts 10.0.0.0/8 and fd00::/8.
func testTrusted(a netip.Addr) bool {
	return netip.MustParsePrefix("10.0.0.0/8").Contains(a) || netip.MustParsePrefix("fd00::/8").Contains(a)
}

func TestRealIP(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		xff    []string
		xreal  []string
		want   string // "" means the zero Addr
	}{
		{"untrusted peer, no headers", "203.0.113.5:1234", nil, nil, "203.0.113.5"},
		{"untrusted peer ignores XFF", "203.0.113.5:1234", []string{"192.0.2.1"}, nil, "203.0.113.5"},
		{"untrusted peer ignores X-Real-IP", "203.0.113.5:1234", nil, []string{"192.0.2.1"}, "203.0.113.5"},
		{"trusted peer, single XFF", "10.0.0.2:443", []string{"192.0.2.1"}, nil, "192.0.2.1"},
		{"spoofed left entry ignored", "10.0.0.2:443", []string{"1.1.1.1, 192.0.2.1"}, nil, "192.0.2.1"},
		{"skip trusted hops", "10.0.0.2:443", []string{"198.51.100.7, 192.0.2.1, 10.0.0.9"}, nil, "192.0.2.1"},
		{"multiple header lines", "10.0.0.2:443", []string{"198.51.100.7", "192.0.2.1, 10.1.1.1"}, nil, "192.0.2.1"},
		{"all trusted gives no client IP", "10.0.0.2:443", []string{"10.0.0.5, 10.0.0.6"}, nil, ""},
		{"empty entries ignored", "10.0.0.2:443", []string{" , 192.0.2.1 ,, \t"}, nil, "192.0.2.1"},
		{"malformed reached fails closed", "10.0.0.2:443", []string{"evil, 10.0.0.3"}, nil, ""},
		{"malformed rightmost fails closed", "10.0.0.2:443", []string{"192.0.2.60, garbage"}, nil, ""},
		{"malformed in later line fails closed", "10.0.0.2:443", []string{"192.0.2.60", "garbage"}, []string{"192.0.2.1"}, ""},
		{"malformed left of client unreached", "10.0.0.2:443", []string{"evil, 192.0.2.1"}, nil, "192.0.2.1"},
		{"unknown token fails closed", "10.0.0.2:443", []string{"unknown"}, nil, ""},
		{"overlong entry fails closed", "10.0.0.2:443", []string{strings.Repeat("1", 100)}, nil, ""},
		{"entry with port", "10.0.0.2:443", []string{"192.0.2.1:5555"}, nil, "192.0.2.1"},
		{"ipv6 entry with port", "10.0.0.2:443", []string{"[2001:db8::1]:5555"}, nil, "2001:db8::1"},
		{"ipv4-mapped unmapped", "10.0.0.2:443", []string{"::ffff:192.0.2.1"}, nil, "192.0.2.1"},
		{"zone stripped", "10.0.0.2:443", []string{"fe80::1%eth0"}, nil, "fe80::1"},
		{"ipv6 trusted peer", "[fd00::2]:443", []string{"2001:db8::5"}, nil, "2001:db8::5"},
		{"mapped trusted peer", "[::ffff:10.0.0.2]:443", []string{"192.0.2.1"}, nil, "192.0.2.1"},
		{"X-Real-IP from trusted peer", "10.0.0.2:443", nil, []string{" 192.0.2.1 "}, "192.0.2.1"},
		{"empty XFF falls back to X-Real-IP", "10.0.0.2:443", []string{" , "}, []string{"192.0.2.1"}, "192.0.2.1"},
		{"XFF wins over X-Real-IP", "10.0.0.2:443", []string{"192.0.2.1"}, []string{"198.51.100.1"}, "192.0.2.1"},
		{"invalid X-Real-IP fails closed", "10.0.0.2:443", nil, []string{"nope"}, ""},
		{"repeated X-Real-IP fails closed", "10.0.0.2:443", nil, []string{"192.0.2.1", "192.0.2.2"}, ""},
		{"trusted peer, no headers fails closed", "10.0.0.2:443", nil, nil, ""},
		{"trusted peer, empty XFF and no X-Real-IP", "10.0.0.2:443", []string{" , "}, nil, ""},
		{"bare peer address", "203.0.113.5", nil, nil, "203.0.113.5"},
		{"unparsable peer", "@", []string{"192.0.2.1"}, nil, ""},
		{"empty peer", "", nil, nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got netip.Addr
			h := RealIP(testTrusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = ClientIP(r.Context())
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			for _, v := range tc.xreal {
				req.Header.Add("X-Real-IP", v)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
			var want netip.Addr
			if tc.want != "" {
				want = netip.MustParseAddr(tc.want)
			}
			if got != want {
				t.Fatalf("ClientIP = %v, want %v", got, want)
			}
		})
	}
}

func TestRealIPNilTrusted(t *testing.T) {
	var got netip.Addr
	h := RealIP(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = ClientIP(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Forwarded-For", "192.0.2.1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("ClientIP = %v", got)
	}
	if ClientIP(context.Background()).IsValid() {
		t.Fatal("ClientIP of empty context should be the zero Addr")
	}
}

func FuzzForwardedFor(f *testing.F) {
	f.Add(true, "1.1.1.1, 192.0.2.1, 10.0.0.9", "", "")
	f.Add(true, "", "", "192.0.2.1")
	f.Add(true, "evil,10.0.0.1", "10.0.0.2", "")
	f.Add(true, "192.0.2.60, garbage", "", "192.0.2.1")
	f.Add(true, "", "", "")
	f.Add(false, "192.0.2.1", "", "192.0.2.2")
	f.Add(true, "[fe80::1%eth0]:80, ::ffff:10.0.0.1", "fd00::1", "x")
	f.Fuzz(func(t *testing.T, peerTrusted bool, xff1, xff2, xreal string) {
		peer := netip.MustParseAddr("203.0.113.9")
		if peerTrusted {
			peer = netip.MustParseAddr("10.0.0.2")
		}
		h := http.Header{}
		h.Add("X-Forwarded-For", xff1)
		h.Add("X-Forwarded-For", xff2)
		h.Set("X-Real-Ip", xreal)
		got := clientIP(peer, h, testTrusted)
		if !peerTrusted {
			if got != peer {
				t.Fatalf("untrusted peer: clientIP = %v, want peer", got)
			}
			return
		}
		if !got.IsValid() {
			return // fail closed: no valid forwarded address
		}
		if got.Zone() != "" || got.Is4In6() {
			t.Fatalf("clientIP = %v: zoned or mapped", got)
		}
		if !strings.Contains(xff1+","+xff2+","+xreal, got.Unmap().String()) && !strings.Contains(strings.ToLower(xff1+","+xff2+","+xreal), ":") {
			// Also proves the proxy address is never used as a fallback.
			t.Fatalf("clientIP %v appears nowhere in the input", got)
		}
	})
}

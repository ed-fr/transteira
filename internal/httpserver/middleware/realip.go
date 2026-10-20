package middleware

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
)

// maxIPLen bounds the length of a single forwarded address entry. An IPv6
// address with brackets, zone and port fits easily.
const maxIPLen = 64

// RealIP computes the real client IP and stores it in the request context
// (see [ClientIP]). trusted reports whether an address is a declared
// reverse proxy (typically config.Config.IsTrustedProxy); a nil trusted
// trusts nobody.
//
// The TCP peer address (r.RemoteAddr) is the only fact the server knows for
// sure. Forwarding headers are read only when that peer is trusted, so that
// a client connecting directly can never choose its IP (threat model T-05,
// T-06):
//
//   - X-Forwarded-For: all header lines are concatenated in order and the
//     comma-separated entries are walked from right to left, skipping
//     trusted proxies. The first untrusted address is the client. Empty
//     entries are ignored.
//   - X-Real-IP: used only when X-Forwarded-For is absent or empty, and only
//     when it appears exactly once with a valid address.
//
// When the peer is a trusted proxy, the client address must come from
// these headers. If no valid forwarded address can be found (no
// X-Forwarded-For entry and no usable X-Real-IP, a malformed entry reached
// during the right-to-left walk, or only trusted entries), ClientIP is the
// zero Addr: the
// rule fails closed. The proxy address is never used as the client
// address, because it is shared by every client behind the proxy and may
// lie inside a tenant's internal IP range. The zero Addr matches no IP
// range (so access checks refuse internal-only actions), is written as
// "ip=-" in the security log (so fail2ban and CrowdSec never ban the
// proxy), and shares a single rate-limit bucket (see [RateLimitKey]). A
// malformed entry to the left of the first untrusted address is never
// reached and therefore ignored: those entries are client-controlled, and
// letting them change the result would let a client escape per-IP bans.
//
// Addresses are normalized: IPv4-mapped IPv6 addresses are unmapped and
// zones are stripped; entries longer than 64 bytes are malformed. When
// r.RemoteAddr itself cannot be parsed (for example a Unix socket),
// ClientIP is also the zero Addr.
func RealIP(trusted func(netip.Addr) bool) func(http.Handler) http.Handler {
	if trusted == nil {
		trusted = func(netip.Addr) bool { return false }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, _ := parseIP(r.RemoteAddr)
			ip := clientIP(peer, r.Header, trusted)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey, ip)))
		})
	}
}

// ClientIP returns the client IP stored by [RealIP], or the zero Addr when
// there is none.
func ClientIP(ctx context.Context) netip.Addr {
	ip, _ := ctx.Value(clientIPKey).(netip.Addr)
	return ip
}

// clientIP applies the RealIP rules to a peer address and request headers.
// It returns the zero Addr when the peer is trusted but no valid forwarded
// address is available.
func clientIP(peer netip.Addr, h http.Header, trusted func(netip.Addr) bool) netip.Addr {
	if !peer.IsValid() || !trusted(peer) {
		return peer
	}
	if ip, found, ok := fromForwardedFor(h.Values("X-Forwarded-For"), trusted); found {
		if !ok {
			return netip.Addr{}
		}
		return ip
	}
	if values := h.Values("X-Real-Ip"); len(values) == 1 {
		if ip, ok := parseIP(strings.Trim(values[0], " \t")); ok {
			return ip
		}
	}
	return netip.Addr{}
}

// fromForwardedFor walks the X-Forwarded-For entries from right to left.
// found reports whether at least one non-empty entry exists; ok is false
// when a malformed entry was reached or when every entry is trusted (a
// trusted address, possibly the proxy itself, is never a client address).
func fromForwardedFor(values []string, trusted func(netip.Addr) bool) (ip netip.Addr, found, ok bool) {
	for i := len(values) - 1; i >= 0; i-- {
		rest := values[i]
		for done := false; !done; {
			var entry string
			if j := strings.LastIndexByte(rest, ','); j >= 0 {
				entry, rest = rest[j+1:], rest[:j]
			} else {
				entry, done = rest, true
			}
			entry = strings.Trim(entry, " \t")
			if entry == "" {
				continue
			}
			found = true
			addr, valid := parseIP(entry)
			if !valid {
				return netip.Addr{}, true, false
			}
			if !trusted(addr) {
				return addr, true, true
			}
		}
	}
	return netip.Addr{}, found, false
}

// parseIP parses an IP address, optionally followed by a port ("ip:port" or
// "[ipv6]:port"), and normalizes it (unmapped, zone stripped).
func parseIP(s string) (netip.Addr, bool) {
	if len(s) > maxIPLen {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		ap, perr := netip.ParseAddrPort(s)
		if perr != nil {
			return netip.Addr{}, false
		}
		ip = ap.Addr()
	}
	return ip.Unmap().WithZone(""), true
}

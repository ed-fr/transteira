package config

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// Trusted proxy prefix bounds (threat model T-06 and T-08). A trusted proxy
// may set the client IP through X-Forwarded-For / X-Real-IP, so a broad
// trusted range lets every host inside it forge its address and bypass IP
// filtering, rate limiting and the fail2ban/CrowdSec bans.
const (
	// MinTrustedPrefixBitsIPv4 is the shortest IPv4 prefix accepted in
	// TT_TRUSTED_PROXIES (/8). Anything broader is refused at start-up.
	MinTrustedPrefixBitsIPv4 = 8
	// MinTrustedPrefixBitsIPv6 is the shortest IPv6 prefix accepted in
	// TT_TRUSTED_PROXIES (/32). Anything broader is refused at start-up.
	MinTrustedPrefixBitsIPv6 = 32
	// WarnTrustedPrefixBitsIPv4 is the IPv4 prefix length below which the
	// application logs a warning advising to list the proxies precisely (/24).
	WarnTrustedPrefixBitsIPv4 = 24
	// WarnTrustedPrefixBitsIPv6 is the IPv6 prefix length below which the
	// application logs a warning advising to list the proxies precisely (/64).
	WarnTrustedPrefixBitsIPv6 = 64
)

// ErrTrustedProxiesTooBroad is wrapped by [ValidateTrustedProxies] errors.
var ErrTrustedProxiesTooBroad = errors.New("trusted proxies are too broad: any client inside them could forge its IP address")

// ValidateTrustedProxies refuses a trusted proxy list that is too broad: an
// IPv4 prefix shorter than [MinTrustedPrefixBitsIPv4], an IPv6 prefix shorter
// than [MinTrustedPrefixBitsIPv6], or a set of prefixes whose union covers the
// whole IPv4 or the whole IPv6 address space (e.g. split halves such as
// 0.0.0.0/1,128.0.0.0/1). Prefixes are expected masked and unmapped, as
// returned by [Load]. The returned error wraps [ErrTrustedProxiesTooBroad].
func ValidateTrustedProxies(prefixes []netip.Prefix) error {
	var v4, v6 []netip.Prefix
	for _, p := range prefixes {
		minBits, family := MinTrustedPrefixBitsIPv6, "IPv6"
		if p.Addr().Is4() {
			minBits, family = MinTrustedPrefixBitsIPv4, "IPv4"
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
		if p.Bits() < minBits {
			return fmt.Errorf("%w: %s is shorter than the /%d minimum for %s; list the reverse proxies by their exact IP address",
				ErrTrustedProxiesTooBroad, p, minBits, family)
		}
	}
	if coversAll(v4, netip.IPv4Unspecified()) {
		return fmt.Errorf("%w: together the prefixes cover the whole IPv4 address space", ErrTrustedProxiesTooBroad)
	}
	if coversAll(v6, netip.IPv6Unspecified()) {
		return fmt.Errorf("%w: together the prefixes cover the whole IPv6 address space", ErrTrustedProxiesTooBroad)
	}
	return nil
}

// BroadTrustedProxies returns the trusted proxy prefixes wider than
// [WarnTrustedPrefixBitsIPv4] (IPv4) or [WarnTrustedPrefixBitsIPv6] (IPv6).
// They are accepted, but the application warns about them at start-up
// because every host inside them is trusted to report the client IP.
func (c *Config) BroadTrustedProxies() []netip.Prefix {
	var broad []netip.Prefix
	for _, p := range c.TrustedProxies {
		limit := WarnTrustedPrefixBitsIPv6
		if p.Addr().Is4() {
			limit = WarnTrustedPrefixBitsIPv4
		}
		if p.Bits() < limit {
			broad = append(broad, p)
		}
	}
	return broad
}

// coversAll reports whether the union of prefixes, all of the family of
// first (the lowest address of that family), covers the whole family. The
// ranges are sorted by first address and merged; any gap means false.
func coversAll(prefixes []netip.Prefix, first netip.Addr) bool {
	if len(prefixes) == 0 {
		return false
	}
	sorted := slices.Clone(prefixes)
	slices.SortFunc(sorted, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	next := first // lowest address not yet covered
	for _, p := range sorted {
		if p.Addr().Compare(next) > 0 {
			return false // gap before p
		}
		last := lastAddr(p)
		if !last.Next().IsValid() {
			return true // p reaches the highest address of the family
		}
		if last.Next().Compare(next) > 0 {
			next = last.Next()
		}
	}
	return false
}

// lastAddr returns the highest address of the masked prefix p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b) // b has the length of a valid address
	return a
}

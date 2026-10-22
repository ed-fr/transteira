package netpolicy

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
)

// ipv4MappedBits is the length of the ::ffff:0:0/96 IPv4-mapped IPv6 prefix.
const ipv4MappedBits = 96

// Errors of [ParsePrefix]. They never quote the parsed value, so that a
// caller decides whether it may be echoed.
var (
	// ErrPrefixSyntax reports a value that is neither an IP address nor a
	// CIDR prefix.
	ErrPrefixSyntax = errors.New("not a valid IP address or CIDR prefix")
	// ErrPrefixZone reports an IPv6 address with a zone.
	ErrPrefixZone = errors.New("IPv6 zones are not allowed")
	// ErrPrefixHostBits reports a prefix with host bits set.
	ErrPrefixHostBits = errors.New("host bits are set")
)

// ParsePrefix parses one IP range, with the rules shared by the
// installation configuration (TT_TRUSTED_PROXIES, TT_SMTP_DENY_NETWORKS)
// and the internal ranges of the tenants:
//
//   - a bare address is a single host (/32 or /128);
//   - IPv6 zones are refused ([ErrPrefixZone]);
//   - a prefix with host bits set (e.g. 10.0.0.1/8) is refused
//     ([ErrPrefixHostBits]): it usually reveals a typo whose silent
//     correction would widen the range;
//   - an IPv4-mapped address or prefix (e.g. ::ffff:10.0.0.0/104) becomes
//     its IPv4 equivalent (10.0.0.0/8), since client addresses are unmapped
//     before matching. A mapped prefix shorter than /96 has no IPv4
//     equivalent; it fails the host bits check.
//
// Any other malformed value is [ErrPrefixSyntax]. The item is not trimmed.
func ParsePrefix(item string) (netip.Prefix, error) {
	if !strings.Contains(item, "/") {
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return netip.Prefix{}, ErrPrefixSyntax
		}
		if addr.Zone() != "" {
			return netip.Prefix{}, ErrPrefixZone
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	p, err := netip.ParsePrefix(item)
	if err != nil {
		return netip.Prefix{}, ErrPrefixSyntax
	}
	if p != p.Masked() {
		return netip.Prefix{}, ErrPrefixHostBits
	}
	// A masked prefix shorter than /96 cannot keep the ::ffff: marker, so a
	// mapped prefix reaching this point always has at least 96 bits.
	if p.Addr().Is4In6() {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-ipv4MappedBits), nil
	}
	return p, nil
}

// Contains reports whether addr belongs to one of prefixes. An invalid
// address never matches; an IPv4-mapped address is compared as IPv4 and a
// zone is ignored.
func Contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap().WithZone("")
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

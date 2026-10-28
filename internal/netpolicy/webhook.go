package netpolicy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// webhookAlways is the static core of the webhook egress policy (threat
// model T-181, decision P30): networks that no setting can open, because
// a receiver never lives there and reaching them would only serve a
// server-side request forgery. The networks of the container itself
// ([WebhookInterfaceNetworks]) complete it at run time.
var webhookAlways = []string{
	// Unspecified and "this network".
	"0.0.0.0/8", "::/128",
	// Link-local, including the cloud metadata addresses 169.254.169.254
	// and fd00:ec2::254.
	"169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128",
	// IPv4-compatible IPv6 (deprecated), which also holds the IPv6
	// loopback address ::1.
	"::/96",
	// Multicast.
	"224.0.0.0/4", "ff00::/8",
	// Reserved, including the limited broadcast address.
	"240.0.0.0/4",
}

// webhookDenied is the openable part of the built-in webhook deny list
// (threat model T-181, decision P30): refused unless
// TT_WEBHOOK_ALLOW_NETWORKS opens them. IPv4-mapped IPv6 addresses
// (::ffff:0:0/96) need no entry: [Contains] unmaps them, so they are
// judged by their IPv4 address, which the guard dials.
var webhookDenied = []string{
	// IPv4 loopback: opening it is meant for the tests only (local
	// receivers). The IPv6 loopback address lies in the core (::/96).
	"127.0.0.0/8",
	// Private (RFC 1918), shared address space (CGNAT), IETF protocol
	// assignments and benchmarking.
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15",
	// Unique local and the deprecated site-local range.
	"fc00::/7", "fec0::/10",
	// The IPv6 transition prefixes embedding an IPv4 address (SIIT, NAT64,
	// 6to4, Teredo), which could reach an internal IPv4 address through a
	// gateway.
	"::ffff:0:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32",
}

// Errors of [CheckWebhookAllow]. The wrapping error names the prefixes,
// which come from the installation configuration.
var (
	// ErrAllowCore reports an allowed prefix overlapping a network that can
	// never be opened.
	ErrAllowCore = errors.New("netpolicy: this network can never be opened for webhooks")
	// ErrAllowHTTPDenied reports a plain http prefix overlapping the
	// built-in deny list without being opened by the allowed networks.
	ErrAllowHTTPDenied = errors.New("netpolicy: a plain http network inside the built-in deny list must also be allowed")
)

// interfaceAddrs lists the addresses of the local interfaces, replaced in
// tests.
var interfaceAddrs = net.InterfaceAddrs

// mustPrefixes parses a static list of prefixes.
func mustPrefixes(list []string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// WebhookAlwaysDenyNetworks returns the static core of the webhook egress
// policy, which no setting can open: unspecified, link-local (with the
// cloud metadata addresses), IPv4-compatible IPv6 (with ::1), multicast,
// reserved and broadcast ranges. The networks of the container
// ([WebhookInterfaceNetworks]) complete it at run time.
func WebhookAlwaysDenyNetworks() []netip.Prefix { return mustPrefixes(webhookAlways) }

// BuiltinWebhookDenyNetworks returns the openable part of the built-in
// webhook deny list, refused unless TT_WEBHOOK_ALLOW_NETWORKS opens them:
// IPv4 loopback (for the tests only), RFC 1918, 100.64.0.0/10, 192.0.0.0/24,
// 198.18.0.0/15, fc00::/7, fec0::/10 and the IPv4-embedding IPv6
// prefixes.
func BuiltinWebhookDenyNetworks() []netip.Prefix { return mustPrefixes(webhookDenied) }

// InterfaceNetworks returns the networks of the local interfaces (the
// container's own networks), as listed by addrs (net.InterfaceAddrs when
// nil). An address without a mask counts as a single host.
func InterfaceNetworks(addrs func() ([]net.Addr, error)) ([]netip.Prefix, error) {
	if addrs == nil {
		addrs = interfaceAddrs
	}
	list, err := addrs()
	if err != nil {
		return nil, fmt.Errorf("netpolicy: interface addresses: %w", err)
	}
	var out []netip.Prefix
	for _, a := range list {
		var (
			ip   net.IP
			ones = -1
		)
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
			ones, _ = v.Mask.Size()
		case *net.IPAddr:
			ip = v.IP
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if ones < 0 || ones > addr.BitLen() {
			ones = addr.BitLen()
		}
		out = append(out, netip.PrefixFrom(addr, ones).Masked())
	}
	return out, nil
}

// WebhookInterfaceNetworks returns the networks of the local interfaces
// ([InterfaceNetworks] over addrs) that join the core of the webhook
// egress policy: every one but the loopback networks, which stay in the
// openable deny list.
func WebhookInterfaceNetworks(addrs func() ([]net.Addr, error)) ([]netip.Prefix, error) {
	list, err := InterfaceNetworks(addrs)
	if err != nil {
		return nil, err
	}
	out := list[:0]
	for _, p := range list {
		if !p.Addr().IsLoopback() {
			out = append(out, p)
		}
	}
	return out, nil
}

// WebhookDenyNetworks returns the whole core of the webhook egress policy
// computed now: [WebhookAlwaysDenyNetworks] plus
// [WebhookInterfaceNetworks].
func WebhookDenyNetworks() ([]netip.Prefix, error) {
	own, err := WebhookInterfaceNetworks(nil)
	if err != nil {
		return nil, err
	}
	return append(WebhookAlwaysDenyNetworks(), own...), nil
}

// CheckWebhookAllow validates the networks opened by the installation
// configuration against core, the core of the egress policy (the static
// core, plus the container networks when known): an allowed prefix (allow,
// TT_WEBHOOK_ALLOW_NETWORKS) or a plain http prefix (allowHTTP,
// TT_WEBHOOK_ALLOW_HTTP_NETWORKS) overlapping core is refused
// ([ErrAllowCore]), and so is a plain http prefix overlapping the built-in
// deny list ([BuiltinWebhookDenyNetworks]) where allow does not open it
// ([ErrAllowHTTPDenied]). The error names the first offending prefix.
func CheckWebhookAllow(allow, allowHTTP, core []netip.Prefix) error {
	for _, set := range []struct {
		name string
		list []netip.Prefix
	}{{"allowed", allow}, {"plain http", allowHTTP}} {
		for _, p := range set.list {
			if c, ok := overlapping(p, core); ok {
				return fmt.Errorf("%w: %s network %s overlaps %s", ErrAllowCore, set.name, p, c)
			}
		}
	}
	deny := BuiltinWebhookDenyNetworks()
	for _, p := range allowHTTP {
		for _, d := range deny {
			if !p.Overlaps(d) {
				continue
			}
			// Of two overlapping prefixes, the longer one is their
			// intersection.
			inter := p
			if d.Bits() > p.Bits() {
				inter = d
			}
			if !covered(inter, allow) {
				return fmt.Errorf("%w: plain http network %s overlaps the denied %s", ErrAllowHTTPDenied, p, d)
			}
		}
	}
	return nil
}

// overlapping returns the first prefix of list overlapping p.
func overlapping(p netip.Prefix, list []netip.Prefix) (netip.Prefix, bool) {
	for _, c := range list {
		if p.Overlaps(c) {
			return c, true
		}
	}
	return netip.Prefix{}, false
}

// covered reports whether every address of p belongs to the union of
// list.
func covered(p netip.Prefix, list []netip.Prefix) bool {
	split := false
	for _, a := range list {
		switch {
		case a.Bits() <= p.Bits() && a.Contains(p.Addr()):
			return true
		case a.Overlaps(p):
			split = true
		}
	}
	if !split {
		return false
	}
	// Only longer prefixes of list overlap p: check both halves of p.
	lo := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	hi := netip.PrefixFrom(lastAddr(lo).Next(), p.Bits()+1)
	return covered(lo, list) && covered(hi, list)
}

// lastAddr returns the last address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

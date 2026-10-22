package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// ErrAddressDenied reports a server address inside the denied networks
// (TT_SMTP_DENY_NETWORKS), refused by [DialGuard].
var ErrAddressDenied = errors.New("netpolicy: smtp server address is in a denied network")

// errNoAddress reports a host name resolving to no address.
var errNoAddress = errors.New("netpolicy: smtp host has no address")

// Resolver resolves host names (*net.Resolver).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// defaultResolver is the system resolver.
var defaultResolver Resolver = net.DefaultResolver

// DialGuard dials the SMTP servers of the tenants (mail queue and SMTP
// test) while refusing the denied networks (TT_SMTP_DENY_NETWORKS, threat
// model P21). It resolves a host name itself, refuses the connection when
// any resolved address is denied, and connects to the checked address: the
// name is never resolved again by the dialer, so a DNS answer changed in
// between (DNS rebinding) cannot lead to a denied address. It is safe for
// concurrent use.
type DialGuard struct {
	deny     []netip.Prefix
	resolver Resolver
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewDialGuard returns a guard refusing the networks deny, resolving names
// with r (net.DefaultResolver when nil).
func NewDialGuard(deny []netip.Prefix, r Resolver) *DialGuard {
	if r == nil {
		r = defaultResolver
	}
	return &DialGuard{deny: deny, resolver: r, dial: (&net.Dialer{}).DialContext}
}

// Denied reports whether addr belongs to a denied network. IPv4-mapped
// addresses are unmapped and zones ignored first.
func (g *DialGuard) Denied(addr netip.Addr) bool {
	return Contains(g.deny, addr)
}

// DialContext connects to addr ("host:port") like net.Dialer.DialContext,
// after checking every address of host against the denied networks. A
// denied address yields an error matching [ErrAddressDenied]. It has the
// signature of the dial function of an SMTP client.
func (g *DialGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netpolicy: smtp address: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("netpolicy: smtp port: %w", err)
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else if addrs, err = g.resolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, fmt.Errorf("netpolicy: resolve smtp host: %w", err)
	}
	if len(addrs) == 0 {
		return nil, errNoAddress
	}
	for _, a := range addrs {
		if g.Denied(a) {
			return nil, fmt.Errorf("%w: %s", ErrAddressDenied, a.Unmap().WithZone(""))
		}
	}
	var last error
	for _, a := range addrs {
		conn, err := g.dial(ctx, network, netip.AddrPortFrom(a.Unmap(), uint16(port)).String())
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

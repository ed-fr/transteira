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
// (TT_SMTP_DENY_NETWORKS for the SMTP servers, the webhook egress policy
// for the webhooks), refused by [DialGuard].
var ErrAddressDenied = errors.New("netpolicy: address is in a denied network")

// ErrNoAddress reports a host name resolving to no address, returned by
// [DialGuard.DialContext].
var ErrNoAddress = errors.New("netpolicy: host has no address")

// ErrResolve reports a host name that could not be resolved, returned by
// [DialGuard.DialContext] together with the error of the resolver.
var ErrResolve = errors.New("netpolicy: cannot resolve host")

// Resolver resolves host names (*net.Resolver).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// defaultResolver is the system resolver.
var defaultResolver Resolver = net.DefaultResolver

// Policy is the set of networks a [DialGuard] refuses.
type Policy struct {
	// Deny lists the networks refused unless Allow opens them (for the
	// webhooks: the built-in deny list, [WebhookDenyNetworks]).
	Deny []netip.Prefix
	// Allow lists the networks opened inside Deny (for the webhooks:
	// TT_WEBHOOK_ALLOW_NETWORKS).
	Allow []netip.Prefix
	// Always lists the networks refused even when Allow opens them (for
	// the webhooks: TT_WEBHOOK_DENY_NETWORKS).
	Always []netip.Prefix
	// Only, when not empty, restricts the connections to these networks:
	// any other address is refused (for the plain http webhooks:
	// TT_WEBHOOK_ALLOW_HTTP_NETWORKS).
	Only []netip.Prefix
}

// Denied reports whether addr is refused by p: it belongs to Always, or to
// Deny but not to Allow, or Only is set and does not contain it.
// IPv4-mapped addresses are unmapped and zones ignored first.
func (p Policy) Denied(addr netip.Addr) bool {
	return Contains(p.Always, addr) || (Contains(p.Deny, addr) && !Contains(p.Allow, addr)) ||
		(len(p.Only) > 0 && !Contains(p.Only, addr))
}

// DialGuard dials the servers chosen by administrators (SMTP servers of the
// tenants, webhook receivers) while refusing the denied networks (threat
// model P21, P30). It resolves a host name itself, refuses the connection
// when any resolved address is denied, and connects to the checked
// address: the name is never resolved again by the dialer, so a DNS answer
// changed in between (DNS rebinding) cannot lead to a denied address. It
// is safe for concurrent use.
type DialGuard struct {
	label    string
	policy   Policy
	resolver Resolver
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewDialGuard returns the SMTP guard, refusing the networks deny
// (TT_SMTP_DENY_NETWORKS) and resolving names with r (net.DefaultResolver
// when nil).
func NewDialGuard(deny []netip.Prefix, r Resolver) *DialGuard {
	return NewDialGuardPolicy("smtp", Policy{Deny: deny}, r)
}

// NewDialGuardPolicy returns a guard refusing the networks of p, resolving
// names with r (net.DefaultResolver when nil). label names the kind of
// server in the error texts (for example "webhook"); the denial error
// always matches [ErrAddressDenied].
func NewDialGuardPolicy(label string, p Policy, r Resolver) *DialGuard {
	if r == nil {
		r = defaultResolver
	}
	return &DialGuard{label: label, policy: p, resolver: r, dial: (&net.Dialer{}).DialContext}
}

// Denied reports whether addr belongs to a denied network (see
// [Policy.Denied]). IPv4-mapped addresses are unmapped and zones ignored
// first.
func (g *DialGuard) Denied(addr netip.Addr) bool {
	return g.policy.Denied(addr)
}

// DialContext connects to addr ("host:port") like net.Dialer.DialContext,
// after checking every address of host against the denied networks. A
// denied address yields an error matching [ErrAddressDenied]. It has the
// signature of the dial function of an SMTP client and of an
// http.Transport.
func (g *DialGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netpolicy: %s address: %w", g.label, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("netpolicy: %s port: %w", g.label, err)
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else if addrs, err = g.resolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, fmt.Errorf("%w (%s): %w", ErrResolve, g.label, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w (%s)", ErrNoAddress, g.label)
	}
	for _, a := range addrs {
		if g.Denied(a) {
			return nil, fmt.Errorf("%w: %s %s", ErrAddressDenied, g.label, a.Unmap().WithZone(""))
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

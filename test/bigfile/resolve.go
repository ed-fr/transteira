package bigfile

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// ParseResolve parses a name resolution override: a comma-separated list of
// host=address entries, where address is an IP address (the port of the
// dialed address is kept) or ip:port ([ipv6]:port). Host names are
// case-insensitive. An empty string gives an empty map.
//
// It lets the client reach the stack on 127.0.0.1 while using the real host
// names for the TLS server name and the Host header, as curl --resolve
// does (*.localhost names do not resolve everywhere).
func ParseResolve(s string) (map[string]string, error) {
	m := map[string]string{}
	for entry := range strings.SplitSeq(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, addr, ok := strings.Cut(entry, "=")
		host = strings.ToLower(strings.TrimSpace(host))
		addr = strings.TrimSpace(addr)
		if !ok || host == "" || addr == "" {
			return nil, fmt.Errorf("entry %q: want host=address", entry)
		}
		ip := addr
		if h, port, err := net.SplitHostPort(addr); err == nil {
			if port == "" {
				return nil, fmt.Errorf("entry %q: empty port", entry)
			}
			ip = h
		}
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("entry %q: %q is not an IP address", entry, ip)
		}
		if _, dup := m[host]; dup {
			return nil, fmt.Errorf("entry %q: host listed twice", entry)
		}
		m[host] = addr
	}
	return m, nil
}

// Dialer dials TCP connections, replacing the host of the addresses listed
// in Resolve (see ParseResolve). Other addresses are dialed unchanged.
type Dialer struct {
	Resolve map[string]string
	Base    net.Dialer
}

// Target returns the address actually dialed for address (host:port).
func (d *Dialer) Target(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	to, ok := d.Resolve[strings.ToLower(host)]
	if !ok {
		return address
	}
	if _, _, err := net.SplitHostPort(to); err == nil {
		return to
	}
	return net.JoinHostPort(to, port)
}

// DialContext has the signature of http.Transport.DialContext.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.Base.DialContext(ctx, network, d.Target(address))
}

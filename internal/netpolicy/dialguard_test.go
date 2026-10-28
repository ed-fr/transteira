package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
)

var errBoom = errors.New("boom")

// fakeResolver answers from a map, or fails with err.
type fakeResolver struct {
	ips map[string][]netip.Addr
	err error
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.ips[host], nil
}

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, x := range s {
		out[i] = netip.MustParsePrefix(x)
	}
	return out
}

// listen returns a local TCP listener accepting and closing connections.
func listen(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want %v", what, err, target)
	}
}

func TestDialGuard(t *testing.T) {
	ctx := context.Background()
	addr := listen(t)
	port := uint16(addr.Port)
	res := &fakeResolver{ips: map[string][]netip.Addr{
		"relay.internal":     {netip.MustParseAddr("192.0.2.200"), netip.MustParseAddr("127.0.0.1")},
		"rebind.example.com": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("169.254.169.254")},
		"mapped.example.com": {netip.MustParseAddr("::ffff:169.254.169.254")},
		"empty.example.com":  nil,
	}}

	open := NewDialGuard(prefixes("169.254.0.0/16"), res)
	// 192.0.2.200 is unreachable (TEST-NET); the guard falls back to the
	// next address.
	open.dial = func(ctx context.Context, network, a string) (net.Conn, error) {
		if a == netip.AddrPortFrom(netip.MustParseAddr("192.0.2.200"), port).String() {
			return nil, errBoom
		}
		return (&net.Dialer{}).DialContext(ctx, network, a)
	}
	conn, err := open.DialContext(ctx, "tcp", net.JoinHostPort("relay.internal", strconv.Itoa(addr.Port)))
	if err != nil {
		t.Fatalf("allowed name: %v", err)
	}
	_ = conn.Close()
	conn, err = open.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		t.Fatalf("allowed literal: %v", err)
	}
	_ = conn.Close()

	// A name resolving (also) to a denied address is refused at dial time.
	_, err = open.DialContext(ctx, "tcp", "rebind.example.com:25")
	wantErr(t, "rebinding", err, ErrAddressDenied)
	_, err = open.DialContext(ctx, "tcp", "mapped.example.com:25")
	wantErr(t, "mapped", err, ErrAddressDenied)
	_, err = open.DialContext(ctx, "tcp", "169.254.169.254:25")
	wantErr(t, "literal", err, ErrAddressDenied)

	loop := NewDialGuard(prefixes("127.0.0.0/8"), res)
	_, err = loop.DialContext(ctx, "tcp", addr.String())
	wantErr(t, "loopback denied", err, ErrAddressDenied)
	if !loop.Denied(netip.MustParseAddr("::ffff:127.0.0.1")) || loop.Denied(netip.MustParseAddr("10.0.0.1")) {
		t.Error("Denied")
	}

	if _, err = open.DialContext(ctx, "tcp", "no-port"); err == nil {
		t.Error("missing port accepted")
	}
	if _, err = open.DialContext(ctx, "tcp", "relay.internal:99999"); err == nil {
		t.Error("bad port accepted")
	}
	_, err = open.DialContext(ctx, "tcp", "empty.example.com:25")
	wantErr(t, "no address", err, ErrNoAddress)
	res.err = errBoom
	_, err = open.DialContext(ctx, "tcp", "relay.internal:25")
	wantErr(t, "resolution failure", err, errBoom)
	wantErr(t, "resolution failure", err, ErrResolve)

	// Every address failing: the last error.
	open.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errBoom }
	_, err = open.DialContext(ctx, "tcp", "192.0.2.9:25")
	wantErr(t, "dial failure", err, errBoom)

	if g := NewDialGuard(nil, nil); g.resolver != defaultResolver {
		t.Error("default resolver")
	}
}

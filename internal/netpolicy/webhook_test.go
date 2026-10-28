package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func TestPolicyDenied(t *testing.T) {
	p := Policy{
		Deny:   prefixes("10.0.0.0/8"),
		Allow:  prefixes("10.1.0.0/16"),
		Always: prefixes("10.1.2.0/24"),
	}
	for addr, want := range map[string]bool{
		"10.0.0.1":         true,  // denied
		"10.1.0.1":         false, // opened by Allow
		"10.1.2.3":         true,  // Always wins over Allow
		"::ffff:10.1.2.3":  true,  // mapped: judged as IPv4
		"192.0.2.1":        false, // outside every list
		"::ffff:192.0.2.1": false,
	} {
		if got := p.Denied(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Denied(%s) = %v, want %v", addr, got, want)
		}
	}
	if p.Denied(netip.Addr{}) {
		t.Error("invalid address denied")
	}
	only := Policy{Deny: prefixes("10.0.0.0/8"), Only: prefixes("10.1.0.0/16", "192.0.2.0/24")}
	for addr, want := range map[string]bool{"192.0.2.1": false, "198.51.100.1": true, "10.1.0.1": true} {
		if got := only.Denied(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Only: Denied(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestDialGuardPolicy(t *testing.T) {
	ctx := context.Background()
	addr := listen(t)
	res := &fakeResolver{ips: map[string][]netip.Addr{"hook.example.com": {netip.MustParseAddr("127.0.0.1")}}}
	deny := BuiltinWebhookDenyNetworks()

	g := NewDialGuardPolicy("webhook", Policy{Deny: deny}, res)
	_, err := g.DialContext(ctx, "tcp", addr.String())
	wantErr(t, "loopback", err, ErrAddressDenied)
	if strings.Contains(err.Error(), "smtp") || !strings.Contains(err.Error(), "webhook") {
		t.Errorf("label: %v", err)
	}
	for _, e := range []error{
		dialErr(g, "no-port"), dialErr(g, "x:99999"),
	} {
		if e == nil || strings.Contains(e.Error(), "smtp") {
			t.Errorf("error %v", e)
		}
	}
	_, err = NewDialGuardPolicy("webhook", Policy{Deny: deny}, &fakeResolver{ips: map[string][]netip.Addr{}}).
		DialContext(ctx, "tcp", "empty.example.com:443")
	wantErr(t, "no address", err, ErrNoAddress)

	open := NewDialGuardPolicy("webhook", Policy{Deny: deny, Allow: prefixes("127.0.0.1/32")}, res)
	conn, err := open.DialContext(ctx, "tcp", net.JoinHostPort("hook.example.com", strconv.Itoa(addr.Port)))
	if err != nil {
		t.Fatalf("allowed: %v", err)
	}
	_ = conn.Close()

	closed := NewDialGuardPolicy("webhook", Policy{Deny: deny, Allow: prefixes("127.0.0.1/32"), Always: prefixes("127.0.0.0/8")}, res)
	_, err = closed.DialContext(ctx, "tcp", addr.String())
	wantErr(t, "always", err, ErrAddressDenied)

	// The SMTP guard keeps its label.
	_, err = NewDialGuard(prefixes("127.0.0.0/8"), res).DialContext(ctx, "tcp", addr.String())
	if !errors.Is(err, ErrAddressDenied) || !strings.Contains(err.Error(), "smtp") {
		t.Errorf("smtp guard: %v", err)
	}
	if NewDialGuardPolicy("webhook", Policy{}, nil).resolver != defaultResolver {
		t.Error("default resolver")
	}
}

func dialErr(g *DialGuard, addr string) error {
	_, err := g.DialContext(context.Background(), "tcp", addr)
	return err
}

func TestBuiltinWebhookDenyNetworks(t *testing.T) {
	deny := Policy{Deny: BuiltinWebhookDenyNetworks()}
	always := Policy{Always: WebhookAlwaysDenyNetworks()}
	openable := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1",
		"100.127.255.254", "192.0.0.170", "198.18.0.1", "198.19.255.254", "fc00::1", "fd12::1", "fec0::1",
		"::ffff:0:a00:1", "64:ff9b::a00:1", "64:ff9b:1::1", "2002:a00:1::1", "2001:0:a00:1::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1",
	}
	for _, a := range openable {
		addr := netip.MustParseAddr(a)
		if !deny.Denied(addr) || always.Denied(addr) {
			t.Errorf("%s: openable deny %v, core %v", a, deny.Denied(addr), always.Denied(addr))
		}
	}
	core := []string{
		"0.0.0.0", "0.1.2.3", "::", "::1", "169.254.169.254", "fe80::1", "fd00:ec2::254", "::a00:1",
		"224.0.0.1", "239.255.255.250", "ff02::1", "240.0.0.1", "255.255.255.255", "::ffff:169.254.169.254",
	}
	for _, a := range core {
		addr := netip.MustParseAddr(a)
		if !always.Denied(addr) {
			t.Errorf("%s not in the core", a)
		}
	}
	allowed := []string{
		"8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1", "192.0.2.1", "198.20.0.1",
		"2001:4860:4860::8888", "::ffff:8.8.8.8",
	}
	for _, a := range allowed {
		if addr := netip.MustParseAddr(a); deny.Denied(addr) || always.Denied(addr) {
			t.Errorf("%s denied", a)
		}
	}
}

func TestWebhookInterfaceNetworks(t *testing.T) {
	addrs := func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1").To4(), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
			&net.IPNet{IP: net.ParseIP("172.18.0.5").To4(), Mask: net.CIDRMask(16, 32)},
		}, nil
	}
	got, err := WebhookInterfaceNetworks(addrs)
	if err != nil || len(got) != 1 || got[0] != netip.MustParsePrefix("172.18.0.0/16") {
		t.Errorf("WebhookInterfaceNetworks = %v, %v", got, err)
	}
	if _, err := WebhookInterfaceNetworks(func() ([]net.Addr, error) { return nil, errBoom }); !errors.Is(err, errBoom) {
		t.Errorf("error: %v", err)
	}
}

func TestCheckWebhookAllow(t *testing.T) {
	core := append(WebhookAlwaysDenyNetworks(), prefixes("172.18.0.0/16")...)
	for _, c := range []struct {
		name             string
		allow, allowHTTP []netip.Prefix
		want             error
	}{
		{"empty", nil, nil, nil},
		{"loopback for the tests", prefixes("127.0.0.0/8"), prefixes("127.0.0.0/8"), nil},
		{"private and public http", prefixes("10.0.0.0/8"), prefixes("10.1.0.0/16", "192.0.2.0/24"), nil},
		{"http covered by two allowed halves", prefixes("10.0.0.0/9", "10.128.0.0/9"), prefixes("10.0.0.0/8"), nil},
		{"http covered by finer allowed prefixes", prefixes("10.0.0.0/9", "10.128.0.0/10", "10.192.0.0/10"), prefixes("10.0.0.0/8"), nil},
		{"http around a whole denied range", prefixes("10.0.0.0/8"), prefixes("8.0.0.0/6"), nil},
		{"metadata", prefixes("169.254.169.254/32"), nil, ErrAllowCore},
		{"everything", prefixes("0.0.0.0/0"), nil, ErrAllowCore},
		{"unique local holds the metadata address", prefixes("fc00::/7"), nil, ErrAllowCore},
		{"container network", prefixes("172.16.0.0/12"), nil, ErrAllowCore},
		{"http in the core", nil, prefixes("224.0.0.0/4"), ErrAllowCore},
		{"http not allowed", nil, prefixes("10.1.0.0/16"), ErrAllowHTTPDenied},
		{"http wider than allowed", prefixes("10.1.0.0/16"), prefixes("10.0.0.0/8"), ErrAllowHTTPDenied},
		{"http half covered", prefixes("10.0.0.0/9", "11.0.0.0/8"), prefixes("10.0.0.0/8"), ErrAllowHTTPDenied},
		{"http with a hole", prefixes("10.0.0.0/9", "10.128.0.0/10"), prefixes("10.0.0.0/8"), ErrAllowHTTPDenied},
	} {
		err := CheckWebhookAllow(c.allow, c.allowHTTP, core)
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

func TestLastAddr(t *testing.T) {
	for p, want := range map[string]string{
		"10.0.0.0/8": "10.255.255.255", "192.0.2.4/32": "192.0.2.4", "2001:db8::/112": "2001:db8::ffff",
	} {
		if got := lastAddr(netip.MustParsePrefix(p)); got != netip.MustParseAddr(want) {
			t.Errorf("lastAddr(%s) = %s", p, got)
		}
	}
}

func TestInterfaceNetworks(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("198.51.100.7/24")
	ipnet.IP = net.ParseIP("198.51.100.7").To4()
	_, v6, _ := net.ParseCIDR("2001:db8:1::5/64")
	addrs := func() ([]net.Addr, error) {
		return []net.Addr{
			ipnet, v6,
			&net.IPAddr{IP: net.ParseIP("203.0.113.9")},
			&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(24, 32)},        // 16-byte form
			&net.IPNet{IP: net.IP{1, 2}},                                                // malformed
			&net.UnixAddr{Name: "x"},                                                    // ignored type
			&net.IPNet{IP: net.ParseIP("192.0.2.1").To4(), Mask: net.CIDRMask(64, 128)}, // mask too long
		}, nil
	}
	got, err := InterfaceNetworks(addrs)
	if err != nil {
		t.Fatal(err)
	}
	want := prefixes("198.51.100.0/24", "2001:db8:1::/64", "203.0.113.9/32", "192.0.2.0/24", "192.0.2.1/32")
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
	if _, err := InterfaceNetworks(func() ([]net.Addr, error) { return nil, errBoom }); !errors.Is(err, errBoom) {
		t.Errorf("error: %v", err)
	}
}

func TestWebhookDenyNetworks(t *testing.T) {
	saved := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = saved })
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("198.51.100.7").To4(), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("127.0.0.1").To4(), Mask: net.CIDRMask(8, 32)},
		}, nil
	}
	got, err := WebhookDenyNetworks()
	if err != nil {
		t.Fatal(err)
	}
	if !Contains(got, netip.MustParseAddr("198.51.100.200")) || !Contains(got, netip.MustParseAddr("169.254.169.254")) ||
		Contains(got, netip.MustParseAddr("127.0.0.1")) {
		t.Errorf("deny list %v", got)
	}
	interfaceAddrs = func() ([]net.Addr, error) { return nil, errBoom }
	if _, err := WebhookDenyNetworks(); !errors.Is(err, errBoom) {
		t.Errorf("error: %v", err)
	}
}

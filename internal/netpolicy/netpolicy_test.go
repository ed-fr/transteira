package netpolicy

import (
	"net/netip"
	"testing"
)

func TestEvaluate(t *testing.T) {
	t.Parallel()
	rules := Rules{
		CIDRs:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")},
		Domains: []string{"Entity-A.example.com.", "bücher.example", "bad domain", "host:25"},
	}
	cases := []struct {
		name, ip, email string
		ipOK, domainOK  bool
	}{
		{"internal", "10.1.2.3", "alice@entity-a.example.com", true, true},
		{"case and trailing dot", "10.1.2.3", "Alice@ENTITY-A.example.com.", true, true},
		{"mapped ipv4", "::ffff:10.1.2.3", "alice@entity-a.example.com", true, true},
		{"ipv6 with zone", "2001:db8::1%eth0", "alice@entity-a.example.com", true, true},
		{"idn rule, punycode address", "10.0.0.1", "a@xn--bcher-kva.example", true, true},
		{"idn address", "10.0.0.1", "a@BÜCHER.example", true, true},
		{"external ip", "203.0.113.7", "alice@entity-a.example.com", false, true},
		{"other domain", "10.1.2.3", "carol@entity-b.example.com", true, false},
		{"subdomain is not the domain", "10.1.2.3", "a@sub.entity-a.example.com", true, false},
		{"no at", "10.1.2.3", "entity-a.example.com", true, false},
		{"malformed domain", "10.1.2.3", "a@entity-a.example.com:25", true, false},
		{"empty domain", "10.1.2.3", "a@", true, false},
		{"malformed rule never matches", "10.1.2.3", "a@host", true, false},
	}
	for _, c := range cases {
		var ip netip.Addr
		if c.ip != "" {
			ip = netip.MustParseAddr(c.ip)
		}
		v := Evaluate(rules, ip, c.email)
		if v.IPOK != c.ipOK || v.DomainOK != c.domainOK || v.Internal() != (c.ipOK && c.domainOK) {
			t.Errorf("%s: got %+v internal=%v, want ip %v domain %v", c.name, v, v.Internal(), c.ipOK, c.domainOK)
		}
	}
	if v := Evaluate(rules, netip.Addr{}, "alice@entity-a.example.com"); v.IPOK || v.Internal() {
		t.Errorf("invalid ip: %+v", v)
	}
	if v := Evaluate(Rules{}, netip.MustParseAddr("10.1.2.3"), "alice@entity-a.example.com"); v.IPOK || v.DomainOK {
		t.Errorf("empty rules: %+v", v)
	}
}

func FuzzEvaluate(f *testing.F) {
	f.Add("10.1.2.3", "alice@entity-a.example.com")
	f.Add("::ffff:10.0.0.1", "a@@b")
	f.Fuzz(func(t *testing.T, ipText, email string) {
		rules := Rules{CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Domains: []string{"entity-a.example.com"}}
		ip, _ := netip.ParseAddr(ipText)
		v := Evaluate(rules, ip, email)
		if v.IPOK && !ip.IsValid() {
			t.Fatal("an invalid ip matched")
		}
	})
}

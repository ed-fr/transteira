package securitylog

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzLogLine checks that any event renders as exactly one valid UTF-8 line
// that the strict parser reads back, with the ip= token equal to the event
// IP, the values round-tripping, and the ban filters never extracting an
// address other than the event IP.
func FuzzLogLine(f *testing.F) {
	f.Add([]byte{203, 0, 113, 7}, "", tenantA, "evil.example.net", "alice@example.com")
	f.Add([]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}, "eth0", "", "x\n2026-10-20T07:41:00.000Z ip=192.0.2.66", "\" ip=192.0.2.66")
	f.Add([]byte{}, "", "Bad Tenant", nonPrintable, strings.Repeat(eAcute, 200))
	for _, v := range forgedValues {
		f.Add([]byte{198, 51, 100, 9}, " ip=192.0.2.66", tenantA, v, v)
	}
	sim := loadFail2ban(f)
	f.Fuzz(func(t *testing.T, ipb []byte, zone, tenant, host, email string) {
		ip, _ := netip.AddrFromSlice(ipb)
		if ip.Is6() {
			ip = ip.WithZone(zone)
		}
		ev := Event{Type: UnknownFQDN, IP: ip, Tenant: tenant, Fields: []Field{{KeyHost, host}, {"email", email}}}
		var buf bytes.Buffer
		if err := New(&buf, WithClock(fixedClock)).Log(ev); err != nil {
			t.Fatal(err)
		}
		line := buf.String()
		if !utf8.ValidString(line) {
			t.Fatalf("invalid UTF-8: %q", line)
		}
		p, err := parseLine(line)
		if err != nil {
			t.Fatalf("unparseable line %q: %v", line, err)
		}
		wantIP := FormatIP(ip)
		if p.ip != wantIP || p.event != string(UnknownFQDN) || p.tenant != formatTenant(tenant) {
			t.Fatalf("parsed %+v from %q", p, line)
		}
		if len(p.fields) != 2 || p.fields[0].Value != truncate(host, MaxValueLen) || p.fields[1].Value != truncate(email, MaxValueLen) {
			t.Fatalf("values do not round-trip: %q", line)
		}
		banned := sim.match(line)
		if (ip.IsValid() && banned != wantIP) || (!ip.IsValid() && banned != "") {
			t.Fatalf("fail2ban banned %q for ip %q: %q", banned, wantIP, line)
		}
	})
}

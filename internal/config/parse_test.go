package config

import (
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParsePrefixes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw     string
		want    []string
		wantErr bool
	}{
		{raw: "", want: nil},
		{raw: " , ,", want: nil},
		{raw: "192.0.2.1", want: []string{"192.0.2.1/32"}},
		{raw: "2001:db8::1", want: []string{"2001:db8::1/128"}},
		{raw: "::ffff:192.0.2.1", want: []string{"192.0.2.1/32"}},
		{raw: "10.0.0.0/8, 0.0.0.0/0", want: []string{"10.0.0.0/8", "0.0.0.0/0"}},
		{raw: "::ffff:10.0.0.0/104", want: []string{"10.0.0.0/8"}},
		{raw: "::ffff:192.0.2.1/128", want: []string{"192.0.2.1/32"}},
		{raw: "::ffff:0:0/96", want: []string{"0.0.0.0/0"}},
		{raw: "::ffff:0:0/95", wantErr: true},
		{raw: "::ffff:10.0.0.1/104", wantErr: true},
		{raw: "10.0.0.1/8", wantErr: true},
		{raw: "10.0.0.0/", wantErr: true},
		{raw: "fe80::1%eth0", wantErr: true},
		{raw: "example.com", wantErr: true},
		{raw: "1.2.3.4.5", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parsePrefixes(tc.raw)
		if (err != nil) != tc.wantErr {
			t.Errorf("parsePrefixes(%q) error = %v, wantErr %v", tc.raw, err, tc.wantErr)
			continue
		}
		var gotStr []string
		for _, p := range got {
			gotStr = append(gotStr, p.String())
		}
		if !slices.Equal(gotStr, tc.want) {
			t.Errorf("parsePrefixes(%q) = %v, want %v", tc.raw, gotStr, tc.want)
		}
	}
}

func TestParsePrefixErrors(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"10.0.0.1/8":   `"10.0.0.1/8" has host bits set (did you mean 10.0.0.0/8?)`,
		"fe80::1%eth0": `"fe80::1%eth0": IPv6 zones are not allowed`,
		"example.com":  `"example.com": not a valid IP address or CIDR prefix`,
	} {
		if _, err := parsePrefixes(raw); err == nil || err.Error() != want {
			t.Errorf("parsePrefixes(%q) error = %v, want %s", raw, err, want)
		}
	}
}

func TestParseBool(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"true", "TRUE", " True ", "1"} {
		if b, err := parseBool(raw); err != nil || !b {
			t.Errorf("parseBool(%q) = %v, %v", raw, b, err)
		}
	}
	for _, raw := range []string{"false", "FALSE", "0"} {
		if b, err := parseBool(raw); err != nil || b {
			t.Errorf("parseBool(%q) = %v, %v", raw, b, err)
		}
	}
	for _, raw := range []string{"", "yes", "no", "on", "2", "t"} {
		if _, err := parseBool(raw); err == nil {
			t.Errorf("parseBool(%q) accepted", raw)
		}
	}
}

func TestParseDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"1h", time.Hour, false},
		{" 90m ", 90 * time.Minute, false},
		{"2h", 2 * time.Hour, false},
		{"59m59s", 0, true},
		{"2h0m1s", 0, true},
		{"1d", 0, true},
		{"", 0, true},
	}
	for _, tc := range tests {
		got, err := parseDuration(tc.raw, time.Hour, 2*time.Hour)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("parseDuration(%q) = %v, %v; want %v, err %v", tc.raw, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestValidHostname(t *testing.T) {
	t.Parallel()
	valid := []string{"localhost", "a.example.com", "transfer.entity-a.localhost", "x1", strings.Repeat("a", 63) + ".com"}
	invalid := []string{
		"", "a..b", ".a", "a.", "-a.com", "a-.com", "A.com", "a_b.com", "a b", "192.0.2.1", "::1",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "aa",
	}
	for _, h := range valid {
		if !validHostname(h) {
			t.Errorf("validHostname(%q) = false", h)
		}
	}
	for _, h := range invalid {
		if validHostname(h) {
			t.Errorf("validHostname(%q) = true", h)
		}
	}
}

func TestParseHosts(t *testing.T) {
	t.Parallel()
	got, err := parseHosts(" B.example.com , a.example.com., b.example.com ")
	if err != nil || !slices.Equal(got, []string{"b.example.com", "a.example.com"}) {
		t.Errorf("parseHosts() = %v, %v", got, err)
	}
	if _, err := parseHosts("ok.example.com, bad host"); err == nil {
		t.Error("parseHosts accepted an invalid host")
	}
}

func TestValidateHostPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw          string
		hostRequired bool
		ok           bool
	}{
		{":8080", false, true},
		{":8080", true, false},
		{"0.0.0.0:80", true, true},
		{"[2001:db8::1]:443", true, true},
		{"clamav:3310", true, true},
		{"clamav:0", true, false},
		{"clamav:65535", true, true},
		{"clamav:-1", true, false},
		{"clamav", true, false},
		{"bad!host:80", true, false},
	}
	for _, tc := range tests {
		if err := validateHostPort(tc.raw, tc.hostRequired); (err == nil) != tc.ok {
			t.Errorf("validateHostPort(%q, %v) = %v, want ok=%v", tc.raw, tc.hostRequired, err, tc.ok)
		}
	}
}

func TestPathHelpers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		child, dir string
		within     bool
	}{
		{"/data", "/data", true},
		{"/data/", "/data", true},
		{"/data/a/b", "/data", true},
		{"/data/a/../b", "/data/", true},
		{"/data2/key", "/data", false},
		{"/dat", "/data", false},
		{"/data/../key", "/data", false},
		{"/anything", "/", true},
	}
	for _, tc := range tests {
		if got := pathWithin(tc.child, tc.dir); got != tc.within {
			t.Errorf("pathWithin(%q, %q) = %v, want %v", tc.child, tc.dir, got, tc.within)
		}
	}
	if !samePath("/a/b/", "/a/./b") || samePath("/a/b", "/a/c") {
		t.Error("samePath gives unexpected results")
	}
	if !isAbsPath("/var/lib") || isAbsPath("var/lib") || isAbsPath("") {
		t.Error("isAbsPath gives unexpected results")
	}
}

// TestPathCaseSensitivity toggles the package-level case flag, so it must not
// run in parallel with other tests.
func TestPathCaseSensitivity(t *testing.T) {
	saved := caseInsensitivePaths
	t.Cleanup(func() { caseInsensitivePaths = saved })

	caseInsensitivePaths = true
	if !pathWithin("/DATA/Key", "/data") || !samePath("/Run/Key", "/run/key") {
		t.Error("case-insensitive comparison failed")
	}
	caseInsensitivePaths = false
	if pathWithin("/DATA/Key", "/data") || samePath("/Run/Key", "/run/key") {
		t.Error("case-sensitive comparison failed")
	}
}

func TestSQLiteDir(t *testing.T) {
	t.Parallel()
	tests := []struct {
		dsn, dir string
		ok       bool
	}{
		{"/var/lib/transteira/db/transteira.db", "/var/lib/transteira/db", true},
		{"file:/srv/db/tt.db?_pragma=journal_mode(WAL)", "/srv/db", true},
		{"file:///srv/db/tt.db", "/srv/db", true},
		{":memory:", "", false},
		{"file::memory:?cache=shared", "", false},
		{"file:", "", false},
		{"relative.db", "", false},
		{"/a/\x00/b.db", "", false},
	}
	for _, tc := range tests {
		dir, ok := sqliteDir(tc.dsn)
		want := tc.dir
		if tc.ok {
			want = filepath.Clean(tc.dir)
		}
		if ok != tc.ok || dir != want {
			t.Errorf("sqliteDir(%q) = %q, %v; want %q, %v", tc.dsn, dir, ok, want, tc.ok)
		}
	}
}

func FuzzParsePrefixes(f *testing.F) {
	for _, seed := range []string{
		"", "10.0.0.0/8", "192.0.2.1, 2001:db8::/32", "0.0.0.0/0", "::/0", "fe80::1%eth0", "::ffff:10.0.0.0/104", "::ffff:0:0/95",
		"10.0.0.1/8", "::ffff:1.2.3.4", ",,,", "1.2.3.4/33",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		prefixes, err := parsePrefixes(raw)
		if err != nil {
			if prefixes != nil {
				t.Fatalf("non-nil result with error for %q", raw)
			}
			return
		}
		for _, p := range prefixes {
			if !p.IsValid() || p != p.Masked() || p.Addr().Zone() != "" || p.Addr().Is4In6() {
				t.Fatalf("invalid prefix %v from %q", p, raw)
			}
			// Round trip: a parsed prefix must parse back to itself.
			again, err := parsePrefix(p.String())
			if err != nil || again != p {
				t.Fatalf("round trip of %v failed: %v, %v", p, again, err)
			}
			if !p.Contains(p.Addr()) {
				t.Fatalf("%v does not contain its own address", p)
			}
		}
		_ = (&Config{TrustedProxies: prefixes}).IsTrustedProxy(netip.IPv4Unspecified())
	})
}

func FuzzParseBool(f *testing.F) {
	for _, seed := range []string{"true", "FALSE", "1", "0", "yes", "", " tRuE "} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		b, err := parseBool(raw)
		norm := strings.ToLower(strings.TrimSpace(raw))
		switch norm {
		case "true", "1":
			if err != nil || !b {
				t.Fatalf("parseBool(%q) = %v, %v", raw, b, err)
			}
		case "false", "0":
			if err != nil || b {
				t.Fatalf("parseBool(%q) = %v, %v", raw, b, err)
			}
		default:
			if err == nil {
				t.Fatalf("parseBool(%q) accepted", raw)
			}
		}
	})
}

func FuzzParseDuration(f *testing.F) {
	for _, seed := range []string{"15m", "24h", "-1s", "168h", "1d", "", "9223372036854775807ns", "1h1m1.5s"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		d, err := parseDuration(raw, minDepositSessionTTL, maxDepositSessionTTL)
		if err != nil {
			if d != 0 {
				t.Fatalf("non-zero duration %v with error for %q", d, raw)
			}
			return
		}
		if d < minDepositSessionTTL || d > maxDepositSessionTTL {
			t.Fatalf("parseDuration(%q) = %v out of bounds", raw, d)
		}
	})
}

func FuzzParseHosts(f *testing.F) {
	for _, seed := range []string{"admin.example.com", "A.example.com., b.example.com", "-x", "1.2.3.4", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		hosts, err := parseHosts(raw)
		if err != nil {
			return
		}
		for _, h := range hosts {
			if !validHostname(h) || h != strings.ToLower(h) {
				t.Fatalf("invalid host %q from %q", h, raw)
			}
		}
	})
}

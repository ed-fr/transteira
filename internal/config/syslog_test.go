package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// testSyslogAddr is the fictitious syslog server of the tests.
const testSyslogAddr = "siem.example.com:6514"

// writeTestCA writes a self-signed PEM certificate into dir and returns its
// path.
func writeTestCA(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Example test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSyslogDisabledByDefault(t *testing.T) {
	t.Parallel()
	c := mustLoad(t, nil)
	if c.Syslog.Enabled() || c.Syslog.Addr != "" || c.Syslog.Streams != nil || c.Syslog.HasStream(SyslogStreamAudit) {
		t.Errorf("Syslog = %+v, want disabled and empty", c.Syslog)
	}
	// The variables with a default may keep it without an address.
	c = mustLoad(t, map[string]string{EnvSyslogProtocol: "TLS", EnvSyslogStreams: DefaultSyslogStreams, EnvSyslogFacility: " local0"})
	if c.Syslog.Enabled() {
		t.Errorf("Syslog = %+v, want disabled", c.Syslog)
	}
}

func TestSyslogValid(t *testing.T) {
	t.Parallel()
	ca := writeTestCA(t, t.TempDir())
	tests := []struct {
		name string
		vars map[string]string
		want SyslogConfig
	}{
		{
			"defaults",
			map[string]string{EnvSyslogAddr: testSyslogAddr},
			SyslogConfig{Addr: testSyslogAddr, Protocol: SyslogProtocolTLS, Streams: []string{"audit", "security"}, Facility: 16},
		},
		{
			"udp security only",
			map[string]string{
				EnvSyslogAddr: "192.0.2.10:514", EnvSyslogProtocol: "UDP", EnvSyslogStreams: " Security ",
				EnvSyslogFacility: "AuthPriv",
			},
			SyslogConfig{Addr: "192.0.2.10:514", Protocol: SyslogProtocolUDP, Streams: []string{"security"}, Facility: 10},
		},
		{
			"tcp with duplicates",
			map[string]string{
				EnvSyslogAddr: "[2001:db8::514]:601", EnvSyslogProtocol: "tcp",
				EnvSyslogStreams: "security,audit,security,", EnvSyslogFacility: "kern",
			},
			SyslogConfig{Addr: "[2001:db8::514]:601", Protocol: SyslogProtocolTCP, Streams: []string{"audit", "security"}, Facility: 0},
		},
		{
			"tls with a CA file",
			map[string]string{EnvSyslogAddr: testSyslogAddr, EnvSyslogCAFile: ca, EnvSyslogFacility: "local7"},
			SyslogConfig{Addr: testSyslogAddr, Protocol: SyslogProtocolTLS, Streams: []string{"audit", "security"}, Facility: 23, CAFile: filepath.Clean(ca)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mustLoad(t, tt.vars).Syslog
			if !got.Enabled() || got.Addr != tt.want.Addr || got.Protocol != tt.want.Protocol ||
				!slices.Equal(got.Streams, tt.want.Streams) || got.Facility != tt.want.Facility || got.CAFile != tt.want.CAFile {
				t.Errorf("Syslog = %+v, want %+v", got, tt.want)
			}
			for _, s := range tt.want.Streams {
				if !got.HasStream(s) {
					t.Errorf("HasStream(%q) = false", s)
				}
			}
		})
	}
}

func TestSyslogFacilities(t *testing.T) {
	t.Parallel()
	want := map[string]int{"user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7, "uucp": 8, "cron": 9, "ftp": 11}
	for i := range 8 {
		want[fmt.Sprintf("local%d", i)] = 16 + i
	}
	for name, code := range want {
		if got := mustLoad(t, map[string]string{EnvSyslogAddr: testSyslogAddr, EnvSyslogFacility: name}).Syslog.Facility; got != code {
			t.Errorf("facility %s = %d, want %d", name, got, code)
		}
	}
}

func TestSyslogInvalid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ca := writeTestCA(t, dir)
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := func(extra map[string]string) map[string]string {
		m := map[string]string{EnvSyslogAddr: testSyslogAddr}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name string
		vars map[string]string
		want string // variable reported
		text string // part of the reason
	}{
		{"protocol without addr", map[string]string{EnvSyslogProtocol: "udp"}, EnvSyslogProtocol, EnvSyslogAddr},
		{"streams without addr", map[string]string{EnvSyslogStreams: "audit"}, EnvSyslogStreams, EnvSyslogAddr},
		{"facility without addr", map[string]string{EnvSyslogFacility: "local1"}, EnvSyslogFacility, EnvSyslogAddr},
		{"CA file without addr", map[string]string{EnvSyslogCAFile: ca}, EnvSyslogCAFile, EnvSyslogAddr},
		{"addr without port", base(map[string]string{EnvSyslogAddr: "siem.example.com"}), EnvSyslogAddr, "host:port"},
		{"addr without host", base(map[string]string{EnvSyslogAddr: ":514"}), EnvSyslogAddr, "no host"},
		{"addr bad port", base(map[string]string{EnvSyslogAddr: "siem.example.com:0"}), EnvSyslogAddr, "between 1 and 65535"},
		{"bad protocol", base(map[string]string{EnvSyslogProtocol: "relp"}), EnvSyslogProtocol, "not supported"},
		{"unknown stream", base(map[string]string{EnvSyslogStreams: "audit,access"}), EnvSyslogStreams, "\"access\""},
		{"empty streams", base(map[string]string{EnvSyslogStreams: " , ,"}), EnvSyslogStreams, "must list"},
		{"unknown facility", base(map[string]string{EnvSyslogFacility: "local8"}), EnvSyslogFacility, "not a syslog facility"},
		{"numeric facility", base(map[string]string{EnvSyslogFacility: "16"}), EnvSyslogFacility, "not a syslog facility"},
		{"CA file with udp", base(map[string]string{EnvSyslogProtocol: "udp", EnvSyslogCAFile: ca}), EnvSyslogCAFile, "only allowed"},
		{"CA file with tcp", base(map[string]string{EnvSyslogProtocol: "tcp", EnvSyslogCAFile: ca}), EnvSyslogCAFile, "only allowed"},
		{"relative CA file", base(map[string]string{EnvSyslogCAFile: "certs/ca.pem"}), EnvSyslogCAFile, "absolute"},
		{"missing CA file", base(map[string]string{EnvSyslogCAFile: filepath.Join(dir, "missing.pem")}), EnvSyslogCAFile, "cannot read"},
		{"CA file without certificate", base(map[string]string{EnvSyslogCAFile: notPEM}), EnvSyslogCAFile, "no PEM certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			verr := mustFail(t, tt.vars)
			found := false
			for _, p := range verr.Problems {
				if p.Variable == tt.want && strings.Contains(p.Reason, tt.text) {
					found = true
				}
			}
			if !found {
				t.Errorf("problems = %v, want one on %s mentioning %q", verr.Problems, tt.want, tt.text)
			}
		})
	}
}

func TestWebhookNetworks(t *testing.T) {
	t.Parallel()
	c := mustLoad(t, nil)
	if c.WebhookAllowNetworks != nil || c.WebhookAllowHTTPNetworks != nil || c.WebhookDenyNetworks != nil {
		t.Errorf("webhook networks = %v %v %v, want empty", c.WebhookAllowNetworks, c.WebhookAllowHTTPNetworks, c.WebhookDenyNetworks)
	}
	c = mustLoad(t, map[string]string{
		EnvWebhookAllowNetworks:     "10.20.0.0/16, 192.0.2.7",
		EnvWebhookAllowHTTPNetworks: "10.20.30.0/24",
		EnvWebhookDenyNetworks:      "::ffff:198.51.100.0/120,2001:db8::/32",
	})
	for _, tc := range []struct{ name, got, want string }{
		{EnvWebhookAllowNetworks, fmt.Sprint(c.WebhookAllowNetworks), "[10.20.0.0/16 192.0.2.7/32]"},
		{EnvWebhookAllowHTTPNetworks, fmt.Sprint(c.WebhookAllowHTTPNetworks), "[10.20.30.0/24]"},
		{EnvWebhookDenyNetworks, fmt.Sprint(c.WebhookDenyNetworks), "[198.51.100.0/24 2001:db8::/32]"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, tc.got, tc.want)
		}
	}
	for _, name := range []string{EnvWebhookAllowNetworks, EnvWebhookAllowHTTPNetworks, EnvWebhookDenyNetworks} {
		for _, bad := range []string{"10.0.0.0/8,nowhere", "10.1.2.3/8"} {
			if verr := mustFail(t, map[string]string{name: bad}); !verr.Has(name) {
				t.Errorf("%s=%q: problems = %v", name, bad, verr.Problems)
			}
		}
	}
}

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fictitious system SMTP settings of the tests.
const (
	testSMTPHost = "smtp.example.com"
	testSMTPFrom = "transteira@example.com"
)

func TestSystemSMTPDisabledByDefault(t *testing.T) {
	t.Parallel()
	c := mustLoad(t, nil)
	if c.SystemSMTP.Enabled() || c.SystemSMTP != (SystemSMTP{}) {
		t.Errorf("SystemSMTP = %+v, want disabled and empty", c.SystemSMTP)
	}
	// The variables with a default may keep it without a host.
	c = mustLoad(t, map[string]string{EnvSystemSMTPSecurity: "tls", EnvSystemSMTPFromName: "Ops"})
	if c.SystemSMTP.Enabled() {
		t.Errorf("SystemSMTP = %+v, want disabled", c.SystemSMTP)
	}
}

func TestSystemSMTPValid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pw := filepath.Join(dir, "smtp_password")
	if err := os.WriteFile(pw, []byte(" s3cret pass \r\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		vars map[string]string
		want SystemSMTP
	}{
		{
			"defaults",
			map[string]string{EnvSystemSMTPHost: "SMTP.Example.com.", EnvSystemSMTPFrom: testSMTPFrom},
			SystemSMTP{Host: testSMTPHost, Port: 587, Security: SMTPSecurityStartTLS, From: testSMTPFrom, FromName: "TransTeira"},
		},
		{
			"relay without encryption",
			map[string]string{
				EnvSystemSMTPHost: "127.0.0.1", EnvSystemSMTPSecurity: "NONE", EnvSystemSMTPFrom: testSMTPFrom,
				EnvSystemSMTPFromName: "Équipe TransTeira",
			},
			SystemSMTP{Host: "127.0.0.1", Port: 25, Security: SMTPSecurityNone, From: testSMTPFrom, FromName: "Équipe TransTeira"},
		},
		{
			"implicit tls on an IPv6 relay",
			map[string]string{
				EnvSystemSMTPHost: "2001:db8::25", EnvSystemSMTPSecurity: "tls", EnvSystemSMTPFrom: testSMTPFrom,
			},
			SystemSMTP{Host: "2001:db8::25", Port: 465, Security: SMTPSecurityTLS, From: testSMTPFrom, FromName: "TransTeira"},
		},
		{
			"authenticated with explicit port",
			map[string]string{
				EnvSystemSMTPHost: testSMTPHost, EnvSystemSMTPPort: "2525", EnvSystemSMTPFrom: testSMTPFrom,
				EnvSystemSMTPUsername: "transteira", EnvSystemSMTPPasswordFile: pw,
			},
			SystemSMTP{
				Host: testSMTPHost, Port: 2525, Security: SMTPSecurityStartTLS, From: testSMTPFrom, FromName: "TransTeira",
				Username: "transteira", Password: NewSecret(" s3cret pass "),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mustLoad(t, tt.vars).SystemSMTP
			if got != tt.want || !got.Enabled() {
				t.Errorf("SystemSMTP = %+v, want %+v", got, tt.want)
			}
			if got.Password.Reveal() != tt.want.Password.Reveal() {
				t.Errorf("password = %q, want %q", got.Password.Reveal(), tt.want.Password.Reveal())
			}
		})
	}
}

func TestSystemSMTPInvalid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("pw", "s3cret\n")
	empty := write("empty", "\r\n")
	long := write("long", strings.Repeat("x", maxSMTPPasswordLen+1))
	base := func(extra map[string]string) map[string]string {
		m := map[string]string{EnvSystemSMTPHost: testSMTPHost, EnvSystemSMTPFrom: testSMTPFrom}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	auth := func(extra map[string]string) map[string]string {
		m := base(map[string]string{EnvSystemSMTPUsername: "transteira", EnvSystemSMTPPasswordFile: good})
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	dataDir := filepath.Join(dir, "data")
	tests := []struct {
		name string
		vars map[string]string
		want string // variable reported
		text string // part of the reason
	}{
		{"plain password", base(map[string]string{EnvSystemSMTPPassword: "s3cret"}), EnvSystemSMTPPassword, EnvSystemSMTPPasswordFile},
		{"plain password without host", map[string]string{EnvSystemSMTPPassword: "s3cret"}, EnvSystemSMTPPassword, "not supported"},
		{"port without host", map[string]string{EnvSystemSMTPPort: "25"}, EnvSystemSMTPPort, EnvSystemSMTPHost},
		{"from without host", map[string]string{EnvSystemSMTPFrom: testSMTPFrom}, EnvSystemSMTPFrom, EnvSystemSMTPHost},
		{"username without host", map[string]string{EnvSystemSMTPUsername: "u"}, EnvSystemSMTPUsername, EnvSystemSMTPHost},
		{"password file without host", map[string]string{EnvSystemSMTPPasswordFile: good}, EnvSystemSMTPPasswordFile, EnvSystemSMTPHost},
		{"bad host", base(map[string]string{EnvSystemSMTPHost: "smtp_.example.com:25"}), EnvSystemSMTPHost, "not a valid host"},
		{"zoned host", base(map[string]string{EnvSystemSMTPHost: "fe80::1%eth0"}), EnvSystemSMTPHost, "not a valid host"},
		{"bad security", base(map[string]string{EnvSystemSMTPSecurity: "ssl"}), EnvSystemSMTPSecurity, "not supported"},
		{"port zero", base(map[string]string{EnvSystemSMTPPort: "0"}), EnvSystemSMTPPort, "between 1 and 65535"},
		{"port text", base(map[string]string{EnvSystemSMTPPort: "smtp"}), EnvSystemSMTPPort, "between 1 and 65535"},
		{"missing from", map[string]string{EnvSystemSMTPHost: testSMTPHost}, EnvSystemSMTPFrom, "is required"},
		{"from with name", base(map[string]string{EnvSystemSMTPFrom: "Ops <ops@example.com>"}), EnvSystemSMTPFrom, "bare mail address"},
		{"from not an address", base(map[string]string{EnvSystemSMTPFrom: "ops"}), EnvSystemSMTPFrom, "bare mail address"},
		{"from too long", base(map[string]string{EnvSystemSMTPFrom: strings.Repeat("a", 64) + "@" + strings.Repeat("b", 190) + ".example.com"}), EnvSystemSMTPFrom, "bare mail address"},
		{"from name too long", base(map[string]string{EnvSystemSMTPFromName: strings.Repeat("é", maxSMTPFromNameLen+1)}), EnvSystemSMTPFromName, "single line"},
		{"from name header injection", base(map[string]string{EnvSystemSMTPFromName: "Ops\r\nBcc: eve@example.com"}), EnvSystemSMTPFromName, "single line"},
		{"from name line separator", base(map[string]string{EnvSystemSMTPFromName: "Ops x"}), EnvSystemSMTPFromName, "single line"},
		{"from name invalid utf-8", base(map[string]string{EnvSystemSMTPFromName: "Ops\xff"}), EnvSystemSMTPFromName, "single line"},
		{"username control", auth(map[string]string{EnvSystemSMTPUsername: "u\tv"}), EnvSystemSMTPUsername, "single line"},
		{"username with security none", auth(map[string]string{EnvSystemSMTPSecurity: "none"}), EnvSystemSMTPUsername, "never sent unencrypted"},
		{"username without password file", base(map[string]string{EnvSystemSMTPUsername: "u"}), EnvSystemSMTPPasswordFile, "is required"},
		{"password file without username", base(map[string]string{EnvSystemSMTPPasswordFile: good}), EnvSystemSMTPPasswordFile, "requires " + EnvSystemSMTPUsername},
		{"relative password file", auth(map[string]string{EnvSystemSMTPPasswordFile: "secrets/pw"}), EnvSystemSMTPPasswordFile, "absolute"},
		{"password file in data", auth(map[string]string{EnvDataDir: dataDir, EnvSystemSMTPPasswordFile: filepath.Join(dataDir, "pw")}), EnvSystemSMTPPasswordFile, systemSMTPPasswordWhat},
		{"password file is the master key", auth(map[string]string{EnvSystemSMTPPasswordFile: testMasterKey}), EnvSystemSMTPPasswordFile, "master key"},
		{"password file is the new master key", auth(map[string]string{EnvMasterKeyNewFile: good, EnvSystemSMTPPasswordFile: good}), EnvSystemSMTPPasswordFile, "master key"},
		{"unreadable password file", auth(map[string]string{EnvSystemSMTPPasswordFile: filepath.Join(dir, "missing")}), EnvSystemSMTPPasswordFile, "cannot read"},
		{"empty password file", auth(map[string]string{EnvSystemSMTPPasswordFile: empty}), EnvSystemSMTPPasswordFile, "empty"},
		{"long password file", auth(map[string]string{EnvSystemSMTPPasswordFile: long}), EnvSystemSMTPPasswordFile, "at most"},
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
			// The password never appears in the problems.
			if strings.Contains(verr.Error(), "s3cret") {
				t.Errorf("error leaks the password: %v", verr)
			}
		})
	}
}

func TestSystemSMTPPasswordNeverPrinted(t *testing.T) {
	t.Parallel()
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := mustLoad(t, map[string]string{
		EnvSystemSMTPHost: testSMTPHost, EnvSystemSMTPFrom: testSMTPFrom,
		EnvSystemSMTPUsername: "transteira", EnvSystemSMTPPasswordFile: pw,
	})
	for _, out := range []string{fmt.Sprintf("%v", c.SystemSMTP), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c.SystemSMTP)} {
		if strings.Contains(out, "s3cret") || !strings.Contains(out, Redacted) {
			t.Errorf("printed configuration leaks the password: %s", out)
		}
	}
	// A read error is reported without the file content.
	_, err := Load(envFunc(map[string]string{
		EnvSystemSMTPHost: testSMTPHost, EnvSystemSMTPFrom: testSMTPFrom,
		EnvSystemSMTPUsername: "transteira", EnvSystemSMTPPasswordFile: pw,
	}), WithReadFile(func(string) ([]byte, error) { return nil, errors.New("permission denied") }))
	var verr *ValidationError
	if !errors.As(err, &verr) || !verr.Has(EnvSystemSMTPPasswordFile) {
		t.Errorf("Load with an unreadable file = %v", err)
	}
}

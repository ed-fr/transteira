package config

import (
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeToken is an obviously fake, low-entropy setup token of the minimum length.
var fakeToken = strings.Repeat("x", minSetupTokenLength)

// testMasterKey is a valid master key path outside the default volumes.
const testMasterKey = "/run/secrets/transteira_master_key"

// envFunc returns a getenv function backed by a map, with a valid master key
// path unless overridden.
func envFunc(vars map[string]string) func(string) string {
	m := map[string]string{EnvMasterKeyFile: testMasterKey}
	for k, v := range vars {
		m[k] = v
	}
	return func(name string) string { return m[name] }
}

// mustLoad loads the configuration and fails the test on error.
func mustLoad(t *testing.T, vars map[string]string, opts ...Option) *Config {
	t.Helper()
	c, err := Load(envFunc(vars), opts...)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	return c
}

// mustFail loads the configuration and returns the ValidationError.
func mustFail(t *testing.T, vars map[string]string, opts ...Option) *ValidationError {
	t.Helper()
	c, err := Load(envFunc(vars), opts...)
	if err == nil {
		t.Fatalf("Load() = %+v, want error", c)
	}
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("Load() error type = %T, want *ValidationError", err)
	}
	return verr
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()
	c := mustLoad(t, nil)
	checks := []struct {
		name      string
		got, want any
	}{
		{"DBDriver", c.DBDriver, DriverSQLite},
		{"DBDSN", c.DBDSN.Reveal(), DefaultSQLiteDSN},
		{"DataDir", c.DataDir, filepath.Clean(DefaultDataDir)},
		{"BackupDir", c.BackupDir, filepath.Clean(DefaultBackupDir)},
		{"LogDir", c.LogDir, filepath.Clean(DefaultLogDir)},
		{"MasterKeyFile", c.MasterKeyFile, filepath.Clean(testMasterKey)},
		{"MasterKeyNewFile", c.MasterKeyNewFile, ""},
		{"TrustedProxies", len(c.TrustedProxies), 0},
		{"ListenAddr", c.ListenAddr, DefaultListenAddr},
		{"AdminHosts", len(c.AdminHosts), 0},
		{"LogLevel", c.LogLevel, slog.LevelInfo},
		{"Maintenance", c.Maintenance, false},
		{"APIDocsPublic", c.APIDocsPublic, false},
		{"SetupToken", c.SetupToken.IsSet(), false},
		{"UploadTTL", c.UploadTTL, 24 * time.Hour},
		{"DepositSessionTTL", c.DepositSessionTTL, 4 * time.Hour},
		{"DeleteAfterDownloadGrace", c.DeleteAfterDownloadGrace, 15 * time.Minute},
		{"ClamAV", c.ClamAV, ClamAVAddr{Network: "tcp", Address: DefaultClamAVAddr}},
		{"TrustsEverything", c.TrustsEverything(), false},
	}
	for _, tc := range checks {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestLoadValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		vars  map[string]string
		check func(t *testing.T, c *Config)
	}{
		{
			name: "postgres with DSN",
			vars: map[string]string{
				EnvDBDriver: " Postgres ", EnvDBDSN: "postgres://u:p@db/tt", EnvDBMigrateDSN: "postgres://owner@db/tt",
			},
			check: func(t *testing.T, c *Config) {
				t.Helper()
				if c.DBDriver != DriverPostgres || c.DBDSN.Reveal() != "postgres://u:p@db/tt" ||
					c.DBMigrateDSN.Reveal() != "postgres://owner@db/tt" {
					t.Errorf("got driver %q dsn %q", c.DBDriver, c.DBDSN.Reveal())
				}
			},
		},
		{
			name: "postgres without migrate DSN (runtime server)",
			vars: map[string]string{EnvDBDriver: "postgres", EnvDBDSN: "postgres://app@db/tt"},
			check: func(t *testing.T, c *Config) {
				t.Helper()
				if c.DBMigrateDSN.IsSet() {
					t.Error("DBMigrateDSN unexpectedly set")
				}
			},
		},
		{
			name: "sqlite custom DSN",
			vars: map[string]string{EnvDBDSN: "/srv/tt.db"},
			check: func(t *testing.T, c *Config) {
				t.Helper()
				if c.DBDSN.Reveal() != "/srv/tt.db" {
					t.Errorf("DSN = %q", c.DBDSN.Reveal())
				}
			},
		},
		{
			name: "custom paths are cleaned",
			vars: map[string]string{
				EnvDataDir: "/data/", EnvBackupDir: "/backups/./x/..", EnvLogDir: "/logs",
				EnvMasterKeyFile: "/secrets//key", EnvMasterKeyNewFile: "/secrets/key2",
			},
			check: func(t *testing.T, c *Config) {
				t.Helper()
				want := []string{"/data", "/backups", "/logs", "/secrets/key", "/secrets/key2"}
				got := []string{c.DataDir, c.BackupDir, c.LogDir, c.MasterKeyFile, c.MasterKeyNewFile}
				for i := range want {
					if got[i] != filepath.Clean(want[i]) {
						t.Errorf("path %d = %q, want %q", i, got[i], filepath.Clean(want[i]))
					}
				}
			},
		},
		{
			name: "master key next to data dir with common prefix",
			vars: map[string]string{EnvDataDir: "/data", EnvMasterKeyFile: "/data2/key"},
			check: func(t *testing.T, c *Config) {
				t.Helper()
				if c.MasterKeyFile != filepath.Clean("/data2/key") {
					t.Errorf("MasterKeyFile = %q", c.MasterKeyFile)
				}
			},
		},
		{
			name: "network settings",
			vars: map[string]string{
				EnvTrustedProxies: "172.18.0.2, 10.0.0.0/8,,fd00::/8, ::ffff:192.0.2.1",
				EnvListenAddr:     "127.0.0.1:9000",
				EnvAdminHosts:     "Admin.Example.com., transfer.entity-a.example.com,admin.example.com",
				EnvClamAVAddr:     "unix:/run/clamav/clamd.sock",
			},
			check: func(t *testing.T, c *Config) {
				t.Helper()
				want := []netip.Prefix{
					netip.MustParsePrefix("172.18.0.2/32"), netip.MustParsePrefix("10.0.0.0/8"),
					netip.MustParsePrefix("fd00::/8"), netip.MustParsePrefix("192.0.2.1/32"),
				}
				if !slices.Equal(c.TrustedProxies, want) {
					t.Errorf("TrustedProxies = %v, want %v", c.TrustedProxies, want)
				}
				if c.ListenAddr != "127.0.0.1:9000" {
					t.Errorf("ListenAddr = %q", c.ListenAddr)
				}
				wantHosts := []string{"admin.example.com", "transfer.entity-a.example.com"}
				if !slices.Equal(c.AdminHosts, wantHosts) {
					t.Errorf("AdminHosts = %v, want %v", c.AdminHosts, wantHosts)
				}
				wantAV := ClamAVAddr{Network: "unix", Address: "/run/clamav/clamd.sock"}
				if c.ClamAV != wantAV || c.ClamAV.String() != "unix:/run/clamav/clamd.sock" {
					t.Errorf("ClamAV = %+v (%s)", c.ClamAV, c.ClamAV)
				}
			},
		},
		{
			name: "listen and clamav with names and IPv6",
			vars: map[string]string{EnvListenAddr: "[::1]:8443", EnvClamAVAddr: "Antivirus.internal:3310"},
			check: func(t *testing.T, c *Config) {
				t.Helper()
				if c.ClamAV.String() != "Antivirus.internal:3310" || c.ClamAV.Network != "tcp" {
					t.Errorf("ClamAV = %+v", c.ClamAV)
				}
			},
		},
		{
			name: "operations",
			vars: map[string]string{
				EnvLogLevel: "DEBUG", EnvMaintenance: "TRUE", EnvAPIDocsPublic: "1",
				EnvSetupToken: "  " + fakeToken + "  ",
			},
			check: func(t *testing.T, c *Config) {
				t.Helper()
				if c.LogLevel != slog.LevelDebug || !c.Maintenance || !c.APIDocsPublic {
					t.Errorf("got level %v maintenance %v docs %v", c.LogLevel, c.Maintenance, c.APIDocsPublic)
				}
				if c.SetupToken.Reveal() != fakeToken {
					t.Errorf("SetupToken not trimmed")
				}
			},
		},
		{
			name: "explicit false flags and other levels",
			vars: map[string]string{EnvLogLevel: "error", EnvMaintenance: "0", EnvAPIDocsPublic: "False"},
			check: func(t *testing.T, c *Config) {
				t.Helper()
				if c.LogLevel != slog.LevelError || c.Maintenance || c.APIDocsPublic {
					t.Errorf("unexpected %+v", c)
				}
			},
		},
		{
			name: "duration bounds inclusive",
			vars: map[string]string{
				EnvUploadTTL: "168h", EnvDepositSessionTTL: "15m", EnvDeleteAfterDownloadGrace: "0s",
			},
			check: func(t *testing.T, c *Config) {
				t.Helper()
				if c.UploadTTL != 7*24*time.Hour || c.DepositSessionTTL != 15*time.Minute ||
					c.DeleteAfterDownloadGrace != 0 {
					t.Errorf("durations = %v %v %v", c.UploadTTL, c.DepositSessionTTL, c.DeleteAfterDownloadGrace)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.check(t, mustLoad(t, tc.vars))
		})
	}
}

func TestLoadInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		vars map[string]string
		want []string
	}{
		{"unknown driver", map[string]string{EnvDBDriver: "mysql"}, []string{EnvDBDriver}},
		{"postgres without DSNs", map[string]string{EnvDBDriver: "postgres"}, []string{EnvDBDSN}},
		{
			"migrate DSN equals DSN",
			map[string]string{EnvDBDriver: "postgres", EnvDBDSN: "postgres://db/tt", EnvDBMigrateDSN: "postgres://db/tt"},
			[]string{EnvDBMigrateDSN},
		},
		{
			"migrate DSN and file",
			map[string]string{
				EnvDBDriver: "postgres", EnvDBDSN: "postgres://app@db/tt",
				EnvDBMigrateDSN: "postgres://owner@db/tt", EnvDBMigrateDSNFile: "/x",
			},
			[]string{EnvDBMigrateDSN},
		},
		{"migrate DSN with sqlite", map[string]string{EnvDBMigrateDSN: "/x.db"}, []string{EnvDBMigrateDSN}},
		{
			"migrate DSN file with sqlite",
			map[string]string{EnvDBMigrateDSNFile: "/nonexistent/m"},
			[]string{EnvDBMigrateDSNFile},
		},
		{"bad driver with migrate DSN", map[string]string{EnvDBDriver: "mysql", EnvDBMigrateDSN: "x"}, []string{EnvDBDriver}},
		{"DSN and DSN file", map[string]string{EnvDBDSN: "x", EnvDBDSNFile: "/x"}, []string{EnvDBDSN}},
		{"relative DSN file", map[string]string{EnvDBDSNFile: "secret.txt"}, []string{EnvDBDSNFile}},
		{"missing DSN file", map[string]string{EnvDBDSNFile: "/nonexistent/dsn"}, []string{EnvDBDSNFile}},
		{"missing master key", map[string]string{EnvMasterKeyFile: ""}, []string{EnvMasterKeyFile}},
		{"relative data dir", map[string]string{EnvDataDir: "data"}, []string{EnvDataDir}},
		{"NUL in path", map[string]string{EnvLogDir: "/var/\x00log"}, []string{EnvLogDir}},
		{"relative master key", map[string]string{EnvMasterKeyFile: "key"}, []string{EnvMasterKeyFile}},
		{
			"master key in data dir",
			map[string]string{EnvMasterKeyFile: DefaultDataDir + "/master.key"},
			[]string{EnvMasterKeyFile},
		},
		{
			"master key is backup dir",
			map[string]string{EnvMasterKeyFile: DefaultBackupDir + "/"},
			[]string{EnvMasterKeyFile},
		},
		{
			"master key in log dir with dot segments",
			map[string]string{EnvMasterKeyFile: "/run/../var/log/transteira/sub/key"},
			[]string{EnvMasterKeyFile},
		},
		{
			"new master key in data dir",
			map[string]string{EnvMasterKeyNewFile: DefaultDataDir + "/new.key"},
			[]string{EnvMasterKeyNewFile},
		},
		{
			"new master key equals current",
			map[string]string{EnvMasterKeyNewFile: testMasterKey + "/."},
			[]string{EnvMasterKeyNewFile},
		},
		{
			"master key in default sqlite folder",
			map[string]string{EnvMasterKeyFile: "/var/lib/transteira/db/master.key"},
			[]string{EnvMasterKeyFile},
		},
		{
			"new master key in sqlite folder (plain path)",
			map[string]string{EnvDBDSN: "/srv/db/tt.db", EnvMasterKeyNewFile: "/srv/db/new.key"},
			[]string{EnvMasterKeyNewFile},
		},
		{
			"master key in sqlite folder (file URI with query)",
			map[string]string{EnvDBDSN: "file:/srv/db/tt.db?_pragma=journal_mode(WAL)", EnvMasterKeyFile: "/srv/db/k"},
			[]string{EnvMasterKeyFile},
		},
		{"mapped proxy too short", map[string]string{EnvTrustedProxies: "::ffff:0:0/95"}, []string{EnvTrustedProxies}},
		{"bad proxy", map[string]string{EnvTrustedProxies: "10.0.0.0/8,proxy"}, []string{EnvTrustedProxies}},
		{"proxy host bits", map[string]string{EnvTrustedProxies: "10.0.0.1/8"}, []string{EnvTrustedProxies}},
		{"proxy zone", map[string]string{EnvTrustedProxies: "fe80::1%eth0"}, []string{EnvTrustedProxies}},
		{"proxy bad prefix", map[string]string{EnvTrustedProxies: "10.0.0.0/33"}, []string{EnvTrustedProxies}},
		{"listen no port", map[string]string{EnvListenAddr: "localhost"}, []string{EnvListenAddr}},
		{"listen port 0", map[string]string{EnvListenAddr: ":0"}, []string{EnvListenAddr}},
		{"listen port text", map[string]string{EnvListenAddr: ":http"}, []string{EnvListenAddr}},
		{"listen bad host", map[string]string{EnvListenAddr: "bad_host:80"}, []string{EnvListenAddr}},
		{"listen zone", map[string]string{EnvListenAddr: "[fe80::1%eth0]:80"}, []string{EnvListenAddr}},
		{"admin host invalid", map[string]string{EnvAdminHosts: "ok.example.com,-bad.example.com"}, []string{EnvAdminHosts}},
		{"admin host IP", map[string]string{EnvAdminHosts: "192.0.2.1"}, []string{EnvAdminHosts}},
		{"admin host with port", map[string]string{EnvAdminHosts: "admin.example.com:443"}, []string{EnvAdminHosts}},
		{"clamav no host", map[string]string{EnvClamAVAddr: ":3310"}, []string{EnvClamAVAddr}},
		{"clamav port too big", map[string]string{EnvClamAVAddr: "clamav:65536"}, []string{EnvClamAVAddr}},
		{"clamav relative socket", map[string]string{EnvClamAVAddr: "unix:clamd.sock"}, []string{EnvClamAVAddr}},
		{"log level", map[string]string{EnvLogLevel: "verbose"}, []string{EnvLogLevel}},
		{"maintenance", map[string]string{EnvMaintenance: "yes"}, []string{EnvMaintenance}},
		{"api docs", map[string]string{EnvAPIDocsPublic: "on"}, []string{EnvAPIDocsPublic}},
		{"setup token short", map[string]string{EnvSetupToken: "short"}, []string{EnvSetupToken}},
		{"setup token long", map[string]string{EnvSetupToken: strings.Repeat("a", 129)}, []string{EnvSetupToken}},
		{
			"setup token both",
			map[string]string{EnvSetupToken: fakeToken, EnvSetupTokenFile: "/x"},
			[]string{EnvSetupToken},
		},
		{"upload TTL too short", map[string]string{EnvUploadTTL: "59m"}, []string{EnvUploadTTL}},
		{"upload TTL too long", map[string]string{EnvUploadTTL: "169h"}, []string{EnvUploadTTL}},
		{"upload TTL days", map[string]string{EnvUploadTTL: "7d"}, []string{EnvUploadTTL}},
		{"session TTL too short", map[string]string{EnvDepositSessionTTL: "14m"}, []string{EnvDepositSessionTTL}},
		{"session TTL too long", map[string]string{EnvDepositSessionTTL: "25h"}, []string{EnvDepositSessionTTL}},
		{"grace negative", map[string]string{EnvDeleteAfterDownloadGrace: "-1s"}, []string{EnvDeleteAfterDownloadGrace}},
		{"grace too long", map[string]string{EnvDeleteAfterDownloadGrace: "24h1s"}, []string{EnvDeleteAfterDownloadGrace}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verr := mustFail(t, tc.vars)
			var got []string
			for _, p := range verr.Problems {
				got = append(got, p.Variable)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("problems on %v, want %v\n%v", got, tc.want, verr)
			}
		})
	}
}

func TestLoadReportsAllProblems(t *testing.T) {
	t.Parallel()
	verr := mustFail(t, map[string]string{
		EnvMasterKeyFile:  "",
		EnvDBDriver:       "oracle",
		EnvTrustedProxies: "nope",
		EnvLogLevel:       "loud",
		EnvMaintenance:    "maybe",
		EnvUploadTTL:      "forever",
		EnvClamAVAddr:     "clamav",
	})
	want := []string{
		EnvDBDriver, EnvMasterKeyFile, EnvTrustedProxies, EnvClamAVAddr,
		EnvLogLevel, EnvMaintenance, EnvUploadTTL,
	}
	for _, name := range want {
		if !verr.Has(name) {
			t.Errorf("missing problem for %s in:\n%v", name, verr)
		}
	}
	if verr.Has("TT_NOT_A_VARIABLE") {
		t.Error("Has() reported an unrelated variable")
	}
	if len(verr.Problems) != len(want) {
		t.Errorf("got %d problems, want %d:\n%v", len(verr.Problems), len(want), verr)
	}
	msg := verr.Error()
	if !strings.HasPrefix(msg, "invalid configuration:") || strings.Count(msg, "\n  - ") != len(want) {
		t.Errorf("unexpected message format:\n%s", msg)
	}
}

func TestSecretsNeverInErrors(t *testing.T) {
	t.Parallel()
	const dsn = "postgres://user:SuperSecretPassw0rd@db/tt"
	const token = "tok-SuperSecretPassw0rd-but-way-too-long-" +
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("SuperSecretPassw0rd-short"[:10]), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []map[string]string{
		{EnvDBDSN: dsn, EnvDBDSNFile: "/x", EnvDBDriver: "postgres", EnvDBMigrateDSN: dsn},
		{EnvDBDSN: dsn, EnvDBDriver: "postgres", EnvDBMigrateDSN: dsn},
		{EnvDBMigrateDSN: dsn},
		{EnvSetupToken: token},
		{EnvSetupToken: "SuperSecret"},
		{EnvSetupTokenFile: tokenFile},
	}
	for _, vars := range cases {
		verr := mustFail(t, vars)
		if strings.Contains(verr.Error(), "SuperSecret") {
			t.Errorf("error leaks a secret: %v", verr)
		}
	}
}

func TestSecretFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	dsnFile := write("dsn", "postgres://u:p@db/tt\n")
	migrateFile := write("migrate", "postgres://owner@db/tt\n")
	tokenFile := write("token", "  "+fakeToken+"xxxx\r\n")
	emptyFile := write("empty", " \n")
	shortFile := write("short", "abc")

	c := mustLoad(t, map[string]string{
		EnvDBDriver: "postgres", EnvDBDSNFile: dsnFile, EnvSetupTokenFile: tokenFile,
		EnvDBMigrateDSNFile: migrateFile,
	})
	if c.DBDSN.Reveal() != "postgres://u:p@db/tt" || c.DBMigrateDSN.Reveal() != "postgres://owner@db/tt" {
		t.Errorf("DSN from file = %q", c.DBDSN.Reveal())
	}
	if c.SetupToken.Reveal() != fakeToken+"xxxx" {
		t.Errorf("token from file = %q", c.SetupToken.Reveal())
	}

	tests := []struct {
		name string
		vars map[string]string
		want string
	}{
		{"empty DSN file", map[string]string{EnvDBDSNFile: emptyFile}, EnvDBDSNFile},
		{"migrate DSN file with sqlite", map[string]string{EnvDBMigrateDSNFile: migrateFile}, EnvDBMigrateDSNFile},
		{"empty token file", map[string]string{EnvSetupTokenFile: emptyFile}, EnvSetupTokenFile},
		{"short token file", map[string]string{EnvSetupTokenFile: shortFile}, EnvSetupTokenFile},
		{"missing token file", map[string]string{EnvSetupTokenFile: filepath.Join(dir, "none")}, EnvSetupTokenFile},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if verr := mustFail(t, tc.vars); !verr.Has(tc.want) || len(verr.Problems) != 1 {
				t.Errorf("want one problem on %s, got:\n%v", tc.want, verr)
			}
		})
	}
}

func TestWithReadFile(t *testing.T) {
	t.Parallel()
	var asked string
	read := func(name string) ([]byte, error) {
		asked = name
		return []byte("postgres://from-fake"), nil
	}
	c := mustLoad(t, map[string]string{
		EnvDBDriver: "postgres", EnvDBDSNFile: "/run/secrets/dsn", EnvDBMigrateDSN: "postgres://owner@db/tt",
	}, WithReadFile(read))
	if c.DBDSN.Reveal() != "postgres://from-fake" || asked != filepath.Clean("/run/secrets/dsn") {
		t.Errorf("DSN = %q, asked = %q", c.DBDSN.Reveal(), asked)
	}
	failing := WithReadFile(func(string) ([]byte, error) { return nil, os.ErrPermission })
	if verr := mustFail(t, map[string]string{EnvDBDSNFile: "/run/secrets/dsn"}, failing); !verr.Has(EnvDBDSNFile) {
		t.Errorf("want problem on %s, got %v", EnvDBDSNFile, verr)
	}
}

func TestMasterKeyWithTempDirs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	key := filepath.Join(root, "secrets", "master.key")
	mustLoad(t, map[string]string{EnvDataDir: data, EnvMasterKeyFile: key})
	verr := mustFail(t, map[string]string{EnvDataDir: data, EnvMasterKeyFile: filepath.Join(data, "t1", "k")})
	if !verr.Has(EnvMasterKeyFile) {
		t.Errorf("want problem on %s, got %v", EnvMasterKeyFile, verr)
	}
}

func TestMasterKeySQLiteFolder(t *testing.T) {
	t.Parallel()
	// The problem names the folder only, never the DSN (file name, query).
	verr := mustFail(t, map[string]string{
		EnvDBDSN: "file:/srv/db/tt.db?_pragma=busy_timeout(5000)", EnvMasterKeyFile: "/srv/db/k",
	})
	msg := verr.Error()
	if !strings.Contains(msg, EnvDBDSN) || !strings.Contains(msg, filepath.Clean("/srv/db")) ||
		strings.Contains(msg, "tt.db") || strings.Contains(msg, "busy_timeout") {
		t.Errorf("unexpected message: %s", msg)
	}
	// Not applicable to postgres, in-memory or relative SQLite databases.
	for _, vars := range []map[string]string{
		{
			EnvDBDriver: DriverPostgres, EnvDBDSN: "postgres://db/tt", EnvDBMigrateDSN: "postgres://owner@db/tt",
			EnvMasterKeyFile: "/var/lib/transteira/db/k",
		},
		{EnvDBDSN: ":memory:", EnvMasterKeyFile: "/var/lib/transteira/db/k"},
		{EnvDBDSN: "file::memory:?cache=shared", EnvMasterKeyFile: "/var/lib/transteira/db/k"},
		{EnvDBDSN: "tt.db", EnvMasterKeyFile: "/var/lib/transteira/db/k"},
	} {
		mustLoad(t, vars)
	}
}

func TestTrustedProxyHelpers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		proxies    string
		everything bool
		addr       string
		trusted    bool
	}{
		{"", false, "10.0.0.1", false},
		{"10.0.0.0/8", false, "10.1.2.3", true},
		{"10.0.0.0/8", false, "::ffff:10.1.2.3", true},
		{"10.0.0.0/8", false, "11.0.0.1", false},
		{"fe80::/10", false, "fe80::1%eth0", true},
		{"10.0.0.0/8,0.0.0.0/0", true, "203.0.113.9", true},
		{"::/0", true, "2001:db8::1", true},
		{"::ffff:10.0.0.0/104", false, "10.1.2.3", true},
		{"::ffff:10.0.0.0/104", false, "::ffff:10.1.2.3", true},
		{"::ffff:0:0/96", true, "192.0.2.1", true},
	}
	for _, tc := range tests {
		c := mustLoad(t, map[string]string{EnvTrustedProxies: tc.proxies})
		if got := c.TrustsEverything(); got != tc.everything {
			t.Errorf("%q: TrustsEverything() = %v, want %v", tc.proxies, got, tc.everything)
		}
		if got := c.IsTrustedProxy(netip.MustParseAddr(tc.addr)); got != tc.trusted {
			t.Errorf("%q: IsTrustedProxy(%s) = %v, want %v", tc.proxies, tc.addr, got, tc.trusted)
		}
	}
}

func TestFromEnvironment(t *testing.T) {
	t.Setenv(EnvMasterKeyFile, testMasterKey)
	t.Setenv(EnvLogLevel, "warn")
	c, err := FromEnvironment()
	if err != nil {
		t.Fatalf("FromEnvironment() error: %v", err)
	}
	if c.LogLevel != slog.LevelWarn {
		t.Errorf("LogLevel = %v, want warn", c.LogLevel)
	}
}

func TestClamAVAddrString(t *testing.T) {
	t.Parallel()
	if got := (ClamAVAddr{Network: "tcp", Address: "clamav:3310"}).String(); got != "clamav:3310" {
		t.Errorf("String() = %q", got)
	}
}

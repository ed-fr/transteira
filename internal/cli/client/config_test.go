package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rlo is U+202E (right-to-left override), a hidden format character.
var rlo = string(rune(0x202e))

// testToken returns a well-formed API token built from c.
func testToken(c byte) string { return "tt_" + strings.Repeat(string(c), tokenBodyLen) }

// envOf returns a Getenv reading m.
func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// writeFile writes a file with the given mode and returns its path.
func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// noDefaultDir points the default configuration directory to an empty
// temporary directory for the duration of the test.
func noDefaultDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := userConfigDir
	userConfigDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { userConfigDir = old })
	return dir
}

// setGOOS replaces the operating system seen by the permission check.
func setGOOS(t *testing.T, v string) {
	t.Helper()
	old := goos
	goos = v
	t.Cleanup(func() { goos = old })
}

func TestLoadPrecedence(t *testing.T) {
	setGOOS(t, "linux")
	dir := noDefaultDir(t)
	cfgDir := filepath.Join(dir, "transteira")
	if err := os.Mkdir(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfgDir, "a.token", testToken('a')+"\n", 0o600)
	writeFile(t, dir, "flag.token", testToken('f')+"\r\n", 0o600)
	writeFile(t, dir, "env.token", testToken('e'), 0o600)
	writeFile(t, cfgDir, "config.json", `{"default":"a","profiles":{
		"a":{"url":"https://transfer.entity-a.example.com/","tokenFile":"a.token","sender":"a@entity-a.example.com","caFile":"ca.pem"},
		"b":{"url":"https://transfer.entity-b.example.com","token":"`+testToken('b')+`","sender":"b@entity-b.example.com","caFile":"/abs/ca.pem"}}}`, 0o600)

	// Profile only (the default one), relative paths resolved.
	cfg, err := Load(LoadOptions{Getenv: envOf(nil)})
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		URL: "https://transfer.entity-a.example.com", Token: testToken('a'), Sender: "a@entity-a.example.com",
		CAFile: filepath.Join(cfgDir, "ca.pem"), Profile: "a", ConfigFile: filepath.Join(cfgDir, "config.json"),
	}
	if cfg != want {
		t.Fatalf("profile: got %#v, want %#v", cfg, want)
	}

	// Environment over the profile, TT_PROFILE selects b.
	env := map[string]string{EnvProfile: "b"}
	cfg, err = Load(LoadOptions{Getenv: envOf(env)})
	if err != nil || cfg.Token != testToken('b') || cfg.CAFile != "/abs/ca.pem" || cfg.Profile != "b" {
		t.Fatalf("profile b: %v %v", cfg, err)
	}
	env = map[string]string{
		EnvURL: "https://env.example.com", EnvTokenFile: filepath.Join(dir, "env.token"),
		EnvSender: " env@example.com ", EnvCAFile: "/env/ca.pem",
	}
	cfg, err = Load(LoadOptions{Getenv: envOf(env)})
	if err != nil || cfg.URL != "https://env.example.com" || cfg.Token != testToken('e') ||
		cfg.Sender != "env@example.com" || cfg.CAFile != "/env/ca.pem" {
		t.Fatalf("env: %v %v", cfg, err)
	}

	// Flags over the environment.
	cfg, err = Load(LoadOptions{
		URL: "https://flag.example.com:8443", TokenFile: filepath.Join(dir, "flag.token"),
		Sender: "flag@example.com", CAFile: "/flag/ca.pem", Profile: "b", Getenv: envOf(env),
	})
	if err != nil || cfg.URL != "https://flag.example.com:8443" || cfg.Token != testToken('f') ||
		cfg.Sender != "flag@example.com" || cfg.CAFile != "/flag/ca.pem" || cfg.Profile != "b" {
		t.Fatalf("flags: %v %v", cfg, err)
	}

	// TT_TOKEN from the environment.
	cfg, err = Load(LoadOptions{Getenv: envOf(map[string]string{EnvToken: " " + testToken('t') + "\n"})})
	if err != nil || cfg.Token != testToken('t') {
		t.Fatalf("TT_TOKEN: %v %v", cfg, err)
	}
}

func TestLoadDefaultsAndErrors(t *testing.T) {
	setGOOS(t, "linux")
	dir := noDefaultDir(t)

	// No default file: fine, the URL comes from the environment.
	cfg, err := Load(LoadOptions{Getenv: envOf(map[string]string{EnvURL: "https://transfer.entity-a.example.com"})})
	if err != nil || cfg.ConfigFile != "" || cfg.Token != "" {
		t.Fatalf("no file: %v %v", cfg, err)
	}
	// Nothing at all.
	if _, err := Load(LoadOptions{Getenv: envOf(nil)}); !errors.Is(err, ErrNoURL) {
		t.Fatalf("no URL: %v", err)
	}
	// os.Getenv by default (TT_URL unset in the test environment).
	t.Setenv(EnvURL, "")
	t.Setenv(EnvConfigFile, "")
	t.Setenv(EnvProfile, "")
	if _, err := Load(LoadOptions{}); !errors.Is(err, ErrNoURL) {
		t.Fatalf("os.Getenv: %v", err)
	}
	// RequireToken.
	if _, err := Load(LoadOptions{URL: "https://a.example.com", RequireToken: true, Getenv: envOf(nil)}); !errors.Is(err, ErrNoToken) {
		t.Fatalf("require token: %v", err)
	}
	// No configuration directory.
	old := userConfigDir
	userConfigDir = func() (string, error) { return "", errors.New("no home") }
	if cfg, err := Load(LoadOptions{URL: "https://a.example.com", Getenv: envOf(nil)}); err != nil || cfg.ConfigFile != "" {
		t.Fatalf("no config dir: %v %v", cfg, err)
	}
	userConfigDir = old

	good := writeFile(t, dir, "good.json", `{"profiles":{"a":{"url":"https://a.example.com"}}}`, 0o600)
	tokenOK := writeFile(t, dir, "ok.token", testToken('k'), 0o600)
	cases := []struct {
		name string
		opts LoadOptions
		want string
	}{
		{"explicit file missing (flag)", LoadOptions{ConfigFile: filepath.Join(dir, "missing.json")}, "configuration file"},
		{"explicit file missing (env)", LoadOptions{Getenv: envOf(map[string]string{EnvConfigFile: filepath.Join(dir, "missing.json")})}, "no such file"},
		{"profile without file", LoadOptions{Profile: "a"}, "no configuration file"},
		{"profile not found", LoadOptions{ConfigFile: good, Profile: "zz"}, `profile "zz" not found`},
		{"invalid URL", LoadOptions{URL: "http://a.example.com"}, "https://"},
		{"both env tokens", LoadOptions{URL: "https://a.example.com", Getenv: envOf(map[string]string{EnvToken: testToken('a'), EnvTokenFile: tokenOK})}, "keep only one"},
		{"bad env token", LoadOptions{URL: "https://a.example.com", Getenv: envOf(map[string]string{EnvToken: "tt_secretvalue"})}, "TT_TOKEN is not an API token"},
		{"sender too long", LoadOptions{URL: "https://a.example.com", Sender: strings.Repeat("a", 255)}, "longer than"},
		{"sender control", LoadOptions{URL: "https://a.example.com", Sender: "a\x1b[2J@example.com"}, "control characters"},
		{"sender tab", LoadOptions{URL: "https://a.example.com", Sender: "a\t@example.com"}, "control characters"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.opts.Getenv == nil {
				tc.opts.Getenv = envOf(nil)
			}
			_, err := Load(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "secretvalue") {
				t.Fatalf("error quotes the token: %v", err)
			}
		})
	}
}

func TestLoadProfileToken(t *testing.T) {
	setGOOS(t, "linux")
	dir := noDefaultDir(t)
	both := writeFile(t, dir, "both.json", `{"default":"a","profiles":{"a":{"url":"https://a.example.com","token":"`+testToken('a')+`","tokenFile":"x"}}}`, 0o600)
	if _, err := Load(LoadOptions{ConfigFile: both, Getenv: envOf(nil)}); err == nil || !strings.Contains(err.Error(), "both token and tokenFile") {
		t.Fatalf("both: %v", err)
	}
	bad := writeFile(t, dir, "bad.json", `{"default":"a","profiles":{"a":{"url":"https://a.example.com","token":"tt_hunter2"}}}`, 0o600)
	if _, err := Load(LoadOptions{ConfigFile: bad, Getenv: envOf(nil)}); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("bad profile token: %v", err)
	}
	// The configuration file named by the environment.
	if _, err := Load(LoadOptions{Getenv: envOf(map[string]string{EnvConfigFile: bad})}); err == nil {
		t.Fatal("env config file not read")
	}
	// An invalid file is reported with its path.
	inv := writeFile(t, dir, "inv.json", `{"profiles":[]}`, 0o600)
	if _, err := Load(LoadOptions{ConfigFile: inv, Getenv: envOf(nil)}); err == nil || !strings.Contains(err.Error(), "inv.json") {
		t.Fatalf("invalid file: %v", err)
	}
}

func TestTokenFile(t *testing.T) {
	setGOOS(t, "linux")
	dir := t.TempDir()
	secret := "tt_" + strings.Repeat("s", tokenBodyLen-1) + "!"
	cases := []struct {
		name, content string
		mode          os.FileMode
		want          string
	}{
		{"group readable", testToken('a'), 0o640, "chmod 600"},
		{"others writable", testToken('a'), 0o602, "chmod 600"},
		{"bad content", secret, 0o600, "is not an API token"},
		{"too large", strings.Repeat("x", MaxTokenFileBytes+1), 0o600, "larger than"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, dir, strings.ReplaceAll(tc.name, " ", "_"), tc.content, tc.mode)
			_, err := readTokenFile(p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "sss") {
				t.Fatalf("error quotes the token: %v", err)
			}
		})
	}
	if _, err := readTokenFile(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: %v", err)
	}
	if _, err := readTokenFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	// On Windows the permission bits are not checked.
	setGOOS(t, "windows")
	p := writeFile(t, dir, "win.token", testToken('w'), 0o644)
	if tok, err := readTokenFile(p); err != nil || tok != testToken('w') {
		t.Fatalf("windows: %q %v", tok, err)
	}
}

func TestConfigFilePermissions(t *testing.T) {
	setGOOS(t, "linux")
	dir := noDefaultDir(t)
	if err := os.Mkdir(filepath.Join(dir, "transteira"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := writeFile(t, filepath.Join(dir, "transteira"), "config.json", `{"profiles":{}}`, 0o644)
	_, err := Load(LoadOptions{URL: "https://a.example.com", Getenv: envOf(nil)})
	if err == nil || !strings.Contains(err.Error(), "chmod 600 "+p) || !strings.Contains(err.Error(), "0644") {
		t.Fatalf("got %v", err)
	}
}

// fakeFile is a readFile whose Stat or Read fail.
type fakeFile struct {
	statErr, readErr error
}

func (f fakeFile) Read([]byte) (int, error) { return 0, f.readErr }
func (fakeFile) Close() error               { return nil }
func (f fakeFile) Stat() (fs.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}
	return fakeInfo{}, nil
}

// fakeInfo describes a private regular file.
type fakeInfo struct{}

func (fakeInfo) Name() string       { return "f" }
func (fakeInfo) Size() int64        { return 0 }
func (fakeInfo) Mode() fs.FileMode  { return 0o600 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (fakeInfo) Sys() any           { return nil }

// setOpen replaces openFile with one returning f.
func setOpen(t *testing.T, f fakeFile) {
	t.Helper()
	old := openFile
	openFile = func(string) (readFile, error) { return f, nil }
	t.Cleanup(func() { openFile = old })
}

func TestReadPrivateFileFailures(t *testing.T) {
	setOpen(t, fakeFile{statErr: errors.New("stat failed")})
	if _, err := readPrivateFile("x", 10, "token file"); err == nil || !strings.Contains(err.Error(), "stat failed") {
		t.Fatalf("stat: %v", err)
	}
	setOpen(t, fakeFile{readErr: errors.New("read failed")})
	if _, err := readPrivateFile("x", 10, "token file"); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("read: %v", err)
	}
}

func TestParseConfigFile(t *testing.T) {
	ok := []string{
		`{}`,
		`{"profiles":{"a":{}}}`,
		`{"default":"a.b-c_D9","profiles":{"a.b-c_D9":{"url":"https://a.example.com","sender":"x"}}}`,
		" {\"profiles\":null} \n",
	}
	for _, s := range ok {
		if _, err := parseConfigFile([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := map[string]string{
		`{"profiles":{"a":{"password":"x"}}}`: "unknown field",
		`{"extra":1}`:                         "unknown field",
		`{}{}`:                                "data after",
		`{} x`:                                "data after",
		`[]`:                                  "invalid JSON",
		`{"profiles":{"a":{"url":42}}}`:       `member "profiles.a.url" has the wrong type`,
		`{"profiles":{"a b":{}}}`:             "invalid profile name",
		`{"profiles":{"":{}}}`:                "invalid profile name",
		`{"profiles":{"` + strings.Repeat("a", 65) + `":{}}}`: "invalid profile name",
		`{"default":"zz","profiles":{"a":{}}}`:                "default profile",
		`{"default":"zz"}`:                                    "default profile",
	}
	for s, want := range bad {
		_, err := parseConfigFile([]byte(s))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", s, err, want)
		}
	}
	big := append([]byte(`{"profiles":{}}`), bytes.Repeat([]byte(" "), MaxConfigFileBytes)...)
	if _, err := parseConfigFile(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("big: %v", err)
	}
	// A wrong type never quotes the value (a token pasted in the wrong place).
	_, err := parseConfigFile([]byte(`{"default":12345678901234567890}`))
	if err == nil || strings.Contains(err.Error(), "1234567890") {
		t.Errorf("type error quotes the value: %v", err)
	}
}

func TestNormalizeURL(t *testing.T) {
	good := map[string]string{
		"https://Transfer.Entity-A.example.com": "https://transfer.entity-a.example.com",
		"https://transfer.example.com:443":      "https://transfer.example.com",
		"https://transfer.example.com:8443/":    "https://transfer.example.com:8443",
		"HTTPS://transfer.example.com":          "https://transfer.example.com",
		"https://[::1]":                         "https://[::1]",
		"https://[::1]:8443":                    "https://[::1]:8443",
		"https://127.0.0.1:1":                   "https://127.0.0.1:1",
	}
	good[" https://transfer.example.com/\n"] = "https://transfer.example.com"
	for in, want := range good {
		if got, err := NormalizeURL(in); err != nil || got != want {
			t.Errorf("%q: got %q %v, want %q", in, got, err, want)
		}
	}
	bad := map[string]string{
		"http://transfer.example.com":          "https://",
		"transfer.example.com":                 "https://",
		"https://":                             "no host",
		"https::opaque":                        "no host",
		"https://:443":                         "no host",
		"https://user:pw@transfer.example.com": "user name",
		"https://transfer.example.com?x=1":     "query",
		"https://transfer.example.com?":        "query",
		"https://transfer.example.com#k=abc":   "fragment",
		"https://transfer.example.com#":        "fragment",
		"https://transfer.example.com/api":     "without a path",
		"https://transfer.example.com:":        "empty port",
		"https://transfer.example.com:0":       "invalid port",
		"https://transfer.example.com:70000":   "invalid port",
		"https://transfer.example.com:abc":     "invalid URL",
		"https://exa mple.com":                 "invalid URL",
	}
	for in, want := range bad {
		if _, err := NormalizeURL(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", in, err, want)
		}
	}
}

func TestConfigRedaction(t *testing.T) {
	tok := testToken('z')
	cfg := Config{URL: "https://a.example.com", Token: tok, Sender: "s@example.com", Profile: "p"}
	var logBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("config", "cfg", cfg)
	js, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	outputs := []string{
		fmt.Sprint(cfg), fmt.Sprintf("%v %+v %#v %s", cfg, cfg, cfg, cfg),
		fmt.Sprintf("%v", &cfg), string(js), logBuf.String(),
	}
	for _, out := range outputs {
		if strings.Contains(out, tok[3:20]) {
			t.Fatalf("token printed: %s", out)
		}
		if !strings.Contains(out, redacted) || !strings.Contains(out, "a.example.com") {
			t.Fatalf("unexpected form: %s", out)
		}
	}
	if s := (Config{}).String(); strings.Contains(s, redacted) {
		t.Fatalf("empty token shown as set: %s", s)
	}
}

func TestPrintable(t *testing.T) {
	if got := printable("a\nb\tc\x1b[31m" + rlo + "\xff"); got != "a b c�[31m��" {
		t.Fatalf("got %q", got)
	}
	long := printable(strings.Repeat("é", 300))
	if r := []rune(long); len(r) != 201 || r[200] != '…' {
		t.Fatalf("truncation: %d runes", len(r))
	}
}

func TestValidProfileName(t *testing.T) {
	for _, n := range []string{"a", "Z", "0", "a.b", "a_b", "a-b"} {
		if !validProfileName(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", "a/b", "é", "a b", "a:b", "@"} {
		if validProfileName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

// FuzzConfig checks that the configuration file parser never panics and
// that an accepted file is consistent.
func FuzzConfig(f *testing.F) {
	f.Add([]byte(`{"default":"a","profiles":{"a":{"url":"https://a.example.com","token":"x","tokenFile":"t","sender":"s","caFile":"c"}}}`))
	f.Add([]byte(`{"profiles":{"a b":{}}}`))
	f.Add([]byte(`{}{}`))
	f.Add([]byte(`{"default":"x"}`))
	f.Add([]byte(`{"profiles":{"a":{"url":1}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		fc, err := parseConfigFile(data)
		if err != nil {
			if fc.Default != "" || fc.Profiles != nil {
				t.Fatalf("partial result on error: %+v", fc)
			}
			return
		}
		for name := range fc.Profiles {
			if !validProfileName(name) {
				t.Fatalf("invalid name accepted: %q", name)
			}
		}
		if _, ok := fc.Profiles[fc.Default]; fc.Default != "" && !ok {
			t.Fatalf("dangling default %q", fc.Default)
		}
	})
}

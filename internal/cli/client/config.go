package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// Environment variables read by [Load].
const (
	// EnvURL is the base URL of the tenant (https://host[:port]).
	EnvURL = "TT_URL"
	// EnvToken carries the API token itself.
	EnvToken = "TT_TOKEN"
	// EnvTokenFile is the path of a file holding the API token.
	EnvTokenFile = "TT_TOKEN_FILE" //nolint:gosec // G101: the name of a variable, not a credential
	// EnvSender is the sender address used for deposits.
	EnvSender = "TT_SENDER"
	// EnvProfile names the profile of the configuration file.
	EnvProfile = "TT_PROFILE"
	// EnvConfigFile is the path of the configuration file.
	EnvConfigFile = "TT_CLI_CONFIG"
	// EnvCAFile is the path of a PEM file of extra certificate authorities.
	EnvCAFile = "TT_CA_FILE"
)

// Size limits of the files read by [Load].
const (
	// MaxConfigFileBytes is the largest configuration file accepted.
	MaxConfigFileBytes = 64 << 10
	// MaxTokenFileBytes is the largest token file accepted.
	MaxTokenFileBytes = 4 << 10
	// maxSenderLen bounds the sender address (RFC 5321 path limit).
	maxSenderLen = 254
)

// tokenPrefix and tokenBodyLen describe an API token: "tt_" followed by 43
// base62 characters (internal/apitoken).
const (
	tokenPrefix  = "tt"
	tokenBodyLen = 43
)

// Hooks replaced by the tests: the operating system (the permission check
// is skipped on Windows), the default configuration directory and the
// opening of the files read by Load and New.
var (
	goos          = runtime.GOOS
	userConfigDir = os.UserConfigDir
	openFile      = func(path string) (readFile, error) {
		return os.Open(path) //nolint:gosec // G304: the path is chosen by the user who runs the client
	}
)

// readFile is the part of *os.File used to read a configuration, token or
// CA file.
type readFile interface {
	io.ReadCloser
	Stat() (fs.FileInfo, error)
}

// ErrNoURL is returned by [Load] when no URL is configured anywhere.
var ErrNoURL = errors.New("no server URL: use --url, " + EnvURL + " or a profile")

// ErrNoToken is returned by [Load] when [LoadOptions.RequireToken] is set
// and no token is configured anywhere.
var ErrNoToken = errors.New("no API token: use --token-file, " + EnvTokenFile + ", " + EnvToken + " or a profile")

// LoadOptions carries the command-line flags given to [Load]. An empty
// field means "not given"; the environment, then the profile, fill it.
type LoadOptions struct {
	// URL is --url.
	URL string
	// TokenFile is --token-file. There is deliberately no flag for the
	// token value itself: it would show in the shell history and the
	// process list.
	TokenFile string
	// Sender is --sender.
	Sender string
	// Profile is --profile.
	Profile string
	// ConfigFile is --config.
	ConfigFile string
	// CAFile is --ca-file.
	CAFile string
	// RequireToken makes a missing token an error ([ErrNoToken]); deposits
	// need one, downloads do not.
	RequireToken bool
	// Getenv reads the environment; nil means os.Getenv.
	Getenv func(string) string
}

// Config is the resolved configuration of the client. Its token is
// redacted by String, GoString, LogValue and MarshalJSON.
type Config struct {
	// URL is the normalized base URL: "https://host[:port]", lowercase
	// host, no path, no trailing slash.
	URL string
	// Token is the API token, or empty. Never print it.
	Token string
	// Sender is the sender address, or empty.
	Sender string
	// CAFile is the path of the extra CA file, or empty.
	CAFile string
	// Profile is the profile used, or empty.
	Profile string
	// ConfigFile is the configuration file read, or empty when none was.
	ConfigFile string
}

// redacted replaces the token in every printed form of a Config.
const redacted = "[REDACTED]"

func (c Config) tokenState() string {
	if c.Token == "" {
		return ""
	}
	return redacted
}

// String returns the configuration with the token redacted.
func (c Config) String() string {
	return fmt.Sprintf("Config{URL:%q Token:%q Sender:%q CAFile:%q Profile:%q ConfigFile:%q}",
		c.URL, c.tokenState(), c.Sender, c.CAFile, c.Profile, c.ConfigFile)
}

// GoString returns the same redacted form as String, for %#v.
func (c Config) GoString() string { return c.String() }

// LogValue returns the configuration as a slog group, token redacted.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("url", c.URL),
		slog.String("token", c.tokenState()),
		slog.String("sender", c.Sender),
		slog.String("caFile", c.CAFile),
		slog.String("profile", c.Profile),
		slog.String("configFile", c.ConfigFile),
	)
}

// MarshalJSON encodes the configuration with the token redacted.
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		URL        string `json:"url"`
		Token      string `json:"token,omitempty"`
		Sender     string `json:"sender,omitempty"`
		CAFile     string `json:"caFile,omitempty"`
		Profile    string `json:"profile,omitempty"`
		ConfigFile string `json:"configFile,omitempty"`
	}{c.URL, c.tokenState(), c.Sender, c.CAFile, c.Profile, c.ConfigFile})
}

// fileConfig is the configuration file.
type fileConfig struct {
	Default  string             `json:"default"`
	Profiles map[string]profile `json:"profiles"`
}

// profile is one profile of the configuration file.
type profile struct {
	URL       string `json:"url"`
	Token     string `json:"token"`
	TokenFile string `json:"tokenFile"`
	Sender    string `json:"sender"`
	CAFile    string `json:"caFile"`
}

// Load resolves the configuration: each setting comes from the flag in
// opts, else from the environment, else from the selected profile. The
// configuration file is TT_CLI_CONFIG or --config when given (it must then
// exist), else os.UserConfigDir()/transteira/config.json (silently skipped
// when absent). The profile is --profile, else TT_PROFILE, else the
// "default" member of the file; a named profile must exist. Relative paths
// in a profile are relative to the directory of the configuration file.
// Errors never quote a token.
func Load(opts LoadOptions) (Config, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	file, path, err := loadFile(first(opts.ConfigFile, getenv(EnvConfigFile)))
	if err != nil {
		return Config{}, err
	}
	cfg := Config{ConfigFile: path}
	cfg.Profile = first(opts.Profile, getenv(EnvProfile))
	if cfg.Profile == "" {
		cfg.Profile = file.Default
	}
	var prof profile
	if cfg.Profile != "" {
		p, ok := file.Profiles[cfg.Profile]
		switch {
		case !ok && path == "":
			return Config{}, fmt.Errorf("profile %q: no configuration file", printable(cfg.Profile))
		case !ok:
			// parseConfigFile already checked the default profile.
			return Config{}, fmt.Errorf("profile %q not found in %s", printable(cfg.Profile), path)
		}
		prof = p.resolve(filepath.Dir(path))
	}

	rawURL := first(opts.URL, getenv(EnvURL), prof.URL)
	if rawURL == "" {
		return Config{}, ErrNoURL
	}
	if cfg.URL, err = NormalizeURL(rawURL); err != nil {
		return Config{}, err
	}
	if cfg.Token, err = resolveToken(opts.TokenFile, getenv, prof); err != nil {
		return Config{}, err
	}
	if cfg.Token == "" && opts.RequireToken {
		return Config{}, ErrNoToken
	}
	cfg.Sender = strings.TrimSpace(first(opts.Sender, getenv(EnvSender), prof.Sender))
	if err := checkSender(cfg.Sender); err != nil {
		return Config{}, err
	}
	cfg.CAFile = first(opts.CAFile, getenv(EnvCAFile), prof.CAFile)
	return cfg, nil
}

// first returns the first non-empty value.
func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// resolve makes the relative paths of a profile relative to dir.
func (p profile) resolve(dir string) profile {
	if p.TokenFile != "" && !filepath.IsAbs(p.TokenFile) {
		p.TokenFile = filepath.Join(dir, p.TokenFile)
	}
	if p.CAFile != "" && !filepath.IsAbs(p.CAFile) {
		p.CAFile = filepath.Join(dir, p.CAFile)
	}
	return p
}

// resolveToken returns the token from the flag, else the environment, else
// the profile. Two sources at the same level are refused as ambiguous.
func resolveToken(flagFile string, getenv func(string) string, prof profile) (string, error) {
	if flagFile != "" {
		return readTokenFile(flagFile)
	}
	envToken, envFile := getenv(EnvToken), getenv(EnvTokenFile)
	switch {
	case envToken != "" && envFile != "":
		return "", errors.New("both " + EnvToken + " and " + EnvTokenFile + " are set: keep only one")
	case envFile != "":
		return readTokenFile(envFile)
	case envToken != "":
		return checkToken(strings.TrimSpace(envToken), EnvToken)
	}
	switch {
	case prof.Token != "" && prof.TokenFile != "":
		return "", errors.New("the profile sets both token and tokenFile: keep only one")
	case prof.TokenFile != "":
		return readTokenFile(prof.TokenFile)
	case prof.Token != "":
		return checkToken(strings.TrimSpace(prof.Token), "the profile token")
	}
	return "", nil
}

// checkToken validates the shape of a token without ever quoting it.
func checkToken(token, source string) (string, error) {
	if !id.TokenValid(tokenPrefix, token, tokenBodyLen, tokenBodyLen) {
		return "", fmt.Errorf("%s is not an API token (expected tt_ followed by %d letters and digits)", source, tokenBodyLen)
	}
	return token, nil
}

// readTokenFile reads and validates a token file.
func readTokenFile(path string) (string, error) {
	data, err := readPrivateFile(path, MaxTokenFileBytes, "token file")
	if err != nil {
		return "", err
	}
	return checkToken(strings.TrimSpace(string(data)), "token file "+path)
}

// loadFile reads the configuration file. An explicit path must exist; the
// default one may be absent, in which case the result is empty with an
// empty path.
func loadFile(explicit string) (fileConfig, string, error) {
	path := explicit
	if path == "" {
		dir, err := userConfigDir()
		if err != nil {
			// No configuration directory (no HOME): there is no default file.
			return fileConfig{}, "", nil
		}
		path = filepath.Join(dir, "transteira", "config.json")
	}
	data, err := readPrivateFile(path, MaxConfigFileBytes, "configuration file")
	if errors.Is(err, fs.ErrNotExist) && explicit == "" {
		return fileConfig{}, "", nil
	}
	if err != nil {
		return fileConfig{}, "", err
	}
	fc, err := parseConfigFile(data)
	if err != nil {
		return fileConfig{}, "", fmt.Errorf("configuration file %s: %w", path, err)
	}
	return fc, path, nil
}

// parseConfigFile checks the content of a configuration file: one JSON
// object, no unknown member, no trailing data, at most
// [MaxConfigFileBytes], every profile with a valid name, and a default that
// names an existing profile.
func parseConfigFile(data []byte) (fileConfig, error) {
	var fc fileConfig
	if len(data) > MaxConfigFileBytes {
		return fc, fmt.Errorf("larger than %d bytes", MaxConfigFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return fileConfig{}, fmt.Errorf("invalid JSON: %w", jsonError(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fileConfig{}, errors.New("invalid JSON: data after the object")
	}
	for name := range fc.Profiles {
		if !validProfileName(name) {
			return fileConfig{}, fmt.Errorf("invalid profile name %q (letters, digits, '.', '_' and '-', 64 at most)", printable(name))
		}
	}
	if fc.Default != "" {
		if _, ok := fc.Profiles[fc.Default]; !ok {
			return fileConfig{}, fmt.Errorf("default profile %q not found", printable(fc.Default))
		}
	}
	return fc, nil
}

// jsonError drops the value quoted by some decoding errors (a token put in
// a numeric field, for example) and keeps only the location.
func jsonError(err error) error {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return fmt.Errorf("member %q has the wrong type", printable(typeErr.Field))
	}
	return err
}

// validProfileName reports whether a profile name is 1 to 64 ASCII letters,
// digits, '.', '_' or '-'.
func validProfileName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// readPrivateFile reads a regular file of at most limit bytes and, outside
// Windows, refuses it when the group or others have any right on it.
func readPrivateFile(path string, limit int64, what string) ([]byte, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", what, path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %s is not a regular file", what, path)
	}
	if err := checkPrivate(path, info.Mode(), what); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", what, path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s %s is larger than %d bytes", what, path, limit)
	}
	return data, nil
}

// checkPrivate refuses, outside Windows (where the permission bits do not
// describe the ACL), a file the group or others can access.
func checkPrivate(path string, mode fs.FileMode, what string) error {
	if goos == "windows" || mode.Perm()&0o077 == 0 {
		return nil
	}
	return fmt.Errorf("%s %s is accessible by other users (mode %04o): run chmod 600 %s", what, path, mode.Perm(), path)
}

// NormalizeURL checks a base URL and returns it as "https://host[:port]":
// https only, a host, no user information, no query, no fragment, and an
// empty path or "/". The default port 443 is dropped.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("invalid URL")
	}
	switch {
	case u.Scheme != "https":
		return "", errors.New("the URL must start with https://")
	case u.Opaque != "" || u.Host == "" || u.Hostname() == "":
		return "", errors.New("the URL has no host")
	case u.User != nil:
		return "", errors.New("the URL must not carry a user name or password")
	case u.RawQuery != "" || u.ForceQuery:
		return "", errors.New("the URL must not carry a query")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return "", errors.New("the URL must not carry a fragment")
	case u.Path != "" && u.Path != "/":
		return "", errors.New("the URL must be the server address only, without a path")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" && strings.HasSuffix(u.Host, ":") {
		return "", errors.New("the URL has an empty port")
	}
	if port == "" || port == "443" {
		if strings.Contains(host, ":") {
			return "https://[" + host + "]", nil
		}
		return "https://" + host, nil
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", errors.New("the URL has an invalid port")
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

// checkSender refuses a sender address with hidden characters or too long.
func checkSender(sender string) error {
	if len(sender) > maxSenderLen {
		return fmt.Errorf("the sender address is longer than %d characters", maxSenderLen)
	}
	if strings.ContainsFunc(sender, textsafe.IsHidden) || strings.ContainsAny(sender, "\n\t") {
		return errors.New("the sender address contains control characters")
	}
	return nil
}

// printable makes a string from the configuration file or a server answer
// safe for a terminal: invalid UTF-8 and hidden characters replaced, line
// breaks and tabs turned into spaces, at most 200 characters.
func printable(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case textsafe.IsHidden(r):
			return '�'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

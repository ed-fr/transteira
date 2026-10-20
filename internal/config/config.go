// Package config reads and validates the installation-level configuration of
// TransTeira from TT_* environment variables (spec sections 4 and 17).
//
// Tenant-specific settings (branding, SMTP, IP ranges, quotas...) are stored in
// the database and managed from the administration; they are not handled here.
//
// [Load] is pure: it receives the environment through a getenv function so
// that tests never touch the process environment. It reports every problem at
// once in a [ValidationError]. Sensitive values are wrapped in [Secret], which
// never prints its content. [Variables] documents every variable and is the
// single source used by [WriteEnvExample] to generate .env.example.
//
// Paths: TransTeira runs in Linux containers, but paths starting with "/" are
// accepted as absolute on every platform (including Windows, where they are
// rooted on the current drive) so that defaults and tests stay portable. Path
// comparisons are done on cleaned paths, case-insensitively on Windows;
// symbolic links are not resolved because the files may not exist yet when
// the configuration is loaded.
package config

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Supported database drivers.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

// Setup token length bounds (the API accepts at most 128 characters).
const (
	minSetupTokenLength = 16
	maxSetupTokenLength = 128
)

// Duration bounds.
const (
	minUploadTTL                = time.Hour
	maxUploadTTL                = 7 * 24 * time.Hour
	minDepositSessionTTL        = 15 * time.Minute
	maxDepositSessionTTL        = 24 * time.Hour
	minDeleteAfterDownloadGrace = 0
	maxDeleteAfterDownloadGrace = 24 * time.Hour
)

// unixPrefix introduces a Unix socket address in TT_CLAMAV_ADDR.
const unixPrefix = "unix:"

// ClamAVAddr is the address of the clamd daemon, ready for net.Dial.
type ClamAVAddr struct {
	// Network is "tcp" or "unix".
	Network string
	// Address is "host:port" for tcp, or the socket path for unix.
	Address string
}

// String returns the address in TT_CLAMAV_ADDR syntax.
func (a ClamAVAddr) String() string {
	if a.Network == "unix" {
		return unixPrefix + a.Address
	}
	return a.Address
}

// Config is the validated installation configuration.
type Config struct {
	// DBDriver is DriverSQLite or DriverPostgres.
	DBDriver string
	// DBDSN is the database connection string (file path for SQLite).
	DBDSN Secret
	// DBMigrateDSN is the PostgreSQL connection string of the owner role, used
	// only to apply migrations and grant DML rights to the runtime role. It is
	// optional (only the process applying migrations needs it, so that the
	// long-running server can run without owner credentials) and never set
	// with SQLite.
	DBMigrateDSN Secret

	// DataDir holds the encrypted files, one sub-directory per tenant.
	DataDir string
	// BackupDir receives the regular database backups.
	BackupDir string
	// LogDir holds the security log.
	LogDir string

	// MasterKeyFile is the path of the master key file. The key itself is read
	// by the crypto package, never by config.
	MasterKeyFile string
	// MasterKeyNewFile is the path of the new master key used during a
	// rotation ("" when no rotation is in progress).
	MasterKeyNewFile string

	// TrustedProxies lists the reverse proxies allowed to set the client IP
	// through X-Forwarded-For / X-Real-IP. Empty means none.
	TrustedProxies []netip.Prefix
	// ListenAddr is the host:port the HTTP server listens on.
	ListenAddr string
	// AdminHosts restricts the hosts serving the administration (lowercase
	// FQDNs). Empty means every tenant host.
	AdminHosts []string

	// LogLevel is the minimum level of the application log.
	LogLevel slog.Level
	// Maintenance is true when the instance starts in maintenance mode.
	Maintenance bool
	// APIDocsPublic is true when the API documentation is served to anonymous
	// visitors.
	APIDocsPublic bool
	// SetupToken, when set, must be provided to create the first super admin.
	SetupToken Secret

	// UploadTTL is the time after which an unfinished upload is discarded.
	UploadTTL time.Duration
	// DepositSessionTTL is the lifetime of a deposit session.
	DepositSessionTTL time.Duration
	// DeleteAfterDownloadGrace delays the erasure of delete-after-download
	// transfers so that an interrupted download can resume.
	DeleteAfterDownloadGrace time.Duration

	// ClamAV is the clamd address.
	ClamAV ClamAVAddr
}

// TrustsEverything reports whether a trusted proxy prefix covers the whole
// address space (0.0.0.0/0 or ::/0), which lets any client forge its IP. It is
// allowed, but callers should log a prominent warning.
func (c *Config) TrustsEverything() bool {
	for _, p := range c.TrustedProxies {
		if p.Bits() == 0 {
			return true
		}
	}
	return false
}

// IsTrustedProxy reports whether addr belongs to a trusted proxy prefix.
// IPv4-mapped IPv6 addresses are unmapped and zones ignored before matching.
func (c *Config) IsTrustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	for _, p := range c.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Option customizes [Load].
type Option func(*loader)

// WithReadFile replaces the function used to read *_FILE secrets
// (os.ReadFile by default).
func WithReadFile(readFile func(name string) ([]byte, error)) Option {
	return func(l *loader) { l.readFile = readFile }
}

// FromEnvironment loads the configuration from the process environment.
func FromEnvironment() (*Config, error) {
	return Load(os.Getenv)
}

// Load builds and validates a Config from the variables returned by getenv.
// An empty value is treated as unset. On failure it returns a
// *[ValidationError] listing every problem; secret values never appear in it.
func Load(getenv func(string) string, opts ...Option) (*Config, error) {
	l := &loader{getenv: getenv, readFile: os.ReadFile}
	for _, opt := range opts {
		opt(l)
	}
	c := &Config{}
	l.loadDatabase(c)
	l.loadPaths(c)
	l.loadNetwork(c)
	l.loadOperations(c)
	l.loadDurations(c)
	if len(l.problems) > 0 {
		return nil, &ValidationError{Problems: l.problems}
	}
	return c, nil
}

// loader accumulates validation problems while reading variables.
type loader struct {
	getenv   func(string) string
	readFile func(string) ([]byte, error)
	problems []Problem
}

// get returns the trimmed value of a variable.
func (l *loader) get(name string) string {
	return strings.TrimSpace(l.getenv(name))
}

// getOr returns the value of a variable, or def when it is empty.
func (l *loader) getOr(name, def string) string {
	if v := l.get(name); v != "" {
		return v
	}
	return def
}

// fail records a problem.
func (l *loader) fail(name, format string, args ...any) {
	l.problems = append(l.problems, Problem{Variable: name, Reason: fmt.Sprintf(format, args...)})
}

// secret reads a secret given either directly (name) or through a file
// (fileName). Both being set is an error. File content is trimmed of
// surrounding whitespace. Neither the value nor the file content ever appears
// in a problem.
func (l *loader) secret(name, fileName string) (Secret, bool) {
	direct := l.get(name)
	path := l.get(fileName)
	switch {
	case direct != "" && path != "":
		l.fail(name, "cannot be set together with %s", fileName)
		return Secret{}, false
	case path != "":
		clean, err := checkAbsPath(path)
		if err != nil {
			l.fail(fileName, "%v", err)
			return Secret{}, false
		}
		data, err := l.readFile(clean)
		if err != nil {
			l.fail(fileName, "cannot read file: %v", err)
			return Secret{}, false
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			l.fail(fileName, "file is empty")
			return Secret{}, false
		}
		return NewSecret(value), true
	default:
		return NewSecret(direct), true
	}
}

// loadDatabase reads TT_DB_DRIVER, TT_DB_DSN(_FILE) and
// TT_DB_MIGRATE_DSN(_FILE). With PostgreSQL, migrations use a separate owner
// role so that the runtime role owns nothing and cannot disable RLS; the
// migration DSN is optional because only the migrating process needs it.
func (l *loader) loadDatabase(c *Config) {
	c.DBDriver = strings.ToLower(l.getOr(EnvDBDriver, DefaultDBDriver))
	driverOK := c.DBDriver == DriverSQLite || c.DBDriver == DriverPostgres
	if !driverOK {
		l.fail(EnvDBDriver, "%q is not supported (use %s or %s)", c.DBDriver, DriverSQLite, DriverPostgres)
	}
	dsn, dsnOK := l.secret(EnvDBDSN, EnvDBDSNFile)
	migrate, migrateOK := l.secret(EnvDBMigrateDSN, EnvDBMigrateDSNFile)

	if dsnOK && !dsn.IsSet() {
		switch {
		case c.DBDriver == DriverPostgres:
			l.fail(EnvDBDSN, "is required when %s is %s (or set %s)", EnvDBDriver, DriverPostgres, EnvDBDSNFile)
		case driverOK:
			dsn = NewSecret(DefaultSQLiteDSN)
		}
	}
	if migrateOK {
		switch {
		case c.DBDriver == DriverSQLite && migrate.IsSet():
			l.fail(l.setName(EnvDBMigrateDSN, EnvDBMigrateDSNFile), "is only allowed when %s is %s",
				EnvDBDriver, DriverPostgres)
		case dsnOK && migrate.IsSet() && migrate.Reveal() == dsn.Reveal():
			l.fail(EnvDBMigrateDSN, "must differ from %s: migrations use the owner role, "+
				"the application a runtime role with DML rights only", EnvDBDSN)
		}
	}
	c.DBDSN = dsn
	c.DBMigrateDSN = migrate
}

// setName returns fileName when it is set, name otherwise, to report a
// problem on the variable the operator actually used.
func (l *loader) setName(name, fileName string) string {
	if l.get(fileName) != "" {
		return fileName
	}
	return name
}

// path reads a directory or file path variable and returns its cleaned form.
func (l *loader) path(name, def string) string {
	raw := l.getOr(name, def)
	if raw == "" {
		return ""
	}
	clean, err := checkAbsPath(raw)
	if err != nil {
		l.fail(name, "%q %v", raw, err)
		return ""
	}
	return clean
}

// loadPaths reads the volume paths and the master key paths, and checks that
// the master keys live outside the data, backup, log and SQLite database
// volumes (spec 16.1 and 18.1). It must run after loadDatabase.
func (l *loader) loadPaths(c *Config) {
	c.DataDir = l.path(EnvDataDir, DefaultDataDir)
	c.BackupDir = l.path(EnvBackupDir, DefaultBackupDir)
	c.LogDir = l.path(EnvLogDir, DefaultLogDir)

	if l.get(EnvMasterKeyFile) == "" {
		l.fail(EnvMasterKeyFile, "is required")
	}
	c.MasterKeyFile = l.path(EnvMasterKeyFile, "")
	c.MasterKeyNewFile = l.path(EnvMasterKeyNewFile, "")

	volumes := []struct{ name, dir string }{
		{EnvDataDir, c.DataDir}, {EnvBackupDir, c.BackupDir}, {EnvLogDir, c.LogDir},
	}
	// The SQLite database lives in its own volume (spec 18.1). Only its folder
	// is reported, never the DSN itself.
	if c.DBDriver == DriverSQLite {
		if dir, ok := sqliteDir(c.DBDSN.Reveal()); ok {
			volumes = append(volumes, struct{ name, dir string }{"the folder of " + EnvDBDSN, dir})
		}
	}
	for _, key := range []struct{ name, path string }{
		{EnvMasterKeyFile, c.MasterKeyFile}, {EnvMasterKeyNewFile, c.MasterKeyNewFile},
	} {
		if key.path == "" {
			continue
		}
		for _, vol := range volumes {
			if vol.dir != "" && pathWithin(key.path, vol.dir) {
				l.fail(key.name, "must not be located inside %s (%s): the master key must stay outside the data volumes",
					vol.name, vol.dir)
			}
		}
	}
	if c.MasterKeyFile != "" && c.MasterKeyNewFile != "" && samePath(c.MasterKeyFile, c.MasterKeyNewFile) {
		l.fail(EnvMasterKeyNewFile, "must differ from %s", EnvMasterKeyFile)
	}
}

// loadNetwork reads the network-related variables.
func (l *loader) loadNetwork(c *Config) {
	var err error
	if c.TrustedProxies, err = parsePrefixes(l.get(EnvTrustedProxies)); err != nil {
		l.fail(EnvTrustedProxies, "%v", err)
	}
	c.ListenAddr = l.getOr(EnvListenAddr, DefaultListenAddr)
	if err := validateHostPort(c.ListenAddr, false); err != nil {
		l.fail(EnvListenAddr, "%v", err)
	}
	if c.AdminHosts, err = parseHosts(l.get(EnvAdminHosts)); err != nil {
		l.fail(EnvAdminHosts, "%v", err)
	}
	raw := l.getOr(EnvClamAVAddr, DefaultClamAVAddr)
	if path, ok := strings.CutPrefix(raw, unixPrefix); ok {
		clean, err := checkAbsPath(path)
		if err != nil {
			l.fail(EnvClamAVAddr, "unix socket path %q %v", path, err)
			return
		}
		c.ClamAV = ClamAVAddr{Network: "unix", Address: filepath.ToSlash(clean)}
		return
	}
	if err := validateHostPort(raw, true); err != nil {
		l.fail(EnvClamAVAddr, "%v", err)
		return
	}
	c.ClamAV = ClamAVAddr{Network: "tcp", Address: raw}
}

// logLevels maps TT_LOG_LEVEL values to slog levels.
var logLevels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

// boolVar reads an optional boolean variable (false when unset).
func (l *loader) boolVar(name string) bool {
	raw := l.get(name)
	if raw == "" {
		return false
	}
	b, err := parseBool(raw)
	if err != nil {
		l.fail(name, "%v", err)
	}
	return b
}

// loadOperations reads the log level, flags and setup token.
func (l *loader) loadOperations(c *Config) {
	level := strings.ToLower(l.getOr(EnvLogLevel, DefaultLogLevel))
	if lv, ok := logLevels[level]; ok {
		c.LogLevel = lv
	} else {
		l.fail(EnvLogLevel, "%q is not a log level (use debug, info, warn or error)", level)
	}
	c.Maintenance = l.boolVar(EnvMaintenance)
	c.APIDocsPublic = l.boolVar(EnvAPIDocsPublic)

	token, ok := l.secret(EnvSetupToken, EnvSetupTokenFile)
	if !ok {
		return
	}
	if n := len(token.Reveal()); token.IsSet() && (n < minSetupTokenLength || n > maxSetupTokenLength) {
		l.fail(l.setName(EnvSetupToken, EnvSetupTokenFile), "must be between %d and %d characters long", minSetupTokenLength, maxSetupTokenLength)
		return
	}
	c.SetupToken = token
}

// duration reads a bounded duration variable.
func (l *loader) duration(name, def string, lowest, highest time.Duration) time.Duration {
	d, err := parseDuration(l.getOr(name, def), lowest, highest)
	if err != nil {
		l.fail(name, "%v", err)
	}
	return d
}

// loadDurations reads the duration variables.
func (l *loader) loadDurations(c *Config) {
	c.UploadTTL = l.duration(EnvUploadTTL, DefaultUploadTTL, minUploadTTL, maxUploadTTL)
	c.DepositSessionTTL = l.duration(EnvDepositSessionTTL, DefaultDepositSessionTTL,
		minDepositSessionTTL, maxDepositSessionTTL)
	c.DeleteAfterDownloadGrace = l.duration(EnvDeleteAfterDownloadGrace, DefaultDeleteAfterDownloadGrace,
		minDeleteAfterDownloadGrace, maxDeleteAfterDownloadGrace)
}

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
	"crypto/x509"
	"fmt"
	"log/slog"
	netmail "net/mail"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/netpolicy"
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

// Monitoring token length bounds (threat T-193).
const (
	minMetricsTokenLength = 32
	maxMetricsTokenLength = 512
)

// Duration bounds.
const (
	minUploadTTL                = time.Hour
	maxUploadTTL                = 7 * 24 * time.Hour
	minUploadMaxAge             = 24 * time.Hour
	maxUploadMaxAge             = 90 * 24 * time.Hour
	minDepositSessionTTL        = 15 * time.Minute
	maxDepositSessionTTL        = 24 * time.Hour
	minDeleteAfterDownloadGrace = 0
	maxDeleteAfterDownloadGrace = 24 * time.Hour
	minUploadIdleTimeout        = 5 * time.Second
	maxUploadIdleTimeout        = 10 * time.Minute
	minDownloadIdleTimeout      = 5 * time.Second
	maxDownloadIdleTimeout      = 10 * time.Minute
	minSMTPTimeout              = time.Second
	maxSMTPTimeout              = 5 * time.Minute
	minClamAVTimeout            = 10 * time.Second
	maxClamAVTimeout            = 2 * time.Hour
	minAdminSessionIdleTimeout  = 5 * time.Minute
	maxAdminSessionIdleTimeout  = 4 * time.Hour
	minAdminSessionMaxAge       = time.Hour
	maxAdminSessionMaxAge       = 7 * 24 * time.Hour
)

// Antivirus scan size bounds: 4 GiB - 1 is the largest StreamMaxLength clamd
// accepts.
const (
	minClamAVMaxScanBytes = 1 << 20
	maxClamAVMaxScanBytes = 1<<32 - 1
)

// Antivirus worker count bounds.
const (
	minScanWorkers = 1
	maxScanWorkers = 16
)

// Mail queue capacity bounds.
const (
	minMailQueueSize = 1
	maxMailQueueSize = 100000
)

// Recipient ceiling bounds (the OpenAPI TransferCreate allows at most 100).
const (
	minMaxRecipients = 1
	maxMaxRecipients = 100
)

// Open transfer cap bounds.
const (
	minMaxOpenTransfers = 1
	maxMaxOpenTransfers = 1000
)

// Nightly database copy retention bounds.
const (
	minBackupKeep = 1
	maxBackupKeep = 90
)

// AntivirusEngine names the antivirus engine of the instance
// (TT_ANTIVIRUS_ENGINE).
type AntivirusEngine string

// Antivirus engines. EngineICAP and EngineHTTP are reserved names refused by
// [Load] until their implementation lands.
const (
	// EngineClamd analyzes files with the ClamAV daemon (default).
	EngineClamd AntivirusEngine = "clamd"
	// EngineNone disables the analysis for the whole instance.
	EngineNone AntivirusEngine = "none"
	// EngineICAP is an ICAP server (RFC 3507), not available yet.
	EngineICAP AntivirusEngine = "icap"
	// EngineHTTP is a generic HTTP scanning API, not available yet.
	EngineHTTP AntivirusEngine = "http"
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
	// through X-Forwarded-For / X-Real-IP. Empty means none. Load refuses a
	// list that is too broad (see [ValidateTrustedProxies]).
	TrustedProxies []netip.Prefix
	// ListenAddr is the host:port the HTTP server listens on.
	ListenAddr string
	// AdminHosts lists the dedicated hosts serving the administration
	// (lowercase FQDNs, at least one). The administration is never served on
	// tenant FQDNs.
	AdminHosts []string
	// AdminSessionIdleTimeout ends an admin session after this inactivity;
	// every authenticated request resets it.
	AdminSessionIdleTimeout time.Duration
	// AdminSessionMaxAge is the longest life of an admin session after
	// sign-in, whatever its activity (at least AdminSessionIdleTimeout).
	AdminSessionMaxAge time.Duration

	// LogLevel is the minimum level of the application log.
	LogLevel slog.Level
	// Maintenance is true when the instance starts in maintenance mode.
	Maintenance bool
	// APIDocsPublic is true when the interactive API documentation is served
	// to anonymous visitors on the tenant FQDNs, in addition to the admin
	// sessions on the admin host.
	APIDocsPublic bool
	// SetupToken, when set, must be provided to create the first super admin.
	// When it is unset, the server generates a random token at each start
	// while no admin exists and prints it in its logs.
	SetupToken Secret

	// UploadTTL is the time after which an unfinished upload is discarded.
	UploadTTL time.Duration
	// UploadMaxAge is the longest life of an unfinished upload after the
	// creation of its transfer, whatever its activity (at least UploadTTL).
	UploadMaxAge time.Duration
	// DepositSessionTTL is the lifetime of a deposit session.
	DepositSessionTTL time.Duration
	// DeleteAfterDownloadGrace delays the erasure of delete-after-download
	// transfers so that an interrupted download can resume.
	DeleteAfterDownloadGrace time.Duration
	// UploadIdleTimeout is the longest wait between two reads of an upload
	// request body; every read resets it.
	UploadIdleTimeout time.Duration
	// DownloadIdleTimeout is the longest wait for the client to accept the
	// next write of a download response; every write resets it.
	DownloadIdleTimeout time.Duration
	// MaxRecipients is the largest number of recipients of one transfer
	// (decision P15).
	MaxRecipients int
	// MaxOpenTransfers is the largest number of unfinished transfers of one
	// internal sender.
	MaxOpenTransfers int

	// AntivirusEngine is the antivirus engine of the instance; with
	// EngineNone no file is ever analyzed.
	AntivirusEngine AntivirusEngine
	// ClamAV is the clamd address.
	ClamAV ClamAVAddr
	// ClamAVMaxScanBytes is the largest file size sent to clamd; larger
	// files are not analyzed.
	ClamAVMaxScanBytes int64
	// ClamAVTimeout bounds the analysis of one file.
	ClamAVTimeout time.Duration
	// ICAP configures the ICAP engine; set only with EngineICAP.
	ICAP ICAPConfig
	// AVHTTP configures the generic HTTP engine; set only with EngineHTTP.
	AVHTTP AVHTTPConfig
	// ScanWorkers is the number of antivirus workers, each analyzing one
	// file at a time.
	ScanWorkers int

	// SMTPTimeout bounds one SMTP delivery attempt.
	SMTPTimeout time.Duration
	// MailQueueSize is the capacity of the in-memory mail queue.
	MailQueueSize int
	// SMTPDenyNetworks lists the networks a tenant SMTP server may never
	// resolve to (SSRF protection), checked at connection time.
	SMTPDenyNetworks []netip.Prefix
	// SystemSMTP is the SMTP server of the instance mails (disk and
	// antivirus alerts to the super admins), distinct from the SMTP servers
	// of the tenants.
	// It is disabled when its Host is empty.
	SystemSMTP SystemSMTP

	// BackupTime is the UTC time of day of the nightly SQLite copy, as an
	// offset since midnight in [0, 24h).
	BackupTime time.Duration
	// BackupKeep is the number of nightly database copies kept.
	BackupKeep int

	// WebhookAllowNetworks lists the networks webhook URLs may reach over
	// HTTPS although the built-in deny list refuses them (decision P30).
	WebhookAllowNetworks []netip.Prefix
	// WebhookAllowHTTPNetworks lists the networks towards which a webhook
	// URL may use plain http.
	WebhookAllowHTTPNetworks []netip.Prefix
	// WebhookDenyNetworks lists the networks webhook URLs may never reach,
	// in addition to the built-in deny list; it wins over the allow lists.
	WebhookDenyNetworks []netip.Prefix

	// Syslog is the RFC 5424 export of the audit and security logs
	// (decision P41). It is disabled when its Addr is empty.
	Syslog SyslogConfig

	// MetricsToken protects /metrics and /status; when unset both answer
	// 404 (threats T-191 to T-193).
	MetricsToken Secret
	// MetricsAllowedIPs, when not empty, lists the client networks allowed
	// to read /metrics and /status, checked before the token.
	MetricsAllowedIPs []netip.Prefix

	// Warnings lists the non-fatal problems found by Load (variables
	// ignored with the selected antivirus engine), for the start-up log.
	// They never quote a value.
	Warnings []string
}

// Transports of the syslog export (TT_SYSLOG_PROTOCOL).
const (
	SyslogProtocolUDP = "udp"
	SyslogProtocolTCP = "tcp"
	SyslogProtocolTLS = "tls"
)

// Logs that the syslog export can carry (TT_SYSLOG_STREAMS).
const (
	SyslogStreamAudit    = "audit"
	SyslogStreamSecurity = "security"
)

// syslogFacilities maps the RFC 5424 facility names accepted by
// TT_SYSLOG_FACILITY to their numeric codes.
var syslogFacilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
	"uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// SyslogConfig is the export of the audit and security logs to a syslog
// server, configured by the TT_SYSLOG_* variables. It is an installation
// setting: no API can change it.
type SyslogConfig struct {
	// Addr is the "host:port" of the server, "" when the export is
	// disabled.
	Addr string
	// Protocol is SyslogProtocolUDP, SyslogProtocolTCP or SyslogProtocolTLS.
	Protocol string
	// Streams lists the exported logs (SyslogStreamAudit,
	// SyslogStreamSecurity), sorted and without duplicates.
	Streams []string
	// Facility is the RFC 5424 numeric facility code (0 to 23).
	Facility int
	// CAFile is the absolute path of a PEM file of trusted certificate
	// authorities, "" to use those of the system. Only set with
	// SyslogProtocolTLS; the server certificate is always verified.
	CAFile string
}

// Enabled reports whether the syslog export is configured.
func (s SyslogConfig) Enabled() bool { return s.Addr != "" }

// HasStream reports whether the export carries the given log.
func (s SyslogConfig) HasStream(stream string) bool { return slices.Contains(s.Streams, stream) }

// Security modes of the system SMTP server (TT_SYSTEM_SMTP_SECURITY), the
// values of the tenant SMTP settings.
const (
	SMTPSecurityNone     = "none"
	SMTPSecurityStartTLS = "starttls"
	SMTPSecurityTLS      = "tls"
)

// Limits of the system SMTP settings, those of the tenant SMTP settings of
// the API.
const (
	maxSMTPFromNameLen = 100
	maxSMTPUsernameLen = 320
	maxSMTPPasswordLen = 1024
	maxMailboxLen      = 254
)

// SystemSMTP is the SMTP server of the instance mails, configured by the
// TT_SYSTEM_SMTP_* variables. It is an installation setting, trusted like
// the database: unlike the tenant SMTP servers it may be a relay on
// loopback or on the internal Docker network, so no deny list applies.
type SystemSMTP struct {
	// Host is the server name or IP address, "" when system mail is
	// disabled.
	Host string
	// Port is the TCP port (by default 25, 587 or 465 for the security
	// modes none, starttls and tls).
	Port int
	// Security is SMTPSecurityNone, SMTPSecurityStartTLS or SMTPSecurityTLS.
	Security string
	// From is the bare sender address.
	From string
	// FromName is the display name of the sender.
	FromName string
	// Username is the authentication identity, "" for an unauthenticated
	// relay.
	Username string
	// Password is the authentication secret, read from
	// TT_SYSTEM_SMTP_PASSWORD_FILE; set if and only if Username is.
	Password Secret
}

// Enabled reports whether system mail is configured.
func (s SystemSMTP) Enabled() bool { return s.Host != "" }

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
	l.loadAdmin(c)
	l.loadOperations(c)
	l.loadDurations(c)
	l.loadMail(c)
	l.loadAntivirus(c)
	l.loadMaintenance(c)
	l.loadWebhooks(c)
	l.loadSyslog(c)
	l.loadMetrics(c)
	if len(l.problems) > 0 {
		return nil, &ValidationError{Problems: l.problems}
	}
	c.Warnings = l.warnings
	return c, nil
}

// loader accumulates validation problems and warnings while reading
// variables.
type loader struct {
	getenv   func(string) string
	readFile func(string) ([]byte, error)
	problems []Problem
	warnings []string
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

// failErr records a problem caused by err, which callers can match through
// [ValidationError.Unwrap]. err must not contain a secret value.
func (l *loader) failErr(name string, err error) {
	l.problems = append(l.problems, Problem{Variable: name, Reason: err.Error(), Err: err})
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
// volumes (spec 16.1 and 18.1), and that the backup directory is separate
// from the other volumes. It must run after loadDatabase.
func (l *loader) loadPaths(c *Config) {
	c.DataDir = l.path(EnvDataDir, DefaultDataDir)
	c.BackupDir = l.path(EnvBackupDir, DefaultBackupDir)
	c.LogDir = l.path(EnvLogDir, DefaultLogDir)
	l.checkBackupDir(c)

	if l.get(EnvMasterKeyFile) == "" {
		l.fail(EnvMasterKeyFile, "is required")
	}
	c.MasterKeyFile = l.path(EnvMasterKeyFile, "")
	c.MasterKeyNewFile = l.path(EnvMasterKeyNewFile, "")

	for _, key := range []struct{ name, path string }{
		{EnvMasterKeyFile, c.MasterKeyFile}, {EnvMasterKeyNewFile, c.MasterKeyNewFile},
	} {
		if key.path == "" {
			continue
		}
		if err := c.outsideVolumes(key.path, masterKeyWhat); err != nil {
			l.fail(key.name, "%v", err)
		}
	}
	if c.MasterKeyFile != "" && c.MasterKeyNewFile != "" && samePath(c.MasterKeyFile, c.MasterKeyNewFile) {
		l.fail(EnvMasterKeyNewFile, "must differ from %s", EnvMasterKeyFile)
	}
}

// checkBackupDir checks TT_BACKUP_DIR: no "?" or "#", which the SQLite
// DSN that checks each nightly copy would interpret, and no overlap with the
// data, log and SQLite database volumes, in either direction: the rotation
// of the copies must never see the files of another volume, and the copies
// (which hold the wrapped file keys) must not land in a volume backed up or
// exposed differently.
func (l *loader) checkBackupDir(c *Config) {
	if c.BackupDir == "" {
		return
	}
	if strings.ContainsAny(c.BackupDir, "?#") {
		l.fail(EnvBackupDir, "must not contain \"?\" or \"#\"")
	}
	for _, vol := range c.volumes(false) {
		if vol.dir != "" && (pathWithin(c.BackupDir, vol.dir) || pathWithin(vol.dir, c.BackupDir)) {
			l.fail(EnvBackupDir, "must not be, contain or lie inside %s (%s): the database copies need their own volume",
				vol.name, vol.dir)
		}
	}
}

// volume is a directory of the installation, named by its variable.
type volume struct{ name, dir string }

// volumes returns the data and log directories, the backup directory when
// withBackup is set, and the folder of the SQLite database. Only the folder
// of the SQLite database is named, never the DSN itself.
func (c *Config) volumes(withBackup bool) []volume {
	vols := []volume{{EnvDataDir, c.DataDir}, {EnvLogDir, c.LogDir}}
	if withBackup {
		vols = append(vols, volume{EnvBackupDir, c.BackupDir})
	}
	// The SQLite database lives in its own volume (spec 18.1).
	if c.DBDriver == DriverSQLite {
		if dir, ok := sqliteDir(c.DBDSN.Reveal()); ok {
			vols = append(vols, volume{"the folder of " + EnvDBDSN, dir})
		}
	}
	return vols
}

// CheckMasterKeyPath applies the location rules of TT_MASTER_KEY_FILE to
// path, a master key file given outside the environment (for example the
// old key of "rotate-master-key -recover-from"): it must be absolute and lie
// outside the data, backup and log directories and the folder of the SQLite
// database of c (spec 16.1 and 18.1). It returns the cleaned path.
func (c *Config) CheckMasterKeyPath(path string) (string, error) {
	clean, err := checkAbsPath(path)
	if err != nil {
		return "", fmt.Errorf("%q %w", path, err)
	}
	if err := c.outsideVolumes(clean, masterKeyWhat); err != nil {
		return "", err
	}
	return clean, nil
}

// Secret files that must stay outside the volumes, as named in the
// problems.
const (
	masterKeyWhat          = "the master key"
	systemSMTPPasswordWhat = "the system SMTP password file" //nolint:gosec // G101: a description, not a credential
)

// outsideVolumes reports an error when path, the file of a secret
// described by what (the master key, the system SMTP password), lies
// inside one of the volumes of c: the data, backup and log directories and
// the folder of the SQLite database. Only that folder is reported, never
// the DSN itself.
func (c *Config) outsideVolumes(path, what string) error {
	for _, vol := range c.volumes(true) {
		if vol.dir != "" && pathWithin(path, vol.dir) {
			return fmt.Errorf("must not be located inside %s (%s): %s must stay outside the data volumes",
				vol.name, vol.dir, what)
		}
	}
	return nil
}

// loadNetwork reads the network-related variables.
func (l *loader) loadNetwork(c *Config) {
	var err error
	if c.TrustedProxies, err = parsePrefixes(l.get(EnvTrustedProxies)); err != nil {
		l.fail(EnvTrustedProxies, "%v", err)
	} else if err := ValidateTrustedProxies(c.TrustedProxies); err != nil {
		l.failErr(EnvTrustedProxies, err)
	}
	c.ListenAddr = l.getOr(EnvListenAddr, DefaultListenAddr)
	if err := validateHostPort(c.ListenAddr, false); err != nil {
		l.fail(EnvListenAddr, "%v", err)
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

// loadAdmin reads the administration hosts and the admin session lifetimes.
// At least one dedicated admin host is required: the administration is never
// served on tenant FQDNs.
func (l *loader) loadAdmin(c *Config) {
	hosts, err := parseHosts(l.get(EnvAdminHosts))
	switch {
	case err != nil:
		l.fail(EnvAdminHosts, "%v", err)
	case len(hosts) == 0:
		l.fail(EnvAdminHosts, "is required: set the dedicated host name(s) of the administration, "+
			"e.g. admin.transfer.example.com (never a tenant FQDN)")
	default:
		c.AdminHosts = hosts
	}
	c.AdminSessionIdleTimeout = l.duration(EnvAdminSessionIdleTimeout, DefaultAdminSessionIdleTimeout,
		minAdminSessionIdleTimeout, maxAdminSessionIdleTimeout)
	c.AdminSessionMaxAge = l.duration(EnvAdminSessionMaxAge, DefaultAdminSessionMaxAge,
		minAdminSessionMaxAge, maxAdminSessionMaxAge)
	if c.AdminSessionMaxAge != 0 && c.AdminSessionIdleTimeout != 0 && c.AdminSessionMaxAge < c.AdminSessionIdleTimeout {
		l.fail(EnvAdminSessionMaxAge, "must not be shorter than %s (%s)", EnvAdminSessionIdleTimeout,
			c.AdminSessionIdleTimeout)
	}
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
	c.UploadMaxAge = l.duration(EnvUploadMaxAge, DefaultUploadMaxAge, minUploadMaxAge, maxUploadMaxAge)
	if c.UploadMaxAge != 0 && c.UploadTTL != 0 && c.UploadMaxAge < c.UploadTTL {
		l.fail(EnvUploadMaxAge, "must not be shorter than %s (%s)", EnvUploadTTL, c.UploadTTL)
	}
	c.DepositSessionTTL = l.duration(EnvDepositSessionTTL, DefaultDepositSessionTTL,
		minDepositSessionTTL, maxDepositSessionTTL)
	c.DeleteAfterDownloadGrace = l.duration(EnvDeleteAfterDownloadGrace, DefaultDeleteAfterDownloadGrace,
		minDeleteAfterDownloadGrace, maxDeleteAfterDownloadGrace)
	c.UploadIdleTimeout = l.duration(EnvUploadIdleTimeout, DefaultUploadIdleTimeout,
		minUploadIdleTimeout, maxUploadIdleTimeout)
	c.DownloadIdleTimeout = l.duration(EnvDownloadIdleTimeout, DefaultDownloadIdleTimeout,
		minDownloadIdleTimeout, maxDownloadIdleTimeout)
	n, err := parseInt(l.getOr(EnvMaxRecipients, DefaultMaxRecipients), minMaxRecipients, maxMaxRecipients)
	if err != nil {
		l.fail(EnvMaxRecipients, "%v", err)
	}
	c.MaxRecipients = n
	n, err = parseInt(l.getOr(EnvMaxOpenTransfers, DefaultMaxOpenTransfers), minMaxOpenTransfers, maxMaxOpenTransfers)
	if err != nil {
		l.fail(EnvMaxOpenTransfers, "%v", err)
	}
	c.MaxOpenTransfers = n
}

// loadMail reads the SMTP timeout, the mail queue capacity, the networks
// tenant SMTP servers may never resolve to and the system SMTP server. It
// must run after loadPaths.
func (l *loader) loadMail(c *Config) {
	l.loadSystemSMTP(c)
	c.SMTPTimeout = l.duration(EnvSMTPTimeout, DefaultSMTPTimeout, minSMTPTimeout, maxSMTPTimeout)
	n, err := parseInt(l.getOr(EnvMailQueueSize, DefaultMailQueueSize), minMailQueueSize, maxMailQueueSize)
	if err != nil {
		l.fail(EnvMailQueueSize, "%v", err)
	}
	c.MailQueueSize = n
	deny, err := parsePrefixes(l.getOr(EnvSMTPDenyNetworks, DefaultSMTPDenyNetworks))
	if err != nil {
		l.fail(EnvSMTPDenyNetworks, "%v", err)
	}
	c.SMTPDenyNetworks = deny
}

// loadAntivirus reads the antivirus engine and the settings of the
// selected engine (clamd: the scan size limit and timeout; icap and http:
// see loadEngines), and the number of scan workers.
func (l *loader) loadAntivirus(c *Config) {
	switch e := AntivirusEngine(strings.ToLower(l.getOr(EnvAntivirusEngine, DefaultAntivirusEngine))); e {
	case EngineClamd, EngineNone, EngineICAP, EngineHTTP:
		c.AntivirusEngine = e
	default:
		l.fail(EnvAntivirusEngine, "unknown engine %q (want %q, %q, %q or %q)", string(e),
			string(EngineClamd), string(EngineICAP), string(EngineHTTP), string(EngineNone))
	}
	l.loadEngines(c)
	n, err := parseInt64(l.getOr(EnvClamAVMaxScanBytes, DefaultClamAVMaxScanBytes),
		minClamAVMaxScanBytes, maxClamAVMaxScanBytes)
	if err != nil {
		l.fail(EnvClamAVMaxScanBytes, "%v", err)
	}
	c.ClamAVMaxScanBytes = n
	c.ClamAVTimeout = l.duration(EnvClamAVTimeout, DefaultClamAVTimeout, minClamAVTimeout, maxClamAVTimeout)
	w, err := parseInt(l.getOr(EnvScanWorkers, DefaultScanWorkers), minScanWorkers, maxScanWorkers)
	if err != nil {
		l.fail(EnvScanWorkers, "%v", err)
	}
	c.ScanWorkers = w
}

// loadMaintenance reads the time and the retention of the nightly database
// copy.
func (l *loader) loadMaintenance(c *Config) {
	t, err := parseTimeOfDay(l.getOr(EnvBackupTime, DefaultBackupTime))
	if err != nil {
		l.fail(EnvBackupTime, "%v", err)
	}
	c.BackupTime = t
	n, err := parseInt(l.getOr(EnvBackupKeep, DefaultBackupKeep), minBackupKeep, maxBackupKeep)
	if err != nil {
		l.fail(EnvBackupKeep, "%v", err)
	}
	c.BackupKeep = n
}

// loadWebhooks reads the networks of the webhook egress policy. The
// built-in deny list itself lives in internal/netpolicy: an allowed or
// plain http network overlapping its core (which can never be opened) is
// refused, and so is a plain http network inside the built-in deny list
// that TT_WEBHOOK_ALLOW_NETWORKS does not open. The networks of the
// container, also part of the core, are checked when the webhook client
// starts.
func (l *loader) loadWebhooks(c *Config) {
	ok := true
	for _, v := range []struct {
		name string
		dst  *[]netip.Prefix
	}{
		{EnvWebhookAllowNetworks, &c.WebhookAllowNetworks},
		{EnvWebhookAllowHTTPNetworks, &c.WebhookAllowHTTPNetworks},
		{EnvWebhookDenyNetworks, &c.WebhookDenyNetworks},
	} {
		p, err := parsePrefixes(l.get(v.name))
		if err != nil {
			l.fail(v.name, "%v", err)
			ok = false
		}
		*v.dst = p
	}
	if !ok {
		return
	}
	core := netpolicy.WebhookAlwaysDenyNetworks()
	if err := netpolicy.CheckWebhookAllow(c.WebhookAllowNetworks, nil, core); err != nil {
		l.fail(EnvWebhookAllowNetworks, "%v", err)
	} else if err := netpolicy.CheckWebhookAllow(c.WebhookAllowNetworks, c.WebhookAllowHTTPNetworks, core); err != nil {
		l.fail(EnvWebhookAllowHTTPNetworks, "%v (list it in %s too)", err, EnvWebhookAllowNetworks)
	}
}

// loadMetrics reads the monitoring token and its IP allowlist.
func (l *loader) loadMetrics(c *Config) {
	allowed, err := parsePrefixes(l.get(EnvMetricsAllowedIPs))
	if err != nil {
		l.fail(EnvMetricsAllowedIPs, "%v", err)
	}
	c.MetricsAllowedIPs = allowed
	token, ok := l.secret(EnvMetricsToken, EnvMetricsTokenFile)
	if !ok {
		return
	}
	if n := len(token.Reveal()); token.IsSet() && (n < minMetricsTokenLength || n > maxMetricsTokenLength) {
		l.fail(l.setName(EnvMetricsToken, EnvMetricsTokenFile), "must be between %d and %d characters long", minMetricsTokenLength, maxMetricsTokenLength)
		return
	}
	c.MetricsToken = token
}

// syslogGroup lists the TT_SYSLOG_* variables that require TT_SYSLOG_ADDR,
// with their documented default ("" if none).
var syslogGroup = []struct{ name, def string }{
	{EnvSyslogProtocol, DefaultSyslogProtocol},
	{EnvSyslogStreams, DefaultSyslogStreams},
	{EnvSyslogFacility, DefaultSyslogFacility},
	{EnvSyslogCAFile, ""},
}

// loadSyslog reads the TT_SYSLOG_* variables. Without TT_SYSLOG_ADDR the
// export is disabled and every other variable of the group set to anything
// but its documented default is refused, so that a forgotten address never
// silently disables the export (an .env.example with every default
// uncommented stays valid, as for the system SMTP server).
func (l *loader) loadSyslog(c *Config) {
	addr := l.get(EnvSyslogAddr)
	if addr == "" {
		for _, v := range syslogGroup {
			if raw := strings.ToLower(strings.TrimSpace(l.get(v.name))); raw != "" && raw != v.def {
				l.fail(v.name, "requires %s (the syslog export is disabled without it)", EnvSyslogAddr)
			}
		}
		return
	}
	s := SyslogConfig{Addr: addr}
	if err := validateHostPort(addr, true); err != nil {
		l.fail(EnvSyslogAddr, "%v", err)
	}
	s.Protocol = strings.ToLower(l.getOr(EnvSyslogProtocol, DefaultSyslogProtocol))
	switch s.Protocol {
	case SyslogProtocolUDP, SyslogProtocolTCP, SyslogProtocolTLS:
	default:
		l.fail(EnvSyslogProtocol, "%q is not supported (use %s, %s or %s)", s.Protocol,
			SyslogProtocolTLS, SyslogProtocolTCP, SyslogProtocolUDP)
	}
	streams, err := parseSyslogStreams(l.getOr(EnvSyslogStreams, DefaultSyslogStreams))
	if err != nil {
		l.fail(EnvSyslogStreams, "%v", err)
	}
	s.Streams = streams
	facility := strings.ToLower(strings.TrimSpace(l.getOr(EnvSyslogFacility, DefaultSyslogFacility)))
	code, ok := syslogFacilities[facility]
	if !ok {
		l.fail(EnvSyslogFacility, "%q is not a syslog facility (use kern, user, mail, daemon, auth, syslog, "+
			"lpr, news, uucp, cron, authpriv, ftp or local0 to local7)", facility)
	}
	s.Facility = code
	s.CAFile = l.syslogCAFile(s.Protocol)
	c.Syslog = s
}

// parseSyslogStreams parses TT_SYSLOG_STREAMS: a comma-separated list of
// SyslogStreamAudit and SyslogStreamSecurity, case-insensitive, returned
// sorted without duplicates. An unknown or empty list is an error.
func parseSyslogStreams(raw string) ([]string, error) {
	var streams []string
	for _, item := range splitList(raw) {
		item = strings.ToLower(item)
		if item != SyslogStreamAudit && item != SyslogStreamSecurity {
			return nil, fmt.Errorf("%q is not a log (use %s and/or %s)", item, SyslogStreamAudit, SyslogStreamSecurity)
		}
		if !slices.Contains(streams, item) {
			streams = append(streams, item)
		}
	}
	if len(streams) == 0 {
		return nil, fmt.Errorf("must list %s and/or %s", SyslogStreamAudit, SyslogStreamSecurity)
	}
	slices.Sort(streams)
	return streams, nil
}

// syslogCAFile reads TT_SYSLOG_CA_FILE, only allowed with the tls
// protocol: an absolute path to a readable file holding at least one PEM
// certificate. It returns the cleaned path, "" when unset or invalid.
func (l *loader) syslogCAFile(protocol string) string {
	raw := l.get(EnvSyslogCAFile)
	if raw == "" {
		return ""
	}
	if protocol != SyslogProtocolTLS {
		l.fail(EnvSyslogCAFile, "is only allowed when %s is %s", EnvSyslogProtocol, SyslogProtocolTLS)
		return ""
	}
	path, err := checkAbsPath(raw)
	if err != nil {
		l.fail(EnvSyslogCAFile, "%q %v", raw, err)
		return ""
	}
	data, err := l.readFile(path)
	if err != nil {
		l.fail(EnvSyslogCAFile, "cannot read file: %v", err)
		return ""
	}
	if !x509.NewCertPool().AppendCertsFromPEM(data) {
		l.fail(EnvSyslogCAFile, "the file holds no PEM certificate")
		return ""
	}
	return path
}

// systemSMTPPorts are the default ports of the system SMTP security modes.
var systemSMTPPorts = map[string]int{SMTPSecurityNone: 25, SMTPSecurityStartTLS: 587, SMTPSecurityTLS: 465}

// loadSystemSMTP reads the TT_SYSTEM_SMTP_* variables. Without
// TT_SYSTEM_SMTP_HOST, system mail is disabled and the variables of the
// group that have no default are refused, so that a forgotten host never
// silently disables the disk alert mail (the security mode and sender name
// may keep their documented defaults). TT_SYSTEM_SMTP_PASSWORD is always refused: the
// password only comes from a file outside the volumes.
func (l *loader) loadSystemSMTP(c *Config) {
	if l.get(EnvSystemSMTPPassword) != "" {
		l.fail(EnvSystemSMTPPassword, "is not supported: put the password in a file (for example a Docker secret) "+
			"and set %s to its path", EnvSystemSMTPPasswordFile)
	}
	host := l.get(EnvSystemSMTPHost)
	if host == "" {
		for _, name := range []string{
			EnvSystemSMTPPort, EnvSystemSMTPFrom, EnvSystemSMTPUsername, EnvSystemSMTPPasswordFile,
		} {
			if l.get(name) != "" {
				l.fail(name, "requires %s (system mail is disabled without it)", EnvSystemSMTPHost)
			}
		}
		return
	}
	s := SystemSMTP{Host: strings.TrimSuffix(strings.ToLower(host), ".")}
	if !validSMTPHost(s.Host) {
		l.fail(EnvSystemSMTPHost, "%q is not a valid host name or IP address", host)
	}
	s.Security = strings.ToLower(l.getOr(EnvSystemSMTPSecurity, DefaultSystemSMTPSecurity))
	defPort, ok := systemSMTPPorts[s.Security]
	if !ok {
		l.fail(EnvSystemSMTPSecurity, "%q is not supported (use %s, %s or %s)", s.Security,
			SMTPSecurityNone, SMTPSecurityStartTLS, SMTPSecurityTLS)
	}
	s.Port = defPort
	if raw := l.get(EnvSystemSMTPPort); raw != "" {
		if err := parsePort(raw); err != nil {
			l.fail(EnvSystemSMTPPort, "%v", err)
		} else {
			s.Port, _ = strconv.Atoi(raw) // parsePort accepted it
		}
	}
	s.From = l.get(EnvSystemSMTPFrom)
	switch {
	case s.From == "":
		l.fail(EnvSystemSMTPFrom, "is required with %s", EnvSystemSMTPHost)
	case !validMailbox(s.From):
		l.fail(EnvSystemSMTPFrom, "%q is not a bare mail address", s.From)
	}
	s.FromName = l.getOr(EnvSystemSMTPFromName, DefaultSystemSMTPFromName)
	if !validSingleLine(s.FromName, maxSMTPFromNameLen) {
		l.fail(EnvSystemSMTPFromName, "must be at most %d characters on a single line", maxSMTPFromNameLen)
	}
	s.Username = l.get(EnvSystemSMTPUsername)
	if s.Username != "" {
		if !validSingleLine(s.Username, maxSMTPUsernameLen) {
			l.fail(EnvSystemSMTPUsername, "must be at most %d characters on a single line", maxSMTPUsernameLen)
		}
		if s.Security == SMTPSecurityNone {
			l.fail(EnvSystemSMTPUsername, "is refused with %s=%s: credentials are never sent unencrypted",
				EnvSystemSMTPSecurity, SMTPSecurityNone)
		}
	}
	s.Password = l.systemSMTPPassword(c, s.Username != "")
	c.SystemSMTP = s
}

// systemSMTPPassword reads TT_SYSTEM_SMTP_PASSWORD_FILE, required if and
// only if a username is set: an absolute path outside the volumes and the
// master key files, whose content is the password, trailing line breaks
// removed (other whitespace is part of the password).
func (l *loader) systemSMTPPassword(c *Config, wanted bool) Secret {
	raw := l.get(EnvSystemSMTPPasswordFile)
	switch {
	case raw == "" && wanted:
		l.fail(EnvSystemSMTPPasswordFile, "is required with %s", EnvSystemSMTPUsername)
		return Secret{}
	case raw == "":
		return Secret{}
	case !wanted:
		l.fail(EnvSystemSMTPPasswordFile, "requires %s", EnvSystemSMTPUsername)
		return Secret{}
	}
	path, err := checkAbsPath(raw)
	if err != nil {
		l.fail(EnvSystemSMTPPasswordFile, "%q %v", raw, err)
		return Secret{}
	}
	if err := c.outsideVolumes(path, systemSMTPPasswordWhat); err != nil {
		l.fail(EnvSystemSMTPPasswordFile, "%v", err)
		return Secret{}
	}
	for _, key := range []string{c.MasterKeyFile, c.MasterKeyNewFile} {
		if key != "" && samePath(path, key) {
			l.fail(EnvSystemSMTPPasswordFile, "must not be a master key file")
			return Secret{}
		}
	}
	data, err := l.readFile(path)
	if err != nil {
		l.fail(EnvSystemSMTPPasswordFile, "cannot read file: %v", err)
		return Secret{}
	}
	value := strings.TrimRight(string(data), "\r\n")
	switch {
	case value == "":
		l.fail(EnvSystemSMTPPasswordFile, "file is empty")
		return Secret{}
	case len(value) > maxSMTPPasswordLen:
		l.fail(EnvSystemSMTPPasswordFile, "the password must be at most %d bytes", maxSMTPPasswordLen)
		return Secret{}
	}
	return NewSecret(value)
}

// validSMTPHost reports whether host is a host name or an IP address
// without zone.
func validSMTPHost(host string) bool {
	if validHostname(host) {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Zone() == ""
}

// validMailbox reports whether s is a bare mail address (no display name,
// no whitespace or control character). The application checks it again
// with the stricter rules of the mail package at startup.
func validMailbox(s string) bool {
	if len(s) > maxMailboxLen || strings.ContainsFunc(s, unicode.IsSpace) {
		return false
	}
	a, err := netmail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s
}

// validSingleLine reports whether s is valid UTF-8 of at most maxRunes
// characters without control characters or Unicode line separators, so
// that it can never inject a mail header.
func validSingleLine(s string, maxRunes int) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= maxRunes &&
		!strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == 0x2028 || r == 0x2029 })
}

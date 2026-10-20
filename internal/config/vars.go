package config

import (
	"bufio"
	"io"
	"slices"
	"strings"
)

// Environment variable names read by [Load].
const (
	EnvDBDriver                 = "TT_DB_DRIVER"
	EnvDBDSN                    = "TT_DB_DSN"
	EnvDBDSNFile                = "TT_DB_DSN_FILE"
	EnvDBMigrateDSN             = "TT_DB_MIGRATE_DSN"
	EnvDBMigrateDSNFile         = "TT_DB_MIGRATE_DSN_FILE"
	EnvDataDir                  = "TT_DATA_DIR"
	EnvBackupDir                = "TT_BACKUP_DIR"
	EnvLogDir                   = "TT_LOG_DIR"
	EnvMasterKeyFile            = "TT_MASTER_KEY_FILE"
	EnvMasterKeyNewFile         = "TT_MASTER_KEY_NEW_FILE"
	EnvTrustedProxies           = "TT_TRUSTED_PROXIES"
	EnvListenAddr               = "TT_LISTEN_ADDR"
	EnvLogLevel                 = "TT_LOG_LEVEL"
	EnvMaintenance              = "TT_MAINTENANCE"
	EnvAdminHosts               = "TT_ADMIN_HOSTS"
	EnvAPIDocsPublic            = "TT_API_DOCS_PUBLIC"
	EnvSetupToken               = "TT_SETUP_TOKEN"      //nolint:gosec // G101: variable name, not a credential
	EnvSetupTokenFile           = "TT_SETUP_TOKEN_FILE" //nolint:gosec // G101: variable name, not a credential
	EnvUploadTTL                = "TT_UPLOAD_TTL"
	EnvUploadMaxAge             = "TT_UPLOAD_MAX_AGE"
	EnvDepositSessionTTL        = "TT_DEPOSIT_SESSION_TTL"
	EnvDeleteAfterDownloadGrace = "TT_DELETE_AFTER_DOWNLOAD_GRACE"
	EnvUploadIdleTimeout        = "TT_UPLOAD_IDLE_TIMEOUT"
	EnvMaxRecipients            = "TT_MAX_RECIPIENTS"
	EnvMaxOpenTransfers         = "TT_MAX_OPEN_TRANSFERS"
	EnvClamAVAddr               = "TT_CLAMAV_ADDR"
	EnvSMTPTimeout              = "TT_SMTP_TIMEOUT"
	EnvMailQueueSize            = "TT_MAIL_QUEUE_SIZE"
)

// Default values applied by [Load] when a variable is unset or empty.
const (
	DefaultDBDriver                 = DriverSQLite
	DefaultSQLiteDSN                = "/var/lib/transteira/db/transteira.db"
	DefaultDataDir                  = "/var/lib/transteira/data"
	DefaultBackupDir                = "/var/lib/transteira/backups"
	DefaultLogDir                   = "/var/log/transteira"
	DefaultListenAddr               = ":8080"
	DefaultLogLevel                 = "info"
	DefaultUploadTTL                = "24h"
	DefaultUploadMaxAge             = "168h"
	DefaultDepositSessionTTL        = "4h"
	DefaultDeleteAfterDownloadGrace = "15m"
	DefaultUploadIdleTimeout        = "60s"
	DefaultMaxRecipients            = "50"
	DefaultMaxOpenTransfers         = "10"
	DefaultClamAVAddr               = "clamav:3310"
	DefaultSMTPTimeout              = "30s"
	DefaultMailQueueSize            = "1000"
)

// envPrefix is the prefix shared by every TransTeira variable.
const envPrefix = "TT_"

// Var documents one environment variable. [Variables] is the single source of
// truth used to generate .env.example.
type Var struct {
	// Name is the environment variable name.
	Name string
	// Group is the .env.example section the variable belongs to.
	Group string
	// Default is the value used when the variable is unset ("" if none).
	Default string
	// Example is the value written uncommented in .env.example for required
	// variables ("" for optional ones).
	Example string
	// Description explains the variable in English.
	Description string
	// Required is true when Load fails if the variable is missing.
	Required bool
	// Secret is true when the value is sensitive and must never be logged.
	Secret bool
}

// Variables returns the documentation of every environment variable read by
// [Load], in .env.example order.
func Variables() []Var {
	return []Var{
		{
			Name: EnvDBDriver, Group: "Database", Default: DefaultDBDriver,
			Description: "Database engine: sqlite (default, single instance) or postgres.",
		},
		{
			Name: EnvDBDSN, Group: "Database", Default: DefaultSQLiteDSN, Secret: true,
			Description: "Database connection string. For sqlite, the path of the database file " +
				"(default shown). Required for postgres, e.g. " +
				"postgres://transteira:password@postgres:5432/transteira?sslmode=disable. " +
				"Mutually exclusive with " + EnvDBDSNFile + ".",
		},
		{
			Name: EnvDBDSNFile, Group: "Database",
			Description: "Path of a file (e.g. a Docker secret) containing the database connection " +
				"string. Preferred over " + EnvDBDSN + " for postgres since it keeps the password " +
				"out of the environment.",
		},
		{
			Name: EnvDBMigrateDSN, Group: "Database", Secret: true,
			Description: "PostgreSQL only (refused with sqlite): connection string of the owner " +
				"role, used only to apply migrations and grant DML rights to the runtime role. " +
				"Needed only by the process that applies migrations (transteira migrate, or serve " +
				"when it migrates at startup); migrations fail with a clear error when it is " +
				"absent. Prefer a one-shot migrate container so that the long-running server " +
				"never holds the owner credentials. " + EnvDBDSN + " must use a different role " +
				"that owns no table, is not superuser and has no BYPASSRLS, so that it cannot " +
				"disable row-level security. Mutually exclusive with " + EnvDBMigrateDSNFile + ".",
		},
		{
			Name: EnvDBMigrateDSNFile, Group: "Database",
			Description: "Path of a file (e.g. a Docker secret) containing the migration connection " +
				"string (alternative to " + EnvDBMigrateDSN + ").",
		},
		{
			Name: EnvDataDir, Group: "Storage", Default: DefaultDataDir,
			Description: "Absolute path of the volume holding the encrypted uploaded files " +
				"(one sub-directory per tenant).",
		},
		{
			Name: EnvBackupDir, Group: "Storage", Default: DefaultBackupDir,
			Description: "Absolute path of the volume receiving the regular database backups " +
				"(VACUUM INTO or pg_dump).",
		},
		{
			Name: EnvLogDir, Group: "Storage", Default: DefaultLogDir,
			Description: "Absolute path of the directory holding the security log read by " +
				"fail2ban or CrowdSec.",
		},
		{
			Name: EnvMasterKeyFile, Group: "Encryption", Required: true,
			Example: "/run/secrets/transteira_master_key",
			Description: "Absolute path of the file containing the master key (e.g. a Docker " +
				"secret). It must NOT be located inside the data, backup or log directories, " +
				"nor in the folder of the SQLite database. " +
				"Keep a copy of the key in a password vault outside the VM: without it, " +
				"files and backups cannot be decrypted. See docs/operations/master-key.md.",
		},
		{
			Name: EnvMasterKeyNewFile, Group: "Encryption",
			Description: "Absolute path of the new master key during a rotation: set it and " +
				"restart, run rotate-master-key, then move the new key to " + EnvMasterKeyFile +
				" and remove this variable. Same location rules as " + EnvMasterKeyFile +
				", and it must differ from it. See docs/operations/master-key.md.",
		},
		{
			Name: EnvTrustedProxies, Group: "Network",
			Description: "Comma-separated list of IP addresses or CIDR prefixes of the trusted " +
				"reverse proxies. X-Forwarded-For / X-Real-IP are only honored for requests " +
				"coming from these addresses. List the reverse proxies by their exact IP " +
				"address: every host inside a trusted range can forge the client IP. Startup " +
				"fails on an IPv4 prefix shorter than /8, an IPv6 prefix shorter than /32, or " +
				"prefixes that together cover the whole IPv4 or IPv6 space; a warning is " +
				"logged for prefixes wider than /24 (IPv4) or /64 (IPv6). A trusted proxy " +
				"must never sit inside a tenant's internal IP range. A request from a trusted " +
				"proxy without a valid X-Forwarded-For / X-Real-IP is treated as coming from " +
				"an unknown client (fail closed). Empty means no proxy is trusted.",
		},
		{
			Name: EnvListenAddr, Group: "Network", Default: DefaultListenAddr,
			Description: "Address (host:port) the HTTP server listens on inside the container.",
		},
		{
			Name: EnvAdminHosts, Group: "Network",
			Description: "Comma-separated list of host names from which the administration is " +
				"reachable. Empty means every tenant host.",
		},
		{
			Name: EnvClamAVAddr, Group: "Antivirus", Default: DefaultClamAVAddr,
			Description: "Address of the clamd daemon: host:port, or unix:/absolute/path for a " +
				"Unix socket.",
		},
		{
			Name: EnvSMTPTimeout, Group: "Mail", Default: DefaultSMTPTimeout,
			Description: "Time limit of one SMTP delivery attempt, from connection to the end of " +
				"the message (Go duration, between 1s and 5m). Mails are sent in the background " +
				"and retried once, so a slow server never delays a request.",
		},
		{
			Name: EnvMailQueueSize, Group: "Mail", Default: DefaultMailQueueSize,
			Description: "Capacity of the in-memory queue of mails waiting to be sent (between 1 " +
				"and 100000). When it is full, requests that send a mail (verification codes, " +
				"invitations) are answered 429 Too Many Requests.",
		},
		{
			Name: EnvLogLevel, Group: "Logging", Default: DefaultLogLevel,
			Description: "Application log level: debug, info, warn or error.",
		},
		{
			Name: EnvMaintenance, Group: "Operations", Default: "false",
			Description: "Start in maintenance mode (true/false/1/0): new deposits are refused, " +
				"the health check keeps answering.",
		},
		{
			Name: EnvAPIDocsPublic, Group: "Operations", Default: "false",
			Description: "Serve the interactive API documentation to anonymous visitors " +
				"(true/false/1/0). By default it is reserved to authenticated admins.",
		},
		{
			Name: EnvSetupToken, Group: "Operations", Secret: true,
			Description: "Optional token (16 to 128 characters) required to create the first " +
				"super admin, protecting the window between deployment and setup. Mutually " +
				"exclusive with " + EnvSetupTokenFile + ".",
		},
		{
			Name: EnvSetupTokenFile, Group: "Operations",
			Description: "Path of a file containing the setup token (alternative to " +
				EnvSetupToken + ").",
		},
		{
			Name: EnvUploadTTL, Group: "Uploads", Default: DefaultUploadTTL,
			Description: "Time after which an unfinished resumable upload is discarded " +
				"(Go duration, between 1h and 168h).",
		},
		{
			Name: EnvUploadMaxAge, Group: "Uploads", Default: DefaultUploadMaxAge,
			Description: "Longest life of an unfinished upload after the creation of its transfer, " +
				"whatever its activity, so that an upload kept alive by tiny requests cannot hold " +
				"the storage quota forever (Go duration, between 24h and 2160h, and at least " +
				EnvUploadTTL + ").",
		},
		{
			Name: EnvDepositSessionTTL, Group: "Uploads", Default: DefaultDepositSessionTTL,
			Description: "Lifetime of a deposit session after e-mail verification " +
				"(Go duration, between 15m and 24h).",
		},
		{
			Name: EnvDeleteAfterDownloadGrace, Group: "Uploads",
			Default: DefaultDeleteAfterDownloadGrace,
			Description: "Grace period before a delete-after-first-download transfer is erased, " +
				"so that an interrupted download can be resumed (Go duration, between 0s and 24h).",
		},
		{
			Name: EnvUploadIdleTimeout, Group: "Uploads", Default: DefaultUploadIdleTimeout,
			Description: "Longest wait between two reads of an upload request body before the " +
				"server cuts the connection; reset by every read, so that slow but active " +
				"uploads continue (Go duration, between 5s and 10m).",
		},
		{
			Name: EnvMaxRecipients, Group: "Uploads", Default: DefaultMaxRecipients,
			Description: "Largest number of recipients of one transfer (anti-spam ceiling, " +
				"between 1 and 100).",
		},
		{
			Name: EnvMaxOpenTransfers, Group: "Uploads", Default: DefaultMaxOpenTransfers,
			Description: "Largest number of unfinished (not yet finalized) transfers one internal " +
				"sender may have at once, so that abandoned transfers cannot hold the storage " +
				"quota (between 1 and 1000). Invited external senders are limited to 3.",
		},
	}
}

// commentWidth is the line width used to wrap descriptions in .env.example.
const commentWidth = 78

// WriteEnvExample writes a commented .env.example generated from [Variables].
// Required variables are written uncommented with their example value; other
// variables are commented out with their default value.
func WriteEnvExample(w io.Writer) error {
	bw := bufio.NewWriter(w)
	rule := "# " + strings.Repeat("=", commentWidth-2) + "\n"
	write := func(s string) { _, _ = bw.WriteString(s) } // errors surface in Flush
	write("# TransTeira configuration (generated from internal/config, do not edit by hand).\n")
	write("# Copy this file to .env and adjust the values. Durations use Go syntax (15m, 4h, 168h).\n")
	write("# Tenant-specific settings (branding, SMTP, IP ranges...) live in the database and are\n")
	write("# managed from the administration, not here.\n")
	group := ""
	for _, v := range Variables() {
		if v.Group != group {
			group = v.Group
			write("\n" + rule + "# " + group + "\n" + rule)
		}
		write("\n")
		for _, line := range wrap(v.Description, commentWidth-2) {
			write("# " + line + "\n")
		}
		switch {
		case v.Required:
			write("# Required.\n")
		case v.Default != "":
			write("# Default: " + v.Default + "\n")
		}
		if v.Secret {
			write("# Secret: never commit a real value.\n")
		}
		if v.Required {
			write(v.Name + "=" + v.Example + "\n")
		} else {
			write("# " + v.Name + "=" + v.Default + "\n")
		}
	}
	return bw.Flush()
}

// wrap splits text into lines of at most width characters, breaking on
// spaces. Words longer than width are kept whole.
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// UnknownVariables returns, sorted, the names of the TT_ variables present in
// environ (in os.Environ "NAME=value" form) that TransTeira does not know.
// It helps operators spot typos such as TT_TRUSTED_PROXY.
func UnknownVariables(environ []string) []string {
	known := make(map[string]bool)
	for _, v := range Variables() {
		known[v.Name] = true
	}
	var unknown []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, envPrefix) && !known[name] && !slices.Contains(unknown, name) {
			unknown = append(unknown, name)
		}
	}
	slices.Sort(unknown)
	return unknown
}

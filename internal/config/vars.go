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
	EnvAdminSessionIdleTimeout  = "TT_ADMIN_SESSION_IDLE_TIMEOUT"
	EnvAdminSessionMaxAge       = "TT_ADMIN_SESSION_MAX_AGE"
	EnvAPIDocsPublic            = "TT_API_DOCS_PUBLIC"
	EnvSetupToken               = "TT_SETUP_TOKEN"      //nolint:gosec // G101: variable name, not a credential
	EnvSetupTokenFile           = "TT_SETUP_TOKEN_FILE" //nolint:gosec // G101: variable name, not a credential
	EnvUploadTTL                = "TT_UPLOAD_TTL"
	EnvUploadMaxAge             = "TT_UPLOAD_MAX_AGE"
	EnvDepositSessionTTL        = "TT_DEPOSIT_SESSION_TTL"
	EnvDeleteAfterDownloadGrace = "TT_DELETE_AFTER_DOWNLOAD_GRACE"
	EnvUploadIdleTimeout        = "TT_UPLOAD_IDLE_TIMEOUT"
	EnvDownloadIdleTimeout      = "TT_DOWNLOAD_IDLE_TIMEOUT"
	EnvMaxRecipients            = "TT_MAX_RECIPIENTS"
	EnvMaxOpenTransfers         = "TT_MAX_OPEN_TRANSFERS"
	EnvClamAVAddr               = "TT_CLAMAV_ADDR"
	EnvClamAVMaxScanBytes       = "TT_CLAMAV_MAX_SCAN_BYTES"
	EnvClamAVTimeout            = "TT_CLAMAV_TIMEOUT"
	EnvScanWorkers              = "TT_SCAN_WORKERS"
	EnvSMTPTimeout              = "TT_SMTP_TIMEOUT"
	EnvMailQueueSize            = "TT_MAIL_QUEUE_SIZE"
	EnvSMTPDenyNetworks         = "TT_SMTP_DENY_NETWORKS"
	EnvSystemSMTPHost           = "TT_SYSTEM_SMTP_HOST"
	EnvSystemSMTPPort           = "TT_SYSTEM_SMTP_PORT"
	EnvSystemSMTPSecurity       = "TT_SYSTEM_SMTP_SECURITY"
	EnvSystemSMTPFrom           = "TT_SYSTEM_SMTP_FROM"
	EnvSystemSMTPFromName       = "TT_SYSTEM_SMTP_FROM_NAME"
	EnvSystemSMTPUsername       = "TT_SYSTEM_SMTP_USERNAME"
	EnvSystemSMTPPassword       = "TT_SYSTEM_SMTP_PASSWORD"      //nolint:gosec // G101: variable name, not a credential
	EnvSystemSMTPPasswordFile   = "TT_SYSTEM_SMTP_PASSWORD_FILE" //nolint:gosec // G101: variable name, not a credential
	EnvBackupTime               = "TT_BACKUP_TIME"
	EnvBackupKeep               = "TT_BACKUP_KEEP"
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
	DefaultAdminSessionIdleTimeout  = "30m"
	DefaultAdminSessionMaxAge       = "12h"
	DefaultUploadTTL                = "24h"
	DefaultUploadMaxAge             = "168h"
	DefaultDepositSessionTTL        = "4h"
	DefaultDeleteAfterDownloadGrace = "15m"
	DefaultUploadIdleTimeout        = "60s"
	DefaultDownloadIdleTimeout      = "60s"
	DefaultMaxRecipients            = "50"
	DefaultMaxOpenTransfers         = "10"
	DefaultClamAVAddr               = "clamav:3310"
	DefaultClamAVMaxScanBytes       = "2147483648"
	DefaultClamAVTimeout            = "10m"
	DefaultScanWorkers              = "2"
	DefaultSMTPTimeout              = "30s"
	DefaultMailQueueSize            = "1000"
	DefaultSystemSMTPSecurity       = SMTPSecurityStartTLS
	DefaultSystemSMTPFromName       = "TransTeira"
	DefaultBackupTime               = "02:30"
	DefaultBackupKeep               = "7"
)

// DefaultSMTPDenyNetworks lists the networks a tenant SMTP server may never
// resolve to: loopback, link-local (including the cloud metadata addresses
// 169.254.169.254 and fd00:ec2::254), the Alibaba Cloud metadata address
// 100.100.100.200 (only that address: the rest of the shared address space
// 100.64.0.0/10 is used by carrier-grade NAT and overlay networks), "this
// network", and the IPv4-compatible IPv6 addresses ::/96, which include the
// unspecified address. Private ranges stay allowed for internal relays
// (§12.1).
const DefaultSMTPDenyNetworks = "127.0.0.0/8,::1/128,169.254.0.0/16,fe80::/10," +
	"fd00:ec2::254/128,100.100.100.200/32,0.0.0.0/8,::/96"

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
				"(VACUUM INTO or pg_dump). It must be separate from " + EnvDataDir + ", " + EnvLogDir +
				" and the folder of the SQLite database (neither inside nor containing them), and must " +
				"not contain \"?\" or \"#\".",
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
			Name: EnvAdminHosts, Group: "Administration", Required: true,
			Example: "admin.transfer.example.com",
			Description: "Comma-separated list of the dedicated host names serving the " +
				"administration, for example admin.transfer.example.com. The administration " +
				"is served only on these hosts, never on tenant FQDNs: a host listed here must " +
				"not be the FQDN of a tenant. Put the reverse proxy in front of it with TLS, " +
				"like the tenant hosts.",
		},
		{
			Name: EnvAdminSessionIdleTimeout, Group: "Administration", Default: DefaultAdminSessionIdleTimeout,
			Description: "Inactivity after which an admin session ends; every authenticated " +
				"request resets it (Go duration, between 5m and 4h).",
		},
		{
			Name: EnvAdminSessionMaxAge, Group: "Administration", Default: DefaultAdminSessionMaxAge,
			Description: "Longest life of an admin session after sign-in, whatever its activity " +
				"(Go duration, between 1h and 168h, and at least " + EnvAdminSessionIdleTimeout + ").",
		},
		{
			Name: EnvClamAVAddr, Group: "Antivirus", Default: DefaultClamAVAddr,
			Description: "Address of the clamd daemon: host:port, or unix:/absolute/path for a " +
				"Unix socket.",
		},
		{
			Name: EnvClamAVMaxScanBytes, Group: "Antivirus", Default: DefaultClamAVMaxScanBytes,
			Description: "Largest file size, in bytes, sent to clamd for analysis (between " +
				"1048576 and 4294967295; default 2 GiB). Larger files are accepted without " +
				"analysis, and the sender and recipients are told so. Align clamd's " +
				"StreamMaxLength, MaxScanSize and MaxFileSize on this value: a file clamd " +
				"refuses as too large is treated the same way.",
		},
		{
			Name: EnvClamAVTimeout, Group: "Antivirus", Default: DefaultClamAVTimeout,
			Description: "Time limit of the analysis of one file by clamd (Go duration, between " +
				"10s and 2h). A stalled exchange is also cut after one minute without progress. " +
				"A timed-out analysis counts against the file and is retried later; the file stays " +
				"unavailable meanwhile, and after 3 timeouts it is withheld for good (scan_error).",
		},
		{
			Name: EnvScanWorkers, Group: "Antivirus", Default: DefaultScanWorkers,
			Description: "Number of antivirus workers (between 1 and 16). Each worker analyzes " +
				"one file at a time; a transfer is never analyzed by two workers at once. Keep it at " +
				"or below clamd's MaxThreads (10 by default): otherwise scans queued by clamd may " +
				"time out and count against their files.",
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
			Name: EnvSMTPDenyNetworks, Group: "Mail", Default: DefaultSMTPDenyNetworks,
			Description: "Comma-separated list of IP addresses or CIDR prefixes that a tenant SMTP " +
				"server may never resolve to, checked on the address resolved at connection " +
				"time (protection against server-side request forgery and DNS rebinding). The " +
				"default denies loopback, link-local (including the cloud metadata addresses " +
				"169.254.169.254 and fd00:ec2::254, and 100.100.100.200 on Alibaba Cloud), " +
				"0.0.0.0/8 and the IPv4-compatible IPv6 addresses ::/96 (including the " +
				"unspecified address ::). " +
				"Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are NOT denied by " +
				"default, so that an SMTP relay on the internal Docker network keeps working; " +
				"consider adding the networks of the database and ClamAV containers. A value " +
				"replaces the default entirely: to extend it, repeat the default list and append " +
				"your networks, e.g. " + DefaultSMTPDenyNetworks + ",172.20.0.0/16.",
		},
		{
			Name: EnvSystemSMTPHost, Group: "Mail",
			Description: "Host name or IP address of the SMTP server of the instance mails (the disk " +
				"alert sent to the super admins), distinct from the SMTP servers of the entities, " +
				"which are set in the administration. Empty (default): system mail is disabled and " +
				"the disk alert is only shown in the administration, the audit log and the " +
				"application log; " + EnvSystemSMTPPort + ", " + EnvSystemSMTPFrom + ", " +
				EnvSystemSMTPUsername + " and " + EnvSystemSMTPPasswordFile + " are then refused. As an installation setting it may be a relay on " +
				"loopback or on the internal Docker network: " + EnvSMTPDenyNetworks + " does not apply.",
		},
		{
			Name: EnvSystemSMTPPort, Group: "Mail",
			Description: "Port of the system SMTP server (1 to 65535). Default: 25 with security none, " +
				"587 with starttls, 465 with tls.",
		},
		{
			Name: EnvSystemSMTPSecurity, Group: "Mail", Default: DefaultSystemSMTPSecurity,
			Description: "Encryption of the system SMTP connection: none (unauthenticated relay on " +
				"the internal network only), starttls or tls (implicit TLS).",
		},
		{
			Name: EnvSystemSMTPFrom, Group: "Mail",
			Description: "Bare sender address of the system mails, e.g. transteira@example.com. " +
				"Required with " + EnvSystemSMTPHost + ".",
		},
		{
			Name: EnvSystemSMTPFromName, Group: "Mail", Default: DefaultSystemSMTPFromName,
			Description: "Display name of the sender of the system mails (at most 100 characters).",
		},
		{
			Name: EnvSystemSMTPUsername, Group: "Mail",
			Description: "User name of the system SMTP server, empty for an unauthenticated relay. " +
				"Refused with security none; requires " + EnvSystemSMTPPasswordFile + ".",
		},
		{
			Name: EnvSystemSMTPPasswordFile, Group: "Mail",
			Description: "Path of a file (e.g. a Docker secret) containing the password of the system " +
				"SMTP server, required if and only if " + EnvSystemSMTPUsername + " is set. Absolute, " +
				"outside the data, backup and log volumes and the database folder (like the master " +
				"key); trailing line breaks are removed.",
		},
		{
			Name: EnvSystemSMTPPassword, Group: "Mail", Secret: true,
			Description: "Not supported: setting it stops the startup. The password of the system " +
				"SMTP server is only read from " + EnvSystemSMTPPasswordFile + ", so that it never " +
				"appears in the environment.",
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
			Description: "Serve the interactive API documentation (/api/docs) to anonymous visitors " +
				"on the tenant FQDNs (true/false/1/0). By default it is only served on the admin " +
				"host, to authenticated admins.",
		},
		{
			Name: EnvSetupToken, Group: "Operations", Secret: true,
			Description: "Token (16 to 128 characters) required to create the first super " +
				"admin, protecting the window between deployment and setup. When neither this " +
				"variable nor " + EnvSetupTokenFile + " is set, TransTeira generates a random " +
				"setup token at each start while no admin exists and prints it in the container " +
				"logs (docker logs). Mutually exclusive with " + EnvSetupTokenFile + ".",
		},
		{
			Name: EnvSetupTokenFile, Group: "Operations",
			Description: "Path of a file (e.g. a Docker secret) containing the setup token " +
				"(alternative to " + EnvSetupToken + "). When neither is set, a random token is " +
				"generated at each start while no admin exists and printed in the container logs.",
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
				"(Go duration, between 15m and 24h). It is not extended by activity and " +
				"every upload request needs a live session: at 4h, a 20 GB transfer needs " +
				"about 11 Mbit/s of upload bandwidth; raise it for slow links.",
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
		{
			Name: EnvDownloadIdleTimeout, Group: "Downloads", Default: DefaultDownloadIdleTimeout,
			Description: "Longest wait for a client to accept the next part of a download before the " +
				"server cuts the connection; reset by every write, so that slow but active " +
				"downloads continue (Go duration, between 5s and 10m).",
		},
		{
			Name: EnvBackupTime, Group: "Maintenance", Default: DefaultBackupTime,
			Description: "UTC time of day (HH:MM, 24-hour clock) of the nightly copy of the database. " +
				"SQLite only: the copy is written into " + EnvBackupDir + ". With PostgreSQL, a " +
				"dedicated backup container runs pg_dump instead (see docs/operations/backup.md).",
		},
		{
			Name: EnvBackupKeep, Group: "Maintenance", Default: DefaultBackupKeep,
			Description: "Number of nightly database copies kept, the oldest being deleted first " +
				"(between 1 and 90). A copy keeps the wrapped keys of the files present that day, " +
				"so cryptographic erasure reaches the copies only once the oldest copy holding a " +
				"key is rotated out (or after a master key rotation).",
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

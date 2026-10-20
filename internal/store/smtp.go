package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// SMTPSecurity is the transport security of a tenant's SMTP server.
type SMTPSecurity string

// SMTP transport security modes (OpenAPI SmtpSecurity).
const (
	// SMTPSecurityNone is a plain connection, intended for an
	// unauthenticated relay on the internal Docker network.
	SMTPSecurityNone SMTPSecurity = "none"
	// SMTPSecuritySTARTTLS upgrades a plain connection with STARTTLS.
	SMTPSecuritySTARTTLS SMTPSecurity = "starttls"
	// SMTPSecurityTLS is implicit TLS (SMTPS).
	SMTPSecurityTLS SMTPSecurity = "tls"
)

// Length limits of the SMTP settings, in characters (OpenAPI SmtpSettings).
const (
	maxSMTPHostLen     = 253
	maxSMTPUsernameLen = 320
	maxSMTPFromNameLen = 100
	maxPort            = 65535
)

// smtpColumns is the column list read by the SMTP settings queries.
const smtpColumns = `host, port, security, username, password_key_id, from_address, from_name, updated_at`

// Statements of the SMTPSettings repository.
var (
	qSMTPGet = tenantQuery(
		`SELECT ` + smtpColumns + ` FROM tenant_smtp_settings WHERE tenant_id = ?`)
	qSMTPUpdate = tenantQuery(
		`UPDATE tenant_smtp_settings SET host = ?, port = ?, security = ?, username = ?, password_key_id = ?,
		from_address = ?, from_name = ?, updated_at = ? WHERE tenant_id = ?`)
	qSMTPInsert = tenantQuery(
		`INSERT INTO tenant_smtp_settings (tenant_id, host, port, security, username, password_key_id,
		from_address, from_name, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
)

// SMTPConfig is the SMTP configuration of a tenant (spec 12.1). The
// password is never held here: PasswordKeyID references the wrapped secret
// (purpose KeyPurposeSecret) sealed by the master key vault.
type SMTPConfig struct {
	// Host is the SMTP server: a host name, a Docker service name or an IP
	// address (1 to 253 characters among letters, digits, ".", "-", "_"
	// and ":").
	Host string
	// Port is the TCP port (1 to 65535).
	Port int
	// Security is the transport security mode.
	Security SMTPSecurity
	// Username is the authentication user, "" without authentication (at
	// most 320 bytes, no control character). Authentication requires
	// SMTPSecuritySTARTTLS or SMTPSecurityTLS.
	Username string
	// PasswordKeyID is the wrapped secret holding the password ("wk_" +
	// ULID), "" without password. It must be a secret of the same tenant
	// and requires a Username.
	// Deleting that wrapped key clears it.
	PasswordKeyID string
	// FromAddress is the sender address: a bare address in the restricted
	// syntax of mail.ParseAddress (see validMailbox), stored normalized.
	FromAddress string
	// FromName is the sender display name, "" for none (at most 100
	// characters, no control character).
	FromName string
	// UpdatedAt is the time of the last change; the store's clock is used
	// when it is zero.
	UpdatedAt time.Time
}

// SMTPSettings is the tenant-scoped repository of SMTP configurations, one
// per tenant. Obtain it with [DB.SMTPSettings].
type SMTPSettings struct {
	db *DB
}

// SMTPSettings returns the SMTP settings repository.
func (db *DB) SMTPSettings() *SMTPSettings { return &SMTPSettings{db: db} }

// validSMTPHost reports whether h looks like a host name, a Docker service
// name or an IP address, without any character that could break a dial
// address or a log line.
func validSMTPHost(h string) bool {
	if h == "" || len(h) > maxSMTPHostLen {
		return false
	}
	return strings.Trim(h, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:") == ""
}

// normalizeSMTP validates c and returns it with its sender address
// normalized and its timestamp set.
func (r *SMTPSettings) normalizeSMTP(c SMTPConfig) (SMTPConfig, error) {
	switch c.Security {
	case SMTPSecurityNone, SMTPSecuritySTARTTLS, SMTPSecurityTLS:
	default:
		return SMTPConfig{}, invalid("unknown smtp security mode")
	}
	switch {
	case !validSMTPHost(c.Host):
		return SMTPConfig{}, invalid("malformed smtp host")
	case c.Port < 1 || c.Port > maxPort:
		return SMTPConfig{}, invalid("smtp port must be between 1 and %d", maxPort)
	case len(c.Username) > maxSMTPUsernameLen || !validText(c.Username, maxSMTPUsernameLen, true):
		return SMTPConfig{}, invalid("smtp username must be text of at most %d bytes", maxSMTPUsernameLen)
	case c.Username != "" && c.Security == SMTPSecurityNone:
		// The credentials would cross the network in clear text.
		return SMTPConfig{}, invalid("smtp authentication requires starttls or tls")
	case !validText(c.FromName, maxSMTPFromNameLen, true):
		return SMTPConfig{}, invalid("sender name must be text of at most %d characters", maxSMTPFromNameLen)
	case c.PasswordKeyID != "" && !id.Valid(id.WrappedKey, c.PasswordKeyID):
		return SMTPConfig{}, invalid("malformed password key id")
	case c.PasswordKeyID != "" && c.Username == "":
		return SMTPConfig{}, invalid("an smtp password requires a username")
	}
	if !validMailbox(strings.TrimSpace(c.FromAddress)) {
		return SMTPConfig{}, invalid("malformed sender address")
	}
	from, err := NormalizeEmail(c.FromAddress)
	if err != nil {
		return SMTPConfig{}, invalid("malformed sender address")
	}
	c.FromAddress = from
	c.UpdatedAt = r.db.orNow(c.UpdatedAt)
	return c, nil
}

// Get returns the SMTP configuration of tenant tid, or ErrNotFound when it
// has none (or the tenant does not exist).
func (r *SMTPSettings) Get(ctx context.Context, tid tenant.ID) (SMTPConfig, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return SMTPConfig{}, err
	}
	var c SMTPConfig
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		var err error
		c, err = getSMTP(ctx, tx)
		return err
	})
	if err != nil {
		return SMTPConfig{}, wrap("get smtp settings", err)
	}
	return c, nil
}

// GetTx returns the SMTP configuration of the tenant tx is bound to, inside
// tx (for example to find the password key a [SMTPSettings.PutTx] is about
// to replace). It returns ErrNotFound when the tenant has none.
func (r *SMTPSettings) GetTx(ctx context.Context, tx *ScopedTx) (SMTPConfig, error) {
	c, err := getSMTP(ctx, tx)
	if err != nil {
		return SMTPConfig{}, wrap("get smtp settings", err)
	}
	return c, nil
}

// getSMTP reads the configuration in tx, returning raw errors.
func getSMTP(ctx context.Context, tx *ScopedTx) (SMTPConfig, error) {
	var (
		c       SMTPConfig
		sec     string
		keyID   sql.NullString
		updated int64
	)
	err := tx.QueryRow(ctx, qSMTPGet).Scan(&c.Host, &c.Port, &sec, &c.Username, &keyID,
		&c.FromAddress, &c.FromName, &updated)
	if err != nil {
		return SMTPConfig{}, err
	}
	c.Security = SMTPSecurity(sec)
	c.PasswordKeyID = keyID.String
	c.UpdatedAt = fromMillis(updated)
	return c, nil
}

// Put creates or replaces the SMTP configuration of tenant tid in its own
// transaction (see [SMTPSettings.PutTx]).
func (r *SMTPSettings) Put(ctx context.Context, tid tenant.ID, c SMTPConfig) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if err := s.Tx(ctx, func(tx *ScopedTx) error { return r.put(ctx, tx, c) }); err != nil {
		return wrap("put smtp settings", err)
	}
	return nil
}

// PutTx creates or replaces the SMTP configuration of the tenant tx is
// bound to, inside tx, so that a new password secret, the configuration and
// the erasure of the previous secret can be committed together. It returns
// ErrInvalid for a malformed field, and ErrNotFound when the tenant does not
// exist or when PasswordKeyID is not a secret of this tenant. The previous
// password key, if any, is left to the caller to delete. After an error,
// the caller must abort the transaction.
func (r *SMTPSettings) PutTx(ctx context.Context, tx *ScopedTx, c SMTPConfig) error {
	if err := r.put(ctx, tx, c); err != nil {
		return wrap("put smtp settings", err)
	}
	return nil
}

// put validates and upserts c in tx, returning raw errors.
func (r *SMTPSettings) put(ctx context.Context, tx *ScopedTx, c SMTPConfig) error {
	c, err := r.normalizeSMTP(c)
	if err != nil {
		return err
	}
	if c.PasswordKeyID != "" {
		// The foreign key only checks that the key exists: the tenant-scoped
		// read also proves it belongs to this tenant.
		k, err := scanWrappedKey(tx.QueryRow(ctx, qWrappedKeyGet, c.PasswordKeyID))
		if err != nil {
			return err
		}
		if k.Purpose != KeyPurposeSecret {
			return invalid("password key is not a secret")
		}
	}
	args := []any{
		c.Host, c.Port, string(c.Security), c.Username, nullText(c.PasswordKeyID),
		c.FromAddress, c.FromName, toMillis(c.UpdatedAt),
	}
	return upsert(ctx, tx, qSMTPUpdate, args, qSMTPInsert, args)
}

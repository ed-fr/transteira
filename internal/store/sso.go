package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Limits of the single sign-on configuration (OpenAPI TenantSso,
// migration 0027).
const (
	// MaxSSODomains bounds the e-mail domains routed to one configuration.
	MaxSSODomains = 20
	// MinSSOIssuerLen and MaxSSOIssuerLen bound the issuer URL, in bytes.
	MinSSOIssuerLen = 9
	MaxSSOIssuerLen = 512
	// MaxSSOClientIDLen bounds the client ID, in bytes.
	MaxSSOClientIDLen = 255
	// maxSSODomainLen bounds a stored domain (DNS limit).
	maxSSODomainLen = 253
	// maxSSOUpdatedByLen bounds updated_by (an admin ID).
	maxSSOUpdatedByLen = 64
)

// Reasons of the single sign-on system queries.
const (
	reasonSSOLogin  = "single sign-on login: route an e-mail domain to its tenant configuration (no tenant yet)"
	reasonSSOAccess = "single sign-on session scope: configurations of the tenants of an administrator"
)

// ssoColumns is the column list read by the tenant-scoped SSO queries (the
// tenant is the scope's); ssoSystemColumns adds the tenant for the system
// queries, on the alias s.
const (
	ssoColumns       = `enabled, issuer, client_id, client_secret_key_id, enforced, require_mfa, created_at, updated_at, updated_by`
	ssoSystemColumns = `s.tenant_id, s.enabled, s.issuer, s.client_id, s.client_secret_key_id, s.enforced, s.require_mfa, ` +
		`s.created_at, s.updated_at, s.updated_by`
)

// Statements of the SSOSettings repository.
var (
	qSSOGet = tenantQuery(
		`SELECT ` + ssoColumns + ` FROM tenant_sso_settings WHERE tenant_id = ?`)
	qSSODomains = tenantQuery(
		`SELECT domain FROM sso_email_domains WHERE tenant_id = ? ORDER BY domain`)
	qSSOUpdate = tenantQuery(
		`UPDATE tenant_sso_settings SET enabled = ?, issuer = ?, client_id = ?, client_secret_key_id = ?, enforced = ?,
		require_mfa = ?, updated_at = ?, updated_by = ? WHERE tenant_id = ?`)
	qSSOInsert = tenantQuery(
		`INSERT INTO tenant_sso_settings (tenant_id, enabled, issuer, client_id, client_secret_key_id, enforced,
		require_mfa, created_at, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	qSSODelete = tenantQuery(
		`DELETE FROM tenant_sso_settings WHERE tenant_id = ?`)
	qSSODomainsDelete = tenantQuery(
		`DELETE FROM sso_email_domains WHERE tenant_id = ?`)
	qSSODomainInsert = tenantQuery(
		`INSERT INTO sso_email_domains (tenant_id, domain) VALUES (?, ?)`)

	// qSSORoute finds the enabled configuration, with a secret, that an
	// e-mail domain is routed to.
	qSSORoute = systemQuery(
		`SELECT `+ssoSystemColumns+` FROM sso_email_domains d JOIN tenant_sso_settings s ON s.tenant_id = d.tenant_id
		WHERE d.domain = ? AND s.enabled = true AND s.client_secret_key_id IS NOT NULL`,
		reasonSSOLogin)
	qSSODomainsSystem = systemQuery(
		`SELECT domain FROM sso_email_domains WHERE tenant_id = ? ORDER BY domain`,
		reasonSSOLogin)
	qSSOAnyEnabled = systemQuery(
		`SELECT count(*) FROM tenant_sso_settings WHERE enabled = true AND client_secret_key_id IS NOT NULL`,
		reasonSSOLogin)
	qSSOForAdmin = systemQuery(
		`SELECT `+ssoSystemColumns+` FROM admin_tenants a JOIN tenant_sso_settings s ON s.tenant_id = a.tenant_id
		WHERE a.admin_id = ? ORDER BY s.tenant_id`,
		reasonSSOAccess)
)

// TenantSSO is the OpenID Connect configuration of a tenant (V2, spec
// 6.5, OpenAPI TenantSso). The client secret is never held here:
// ClientSecretKeyID references the wrapped secret (purpose
// KeyPurposeSecret) sealed by the master key vault, exactly like
// [SMTPConfig.PasswordKeyID]; the caller unseals it with the tenant's vault
// (masterkey.Vault.Open with crypto.PurposeSecret) only to call the token
// endpoint.
type TenantSSO struct {
	// TenantID is the tenant of the configuration (set by the store on
	// reads; ignored on writes, which use the transaction's tenant).
	TenantID tenant.ID
	// Enabled opens the single sign-on login for the tenant. An enabled
	// configuration needs a client secret.
	Enabled bool
	// Issuer is the OpenID Connect issuer URL: https, MinSSOIssuerLen to
	// MaxSSOIssuerLen printable ASCII bytes, no user information, query or
	// fragment, never a multi-directory Entra ID issuer
	// ([ErrSSOIssuerNotAllowed]). It is stored and compared exactly.
	Issuer string
	// ClientID is the client ID of the application at the provider (1 to
	// MaxSSOClientIDLen printable ASCII bytes).
	ClientID string
	// ClientSecretKeyID is the wrapped secret holding the client secret
	// ("wk_" + ULID), "" when none. On writes, "" keeps the stored secret.
	// Deleting that wrapped key clears it.
	ClientSecretKeyID string
	// EmailDomains are the e-mail domains routed to this configuration (1
	// to MaxSSODomains), stored lower case, IDNA A-label, sorted; each is
	// routed to one tenant at most on the whole instance. Nil in the
	// results of [SSOSettings.ForAdmin].
	EmailDomains []string
	// Enforced refuses the local password login of the delegated admins
	// and auditors attached to the tenant.
	Enforced bool
	// RequireMFA requires the ID token to prove a multi-factor
	// authentication (amr contains "mfa").
	RequireMFA bool
	// CreatedAt and UpdatedAt are set by the store.
	CreatedAt time.Time
	UpdatedAt time.Time
	// UpdatedBy is the admin ID of the last writer ("" if unknown, at most
	// 64 bytes).
	UpdatedBy string
}

// HasClientSecret reports whether a client secret is stored (OpenAPI
// TenantSso.hasClientSecret).
func (c TenantSSO) HasClientSecret() bool { return c.ClientSecretKeyID != "" }

// Admits reports whether a single sign-on session opened through issuer
// and clientID, with mfa recording whether its ID token proved a
// multi-factor authentication, reaches the tenant of c (threats T-287,
// T-291): the configuration is enabled and has a secret, has exactly this
// issuer and this client ID, and its MFA requirement is met. The access
// layer applies it on every request, against the current configuration.
func (c TenantSSO) Admits(issuer, clientID string, mfa bool) bool {
	return c.Enabled && c.HasClientSecret() && c.Issuer == issuer && c.ClientID == clientID && (!c.RequireMFA || mfa)
}

// SSOSettings is the repository of the single sign-on configurations, one
// per tenant at most, with their routed e-mail domains. Obtain it with
// [DB.SSOSettings].
//
// Reads and writes of one configuration are tenant-scoped (row-level
// security on PostgreSQL), so that the client secret is sealed, replaced
// and erased in the same transaction as the configuration
// (masterkey.Vault.SealTx needs a [ScopedTx]). Only the super admin may
// write (threat T-287): the store does not know the caller, the service
// checks it. The login and the session scope read across tenants in the
// system scope ([SSOSettings.RouteDomain], [SSOSettings.AnyEnabled],
// [SSOSettings.ForAdmin]).
type SSOSettings struct {
	db *DB
}

// SSOSettings returns the single sign-on configuration repository.
func (db *DB) SSOSettings() *SSOSettings { return &SSOSettings{db: db} }

// NormalizeSSODomain validates an e-mail domain routed to a single sign-on
// configuration and returns its stored form (lower case, IDNA A-label, no
// trailing dot, at least two labels). It returns ErrInvalid otherwise; the
// error never quotes the value. The login normalizes the domain of the
// address it routes with it.
func NormalizeSSODomain(s string) (string, error) {
	d, err := normalizeDomain(strings.TrimSpace(s))
	if err != nil || len(d) > maxSSODomainLen || !validMailDomain(d) {
		return "", invalid("malformed single sign-on domain")
	}
	return d, nil
}

// multiDirectoryPaths are the first path segments of the Entra ID issuers
// that accept the users of any directory (threat T-288).
var multiDirectoryPaths = []string{"common", "organizations", "consumers"}

// ValidateSSOIssuer checks an issuer URL: https, MinSSOIssuerLen to
// MaxSSOIssuerLen printable ASCII bytes, a host, no user information,
// query or fragment. It returns ErrSSOIssuerNotAllowed for a template
// issuer (braces, such as "{tenantid}") or an issuer whose first path
// segment is common, organizations or consumers (any case): the Entra ID
// issuers that accept every directory. It returns ErrInvalid for any other
// malformed value; the error never quotes the value.
func ValidateSSOIssuer(s string) error {
	if len(s) < MinSSOIssuerLen || !isPrintableASCII(s, MaxSSOIssuerLen) {
		return invalid("issuer must be %d to %d printable ascii bytes", MinSSOIssuerLen, MaxSSOIssuerLen)
	}
	if strings.ContainsAny(s, "{}") {
		return ErrSSOIssuerNotAllowed
	}
	u, err := url.Parse(s)
	if err != nil || !strings.HasPrefix(s, "https://") || u.Host == "" || u.User != nil || u.Opaque != "" ||
		strings.ContainsAny(s, "?#\\") {
		return invalid("issuer must be an https url without user information, query or fragment")
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
	if slices.Contains(multiDirectoryPaths, strings.ToLower(first)) {
		return ErrSSOIssuerNotAllowed
	}
	return nil
}

// validClientID reports whether s is an acceptable client ID.
func validClientID(s string) bool {
	return isPrintableASCII(s, MaxSSOClientIDLen)
}

// normalizeSSO validates the caller-set fields of c and returns it with
// its domains normalized and sorted.
func normalizeSSO(c TenantSSO) (TenantSSO, error) {
	if err := ValidateSSOIssuer(c.Issuer); err != nil {
		return TenantSSO{}, err
	}
	switch {
	case !validClientID(c.ClientID):
		return TenantSSO{}, invalid("client id must be 1 to %d printable ascii bytes", MaxSSOClientIDLen)
	case c.ClientSecretKeyID != "" && !id.Valid(id.WrappedKey, c.ClientSecretKeyID):
		return TenantSSO{}, invalid("malformed client secret key id")
	case len(c.UpdatedBy) > maxSSOUpdatedByLen || !validText(c.UpdatedBy, maxSSOUpdatedByLen, true):
		return TenantSSO{}, invalid("updated by must be at most %d bytes", maxSSOUpdatedByLen)
	case len(c.EmailDomains) == 0 || len(c.EmailDomains) > MaxSSODomains:
		return TenantSSO{}, invalid("1 to %d single sign-on domains", MaxSSODomains)
	}
	domains := make([]string, 0, len(c.EmailDomains))
	for _, raw := range c.EmailDomains {
		d, err := NormalizeSSODomain(raw)
		if err != nil {
			return TenantSSO{}, err
		}
		domains = append(domains, d)
	}
	slices.Sort(domains)
	if len(slices.Compact(slices.Clone(domains))) != len(domains) {
		return TenantSSO{}, invalid("duplicate single sign-on domain")
	}
	c.EmailDomains = domains
	return c, nil
}

// scanSSO reads one row of ssoColumns, preceded by the tenant when
// withTenant (ssoSystemColumns).
func scanSSO(sc interface{ Scan(...any) error }, withTenant bool) (TenantSSO, error) {
	var (
		c                TenantSSO
		tid              string
		keyID            sql.NullString
		created, updated int64
	)
	dest := []any{&c.Enabled, &c.Issuer, &c.ClientID, &keyID, &c.Enforced, &c.RequireMFA, &created, &updated, &c.UpdatedBy}
	if withTenant {
		dest = append([]any{&tid}, dest...)
	}
	if err := sc.Scan(dest...); err != nil {
		return TenantSSO{}, err
	}
	c.TenantID = tenant.ID(tid)
	c.ClientSecretKeyID = keyID.String
	c.CreatedAt, c.UpdatedAt = fromMillis(created), fromMillis(updated)
	return c, nil
}

// scanDomains reads a list of domains.
func scanDomains(rows *sql.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r *sql.Rows) (string, error) {
		var d string
		err := r.Scan(&d)
		return d, err
	})
}

// getSSO reads the configuration of tx's tenant with its domains, returning
// raw errors (ErrNotFound when none).
func getSSO(ctx context.Context, tx *ScopedTx) (TenantSSO, error) {
	c, err := scanSSO(tx.QueryRow(ctx, qSSOGet), false)
	if err != nil {
		return TenantSSO{}, err
	}
	c.TenantID = tx.Tenant()
	c.EmailDomains, err = scanDomains(tx.Query(ctx, qSSODomains))
	if err != nil {
		return TenantSSO{}, err
	}
	return c, nil
}

// Get returns the single sign-on configuration of tenant tid, or
// ErrNotFound when it has none (or the tenant does not exist). Any admin
// attached to the tenant may read it; the client secret never leaves the
// store through it (only its key ID).
func (r *SSOSettings) Get(ctx context.Context, tid tenant.ID) (TenantSSO, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return TenantSSO{}, err
	}
	var c TenantSSO
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		var err error
		c, err = getSSO(ctx, tx)
		return err
	})
	if err != nil {
		return TenantSSO{}, wrap("get sso settings", err)
	}
	return c, nil
}

// GetTx is Get for the tenant tx is bound to, inside tx.
func (r *SSOSettings) GetTx(ctx context.Context, tx *ScopedTx) (TenantSSO, error) {
	c, err := getSSO(ctx, tx)
	if err != nil {
		return TenantSSO{}, wrap("get sso settings", err)
	}
	return c, nil
}

// Put creates or replaces the configuration of tenant tid in its own
// transaction (see [SSOSettings.PutTx]).
func (r *SSOSettings) Put(ctx context.Context, tid tenant.ID, c TenantSSO) (before, after TenantSSO, err error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return TenantSSO{}, TenantSSO{}, err
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		var err error
		before, after, err = r.put(ctx, tx, c)
		return err
	})
	if err != nil {
		return TenantSSO{}, TenantSSO{}, wrap("put sso settings", err)
	}
	return before, after, nil
}

// PutTx creates or replaces the single sign-on configuration of the tenant
// tx is bound to, inside tx, under the tenant lock, so that a new client
// secret (sealed in tx by the caller), the configuration, its domains and
// the erasure of the replaced secret commit together. It returns the
// configuration before the write (zero, with an empty TenantID, when there
// was none) and after it.
//
// c.ClientSecretKeyID is the new secret, or "" to keep the stored one. The
// new secret must be a wrapped key of this tenant with purpose
// KeyPurposeSecret (ErrNotFound otherwise, ErrInvalid for another
// purpose). A replaced secret is deleted in tx (cryptographic erasure).
// The domains replace the stored ones.
//
// It returns [ErrSSOSecretRequired] when the configuration would be
// enabled without a secret, or when the issuer or the client ID changes
// while the stored secret is kept; [ErrSSOIssuerNotAllowed] for a
// multi-directory or template issuer; ErrInvalid for a malformed field;
// [ErrSSODomainConflict] when a domain is routed to another tenant; and
// ErrNotFound when the tenant does not exist. Revoking the single sign-on
// sessions and unpinning the identities of a replaced (issuer, client ID)
// pair are system-scope operations the caller runs after the commit
// ([AdminSessions.DeleteSSOForTenant],
// [AdminIdentities.DeleteForTenantClient]). After an error, the caller
// must abort the transaction.
func (r *SSOSettings) PutTx(ctx context.Context, tx *ScopedTx, c TenantSSO) (before, after TenantSSO, err error) {
	before, after, err = r.put(ctx, tx, c)
	if err != nil {
		return TenantSSO{}, TenantSSO{}, wrap("put sso settings", err)
	}
	return before, after, nil
}

// put implements PutTx, returning raw errors.
func (r *SSOSettings) put(ctx context.Context, tx *ScopedTx, c TenantSSO) (TenantSSO, TenantSSO, error) {
	c, err := normalizeSSO(c)
	if err != nil {
		return TenantSSO{}, TenantSSO{}, err
	}
	if err := tx.lock(ctx); err != nil {
		return TenantSSO{}, TenantSSO{}, err
	}
	old, err := getSSO(ctx, tx)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return TenantSSO{}, TenantSSO{}, err
	}
	if !exists {
		old = TenantSSO{}
	}
	if c.ClientSecretKeyID == old.ClientSecretKeyID {
		c.ClientSecretKeyID = ""
	}
	if c.ClientSecretKeyID == "" {
		if old.ClientSecretKeyID != "" && (old.Issuer != c.Issuer || old.ClientID != c.ClientID) {
			return TenantSSO{}, TenantSSO{}, ErrSSOSecretRequired
		}
		c.ClientSecretKeyID = old.ClientSecretKeyID
	} else {
		// The foreign key only checks that the key exists: the
		// tenant-scoped read also proves it belongs to this tenant.
		k, err := scanWrappedKey(tx.QueryRow(ctx, qWrappedKeyGet, c.ClientSecretKeyID))
		if err != nil {
			return TenantSSO{}, TenantSSO{}, err
		}
		if k.Purpose != KeyPurposeSecret {
			return TenantSSO{}, TenantSSO{}, invalid("client secret key is not a secret")
		}
	}
	if c.Enabled && c.ClientSecretKeyID == "" {
		return TenantSSO{}, TenantSSO{}, ErrSSOSecretRequired
	}
	now := fromMillis(toMillis(r.db.now()))
	c.TenantID, c.CreatedAt, c.UpdatedAt = tx.Tenant(), now, now
	if exists {
		c.CreatedAt = old.CreatedAt
	}
	key := nullText(c.ClientSecretKeyID)
	if err := upsert(ctx, tx,
		qSSOUpdate, []any{c.Enabled, c.Issuer, c.ClientID, key, c.Enforced, c.RequireMFA, toMillis(now), c.UpdatedBy},
		qSSOInsert, []any{
			c.Enabled, c.Issuer, c.ClientID, key, c.Enforced, c.RequireMFA, toMillis(c.CreatedAt),
			toMillis(now), c.UpdatedBy,
		},
	); err != nil {
		return TenantSSO{}, TenantSSO{}, err
	}
	if _, err := tx.Exec(ctx, qSSODomainsDelete); err != nil {
		return TenantSSO{}, TenantSSO{}, err
	}
	for _, d := range c.EmailDomains {
		if _, err := tx.Exec(ctx, qSSODomainInsert, d); err != nil {
			if errors.Is(classify(err), ErrConflict) {
				return TenantSSO{}, TenantSSO{}, ErrSSODomainConflict
			}
			return TenantSSO{}, TenantSSO{}, err
		}
	}
	if old.ClientSecretKeyID != "" && old.ClientSecretKeyID != c.ClientSecretKeyID {
		if err := deleteWrappedKey(ctx, tx, old.ClientSecretKeyID); err != nil {
			return TenantSSO{}, TenantSSO{}, err
		}
	}
	return old, c, nil
}

// Delete removes the configuration of tenant tid in its own transaction
// (see [SSOSettings.DeleteTx]).
func (r *SSOSettings) Delete(ctx context.Context, tid tenant.ID) (TenantSSO, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return TenantSSO{}, err
	}
	var old TenantSSO
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		var err error
		old, err = r.deleteSSO(ctx, tx)
		return err
	})
	if err != nil {
		return TenantSSO{}, wrap("delete sso settings", err)
	}
	return old, nil
}

// DeleteTx removes, inside tx, the single sign-on configuration of the
// tenant tx is bound to, its routed domains (cascade) and its client
// secret (cryptographic erasure, spec 16.1), and returns the deleted
// configuration. It returns ErrNotFound when the tenant has none. The
// pinned identities stay (OpenAPI deleteTenantSso); revoking the single
// sign-on sessions is the caller's job after the commit
// ([AdminSessions.DeleteSSOForTenant]). Call [DB.ScrubDeleted] afterwards
// to purge the SQLite WAL.
func (r *SSOSettings) DeleteTx(ctx context.Context, tx *ScopedTx) (TenantSSO, error) {
	old, err := r.deleteSSO(ctx, tx)
	if err != nil {
		return TenantSSO{}, wrap("delete sso settings", err)
	}
	return old, nil
}

// deleteSSO implements DeleteTx, returning raw errors.
func (r *SSOSettings) deleteSSO(ctx context.Context, tx *ScopedTx) (TenantSSO, error) {
	if err := tx.lock(ctx); err != nil {
		return TenantSSO{}, err
	}
	old, err := getSSO(ctx, tx)
	if err != nil {
		return TenantSSO{}, err
	}
	if _, err := tx.Exec(ctx, qSSODelete); err != nil {
		return TenantSSO{}, err
	}
	if old.ClientSecretKeyID != "" {
		if err := deleteWrappedKey(ctx, tx, old.ClientSecretKeyID); err != nil {
			return TenantSSO{}, err
		}
	}
	return old, nil
}

// RouteDomain returns the enabled configuration, with a client secret,
// that the e-mail domain is routed to, with its tenant and its domains.
// The login calls it in the system scope, before any tenant is known
// (threat T-296: no account lookup). domain is normalized first
// ([NormalizeSSODomain]). It returns ErrNotFound for an unknown domain, a
// disabled configuration or one without secret alike, and for a malformed
// domain too.
func (r *SSOSettings) RouteDomain(ctx context.Context, domain string) (TenantSSO, error) {
	d, err := NormalizeSSODomain(domain)
	if err != nil {
		return TenantSSO{}, wrap("route sso domain", ErrNotFound)
	}
	var c TenantSSO
	err = r.db.systemScope(reasonSSOLogin).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		if c, err = scanSSO(tx.QueryRow(ctx, qSSORoute, d), true); err != nil {
			return err
		}
		c.EmailDomains, err = scanDomains(tx.Query(ctx, qSSODomainsSystem, string(c.TenantID)))
		return err
	})
	if err != nil {
		return TenantSSO{}, wrap("route sso domain", err)
	}
	return c, nil
}

// AnyEnabled reports whether at least one tenant has an enabled single
// sign-on configuration with a client secret (OpenAPI GET
// /admin/auth/methods).
func (r *SSOSettings) AnyEnabled(ctx context.Context) (bool, error) {
	var n int64
	err := r.db.systemScope(reasonSSOLogin).ReadTx(ctx, func(tx *SystemTx) error {
		return tx.QueryRow(ctx, qSSOAnyEnabled).Scan(&n)
	})
	if err != nil {
		return false, wrap("check sso enabled", err)
	}
	return n > 0, nil
}

// ForAdmin returns, in one statement, the single sign-on configurations of
// the tenants the administrator adminID is attached to, sorted by tenant,
// without their domains (EmailDomains nil); tenants without configuration
// are absent. The access layer calls it on every request of a single
// sign-on session and keeps the tenants whose configuration
// [TenantSSO.Admits] the session; the password login uses it to refuse
// the accounts attached to a tenant that enforces single sign-on. It
// returns an empty list for a super admin or an unknown admin.
func (r *SSOSettings) ForAdmin(ctx context.Context, adminID string) ([]TenantSSO, error) {
	var out []TenantSSO
	err := r.db.systemScope(reasonSSOAccess).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qSSOForAdmin, adminID)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (TenantSSO, error) { return scanSSO(r, true) })
		return err
	})
	if err != nil {
		return nil, wrap("list admin sso settings", err)
	}
	return out, nil
}

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// reasonProvisioning is the reason of the provisioning system queries: the
// provisioning tokens are an instance table without tenant (like admins),
// and the tenants they created are found by their provisioned_by column.
const reasonProvisioning = "provisioning api: instance tokens, and the tenants each token created (provisioned_by filter)"

// lockProvisioning serializes the provisioned tenant creations, so that the
// count of the live tenants of a token and of its recent creations is
// checked and the new tenant inserted as one step (threat model T-271).
const lockProvisioning lockName = "provisioning"

// Rules of the provisioning tokens (V1.2, threat model section 6.45).
const (
	// MaxProvisioningTokenNameLen bounds the name of a token, in characters.
	MaxProvisioningTokenNameLen = 100
	// MaxProvisioningTokenCIDRs bounds the allowed IP ranges of a token.
	MaxProvisioningTokenCIDRs = 100
	// MaxProvisioningTokenSuffixes bounds the FQDN suffixes of a token.
	MaxProvisioningTokenSuffixes = 100
	// MaxProvisioningTokenPrefixLen bounds the visible prefix of a token.
	MaxProvisioningTokenPrefixLen = 16
	// maxSuffixLen bounds a suffix, its leading dot included.
	maxSuffixLen = 254
	// ProvisioningCreationsPerHour bounds the tenants created by one token
	// within ProvisioningCreationWindow (T-273).
	ProvisioningCreationsPerHour = 30
	// ProvisioningCreationWindow is the sliding window of
	// ProvisioningCreationsPerHour.
	ProvisioningCreationWindow = time.Hour
)

// Errors of a provisioned tenant creation ([Tenants.CreateProvisioned]),
// checked under the provisioning lock. Nothing is created.
var (
	// ErrProvisioningTokenUnusable reports a token that is unknown,
	// revoked or expired when the creation runs (revoked after the
	// authentication of the request, for example).
	ErrProvisioningTokenUnusable = errors.New("store: provisioning token unusable")
	// ErrProvisioningMaxTenants reports a token that has already created
	// its maximum number of live tenants.
	ErrProvisioningMaxTenants = errors.New("store: provisioning token reached its maximum number of tenants")
	// ErrProvisioningRateLimited reports a token that has already created
	// ProvisioningCreationsPerHour tenants within the last
	// ProvisioningCreationWindow. The error is a
	// *[ProvisioningRateLimitError].
	ErrProvisioningRateLimited = errors.New("store: too many tenant creations for the provisioning token")
)

// ProvisioningRateLimitError reports the creation rate limit of a token. It
// matches [ErrProvisioningRateLimited].
type ProvisioningRateLimitError struct {
	// RetryAfter is the time left before a creation is allowed again (at
	// least one second).
	RetryAfter time.Duration
}

// Error implements error.
func (e *ProvisioningRateLimitError) Error() string {
	return fmt.Sprintf("store: too many tenant creations for the provisioning token, retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrProvisioningRateLimited) true.
func (e *ProvisioningRateLimitError) Is(target error) bool {
	return target == ErrProvisioningRateLimited
}

// provisioningTokenColumns is the column list of a token, read by the
// authentication and the creation check, which do not need the count of
// its tenants.
const provisioningTokenColumns = `id, name, prefix, token_hash, allowed_cidrs, allowed_fqdn_suffixes, ` +
	`max_storage_quota_bytes, max_transfer_bytes, max_tenants, created_by, created_at, last_used_at, expires_at, ` +
	`revoked_at`

// provisioningTokenCountedColumns is provisioningTokenColumns followed by
// the computed count of the tenants of the token (live ones and those
// being deleted), read by the super admin views (Get, List, Revoke).
const provisioningTokenCountedColumns = provisioningTokenColumns +
	`, (SELECT count(*) FROM tenants t WHERE t.provisioned_by = provisioning_tokens.id)`

// provisionedTenantColumns is the column list of a tenant as a provisioning
// token sees it (OpenAPI ProvisionedTenant): whether the delegated admin is
// activated is a boolean computed from the accounts assigned to the tenant.
const provisionedTenantColumns = `t.id, t.name, t.fqdn, t.setup_state, t.created_at, ` +
	`EXISTS (SELECT 1 FROM admin_tenants j JOIN admins a ON a.id = j.admin_id ` +
	`WHERE j.tenant_id = t.id AND a.role = 'delegated_admin' AND a.password_hash IS NOT NULL)`

// Statements of the ProvisioningTokens repository and of the provisioned
// tenant creation.
var (
	qProvTokenInsert = systemQuery(
		`INSERT INTO provisioning_tokens (id, name, prefix, token_hash, allowed_cidrs, allowed_fqdn_suffixes,
		max_storage_quota_bytes, max_transfer_bytes, max_tenants, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reasonProvisioning)
	qProvTokenGet = systemQuery(
		`SELECT `+provisioningTokenCountedColumns+` FROM provisioning_tokens WHERE id = ?`,
		reasonProvisioning)
	// qProvTokenCheck reads a token without the count of its tenants, for
	// the creation check (which counts them itself).
	qProvTokenCheck = systemQuery(
		`SELECT `+provisioningTokenColumns+` FROM provisioning_tokens WHERE id = ?`,
		reasonProvisioning)
	qProvTokenGetByHash = systemQuery(
		`SELECT `+provisioningTokenColumns+` FROM provisioning_tokens WHERE token_hash = ?`,
		reasonProvisioning)
	qProvTokenList = systemQuery(
		`SELECT `+provisioningTokenCountedColumns+` FROM provisioning_tokens ORDER BY created_at DESC, id DESC`,
		reasonProvisioning)
	// qProvTokenRevoke only revokes a token once; there is no deletion.
	qProvTokenRevoke = systemQuery(
		`UPDATE provisioning_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		reasonProvisioning)
	// qProvTokenTouch only moves the last use forward.
	qProvTokenTouch = systemQuery(
		`UPDATE provisioning_tokens SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`,
		reasonProvisioning)
	// qProvTenantCount counts the tenants of a token (live ones: a deleted
	// tenant has no row; one being deleted still counts).
	qProvTenantCount = systemQuery(
		`SELECT count(*) FROM tenants WHERE provisioned_by = ?`,
		reasonProvisioning)
	// qProvTenantRecent counts the tenants a token created since a time,
	// with the oldest of them, for the creation rate limit.
	qProvTenantRecent = systemQuery(
		`SELECT count(*), COALESCE(min(created_at), 0) FROM tenants WHERE provisioned_by = ? AND created_at > ?`,
		reasonProvisioning)
	// qProvTenantList and qProvTenantGet always filter on the token (T-270)
	// and leave out the tenants being deleted.
	qProvTenantList = systemQuery(
		`SELECT `+provisionedTenantColumns+` FROM tenants t WHERE t.provisioned_by = ? AND t.status = 'active'
		ORDER BY t.created_at DESC, t.id DESC`,
		reasonProvisioning)
	qProvTenantGet = systemQuery(
		`SELECT `+provisionedTenantColumns+` FROM tenants t WHERE t.provisioned_by = ? AND t.id = ? AND t.status = 'active'`,
		reasonProvisioning)
)

// suffixPattern is the syntax of a stored FQDN suffix (OpenAPI
// FqdnSuffixes): a leading dot, then lower-case ASCII labels, the last one
// alphabetic or punycode.
var suffixPattern = regexp.MustCompile(`^\.([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*([a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)

// ProvisioningToken is a provisioning token of the instance (OpenAPI
// ProvisioningToken): the record of a secret shown once at its creation, of
// which only the SHA-256 is kept. It belongs to no tenant.
type ProvisioningToken struct {
	// ID is the identifier ("prv_" + ULID), assigned by the caller.
	ID string
	// Name is the label chosen by the super admin (1 to
	// MaxProvisioningTokenNameLen characters on one line).
	Name string
	// Prefix is the beginning of the secret, shown to recognize the token
	// (1 to MaxProvisioningTokenPrefixLen visible ASCII characters).
	Prefix string
	// TokenHash is the SHA-256 of the secret (TokenHashSize bytes), unique.
	TokenHash []byte
	// AllowedCIDRs are the IP ranges the token may be used from: 1 to
	// MaxProvisioningTokenCIDRs distinct ranges, masked by the store, never
	// a range of prefix length 0 nor an IPv4-mapped IPv6 range.
	AllowedCIDRs []netip.Prefix
	// AllowedFQDNSuffixes are the suffixes the FQDN of a tenant created
	// with the token must end with: 1 to MaxProvisioningTokenSuffixes
	// distinct suffixes, already normalized by the caller (leading dot,
	// lower-case A-labels, at least two labels).
	AllowedFQDNSuffixes []string
	// MaxStorageQuotaBytes caps the storage quota of each tenant created
	// (positive).
	MaxStorageQuotaBytes int64
	// MaxTransferBytes caps the transfer limit of each tenant created, 0
	// for no cap below [tenant.MaxTransferLimit].
	MaxTransferBytes int64
	// MaxTenants caps the live tenants created with the token (positive).
	MaxTenants int
	// CreatedBy is the identifier ("adm_" + ULID) of the super admin who
	// created the token.
	CreatedBy string
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// LastUsedAt is the last recorded use, zero when never used.
	LastUsedAt time.Time
	// ExpiresAt is the optional expiry, zero for none.
	ExpiresAt time.Time
	// RevokedAt is the revocation time, zero while not revoked.
	RevokedAt time.Time
	// TenantsCreated is the number of tenants of the token that still
	// exist, computed when read (ignored by Create).
	TenantsCreated int
}

// Revoked reports whether the token was revoked.
func (t ProvisioningToken) Revoked() bool { return !t.RevokedAt.IsZero() }

// Expired reports whether the token has an expiry at or before now.
func (t ProvisioningToken) Expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

// Usable reports whether the token is neither revoked nor expired at now.
func (t ProvisioningToken) Usable(now time.Time) bool { return !t.Revoked() && !t.Expired(now) }

// ProvisionedTenant is a tenant as a provisioning token sees it (OpenAPI
// ProvisionedTenant): no address, no admin identifier, no configuration.
type ProvisionedTenant struct {
	ID         tenant.ID
	Name       string
	FQDN       string
	SetupState tenant.SetupState
	CreatedAt  time.Time
	// DelegatedAdminActivated reports whether a delegated admin assigned to
	// the tenant has activated the account (set a password).
	DelegatedAdminActivated bool
}

// ProvisioningTokens is the repository of the provisioning tokens. Its
// operations are system-scoped: callers check that the caller is a super
// admin, or authenticate the token. Obtain it with [DB.ProvisioningTokens].
type ProvisioningTokens struct {
	db *DB
}

// ProvisioningTokens returns the provisioning token repository.
func (db *DB) ProvisioningTokens() *ProvisioningTokens { return &ProvisioningTokens{db: db} }

// normalizeProvisioningCIDRs validates the allowed ranges of a provisioning
// token and returns them masked, in the order given, with their JSON text:
// the ranges of an API token, without any range of prefix length 0
// (0.0.0.0/0, ::/0) nor any IPv4-mapped IPv6 range.
func normalizeProvisioningCIDRs(cidrs []netip.Prefix) ([]netip.Prefix, string, error) {
	if len(cidrs) > MaxProvisioningTokenCIDRs {
		return nil, "", invalid("a provisioning token needs 1 to %d ip ranges", MaxProvisioningTokenCIDRs)
	}
	for _, p := range cidrs {
		if p.IsValid() && (p.Bits() == 0 || p.Addr().Is4In6()) {
			return nil, "", invalid("a provisioning token may not allow every address")
		}
	}
	return normalizeCIDRs(cidrs)
}

// validSuffix reports whether s is a stored FQDN suffix: the OpenAPI
// syntax, with at least two labels.
func validSuffix(s string) bool {
	return len(s) <= maxSuffixLen && suffixPattern.MatchString(s) && strings.Count(s, ".") >= 2
}

// suffixesDoc validates the FQDN suffixes of a token and returns their JSON
// text.
func suffixesDoc(suffixes []string) (string, error) {
	if len(suffixes) == 0 || len(suffixes) > MaxProvisioningTokenSuffixes {
		return "", invalid("a provisioning token needs 1 to %d fqdn suffixes", MaxProvisioningTokenSuffixes)
	}
	seen := make(map[string]bool, len(suffixes))
	for _, s := range suffixes {
		if !validSuffix(s) {
			return "", invalid("malformed fqdn suffix")
		}
		if seen[s] {
			return "", invalid("duplicate fqdn suffix")
		}
		seen[s] = true
	}
	doc, _ := json.Marshal(suffixes) // a []string always marshals
	return string(doc), nil
}

// checkProvisioningToken validates the fields of a new token t, whose
// creation time is set.
func checkProvisioningToken(t ProvisioningToken) error {
	switch {
	case !id.Valid(id.ProvisioningToken, t.ID):
		return invalid("malformed provisioning token id")
	case t.Name == "" || !validText(t.Name, MaxProvisioningTokenNameLen, true):
		return invalid("name must be 1 to %d characters on one line", MaxProvisioningTokenNameLen)
	case !isPrintableASCII(t.Prefix, MaxProvisioningTokenPrefixLen):
		return invalid("prefix must hold 1 to %d visible ASCII characters", MaxProvisioningTokenPrefixLen)
	case !validTokenHash(t.TokenHash):
		return invalid("token hash must hold %d bytes", TokenHashSize)
	case t.MaxStorageQuotaBytes <= 0:
		return invalid("the storage quota cap must be positive")
	case t.MaxTransferBytes < 0 || t.MaxTransferBytes > tenant.MaxTransferLimit:
		return invalid("the transfer cap must be between 1 and %d bytes", tenant.MaxTransferLimit)
	case t.MaxTenants <= 0:
		return invalid("the tenant cap must be positive")
	case !id.Valid(id.Admin, t.CreatedBy):
		return invalid("malformed creator id")
	case !t.ExpiresAt.IsZero() && !t.ExpiresAt.After(t.CreatedAt):
		return invalid("token must expire after its creation")
	case !t.LastUsedAt.IsZero() || !t.RevokedAt.IsZero():
		return invalid("a new token is neither used nor revoked")
	}
	return nil
}

// nullPositive returns n, or NULL when it is 0.
func nullPositive(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

// scanProvisioningToken reads one row of provisioningTokenCountedColumns.
func scanProvisioningToken(row interface{ Scan(...any) error }) (ProvisioningToken, error) {
	return scanToken(row, true)
}

// scanProvisioningTokenUncounted reads one row of provisioningTokenColumns;
// TenantsCreated stays 0.
func scanProvisioningTokenUncounted(row interface{ Scan(...any) error }) (ProvisioningToken, error) {
	return scanToken(row, false)
}

// scanToken reads one row of provisioningTokenCountedColumns when counted,
// else of provisioningTokenColumns.
func scanToken(row interface{ Scan(...any) error }, counted bool) (ProvisioningToken, error) {
	var (
		t                         ProvisioningToken
		cidrs, suffixes           string
		maxTransfer               sql.NullInt64
		created                   int64
		lastUsed, expires, revoke sql.NullInt64
		count                     int64
	)
	dest := []any{
		&t.ID, &t.Name, &t.Prefix, &t.TokenHash, &cidrs, &suffixes, &t.MaxStorageQuotaBytes,
		&maxTransfer, &t.MaxTenants, &t.CreatedBy, &created, &lastUsed, &expires, &revoke,
	}
	if counted {
		dest = append(dest, &count)
	}
	if err := row.Scan(dest...); err != nil {
		return ProvisioningToken{}, err
	}
	var err error
	if t.AllowedCIDRs, err = parseCIDRs(cidrs); err != nil {
		return ProvisioningToken{}, err
	}
	if err = json.Unmarshal([]byte(suffixes), &t.AllowedFQDNSuffixes); err != nil {
		return ProvisioningToken{}, err
	}
	t.MaxTransferBytes, t.TenantsCreated = maxTransfer.Int64, int(count)
	t.CreatedAt, t.LastUsedAt = fromMillis(created), nullMillis(lastUsed)
	t.ExpiresAt, t.RevokedAt = nullMillis(expires), nullMillis(revoke)
	return t, nil
}

// Create stores the new token t (ranges masked, creation time set) and,
// when then is not nil, runs then inside the same transaction with the
// stored token (to record its audit event atomically). It returns the token
// as stored, ErrInvalid for a malformed field (see [ProvisioningToken]; an
// expiry must follow the creation; a new token is neither used nor
// revoked) and ErrConflict when the identifier or the hash is already
// used. An error of then rolls everything back and is returned wrapped.
func (r *ProvisioningTokens) Create(ctx context.Context, t ProvisioningToken, then func(tx *SystemTx, t ProvisioningToken) error) (ProvisioningToken, error) {
	cidrs, cidrsDoc, err := normalizeProvisioningCIDRs(t.AllowedCIDRs)
	if err != nil {
		return ProvisioningToken{}, err
	}
	suffixes, err := suffixesDoc(t.AllowedFQDNSuffixes)
	if err != nil {
		return ProvisioningToken{}, err
	}
	t.AllowedCIDRs = cidrs
	t.AllowedFQDNSuffixes = append([]string(nil), t.AllowedFQDNSuffixes...)
	t.CreatedAt = fromMillis(toMillis(r.db.orNow(t.CreatedAt)))
	if !t.ExpiresAt.IsZero() {
		t.ExpiresAt = fromMillis(toMillis(t.ExpiresAt))
	}
	if err := checkProvisioningToken(t); err != nil {
		return ProvisioningToken{}, err
	}
	t.TenantsCreated = 0
	err = r.db.systemScope(reasonProvisioning).Tx(ctx, func(tx *SystemTx) error {
		if _, err := tx.Exec(ctx, qProvTokenInsert, t.ID, t.Name, t.Prefix, t.TokenHash, cidrsDoc, suffixes,
			t.MaxStorageQuotaBytes, nullPositive(t.MaxTransferBytes), t.MaxTenants, t.CreatedBy,
			toMillis(t.CreatedAt), nullTime(t.ExpiresAt)); err != nil {
			return err
		}
		if then == nil {
			return nil
		}
		return then(tx, t)
	})
	if err != nil {
		return ProvisioningToken{}, wrap("create provisioning token", err)
	}
	return t, nil
}

// Get returns the token tokID, in whatever state it is, or ErrNotFound.
func (r *ProvisioningTokens) Get(ctx context.Context, tokID string) (ProvisioningToken, error) {
	return readProvisioning(ctx, r.db, "get provisioning token", func(tx *SystemTx) (ProvisioningToken, error) {
		return scanProvisioningToken(tx.QueryRow(ctx, qProvTokenGet, tokID))
	})
}

// GetByHash returns the token whose secret hashes to hash, in whatever
// state it is (the caller checks revocation, expiry and the client IP), or
// ErrNotFound. Its TenantsCreated is not computed (0): the authentication
// does not need it. It returns ErrInvalid for a hash of the wrong size.
func (r *ProvisioningTokens) GetByHash(ctx context.Context, hash []byte) (ProvisioningToken, error) {
	if !validTokenHash(hash) {
		return ProvisioningToken{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	return readProvisioning(ctx, r.db, "get provisioning token by hash", func(tx *SystemTx) (ProvisioningToken, error) {
		return scanProvisioningTokenUncounted(tx.QueryRow(ctx, qProvTokenGetByHash, hash))
	})
}

// List returns every token, revoked and expired ones included, newest
// first, each with the number of its tenants.
func (r *ProvisioningTokens) List(ctx context.Context) ([]ProvisioningToken, error) {
	return readProvisioning(ctx, r.db, "list provisioning tokens", func(tx *SystemTx) ([]ProvisioningToken, error) {
		rows, err := tx.Query(ctx, qProvTokenList)
		if err != nil {
			return nil, err
		}
		return collect(rows, func(r *sql.Rows) (ProvisioningToken, error) { return scanProvisioningToken(r) })
	})
}

// Revoke revokes the token tokID at now (the store's clock when zero) and,
// when then is not nil, runs then inside the same transaction with the
// token and whether this call revoked it. Revoking a token already revoked
// changes nothing and reports false; a token is never deleted. It returns
// the token, and ErrNotFound when it does not exist. An error of then
// rolls everything back and is returned wrapped.
func (r *ProvisioningTokens) Revoke(ctx context.Context, tokID string, now time.Time,
	then func(tx *SystemTx, t ProvisioningToken, revoked bool) error,
) (ProvisioningToken, bool, error) {
	var (
		tok     ProvisioningToken
		revoked bool
	)
	err := r.db.systemScope(reasonProvisioning).Tx(ctx, func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qProvTokenRevoke, toMillis(r.db.orNow(now)), tokID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		revoked = n == 1
		if tok, err = scanProvisioningToken(tx.QueryRow(ctx, qProvTokenGet, tokID)); err != nil {
			return err
		}
		if then == nil {
			return nil
		}
		return then(tx, tok, revoked)
	})
	if err != nil {
		return ProvisioningToken{}, false, wrap("revoke provisioning token", err)
	}
	return tok, revoked, nil
}

// Touch records at (the store's clock when zero) as the last use of the
// token tokID, unless a later use is already recorded. An unknown token
// changes nothing and is not an error.
func (r *ProvisioningTokens) Touch(ctx context.Context, tokID string, at time.Time) error {
	err := r.db.systemScope(reasonProvisioning).Tx(ctx, func(tx *SystemTx) error {
		ms := toMillis(r.db.orNow(at))
		_, err := tx.Exec(ctx, qProvTokenTouch, ms, tokID, ms)
		return err
	})
	if err != nil {
		return wrap("touch provisioning token", err)
	}
	return nil
}

// ListTenants returns the active tenants created with the token tokID, and
// only them (the query filters on the token, T-270), newest first.
func (r *ProvisioningTokens) ListTenants(ctx context.Context, tokID string) ([]ProvisionedTenant, error) {
	return readProvisioning(ctx, r.db, "list provisioned tenants", func(tx *SystemTx) ([]ProvisionedTenant, error) {
		rows, err := tx.Query(ctx, qProvTenantList, tokID)
		if err != nil {
			return nil, err
		}
		return collect(rows, func(r *sql.Rows) (ProvisionedTenant, error) { return scanProvisionedTenant(r) })
	})
}

// GetTenant returns the active tenant tid if the token tokID created it,
// and ErrNotFound otherwise: a tenant of another token, of the super admin,
// unknown or being deleted all answer alike (the query filters on the
// token, T-270).
func (r *ProvisioningTokens) GetTenant(ctx context.Context, tokID string, tid tenant.ID) (ProvisionedTenant, error) {
	return readProvisioning(ctx, r.db, "get provisioned tenant", func(tx *SystemTx) (ProvisionedTenant, error) {
		return scanProvisionedTenant(tx.QueryRow(ctx, qProvTenantGet, tokID, string(tid)))
	})
}

// scanProvisionedTenant reads one row of provisionedTenantColumns.
func scanProvisionedTenant(row interface{ Scan(...any) error }) (ProvisionedTenant, error) {
	var (
		t          ProvisionedTenant
		tid, setup string
		created    int64
	)
	if err := row.Scan(&tid, &t.Name, &t.FQDN, &setup, &created, &t.DelegatedAdminActivated); err != nil {
		return ProvisionedTenant{}, err
	}
	t.ID, t.SetupState, t.CreatedAt = tenant.ID(tid), tenant.SetupState(setup), fromMillis(created)
	return t, nil
}

// readProvisioning runs fn in a read transaction of the provisioning scope
// and returns its value.
func readProvisioning[T any](ctx context.Context, db *DB, op string, fn func(*SystemTx) (T, error)) (T, error) {
	var v T
	err := db.systemScope(reasonProvisioning).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		v, err = fn(tx)
		return err
	})
	if err != nil {
		var zero T
		return zero, wrap(op, err)
	}
	return v, nil
}

// CreateProvisioned is [Tenants.CreateWith] for a tenant created with the
// provisioning token tokID, recorded as its provisioned_by. Inside the
// creation transaction and under the provisioning lock, it reads the token
// again and refuses the creation, creating nothing, with
// ErrProvisioningTokenUnusable when the token is unknown, revoked or
// expired, ErrProvisioningMaxTenants when the token already has MaxTenants
// tenants, and a *ProvisioningRateLimitError when it created
// ProvisioningCreationsPerHour tenants within the last
// ProvisioningCreationWindow. The scope of the fields (suffix, caps) is the
// caller's check. t.ProvisionedBy must be empty or tokID.
func (r *Tenants) CreateProvisioned(ctx context.Context, tokID string, t *tenant.Tenant,
	then func(tx *SystemTx, created *tenant.Tenant) error,
) (*tenant.Tenant, error) {
	if !id.Valid(id.ProvisioningToken, tokID) || (t.ProvisionedBy != "" && t.ProvisionedBy != tokID) {
		return nil, invalid("malformed provisioning token id")
	}
	c := t.Clone()
	c.ProvisionedBy = tokID
	return r.create(ctx, c, func(tx *SystemTx) error { return r.checkProvisioning(ctx, tx, tokID) }, then)
}

// checkProvisioning takes the provisioning lock inside tx and checks that
// the token tokID may create one more tenant now.
func (r *Tenants) checkProvisioning(ctx context.Context, tx *SystemTx, tokID string) error {
	if err := tx.lock(ctx, lockProvisioning); err != nil {
		return err
	}
	now := r.db.now()
	tok, err := scanProvisioningTokenUncounted(tx.QueryRow(ctx, qProvTokenCheck, tokID))
	switch {
	case errors.Is(err, ErrNotFound):
		return ErrProvisioningTokenUnusable
	case err != nil:
		return err
	case !tok.Usable(now):
		return ErrProvisioningTokenUnusable
	}
	var live int64
	if err := tx.QueryRow(ctx, qProvTenantCount, tokID).Scan(&live); err != nil {
		return err
	}
	if live >= int64(tok.MaxTenants) {
		return ErrProvisioningMaxTenants
	}
	var recent, oldest int64
	since := toMillis(now.Add(-ProvisioningCreationWindow))
	if err := tx.QueryRow(ctx, qProvTenantRecent, tokID, since).Scan(&recent, &oldest); err != nil {
		return err
	}
	if recent >= ProvisioningCreationsPerHour {
		wait := fromMillis(oldest).Add(ProvisioningCreationWindow).Sub(now)
		return &ProvisioningRateLimitError{RetryAfter: max(wait.Round(time.Second), time.Second)}
	}
	return nil
}

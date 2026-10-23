package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Limits of an API token record.
const (
	// MaxAPITokenNameLen bounds the name of a token, in characters.
	MaxAPITokenNameLen = 100
	// MaxAPITokenCIDRs bounds the number of allowed IP ranges of a token.
	MaxAPITokenCIDRs = 100
	// MaxAPITokenSenders bounds the number of allowed senders of a token.
	MaxAPITokenSenders = 100
	// MaxAPITokenPrefixLen bounds the visible prefix of a token, in bytes.
	MaxAPITokenPrefixLen = 16
	// maxAPITokenCreatedByLen bounds the admin username recorded as the
	// creator.
	maxAPITokenCreatedByLen = 320
)

// apiTokenColumns is the column list read by the API token queries.
const apiTokenColumns = `id, name, prefix, token_hash, allowed_cidrs, allowed_senders, created_by, created_at, ` +
	`last_used_at, expires_at, revoked_at`

// Statements of the APITokens repository.
var (
	qAPITokenInsert = tenantQuery(
		`INSERT INTO api_tokens (tenant_id, id, name, prefix, token_hash, allowed_cidrs, allowed_senders, created_by,
		created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	qAPITokenGet = tenantQuery(
		`SELECT ` + apiTokenColumns + ` FROM api_tokens WHERE tenant_id = ? AND id = ?`)
	qAPITokenGetByHash = tenantQuery(
		`SELECT ` + apiTokenColumns + ` FROM api_tokens WHERE tenant_id = ? AND token_hash = ?`)
	qAPITokenList = tenantQuery(
		`SELECT ` + apiTokenColumns + ` FROM api_tokens WHERE tenant_id = ? ORDER BY created_at DESC, id DESC`)
	// qAPITokenUpdate only changes a token that is not revoked; a NULL
	// argument keeps the current value.
	qAPITokenUpdate = tenantQuery(
		`UPDATE api_tokens SET name = COALESCE(?, name), allowed_cidrs = COALESCE(?, allowed_cidrs),
		allowed_senders = COALESCE(?, allowed_senders) WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`)
	qAPITokenCount = tenantQuery(
		`SELECT count(*) FROM api_tokens WHERE tenant_id = ? AND id = ?`)
	// qAPITokenRevoke only revokes a token once.
	qAPITokenRevoke = tenantQuery(
		`UPDATE api_tokens SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`)
	// qAPITokenTouch only moves the last use forward.
	qAPITokenTouch = tenantQuery(
		`UPDATE api_tokens SET last_used_at = ?
		WHERE tenant_id = ? AND id = ? AND (last_used_at IS NULL OR last_used_at < ?)`)
)

// APIToken is an API token of a tenant (spec 16.4): the record of a secret
// shown once at its creation, of which only the SHA-256 is kept.
type APIToken struct {
	// ID is the identifier ("tok_" + ULID), assigned by the caller.
	ID string
	// Name is the label chosen by the admin (1 to MaxAPITokenNameLen
	// characters on one line).
	Name string
	// Prefix is the beginning of the secret, shown to recognize the token
	// (1 to MaxAPITokenPrefixLen visible ASCII characters).
	Prefix string
	// TokenHash is the SHA-256 of the secret (TokenHashSize bytes), unique
	// across tenants.
	TokenHash []byte
	// AllowedCIDRs are the IP ranges the token may be used from (1 to
	// MaxAPITokenCIDRs distinct ranges, masked by the store, in the order
	// given).
	AllowedCIDRs []netip.Prefix
	// AllowedSenders restrict the sender addresses of the deposits made
	// with the token: each entry is a normalized address or mail domain
	// (0 to MaxAPITokenSenders distinct entries, in the order given; see
	// [APIToken.AllowsSender]). Empty (never nil once stored or read)
	// allows any address.
	AllowedSenders []string
	// CreatedBy is the username of the admin who created the token.
	CreatedBy string
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// LastUsedAt is the last recorded use ([APITokens.TouchLastUsed]), zero
	// when never used.
	LastUsedAt time.Time
	// ExpiresAt is the optional expiry, zero for none.
	ExpiresAt time.Time
	// RevokedAt is the revocation time, zero while the token is not
	// revoked.
	RevokedAt time.Time
}

// Revoked reports whether the token was revoked.
func (t APIToken) Revoked() bool { return !t.RevokedAt.IsZero() }

// Expired reports whether the token has an expiry at or before now.
func (t APIToken) Expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

// Usable reports whether the token is neither revoked nor expired at now.
func (t APIToken) Usable(now time.Time) bool { return !t.Revoked() && !t.Expired(now) }

// AllowsSender reports whether the normalized address email may be the
// sender of a deposit made with the token: always when AllowedSenders is
// empty, otherwise when email equals an address entry or its domain equals
// a domain entry exactly (a domain entry does not cover its subdomains).
// The internal domain and blocklist checks still apply on top.
func (t APIToken) AllowsSender(email string) bool {
	if len(t.AllowedSenders) == 0 {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	domain := email[at+1:]
	for _, e := range t.AllowedSenders {
		if e == email || (!strings.Contains(e, "@") && e == domain) {
			return true
		}
	}
	return false
}

// APITokenUpdate is a change of an API token: the zero value of a field
// keeps its current value.
type APITokenUpdate struct {
	// Name is the new name, "" to keep it.
	Name string
	// AllowedCIDRs are the new allowed ranges, nil to keep them.
	AllowedCIDRs []netip.Prefix
	// AllowedSenders replace the allowed senders, nil to keep them; an
	// empty non-nil slice removes the restriction.
	AllowedSenders []string
}

// APITokens is the tenant-scoped repository of API tokens. Obtain it with
// [DB.APITokens].
type APITokens struct {
	db *DB
}

// APITokens returns the API token repository.
func (db *DB) APITokens() *APITokens { return &APITokens{db: db} }

// normalizeCIDRs validates the allowed ranges of a token and returns them
// masked, in the order given, as JSON text.
func normalizeCIDRs(cidrs []netip.Prefix) ([]netip.Prefix, string, error) {
	if len(cidrs) == 0 || len(cidrs) > MaxAPITokenCIDRs {
		return nil, "", invalid("a token needs 1 to %d ip ranges", MaxAPITokenCIDRs)
	}
	out := make([]netip.Prefix, len(cidrs))
	text := make([]string, len(cidrs))
	seen := make(map[netip.Prefix]bool, len(cidrs))
	for i, p := range cidrs {
		if !p.IsValid() {
			return nil, "", invalid("malformed ip range")
		}
		p = p.Masked()
		if seen[p] {
			return nil, "", invalid("duplicate ip range")
		}
		seen[p] = true
		out[i], text[i] = p, p.String()
	}
	doc, _ := json.Marshal(text) // a []string always marshals
	return out, string(doc), nil
}

// normalizeSenders validates the allowed senders of a token (each entry an
// address, [NormalizeEmail], or a mail domain, [BlockDomain]) and returns
// them normalized, in the order given, never nil, with their JSON text.
func normalizeSenders(senders []string) ([]string, string, error) {
	if len(senders) > MaxAPITokenSenders {
		return nil, "", invalid("a token allows at most %d senders", MaxAPITokenSenders)
	}
	out := make([]string, len(senders))
	seen := make(map[string]bool, len(senders))
	for i, raw := range senders {
		kind := BlockDomain
		if strings.Contains(raw, "@") {
			kind = BlockEmail
		}
		v, err := kind.Normalize(raw)
		if err != nil {
			return nil, "", invalid("malformed allowed sender")
		}
		if seen[v] {
			return nil, "", invalid("duplicate allowed sender")
		}
		seen[v] = true
		out[i] = v
	}
	doc, _ := json.Marshal(out) // a []string always marshals
	return out, string(doc), nil
}

// parseSenders decodes the JSON text of allowed_senders, never nil.
func parseSenders(doc string) ([]string, error) {
	var out []string
	if err := json.Unmarshal([]byte(doc), &out); err != nil {
		return nil, err
	}
	if out == nil { // the JSON text null
		out = []string{}
	}
	return out, nil
}

// parseCIDRs decodes the JSON text of allowed_cidrs.
func parseCIDRs(doc string) ([]netip.Prefix, error) {
	var text []string
	if err := json.Unmarshal([]byte(doc), &text); err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, len(text))
	for i, s := range text {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
}

// validAPITokenName reports whether s is an acceptable token name.
func validAPITokenName(s string) bool {
	return s != "" && validText(s, MaxAPITokenNameLen, true)
}

// scanAPIToken reads one row of apiTokenColumns.
func scanAPIToken(row interface{ Scan(...any) error }) (APIToken, error) {
	var (
		t                         APIToken
		cidrs, senders            string
		created                   int64
		lastUsed, expires, revoke sql.NullInt64
	)
	err := row.Scan(&t.ID, &t.Name, &t.Prefix, &t.TokenHash, &cidrs, &senders, &t.CreatedBy, &created, &lastUsed,
		&expires, &revoke)
	if err != nil {
		return APIToken{}, err
	}
	if t.AllowedCIDRs, err = parseCIDRs(cidrs); err != nil {
		return APIToken{}, err
	}
	if t.AllowedSenders, err = parseSenders(senders); err != nil {
		return APIToken{}, err
	}
	t.CreatedAt, t.LastUsedAt = fromMillis(created), nullMillis(lastUsed)
	t.ExpiresAt, t.RevokedAt = nullMillis(expires), nullMillis(revoke)
	return t, nil
}

// nullTime returns the Unix milliseconds of t, or NULL when t is zero.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return toMillis(t)
}

// Create stores the new token t for tenant tid and returns it as stored
// (ranges masked, senders normalized, creation time set). It returns
// ErrInvalid for a malformed field (an expiry must follow the creation; a new token is neither used
// nor revoked), ErrNotFound when the tenant does not exist and ErrConflict
// when the identifier or the hash is already used.
func (r *APITokens) Create(ctx context.Context, tid tenant.ID, t APIToken) (APIToken, error) {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return APIToken{}, err
	}
	cidrs, doc, err := normalizeCIDRs(t.AllowedCIDRs)
	if err != nil {
		return APIToken{}, err
	}
	t.AllowedCIDRs = cidrs
	senders, sendersDoc, err := normalizeSenders(t.AllowedSenders)
	if err != nil {
		return APIToken{}, err
	}
	t.AllowedSenders = senders
	t.CreatedAt = r.db.orNow(t.CreatedAt)
	switch {
	case !id.Valid(id.APIToken, t.ID):
		return APIToken{}, invalid("malformed api token id")
	case !validAPITokenName(t.Name):
		return APIToken{}, invalid("name must be 1 to %d characters on one line", MaxAPITokenNameLen)
	case !isPrintableASCII(t.Prefix, MaxAPITokenPrefixLen):
		return APIToken{}, invalid("prefix must hold 1 to %d visible ASCII characters", MaxAPITokenPrefixLen)
	case !validTokenHash(t.TokenHash):
		return APIToken{}, invalid("token hash must hold %d bytes", TokenHashSize)
	case t.CreatedBy == "" || !validText(t.CreatedBy, maxAPITokenCreatedByLen, true):
		return APIToken{}, invalid("creator must be 1 to %d characters on one line", maxAPITokenCreatedByLen)
	case !t.ExpiresAt.IsZero() && !t.ExpiresAt.After(t.CreatedAt):
		return APIToken{}, invalid("token must expire after its creation")
	case !t.LastUsedAt.IsZero() || !t.RevokedAt.IsZero():
		return APIToken{}, invalid("a new token is neither used nor revoked")
	}
	t.CreatedAt = fromMillis(toMillis(t.CreatedAt))
	if !t.ExpiresAt.IsZero() {
		t.ExpiresAt = fromMillis(toMillis(t.ExpiresAt))
	}
	err = sc.Tx(ctx, func(tx *ScopedTx) error {
		_, err := tx.Exec(ctx, qAPITokenInsert, t.ID, t.Name, t.Prefix, t.TokenHash, doc, sendersDoc, t.CreatedBy,
			toMillis(t.CreatedAt), nullTime(t.ExpiresAt))
		return err
	})
	if err != nil {
		return APIToken{}, wrap("create api token", err)
	}
	return t, nil
}

// Get returns the token tokID of tenant tid, in whatever state it is, or
// ErrNotFound when it does not exist or belongs to another tenant.
func (r *APITokens) Get(ctx context.Context, tid tenant.ID, tokID string) (APIToken, error) {
	return readScoped(ctx, r.db, tid, "get api token", func(tx *ScopedTx) (APIToken, error) {
		return scanAPIToken(tx.QueryRow(ctx, qAPITokenGet, tokID))
	})
}

// GetByHash returns the token of tenant tid whose secret hashes to hash, in
// whatever state it is (the caller checks revocation and expiry). The
// lookup runs in the tenant scope (under row-level security on
// PostgreSQL): a token of another tenant is reported as ErrNotFound, like
// an unknown one (threat model T-69). It returns ErrInvalid for a hash of
// the wrong size.
func (r *APITokens) GetByHash(ctx context.Context, tid tenant.ID, hash []byte) (APIToken, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return APIToken{}, err
	}
	if !validTokenHash(hash) {
		return APIToken{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	return readScoped(ctx, r.db, tid, "get api token by hash", func(tx *ScopedTx) (APIToken, error) {
		return scanAPIToken(tx.QueryRow(ctx, qAPITokenGetByHash, hash))
	})
}

// List returns every token of tenant tid, revoked ones included, newest
// first.
func (r *APITokens) List(ctx context.Context, tid tenant.ID) ([]APIToken, error) {
	return readScoped(ctx, r.db, tid, "list api tokens", func(tx *ScopedTx) ([]APIToken, error) {
		rows, err := tx.Query(ctx, qAPITokenList)
		if err != nil {
			return nil, err
		}
		return collect(rows, func(r *sql.Rows) (APIToken, error) { return scanAPIToken(r) })
	})
}

// Update applies u to the token tokID of tenant tid and returns the token
// as changed. It returns ErrInvalid for a malformed name, set of ranges or
// set of senders,
// ErrNotFound when the token does not exist (or belongs to another tenant)
// and ErrConflict when it is revoked.
func (r *APITokens) Update(ctx context.Context, tid tenant.ID, tokID string, u APITokenUpdate) (APIToken, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return APIToken{}, err
	}
	if u.Name != "" && !validAPITokenName(u.Name) {
		return APIToken{}, invalid("name must be 1 to %d characters on one line", MaxAPITokenNameLen)
	}
	var name, doc, sendersDoc any
	if u.Name != "" {
		name = u.Name
	}
	if u.AllowedCIDRs != nil {
		_, text, err := normalizeCIDRs(u.AllowedCIDRs)
		if err != nil {
			return APIToken{}, err
		}
		doc = text
	}
	if u.AllowedSenders != nil {
		_, text, err := normalizeSenders(u.AllowedSenders)
		if err != nil {
			return APIToken{}, err
		}
		sendersDoc = text
	}
	return writeScopedValue(ctx, r.db, tid, "update api token", func(tx *ScopedTx) (APIToken, error) {
		res, err := tx.Exec(ctx, qAPITokenUpdate, name, doc, sendersDoc, tokID)
		if err != nil {
			return APIToken{}, err
		}
		if err := expectOne(res); err != nil {
			if !errors.Is(err, ErrNotFound) {
				return APIToken{}, err
			}
			return APIToken{}, probe(ctx, tx, qAPITokenCount, tokID, ErrConflict)
		}
		return scanAPIToken(tx.QueryRow(ctx, qAPITokenGet, tokID))
	})
}

// Revoke revokes the token tokID of tenant tid at now and returns it. It
// reports whether this call revoked it: revoking a token already revoked
// changes nothing and reports false. It returns ErrNotFound when the token
// does not exist or belongs to another tenant.
func (r *APITokens) Revoke(ctx context.Context, tid tenant.ID, tokID string, now time.Time) (APIToken, bool, error) {
	var revoked bool
	tok, err := writeScopedValue(ctx, r.db, tid, "revoke api token", func(tx *ScopedTx) (APIToken, error) {
		res, err := tx.Exec(ctx, qAPITokenRevoke, toMillis(r.db.orNow(now)), tokID)
		if err != nil {
			return APIToken{}, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return APIToken{}, err
		}
		revoked = n == 1
		return scanAPIToken(tx.QueryRow(ctx, qAPITokenGet, tokID))
	})
	if err != nil {
		return APIToken{}, false, err
	}
	return tok, revoked, nil
}

// writeScopedValue is writeScoped for a function returning a value.
func writeScopedValue[T any](ctx context.Context, db *DB, tid tenant.ID, op string, fn func(*ScopedTx) (T, error)) (T, error) {
	var v T
	err := writeScoped(ctx, db, tid, op, func(tx *ScopedTx) error {
		var err error
		v, err = fn(tx)
		return err
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return v, nil
}

// TouchLastUsed records at as the last use of the token tokID of tenant
// tid, unless a later use is already recorded. An unknown token (or one of
// another tenant) changes nothing and is not an error.
func (r *APITokens) TouchLastUsed(ctx context.Context, tid tenant.ID, tokID string, at time.Time) error {
	return writeScoped(ctx, r.db, tid, "touch api token", func(tx *ScopedTx) error {
		ms := toMillis(r.db.orNow(at))
		_, err := tx.Exec(ctx, qAPITokenTouch, ms, tokID, ms)
		return err
	})
}

// checkAPIToken verifies, inside tx, that tokID is a token of the tenant tx
// is bound to, usable at now: the foreign key of transfers.api_token_id only
// proves that the token exists, the tenant-scoped read proves it belongs to
// this tenant. A revoked or expired token is reported as ErrNotFound.
func checkAPIToken(ctx context.Context, tx *ScopedTx, tokID string, now time.Time) error {
	tok, err := scanAPIToken(tx.QueryRow(ctx, qAPITokenGet, tokID))
	if err != nil {
		return err
	}
	if !tok.Usable(now) {
		return ErrNotFound
	}
	return nil
}

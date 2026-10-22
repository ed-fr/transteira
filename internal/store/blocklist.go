package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// BlocklistKind is the kind of value a blocklist entry blocks.
type BlocklistKind string

// Blocklist kinds (spec 15.2).
const (
	// BlockEmail blocks one mail address.
	BlockEmail BlocklistKind = "email"
	// BlockDomain blocks a mail domain and its sub-domains.
	BlockDomain BlocklistKind = "domain"
	// BlockSHA256 blocks a file by its SHA-256 fingerprint.
	BlockSHA256 BlocklistKind = "sha256"
)

// Length limits of blocklist fields, in characters.
const (
	maxEmailLocalLen     = 64
	maxBlockCommentLen   = 500
	maxBlockCreatedByLen = 320
	sha256HexLen         = 64
)

// blockColumns is the column list read by the blocklist queries.
const blockColumns = `id, kind, value, comment, created_by, created_at`

// Statements of the Blocklist repository.
var (
	qBlockInsert = tenantQuery(
		`INSERT INTO blocklist_entries (tenant_id, id, kind, value, comment, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	qBlockList = tenantQuery(
		`SELECT ` + blockColumns + ` FROM blocklist_entries
		WHERE tenant_id = ? AND id > ? ORDER BY id LIMIT ?`)
	qBlockListKind = tenantQuery(
		`SELECT ` + blockColumns + ` FROM blocklist_entries
		WHERE tenant_id = ? AND kind = ? AND id > ? ORDER BY id LIMIT ?`)
	qBlockGet = tenantQuery(
		`SELECT ` + blockColumns + ` FROM blocklist_entries WHERE tenant_id = ? AND id = ?`)
	qBlockDelete = tenantQuery(
		`DELETE FROM blocklist_entries WHERE tenant_id = ? AND id = ?`)
	// qBlockMatch finds the entries blocking an address, its domain (or a
	// parent domain) or a file fingerprint. Arguments after the tenant:
	// email, sha256, domain, domain. Domains only contain [a-z0-9.-], so
	// the LIKE pattern has no wildcard other than the leading '%'.
	qBlockMatch = tenantQuery(
		`SELECT ` + blockColumns + ` FROM blocklist_entries
		WHERE tenant_id = ? AND (
			(kind = 'email' AND value = ?)
			OR (kind = 'sha256' AND value = ?)
			OR (kind = 'domain' AND (value = ? OR ? LIKE ('%.' || value)))
		)
		ORDER BY id`)
)

// BlocklistEntry is a blocked address, domain or file fingerprint.
type BlocklistEntry struct {
	// ID is the entry identifier ("blk_" + ULID), assigned by the store.
	ID string
	// Kind is the kind of Value.
	Kind BlocklistKind
	// Value is the normalized blocked value.
	Value string
	// Comment is an optional note from the admin (at most 500 characters).
	Comment string
	// CreatedBy identifies the admin who created the entry.
	CreatedBy string
	// CreatedAt is the creation time, assigned by the store.
	CreatedAt time.Time
}

// Normalize validates v for kind k and returns its normalized form:
// lowercase address with a valid domain, normalized domain, or lowercase
// hexadecimal SHA-256. It returns ErrInvalid otherwise; the error never
// quotes v.
func (k BlocklistKind) Normalize(v string) (string, error) {
	v = strings.TrimSpace(v)
	switch k {
	case BlockEmail:
		local, domain, ok := strings.Cut(strings.ToLower(v), "@")
		if !ok || local == "" || len(local) > maxEmailLocalLen || strings.ContainsAny(local, "@ \t\r\n") {
			return "", invalid("malformed email address")
		}
		d, err := normalizeDomain(domain)
		if err != nil {
			return "", invalid("malformed email address")
		}
		return local + "@" + d, nil
	case BlockDomain:
		return normalizeDomain(v)
	case BlockSHA256:
		v = strings.ToLower(v)
		if len(v) != sha256HexLen || strings.Trim(v, "0123456789abcdef") != "" {
			return "", invalid("malformed sha256 fingerprint")
		}
		return v, nil
	}
	return "", invalid("unknown blocklist kind")
}

// Blocklist is the tenant-scoped repository of blocked addresses, domains
// and file fingerprints. Obtain it with [DB.Blocklist].
type Blocklist struct {
	db *DB
}

// Blocklist returns the blocklist repository.
func (db *DB) Blocklist() *Blocklist { return &Blocklist{db: db} }

// scanBlock reads one row of blockColumns.
func scanBlock(r interface{ Scan(...any) error }) (BlocklistEntry, error) {
	var (
		e       BlocklistEntry
		kind    string
		created int64
	)
	if err := r.Scan(&e.ID, &kind, &e.Value, &e.Comment, &e.CreatedBy, &created); err != nil {
		return BlocklistEntry{}, err
	}
	e.Kind = BlocklistKind(kind)
	e.CreatedAt = fromMillis(created)
	return e, nil
}

// BlocklistFilter selects a page of blocklist entries.
type BlocklistFilter struct {
	// Kind restricts the list to one kind ("" for every kind).
	Kind BlocklistKind
	// Cursor is the NextCursor of the previous page, or "" for the first.
	Cursor string
	// Limit is the page size (DefaultPageSize when <= 0, at most
	// MaxPageSize).
	Limit int
}

// List returns a page of the entries of tenant tid, ordered by ID, which is
// approximately creation order (IDs created in the same millisecond sort
// randomly). An unknown kind or a malformed cursor yields ErrInvalid.
func (r *Blocklist) List(ctx context.Context, tid tenant.ID, f BlocklistFilter) (Page[BlocklistEntry], error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return Page[BlocklistEntry]{}, err
	}
	switch f.Kind {
	case "", BlockEmail, BlockDomain, BlockSHA256:
	default:
		return Page[BlocklistEntry]{}, invalid("unknown blocklist kind")
	}
	if f.Cursor != "" && !id.Valid(id.Blocklist, f.Cursor) {
		return Page[BlocklistEntry]{}, invalid("malformed cursor")
	}
	limit := pageLimit(f.Limit)
	var items []BlocklistEntry
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		var (
			rows *sql.Rows
			err  error
		)
		if f.Kind == "" {
			rows, err = tx.Query(ctx, qBlockList, f.Cursor, limit+1)
		} else {
			rows, err = tx.Query(ctx, qBlockListKind, string(f.Kind), f.Cursor, limit+1)
		}
		if err != nil {
			return err
		}
		items, err = collect(rows, func(r *sql.Rows) (BlocklistEntry, error) { return scanBlock(r) })
		return err
	})
	if err != nil {
		return Page[BlocklistEntry]{}, wrap("list blocklist", err)
	}
	return paginate(items, limit, func(e BlocklistEntry) string { return e.ID }), nil
}

// Create normalizes and stores a new entry for tenant tid. The ID and
// CreatedAt fields of e are ignored and assigned by the store. It returns
// the stored entry, ErrInvalid for invalid fields, ErrConflict when the
// value is already blocked and ErrNotFound when the tenant does not exist.
func (r *Blocklist) Create(ctx context.Context, tid tenant.ID, e BlocklistEntry) (BlocklistEntry, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return BlocklistEntry{}, err
	}
	value, err := e.Kind.Normalize(e.Value)
	if err != nil {
		return BlocklistEntry{}, err
	}
	if utf8.RuneCountInString(e.Comment) > maxBlockCommentLen || !utf8.ValidString(e.Comment) {
		return BlocklistEntry{}, invalid("comment must be valid text of at most %d characters", maxBlockCommentLen)
	}
	if utf8.RuneCountInString(e.CreatedBy) > maxBlockCreatedByLen || !utf8.ValidString(e.CreatedBy) {
		return BlocklistEntry{}, invalid("creator must be valid text of at most %d characters", maxBlockCreatedByLen)
	}
	newID, err := r.db.newID(id.Blocklist)
	if err != nil {
		return BlocklistEntry{}, wrap("create blocklist entry", err)
	}
	out := BlocklistEntry{
		ID: newID, Kind: e.Kind, Value: value, Comment: e.Comment, CreatedBy: e.CreatedBy,
		CreatedAt: r.db.now().UTC().Truncate(time.Millisecond),
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		_, err := tx.Exec(ctx, qBlockInsert, out.ID, string(out.Kind), out.Value, out.Comment,
			out.CreatedBy, toMillis(out.CreatedAt))
		return err
	})
	if err != nil {
		return BlocklistEntry{}, wrap("create blocklist entry", err)
	}
	return out, nil
}

// Get returns the entry entryID of tenant tid. It returns ErrNotFound when
// the entry does not exist or belongs to another tenant.
func (r *Blocklist) Get(ctx context.Context, tid tenant.ID, entryID string) (BlocklistEntry, error) {
	return readScoped(ctx, r.db, tid, "get blocklist entry", func(tx *ScopedTx) (BlocklistEntry, error) {
		return scanBlock(tx.QueryRow(ctx, qBlockGet, entryID))
	})
}

// Delete removes the entry entryID of tenant tid. It returns ErrNotFound
// when the entry does not exist or belongs to another tenant.
func (r *Blocklist) Delete(ctx context.Context, tid tenant.ID, entryID string) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		res, err := tx.Exec(ctx, qBlockDelete, entryID)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("delete blocklist entry", err)
	}
	return nil
}

// Match returns the entries of tenant tid blocking the mail address email
// (exact address, its domain or any parent domain) or the file fingerprint
// sha256. Either argument may be empty to skip it. It returns an empty
// slice when nothing matches and ErrInvalid for a malformed argument.
func (r *Blocklist) Match(ctx context.Context, tid tenant.ID, email, sha256 string) ([]BlocklistEntry, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return nil, err
	}
	var domain string
	if email != "" {
		if email, err = BlockEmail.Normalize(email); err != nil {
			return nil, err
		}
		_, domain, _ = strings.Cut(email, "@")
	}
	if sha256 != "" {
		if sha256, err = BlockSHA256.Normalize(sha256); err != nil {
			return nil, err
		}
	}
	if email == "" && sha256 == "" {
		return []BlocklistEntry{}, nil
	}
	var out []BlocklistEntry
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		rows, err := tx.Query(ctx, qBlockMatch, email, sha256, domain, domain)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (BlocklistEntry, error) { return scanBlock(r) })
		return err
	})
	if err != nil {
		return nil, wrap("match blocklist", err)
	}
	return out, nil
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Reasons of the tenant system queries.
const (
	reasonTenantAdmin   = "tenant administration by the super admin (tenants table is the tenant registry)"
	reasonTenantResolve = "resolve the tenant serving an HTTP Host before any tenant is known"
)

// tenantColumns is the column list read by the tenant queries.
const tenantColumns = `id, name, fqdn, default_language, max_transfer_bytes, storage_quota_bytes, created_at, updated_at`

// Statements of the Tenants repository. The tenants table is the registry of
// tenants itself, so its statements are system queries.
var (
	qTenantInsert = systemQuery(
		`INSERT INTO tenants (`+tenantColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		reasonTenantAdmin)
	qTenantGet = systemQuery(
		`SELECT `+tenantColumns+` FROM tenants WHERE id = ?`,
		reasonTenantAdmin)
	qTenantByFQDN = systemQuery(
		`SELECT `+tenantColumns+` FROM tenants WHERE fqdn = ?`,
		reasonTenantResolve)
	qTenantList = systemQuery(
		`SELECT `+tenantColumns+` FROM tenants WHERE id > ? ORDER BY id LIMIT ?`,
		reasonTenantAdmin)
	qTenantUpdate = systemQuery(
		`UPDATE tenants SET name = ?, fqdn = ?, default_language = ?, max_transfer_bytes = ?,
			storage_quota_bytes = ?, updated_at = ? WHERE id = ?`,
		reasonTenantAdmin)
	qTenantDelete = systemQuery(
		`DELETE FROM tenants WHERE id = ?`,
		reasonTenantAdmin)
)

// Tenants is the repository of tenants. Its operations are system-scoped:
// it serves the super admin and the Host resolution. Callers must check the
// caller's scope before using it. Obtain it with [DB.Tenants].
type Tenants struct {
	db *DB
}

// Tenants returns the tenant repository.
func (db *DB) Tenants() *Tenants { return &Tenants{db: db} }

// compile-time check: Tenants resolves hosts for tenant.Resolver.
var _ tenant.Lookup = (*Tenants)(nil)

// system returns the system executor for reason (always non-empty here).
func (r *Tenants) system(reason string) *System {
	s, _ := r.db.System(reason)
	return s
}

// scanTenant reads one row of tenantColumns.
func scanTenant(sc interface{ Scan(...any) error }) (*tenant.Tenant, error) {
	var (
		t                tenant.Tenant
		tid              string
		created, updated int64
	)
	if err := sc.Scan(&tid, &t.Name, &t.FQDN, &t.DefaultLanguage, &t.MaxTransferBytes,
		&t.StorageQuotaBytes, &created, &updated); err != nil {
		return nil, err
	}
	t.ID = tenant.ID(tid)
	t.CreatedAt = fromMillis(created)
	t.UpdatedAt = fromMillis(updated)
	return &t, nil
}

// Create validates t, assigns it a new ID and timestamps, and stores it. It
// returns the stored tenant, ErrInvalid for invalid fields (including a
// preset ID) and ErrConflict when the FQDN is already used.
func (r *Tenants) Create(ctx context.Context, t *tenant.Tenant) (*tenant.Tenant, error) {
	if !t.ID.IsZero() {
		return nil, invalid("tenant id is assigned by the store")
	}
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	newID, err := r.db.newID(id.Tenant)
	if err != nil {
		return nil, wrap("create tenant", err)
	}
	c := t.Clone()
	c.ID = tenant.ID(newID)
	now := r.db.now().UTC().Truncate(time.Millisecond) // millisecond precision, as stored
	c.CreatedAt, c.UpdatedAt = now, now
	err = r.system(reasonTenantAdmin).Tx(ctx, func(tx *SystemTx) error {
		_, err := tx.Exec(ctx, qTenantInsert, string(c.ID), c.Name, c.FQDN, c.DefaultLanguage,
			c.MaxTransferBytes, c.StorageQuotaBytes, toMillis(now), toMillis(now))
		return err
	})
	if err != nil {
		return nil, wrap("create tenant", err)
	}
	return c, nil
}

// Get returns the tenant tid, or ErrNotFound.
func (r *Tenants) Get(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if err := tid.Validate(); err != nil {
		return nil, fmt.Errorf("store: get tenant: %w", ErrNotFound)
	}
	var t *tenant.Tenant
	err := r.system(reasonTenantAdmin).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		t, err = scanTenant(tx.QueryRow(ctx, qTenantGet, string(tid)))
		return err
	})
	if err != nil {
		return nil, wrap("get tenant", err)
	}
	return t, nil
}

// TenantByFQDN returns the tenant served by the normalized host name fqdn.
// It implements [tenant.Lookup]: an unknown host yields an error wrapping
// both tenant.ErrUnknownTenant and ErrNotFound.
func (r *Tenants) TenantByFQDN(ctx context.Context, fqdn string) (*tenant.Tenant, error) {
	var t *tenant.Tenant
	err := r.system(reasonTenantResolve).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		t, err = scanTenant(tx.QueryRow(ctx, qTenantByFQDN, fqdn))
		return err
	})
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, fmt.Errorf("%w: %w", tenant.ErrUnknownTenant, ErrNotFound)
	case err != nil:
		return nil, wrap("resolve tenant", err)
	}
	return t, nil
}

// TenantListOptions selects a page of tenants.
type TenantListOptions struct {
	// Cursor is the NextCursor of the previous page, or "" for the first.
	Cursor string
	// Limit is the page size (DefaultPageSize when <= 0, at most
	// MaxPageSize).
	Limit int
}

// List returns a page of tenants ordered by ID, which is approximately
// creation order (IDs created in the same millisecond sort randomly). A
// malformed cursor yields ErrInvalid.
func (r *Tenants) List(ctx context.Context, opts TenantListOptions) (Page[*tenant.Tenant], error) {
	if opts.Cursor != "" && tenant.ID(opts.Cursor).Validate() != nil {
		return Page[*tenant.Tenant]{}, invalid("malformed cursor")
	}
	limit := pageLimit(opts.Limit)
	var items []*tenant.Tenant
	err := r.system(reasonTenantAdmin).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qTenantList, opts.Cursor, limit+1)
		if err != nil {
			return err
		}
		items, err = collect(rows, func(r *sql.Rows) (*tenant.Tenant, error) { return scanTenant(r) })
		return err
	})
	if err != nil {
		return Page[*tenant.Tenant]{}, wrap("list tenants", err)
	}
	return paginate(items, limit, func(t *tenant.Tenant) string { return string(t.ID) }), nil
}

// Update stores the modifiable fields of t (name, FQDN, language, limits)
// and refreshes UpdatedAt. It returns the stored tenant, ErrInvalid for
// invalid fields, ErrNotFound when the tenant does not exist and ErrConflict
// when the new FQDN is already used. Callers must invalidate the
// tenant.Resolver cache for the old and new FQDN.
func (r *Tenants) Update(ctx context.Context, t *tenant.Tenant) (*tenant.Tenant, error) {
	if t.ID.IsZero() {
		return nil, invalid("tenant id is required")
	}
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	now := toMillis(r.db.now())
	var out *tenant.Tenant
	err := r.system(reasonTenantAdmin).Tx(ctx, func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qTenantUpdate, t.Name, t.FQDN, t.DefaultLanguage,
			t.MaxTransferBytes, t.StorageQuotaBytes, now, string(t.ID))
		if err != nil {
			return err
		}
		if err := expectOne(res); err != nil {
			return err
		}
		out, err = scanTenant(tx.QueryRow(ctx, qTenantGet, string(t.ID)))
		return err
	})
	if err != nil {
		return nil, wrap("update tenant", err)
	}
	return out, nil
}

// Delete removes the tenant tid and, by cascade, every row it owns. It
// returns ErrNotFound when the tenant does not exist. Erasing the tenant's
// files and keys is the caller's job.
func (r *Tenants) Delete(ctx context.Context, tid tenant.ID) error {
	err := r.system(reasonTenantAdmin).Tx(ctx, func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qTenantDelete, string(tid))
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("delete tenant", err)
	}
	return nil
}

// expectOne returns ErrNotFound unless res reports at least one affected row.
func expectOne(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

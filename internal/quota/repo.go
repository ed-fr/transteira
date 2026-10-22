package quota

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// storeRepo is the repo of the monitor over the store.
type storeRepo struct {
	db *store.DB
}

// tenant implements repo.
func (r storeRepo) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	return r.db.Tenants().Get(ctx, tid)
}

// activeTenants implements repo: every page of the tenants, those being
// deleted left out.
func (r storeRepo) activeTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	return activeTenants(ctx, r.db)
}

// usedBytes implements repo.
func (r storeRepo) usedBytes(ctx context.Context, tid tenant.ID) (int64, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return 0, err
	}
	var n int64
	err = s.ReadTx(ctx, func(tx *store.ScopedTx) error {
		var err error
		n, err = r.db.Transfers().UsedBytesTx(ctx, tx)
		return err
	})
	return n, err
}

// usedBytesAll implements repo.
func (r storeRepo) usedBytesAll(ctx context.Context) (map[tenant.ID]int64, error) {
	return r.db.Transfers().UsedBytesAll(ctx)
}

// level implements repo.
func (r storeRepo) level(ctx context.Context, tid tenant.ID) (int, error) {
	a, err := r.db.QuotaAlerts().Get(ctx, tid)
	return a.Level, err
}

// compareAndSet implements repo.
func (r storeRepo) compareAndSet(ctx context.Context, tid tenant.ID, old, level int, now time.Time) (bool, error) {
	return r.db.QuotaAlerts().CompareAndSet(ctx, tid, old, level, now)
}

// tenantContacts implements repo.
func (r storeRepo) tenantContacts(ctx context.Context, tid tenant.ID) ([]store.AdminContact, error) {
	return r.db.Admins().TenantContacts(ctx, tid)
}

// superAdminContacts implements repo.
func (r storeRepo) superAdminContacts(ctx context.Context) ([]store.AdminContact, error) {
	return r.db.Admins().SuperAdminContacts(ctx)
}

// listPageSize is the page size of the tenant list (a variable for the
// tests).
var listPageSize = store.MaxPageSize

// activeTenants returns every active tenant of db (tenants being deleted
// left out), by ID, reading all the pages of the tenant list.
func activeTenants(ctx context.Context, db *store.DB) ([]*tenant.Tenant, error) {
	var (
		out    []*tenant.Tenant
		cursor string
	)
	for {
		page, err := db.Tenants().List(ctx, store.TenantListOptions{Cursor: cursor, Limit: listPageSize})
		if err != nil {
			return nil, err
		}
		for _, t := range page.Items {
			if t.Status == tenant.StatusActive {
				out = append(out, t)
			}
		}
		if page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
}

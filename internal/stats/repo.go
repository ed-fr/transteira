package stats

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// listPageSize is the page size of the tenant list (a variable for the
// tests).
var listPageSize = store.MaxPageSize

// storeRepo is the repo of the service over the store.
type storeRepo struct {
	db *store.DB
}

// tenant implements repo.
func (r storeRepo) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	return r.db.Tenants().Get(ctx, tid)
}

// activeTenants implements repo: every page of the tenants, those being
// deleted left out, by ID.
func (r storeRepo) activeTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	var (
		out    []*tenant.Tenant
		cursor string
	)
	for {
		page, err := r.db.Tenants().List(ctx, store.TenantListOptions{Cursor: cursor, Limit: listPageSize})
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

// usedBytes implements repo, in the scope of tenant tid.
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

// usage implements repo.
func (r storeRepo) usage(ctx context.Context, tid tenant.ID, fromDay time.Time) ([]store.DailyUsage, error) {
	return r.db.TenantUsage().Range(ctx, tid, fromDay)
}

// usageAll implements repo.
func (r storeRepo) usageAll(ctx context.Context, fromDay time.Time) (map[tenant.ID]store.UsageCounts, error) {
	return r.db.TenantUsage().RangeAll(ctx, fromDay)
}

// scanQueueFiles implements repo.
func (r storeRepo) scanQueueFiles(ctx context.Context) (int64, error) {
	return r.db.Transfers().ScanQueueFiles(ctx)
}

// activeCounts implements repo.
func (r storeRepo) activeCounts(ctx context.Context, since time.Time) (map[tenant.ID]store.TenantTransferCounts, error) {
	rows, err := r.db.Transfers().ActiveCounts(ctx, since)
	if err != nil {
		return nil, err
	}
	out := make(map[tenant.ID]store.TenantTransferCounts, len(rows))
	for _, c := range rows {
		out[c.TenantID] = c
	}
	return out, nil
}

package avalert

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

// settings implements repo.
func (r storeRepo) settings(ctx context.Context) (store.SystemSettingsRow, error) {
	return r.db.SystemSettings().Get(ctx)
}

// superAdminContacts implements repo.
func (r storeRepo) superAdminContacts(ctx context.Context) ([]store.AdminContact, error) {
	return r.db.Admins().SuperAdminContacts(ctx)
}

// tenantContacts implements repo.
func (r storeRepo) tenantContacts(ctx context.Context, tid tenant.ID) ([]store.AdminContact, error) {
	return r.db.Admins().TenantContacts(ctx, tid)
}

// tenant implements repo.
func (r storeRepo) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	return r.db.Tenants().Get(ctx, tid)
}

// waiting implements repo.
func (r storeRepo) waiting(ctx context.Context) ([]store.TenantScanning, error) {
	return r.db.Transfers().ScanningCounts(ctx)
}

// claimMail implements repo.
func (r storeRepo) claimMail(ctx context.Context, now time.Time) (bool, error) {
	return r.db.SystemSettings().ClaimAntivirusAlertMail(ctx, now, MailInterval)
}

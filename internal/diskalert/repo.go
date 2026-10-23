package diskalert

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/store"
)

// storeRepo is the repo of the monitor over the store.
type storeRepo struct {
	db *store.DB
}

// settings implements repo.
func (r storeRepo) settings(ctx context.Context) (store.SystemSettingsRow, error) {
	return r.db.SystemSettings().Get(ctx)
}

// compareAndSet implements repo.
func (r storeRepo) compareAndSet(ctx context.Context, old, level int, now time.Time) (bool, error) {
	return r.db.SystemSettings().CompareAndSetDiskLevel(ctx, old, level, now)
}

// superAdminContacts implements repo.
func (r storeRepo) superAdminContacts(ctx context.Context) ([]store.AdminContact, error) {
	return r.db.Admins().SuperAdminContacts(ctx)
}

// claimMail implements repo.
func (r storeRepo) claimMail(ctx context.Context, now time.Time) (bool, error) {
	return r.db.SystemSettings().ClaimDiskAlertMail(ctx, now, MailInterval)
}

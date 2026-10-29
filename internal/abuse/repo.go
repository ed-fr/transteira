package abuse

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// repo is the data the detector reads and writes. storeRepo implements it
// over the store; every method is scoped to one tenant.
type repo interface {
	// settings returns the abuse settings of tenant tid.
	settings(ctx context.Context, tid tenant.ID) (store.AbuseSettings, error)
	// settingsTx returns the abuse settings of the tenant of tx.
	settingsTx(ctx context.Context, tx *store.ScopedTx) (store.AbuseSettings, error)
	// activityTx sums the activity of email in [start, end) inside tx.
	activityTx(ctx context.Context, tx *store.ScopedTx, email string, start, end time.Time, kinds []store.DepositorKind) (int64, int, error)
	// activity sums the activity of email in [start, end) for tenant tid.
	activity(ctx context.Context, tid tenant.ID, email string, start, end time.Time, kinds []store.DepositorKind) (int64, int, error)
	// history lists the creations of email since since, newest first.
	history(ctx context.Context, tid tenant.ID, email string, since time.Time) ([]store.SenderTransferVolume, error)
	// internalDomains returns the internal mail domains of tenant tid.
	internalDomains(ctx context.Context, tid tenant.ID) ([]string, error)
	// tryAlert records the alert of email, rule, day and kind (blocked or
	// alert-only) for tenant tid and reports whether it is the first one.
	tryAlert(ctx context.Context, tid tenant.ID, email string, rule store.AbuseRule, day string, blocked bool, now time.Time) (bool, error)
	// tenantContacts returns the delegated admins of tenant tid to notify.
	tenantContacts(ctx context.Context, tid tenant.ID) ([]store.AdminContact, error)
	// superAdminContacts returns the super admins to notify.
	superAdminContacts(ctx context.Context) ([]store.AdminContact, error)
}

// storeRepo is the repo of the detector over the store.
type storeRepo struct {
	db *store.DB
}

// settings implements repo.
func (r storeRepo) settings(ctx context.Context, tid tenant.ID) (store.AbuseSettings, error) {
	return r.db.AbuseSettings().Get(ctx, tid)
}

// settingsTx implements repo.
func (r storeRepo) settingsTx(ctx context.Context, tx *store.ScopedTx) (store.AbuseSettings, error) {
	return r.db.AbuseSettings().GetTx(ctx, tx)
}

// activityTx implements repo.
func (r storeRepo) activityTx(ctx context.Context, tx *store.ScopedTx, email string, start, end time.Time, kinds []store.DepositorKind) (int64, int, error) {
	return r.db.Transfers().SenderActivityTx(ctx, tx, email, start, end, kinds)
}

// activity implements repo.
func (r storeRepo) activity(ctx context.Context, tid tenant.ID, email string, start, end time.Time, kinds []store.DepositorKind) (int64, int, error) {
	return r.db.Transfers().SenderActivity(ctx, tid, email, start, end, kinds)
}

// history implements repo, capped at store.MaxSenderHistoryRows rows.
func (r storeRepo) history(ctx context.Context, tid tenant.ID, email string, since time.Time) ([]store.SenderTransferVolume, error) {
	return r.db.Transfers().SenderHistory(ctx, tid, email, since, store.MaxSenderHistoryRows)
}

// internalDomains implements repo.
func (r storeRepo) internalDomains(ctx context.Context, tid tenant.ID) ([]string, error) {
	rs, err := r.db.NetworkRules().Get(ctx, tid)
	return rs.Domains, err
}

// tryAlert implements repo, in a transaction of its own.
func (r storeRepo) tryAlert(ctx context.Context, tid tenant.ID, email string, rule store.AbuseRule, day string, blocked bool, now time.Time) (bool, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return false, err
	}
	var inserted bool
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		inserted, err = r.db.AbuseAlerts().TryInsertTx(ctx, tx, email, rule, day, blocked, now)
		return err
	})
	return inserted, err
}

// tenantContacts implements repo.
func (r storeRepo) tenantContacts(ctx context.Context, tid tenant.ID) ([]store.AdminContact, error) {
	return r.db.Admins().TenantContacts(ctx, tid)
}

// superAdminContacts implements repo.
func (r storeRepo) superAdminContacts(ctx context.Context) ([]store.AdminContact, error) {
	return r.db.Admins().SuperAdminContacts(ctx)
}

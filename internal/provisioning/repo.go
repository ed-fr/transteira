package provisioning

import (
	"context"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// repo is the persistence used by the service: the store repositories and
// the audit writer behind one interface, so that the tests can inject
// failures.
type repo interface {
	createToken(ctx context.Context, t store.ProvisioningToken, then func(tx *store.SystemTx, t store.ProvisioningToken) error) (store.ProvisioningToken, error)
	listTokens(ctx context.Context) ([]store.ProvisioningToken, error)
	revokeToken(ctx context.Context, tokID string, now time.Time, then func(tx *store.SystemTx, t store.ProvisioningToken, revoked bool) error) (store.ProvisioningToken, bool, error)
	tokenByHash(ctx context.Context, hash []byte) (store.ProvisioningToken, error)
	touch(ctx context.Context, tokID string, at time.Time) error
	listTenants(ctx context.Context, tokID string) ([]store.ProvisionedTenant, error)
	getTenant(ctx context.Context, tokID string, tid tenant.ID) (store.ProvisionedTenant, error)
	record(ctx context.Context, ev audit.Event) error
	recordTx(ctx context.Context, tx *store.SystemTx, ev audit.Event) error
}

// storeRepo implements repo with the store and an audit writer.
type storeRepo struct {
	db     *store.DB
	writer *audit.Writer
}

func (r *storeRepo) createToken(ctx context.Context, t store.ProvisioningToken, then func(tx *store.SystemTx, t store.ProvisioningToken) error) (store.ProvisioningToken, error) {
	return r.db.ProvisioningTokens().Create(ctx, t, then)
}

func (r *storeRepo) listTokens(ctx context.Context) ([]store.ProvisioningToken, error) {
	return r.db.ProvisioningTokens().List(ctx)
}

func (r *storeRepo) revokeToken(ctx context.Context, tokID string, now time.Time, then func(tx *store.SystemTx, t store.ProvisioningToken, revoked bool) error) (store.ProvisioningToken, bool, error) {
	return r.db.ProvisioningTokens().Revoke(ctx, tokID, now, then)
}

func (r *storeRepo) tokenByHash(ctx context.Context, hash []byte) (store.ProvisioningToken, error) {
	return r.db.ProvisioningTokens().GetByHash(ctx, hash)
}

func (r *storeRepo) touch(ctx context.Context, tokID string, at time.Time) error {
	return r.db.ProvisioningTokens().Touch(ctx, tokID, at)
}

func (r *storeRepo) listTenants(ctx context.Context, tokID string) ([]store.ProvisionedTenant, error) {
	return r.db.ProvisioningTokens().ListTenants(ctx, tokID)
}

func (r *storeRepo) getTenant(ctx context.Context, tokID string, tid tenant.ID) (store.ProvisionedTenant, error) {
	return r.db.ProvisioningTokens().GetTenant(ctx, tokID, tid)
}

func (r *storeRepo) record(ctx context.Context, ev audit.Event) error {
	return r.writer.Record(ctx, ev)
}

func (r *storeRepo) recordTx(ctx context.Context, tx *store.SystemTx, ev audit.Event) error {
	return r.writer.RecordTx(ctx, tx, ev)
}

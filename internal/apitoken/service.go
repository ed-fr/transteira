package apitoken

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Defaults of the [Options].
const (
	// DefaultTouchInterval is the minimum delay between two recordings of
	// the last use of a token.
	DefaultTouchInterval = time.Minute
	// DefaultMaxTracked bounds the number of tokens whose last recording
	// is remembered in memory.
	DefaultMaxTracked = 10000
)

// repo is the persistence used by the service: the store repositories
// behind one interface, so that the tests can inject failures.
type repo interface {
	getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	list(ctx context.Context, tid tenant.ID) ([]store.APIToken, error)
	create(ctx context.Context, tid tenant.ID, t store.APIToken) (store.APIToken, error)
	update(ctx context.Context, tid tenant.ID, tokID string, u store.APITokenUpdate) (store.APIToken, error)
	revoke(ctx context.Context, tid tenant.ID, tokID string, now time.Time) (store.APIToken, bool, error)
	getByHash(ctx context.Context, tid tenant.ID, hash []byte) (store.APIToken, error)
	touch(ctx context.Context, tid tenant.ID, tokID string, at time.Time) error
	audit(ctx context.Context, tid tenant.ID, ev audit.Event) error
}

// storeRepo implements repo with the store.
type storeRepo struct {
	db     *store.DB
	writer *audit.Writer
}

func (r *storeRepo) getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	return r.db.Tenants().Get(ctx, tid)
}

func (r *storeRepo) list(ctx context.Context, tid tenant.ID) ([]store.APIToken, error) {
	return r.db.APITokens().List(ctx, tid)
}

func (r *storeRepo) create(ctx context.Context, tid tenant.ID, t store.APIToken) (store.APIToken, error) {
	return r.db.APITokens().Create(ctx, tid, t)
}

func (r *storeRepo) update(ctx context.Context, tid tenant.ID, tokID string, u store.APITokenUpdate) (store.APIToken, error) {
	return r.db.APITokens().Update(ctx, tid, tokID, u)
}

func (r *storeRepo) revoke(ctx context.Context, tid tenant.ID, tokID string, now time.Time) (store.APIToken, bool, error) {
	return r.db.APITokens().Revoke(ctx, tid, tokID, now)
}

func (r *storeRepo) getByHash(ctx context.Context, tid tenant.ID, hash []byte) (store.APIToken, error) {
	return r.db.APITokens().GetByHash(ctx, tid, hash)
}

func (r *storeRepo) touch(ctx context.Context, tid tenant.ID, tokID string, at time.Time) error {
	return r.db.APITokens().TouchLastUsed(ctx, tid, tokID, at)
}

func (r *storeRepo) audit(ctx context.Context, tid tenant.ID, ev audit.Event) error {
	return r.writer.RecordScoped(ctx, tid, ev)
}

// Options configures a [Service].
type Options struct {
	// Logger receives the audit and last-use write failures; nil means
	// slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// TouchInterval is the minimum delay between two recordings of the
	// last use of a token; <= 0 means DefaultTouchInterval.
	TouchInterval time.Duration
	// MaxTracked bounds the tokens remembered for that throttling; <= 0
	// means DefaultMaxTracked.
	MaxTracked int
}

// Service manages and authenticates the API tokens. It is safe for
// concurrent use.
type Service struct {
	repo          repo
	logger        *slog.Logger
	now           func() time.Time
	touchInterval time.Duration
	maxTracked    int

	// mu guards touched: token ID -> time of the last recording of its
	// use by this process.
	mu      sync.Mutex
	touched map[string]time.Time
}

// errMissingDB reports a [New] call without a database.
var errMissingDB = errors.New("apitoken: a database is required")

// New returns the service over db.
func New(db *store.DB, opts Options) (*Service, error) {
	if db == nil {
		return nil, errMissingDB
	}
	return newService(&storeRepo{db: db, writer: audit.New(db)}, opts), nil
}

// newService returns the service over r.
func newService(r repo, opts Options) *Service {
	s := &Service{
		repo: r, logger: opts.Logger, now: opts.Now, touchInterval: opts.TouchInterval, maxTracked: opts.MaxTracked,
		touched: map[string]time.Time{},
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.touchInterval <= 0 {
		s.touchInterval = DefaultTouchInterval
	}
	if s.maxTracked <= 0 {
		s.maxTracked = DefaultMaxTracked
	}
	return s
}

// readable checks that p may read tenant tid, which must be active.
func (s *Service) readable(ctx context.Context, p adminauth.Principal, tid tenant.ID) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	if err := adminauth.RequireTenantAccess(p.Admin, tid); err != nil {
		return err
	}
	return s.activeTenant(ctx, tid)
}

// writable checks that p may change tenant tid, which must be active.
func (s *Service) writable(ctx context.Context, p adminauth.Principal, tid tenant.ID) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	if err := adminauth.RequireTenantWrite(p.Admin, tid); err != nil {
		return err
	}
	return s.activeTenant(ctx, tid)
}

// activeTenant checks that tenant tid exists and is active; a missing
// tenant, and a tenant being deleted, are ErrNotFound.
func (s *Service) activeTenant(ctx context.Context, tid tenant.ID) error {
	t, err := s.repo.getTenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("apitoken: get tenant: %w", err)
	case t.Status != tenant.StatusActive:
		return ErrNotFound
	}
	return nil
}

// record writes the audit event of a change made by p on token tokID of
// tenant tid. The change is committed already: a failure is logged, never
// returned, and a canceled request does not prevent the write.
func (s *Service) record(ctx context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID,
	action audit.Action, tokID string, details map[string]any,
) {
	ev := audit.Event{
		TenantID: tid, ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: ip,
		Action: action, ObjectKind: audit.ObjectAPIToken, ObjectID: tokID, Details: details,
	}
	if err := s.repo.audit(context.WithoutCancel(ctx), tid, ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(action)),
			slog.String("tenant", string(tid)), slog.String("error", err.Error()))
	}
}

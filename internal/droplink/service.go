package droplink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// repo is the persistence used by the service: the store repositories
// behind one interface, so that the tests can inject failures.
type repo interface {
	getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error)
	levels(ctx context.Context, tid tenant.ID) ([]store.ConfidentialityLevel, error)
	list(ctx context.Context, tid tenant.ID) ([]store.DropLink, error)
	get(ctx context.Context, tid tenant.ID, linkID string) (store.DropLink, error)
	create(ctx context.Context, tid tenant.ID, l store.DropLink) (store.DropLink, error)
	update(ctx context.Context, tid tenant.ID, linkID string, u store.DropLinkUpdate, now time.Time) (store.DropLink, bool, error)
	rotate(ctx context.Context, tid tenant.ID, linkID string, hash []byte, now time.Time) (store.DropLink, error)
	revoke(ctx context.Context, tid tenant.ID, linkID string, now time.Time) (store.DropLink, bool, error)
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

func (r *storeRepo) networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error) {
	return r.db.NetworkRules().Get(ctx, tid)
}

func (r *storeRepo) levels(ctx context.Context, tid tenant.ID) ([]store.ConfidentialityLevel, error) {
	return r.db.ConfidentialityLevels().List(ctx, tid)
}

func (r *storeRepo) list(ctx context.Context, tid tenant.ID) ([]store.DropLink, error) {
	return r.db.DropLinks().List(ctx, tid)
}

func (r *storeRepo) get(ctx context.Context, tid tenant.ID, linkID string) (store.DropLink, error) {
	return r.db.DropLinks().Get(ctx, tid, linkID)
}

func (r *storeRepo) create(ctx context.Context, tid tenant.ID, l store.DropLink) (store.DropLink, error) {
	return r.db.DropLinks().Create(ctx, tid, l)
}

func (r *storeRepo) update(ctx context.Context, tid tenant.ID, linkID string, u store.DropLinkUpdate, now time.Time) (store.DropLink, bool, error) {
	return r.db.DropLinks().Update(ctx, tid, linkID, u, now)
}

func (r *storeRepo) rotate(ctx context.Context, tid tenant.ID, linkID string, hash []byte, now time.Time) (store.DropLink, error) {
	return r.db.DropLinks().Rotate(ctx, tid, linkID, hash, now)
}

func (r *storeRepo) revoke(ctx context.Context, tid tenant.ID, linkID string, now time.Time) (store.DropLink, bool, error) {
	return r.db.DropLinks().Revoke(ctx, tid, linkID, now)
}

func (r *storeRepo) audit(ctx context.Context, tid tenant.ID, ev audit.Event) error {
	return r.writer.RecordScoped(ctx, tid, ev)
}

// Options configures a [Service].
type Options struct {
	// Logger receives the audit write failures; nil means slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Audit is the shared audit writer of the application, which publishes
	// the events it writes; nil means a writer of its own over the
	// database, publishing nothing.
	Audit *audit.Writer
}

// Service manages the permanent drop links. It is safe for concurrent use.
type Service struct {
	repo   repo
	logger *slog.Logger
	now    func() time.Time
	// newToken draws a token; id.NewDropToken, replaced in tests.
	newToken func() (string, error)
}

// errMissingDB reports a [New] call without a database.
var errMissingDB = errors.New("droplink: a database is required")

// New returns the service over db.
func New(db *store.DB, opts Options) (*Service, error) {
	if db == nil {
		return nil, errMissingDB
	}
	return newService(&storeRepo{db: db, writer: audit.OrNew(opts.Audit, db)}, opts), nil
}

// newService returns the service over r.
func newService(r repo, opts Options) *Service {
	s := &Service{repo: r, logger: opts.Logger, now: opts.Now, newToken: id.NewDropToken}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// readable checks that p may read the links of tenant tid (an auditor
// attached to it may), which must be active.
func (s *Service) readable(ctx context.Context, p adminauth.Principal, tid tenant.ID) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	if err := adminauth.RequireTenantAuditRead(p.Admin, tid); err != nil {
		return err
	}
	_, err := s.activeTenant(ctx, tid)
	return err
}

// writable checks that p may change the links of tenant tid, which must be
// active, and returns it.
func (s *Service) writable(ctx context.Context, p adminauth.Principal, tid tenant.ID) (*tenant.Tenant, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return nil, err
	}
	if err := adminauth.RequireTenantWrite(p.Admin, tid); err != nil {
		return nil, err
	}
	return s.activeTenant(ctx, tid)
}

// activeTenant returns tenant tid, which must exist and be active; a
// missing tenant, and a tenant being deleted, are ErrNotFound.
func (s *Service) activeTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	t, err := s.repo.getTenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return nil, ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("droplink: get tenant: %w", err)
	case t.Status != tenant.StatusActive:
		return nil, ErrNotFound
	}
	return t, nil
}

// record writes the audit event of a change made by p on link linkID of
// tenant tid. The change is committed already: a failure is logged, never
// returned, and a canceled request does not prevent the write.
func (s *Service) record(ctx context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID,
	action audit.Action, linkID string, details map[string]any,
) {
	ev := audit.Event{
		TenantID: tid, ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: ip,
		Action: action, ObjectKind: audit.ObjectDropLink, ObjectID: linkID, Details: details,
	}
	if err := s.repo.audit(context.WithoutCancel(ctx), tid, ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(action)),
			slog.String("tenant", string(tid)), slog.String("error", err.Error()))
	}
}

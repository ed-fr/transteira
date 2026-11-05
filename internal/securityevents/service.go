package securityevents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Names of the request fields, for the validation errors (OpenAPI query
// parameters of listTenantSecurityEvents and listGlobalSecurityEvents).
const (
	FieldType     = "type"
	FieldTo       = "to"
	FieldLimit    = "limit"
	FieldCursor   = "cursor"
	FieldTenantID = "tenantId"
)

// ErrNotFound reports a tenant that does not exist or is being deleted
// (404 not-found, like a tenant the administrator is not attached to).
var ErrNotFound = errors.New("securityevents: tenant not found")

// InvalidError reports a malformed filter (400 validation-failed).
type InvalidError struct {
	// Field names the query parameter.
	Field string
	// Reason explains the error (never echoes the value).
	Reason string
}

// Error implements error.
func (e *InvalidError) Error() string {
	return fmt.Sprintf("securityevents: invalid %s: %s", e.Field, e.Reason)
}

// Lister reads the rows. *store.SecurityEvents implements it.
type Lister interface {
	List(ctx context.Context, f store.SecurityEventFilter) (store.Page[store.SecurityEvent], error)
}

// Tenants reads the tenant registry. *store.Tenants implements it.
type Tenants interface {
	Get(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
}

// Compile-time checks that the store fits.
var (
	_ Lister  = (*store.SecurityEvents)(nil)
	_ Tenants = (*store.Tenants)(nil)
)

// Filter selects a page of security events.
type Filter struct {
	// Type keeps the events of this type ("" for all). Any value of the
	// form of a type is accepted; an unknown one matches no event.
	Type string
	// From and To bound the time of the first occurrence, both inclusive
	// (zero: no bound).
	From time.Time
	To   time.Time
	// Cursor is the nextCursor of the previous page, "" for the first.
	Cursor string
	// Limit is the page size, 0 for store.DefaultPageSize.
	Limit int
}

// Service lists the security events kept in the database for the
// administration.
type Service struct {
	events  Lister
	tenants Tenants
}

// NewService returns a service reading events and tenants.
func NewService(events Lister, tenants Tenants) (*Service, error) {
	if events == nil || tenants == nil {
		return nil, errors.New("securityevents: the events and the tenants are required")
	}
	return &Service{events: events, tenants: tenants}, nil
}

// ListTenant returns a page of the security events of tenant tid, most
// recent first: only the events of that tenant, never those of another
// tenant nor those without tenant (T-283). It is open to the super admin
// and to the delegated admins and auditors attached to the tenant
// (adminauth.RequireTenantAuditRead); a tenant the administrator is not
// attached to, an unknown one and one being deleted answer ErrNotFound or
// adminauth.ErrNotFound alike.
func (s *Service) ListTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, f Filter) (store.Page[store.SecurityEvent], error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return store.Page[store.SecurityEvent]{}, err
	}
	if err := adminauth.RequireTenantAuditRead(p.Admin, tid); err != nil {
		return store.Page[store.SecurityEvent]{}, err
	}
	if err := s.active(ctx, tid); err != nil {
		return store.Page[store.SecurityEvent]{}, err
	}
	return s.list(ctx, tid, f)
}

// ListGlobal returns a page of the security events of the instance, most
// recent first, for the super admin only (adminauth.ErrForbidden
// otherwise). Without tid it holds the events of every tenant and those
// without tenant; with it, the events of that tenant only (none for an
// unknown tenant).
func (s *Service) ListGlobal(ctx context.Context, p adminauth.Principal, tid tenant.ID, f Filter) (store.Page[store.SecurityEvent], error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return store.Page[store.SecurityEvent]{}, err
	}
	if err := adminauth.RequireSuperAdmin(p.Admin); err != nil {
		return store.Page[store.SecurityEvent]{}, err
	}
	if tid != "" && tid.Validate() != nil {
		return store.Page[store.SecurityEvent]{}, &InvalidError{Field: FieldTenantID, Reason: "malformed tenant identifier"}
	}
	return s.list(ctx, tid, f)
}

// active returns ErrNotFound unless tenant tid exists and is active.
func (s *Service) active(ctx context.Context, tid tenant.ID) error {
	t, err := s.tenants.Get(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("securityevents: get tenant: %w", err)
	case t.Status != tenant.StatusActive:
		return ErrNotFound
	}
	return nil
}

// list validates f and lists the events of tid ("" for the whole log).
func (s *Service) list(ctx context.Context, tid tenant.ID, f Filter) (store.Page[store.SecurityEvent], error) {
	switch {
	case f.Type != "" && !store.ValidSecurityEventType(f.Type):
		return store.Page[store.SecurityEvent]{}, &InvalidError{Field: FieldType, Reason: "must match ^[a-z][a-z0-9_]*$, at most 64 characters"}
	case !f.From.IsZero() && !f.To.IsZero() && f.To.Before(f.From):
		return store.Page[store.SecurityEvent]{}, &InvalidError{Field: FieldTo, Reason: "must not be before from"}
	case f.Limit < 0 || f.Limit > store.MaxPageSize:
		return store.Page[store.SecurityEvent]{}, &InvalidError{Field: FieldLimit, Reason: fmt.Sprintf("must be between 1 and %d", store.MaxPageSize)}
	}
	page, err := s.events.List(ctx, store.SecurityEventFilter{
		TenantID: tid, Type: f.Type, Since: f.From, Until: f.To, Cursor: f.Cursor, Limit: f.Limit,
	})
	switch {
	case errors.Is(err, store.ErrInvalid):
		// The other filters were checked above: a malformed cursor.
		return store.Page[store.SecurityEvent]{}, &InvalidError{Field: FieldCursor, Reason: "malformed cursor"}
	case err != nil:
		return store.Page[store.SecurityEvent]{}, fmt.Errorf("securityevents: list: %w", err)
	}
	return page, nil
}

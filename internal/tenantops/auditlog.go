package tenantops

import (
	"context"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Bounds of the audit filters (OpenAPI AuditAction and the actor
// parameter).
const (
	// MaxActionFilterLen bounds the action filter, in characters.
	MaxActionFilterLen = 64
	// MaxActorFilterLen bounds the actor filter, in characters.
	MaxActorFilterLen = 320
)

// actionPattern is the form of an audit action: any value of this form is
// accepted as a filter, an unknown one simply matches no event.
var actionPattern = regexp.MustCompile(`^[a-z_]+\.[a-z_]+$`)

// AuditFilter selects a page of the audit log of a tenant (OpenAPI
// listTenantAuditEvents).
type AuditFilter struct {
	// Action keeps the events of this action ("" for all).
	Action string
	// Actor keeps the events of this actor, a mail address or an admin
	// username ("" for all).
	Actor string
	// From and To bound the event time, both inclusive (zero: no bound).
	From time.Time
	To   time.Time
	// Cursor is the nextCursor of the previous page, "" for the first.
	Cursor string
	// Limit is the page size, 0 for store.DefaultPageSize.
	Limit int
}

// GlobalAuditFilter selects a page of the audit log of the instance
// (OpenAPI listGlobalAuditEvents).
type GlobalAuditFilter struct {
	// TenantID keeps the events of this tenant, without the events without
	// tenant ("" for the whole log).
	TenantID tenant.ID
	// Action keeps the events of this action ("" for all).
	Action string
	// Cursor is the nextCursor of the previous page, "" for the first.
	Cursor string
	// Limit is the page size, 0 for store.DefaultPageSize.
	Limit int
}

// checkAction validates an action filter.
func checkAction(action string) error {
	if action != "" && (len(action) > MaxActionFilterLen || !actionPattern.MatchString(action)) {
		return invalid(FieldAction, "must match %s, at most %d characters", actionPattern, MaxActionFilterLen)
	}
	return nil
}

// ListAuditEvents returns a page of the audit log of tenant tid, most
// recent first: only the events of the tenant, never the events without
// tenant nor those of another tenant. An actor given as a mail address is
// normalized like the stored actors.
func (s *Service) ListAuditEvents(ctx context.Context, p adminauth.Principal, tid tenant.ID, f AuditFilter) (store.Page[store.AuditEvent], error) {
	if err := s.readable(ctx, p, tid); err != nil {
		return store.Page[store.AuditEvent]{}, err
	}
	if err := checkAction(f.Action); err != nil {
		return store.Page[store.AuditEvent]{}, err
	}
	actor := f.Actor
	if !utf8.ValidString(actor) || utf8.RuneCountInString(actor) > MaxActorFilterLen {
		return store.Page[store.AuditEvent]{}, invalid(FieldActor, "must be text of at most %d characters", MaxActorFilterLen)
	}
	if email, err := store.NormalizeEmail(actor); err == nil {
		actor = email
	}
	if !f.From.IsZero() && !f.To.IsZero() && f.To.Before(f.From) {
		return store.Page[store.AuditEvent]{}, invalid(FieldTo, "must not be before from")
	}
	if err := checkLimit(f.Limit); err != nil {
		return store.Page[store.AuditEvent]{}, err
	}
	page, err := s.repo.listAudit(ctx, store.AuditFilter{
		TenantID: tid, Action: f.Action, Actor: actor, Since: f.From, Until: f.To, Cursor: f.Cursor, Limit: f.Limit,
	})
	if err != nil {
		return store.Page[store.AuditEvent]{}, listError("list audit events", err)
	}
	return page, nil
}

// ListGlobalAuditEvents returns a page of the audit log of the instance,
// most recent first, for the super admin only (ErrForbidden otherwise).
// Without f.TenantID it holds the events of every tenant and the events
// without tenant; with it, the events of that tenant only (none for an
// unknown tenant).
func (s *Service) ListGlobalAuditEvents(ctx context.Context, p adminauth.Principal, f GlobalAuditFilter) (store.Page[store.AuditEvent], error) {
	if err := superAdmin(p); err != nil {
		return store.Page[store.AuditEvent]{}, err
	}
	if f.TenantID != "" && f.TenantID.Validate() != nil {
		return store.Page[store.AuditEvent]{}, invalid(FieldTenantID, "malformed tenant identifier")
	}
	if err := checkAction(f.Action); err != nil {
		return store.Page[store.AuditEvent]{}, err
	}
	if err := checkLimit(f.Limit); err != nil {
		return store.Page[store.AuditEvent]{}, err
	}
	page, err := s.repo.listAudit(ctx, store.AuditFilter{
		TenantID: f.TenantID, Action: f.Action, Cursor: f.Cursor, Limit: f.Limit,
	})
	if err != nil {
		return store.Page[store.AuditEvent]{}, listError("list audit events", err)
	}
	return page, nil
}

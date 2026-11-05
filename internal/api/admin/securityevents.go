package admin

import (
	"context"
	"errors"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/securityevents"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// SecurityEventsService lists the security events kept in the database
// (*securityevents.Service). Both methods check the principal themselves.
type SecurityEventsService interface {
	ListTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, f securityevents.Filter) (store.Page[store.SecurityEvent], error)
	ListGlobal(ctx context.Context, p adminauth.Principal, tid tenant.ID, f securityevents.Filter) (store.Page[store.SecurityEvent], error)
}

// Compile-time check that the service fits.
var _ SecurityEventsService = (*securityevents.Service)(nil)

// WithSecurityEventsService serves the security event listings with svc.
// Without it they answer 500.
func WithSecurityEventsService(svc SecurityEventsService) Option {
	return func(s *Server) { s.securityEvents = svc }
}

// errNoSecurityEventsService reports a server built without
// WithSecurityEventsService: a wiring error, answered 500.
var errNoSecurityEventsService = errors.New("admin: no security events service configured")

// ListTenantSecurityEvents returns the security events of a tenant, most
// recent first (never the events without tenant).
func (s *Server) ListTenantSecurityEvents(ctx context.Context, req gen.ListTenantSecurityEventsRequestObject) (gen.ListTenantSecurityEventsResponseObject, error) {
	svc, p, err := s.securityEventsSession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := svc.ListTenant(ctx, p, tenant.ID(req.TenantId), securityevents.Filter{
		Type: string(deref(req.Params.Type)), From: deref(req.Params.From), To: deref(req.Params.To),
		Cursor: deref(req.Params.Cursor), Limit: deref(req.Params.Limit),
	})
	if err != nil {
		return nil, securityEventsError(err)
	}
	return gen.ListTenantSecurityEvents200JSONResponse(securityEventList(page)), nil
}

// ListGlobalSecurityEvents returns the security events of the instance
// (super admin), most recent first.
func (s *Server) ListGlobalSecurityEvents(ctx context.Context, req gen.ListGlobalSecurityEventsRequestObject) (gen.ListGlobalSecurityEventsResponseObject, error) {
	svc, p, err := s.securityEventsSession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := svc.ListGlobal(ctx, p, tenant.ID(deref(req.Params.TenantId)), securityevents.Filter{
		Type: string(deref(req.Params.Type)), From: deref(req.Params.From), To: deref(req.Params.To),
		Cursor: deref(req.Params.Cursor), Limit: deref(req.Params.Limit),
	})
	if err != nil {
		return nil, securityEventsError(err)
	}
	return gen.ListGlobalSecurityEvents200JSONResponse(securityEventList(page)), nil
}

// securityEventsSession returns the security events service and the
// session of the request, or the error to answer.
func (s *Server) securityEventsSession(ctx context.Context) (SecurityEventsService, adminauth.Principal, error) {
	if s.securityEvents == nil {
		return nil, adminauth.Principal{}, errNoSecurityEventsService
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.securityEvents, p, nil
}

// securityEventsError maps an error of the security events service to the
// error the strict handler renders.
func securityEventsError(err error) error {
	var invalid *securityevents.InvalidError
	switch {
	case errors.As(err, &invalid):
		return validationFailed(invalid.Field, fieldInvalidFormat)
	case errors.Is(err, securityevents.ErrNotFound), errors.Is(err, adminauth.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, adminauth.ErrUnauthenticated):
		return problem.New(problem.CodeUnauthenticated)
	case errors.Is(err, adminauth.ErrForbidden):
		return problem.New(problem.CodeForbidden)
	default:
		return err
	}
}

// securityEventList renders a page of security events as the OpenAPI
// SecurityEventList: the IP "-" when unknown, lastSeenAt only for a row
// that coalesced several events.
func securityEventList(page store.Page[store.SecurityEvent]) gen.SecurityEventList {
	out := gen.SecurityEventList{Items: make([]gen.SecurityEvent, len(page.Items)), NextCursor: nextCursor(page.NextCursor)}
	for i, ev := range page.Items {
		occurrences := ev.Occurrences
		item := gen.SecurityEvent{
			Id: ev.ID, OccurredAt: ev.At, Type: gen.SecurityEventType(ev.Type), Ip: securitylog.FormatIP(ev.IP),
			Reason: optional(ev.Reason), TenantId: optional(string(ev.TenantID)), Occurrences: &occurrences,
		}
		if occurrences > 1 {
			last := ev.LastSeenAt
			item.LastSeenAt = &last
		}
		out.Items[i] = item
	}
	return out
}

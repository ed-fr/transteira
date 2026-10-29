package httpserver

import (
	"context"
	"errors"

	"github.com/ed-fr/transteira/internal/deposit"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/mytransfers"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DepositSessions is the part of the deposit service used by the session
// and CSRF middlewares. *deposit.Service implements it.
type DepositSessions interface {
	Session(ctx context.Context, t *tenant.Tenant, rawToken string) (deposit.SessionInfo, error)
	CheckCSRF(rawToken, header string) bool
}

// sessionResolver adapts DepositSessions to middleware.SessionResolver: the
// session is looked up in the tenant of the request only, so that a cookie
// of one tenant is never accepted under the host of another.
type sessionResolver struct {
	svc DepositSessions
}

// Compile-time check of the middleware interface.
var _ middleware.SessionResolver = sessionResolver{}

// ResolveSession implements middleware.SessionResolver. The session is a
// deposit.SessionInfo.
func (a sessionResolver) ResolveSession(ctx context.Context, rawToken string) (any, bool, error) {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return nil, false, nil
	}
	info, err := a.svc.Session(ctx, t, rawToken)
	switch {
	case errors.Is(err, deposit.ErrUnauthenticated):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	return info, true, nil
}

// CheckCSRF implements middleware.SessionResolver.
func (a sessionResolver) CheckCSRF(rawToken, header string) bool {
	return a.svc.CheckCSRF(rawToken, header)
}

// noSessions is the resolver used without a deposit or "my transfers"
// service: no cookie is ever valid.
type noSessions struct{}

// ResolveSession implements middleware.SessionResolver.
func (noSessions) ResolveSession(context.Context, string) (any, bool, error) { return nil, false, nil }

// CheckCSRF implements middleware.SessionResolver.
func (noSessions) CheckCSRF(string, string) bool { return false }

// MyTransfersSessions is the part of the "my transfers" service used by the
// session and CSRF middlewares. *mytransfers.Service implements it.
type MyTransfersSessions interface {
	Session(ctx context.Context, t *tenant.Tenant, rawToken string) (mytransfers.SessionInfo, error)
	CheckCSRF(rawToken, header string) bool
}

// myTransfersResolver adapts MyTransfersSessions to
// middleware.SessionResolver: the session is looked up in the tenant of the
// request only, so that a cookie of one tenant is never accepted under the
// host of another.
type myTransfersResolver struct {
	svc MyTransfersSessions
}

// Compile-time check of the middleware interface.
var _ middleware.SessionResolver = myTransfersResolver{}

// ResolveSession implements middleware.SessionResolver. The session is a
// mytransfers.SessionInfo.
func (a myTransfersResolver) ResolveSession(ctx context.Context, rawToken string) (any, bool, error) {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return nil, false, nil
	}
	info, err := a.svc.Session(ctx, t, rawToken)
	switch {
	case errors.Is(err, mytransfers.ErrUnauthenticated):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	return info, true, nil
}

// CheckCSRF implements middleware.SessionResolver.
func (a myTransfersResolver) CheckCSRF(rawToken, header string) bool {
	return a.svc.CheckCSRF(rawToken, header)
}

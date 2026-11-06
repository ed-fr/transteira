package public

import (
	"context"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
)

// GetPublicDropLink returns what the landing page of a permanent drop link
// shows (since 2.0): its label, the validity of the transfers and the
// confidentiality level applied, never the recipients. A malformed,
// unknown, disabled or revoked link gets the same 404 drop-link-invalid,
// written to the security log by the deposit service. The lookups are
// bounded by the global per-IP limit of the HTTP layer (429), like every
// public operation.
func (s *Server) GetPublicDropLink(ctx context.Context, req gen.GetPublicDropLinkRequestObject) (gen.GetPublicDropLinkResponseObject, error) {
	t, err := s.depositTenant(ctx)
	if err != nil {
		return nil, err
	}
	accept := ""
	if r, ok := requestOf(ctx); ok {
		accept = r.Header.Get("Accept-Language")
	}
	l, err := s.deposit.PublicDropLink(ctx, t, middleware.ClientIP(ctx), accept, req.DropToken)
	if err != nil {
		return nil, depositError(err)
	}
	resp := gen.GetPublicDropLink200JSONResponse{Label: l.Label, ValidityDays: gen.ExpiryDays(l.ValidityDays)}
	if lv := l.Level; lv != nil {
		resp.Level = levelRef(lv.Key, lv.Label, &lv.Rules)
	}
	return resp, nil
}

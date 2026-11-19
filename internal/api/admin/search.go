package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/tenantops"
)

// TransferSearchService serves the transfer search across the tenants of
// an administrator (since 2.3, threat model T-409 to T-414). The
// operations service of WithOperationsService serves it when it
// implements this interface, as *tenantops.Service does: the search has
// no wiring of its own. The service checks the session, refuses an
// address to an auditor, validates the query and the limit, applies the
// rate limit per administrator and reads each tenant through its
// tenant-scoped reads.
type TransferSearchService interface {
	SearchTransfers(ctx context.Context, p adminauth.Principal, q string, limit int) (tenantops.SearchResult, error)
}

// Compile-time check that the operations service serves the search.
var _ TransferSearchService = (*tenantops.Service)(nil)

// searchRoute is the route pattern of searchTransfers, whose raw body is
// kept by CaptureRawBody to refuse its unknown members.
const searchRoute = http.MethodPost + " " + apiBase + "/admin/transfers/search"

// Members of the OpenAPI TransferSearch (additionalProperties false).
const (
	memberSearchQuery = "q"
	memberSearchLimit = "limit"
)

// transferSearchFields lists the members of a TransferSearch.
var transferSearchFields = []string{memberSearchQuery, memberSearchLimit}

// Wiring errors of the search, answered 500.
var (
	errNoTransferSearch = errors.New("admin: the operations service does not serve the transfer search")
	errNoSearchBody     = errors.New("admin: raw body of a transfer search missing (CaptureRawBody not installed)")
)

// SearchTransfers finds transfers by identifier or by complete address in
// every tenant within the scope of the administrator (since 2.3): a read
// despite its POST, which keeps the address out of every URL (P93); the
// admin router checks its CSRF token and marks the answer Cache-Control:
// no-store. Once the session is authenticated, the body must be an object
// without unknown member, its q and limit not null (400 validation-failed,
// invalid-format on the pointer), like the structural checks of the
// generated decoder; a missing limit is DefaultSearchLimit. The service
// then answers an auditor holding "@" 403 read-only-role before the query
// is checked, a malformed query or limit 400 validation-failed on /q or
// /limit, a 31st search within the minute 429 rate-limited with
// Retry-After (never written to the security log, P94), and the search is
// not audited (P95).
func (s *Server) SearchTransfers(ctx context.Context, req gen.SearchTransfersRequestObject) (gen.SearchTransfersResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	search, ok := svc.(TransferSearchService)
	if !ok {
		return nil, errNoTransferSearch
	}
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return nil, operationError(err)
	}
	raw, ok := ctx.Value(rawBodyKey{}).([]byte)
	if !ok {
		return nil, errNoSearchBody
	}
	if err := checkSearchMembers(raw); err != nil {
		return nil, err
	}
	q, limit := "", tenantops.DefaultSearchLimit
	if b := req.Body; b != nil {
		q = b.Q
		if b.Limit != nil {
			limit = *b.Limit
		}
	}
	res, err := search.SearchTransfers(ctx, p, q, limit)
	if err != nil {
		return nil, operationError(err)
	}
	return gen.SearchTransfers200JSONResponse(transferSearchBody(res)), nil
}

// checkSearchMembers refuses a TransferSearch body that is not an object,
// that has an unknown member or a null q or limit.
func checkSearchMembers(raw []byte) error {
	members, err := objectMembers(raw, "")
	if err != nil {
		return err
	}
	if err := rejectUnknownMembers(members, transferSearchFields); err != nil {
		return err
	}
	return rejectNulls(members, "", transferSearchFields)
}

// transferSearchBody renders r as the OpenAPI TransferSearchResult: each
// transfer as in the transfer list (adminTransferBody), the lists empty
// rather than null.
func transferSearchBody(r tenantops.SearchResult) gen.TransferSearchResult {
	out := gen.TransferSearchResult{
		Kind: gen.TransferSearchResultKind(r.Kind), Truncated: r.Truncated,
		Items: make([]gen.TransferSearchHit, len(r.Items)), Tenants: make([]gen.TransferSearchTenant, len(r.Tenants)),
	}
	for i, h := range r.Items {
		out.Items[i] = gen.TransferSearchHit{TenantId: string(h.TenantID), TenantName: h.TenantName, Transfer: adminTransferBody(h.Transfer)}
	}
	for i, t := range r.Tenants {
		out.Tenants[i] = gen.TransferSearchTenant{TenantId: string(t.TenantID), TenantName: t.TenantName, More: t.More}
	}
	return out
}

package tenantops

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Limits of the transfer search (OpenAPI searchTransfers, since 2.3).
const (
	// DefaultSearchLimit is the number of transfers a search answers when
	// the request gives no limit. The HTTP layer applies it: the service
	// itself requires an explicit limit.
	DefaultSearchLimit = 20
	// MaxSearchLimit is the largest limit of a search, all tenants
	// together, and the largest number of transfers read in one tenant.
	MaxSearchLimit = 50
	// MaxSearchQueryLen is the largest length of the query, in characters,
	// before its surrounding spaces are trimmed.
	MaxSearchQueryLen = 254
	// SearchRateLimit is the number of searches an administrator may run
	// within SearchRateWindow (T-413).
	SearchRateLimit = 30
	// SearchRateWindow is the rolling period of SearchRateLimit.
	SearchRateWindow = time.Minute
)

// Fields of the search body named by an [InvalidError] (JSON pointers of
// the OpenAPI TransferSearch).
const (
	FieldSearchQuery = "/q"
	FieldSearchLimit = "/limit"
)

// SearchKind tells how the query of a search was read (OpenAPI
// TransferSearchResult.kind).
type SearchKind string

// Search kinds.
const (
	// SearchByTransferID is a transfer identifier ("trf_" and a ULID).
	SearchByTransferID SearchKind = "transfer_id"
	// SearchByEmail is a complete mail address, sender or recipient.
	SearchByEmail SearchKind = "email"
)

// SearchHit is a transfer found by a search, with its tenant (OpenAPI
// TransferSearchHit).
type SearchHit struct {
	TenantID   tenant.ID
	TenantName string
	// Transfer is the transfer as the transfer list of its tenant shows
	// it: metadata only.
	Transfer Transfer
}

// SearchTenant is a tenant in which a search found transfers (OpenAPI
// TransferSearchTenant).
type SearchTenant struct {
	TenantID   tenant.ID
	TenantName string
	// More tells that some matches of the tenant are not in the items of
	// the result: cut by the limit, or beyond the limit newest matches of
	// the tenant.
	More bool
}

// SearchResult is the answer of a search (OpenAPI TransferSearchResult).
type SearchResult struct {
	// Kind is how the query was read.
	Kind SearchKind
	// Items are at most limit matches, newest first (creation time, then
	// identifier, both descending), all tenants together.
	Items []SearchHit
	// Truncated tells that matches were left out of Items.
	Truncated bool
	// Tenants are the tenants with at least one match, sorted by name,
	// then identifier.
	Tenants []SearchTenant
}

// ClassifySearchQuery reads the query of a transfer search. A query longer
// than MaxSearchQueryLen characters (or not valid UTF-8), or empty once
// trimmed of its surrounding Unicode spaces, is an *[InvalidError] on
// FieldSearchQuery. A transfer identifier ("trf_" and 26 ULID characters,
// in any case) is SearchByTransferID, normalized to the lowercase prefix
// and the uppercase ULID. Otherwise, a value holding "@" must be a bare
// mail address, normalized like the email filter of
// [Service.ListTransfers] (SearchByEmail; an *[InvalidError] with
// NotAnAddress otherwise), and anything else is an *[InvalidError]. There
// is no prefix nor partial matching. The check is purely syntactic: its
// answer never depends on what the database holds.
func ClassifySearchQuery(q string) (SearchKind, string, error) {
	if !utf8.ValidString(q) || utf8.RuneCountInString(q) > MaxSearchQueryLen {
		return "", "", invalid(FieldSearchQuery, "must be text of at most %d characters", MaxSearchQueryLen)
	}
	v := strings.TrimSpace(q)
	if v == "" {
		return "", "", invalid(FieldSearchQuery, "must not be empty")
	}
	if trfID, ok := normalizeTransferID(v); ok {
		return SearchByTransferID, trfID, nil
	}
	if strings.Contains(v, "@") {
		addr, ok := normalizeAddress(v)
		if !ok {
			return "", "", invalidAddress(FieldSearchQuery)
		}
		return SearchByEmail, addr, nil
	}
	return "", "", invalid(FieldSearchQuery, "must be a transfer identifier or a mail address")
}

// ulidChars is the length of the ULID part of an identifier.
const ulidChars = 26

// normalizeTransferID returns v as a transfer identifier, its prefix in
// lowercase and its ULID in uppercase, when it is one in any case. The
// length is checked in bytes first, so that no non-ASCII letter whose
// uppercase is ASCII (such as U+017F, uppercase S) passes for a ULID
// character.
func normalizeTransferID(v string) (string, bool) {
	head := string(id.Transfer) + "_"
	if len(v) != len(head)+ulidChars || !strings.EqualFold(v[:len(head)], head) {
		return "", false
	}
	out := head + strings.ToUpper(v[len(head):])
	return out, id.Valid(id.Transfer, out)
}

// SearchTransfers finds transfers in every tenant within the scope of p
// (since 2.3, threat model T-409 to T-414): every active tenant for the
// super admin, read page by page from the tenant registry; the active
// tenants p is attached to for a delegated admin or an auditor. A tenant
// being deleted is skipped.
//
// The checks run in this order, before any read: an authenticated session
// (adminauth.ErrUnauthenticated); an auditor whose query holds "@" gets
// adminauth.ErrReadOnlyRole before the query is even checked (T-411, the
// order of the email filter of [Service.ListTransfers]); limit must be 1
// to MaxSearchLimit (*InvalidError on FieldSearchLimit: the default is
// the HTTP layer's); the query is read by [ClassifySearchQuery]; then at
// most SearchRateLimit searches per SearchRateWindow per administrator
// (*RateLimitError, T-413), counted once the request is valid.
//
// Each tenant is then read in turn, never in parallel, through the
// tenant-scoped and access-checked reads only, [Service.GetTransfer] for
// an identifier and [Service.ListTransfers] with the address filter and
// limit for an address: no query spans tenants, and a tenant outside the
// scope is never read, so that an identifier or an address of another
// tenant answers exactly like an unknown one (T-409, T-410). A tenant
// answering ErrNotFound (missing, or no longer active since the registry
// was read, or, for an identifier, simply without that transfer) is
// skipped like a tenant without match; any other error fails the whole
// search, never a partial result.
//
// Each tenant contributes at most limit of its newest matches; they are
// merged, sorted newest first (creation time, then identifier, both
// descending) and cut to limit. The search writes nothing: it is not
// audited (P95), like the address filter of the transfer list.
func (s *Service) SearchTransfers(ctx context.Context, p adminauth.Principal, q string, limit int) (SearchResult, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return SearchResult{}, err
	}
	if p.Admin.Role == store.RoleAuditor && strings.Contains(q, "@") {
		return SearchResult{}, adminauth.ErrReadOnlyRole
	}
	if limit < 1 || limit > MaxSearchLimit {
		return SearchResult{}, invalid(FieldSearchLimit, "must be between 1 and %d", MaxSearchLimit)
	}
	kind, value, err := ClassifySearchQuery(q)
	if err != nil {
		return SearchResult{}, err
	}
	if ok, retry := s.searches.Allow(p.Admin.ID); !ok {
		return SearchResult{}, &RateLimitError{RetryAfter: max(retry, time.Second)}
	}
	scope, err := s.searchScope(ctx, p)
	if err != nil {
		return SearchResult{}, err
	}
	var (
		hits    []SearchHit
		partial = map[tenant.ID]bool{}
	)
	for _, t := range scope {
		found, more, err := s.searchTenant(ctx, p, t.ID, kind, value, limit)
		switch {
		case errors.Is(err, ErrNotFound):
			continue
		case err != nil:
			return SearchResult{}, err
		}
		for _, tr := range found {
			hits = append(hits, SearchHit{TenantID: t.ID, TenantName: t.Name, Transfer: tr})
		}
		if more {
			partial[t.ID] = true
		}
	}
	return mergeHits(kind, hits, partial, limit), nil
}

// searchScope returns the active tenants a search of p reads: every one
// for the super admin, the ones p is attached to (each once) otherwise.
func (s *Service) searchScope(ctx context.Context, p adminauth.Principal) ([]*tenant.Tenant, error) {
	if adminauth.RequireSuperAdmin(p.Admin) == nil {
		return s.activeTenants(ctx)
	}
	var out []*tenant.Tenant
	seen := map[tenant.ID]bool{}
	for _, tid := range p.Admin.TenantIDs {
		if seen[tid] || !adminauth.CanAccessTenant(p.Admin, tid) {
			continue
		}
		seen[tid] = true
		t, err := s.activeTenant(ctx, tid)
		switch {
		case errors.Is(err, ErrNotFound):
			continue
		case err != nil:
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// activeTenants reads every page of the tenant registry and returns the
// active tenants, by identifier.
func (s *Service) activeTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	var (
		out    []*tenant.Tenant
		cursor string
	)
	for {
		page, err := s.repo.listTenants(ctx, store.TenantListOptions{Cursor: cursor, Limit: s.tenantPage})
		if err != nil {
			return nil, fmt.Errorf("tenantops: list tenants: %w", err)
		}
		for _, t := range page.Items {
			if t.Status == tenant.StatusActive {
				out = append(out, t)
			}
		}
		if page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
}

// searchTenant returns the matches of tenant tid, read through the
// access-checked reads of the transfers, and whether the tenant has more
// matches than limit.
func (s *Service) searchTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, kind SearchKind, value string, limit int,
) ([]Transfer, bool, error) {
	if kind == SearchByTransferID {
		d, err := s.GetTransfer(ctx, p, tid, value)
		if err != nil {
			return nil, false, err
		}
		return []Transfer{d.Transfer}, false, nil
	}
	page, err := s.ListTransfers(ctx, p, tid, TransferFilter{Email: value, Limit: limit})
	if err != nil {
		return nil, false, err
	}
	return page.Items, page.NextCursor != "", nil
}

// mergeHits sorts hits newest first (creation time, then identifier, both
// descending; the order of the tenants otherwise), cuts them to limit and
// lists their tenants, partial holding the tenants with more matches than
// they returned.
func mergeHits(kind SearchKind, hits []SearchHit, partial map[tenant.ID]bool, limit int) SearchResult {
	slices.SortStableFunc(hits, func(a, b SearchHit) int {
		if c := b.Transfer.CreatedAt.Compare(a.Transfer.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.Transfer.ID, a.Transfer.ID)
	})
	out := SearchResult{Kind: kind, Items: []SearchHit{}, Tenants: []SearchTenant{}, Truncated: len(partial) > 0}
	index := map[tenant.ID]int{}
	for i, h := range hits {
		k, ok := index[h.TenantID]
		if !ok {
			k = len(out.Tenants)
			index[h.TenantID] = k
			out.Tenants = append(out.Tenants, SearchTenant{TenantID: h.TenantID, TenantName: h.TenantName, More: partial[h.TenantID]})
		}
		if i >= limit {
			out.Tenants[k].More, out.Truncated = true, true
			continue
		}
		out.Items = append(out.Items, h)
	}
	slices.SortFunc(out.Tenants, func(a, b SearchTenant) int {
		if c := strings.Compare(a.TenantName, b.TenantName); c != 0 {
			return c
		}
		return strings.Compare(string(a.TenantID), string(b.TenantID))
	})
	return out
}

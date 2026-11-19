package tenantops

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// search runs a search of p and forgets it in the rate limit, so that the
// functional cases never reach it (TestSearchTransfersRateLimit covers it).
func (ev *env) search(p adminauth.Principal, q string, limit int) (SearchResult, error) {
	defer ev.svc.searches.Reset(p.Admin.ID)
	return ev.svc.SearchTransfers(context.Background(), p, q, limit)
}

// mustSearch is search failing the test on an error.
func (ev *env) mustSearch(p adminauth.Principal, q string, limit int) SearchResult {
	ev.t.Helper()
	res, err := ev.search(p, q, limit)
	mustNoErr(ev.t, "search "+q, err)
	return res
}

// hitIDs returns the transfer identifiers of the items of res, in order.
func hitIDs(res SearchResult) []string {
	out := make([]string, len(res.Items))
	for i, h := range res.Items {
		out[i] = h.Transfer.ID
	}
	return out
}

// countAudit returns the number of audit events of tenant tid.
func (ev *env) countAudit(tid tenant.ID) int {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{TenantID: tid, Limit: store.MaxPageSize})
	mustNoErr(ev.t, "audit list", err)
	return len(page.Items)
}

// hookRepo wraps a repo: it runs afterListTenants after each read of the
// tenant registry and afterGetTenant after each read of a tenant, and
// fails the transfer reads of failTenant with errBoom.
type hookRepo struct {
	repo
	afterListTenants func()
	afterGetTenant   func(tid tenant.ID)
	failTenant       tenant.ID
}

func (h *hookRepo) listTenants(ctx context.Context, opts store.TenantListOptions) (store.Page[*tenant.Tenant], error) {
	page, err := h.repo.listTenants(ctx, opts)
	if h.afterListTenants != nil {
		h.afterListTenants()
	}
	return page, err
}

func (h *hookRepo) getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	t, err := h.repo.getTenant(ctx, tid)
	if h.afterGetTenant != nil {
		h.afterGetTenant(tid)
	}
	return t, err
}

func (h *hookRepo) listTransfers(ctx context.Context, tid tenant.ID, f store.AdminTransferFilter) (store.Page[store.AdminTransfer], error) {
	if tid == h.failTenant {
		return store.Page[store.AdminTransfer]{}, errBoom
	}
	return h.repo.listTransfers(ctx, tid, f)
}

func (h *hookRepo) getTransfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	if tid == h.failTenant {
		return store.TransferDetails{}, errBoom
	}
	return h.repo.getTransfer(ctx, tid, trfID)
}

// hook replaces the repo of the service with a hookRepo over it.
func (ev *env) hook() *hookRepo {
	h := &hookRepo{repo: ev.svc.repo}
	ev.svc.repo = h
	return h
}

// deleting marks tenant tid as being deleted.
func (ev *env) deleting(tid tenant.ID) {
	ev.t.Helper()
	mustNoErr(ev.t, "set deleting", ev.db.Tenants().SetStatus(context.Background(), tid, tenant.StatusDeleting))
}

// TestClassifySearchQuery reads a transfer identifier in any case and a
// complete address normalized like the email filter, and refuses anything
// else on /q, an address that is not bare with invalid-email.
func TestClassifySearchQuery(t *testing.T) {
	t.Parallel()
	const trf = "trf_01JCQ3V8K2M4N6P8R0S2T4W6Y8"
	padded := " " + trf + strings.Repeat(" ", MaxSearchQueryLen-len(trf)-1)
	tests := []struct {
		name, q   string
		kind      SearchKind
		value     string
		notAnAddr bool
	}{
		{"identifier", trf, SearchByTransferID, trf, false},
		{"lowercase identifier", strings.ToLower(trf), SearchByTransferID, trf, false},
		{"uppercase prefix", "TRF_01JCQ3V8K2M4N6P8R0S2T4W6Y8", SearchByTransferID, trf, false},
		{"mixed case and Unicode spaces", "\u00a0\tTrF_01jCq3V8k2M4n6P8r0S2t4W6y8\u3000\n", SearchByTransferID, trf, false},
		{"padded to the maximum", padded, SearchByTransferID, trf, false},
		{"address", "carol@customer.example.net", SearchByEmail, "carol@customer.example.net", false},
		{"address with an uppercase domain and spaces", "  carol@Customer.Example.NET\u2003", SearchByEmail, "carol@customer.example.net", false},
		{"empty", "", "", "", false},
		{"spaces only", " \t\u00a0\u3000", "", "", false},
		{"too long", padded + " ", "", "", false},
		{"too long in characters", strings.Repeat("\u00e9", MaxSearchQueryLen+1), "", "", false},
		{"invalid UTF-8", "trf_\xff", "", "", false},
		{"prefix only", "trf_", "", "", false},
		{"bare prefix", "trf", "", "", false},
		{"partial identifier", trf[:len(trf)-1], "", "", false},
		{"identifier too long", trf + "0", "", "", false},
		{"value beyond 128 bits", "trf_81JCQ3V8K2M4N6P8R0S2T4W6Y8", "", "", false},
		{"letter outside the ULID alphabet", "trf_01JCQ3V8K2M4N6P8R0S2T4W6YU", "", "", false},
		{"non-ASCII letter", "trf_\u0131JCQ3V8K2M4N6P8R0S2T4W6Y8", "", "", false},
		{"non-ASCII letter with an ASCII uppercase", "trf_01JCQ3V8K2M4N6P8R0S2T4W6\u017f", "", "", false},
		{"another prefix", "inv_01JCQ3V8K2M4N6P8R0S2T4W6Y8", "", "", false},
		{"local part only", "carol", "", "", false},
		{"pattern", "%carol%", "", "", false},
		{"domain only", "customer.example.net", "", "", false},
		{"address without domain", "carol@", "", "", true},
		{"address without local part", "@customer.example.net", "", "", true},
		{"at sign only", "@", "", "", true},
		{"display name", "Carol <carol@customer.example.net>", "", "", true},
		{"two addresses", "carol@customer.example.net, dave@partner.example.org", "", "", true},
		{"header injection", "carol@customer.example.net\r\nBcc: x@partner.example.org", "", "", true},
	}
	for _, tc := range tests {
		kind, value, err := ClassifySearchQuery(tc.q)
		if tc.kind == "" {
			wantInvalid(t, tc.name, err, FieldSearchQuery)
			var ie *InvalidError
			if errors.As(err, &ie); ie.NotAnAddress != tc.notAnAddr || kind != "" || value != "" {
				t.Errorf("%s: NotAnAddress %v, kind %q, value %q", tc.name, ie.NotAnAddress, kind, value)
			}
			if strings.Contains(err.Error(), tc.q) && tc.q != "" {
				t.Errorf("%s: the error quotes the query: %v", tc.name, err)
			}
			continue
		}
		if err != nil || kind != tc.kind || value != tc.value {
			t.Errorf("%s: ClassifySearchQuery(%q) = %q, %q, %v; want %q, %q", tc.name, tc.q, kind, value, err, tc.kind, tc.value)
		}
	}
}

// TestSearchTransfersAcrossTenants finds the same address in tenants A and
// B for the super admin, in its own tenant only for a delegated admin, and
// an identifier only within the scope: an identifier of another tenant
// answers exactly like a random one. Nothing is audited (P95).
func TestSearchTransfersAcrossTenants(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		trA := ev.seed(ev.a, store.TransferAvailable, carol)
		ev.clock.Advance(time.Minute)
		trB := ev.seed(ev.b, store.TransferAvailable, carol, dave)
		ev.clock.Advance(time.Minute)
		ev.seed(ev.a, store.TransferExpired, dave)
		auditA, auditB := ev.countAudit(ev.a.ID), ev.countAudit(ev.b.ID)

		// The same address in A and B.
		res := ev.mustSearch(ev.super, "  Carol@Customer.Example.NET ", DefaultSearchLimit)
		if res.Kind != SearchByEmail || !slices.Equal(hitIDs(res), []string{trB.id, trA.id}) || res.Truncated {
			t.Fatalf("super admin: %+v", res)
		}
		if h := res.Items[0]; h.TenantID != ev.b.ID || h.TenantName != "Entity B" || h.Transfer.SenderEmail != alice ||
			!slices.Equal(h.Transfer.Recipients, []string{carol, dave}) || h.Transfer.Status != store.TransferAvailable {
			t.Errorf("hit of B: %+v", h)
		}
		wantTenants := []SearchTenant{{ev.a.ID, "Entity A", false}, {ev.b.ID, "Entity B", false}}
		if !reflect.DeepEqual(res.Tenants, wantTenants) {
			t.Errorf("tenants: %+v", res.Tenants)
		}
		res = ev.mustSearch(ev.adminA, carol, DefaultSearchLimit)
		if !slices.Equal(hitIDs(res), []string{trA.id}) || !reflect.DeepEqual(res.Tenants, wantTenants[:1]) {
			t.Errorf("admin of A: %+v", res)
		}
		res = ev.mustSearch(ev.adminB, carol, DefaultSearchLimit)
		if !slices.Equal(hitIDs(res), []string{trB.id}) || !reflect.DeepEqual(res.Tenants, wantTenants[1:]) {
			t.Errorf("admin of B: %+v", res)
		}
		// The sender address, in every status; an unknown address.
		if res = ev.mustSearch(ev.adminA, alice, DefaultSearchLimit); len(res.Items) != 2 {
			t.Errorf("sender: %+v", res)
		}
		empty := SearchResult{Kind: SearchByEmail, Items: []SearchHit{}, Tenants: []SearchTenant{}}
		if res = ev.mustSearch(ev.adminA, "nobody@customer.example.net", DefaultSearchLimit); !reflect.DeepEqual(res, empty) {
			t.Errorf("unknown address: %+v", res)
		}

		// Identifiers: in the scope, of another tenant, random.
		random := ev.mustSearch(ev.adminA, missingTrf, DefaultSearchLimit)
		if random.Kind != SearchByTransferID || len(random.Items) != 0 || len(random.Tenants) != 0 || random.Truncated {
			t.Fatalf("random identifier: %+v", random)
		}
		if foreign := ev.mustSearch(ev.adminA, strings.ToLower(trB.id), DefaultSearchLimit); !reflect.DeepEqual(foreign, random) {
			t.Errorf("identifier of B by the admin of A: %+v, want %+v", foreign, random)
		}
		res = ev.mustSearch(ev.adminA, strings.ToLower(trA.id), DefaultSearchLimit)
		if res.Kind != SearchByTransferID || !slices.Equal(hitIDs(res), []string{trA.id}) || !reflect.DeepEqual(res.Tenants, wantTenants[:1]) {
			t.Errorf("identifier of A by the admin of A: %+v", res)
		}
		if res = ev.mustSearch(ev.super, trB.id, 1); !slices.Equal(hitIDs(res), []string{trB.id}) || res.Items[0].TenantID != ev.b.ID {
			t.Errorf("identifier of B by the super admin: %+v", res)
		}

		// The auditor of A: identifiers only, an address refused before it
		// is checked.
		auditor := principal(store.RoleAuditor, "audit.a", ev.a.ID)
		if res = ev.mustSearch(auditor, trA.id, DefaultSearchLimit); !slices.Equal(hitIDs(res), []string{trA.id}) {
			t.Errorf("auditor, identifier of A: %+v", res)
		}
		if res = ev.mustSearch(auditor, trB.id, DefaultSearchLimit); !reflect.DeepEqual(res, random) {
			t.Errorf("auditor, identifier of B: %+v", res)
		}
		for _, q := range []string{carol, "not an address @", "@", strings.Repeat("@", MaxSearchQueryLen+1)} {
			for _, limit := range []int{DefaultSearchLimit, 0, MaxSearchLimit + 1} {
				_, err := ev.search(auditor, q, limit)
				wantErr(t, "auditor search "+q, err, adminauth.ErrReadOnlyRole)
			}
		}
		if ev.countAudit(ev.a.ID) != auditA || ev.countAudit(ev.b.ID) != auditB {
			t.Error("a search was audited")
		}
	})
}

// TestSearchTransfersMerge merges the newest matches of each tenant, cuts
// them to the limit and reports what was left out, by the limit or beyond
// the newest matches of a tenant.
func TestSearchTransfersMerge(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		var ids []string // newest last: A, B, A, B, A
		for i := range 5 {
			tn := ev.a
			if i%2 == 1 {
				tn = ev.b
			}
			ids = append(ids, ev.seed(tn, store.TransferAvailable, carol).id)
			ev.clock.Advance(time.Minute)
		}
		a0, b1, a2, b3, a4 := ids[0], ids[1], ids[2], ids[3], ids[4]
		type want struct {
			items     []string
			truncated bool
			moreA     bool
			moreB     bool
		}
		for limit, w := range map[int]want{
			5:              {[]string{a4, b3, a2, b1, a0}, false, false, false},
			MaxSearchLimit: {[]string{a4, b3, a2, b1, a0}, false, false, false},
			4:              {[]string{a4, b3, a2, b1}, true, true, false},
			3:              {[]string{a4, b3, a2}, true, true, true},
			2:              {[]string{a4, b3}, true, true, true},
			1:              {[]string{a4}, true, true, true},
		} {
			res := ev.mustSearch(ev.super, carol, limit)
			got := want{hitIDs(res), res.Truncated, res.Tenants[0].More, res.Tenants[1].More}
			if !reflect.DeepEqual(got, w) || len(res.Tenants) != 2 || res.Tenants[0].TenantID != ev.a.ID {
				t.Errorf("limit %d: %+v (tenants %+v), want %+v", limit, got, res.Tenants, w)
			}
		}
		// A tenant beyond its newest matches without any cut by the limit.
		res := ev.mustSearch(ev.adminA, carol, 2)
		if !slices.Equal(hitIDs(res), []string{a4, a2}) || !res.Truncated ||
			!reflect.DeepEqual(res.Tenants, []SearchTenant{{ev.a.ID, "Entity A", true}}) {
			t.Errorf("admin of A, limit 2: %+v", res)
		}
		// Equal creation times: by identifier, descending.
		x, y := ev.seed(ev.a, store.TransferAvailable, dave).id, ev.seed(ev.b, store.TransferAvailable, dave).id
		tie := []string{x, y}
		slices.Sort(tie)
		slices.Reverse(tie)
		if res := ev.mustSearch(ev.super, dave, MaxSearchLimit); !slices.Equal(hitIDs(res), tie) {
			t.Errorf("same creation time: %v, want %v", hitIDs(res), tie)
		}
	})
}

// TestMergeHits orders equal transfers in the order of the tenants and
// sorts the tenants by name, then identifier.
func TestMergeHits(t *testing.T) {
	t.Parallel()
	at := testStart
	hit := func(tid tenant.ID, name, trfID string, created time.Time) SearchHit {
		return SearchHit{TenantID: tid, TenantName: name, Transfer: Transfer{ID: trfID, CreatedAt: created}}
	}
	hits := []SearchHit{
		hit("ten_2", "Same", "trf_1", at),
		hit("ten_1", "Same", "trf_1", at),
		hit("ten_0", "Zed", "trf_0", at),
		hit("ten_3", "Alpha", "trf_9", at.Add(-time.Hour)),
	}
	res := mergeHits(SearchByEmail, hits, map[tenant.ID]bool{}, 3)
	var order []tenant.ID
	for _, h := range res.Items {
		order = append(order, h.TenantID)
	}
	if !slices.Equal(order, []tenant.ID{"ten_2", "ten_1", "ten_0"}) || !res.Truncated {
		t.Errorf("items %v, truncated %v", order, res.Truncated)
	}
	want := []SearchTenant{{"ten_3", "Alpha", true}, {"ten_1", "Same", false}, {"ten_2", "Same", false}, {"ten_0", "Zed", false}}
	if !reflect.DeepEqual(res.Tenants, want) {
		t.Errorf("tenants %+v", res.Tenants)
	}
	if res := mergeHits(SearchByTransferID, nil, nil, 1); res.Items == nil || res.Tenants == nil || res.Truncated {
		t.Errorf("no hit: %+v", res)
	}
}

// TestSearchTransfersScope skips the tenants being deleted, including one
// that starts its deletion between the read of the registry (or of the
// tenant) and its own read, and the tenants outside the scope; the super
// admin reads every page of the registry.
func TestSearchTransfersScope(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		c := ev.newTenant("Entity C", "transfer.entity-c.example.com")
		trA := ev.seed(ev.a, store.TransferAvailable, carol)
		trB := ev.seed(ev.b, store.TransferAvailable, carol)
		trC := ev.seed(c, store.TransferAvailable, carol)
		ev.deleting(c.ID)
		both := principal(store.RoleDelegatedAdmin, "deleg.ab", ev.a.ID, ev.b.ID, ev.a.ID, missingTen, c.ID)

		ev.svc.tenantPage = 1 // three pages
		res := ev.mustSearch(ev.super, carol, DefaultSearchLimit)
		if got := hitIDs(res); len(got) != 2 || !slices.Contains(got, trA.id) || !slices.Contains(got, trB.id) {
			t.Errorf("super admin over pages, C being deleted: %v", got)
		}
		if res = ev.mustSearch(ev.super, trC.id, DefaultSearchLimit); len(res.Items) != 0 {
			t.Errorf("identifier of C being deleted: %+v", res)
		}
		// Attached to A twice, B, a missing tenant and C being deleted.
		if got := hitIDs(ev.mustSearch(both, carol, DefaultSearchLimit)); len(got) != 2 {
			t.Errorf("admin of A and B: %v", got)
		}
		// Outside the scope: a disabled account, an unknown role.
		disabled := principal(store.RoleDelegatedAdmin, "deleg.off", ev.a.ID)
		disabled.Admin.Disabled = true
		odd := principal(store.AdminRole("owner"), "odd", ev.a.ID)
		for _, p := range []adminauth.Principal{disabled, odd} {
			if res := ev.mustSearch(p, carol, DefaultSearchLimit); len(res.Items) != 0 || len(res.Tenants) != 0 {
				t.Errorf("%s: %+v", p.Admin.Username, res)
			}
		}

		// B starts its deletion right after the registry, read in one page,
		// listed it active: skipped.
		ev.svc.tenantPage = store.MaxPageSize
		h := ev.hook()
		h.afterListTenants = func() { ev.deleting(ev.b.ID) }
		if got := hitIDs(ev.mustSearch(ev.super, carol, DefaultSearchLimit)); !slices.Equal(got, []string{trA.id}) {
			t.Errorf("B deleted after the registry read: %v", got)
		}
		mustNoErr(t, "restore B", ev.db.Tenants().SetStatus(context.Background(), ev.b.ID, tenant.StatusActive))
		h.afterListTenants = nil
		// B starts its deletion right after its first read by the scope of
		// a delegated admin: its transfer read answers not found, skipped.
		reads := map[tenant.ID]int{}
		h.afterGetTenant = func(tid tenant.ID) {
			if reads[tid]++; tid == ev.b.ID && reads[tid] == 1 {
				ev.deleting(ev.b.ID)
			}
		}
		for _, q := range []string{carol, trB.id} {
			res := ev.mustSearch(both, q, DefaultSearchLimit)
			if q == carol && !slices.Equal(hitIDs(res), []string{trA.id}) || q == trB.id && len(res.Items) != 0 {
				t.Errorf("%s with B deleted after the scope read: %+v", q, res)
			}
			mustNoErr(t, "restore B", ev.db.Tenants().SetStatus(context.Background(), ev.b.ID, tenant.StatusActive))
			clear(reads)
		}
	})
}

// TestSearchTransfersRefusals checks the session, the limit, the query
// and the failures: any error of a tenant other than not found fails the
// whole search, never a partial result.
func TestSearchTransfersRefusals(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		trA := ev.seed(ev.a, store.TransferAvailable, carol)
		trB := ev.seed(ev.b, store.TransferAvailable, carol)
		_, err := ev.search(unauthenticated(ev.adminA), carol, DefaultSearchLimit)
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)
		for _, limit := range []int{0, -1, MaxSearchLimit + 1} {
			_, err := ev.search(ev.adminA, carol, limit)
			wantInvalid(t, "limit", err, FieldSearchLimit)
		}
		_, err = ev.search(ev.adminA, "carol@", 1)
		wantInvalid(t, "address", err, FieldSearchQuery)
		_, err = ev.search(ev.adminA, "carol", 1)
		wantInvalid(t, "neither", err, FieldSearchQuery)

		// One tenant failing fails the whole search, by address and by
		// identifier.
		h := ev.hook()
		h.failTenant = ev.b.ID
		for _, q := range []string{carol, trA.id, trB.id} {
			res, err := ev.search(ev.super, q, DefaultSearchLimit)
			if !errors.Is(err, errBoom) || errors.Is(err, ErrNotFound) || res.Items != nil {
				t.Errorf("%s with B failing: %+v, %v", q, res, err)
			}
		}
		ev.svc.repo = h.repo
		ev.faults("listTenants")
		_, err = ev.search(ev.super, carol, 1)
		wantErr(t, "registry failure", err, errBoom)
		_, err = ev.search(ev.adminA, carol, 1)
		mustNoErr(t, "delegated admin without registry", err)
		ev.faults("getTenant")
		_, err = ev.search(ev.adminA, carol, 1)
		wantErr(t, "tenant failure", err, errBoom)
	})
}

// TestSearchTransfersRateLimit allows SearchRateLimit valid searches per
// administrator in any rolling SearchRateWindow, checked before any read;
// the refused requests do not count.
func TestSearchTransfersRateLimit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		search := func(p adminauth.Principal, q string) error {
			_, err := ev.svc.SearchTransfers(ctx, p, q, 1)
			return err
		}
		auditor := principal(store.RoleAuditor, "audit.a", ev.a.ID)
		for range SearchRateLimit {
			mustNoErr(t, "search", search(ev.adminA, carol))
			wantInvalid(t, "invalid", search(ev.adminA, "carol"), FieldSearchQuery)
			wantErr(t, "auditor address", search(auditor, carol), adminauth.ErrReadOnlyRole)
			mustNoErr(t, "auditor identifier", search(auditor, missingTrf))
		}
		// Refused before any read: the registry would fail.
		ev.faults("listTenants", "getTenant")
		var limited *RateLimitError
		err := search(ev.adminA, carol)
		if !errors.As(err, &limited) || !errors.Is(err, ErrRateLimited) || limited.RetryAfter != SearchRateWindow {
			t.Fatalf("search %d: %v", SearchRateLimit+1, err)
		}
		if err := search(auditor, missingTrf); !errors.Is(err, ErrRateLimited) {
			t.Errorf("auditor: %v", err)
		}
		// The limit is per administrator.
		wantErr(t, "admin of B", search(ev.adminB, carol), errBoom)
		ev.clock.Advance(SearchRateWindow - 500*time.Millisecond)
		if err := search(ev.adminA, carol); !errors.As(err, &limited) || limited.RetryAfter != time.Second {
			t.Errorf("half a second before the window: %v", err)
		}
		ev.clock.Advance(500 * time.Millisecond)
		wantErr(t, "after the window", search(ev.adminA, carol), errBoom)
	})
}

package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fixedNow is the clock of the repository tests.
var fixedNow = time.Date(2026, 10, 19, 12, 30, 45, 123_456_789, time.UTC)

// openDB opens and migrates the engine's database.
func openDB(t *testing.T, e storetest.Engine) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return fixedNow }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// newTenant creates a tenant served by fqdn.
func newTenant(t *testing.T, db *store.DB, fqdn string) *tenant.Tenant {
	t.Helper()
	tn, err := db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "fr",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn
}

func TestTenantsCRUD(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Tenants()

		a := newTenant(t, db, "transfer.entity-a.example.com")
		if a.ID.Validate() != nil || !a.CreatedAt.Equal(fixedNow.Truncate(time.Millisecond)) || a.UpdatedAt != a.CreatedAt {
			t.Fatalf("created tenant = %+v", a)
		}
		got, err := repo.Get(ctx, a.ID)
		if err != nil || *got != *a {
			t.Fatalf("Get = %+v, %v; want %+v", got, err, a)
		}
		byHost, err := repo.TenantByFQDN(ctx, a.FQDN)
		if err != nil || *byHost != *a {
			t.Fatalf("TenantByFQDN = %+v, %v", byHost, err)
		}
		if _, err := repo.TenantByFQDN(ctx, "unknown.example.com"); !errors.Is(err, tenant.ErrUnknownTenant) || !errors.Is(err, store.ErrNotFound) {
			t.Errorf("TenantByFQDN(unknown) err = %v", err)
		}

		// Duplicate FQDN.
		_, err = repo.Create(ctx, &tenant.Tenant{Name: "B", FQDN: a.FQDN, DefaultLanguage: "en", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create(duplicate fqdn) err = %v, want ErrConflict", err)
		}
		if err != nil && strings.Contains(err.Error(), a.FQDN) {
			t.Errorf("error leaks the value: %v", err)
		}

		// Update.
		upd := got.Clone()
		upd.Name = "Renamed"
		upd.FQDN = "transfer.renamed.example.com"
		upd.MaxTransferBytes = 42
		out, err := repo.Update(ctx, upd)
		if err != nil || out.Name != "Renamed" || out.FQDN != upd.FQDN || out.MaxTransferBytes != 42 || !out.CreatedAt.Equal(a.CreatedAt) {
			t.Fatalf("Update = %+v, %v", out, err)
		}
		b := newTenant(t, db, "transfer.entity-b.example.com")
		clash := b.Clone()
		clash.FQDN = upd.FQDN
		if _, err := repo.Update(ctx, clash); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Update(clashing fqdn) err = %v", err)
		}
		ghost := b.Clone()
		ghost.ID = tenant.ID(id.New(id.Tenant))
		if _, err := repo.Update(ctx, ghost); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update(missing) err = %v", err)
		}

		// Delete.
		if err := repo.Delete(ctx, a.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := repo.Delete(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete twice err = %v", err)
		}
		if _, err := repo.Get(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(deleted) err = %v", err)
		}
	})
}

func TestTenantsValidation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		repo := openDB(t, e).Tenants()
		valid := tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1}

		preset := valid
		preset.ID = tenant.ID(id.New(id.Tenant))
		if _, err := repo.Create(ctx, &preset); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Create(preset id) err = %v", err)
		}
		bad := valid
		bad.DefaultLanguage = "xx"
		if _, err := repo.Create(ctx, &bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Create(bad language) err = %v", err)
		}
		if _, err := repo.Update(ctx, &valid); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Update(no id) err = %v", err)
		}
		bad.ID = preset.ID
		if _, err := repo.Update(ctx, &bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Update(bad language) err = %v", err)
		}
		if _, err := repo.Get(ctx, "not-an-id"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(malformed) err = %v", err)
		}
		if _, err := repo.List(ctx, store.TenantListOptions{Cursor: "bogus"}); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("List(bad cursor) err = %v", err)
		}
	})
}

func TestTenantsList(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		var want []tenant.ID
		for i := range 5 {
			want = append(want, newTenant(t, db, fmt.Sprintf("t%d.example.com", i)).ID)
		}
		slices.Sort(want)

		empty, err := db.Tenants().List(ctx, store.TenantListOptions{Cursor: string(want[4])})
		if err != nil || len(empty.Items) != 0 || empty.Items == nil || empty.NextCursor != "" {
			t.Fatalf("List(after last) = %+v, %v", empty, err)
		}
		var got []tenant.ID
		cursor := ""
		for pages := 0; ; pages++ {
			p, err := db.Tenants().List(ctx, store.TenantListOptions{Cursor: cursor, Limit: 2})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			for _, tn := range p.Items {
				got = append(got, tn.ID)
			}
			if p.NextCursor == "" {
				if pages != 2 {
					t.Errorf("pages = %d, want 3", pages+1)
				}
				break
			}
			cursor = p.NextCursor
		}
		if !slices.Equal(got, want) {
			t.Errorf("listed %v, want %v", got, want)
		}
		all, err := db.Tenants().List(ctx, store.TenantListOptions{Limit: 1000})
		if err != nil || len(all.Items) != 5 {
			t.Errorf("List(limit 1000) = %d items, %v", len(all.Items), err)
		}
	})
}

func TestNetworkRules(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "a.example.com")
		b := newTenant(t, db, "b.example.com")
		rules := db.NetworkRules()

		empty, err := rules.Get(ctx, a.ID)
		if err != nil || len(empty.CIDRs) != 0 || len(empty.Domains) != 0 || empty.CIDRs == nil || empty.Domains == nil {
			t.Fatalf("Get(empty) = %+v, %v", empty, err)
		}
		cidrs := []netip.Prefix{
			netip.MustParsePrefix("192.168.1.7/24"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("2001:db8::/32"),
			netip.MustParsePrefix("10.0.0.0/8"),
		}
		domains := []string{"Entity-A.example.com.", "sub.entity-a.example.com", "entity-a.example.com"}
		set, err := rules.Replace(ctx, a.ID, cidrs, domains)
		if err != nil {
			t.Fatalf("Replace: %v", err)
		}
		wantCIDRs := []string{"10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"}
		wantDomains := []string{"entity-a.example.com", "sub.entity-a.example.com"}
		check := func(name string, s store.NetworkRuleSet) {
			t.Helper()
			var got []string
			for _, p := range s.CIDRs {
				got = append(got, p.String())
			}
			if !slices.Equal(got, wantCIDRs) || !slices.Equal(s.Domains, wantDomains) {
				t.Errorf("%s = %v %v, want %v %v", name, got, s.Domains, wantCIDRs, wantDomains)
			}
		}
		check("Replace result", set)
		stored, err := rules.Get(ctx, a.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		check("Get", stored)

		// Isolation: tenant B sees nothing and its replace leaves A intact.
		if other, err := rules.Get(ctx, b.ID); err != nil || len(other.CIDRs)+len(other.Domains) != 0 {
			t.Errorf("Get(B) = %+v, %v", other, err)
		}
		if _, err := rules.Replace(ctx, b.ID, nil, []string{"b.example.com"}); err != nil {
			t.Fatalf("Replace(B): %v", err)
		}
		stored, _ = rules.Get(ctx, a.ID)
		check("Get(A) after Replace(B)", stored)

		// Invalid input changes nothing.
		for _, tc := range []struct {
			cidrs   []netip.Prefix
			domains []string
		}{
			{cidrs: []netip.Prefix{{}}},
			{domains: []string{"not a domain"}},
			{domains: []string{"a.example.com:25"}},
			{domains: []string{"10.0.0.1"}},
			{cidrs: make([]netip.Prefix, store.MaxNetworkRules+1)},
		} {
			if _, err := rules.Replace(ctx, a.ID, tc.cidrs, tc.domains); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Replace(%v, %v) err = %v, want ErrInvalid", len(tc.cidrs), tc.domains, err)
			}
		}
		stored, _ = rules.Get(ctx, a.ID)
		check("Get(A) after invalid Replace", stored)

		// Clearing.
		if _, err := rules.Replace(ctx, a.ID, nil, nil); err != nil {
			t.Fatalf("Replace(clear): %v", err)
		}
		if s, _ := rules.Get(ctx, a.ID); len(s.CIDRs)+len(s.Domains) != 0 {
			t.Errorf("rules after clear = %+v", s)
		}

		// Unknown tenant.
		ghost := tenant.ID(id.New(id.Tenant))
		if _, err := rules.Replace(ctx, ghost, nil, []string{"x.example.com"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Replace(unknown tenant) err = %v", err)
		}
		if _, err := rules.Get(ctx, ""); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Get(empty id) err = %v", err)
		}
		if _, err := rules.Replace(ctx, "ten_bad", nil, nil); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Replace(bad id) err = %v", err)
		}

		// Deleting the tenant cascades.
		if err := db.Tenants().Delete(ctx, b.ID); err != nil {
			t.Fatalf("Delete(B): %v", err)
		}
		if s, _ := rules.Get(ctx, b.ID); len(s.Domains) != 0 {
			t.Errorf("rules of a deleted tenant: %+v", s)
		}
	})
}

// sha is a valid SHA-256 fingerprint for the tests.
var sha = strings.Repeat("ab", 32)

func TestBlocklistCRUD(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "a.example.com")
		b := newTenant(t, db, "b.example.com")
		bl := db.Blocklist()

		entry, err := bl.Create(ctx, a.ID, store.BlocklistEntry{
			Kind: store.BlockEmail, Value: " Bad.Guy@Example.ORG ", Comment: "spam", CreatedBy: "adm_x",
			ID: "ignored", CreatedAt: time.Unix(1, 0),
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if !id.Valid(id.Blocklist, entry.ID) || entry.Value != "bad.guy@example.org" || entry.Comment != "spam" ||
			entry.CreatedBy != "adm_x" || !entry.CreatedAt.Equal(fixedNow.Truncate(time.Millisecond)) {
			t.Fatalf("created entry = %+v", entry)
		}
		if _, err := bl.Create(ctx, a.ID, store.BlocklistEntry{Kind: store.BlockEmail, Value: "bad.guy@example.org"}); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create(duplicate) err = %v", err)
		}
		// Same value for another tenant is fine.
		if _, err := bl.Create(ctx, b.ID, store.BlocklistEntry{Kind: store.BlockEmail, Value: "bad.guy@example.org"}); err != nil {
			t.Errorf("Create(same value, tenant B) err = %v", err)
		}
		dom, _ := bl.Create(ctx, a.ID, store.BlocklistEntry{Kind: store.BlockDomain, Value: "Evil.example.net"})
		hash, _ := bl.Create(ctx, a.ID, store.BlocklistEntry{Kind: store.BlockSHA256, Value: strings.ToUpper(sha)})
		if dom.Value != "evil.example.net" || hash.Value != sha {
			t.Errorf("normalized values = %q, %q", dom.Value, hash.Value)
		}

		page, err := bl.List(ctx, a.ID, store.BlocklistFilter{})
		if err != nil || len(page.Items) != 3 || page.NextCursor != "" {
			t.Fatalf("List = %+v, %v", page, err)
		}
		// IDs share the fixed clock's millisecond: their order is random.
		if i := slices.IndexFunc(page.Items, func(x store.BlocklistEntry) bool { return x.ID == entry.ID }); i < 0 || page.Items[i] != entry {
			t.Errorf("listed entries %+v, want to find %+v", page.Items, entry)
		}
		domains, err := bl.List(ctx, a.ID, store.BlocklistFilter{Kind: store.BlockDomain})
		if err != nil || len(domains.Items) != 1 || domains.Items[0].ID != dom.ID {
			t.Errorf("List(domain) = %+v, %v", domains, err)
		}
		p1, err := bl.List(ctx, a.ID, store.BlocklistFilter{Limit: 2})
		if err != nil || len(p1.Items) != 2 || p1.NextCursor != p1.Items[1].ID {
			t.Fatalf("List(page 1) = %+v, %v", p1, err)
		}
		p2, err := bl.List(ctx, a.ID, store.BlocklistFilter{Limit: 2, Cursor: p1.NextCursor})
		if err != nil || len(p2.Items) != 1 || p2.NextCursor != "" || p2.Items[0].ID != page.Items[2].ID {
			t.Errorf("List(page 2) = %+v, %v", p2, err)
		}
		if _, err := bl.List(ctx, a.ID, store.BlocklistFilter{Kind: "ip"}); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("List(bad kind) err = %v", err)
		}
		if _, err := bl.List(ctx, a.ID, store.BlocklistFilter{Cursor: "ten_x"}); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("List(bad cursor) err = %v", err)
		}

		// Isolation: B lists only its own entry and cannot delete A's.
		pb, _ := bl.List(ctx, b.ID, store.BlocklistFilter{})
		if len(pb.Items) != 1 {
			t.Errorf("List(B) = %+v", pb)
		}
		if err := bl.Delete(ctx, b.ID, entry.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete(A's entry as B) err = %v, want ErrNotFound", err)
		}
		if err := bl.Delete(ctx, a.ID, entry.ID); err != nil {
			t.Errorf("Delete: %v", err)
		}
		if err := bl.Delete(ctx, a.ID, entry.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete twice err = %v", err)
		}

		// Unknown tenant and invalid IDs.
		ghost := tenant.ID(id.New(id.Tenant))
		if _, err := bl.Create(ctx, ghost, store.BlocklistEntry{Kind: store.BlockDomain, Value: "x.example.com"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create(unknown tenant) err = %v", err)
		}
		for name, f := range map[string]func() error{
			"List":   func() error { _, err := bl.List(ctx, "", store.BlocklistFilter{}); return err },
			"Create": func() error { _, err := bl.Create(ctx, "", store.BlocklistEntry{}); return err },
			"Delete": func() error { return bl.Delete(ctx, "", "blk_x") },
			"Match":  func() error { _, err := bl.Match(ctx, "", "a@b.example", ""); return err },
		} {
			if err := f(); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("%s(empty tenant) err = %v", name, err)
			}
		}
	})
}

func TestBlocklistCreateValidation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "a.example.com")
		for _, en := range []store.BlocklistEntry{
			{Kind: "ip", Value: "1.2.3.4"},
			{Kind: store.BlockEmail, Value: "no-at-sign"},
			{Kind: store.BlockDomain, Value: "-bad-.example"},
			{Kind: store.BlockSHA256, Value: "abc"},
			{Kind: store.BlockDomain, Value: "ok.example.com", Comment: strings.Repeat("x", 501)},
			{Kind: store.BlockDomain, Value: "ok.example.com", Comment: "\xff"},
			{Kind: store.BlockDomain, Value: "ok.example.com", CreatedBy: strings.Repeat("x", 321)},
		} {
			if _, err := db.Blocklist().Create(ctx, a.ID, en); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Create(%+v) err = %v, want ErrInvalid", en.Kind, err)
			}
		}
	})
}

func TestBlocklistMatch(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "a.example.com")
		b := newTenant(t, db, "b.example.com")
		bl := db.Blocklist()
		mustCreate := func(tid tenant.ID, k store.BlocklistKind, v string) store.BlocklistEntry {
			t.Helper()
			en, err := bl.Create(ctx, tid, store.BlocklistEntry{Kind: k, Value: v})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			return en
		}
		mail := mustCreate(a.ID, store.BlockEmail, "eve@mail.example.org")
		dom := mustCreate(a.ID, store.BlockDomain, "evil.example.net")
		hash := mustCreate(a.ID, store.BlockSHA256, sha)
		mustCreate(b.ID, store.BlockDomain, "example.com") // B only

		ids := func(es []store.BlocklistEntry) []string {
			out := []string{}
			for _, x := range es {
				out = append(out, x.ID)
			}
			return out
		}
		tests := []struct {
			name, email, sha string
			want             []string
		}{
			{"none", "", "", []string{}},
			{"exact email", "Eve@Mail.Example.org", "", []string{mail.ID}},
			{"other email same domain", "bob@mail.example.org", "", []string{}},
			{"domain", "x@evil.example.net", "", []string{dom.ID}},
			{"sub-domain", "x@a.b.evil.example.net", "", []string{dom.ID}},
			{"look-alike domain", "x@notevil.example.net", "", []string{}},
			{"parent of blocked domain", "x@example.net", "", []string{}},
			{"sha", "", strings.ToUpper(sha), []string{hash.ID}},
			{"all", "eve@mail.example.org", sha, []string{mail.ID, hash.ID}},
			{"other tenant's domain", "x@a.example.com", "", []string{}},
		}
		for _, tt := range tests {
			got, err := bl.Match(ctx, a.ID, tt.email, tt.sha)
			if err != nil {
				t.Errorf("%s: Match err = %v", tt.name, err)
				continue
			}
			g, w := ids(got), slices.Clone(tt.want)
			slices.Sort(g)
			slices.Sort(w)
			if !slices.Equal(g, w) {
				t.Errorf("%s: Match = %v, want %v", tt.name, g, w)
			}
		}
		if _, err := bl.Match(ctx, a.ID, "not-an-email", ""); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Match(bad email) err = %v", err)
		}
		if _, err := bl.Match(ctx, a.ID, "", "zz"); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Match(bad sha) err = %v", err)
		}
	})
}

func TestBlocklistKindNormalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind    store.BlocklistKind
		in      string
		want    string
		wantErr bool
	}{
		{store.BlockEmail, "A.B@Example.COM", "a.b@example.com", false},
		{store.BlockEmail, "@example.com", "", true},
		{store.BlockEmail, "a@b@example.com", "", true},
		{store.BlockEmail, "a b@example.com", "", true},
		{store.BlockEmail, strings.Repeat("a", 65) + "@example.com", "", true},
		{store.BlockEmail, "a@", "", true},
		{store.BlockDomain, "Example.COM.", "example.com", false},
		{store.BlockDomain, "user@example.com", "", true},
		{store.BlockSHA256, strings.Repeat("F", 64), strings.Repeat("f", 64), false},
		{store.BlockSHA256, strings.Repeat("g", 64), "", true},
		{"", "x", "", true},
	}
	for _, tt := range tests {
		got, err := tt.kind.Normalize(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("%s.Normalize(%q) = %q, %v", tt.kind, tt.in, got, err)
		}
		if err != nil && (!errors.Is(err, store.ErrInvalid) || (tt.in != "" && strings.Contains(err.Error(), tt.in))) {
			t.Errorf("%s.Normalize(%q) error %v: must be ErrInvalid and not quote the value", tt.kind, tt.in, err)
		}
	}
}

// TestNetworkRulesConcurrentReplace runs concurrent replaces of the same
// tenant's rules: every one must succeed and the final state must be
// exactly one of the inputs.
func TestNetworkRulesConcurrentReplace(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "a.example.com")
		const writers = 8
		inputs := make([][]string, writers)
		for i := range inputs {
			// Overlapping sets, so that unserialized replaces would collide.
			inputs[i] = []string{"shared.example.com", fmt.Sprintf("w%d.example.com", i), fmt.Sprintf("w%d.example.com", (i+1)%writers)}
			slices.Sort(inputs[i])
		}
		errs := make(chan error, writers*3)
		var wg sync.WaitGroup
		for round := range 3 {
			for i := range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := db.NetworkRules().Replace(ctx, a.ID, nil, inputs[(i+round)%writers])
					errs <- err
				}()
			}
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("concurrent Replace: %v", err)
			}
		}
		got, err := db.NetworkRules().Get(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(inputs, func(in []string) bool { return slices.Equal(in, got.Domains) }) {
			t.Errorf("final rules %v are not one of the inputs", got.Domains)
		}
	})
}

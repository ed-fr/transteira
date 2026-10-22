package isolation_test

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestNetworkRulesIsolation attacks the NetworkRules repository from tenant
// A and checks that B's rules are never seen nor changed.
func TestNetworkRulesIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		rules := f.db.NetworkRules()

		t.Run("get from A never returns B's rules", func(t *testing.T) {
			got, err := rules.Get(ctx, f.a.ID)
			if err != nil {
				t.Fatalf("Get(A): %v", err)
			}
			if !equalRules(got, f.rulesA) {
				t.Fatalf("Get(A) = %+v, want %+v", got, f.rulesA)
			}
			for _, p := range f.rulesB.CIDRs {
				if slices.Contains(got.CIDRs, p) {
					t.Errorf("A sees B's range %s", p)
				}
			}
			for _, d := range f.rulesB.Domains {
				if slices.Contains(got.Domains, d) {
					t.Errorf("A sees B's domain %s", d)
				}
			}
		})

		// Each case replaces A's rules, then checks that A holds exactly the
		// expected set and B is untouched. Reusing B's exact values must not
		// fail with a conflict, which would reveal that B uses them.
		cases := []struct {
			name    string
			cidrs   []netip.Prefix
			domains []string
		}{
			{"replace A with B's exact values", f.rulesB.CIDRs, f.rulesB.Domains},
			{"replace A with B's values in another spelling", []netip.Prefix{netip.MustParsePrefix("10.2.3.4/16")}, []string{"ENTITY-B.EXAMPLE.ORG.", "Partner.Example.Net"}},
			{"clear A", nil, nil},
			{"restore A", f.rulesA.CIDRs, f.rulesA.Domains},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				set, err := rules.Replace(ctx, f.a.ID, tc.cidrs, tc.domains)
				if err != nil {
					t.Fatalf("Replace(A): %v", err)
				}
				got, err := rules.Get(ctx, f.a.ID)
				if err != nil || !equalRules(got, set) {
					t.Fatalf("Get(A) after Replace = %+v, %v; want %+v", got, err, set)
				}
				f.assertBIntact(ctx, t)
			})
		}
		f.assertAIntact(ctx, t)

		t.Run("invalid replace from A changes nothing anywhere", func(t *testing.T) {
			_, err := rules.Replace(ctx, f.a.ID, nil, []string{"entity-b.example.org", "not a domain"})
			if !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("Replace(invalid) err = %v, want ErrInvalid", err)
			}
			f.assertAIntact(ctx, t)
			f.assertBIntact(ctx, t)
		})
	})
}

// TestBlocklistIsolation attacks every method of the Blocklist repository
// from tenant A with B's identifiers and values.
func TestBlocklistIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		bl := f.db.Blocklist()
		idsA, idsB := idSet(f.blockA), idSet(f.blockB)

		t.Run("list from A returns only A's entries", func(t *testing.T) {
			assertSameEntries(t, "A", listAll(ctx, t, f.db, f.a.ID), f.blockA)
			p, err := bl.List(ctx, f.a.ID, store.BlocklistFilter{Limit: store.MaxPageSize})
			if err != nil {
				t.Fatal(err)
			}
			assertSameEntries(t, "A (single page)", p.Items, f.blockA)
		})

		t.Run("list by kind from A returns only A's entries", func(t *testing.T) {
			for _, k := range []store.BlocklistKind{store.BlockEmail, store.BlockDomain, store.BlockSHA256} {
				p, err := bl.List(ctx, f.a.ID, store.BlocklistFilter{Kind: k, Limit: store.MaxPageSize})
				if err != nil {
					t.Fatalf("List(A, %s): %v", k, err)
				}
				var want []store.BlocklistEntry
				for _, x := range f.blockA {
					if x.Kind == k {
						want = append(want, x)
					}
				}
				assertSameEntries(t, "A/"+string(k), p.Items, want)
			}
		})

		// Cursors crafted from B's identifiers must only move inside A's
		// entries: the page is exactly A's entries ordered after the cursor.
		t.Run("cursor crafted from B's IDs", func(t *testing.T) {
			kinds := []store.BlocklistKind{"", store.BlockEmail, store.BlockDomain, store.BlockSHA256}
			for _, b := range f.blockB {
				for _, k := range kinds {
					p, err := bl.List(ctx, f.a.ID, store.BlocklistFilter{Kind: k, Cursor: b.ID, Limit: store.MaxPageSize})
					if err != nil {
						t.Fatalf("List(A, kind %q, cursor %s): %v", k, b.ID, err)
					}
					var want []store.BlocklistEntry
					for _, x := range f.blockA {
						if x.ID > b.ID && (k == "" || x.Kind == k) {
							want = append(want, x)
						}
					}
					assertSameEntries(t, "A after B's cursor", p.Items, want)
					if idsB[p.NextCursor] {
						t.Errorf("next cursor %s is one of B's IDs", p.NextCursor)
					}
					for _, x := range p.Items {
						if idsB[x.ID] || !idsA[x.ID] {
							t.Errorf("page holds foreign entry %+v", x)
						}
					}
				}
				// Small pages: following cursors from B's ID never reaches B.
				cursor := b.ID
				for cursor != "" {
					p, err := bl.List(ctx, f.a.ID, store.BlocklistFilter{Cursor: cursor, Limit: 1})
					if err != nil {
						t.Fatal(err)
					}
					for _, x := range p.Items {
						if !idsA[x.ID] {
							t.Errorf("paging from B's cursor reached foreign entry %+v", x)
						}
					}
					cursor = p.NextCursor
				}
			}
		})

		t.Run("cursor of another prefix or tampered is invalid, not a probe", func(t *testing.T) {
			for _, c := range []string{
				string(f.b.ID),                  // B's tenant ID
				strings.ToLower(f.blockB[0].ID), // case-altered
				f.blockB[0].ID + "' OR '1'='1",  // injection attempt
				"blk_",
			} {
				_, err := bl.List(ctx, f.a.ID, store.BlocklistFilter{Cursor: c})
				if !errors.Is(err, store.ErrInvalid) {
					t.Errorf("List(cursor %q) err = %v, want ErrInvalid", c, err)
				}
			}
		})

		t.Run("match from A ignores B's entries", func(t *testing.T) {
			cases := []struct {
				name, email, sha string
				want             []store.BlocklistEntry
			}{
				{"B's blocked address", "spam-b@example.net", "", nil},
				{"B's blocked address, other case", "SPAM-B@Example.NET", "", nil},
				{"address in B's blocked domain", "someone@bad-b.example.net", "", nil},
				{"address in a sub-domain of B's blocked domain", "x@mail.bad-b.example.net", "", nil},
				{"B-only fingerprint", "", shaOnlyB, nil},
				{"B-only fingerprint upper case", "", strings.ToUpper(shaOnlyB), nil},
				{"fingerprint blocked by both: only A's entry", "", shaShared, []store.BlocklistEntry{f.blockA[2]}},
				{"A's address and B's fingerprint", "spam-a@example.net", shaOnlyB, []store.BlocklistEntry{f.blockA[0]}},
			}
			for _, tc := range cases {
				got, err := bl.Match(ctx, f.a.ID, tc.email, tc.sha)
				if err != nil {
					t.Fatalf("%s: Match(A): %v", tc.name, err)
				}
				assertSameEntries(t, tc.name, got, tc.want)
			}
			// And the other way round.
			got, err := bl.Match(ctx, f.b.ID, "spam-a@example.net", "")
			if err != nil || len(got) != 0 {
				t.Errorf("Match(B, A's address) = %+v, %v; want nothing", got, err)
			}
			got, err = bl.Match(ctx, f.b.ID, "", shaShared)
			if err != nil || len(got) != 1 || got[0] != f.blockB[3] {
				t.Errorf("Match(B, shared fingerprint) = %+v, %v; want only B's entry", got, err)
			}
		})

		t.Run("get from A with B's IDs is indistinguishable from a missing ID", func(t *testing.T) {
			_, refErr := bl.Get(ctx, f.a.ID, id.New(id.Blocklist))
			assertNotFound(t, "Get(A, missing)", refErr)
			targets := []string{f.blockB[0].ID + "' OR '1'='1", "' OR 1=1 --", ""}
			for _, b := range f.blockB {
				targets = append(targets, b.ID)
			}
			for _, target := range targets {
				_, err := bl.Get(ctx, f.a.ID, target)
				assertNotFound(t, "Get(A, "+target+")", err)
				if err != nil && refErr != nil && err.Error() != refErr.Error() {
					t.Errorf("Get(A, %q) err %q differs from missing-ID err %q", target, err, refErr)
				}
			}
			if got, err := bl.Get(ctx, f.a.ID, f.blockA[0].ID); err != nil || got != f.blockA[0] {
				t.Errorf("Get(A, own entry) = %+v, %v", got, err)
			}
		})

		t.Run("delete from A with B's IDs is indistinguishable from a missing ID", func(t *testing.T) {
			missing := id.New(id.Blocklist)
			refErr := bl.Delete(ctx, f.a.ID, missing)
			assertNotFound(t, "Delete(A, missing)", refErr)
			targets := []string{
				strings.ToLower(f.blockB[0].ID),
				f.blockB[0].ID + "' OR '1'='1",
				"' OR 1=1 --",
				"",
			}
			for _, b := range f.blockB {
				targets = append(targets, b.ID)
			}
			for _, target := range targets {
				err := bl.Delete(ctx, f.a.ID, target)
				assertNotFound(t, "Delete(A, "+target+")", err)
				if err != nil && refErr != nil && err.Error() != refErr.Error() {
					t.Errorf("Delete(A, %q) err %q differs from missing-ID err %q", target, err, refErr)
				}
			}
			f.assertBIntact(ctx, t)
			f.assertAIntact(ctx, t)
		})

		t.Run("create in A with B's values is not a conflict oracle", func(t *testing.T) {
			var created []store.BlocklistEntry
			for _, b := range f.blockB {
				if b.Kind == store.BlockSHA256 && b.Value == shaShared {
					continue // A already blocks it: a conflict would be legitimate
				}
				got, err := bl.Create(ctx, f.a.ID, store.BlocklistEntry{Kind: b.Kind, Value: b.Value})
				if err != nil {
					t.Fatalf("Create(A, B's value %s): %v (a conflict would reveal B's entry)", b.Value, err)
				}
				if idsB[got.ID] {
					t.Fatalf("Create(A) reused B's ID %s", got.ID)
				}
				created = append(created, got)
			}
			f.assertBIntact(ctx, t)
			// A sees its new entries; B still does not see them.
			all := listAll(ctx, t, f.db, f.a.ID)
			if len(all) != len(f.blockA)+len(created) {
				t.Errorf("A has %d entries, want %d", len(all), len(f.blockA)+len(created))
			}
			for _, c := range created {
				if err := bl.Delete(ctx, f.b.ID, c.ID); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("Delete(B, A's new entry) err = %v, want ErrNotFound", err)
				}
				if err := bl.Delete(ctx, f.a.ID, c.ID); err != nil {
					t.Errorf("Delete(A, own entry): %v", err)
				}
			}
			// Sanity: conflicts are detected inside one tenant.
			if _, err := bl.Create(ctx, f.a.ID, store.BlocklistEntry{Kind: store.BlockSHA256, Value: shaShared}); !errors.Is(err, store.ErrConflict) {
				t.Errorf("Create(A, duplicate) err = %v, want ErrConflict", err)
			}
			f.assertAIntact(ctx, t)
			f.assertBIntact(ctx, t)
		})
	})
}

// TestUnknownTenantIndistinguishable checks that a well-formed but
// nonexistent tenant behaves like an empty tenant (reads) or a missing row
// (writes), so that tenant IDs cannot be probed through the repositories.
func TestUnknownTenantIndistinguishable(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		ghost := id.New(id.Tenant)
		gid, err := tenant.ParseID(ghost)
		if err != nil {
			t.Fatal(err)
		}

		rules, err := f.db.NetworkRules().Get(ctx, gid)
		if err != nil || len(rules.CIDRs) != 0 || len(rules.Domains) != 0 {
			t.Errorf("NetworkRules.Get(ghost) = %+v, %v; want empty", rules, err)
		}
		_, err = f.db.NetworkRules().Replace(ctx, gid, f.rulesB.CIDRs, f.rulesB.Domains)
		assertNotFound(t, "NetworkRules.Replace(ghost)", err)
		p, err := f.db.Blocklist().List(ctx, gid, store.BlocklistFilter{})
		if err != nil || len(p.Items) != 0 || p.NextCursor != "" {
			t.Errorf("Blocklist.List(ghost) = %+v, %v; want empty", p, err)
		}
		m, err := f.db.Blocklist().Match(ctx, gid, "spam-b@example.net", shaOnlyB)
		if err != nil || len(m) != 0 {
			t.Errorf("Blocklist.Match(ghost) = %+v, %v; want empty", m, err)
		}
		_, err = f.db.Blocklist().Create(ctx, gid, store.BlocklistEntry{Kind: store.BlockEmail, Value: "x@example.net"})
		assertNotFound(t, "Blocklist.Create(ghost)", err)
		assertNotFound(t, "Blocklist.Delete(ghost, B's entry)", f.db.Blocklist().Delete(ctx, gid, f.blockB[0].ID))
		f.assertAIntact(ctx, t)
		f.assertBIntact(ctx, t)
	})
}

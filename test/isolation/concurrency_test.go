package isolation_test

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestConcurrentScopesNeverCross runs goroutines writing and reading A's and
// B's data simultaneously and checks that every result only ever holds the
// caller's own tenant data. On PostgreSQL this also exercises the pooled
// connections reused across tenants.
func TestConcurrentScopesNeverCross(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a := newTenant(t, db, fqdnA)
		b := newTenant(t, db, fqdnB)

		type side struct {
			tid    tenant.ID
			marker string // every value of this tenant contains it
			cidr   netip.Prefix
		}
		sides := []side{
			{a.ID, "entity-a.example.com", netip.MustParsePrefix("10.1.0.0/16")},
			{b.ID, "entity-b.example.org", netip.MustParsePrefix("10.2.0.0/16")},
		}
		const workersPerSide, iterations = 4, 15

		var wg sync.WaitGroup
		for _, s := range sides {
			other := sides[0]
			if s.tid == other.tid {
				other = sides[1]
			}
			for w := range workersPerSide {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range iterations {
						email := fmt.Sprintf("w%d-i%d@%s", w, i, s.marker)
						if _, err := db.Blocklist().Create(ctx, s.tid, store.BlocklistEntry{Kind: store.BlockEmail, Value: email}); err != nil {
							t.Errorf("Create(%s): %v", email, err)
							return
						}
						if _, err := db.NetworkRules().Replace(ctx, s.tid, []netip.Prefix{s.cidr},
							[]string{fmt.Sprintf("w%d.%s", w, s.marker)}); err != nil {
							t.Errorf("Replace: %v", err)
							return
						}
						rules, err := db.NetworkRules().Get(ctx, s.tid)
						if err != nil {
							t.Errorf("Get: %v", err)
							return
						}
						if len(rules.CIDRs) != 1 || rules.CIDRs[0] != s.cidr || len(rules.Domains) != 1 || !strings.HasSuffix(rules.Domains[0], s.marker) {
							t.Errorf("tenant %s sees foreign rules %+v", s.tid, rules)
						}
						p, err := db.Blocklist().List(ctx, s.tid, store.BlocklistFilter{Limit: store.MaxPageSize})
						if err != nil {
							t.Errorf("List: %v", err)
							return
						}
						for _, x := range p.Items {
							if !strings.HasSuffix(x.Value, "@"+s.marker) {
								t.Errorf("tenant %s lists foreign entry %+v", s.tid, x)
							}
						}
						m, err := db.Blocklist().Match(ctx, s.tid, fmt.Sprintf("w%d-i%d@%s", w, i, other.marker), "")
						if err != nil || len(m) != 0 {
							t.Errorf("tenant %s matches the other tenant's address: %+v, %v", s.tid, m, err)
						}
					}
				}()
			}
		}
		wg.Wait()

		for _, s := range sides {
			all := listAll(ctx, t, db, s.tid)
			if len(all) != workersPerSide*iterations {
				t.Errorf("tenant %s has %d entries, want %d", s.tid, len(all), workersPerSide*iterations)
			}
			for _, x := range all {
				if !strings.HasSuffix(x.Value, "@"+s.marker) {
					t.Errorf("tenant %s holds foreign entry %+v", s.tid, x)
				}
			}
		}
	})
}

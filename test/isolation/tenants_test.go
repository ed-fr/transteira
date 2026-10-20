package isolation_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestTenantsSystemScope checks the system-scoped Tenants repository: it
// sees every tenant (it is the registry) and never confuses them.
func TestTenantsSystemScope(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		repo := f.db.Tenants()

		page, err := repo.List(ctx, store.TenantListOptions{})
		if err != nil || len(page.Items) != 2 || page.Items[0].ID != f.a.ID || page.Items[1].ID != f.b.ID {
			t.Fatalf("List = %+v, %v; want [A, B]", page.Items, err)
		}
		for _, want := range []*tenant.Tenant{f.a, f.b} {
			got, err := repo.Get(ctx, want.ID)
			if err != nil || *got != *want {
				t.Errorf("Get(%s) = %+v, %v; want %+v", want.ID, got, err, want)
			}
		}

		// Malformed or foreign-prefixed IDs are reported as not found, never
		// as invalid (no oracle on the ID format).
		for _, bad := range []string{"", strings.ToLower(string(f.a.ID)), string(f.a.ID) + " ", f.blockA[0].ID, string(f.a.ID) + "' OR '1'='1"} {
			_, err := repo.Get(ctx, tenant.ID(bad))
			assertNotFound(t, "Get("+bad+")", err)
		}
		assertNotFound(t, "Delete(missing)", repo.Delete(ctx, tenant.ID(id.New(id.Tenant))))
		assertNotFound(t, "Delete(lower-case A)", repo.Delete(ctx, tenant.ID(strings.ToLower(string(f.a.ID)))))

		// Moving A onto B's FQDN is refused and leaves both unchanged.
		moved := f.a.Clone()
		moved.FQDN = f.b.FQDN
		if _, err := repo.Update(ctx, moved); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Update(A with B's FQDN) err = %v, want ErrConflict", err)
		}
		if got, err := repo.TenantByFQDN(ctx, fqdnB); err != nil || got.ID != f.b.ID {
			t.Errorf("TenantByFQDN(B) after conflict = %+v, %v", got, err)
		}
		if got, err := repo.Get(ctx, f.a.ID); err != nil || *got != *f.a {
			t.Errorf("A changed after conflicting update: %+v, %v", got, err)
		}
	})
}

// TestTenantFQDNResolution checks that a Host always resolves to the tenant
// that registered it, whatever its spelling, and never to another one.
func TestTenantFQDNResolution(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		repo := f.db.Tenants()

		idnFQDN, err := tenant.NormalizeHost("transfer.entité-c.example.net")
		if err != nil {
			t.Fatal(err)
		}
		c := newTenant(t, f.db, idnFQDN)

		// The store lookup is exact: it expects a normalised FQDN.
		for _, raw := range []string{"TRANSFER.ENTITY-A.EXAMPLE.COM", fqdnA + ".", fqdnA + ":443", " " + fqdnA, "entity-a.example.com", "transfer.entity-a.example.com.example.org"} {
			_, err := repo.TenantByFQDN(ctx, raw)
			if !errors.Is(err, tenant.ErrUnknownTenant) || !errors.Is(err, store.ErrNotFound) {
				t.Errorf("TenantByFQDN(%q) err = %v, want unknown tenant", raw, err)
			}
		}
		// Non-normalised FQDNs cannot be stored, so they cannot shadow A.
		for _, raw := range []string{"TRANSFER.ENTITY-A.EXAMPLE.COM", fqdnA + ".", fqdnA + ":8443", "transfer.entité-d.example.net"} {
			_, err := repo.Create(ctx, &tenant.Tenant{Name: "Shadow", FQDN: raw, DefaultLanguage: "en", MaxTransferBytes: 1, StorageQuotaBytes: 1})
			if !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Create(FQDN %q) err = %v, want ErrInvalid", raw, err)
			}
		}

		// Through the resolver, every spelling reaches the right tenant.
		res := tenant.NewResolver(repo)
		cases := []struct {
			host string
			want tenant.ID
		}{
			{"Transfer.Entity-A.Example.COM", f.a.ID},
			{fqdnA + ":443", f.a.ID},
			{fqdnA + ".", f.a.ID},
			{"TRANSFER.ENTITY-B.EXAMPLE.ORG:8443", f.b.ID},
			{"transfer.ENTITÉ-C.example.net", c.ID},
			{idnFQDN, c.ID},
		}
		for _, tc := range cases {
			got, err := res.Resolve(ctx, tc.host)
			if err != nil || got.ID != tc.want {
				t.Errorf("Resolve(%q) = %+v, %v; want %s", tc.host, got, err, tc.want)
			}
		}
		for _, host := range []string{"transfer.entity-z.example.com", "entity-a.example.com", "127.0.0.1", "[::1]:443"} {
			if got, err := res.Resolve(ctx, host); err == nil {
				t.Errorf("Resolve(%q) = %+v, want an error", host, got)
			}
		}
	})
}

// TestTenantDeleteCascadesOnlyOwnRows deletes tenant A and checks that only
// A's rows disappear, at the raw database level.
func TestTenantDeleteCascadesOnlyOwnRows(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)

		if n := rawCount(t, e, "blocklist_entries", "tenant_id", f.a.ID); n != len(f.blockA) {
			t.Fatalf("A has %d raw blocklist rows before delete, want %d", n, len(f.blockA))
		}
		if err := f.db.Tenants().Delete(ctx, f.a.ID); err != nil {
			t.Fatalf("Delete(A): %v", err)
		}
		for _, tc := range []struct{ table, column string }{
			{"tenants", "id"}, {"tenant_network_rules", "tenant_id"}, {"blocklist_entries", "tenant_id"},
		} {
			if n := rawCount(t, e, tc.table, tc.column, f.a.ID); n != 0 {
				t.Errorf("%s still holds %d rows of deleted tenant A", tc.table, n)
			}
		}
		if n := rawCount(t, e, "blocklist_entries", "tenant_id", f.b.ID); n != len(f.blockB) {
			t.Errorf("B has %d raw blocklist rows, want %d", n, len(f.blockB))
		}
		if n := rawCount(t, e, "tenant_network_rules", "tenant_id", f.b.ID); n != len(f.rulesB.CIDRs)+len(f.rulesB.Domains) {
			t.Errorf("B has %d raw rule rows, want %d", n, len(f.rulesB.CIDRs)+len(f.rulesB.Domains))
		}
		f.assertBIntact(ctx, t)
		if _, err := f.db.Tenants().Get(ctx, f.a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(deleted A) err = %v, want ErrNotFound", err)
		}
		// Deleting A again, or writing to it, is a plain not-found.
		assertNotFound(t, "Delete(A) twice", f.db.Tenants().Delete(ctx, f.a.ID))
		_, err := f.db.Blocklist().Create(ctx, f.a.ID, store.BlocklistEntry{Kind: store.BlockEmail, Value: "late@example.net"})
		assertNotFound(t, "Blocklist.Create(deleted A)", err)
	})
}

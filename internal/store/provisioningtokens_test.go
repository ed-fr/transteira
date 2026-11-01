package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// newProvToken returns a valid new provisioning token record.
func newProvToken(t *testing.T) store.ProvisioningToken {
	t.Helper()
	return store.ProvisioningToken{
		ID: id.New(id.ProvisioningToken), Name: "Managed service provider", Prefix: "ttp_AbCd", TokenHash: randomHash(t),
		AllowedCIDRs:         []netip.Prefix{netip.MustParsePrefix("198.51.100.7/24"), netip.MustParsePrefix("2001:db8::/32")},
		AllowedFQDNSuffixes:  []string{".transfer.example.com", ".xn--bcher-kva.example"},
		MaxStorageQuotaBytes: 1 << 40, MaxTransferBytes: 1 << 30, MaxTenants: 5,
		CreatedBy: id.New(id.Admin),
	}
}

// mustProvToken stores tok and returns it.
func mustProvToken(t *testing.T, db *store.DB, tok store.ProvisioningToken) store.ProvisioningToken {
	t.Helper()
	got, err := db.ProvisioningTokens().Create(context.Background(), tok, nil)
	if err != nil {
		t.Fatalf("Create provisioning token: %v", err)
	}
	return got
}

// provTenant returns a new tenant to provision under fqdn.
func provTenant(fqdn string) *tenant.Tenant {
	return &tenant.Tenant{
		SetupState: tenant.SetupStateSetup, Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "fr",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 30,
	}
}

func TestProvisioningTokensCRUD(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.ProvisioningTokens()

		in := newProvToken(t)
		in.ExpiresAt = fixedNow.Add(48 * time.Hour)
		var inTx store.ProvisioningToken
		first, err := repo.Create(ctx, in, func(_ *store.SystemTx, tok store.ProvisioningToken) error {
			inTx = tok
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		wantCIDRs := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8::/32")}
		if !reflect.DeepEqual(first.AllowedCIDRs, wantCIDRs) || !first.CreatedAt.Equal(fixedNow.Truncate(time.Millisecond)) ||
			!first.ExpiresAt.Equal(in.ExpiresAt.Truncate(time.Millisecond)) || !reflect.DeepEqual(inTx, first) {
			t.Errorf("Create = %+v (in tx %+v)", first, inTx)
		}
		got, err := repo.Get(ctx, first.ID)
		if err != nil || !reflect.DeepEqual(got, first) {
			t.Errorf("Get = %+v, %v; want %+v", got, err, first)
		}
		if got, err := repo.GetByHash(ctx, in.TokenHash); err != nil || got.ID != first.ID {
			t.Errorf("GetByHash = %+v, %v", got, err)
		}
		_, err = repo.GetByHash(ctx, randomHash(t))
		wantErr(t, "GetByHash(unknown)", err, store.ErrNotFound)
		_, err = repo.GetByHash(ctx, []byte("short"))
		wantErr(t, "GetByHash(short)", err, store.ErrInvalid)
		_, err = repo.Get(ctx, id.New(id.ProvisioningToken))
		wantErr(t, "Get(unknown)", err, store.ErrNotFound)

		// No transfer cap and no expiry are stored as NULL.
		second := newProvToken(t)
		second.MaxTransferBytes = 0
		second.CreatedAt = fixedNow.Add(time.Minute)
		second = mustProvToken(t, db, second)
		if got, _ := repo.Get(ctx, second.ID); got.MaxTransferBytes != 0 || !got.ExpiresAt.IsZero() {
			t.Errorf("Get(second) = %+v", got)
		}

		// Same identifier or hash: conflict.
		dup := newProvToken(t)
		dup.ID = first.ID
		_, err = repo.Create(ctx, dup, nil)
		wantErr(t, "Create(dup id)", err, store.ErrConflict)
		dup = newProvToken(t)
		dup.TokenHash = in.TokenHash
		_, err = repo.Create(ctx, dup, nil)
		wantErr(t, "Create(dup hash)", err, store.ErrConflict)

		// An error of then rolls the token back.
		boom := errors.New("boom")
		rolled := newProvToken(t)
		_, err = repo.Create(ctx, rolled, func(*store.SystemTx, store.ProvisioningToken) error { return boom })
		wantErr(t, "Create(then fails)", err, boom)
		_, err = repo.Get(ctx, rolled.ID)
		wantErr(t, "Get(rolled back)", err, store.ErrNotFound)

		// List: newest first, with the count of tenants.
		if _, err := db.Tenants().CreateProvisioned(ctx, first.ID, provTenant("a.transfer.example.com"), nil); err != nil {
			t.Fatal(err)
		}
		list, err := repo.List(ctx)
		if err != nil || len(list) != 2 || list[0].ID != second.ID || list[1].ID != first.ID ||
			list[1].TenantsCreated != 1 || list[0].TenantsCreated != 0 {
			t.Fatalf("List = %+v, %v", list, err)
		}

		// Touch moves the last use forward only.
		later := fixedNow.Add(time.Hour)
		if err := repo.Touch(ctx, first.ID, later); err != nil {
			t.Fatal(err)
		}
		if err := repo.Touch(ctx, first.ID, fixedNow); err != nil {
			t.Fatal(err)
		}
		if err := repo.Touch(ctx, id.New(id.ProvisioningToken), time.Time{}); err != nil {
			t.Errorf("Touch(unknown) = %v", err)
		}
		if got, _ := repo.Get(ctx, first.ID); !got.LastUsedAt.Equal(later.Truncate(time.Millisecond)) {
			t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, later)
		}

		// Revoke once, idempotent afterwards, never deleted.
		var seen []bool
		hook := func(_ *store.SystemTx, _ store.ProvisioningToken, revoked bool) error {
			seen = append(seen, revoked)
			return nil
		}
		tok, revoked, err := repo.Revoke(ctx, first.ID, time.Time{}, hook)
		if err != nil || !revoked || !tok.Revoked() || tok.TenantsCreated != 1 {
			t.Errorf("Revoke = %+v, %v, %v", tok, revoked, err)
		}
		tok, revoked, err = repo.Revoke(ctx, first.ID, later, hook)
		if err != nil || revoked || !tok.RevokedAt.Equal(fixedNow.Truncate(time.Millisecond)) {
			t.Errorf("Revoke again = %+v, %v, %v", tok, revoked, err)
		}
		if !reflect.DeepEqual(seen, []bool{true, false}) {
			t.Errorf("then saw %v", seen)
		}
		_, _, err = repo.Revoke(ctx, id.New(id.ProvisioningToken), time.Time{}, nil)
		wantErr(t, "Revoke(unknown)", err, store.ErrNotFound)
		_, _, err = repo.Revoke(ctx, second.ID, time.Time{}, func(*store.SystemTx, store.ProvisioningToken, bool) error { return boom })
		wantErr(t, "Revoke(then fails)", err, boom)
		if got, _ := repo.Get(ctx, second.ID); got.Revoked() {
			t.Error("a failed revocation was kept")
		}
		if list, _ := repo.List(ctx); len(list) != 2 {
			t.Errorf("a revoked token must stay listed: %d", len(list))
		}
	})
}

func TestProvisioningTokenState(t *testing.T) {
	t.Parallel()
	tok := store.ProvisioningToken{}
	if !tok.Usable(fixedNow) || tok.Expired(fixedNow) || tok.Revoked() {
		t.Error("a token without expiry nor revocation is usable")
	}
	tok.ExpiresAt = fixedNow
	if !tok.Expired(fixedNow) || tok.Usable(fixedNow) || tok.Expired(fixedNow.Add(-time.Millisecond)) {
		t.Error("a token expires at its expiry")
	}
	tok = store.ProvisioningToken{RevokedAt: fixedNow}
	if tok.Usable(fixedNow) || !tok.Revoked() {
		t.Error("a revoked token is unusable")
	}
}

func TestProvisioningTokensCreateInvalid(t *testing.T) {
	t.Parallel()
	db := openDB(t, storetest.SQLite(t))
	many := func(n int, f func(i int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	manyCIDRs := make([]netip.Prefix, store.MaxProvisioningTokenCIDRs+1)
	for i := range manyCIDRs {
		manyCIDRs[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16)
	}
	cases := map[string]func(*store.ProvisioningToken){
		"no cidr":        func(p *store.ProvisioningToken) { p.AllowedCIDRs = nil },
		"too many cidrs": func(p *store.ProvisioningToken) { p.AllowedCIDRs = manyCIDRs },
		"v4 any":         func(p *store.ProvisioningToken) { p.AllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} },
		"v6 any":         func(p *store.ProvisioningToken) { p.AllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("::/0")} },
		"v4-mapped": func(p *store.ProvisioningToken) {
			p.AllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("::ffff:0.0.0.0/96")}
		},
		"zero prefix":    func(p *store.ProvisioningToken) { p.AllowedCIDRs = []netip.Prefix{{}} },
		"duplicate cidr": func(p *store.ProvisioningToken) { p.AllowedCIDRs = append(p.AllowedCIDRs, p.AllowedCIDRs[0]) },
		"no suffix":      func(p *store.ProvisioningToken) { p.AllowedFQDNSuffixes = nil },
		"too many suffix": func(p *store.ProvisioningToken) {
			p.AllowedFQDNSuffixes = many(101, func(i int) string { return fmt.Sprintf(".e%d.example.com", i) })
		},
		"suffix no dot":    func(p *store.ProvisioningToken) { p.AllowedFQDNSuffixes = []string{"example.com"} },
		"suffix one label": func(p *store.ProvisioningToken) { p.AllowedFQDNSuffixes = []string{".com"} },
		"suffix upper":     func(p *store.ProvisioningToken) { p.AllowedFQDNSuffixes = []string{".Example.com"} },
		"suffix dup":       func(p *store.ProvisioningToken) { p.AllowedFQDNSuffixes = []string{".a.example.com", ".a.example.com"} },
		"bad id":           func(p *store.ProvisioningToken) { p.ID = id.New(id.APIToken) },
		"empty name":       func(p *store.ProvisioningToken) { p.Name = "" },
		"multiline name":   func(p *store.ProvisioningToken) { p.Name = "a\nb" },
		"bad prefix":       func(p *store.ProvisioningToken) { p.Prefix = "" },
		"bad hash":         func(p *store.ProvisioningToken) { p.TokenHash = []byte("x") },
		"zero quota":       func(p *store.ProvisioningToken) { p.MaxStorageQuotaBytes = 0 },
		"negative cap":     func(p *store.ProvisioningToken) { p.MaxTransferBytes = -1 },
		"cap above 20 GiB": func(p *store.ProvisioningToken) { p.MaxTransferBytes = tenant.MaxTransferLimit + 1 },
		"zero tenants":     func(p *store.ProvisioningToken) { p.MaxTenants = 0 },
		"bad creator":      func(p *store.ProvisioningToken) { p.CreatedBy = "superadmin" },
		"expired at birth": func(p *store.ProvisioningToken) { p.ExpiresAt = fixedNow },
		"already used":     func(p *store.ProvisioningToken) { p.LastUsedAt = fixedNow },
		"already revoked":  func(p *store.ProvisioningToken) { p.RevokedAt = fixedNow },
	}
	for name, mutate := range cases {
		tok := newProvToken(t)
		mutate(&tok)
		_, err := db.ProvisioningTokens().Create(context.Background(), tok, nil)
		wantErr(t, name, err, store.ErrInvalid)
	}
	if list, _ := db.ProvisioningTokens().List(context.Background()); len(list) != 0 {
		t.Errorf("invalid tokens were stored: %d", len(list))
	}
}

func TestCreateProvisioned(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		tok := newProvToken(t)
		tok.MaxTenants = 2
		tok = mustProvToken(t, db, tok)

		created, err := db.Tenants().CreateProvisioned(ctx, tok.ID, provTenant("a.transfer.example.com"),
			func(_ *store.SystemTx, c *tenant.Tenant) error {
				if c.ProvisionedBy != tok.ID {
					t.Errorf("then sees ProvisionedBy = %q", c.ProvisionedBy)
				}
				return nil
			})
		if err != nil || created.ProvisionedBy != tok.ID {
			t.Fatalf("CreateProvisioned = %+v, %v", created, err)
		}
		if got, err := db.Tenants().Get(ctx, created.ID); err != nil || got.ProvisionedBy != tok.ID {
			t.Errorf("Get = %+v, %v", got, err)
		}
		// A tenant created by the super admin has no provisioning token.
		plain := newTenant(t, db, "plain.example.com")
		if got, _ := db.Tenants().Get(ctx, plain.ID); got.ProvisionedBy != "" {
			t.Errorf("super admin tenant ProvisionedBy = %q", got.ProvisionedBy)
		}

		// An error of then rolls the tenant back and does not count.
		boom := errors.New("boom")
		_, err = db.Tenants().CreateProvisioned(ctx, tok.ID, provTenant("b.transfer.example.com"),
			func(*store.SystemTx, *tenant.Tenant) error { return boom })
		wantErr(t, "CreateProvisioned(then fails)", err, boom)

		if _, err := db.Tenants().CreateProvisioned(ctx, tok.ID, provTenant("b.transfer.example.com"), nil); err != nil {
			t.Fatal(err)
		}
		// maxTenants reached.
		_, err = db.Tenants().CreateProvisioned(ctx, tok.ID, provTenant("c.transfer.example.com"), nil)
		wantErr(t, "CreateProvisioned(max)", err, store.ErrProvisioningMaxTenants)

		// Deleting a tenant frees a place.
		if err := db.Tenants().Delete(ctx, created.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Tenants().CreateProvisioned(ctx, tok.ID, provTenant("c.transfer.example.com"), nil); err != nil {
			t.Errorf("CreateProvisioned after a deletion: %v", err)
		}

		// Unknown, revoked or expired token.
		_, err = db.Tenants().CreateProvisioned(ctx, id.New(id.ProvisioningToken), provTenant("d.transfer.example.com"), nil)
		wantErr(t, "CreateProvisioned(unknown)", err, store.ErrProvisioningTokenUnusable)
		expired := newProvToken(t)
		expired.CreatedAt, expired.ExpiresAt = fixedNow.Add(-2*time.Hour), fixedNow.Add(-time.Hour)
		expired = mustProvToken(t, db, expired)
		_, err = db.Tenants().CreateProvisioned(ctx, expired.ID, provTenant("d.transfer.example.com"), nil)
		wantErr(t, "CreateProvisioned(expired)", err, store.ErrProvisioningTokenUnusable)
		revoked := mustProvToken(t, db, newProvToken(t))
		if _, _, err := db.ProvisioningTokens().Revoke(ctx, revoked.ID, time.Time{}, nil); err != nil {
			t.Fatal(err)
		}
		_, err = db.Tenants().CreateProvisioned(ctx, revoked.ID, provTenant("d.transfer.example.com"), nil)
		wantErr(t, "CreateProvisioned(revoked)", err, store.ErrProvisioningTokenUnusable)

		// Malformed arguments.
		_, err = db.Tenants().CreateProvisioned(ctx, "prv_bad", provTenant("d.transfer.example.com"), nil)
		wantErr(t, "CreateProvisioned(bad id)", err, store.ErrInvalid)
		other := provTenant("d.transfer.example.com")
		other.ProvisionedBy = expired.ID
		_, err = db.Tenants().CreateProvisioned(ctx, tok.ID, other, nil)
		wantErr(t, "CreateProvisioned(other token)", err, store.ErrInvalid)
		// Only CreateProvisioned names a token.
		_, err = db.Tenants().Create(ctx, other)
		wantErr(t, "Create(with token)", err, store.ErrInvalid)
		// The FQDN conflict of a plain creation applies.
		_, err = db.Tenants().CreateProvisioned(ctx, revoked.ID, provTenant("plain.example.com"), nil)
		wantErr(t, "CreateProvisioned(revoked first)", err, store.ErrProvisioningTokenUnusable)
		big := newProvToken(t)
		big = mustProvToken(t, db, big)
		_, err = db.Tenants().CreateProvisioned(ctx, big.ID, provTenant("plain.example.com"), nil)
		wantErr(t, "CreateProvisioned(fqdn taken)", err, store.ErrConflict)
	})
}

func TestCreateProvisionedRateLimit(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		tok := newProvToken(t)
		tok.MaxTenants = 100
		tok = mustProvToken(t, db, tok)
		for i := range store.ProvisioningCreationsPerHour {
			if _, err := db.Tenants().CreateProvisioned(ctx, tok.ID, provTenant(fmt.Sprintf("e%d.transfer.example.com", i)), nil); err != nil {
				t.Fatalf("creation %d: %v", i, err)
			}
		}
		_, err := db.Tenants().CreateProvisioned(ctx, tok.ID, provTenant("last.transfer.example.com"), nil)
		var rl *store.ProvisioningRateLimitError
		if !errors.As(err, &rl) || !errors.Is(err, store.ErrProvisioningRateLimited) || rl.RetryAfter != time.Hour {
			t.Fatalf("31st creation = %v", err)
		}
		if rl.Error() == "" {
			t.Error("empty error message")
		}
		// Another token is not limited by this one.
		other := mustProvToken(t, db, newProvToken(t))
		if _, err := db.Tenants().CreateProvisioned(ctx, other.ID, provTenant("other.transfer.example.com"), nil); err != nil {
			t.Errorf("other token: %v", err)
		}
	})
}

// TestCreateProvisionedConcurrent proves that maxTenants holds when many
// creations of one token run at once (T-271): exactly maxTenants pass.
func TestCreateProvisionedConcurrent(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		tok := newProvToken(t)
		tok.MaxTenants = 3
		tok = mustProvToken(t, db, tok)
		const n = 12
		var (
			wg      sync.WaitGroup
			ok, max atomic.Int32
			mu      sync.Mutex
			other   []error
		)
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := db.Tenants().CreateProvisioned(ctx, tok.ID, provTenant(fmt.Sprintf("p%d.transfer.example.com", i)), nil)
				switch {
				case err == nil:
					ok.Add(1)
				case errors.Is(err, store.ErrProvisioningMaxTenants):
					max.Add(1)
				default:
					mu.Lock()
					other = append(other, err)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(other) > 0 {
			t.Fatalf("unexpected errors: %v", other)
		}
		if ok.Load() != 3 || max.Load() != n-3 {
			t.Errorf("created %d, refused %d; want 3 and %d", ok.Load(), max.Load(), n-3)
		}
		if got, _ := db.ProvisioningTokens().Get(ctx, tok.ID); got.TenantsCreated != 3 {
			t.Errorf("TenantsCreated = %d", got.TenantsCreated)
		}
		// The authentication lookup does not count the tenants.
		if got, err := db.ProvisioningTokens().GetByHash(ctx, tok.TokenHash); err != nil || got.ID != tok.ID ||
			got.TenantsCreated != 0 {
			t.Errorf("GetByHash = %+v, %v; want no count", got, err)
		}
	})
}

// TestProvisionedTenantsIsolation checks that a token reaches only the
// tenants it created (T-270): never those of another token, of the super
// admin, nor a tenant being deleted.
func TestProvisionedTenantsIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.ProvisioningTokens()
		tokA := mustProvToken(t, db, newProvToken(t))
		tokB := mustProvToken(t, db, newProvToken(t))
		a1, err := db.Tenants().CreateProvisioned(ctx, tokA.ID, provTenant("a1.transfer.example.com"), nil)
		if err != nil {
			t.Fatal(err)
		}
		a2, err := db.Tenants().CreateProvisioned(ctx, tokA.ID, provTenant("a2.transfer.example.com"), nil)
		if err != nil {
			t.Fatal(err)
		}
		b1, err := db.Tenants().CreateProvisioned(ctx, tokB.ID, provTenant("b1.transfer.example.com"), nil)
		if err != nil {
			t.Fatal(err)
		}
		plain := newTenant(t, db, "plain.example.com")

		// An activated delegated admin of a1, an inactive one of a2.
		adm := newDelegated(t, db, "admin.a1", a1.ID)
		if err := db.Admins().SetPassword(ctx, adm.ID, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"); err != nil {
			t.Fatal(err)
		}
		newDelegated(t, db, "admin.a2", a2.ID)
		// A super admin with a password is not a delegated admin of b1.
		if _, err := db.Admins().Create(ctx, store.Admin{
			Username: "root", Email: "root@example.com", Role: store.RoleSuperAdmin, RequireTOTP: true,
		}); err != nil {
			t.Fatal(err)
		}

		list, err := repo.ListTenants(ctx, tokA.ID)
		if err != nil || len(list) != 2 {
			t.Fatalf("ListTenants(A) = %+v, %v", list, err)
		}
		ids := map[tenant.ID]store.ProvisionedTenant{list[0].ID: list[0], list[1].ID: list[1]}
		if got := ids[a1.ID]; !got.DelegatedAdminActivated || got.FQDN != a1.FQDN || got.Name != a1.Name ||
			got.SetupState != tenant.SetupStateSetup || !got.CreatedAt.Equal(a1.CreatedAt) {
			t.Errorf("a1 = %+v", got)
		}
		if got, ok := ids[a2.ID]; !ok || got.DelegatedAdminActivated {
			t.Errorf("a2 = %+v, %v", got, ok)
		}
		if got, err := repo.GetTenant(ctx, tokA.ID, a1.ID); err != nil || !got.DelegatedAdminActivated {
			t.Errorf("GetTenant(A, a1) = %+v, %v", got, err)
		}
		for name, c := range map[string]struct {
			tok string
			tid tenant.ID
		}{
			"A reads B's":         {tokA.ID, b1.ID},
			"B reads A's":         {tokB.ID, a1.ID},
			"A reads super admin": {tokA.ID, plain.ID},
			"unknown tenant":      {tokA.ID, tenant.ID(id.New(id.Tenant))},
			"unknown token":       {id.New(id.ProvisioningToken), a1.ID},
		} {
			_, err := repo.GetTenant(ctx, c.tok, c.tid)
			wantErr(t, name, err, store.ErrNotFound)
		}
		if list, err := repo.ListTenants(ctx, tokB.ID); err != nil || len(list) != 1 || list[0].ID != b1.ID ||
			list[0].DelegatedAdminActivated {
			t.Errorf("ListTenants(B) = %+v, %v", list, err)
		}
		if list, err := repo.ListTenants(ctx, id.New(id.ProvisioningToken)); err != nil || len(list) != 0 {
			t.Errorf("ListTenants(unknown) = %+v, %v", list, err)
		}

		// A tenant being deleted is out of reach, but still counts.
		if err := db.Tenants().SetStatus(ctx, a2.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		_, err = repo.GetTenant(ctx, tokA.ID, a2.ID)
		wantErr(t, "GetTenant(deleting)", err, store.ErrNotFound)
		if list, _ := repo.ListTenants(ctx, tokA.ID); len(list) != 1 || list[0].ID != a1.ID {
			t.Errorf("ListTenants(A) after deletion start = %+v", list)
		}
		if got, _ := repo.Get(ctx, tokA.ID); got.TenantsCreated != 2 {
			t.Errorf("TenantsCreated = %d, want 2 (a tenant being deleted still exists)", got.TenantsCreated)
		}
	})
}

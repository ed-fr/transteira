package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestTenantExpressSettings covers the express settings of a tenant (since
// 2.3), on both engines: the defaults, the creation (limits kept, the
// anonymous mode always off), SetExpressSettings and UpdateWithPolicies,
// and their refusals.
func TestTenantExpressSettings(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openMigratedEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		repo := db.Tenants()
		base := func(fqdn string, x tenant.ExpressSettings) *tenant.Tenant {
			return &tenant.Tenant{
				SetupState: tenant.SetupStateActive, Name: "T", FQDN: fqdn, DefaultLanguage: "fr",
				MaxTransferBytes: 1, StorageQuotaBytes: 1, Express: x,
			}
		}

		plain, err := repo.Create(ctx, base("a.example.com", tenant.ExpressSettings{}))
		if err != nil || plain.Express != tenant.DefaultExpressSettings() {
			t.Fatalf("Create = %+v, %v", plain, err)
		}
		if got, err := repo.Get(ctx, plain.ID); err != nil || got.Express != tenant.DefaultExpressSettings() {
			t.Errorf("Get = %+v, %v", got.Express, err)
		}
		// An imported configuration keeps its limits (zero ones take the
		// defaults) but never opens the anonymous mode (P92).
		imported, err := repo.Create(ctx, base("b.example.com", tenant.ExpressSettings{Enabled: true, PerHourPerIP: 5, MaxPending: 7}))
		want := tenant.ExpressSettings{PerHourPerIP: 5, PerHourPerToken: tenant.DefaultExpressPerHourPerToken, MaxPending: 7}
		if err != nil || imported.Express != want {
			t.Fatalf("Create with express settings = %+v, %v", imported, err)
		}
		if got, err := repo.Get(ctx, imported.ID); err != nil || got.Express != want {
			t.Errorf("Get imported = %+v, %v", got.Express, err)
		}
		if _, err := repo.Create(ctx, base("c.example.com", tenant.ExpressSettings{PerHourPerIP: 5000})); !errors.Is(err, ErrInvalid) {
			t.Errorf("Create with an out-of-bounds limit: %v", err)
		}

		// SetExpressSettings writes everything given, Enabled included.
		set := tenant.ExpressSettings{Enabled: true, PerHourPerIP: 1, PerHourPerToken: 10000, MaxPending: 100000}
		got, err := repo.SetExpressSettings(ctx, plain.ID, set)
		if err != nil || got.Express != set || !got.UpdatedAt.After(plain.UpdatedAt.Add(-time.Millisecond)) {
			t.Fatalf("SetExpressSettings = %+v, %v", got, err)
		}
		if got, err := repo.TenantByFQDN(ctx, "a.example.com"); err != nil || got.Express != set {
			t.Errorf("TenantByFQDN = %+v, %v", got, err)
		}
		if _, err := repo.SetExpressSettings(ctx, plain.ID, tenant.ExpressSettings{MaxPending: 1}); !errors.Is(err, ErrInvalid) {
			t.Errorf("SetExpressSettings with zero limits: %v", err)
		}
		if _, err := repo.SetExpressSettings(ctx, "ten_bad", set); !errors.Is(err, ErrNotFound) {
			t.Errorf("SetExpressSettings of a malformed ID: %v", err)
		}
		if _, err := repo.SetExpressSettings(ctx, tenant.ID(id.New(id.Tenant)), set); !errors.Is(err, ErrNotFound) {
			t.Errorf("SetExpressSettings of an unknown tenant: %v", err)
		}
		// With the 2.1 settings in one transaction.
		next := got.Clone()
		next.Secrets.Enabled = false
		next.Express = tenant.DefaultExpressSettings()
		both, err := repo.UpdateWithPolicies(ctx, next, TenantParts{Secrets: true, Express: true})
		if err != nil || both.Secrets.Enabled || both.Express != tenant.DefaultExpressSettings() {
			t.Errorf("UpdateWithPolicies = %+v, %v", both, err)
		}
		next.Express.MaxPending = 0
		if _, err := repo.UpdateWithPolicies(ctx, next, TenantParts{Secrets: true, Express: true}); !errors.Is(err, ErrInvalid) {
			t.Errorf("UpdateWithPolicies with an invalid limit: %v", err)
		}
		if after, err := repo.Get(ctx, plain.ID); err != nil || after.Secrets.Enabled || after.Express != both.Express {
			t.Errorf("a refused update changed the tenant: %+v, %v", after, err)
		}
		// A patch writes the members it sets; the others keep the value
		// stored at the time of the write, not the one of next.
		if _, err := repo.SetExpressSettings(ctx, plain.ID, set); err != nil {
			t.Fatal(err)
		}
		next.Secrets.Enabled = true
		patched, err := repo.UpdateWithPolicies(ctx, next, TenantParts{Secrets: true, ExpressPatch: &ExpressPatch{MaxPending: new(42)}})
		if want := (tenant.ExpressSettings{Enabled: true, PerHourPerIP: 1, PerHourPerToken: 10000, MaxPending: 42}); err != nil ||
			!patched.Secrets.Enabled || patched.Express != want {
			t.Errorf("UpdateWithPolicies with a patch = %+v, %v", patched, err)
		}
		patched, err = repo.UpdateWithPolicies(ctx, next, TenantParts{ExpressPatch: &ExpressPatch{
			Enabled: new(false), PerHourPerIP: new(3), PerHourPerToken: new(30),
		}})
		if want := (tenant.ExpressSettings{PerHourPerIP: 3, PerHourPerToken: 30, MaxPending: 42}); err != nil || patched.Express != want {
			t.Errorf("UpdateWithPolicies with every limit but one = %+v, %v", patched.Express, err)
		}
		if same, err := repo.UpdateWithPolicies(ctx, next, TenantParts{ExpressPatch: &ExpressPatch{}}); err != nil || same.Express != patched.Express {
			t.Errorf("empty patch = %+v, %v", same.Express, err)
		}
		// Express set: the patch is ignored.
		next.Express = tenant.DefaultExpressSettings()
		if full, err := repo.UpdateWithPolicies(ctx, next, TenantParts{Express: true, ExpressPatch: &ExpressPatch{MaxPending: new(9)}}); err != nil ||
			full.Express != tenant.DefaultExpressSettings() {
			t.Errorf("Express with a patch = %+v, %v", full.Express, err)
		}
		if _, err := repo.UpdateWithPolicies(ctx, next, TenantParts{ExpressPatch: &ExpressPatch{PerHourPerIP: new(0)}}); !errors.Is(err, ErrInvalid) {
			t.Errorf("patch with an invalid limit: %v", err)
		}
		if err := repo.SetStatus(ctx, imported.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.SetExpressSettings(ctx, imported.ID, set); !errors.Is(err, ErrNotFound) {
			t.Errorf("SetExpressSettings of a tenant being deleted: %v", err)
		}
		gone := imported.Clone()
		if _, err := repo.UpdateWithPolicies(ctx, gone, TenantParts{ExpressPatch: &ExpressPatch{Enabled: new(true)}}); !errors.Is(err, ErrNotFound) {
			t.Errorf("patch of a tenant being deleted: %v", err)
		}
	})
}

// TestExpressPatch covers the member by member change of the express
// settings.
func TestExpressPatch(t *testing.T) {
	t.Parallel()
	s := tenant.ExpressSettings{PerHourPerIP: 1, PerHourPerToken: 2, MaxPending: 3}
	if got := (ExpressPatch{}).Apply(s); got != s {
		t.Errorf("empty patch = %+v", got)
	}
	p := ExpressPatch{Enabled: new(true), PerHourPerIP: new(4), PerHourPerToken: new(5), MaxPending: new(6)}
	if got := p.Apply(s); got != (tenant.ExpressSettings{Enabled: true, PerHourPerIP: 4, PerHourPerToken: 5, MaxPending: 6}) {
		t.Errorf("full patch = %+v", got)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("Validate = %v", err)
	}
	for _, bad := range []ExpressPatch{
		{PerHourPerIP: new(tenant.MaxExpressPerHourPerIP + 1)}, {PerHourPerToken: new(0)}, {MaxPending: new(tenant.MaxExpressMaxPending + 1)},
	} {
		if err := bad.Validate(); !errors.Is(err, tenant.ErrInvalidTenant) {
			t.Errorf("Validate(%+v) = %v", bad, err)
		}
	}
}

// TestTenantExpressSettingsFaults injects failures into the writes of the
// express settings (SQLite).
func TestTenantExpressSettingsFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	plan.add(faultExec, "express_max_pending = ?", 0)
	_, err := db.Tenants().Create(ctx, &tenant.Tenant{
		SetupState: tenant.SetupStateActive, Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr",
		MaxTransferBytes: 1, StorageQuotaBytes: 1, Express: tenant.ExpressSettings{MaxPending: 5},
	})
	if !errors.Is(err, errInjected) {
		t.Errorf("Create with a failing express settings write = %v", err)
	}
	plan.reset()
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
		SetupState: tenant.SetupStateActive, Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr",
		MaxTransferBytes: 1, StorageQuotaBytes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan.add(faultExec, "express_max_pending = ?", 0)
	if _, err := db.Tenants().SetExpressSettings(ctx, tn.ID, tenant.DefaultExpressSettings()); !errors.Is(err, errInjected) {
		t.Errorf("SetExpressSettings with a failing write = %v", err)
	}
}

// TestAPITokenExpressAllowed covers the express secret opt-in of the API
// tokens (since 2.3), on both engines: off by default, set at creation,
// changed or kept by Update, read by every read path.
func TestAPITokenExpressAllowed(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openMigratedEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		tid := newTestTenant(ctx, t, db, "a.example.com")
		repo := db.APITokens()
		create := func(allowed bool) APIToken {
			t.Helper()
			tokID := id.New(id.APIToken)
			hash := sha256.Sum256([]byte(tokID))
			tok, err := repo.Create(ctx, tid, APIToken{
				ID: tokID, Name: "ci", Prefix: "tt_Ab", TokenHash: hash[:],
				CreatedBy: "root", AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, ExpressAllowed: allowed,
			})
			if err != nil || tok.ExpressAllowed != allowed {
				t.Fatalf("Create(%v) = %+v, %v", allowed, tok, err)
			}
			return tok
		}
		off, on := create(false), create(true)
		if got, err := repo.Get(ctx, tid, on.ID); err != nil || !got.ExpressAllowed {
			t.Errorf("Get = %+v, %v", got, err)
		}
		if got, err := repo.GetByHash(ctx, tid, on.TokenHash); err != nil || !got.ExpressAllowed {
			t.Errorf("GetByHash = %+v, %v", got, err)
		}
		list, err := repo.List(ctx, tid)
		if err != nil || len(list) != 2 || list[0].ExpressAllowed == list[1].ExpressAllowed {
			t.Errorf("List = %+v, %v", list, err)
		}
		// Update: nil keeps it, a value replaces it.
		if got, err := repo.Update(ctx, tid, on.ID, APITokenUpdate{Name: "renamed"}); err != nil || !got.ExpressAllowed || got.Name != "renamed" {
			t.Errorf("Update keeping the opt-in = %+v, %v", got, err)
		}
		no, yes := false, true
		if got, err := repo.Update(ctx, tid, on.ID, APITokenUpdate{ExpressAllowed: &no}); err != nil || got.ExpressAllowed || got.Name != "renamed" {
			t.Errorf("Update turning it off = %+v, %v", got, err)
		}
		if got, err := repo.Update(ctx, tid, off.ID, APITokenUpdate{ExpressAllowed: &yes}); err != nil || !got.ExpressAllowed {
			t.Errorf("Update turning it on = %+v, %v", got, err)
		}
		if _, _, err := repo.Revoke(ctx, tid, off.ID, time.Time{}); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Update(ctx, tid, off.ID, APITokenUpdate{ExpressAllowed: &no}); !errors.Is(err, ErrConflict) {
			t.Errorf("Update of a revoked token: %v", err)
		}
	})
}

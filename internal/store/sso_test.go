package store_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Issuers and client IDs of the single sign-on tests.
const (
	ssoIssuer  = "https://login.example.com/11111111-2222-3333-4444-555555555555/v2.0"
	ssoIssuer2 = "https://idp.example.org/realms/entity"
	ssoApp     = "7f3c9a10-0000-4000-8000-00000000c0de"
	ssoApp2    = "app-two"
)

// newSecretKey stores a wrapped secret (purpose secret) for tid.
func newSecretKey(t *testing.T, db *store.DB, tid tenant.ID) string {
	t.Helper()
	k := newWrappedKey(mk1, "client-secret")
	k.Purpose = store.KeyPurposeSecret
	return mustCreateKey(t, db, tid, k).ID
}

// ssoConfig returns a configuration of issuer and client app routing
// domains, with the client secret keyID ("" keeps the stored one).
func ssoConfig(enabled bool, issuer, app, keyID string, domains ...string) store.TenantSSO {
	return store.TenantSSO{
		Enabled: enabled, Issuer: issuer, ClientID: app, ClientSecretKeyID: keyID, EmailDomains: domains,
		RequireMFA: true, UpdatedBy: "adm_01JAAAAAAAAAAAAAAAAAAAAAAA",
	}
}

// keyExists reports whether the wrapped key wkID of tid still exists.
func keyExists(t *testing.T, db *store.DB, tid tenant.ID, wkID string) bool {
	t.Helper()
	_, err := db.WrappedKeys().Get(context.Background(), tid, wkID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func TestSSOSettings(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.SSOSettings()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		if _, err := repo.Get(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get(none) = %v", err)
		}
		// Enabled without secret is refused; disabled without secret is a
		// valid draft.
		if _, _, err := repo.Put(ctx, a.ID, ssoConfig(true, ssoIssuer, ssoApp, "", "entity-a.example.com")); !errors.Is(err, store.ErrSSOSecretRequired) ||
			!errors.Is(err, store.ErrInvalid) {
			t.Fatalf("Put(enabled, no secret) = %v", err)
		}
		before, after, err := repo.Put(ctx, a.ID, ssoConfig(false, ssoIssuer, ssoApp, "", "Entity-A.Example.com.", "bücher.example"))
		if err != nil {
			t.Fatalf("Put(draft) = %v", err)
		}
		if before.TenantID != "" || after.TenantID != a.ID || !slices.Equal(after.EmailDomains, []string{"entity-a.example.com", "xn--bcher-kva.example"}) ||
			after.HasClientSecret() || !after.CreatedAt.Equal(msNow) || !after.UpdatedAt.Equal(msNow) {
			t.Fatalf("Put(draft) = %+v, %+v", before, after)
		}

		// Enabling with a secret of the tenant.
		k1 := newSecretKey(t, db, a.ID)
		cfg := ssoConfig(true, ssoIssuer, ssoApp, k1, "entity-a.example.com")
		cfg.Enforced = true
		before, after, err = repo.Put(ctx, a.ID, cfg)
		if err != nil || before.Enabled || len(before.EmailDomains) != 2 || !after.Enabled || after.ClientSecretKeyID != k1 {
			t.Fatalf("Put(enable) = %+v, %+v, %v", before, after, err)
		}
		got, err := repo.Get(ctx, a.ID)
		if err != nil || got.TenantID != a.ID || !got.Enabled || !got.Enforced || !got.RequireMFA || got.Issuer != ssoIssuer ||
			got.ClientID != ssoApp || got.ClientSecretKeyID != k1 || got.UpdatedBy != cfg.UpdatedBy ||
			!slices.Equal(got.EmailDomains, []string{"entity-a.example.com"}) {
			t.Fatalf("Get = %+v, %v", got, err)
		}

		// Isolation: tenant B never reads A's configuration nor uses A's
		// secret, and cannot take A's domain.
		if _, err := repo.Get(ctx, b.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(B) = %v", err)
		}
		if _, _, err := repo.Put(ctx, b.ID, ssoConfig(true, ssoIssuer, ssoApp, k1, "entity-b.example.com")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Put(B, secret of A) = %v", err)
		}
		kb := newSecretKey(t, db, b.ID)
		_, _, err = repo.Put(ctx, b.ID, ssoConfig(true, ssoIssuer, ssoApp, kb, "entity-b.example.com", "ENTITY-A.example.com"))
		if !errors.Is(err, store.ErrSSODomainConflict) || !errors.Is(err, store.ErrConflict) {
			t.Errorf("Put(B, domain of A) = %v", err)
		}
		if _, err := repo.Get(ctx, b.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(B) after conflict = %v", err)
		}
		if _, _, err := repo.Put(ctx, b.ID, ssoConfig(false, ssoIssuer, ssoApp, kb, "entity-b.example.com")); err != nil {
			t.Fatalf("Put(B) = %v", err)
		}

		// A data key is not a client secret.
		dek := mustCreateKey(t, db, a.ID, newWrappedKey(mk1, "dek")).ID
		if _, _, err := repo.Put(ctx, a.ID, ssoConfig(true, ssoIssuer, ssoApp, dek, "entity-a.example.com")); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Put(dek) = %v", err)
		}

		// Changing the issuer or the client ID needs a new secret.
		for _, c := range []store.TenantSSO{
			ssoConfig(true, ssoIssuer2, ssoApp, "", "entity-a.example.com"),
			ssoConfig(true, ssoIssuer, ssoApp2, "", "entity-a.example.com"),
			ssoConfig(false, ssoIssuer, ssoApp2, k1, "entity-a.example.com"),
		} {
			if _, _, err := repo.Put(ctx, a.ID, c); !errors.Is(err, store.ErrSSOSecretRequired) {
				t.Errorf("Put(%s, %s, kept secret) = %v", c.Issuer, c.ClientID, err)
			}
		}
		// Keeping the secret otherwise.
		keep := ssoConfig(true, ssoIssuer, ssoApp, "", "entity-a.example.com", "a2.example.com")
		keep.RequireMFA = false
		if _, after, err = repo.Put(ctx, a.ID, keep); err != nil || after.ClientSecretKeyID != k1 || after.RequireMFA {
			t.Fatalf("Put(keep) = %+v, %v", after, err)
		}
		// A new secret replaces and erases the old one.
		k2 := newSecretKey(t, db, a.ID)
		before, after, err = repo.Put(ctx, a.ID, ssoConfig(true, ssoIssuer2, ssoApp2, k2, "entity-a.example.com"))
		if err != nil || before.ClientSecretKeyID != k1 || before.Issuer != ssoIssuer || after.ClientSecretKeyID != k2 ||
			!after.CreatedAt.Equal(msNow) {
			t.Fatalf("Put(new secret) = %+v, %+v, %v", before, after, err)
		}
		if keyExists(t, db, a.ID, k1) || !keyExists(t, db, a.ID, k2) {
			t.Error("the replaced secret is not erased, or the new one is")
		}

		// Routing: enabled configurations only, case-insensitive domain.
		r, err := repo.RouteDomain(ctx, "  Entity-A.EXAMPLE.com ")
		if err != nil || r.TenantID != a.ID || r.ClientSecretKeyID != k2 || r.Issuer != ssoIssuer2 ||
			!slices.Equal(r.EmailDomains, []string{"entity-a.example.com"}) {
			t.Errorf("RouteDomain(A) = %+v, %v", r, err)
		}
		for _, d := range []string{"entity-b.example.com", "unknown.example.com", "a2.example.com", "no dot", ""} {
			if _, err := repo.RouteDomain(ctx, d); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("RouteDomain(%q) = %v", d, err)
			}
		}
		if ok, err := repo.AnyEnabled(ctx); err != nil || !ok {
			t.Errorf("AnyEnabled = %v, %v", ok, err)
		}

		// Session scope of an admin attached to both tenants.
		adm := newDelegated(t, db, "both", a.ID, b.ID)
		bound, err := repo.ForAdmin(ctx, adm.ID)
		if err != nil || len(bound) != 2 || bound[0].TenantID > bound[1].TenantID {
			t.Fatalf("ForAdmin = %+v, %v", bound, err)
		}
		for _, s := range bound {
			if s.EmailDomains != nil {
				t.Errorf("ForAdmin(%s) domains = %v", s.TenantID, s.EmailDomains)
			}
			if want := s.TenantID == a.ID; s.Admits(ssoIssuer2, ssoApp2, true) != want {
				t.Errorf("ForAdmin(%s).Admits = %v", s.TenantID, !want)
			}
		}
		if bound, err := repo.ForAdmin(ctx, "adm_unknown"); err != nil || len(bound) != 0 {
			t.Errorf("ForAdmin(unknown) = %v, %v", bound, err)
		}

		// Disabling stops the routing.
		if _, _, err := repo.Put(ctx, a.ID, ssoConfig(false, ssoIssuer2, ssoApp2, "", "entity-a.example.com")); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.RouteDomain(ctx, "entity-a.example.com"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RouteDomain(disabled) = %v", err)
		}
		if ok, err := repo.AnyEnabled(ctx); err != nil || ok {
			t.Errorf("AnyEnabled(none) = %v, %v", ok, err)
		}

		// Deleting erases the secret and frees the domains.
		old, err := repo.Delete(ctx, a.ID)
		if err != nil || old.ClientSecretKeyID != k2 || old.TenantID != a.ID {
			t.Fatalf("Delete = %+v, %v", old, err)
		}
		if keyExists(t, db, a.ID, k2) {
			t.Error("Delete kept the client secret")
		}
		if _, err := repo.Get(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(deleted) = %v", err)
		}
		if _, err := repo.Delete(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete(again) = %v", err)
		}
		if _, _, err := repo.Put(ctx, b.ID, ssoConfig(false, ssoIssuer, ssoApp, "", "entity-b.example.com", "entity-a.example.com")); err != nil {
			t.Errorf("Put(B, freed domain) = %v", err)
		}
		// A configuration without secret can be deleted.
		if _, _, err := repo.Put(ctx, a.ID, ssoConfig(false, ssoIssuer, ssoApp, "", "a3.example.com")); err != nil {
			t.Fatal(err)
		}
		if old, err := repo.Delete(ctx, a.ID); err != nil || old.HasClientSecret() {
			t.Errorf("Delete(no secret) = %+v, %v", old, err)
		}

		// Tenant deletion: the keys are destroyed first, then the
		// configuration and its domains go by cascade.
		ids, err := db.WrappedKeys().ListIDs(ctx, b.ID, "", 0)
		if err != nil || !slices.Contains(ids, kb) {
			t.Fatalf("ListIDs(B) = %v, %v", ids, err)
		}
		for _, k := range ids {
			if err := db.WrappedKeys().Delete(ctx, b.ID, k); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := repo.Get(ctx, b.ID); err != nil || got.HasClientSecret() {
			t.Errorf("Get(B, key erased) = %+v, %v", got, err)
		}
		if err := db.Tenants().Delete(ctx, b.ID); err != nil {
			t.Fatalf("Tenants.Delete = %v", err)
		}
		if bound, err := repo.ForAdmin(ctx, adm.ID); err != nil || len(bound) != 0 {
			t.Errorf("ForAdmin after tenant deletion = %+v, %v", bound, err)
		}
		if _, _, err := repo.Put(ctx, a.ID, ssoConfig(false, ssoIssuer, ssoApp, "", "entity-b.example.com")); err != nil {
			t.Errorf("Put(domain of the deleted tenant) = %v", err)
		}
	})
}

func TestSSOSettingsInTransaction(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.SSOSettings()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		sa, err := db.Scoped(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		// The secret, the configuration and the domains commit together.
		var keyID string
		err = sa.Tx(ctx, func(tx *store.ScopedTx) error {
			k := newWrappedKey(mk1, "secret")
			k.Purpose = store.KeyPurposeSecret
			if err := db.WrappedKeys().CreateTx(ctx, tx, k); err != nil {
				return err
			}
			keyID = k.ID
			if _, _, err := repo.PutTx(ctx, tx, ssoConfig(true, ssoIssuer, ssoApp, k.ID, "entity-a.example.com")); err != nil {
				return err
			}
			got, err := repo.GetTx(ctx, tx)
			if err != nil || got.ClientSecretKeyID != k.ID {
				t.Errorf("GetTx = %+v, %v", got, err)
			}
			if _, _, err := repo.PutTx(ctx, tx, ssoConfig(true, "http://x.example.com", ssoApp, "", "a.example.com")); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("PutTx(invalid) = %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		errAbort := errors.New("abort")
		err = sa.Tx(ctx, func(tx *store.ScopedTx) error {
			old, err := repo.DeleteTx(ctx, tx)
			if err != nil || old.ClientSecretKeyID != keyID {
				t.Errorf("DeleteTx = %+v, %v", old, err)
			}
			return errAbort
		})
		if !errors.Is(err, errAbort) {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || got.ClientSecretKeyID != keyID || !keyExists(t, db, a.ID, keyID) {
			t.Errorf("Get(after rollback) = %+v, %v", got, err)
		}
		err = sa.Tx(ctx, func(tx *store.ScopedTx) error {
			if _, err := repo.DeleteTx(ctx, tx); err != nil {
				return err
			}
			if _, err := repo.DeleteTx(ctx, tx); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("DeleteTx(again) = %v", err)
			}
			if _, err := repo.GetTx(ctx, tx); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("GetTx(deleted) = %v", err)
			}
			return nil
		})
		if err != nil || keyExists(t, db, a.ID, keyID) {
			t.Errorf("DeleteTx committed = %v", err)
		}
	})
}

func TestSSOSettingsValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t, storetest.SQLite(t))
	repo := db.SSOSettings()
	a := newTenant(t, db, "transfer.entity-a.example.com")
	many := make([]string, store.MaxSSODomains+1)
	for i := range many {
		many[i] = strings.Repeat("d", i+1) + ".example.com"
	}
	mod := func(f func(*store.TenantSSO)) store.TenantSSO {
		c := ssoConfig(false, ssoIssuer, ssoApp, "", "entity-a.example.com")
		f(&c)
		return c
	}
	for name, c := range map[string]store.TenantSSO{
		"http issuer":       mod(func(c *store.TenantSSO) { c.Issuer = "http://login.example.com/x" }),
		"upper scheme":      mod(func(c *store.TenantSSO) { c.Issuer = "HTTPS://login.example.com/x" }),
		"short issuer":      mod(func(c *store.TenantSSO) { c.Issuer = "https://" }),
		"long issuer":       mod(func(c *store.TenantSSO) { c.Issuer = "https://x.example.com/" + strings.Repeat("a", 500) }),
		"issuer space":      mod(func(c *store.TenantSSO) { c.Issuer = "https://x.example.com/a b" }),
		"issuer query":      mod(func(c *store.TenantSSO) { c.Issuer = "https://x.example.com/a?b=c" }),
		"issuer fragment":   mod(func(c *store.TenantSSO) { c.Issuer = "https://x.example.com/a#b" }),
		"issuer userinfo":   mod(func(c *store.TenantSSO) { c.Issuer = "https://u:p@x.example.com/a" }),
		"issuer no host":    mod(func(c *store.TenantSSO) { c.Issuer = "https:///tenant/v2.0" }),
		"issuer bad escape": mod(func(c *store.TenantSSO) { c.Issuer = "https://x.example.com/%zz" }),
		"empty client id":   mod(func(c *store.TenantSSO) { c.ClientID = "" }),
		"client id space":   mod(func(c *store.TenantSSO) { c.ClientID = "a b" }),
		"long client id":    mod(func(c *store.TenantSSO) { c.ClientID = strings.Repeat("a", store.MaxSSOClientIDLen+1) }),
		"bad secret id":     mod(func(c *store.TenantSSO) { c.ClientSecretKeyID = "wk_bogus" }),
		"long updated by":   mod(func(c *store.TenantSSO) { c.UpdatedBy = strings.Repeat("a", 65) }),
		"updated by line":   mod(func(c *store.TenantSSO) { c.UpdatedBy = "a\nb" }),
		"no domain":         mod(func(c *store.TenantSSO) { c.EmailDomains = nil }),
		"too many domains":  mod(func(c *store.TenantSSO) { c.EmailDomains = many }),
		"duplicate domains": mod(func(c *store.TenantSSO) { c.EmailDomains = []string{"a.example.com", "A.example.com."} }),
		"single label":      mod(func(c *store.TenantSSO) { c.EmailDomains = []string{"localhost"} }),
		"domain with at":    mod(func(c *store.TenantSSO) { c.EmailDomains = []string{"u@a.example.com"} }),
		"ip domain":         mod(func(c *store.TenantSSO) { c.EmailDomains = []string{"[::1]"} }),
	} {
		if _, _, err := repo.Put(ctx, a.ID, c); !errors.Is(err, store.ErrInvalid) || errors.Is(err, store.ErrSSOIssuerNotAllowed) {
			t.Errorf("Put(%s) = %v", name, err)
		}
	}
	for _, iss := range []string{
		"https://login.example.com/common/v2.0",
		"https://login.example.com/Organizations/v2.0",
		"https://login.example.com/consumers",
		"https://login.example.com/{tenantid}/v2.0",
	} {
		if _, _, err := repo.Put(ctx, a.ID, mod(func(c *store.TenantSSO) { c.Issuer = iss })); !errors.Is(err, store.ErrSSOIssuerNotAllowed) {
			t.Errorf("Put(%s) = %v", iss, err)
		}
	}
	if err := store.ValidateSSOIssuer("https://idp.example.org/realms/common"); err != nil {
		t.Errorf("ValidateSSOIssuer(realm named common) = %v", err)
	}
	if _, _, err := repo.Put(ctx, "bogus", mod(func(*store.TenantSSO) {})); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("Put(bad tenant) = %v", err)
	}
	if _, err := repo.Get(ctx, "bogus"); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("Get(bad tenant) = %v", err)
	}
	if _, err := repo.Delete(ctx, "bogus"); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("Delete(bad tenant) = %v", err)
	}
	// An unknown tenant has no configuration to write.
	if _, _, err := repo.Put(ctx, tenant.ID(id.New(id.Tenant)), mod(func(*store.TenantSSO) {})); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Put(unknown tenant) = %v", err)
	}
}

func TestTenantSSOAdmits(t *testing.T) {
	t.Parallel()
	c := store.TenantSSO{Enabled: true, Issuer: ssoIssuer, ClientID: ssoApp, ClientSecretKeyID: "wk_x", RequireMFA: true}
	for _, tc := range []struct {
		name string
		c    func(store.TenantSSO) store.TenantSSO
		iss  string
		app  string
		mfa  bool
		want bool
	}{
		{"match", func(c store.TenantSSO) store.TenantSSO { return c }, ssoIssuer, ssoApp, true, true},
		{"mfa missing", func(c store.TenantSSO) store.TenantSSO { return c }, ssoIssuer, ssoApp, false, false},
		{"mfa not required", func(c store.TenantSSO) store.TenantSSO { c.RequireMFA = false; return c }, ssoIssuer, ssoApp, false, true},
		{"other issuer", func(c store.TenantSSO) store.TenantSSO { return c }, ssoIssuer2, ssoApp, true, false},
		{"other client", func(c store.TenantSSO) store.TenantSSO { return c }, ssoIssuer, ssoApp2, true, false},
		{"disabled", func(c store.TenantSSO) store.TenantSSO { c.Enabled = false; return c }, ssoIssuer, ssoApp, true, false},
		{"no secret", func(c store.TenantSSO) store.TenantSSO { c.ClientSecretKeyID = ""; return c }, ssoIssuer, ssoApp, true, false},
	} {
		if got := tc.c(c).Admits(tc.iss, tc.app, tc.mfa); got != tc.want {
			t.Errorf("%s: Admits = %v", tc.name, got)
		}
	}
}

func TestAdminIdentities(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AdminIdentities()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		d1 := newDelegated(t, db, "del1", a.ID)
		d2 := newDelegated(t, db, "del2", a.ID, b.ID)
		d3 := newDelegated(t, db, "del3", b.ID)
		root := newSuperAdmin(t, db, "root")

		link := func(adminID, issuer, app, subject string) store.AdminIdentity {
			t.Helper()
			got, err := repo.Link(ctx, store.AdminIdentity{AdminID: adminID, Issuer: issuer, ClientID: app, Subject: subject})
			if err != nil {
				t.Fatalf("Link(%s, %s) = %v", adminID, subject, err)
			}
			return got
		}
		i1 := link(d1.ID, ssoIssuer, ssoApp, "sub-1")
		if !strings.HasPrefix(i1.ID, "aid_") || i1.AdminID != d1.ID || !i1.CreatedAt.Equal(msNow) || !i1.LastUsedAt.IsZero() {
			t.Errorf("Link = %+v", i1)
		}
		if got, err := repo.Find(ctx, ssoIssuer, ssoApp, "sub-1"); err != nil || got != i1 {
			t.Errorf("Find = %+v, %v", got, err)
		}
		if got, err := repo.ForAdmin(ctx, d1.ID, ssoIssuer, ssoApp); err != nil || got != i1 {
			t.Errorf("ForAdmin = %+v, %v", got, err)
		}
		for _, c := range [][3]string{{ssoIssuer, ssoApp2, "sub-1"}, {ssoIssuer2, ssoApp, "sub-1"}, {"x", ssoApp, "s"}, {ssoIssuer, "", "s"}, {ssoIssuer, ssoApp, ""}} {
			if _, err := repo.Find(ctx, c[0], c[1], c[2]); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Find(%v) = %v", c, err)
			}
		}
		if _, err := repo.ForAdmin(ctx, d1.ID, "x", ssoApp); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ForAdmin(malformed) = %v", err)
		}
		if _, err := repo.ForAdmin(ctx, d2.ID, ssoIssuer, ssoApp); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ForAdmin(none) = %v", err)
		}

		// Uniqueness: a subject is pinned once, an account has one identity
		// per (issuer, client ID).
		for name, ai := range map[string]store.AdminIdentity{
			"subject pinned twice":     {AdminID: d2.ID, Issuer: ssoIssuer, ClientID: ssoApp, Subject: "sub-1"},
			"second identity per pair": {AdminID: d1.ID, Issuer: ssoIssuer, ClientID: ssoApp, Subject: "sub-other"},
		} {
			if _, err := repo.Link(ctx, ai); !errors.Is(err, store.ErrIdentityConflict) || !errors.Is(err, store.ErrConflict) {
				t.Errorf("Link(%s) = %v", name, err)
			}
		}
		i1b := link(d1.ID, ssoIssuer, ssoApp2, "sub-1")
		// A super admin never gets an identity; malformed or unknown
		// accounts are refused.
		for name, c := range map[string]struct {
			ai   store.AdminIdentity
			want error
		}{
			"super admin":    {store.AdminIdentity{AdminID: root.ID, Issuer: ssoIssuer, ClientID: ssoApp, Subject: "root"}, store.ErrInvalid},
			"unknown admin":  {store.AdminIdentity{AdminID: id.New(id.Admin), Issuer: ssoIssuer, ClientID: ssoApp, Subject: "x"}, store.ErrNotFound},
			"bad admin":      {store.AdminIdentity{AdminID: "adm_x", Issuer: ssoIssuer, ClientID: ssoApp, Subject: "x"}, store.ErrInvalid},
			"bad issuer":     {store.AdminIdentity{AdminID: d3.ID, Issuer: "https:", ClientID: ssoApp, Subject: "x"}, store.ErrInvalid},
			"no subject":     {store.AdminIdentity{AdminID: d3.ID, Issuer: ssoIssuer, ClientID: ssoApp}, store.ErrInvalid},
			"long subject":   {store.AdminIdentity{AdminID: d3.ID, Issuer: ssoIssuer, ClientID: ssoApp, Subject: strings.Repeat("s", 256)}, store.ErrInvalid},
			"subject spaces": {store.AdminIdentity{AdminID: d3.ID, Issuer: ssoIssuer, ClientID: ssoApp, Subject: "a b"}, store.ErrInvalid},
		} {
			if _, err := repo.Link(ctx, c.ai); !errors.Is(err, c.want) {
				t.Errorf("Link(%s) = %v, want %v", name, err, c.want)
			}
		}

		at := msNow.Add(time.Hour)
		if err := repo.Touch(ctx, i1.ID, at); err != nil {
			t.Fatal(err)
		}
		if got, _ := repo.Find(ctx, ssoIssuer, ssoApp, "sub-1"); !got.LastUsedAt.Equal(at) {
			t.Errorf("LastUsedAt = %v", got.LastUsedAt)
		}
		if err := repo.Touch(ctx, "aid_unknown", time.Time{}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Touch(unknown) = %v", err)
		}
		if got, err := repo.List(ctx, d1.ID); err != nil || len(got) != 2 || got[0].ID > got[1].ID ||
			!slices.ContainsFunc(got, func(x store.AdminIdentity) bool { return x.ID == i1b.ID }) {
			t.Errorf("List = %+v, %v", got, err)
		}
		if got, err := repo.List(ctx, d3.ID); err != nil || len(got) != 0 {
			t.Errorf("List(none) = %+v, %v", got, err)
		}

		// Unpinning is limited to the account's own identities.
		if _, err := repo.Delete(ctx, d2.ID, i1b.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete(other account) = %v", err)
		}
		if got, err := repo.Delete(ctx, d1.ID, i1b.ID); err != nil || got.ID != i1b.ID {
			t.Errorf("Delete = %+v, %v", got, err)
		}
		err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			if _, err := repo.DeleteTx(ctx, tx, d1.ID, i1b.ID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("DeleteTx(again) = %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// A change of the pair of tenant A unpins its accounts, except
		// those still trusting the pair through another tenant.
		kb := newSecretKey(t, db, b.ID)
		if _, _, err := db.SSOSettings().Put(ctx, b.ID, ssoConfig(false, ssoIssuer, ssoApp, kb, "entity-b.example.com")); err != nil {
			t.Fatal(err)
		}
		i2 := link(d2.ID, ssoIssuer, ssoApp, "sub-2")
		i3 := link(d3.ID, ssoIssuer, ssoApp, "sub-3")
		i1c := link(d1.ID, ssoIssuer, ssoApp2, "sub-1")
		gone, err := repo.DeleteForTenantClient(ctx, a.ID, ssoIssuer, ssoApp)
		if err != nil || len(gone) != 1 || gone[0].ID != i1.ID {
			t.Fatalf("DeleteForTenantClient = %+v, %v", gone, err)
		}
		for _, kept := range []store.AdminIdentity{i2, i3, i1c} {
			if _, err := repo.Find(ctx, kept.Issuer, kept.ClientID, kept.Subject); err != nil {
				t.Errorf("identity %s of %s not kept: %v", kept.Subject, kept.AdminID, err)
			}
		}
		// Once B uses another pair, d2's identity goes too; d3 (B only)
		// is never touched by a change of A.
		kb2 := newSecretKey(t, db, b.ID)
		if _, _, err := db.SSOSettings().Put(ctx, b.ID, ssoConfig(false, ssoIssuer2, ssoApp, kb2, "entity-b.example.com")); err != nil {
			t.Fatal(err)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			gone, err := repo.DeleteForTenantClientTx(ctx, tx, a.ID, ssoIssuer, ssoApp)
			if err != nil || len(gone) != 1 || gone[0].ID != i2.ID {
				t.Errorf("DeleteForTenantClientTx = %+v, %v", gone, err)
			}
			if _, err := repo.DeleteForTenantClientTx(ctx, tx, "bogus", ssoIssuer, ssoApp); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("DeleteForTenantClientTx(bad tenant) = %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Find(ctx, ssoIssuer, ssoApp, "sub-3"); err != nil {
			t.Errorf("identity of B's account = %v", err)
		}

		// Inside a transaction.
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			got, err := repo.LinkTx(ctx, tx, store.AdminIdentity{AdminID: d2.ID, Issuer: ssoIssuer2, ClientID: ssoApp, Subject: "sub-2"})
			if err != nil {
				return err
			}
			if _, err := repo.LinkTx(ctx, tx, store.AdminIdentity{AdminID: root.ID, Issuer: ssoIssuer2, ClientID: ssoApp, Subject: "r"}); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("LinkTx(super admin) = %v", err)
			}
			list, err := repo.ListTx(ctx, tx, d2.ID)
			if err != nil || len(list) != 1 || list[0].ID != got.ID {
				t.Errorf("ListTx = %+v, %v", list, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestAdminPromotionUnpinsIdentities(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		d := newDelegated(t, db, "promoted", a.ID)
		other := newDelegated(t, db, "other", a.ID)
		if err := db.Admins().SetPassword(ctx, d.ID, testPHC); err != nil {
			t.Fatal(err)
		}
		enableTOTP(t, db, d.ID)
		for _, ai := range []store.AdminIdentity{
			{AdminID: d.ID, Issuer: ssoIssuer, ClientID: ssoApp, Subject: "s1"},
			{AdminID: d.ID, Issuer: ssoIssuer, ClientID: ssoApp2, Subject: "s1"},
			{AdminID: other.ID, Issuer: ssoIssuer, ClientID: ssoApp, Subject: "s2"},
		} {
			if _, err := db.AdminIdentities().Link(ctx, ai); err != nil {
				t.Fatal(err)
			}
		}
		// A change that is not a promotion keeps the identities.
		lang := "en"
		if _, err := db.Admins().Update(ctx, d.ID, store.AdminUpdate{Language: &lang}); err != nil {
			t.Fatal(err)
		}
		if got, _ := db.AdminIdentities().List(ctx, d.ID); len(got) != 2 {
			t.Fatalf("identities after update = %d", len(got))
		}
		super := store.RoleSuperAdmin
		err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			listed, err := db.AdminIdentities().ListTx(ctx, tx, d.ID)
			if err != nil || len(listed) != 2 {
				t.Errorf("ListTx = %+v, %v", listed, err)
			}
			_, after, err := db.Admins().UpdateTx(ctx, tx, d.ID, store.AdminUpdate{Role: &super})
			if err != nil || after.Role != store.RoleSuperAdmin {
				t.Errorf("UpdateTx(promote) = %+v, %v", after, err)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := db.AdminIdentities().List(ctx, d.ID); err != nil || len(got) != 0 {
			t.Errorf("identities after promotion = %+v, %v", got, err)
		}
		if got, err := db.AdminIdentities().List(ctx, other.ID); err != nil || len(got) != 1 {
			t.Errorf("identities of another account = %+v, %v", got, err)
		}
		// Deleting the account removes its identities (cascade).
		if _, err := db.AdminIdentities().Link(ctx, store.AdminIdentity{AdminID: other.ID, Issuer: ssoIssuer2, ClientID: ssoApp, Subject: "s3"}); err != nil {
			t.Fatal(err)
		}
		if err := db.Admins().Delete(ctx, other.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.AdminIdentities().Find(ctx, ssoIssuer2, ssoApp, "s3"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("identity of a deleted account = %v", err)
		}
	})
}

func TestAdminsSSOOnly(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		admins := db.Admins()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		for name, adm := range map[string]store.Admin{
			"with a password": {
				Username: "pwd", Email: "p@example.com", Role: store.RoleAuditor, TenantIDs: []tenant.ID{a.ID},
				PasswordHash: testPHC, SSOOnly: true,
			},
			"super admin": {Username: "sup", Email: "s@example.com", Role: store.RoleSuperAdmin, SSOOnly: true},
		} {
			if _, err := admins.Create(ctx, adm); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Create(sso only, %s) = %v", name, err)
			}
		}
		created, err := admins.Create(ctx, store.Admin{
			Username: "sso", Email: "sso@example.com", Role: store.RoleAuditor, TenantIDs: []tenant.ID{a.ID}, SSOOnly: true,
		})
		if err != nil || !created.SSOOnly || created.PasswordHash != "" {
			t.Fatalf("Create(sso only) = %+v, %v", created, err)
		}
		got, err := admins.Get(ctx, created.ID)
		if err != nil || !got.SSOOnly {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		if page, err := admins.List(ctx, store.AdminListOptions{}); err != nil || len(page.Items) != 1 || !page.Items[0].SSOOnly {
			t.Errorf("List = %+v, %v", page, err)
		}
		// Never promoted: it has no local password.
		super := store.RoleSuperAdmin
		if _, err := admins.Update(ctx, created.ID, store.AdminUpdate{Role: &super}); !errors.Is(err, store.ErrPromotionRefused) {
			t.Errorf("Update(promote sso only) = %v", err)
		}
		// Other updates keep the flag.
		lang := "en"
		if upd, err := admins.Update(ctx, created.ID, store.AdminUpdate{Language: &lang}); err != nil || !upd.SSOOnly {
			t.Errorf("Update(language) = %+v, %v", upd, err)
		}
		// A credentials reset keeps it; an activation clears it.
		if err := admins.SetPassword(ctx, created.ID, ""); err != nil {
			t.Fatal(err)
		}
		if got, _ := admins.Get(ctx, created.ID); !got.SSOOnly {
			t.Error("reset cleared sso only")
		}
		if err := admins.SetPassword(ctx, created.ID, testPHC); err != nil {
			t.Fatalf("SetPassword(sso only) = %v", err)
		}
		if got, _ := admins.Get(ctx, created.ID); got.SSOOnly || got.PasswordHash != testPHC {
			t.Errorf("after activation = %+v", got)
		}
		// A reset of a regular account never makes it single sign-on only.
		if err := admins.SetPassword(ctx, created.ID, ""); err != nil {
			t.Fatal(err)
		}
		if got, _ := admins.Get(ctx, created.ID); got.SSOOnly {
			t.Error("reset set sso only")
		}
	})
}

func TestAdminSessionsSSO(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AdminSessions()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		d1 := newDelegated(t, db, "del1", a.ID)
		d3 := newDelegated(t, db, "del3", b.ID)
		const idle = 30 * time.Minute

		oidc := func(adminID, token, issuer, app string, mfa bool) store.AdminSession {
			s := newAdminSession(adminID, token)
			s.AuthMethod, s.SSOIssuer, s.SSOClientID, s.SSOMFA = store.AuthOIDC, issuer, app, mfa
			return s
		}
		for _, s := range []store.AdminSession{
			oidc(d1.ID, "t1", ssoIssuer, ssoApp, true),
			oidc(d1.ID, "t2", ssoIssuer, ssoApp2, false),
			newAdminSession(d1.ID, "t3"),
			oidc(d3.ID, "t4", ssoIssuer, ssoApp, true),
		} {
			if err := repo.Create(ctx, s); err != nil {
				t.Fatalf("Create = %v", err)
			}
		}
		got, err := repo.GetByTokenHash(ctx, tokenHash("t1"), msNow, idle)
		if err != nil || got.AuthMethod != store.AuthOIDC || got.SSOIssuer != ssoIssuer || got.SSOClientID != ssoApp || !got.SSOMFA {
			t.Errorf("GetByTokenHash(oidc) = %+v, %v", got, err)
		}
		got, err = repo.GetByTokenHash(ctx, tokenHash("t2"), msNow, idle)
		if err != nil || got.SSOMFA || got.SSOClientID != ssoApp2 {
			t.Errorf("GetByTokenHash(oidc, no mfa) = %+v, %v", got, err)
		}
		got, err = repo.GetByTokenHash(ctx, tokenHash("t3"), msNow, idle)
		if err != nil || got.AuthMethod != store.AuthPassword || got.SSOIssuer != "" || got.SSOClientID != "" || got.SSOMFA {
			t.Errorf("GetByTokenHash(password) = %+v, %v", got, err)
		}

		// Inconsistent sessions are refused before reaching the database.
		pending := oidc(d1.ID, "x1", ssoIssuer, ssoApp, true)
		pending.State, pending.StateExpiresAt = store.SessionTOTPRequired, msNow.Add(time.Minute)
		withIssuer := newAdminSession(d1.ID, "x2")
		withIssuer.SSOIssuer = ssoIssuer
		withMFA := newAdminSession(d1.ID, "x3")
		withMFA.AuthMethod, withMFA.SSOMFA = store.AuthPassword, true
		unknown := newAdminSession(d1.ID, "x4")
		unknown.AuthMethod = "saml"
		for name, s := range map[string]store.AdminSession{
			"oidc pending":        pending,
			"oidc no issuer":      oidc(d1.ID, "x5", "", ssoApp, true),
			"oidc no client":      oidc(d1.ID, "x6", ssoIssuer, "", true),
			"password and issuer": withIssuer,
			"password and mfa":    withMFA,
			"unknown method":      unknown,
		} {
			if err := repo.Create(ctx, s); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Create(%s) = %v", name, err)
			}
		}

		// Revocation: oidc sessions of the pair, of A's accounts, only.
		n, err := repo.DeleteSSOForTenant(ctx, a.ID, ssoIssuer, ssoApp)
		if err != nil || n != 1 {
			t.Fatalf("DeleteSSOForTenant = %d, %v", n, err)
		}
		for token, alive := range map[string]bool{"t1": false, "t2": true, "t3": true, "t4": true} {
			_, err := repo.GetByTokenHash(ctx, tokenHash(token), msNow, idle)
			if (err == nil) != alive {
				t.Errorf("session %s alive = %v (%v)", token, err == nil, err)
			}
		}
		if _, err := repo.DeleteSSOForTenant(ctx, "bogus", ssoIssuer, ssoApp); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("DeleteSSOForTenant(bad tenant) = %v", err)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			n, err := repo.DeleteSSOForTenantTx(ctx, tx, b.ID, ssoIssuer, ssoApp)
			if err != nil || n != 1 {
				t.Errorf("DeleteSSOForTenantTx = %d, %v", n, err)
			}
			if _, err := repo.DeleteSSOForTenantTx(ctx, tx, "", ssoIssuer, ssoApp); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("DeleteSSOForTenantTx(bad tenant) = %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.GetByTokenHash(ctx, tokenHash("t4"), msNow, idle); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("session t4 = %v", err)
		}

		// Revocation of one account: its oidc sessions of the pair only.
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			if n, err := repo.DeleteSSOForAdminTx(ctx, tx, d3.ID, ssoIssuer, ssoApp2); err != nil || n != 0 {
				t.Errorf("DeleteSSOForAdminTx(other account) = %d, %v", n, err)
			}
			if n, err := repo.DeleteSSOForAdminTx(ctx, tx, d1.ID, ssoIssuer, ssoApp2); err != nil || n != 1 {
				t.Errorf("DeleteSSOForAdminTx = %d, %v", n, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for token, alive := range map[string]bool{"t2": false, "t3": true} {
			_, err := repo.GetByTokenHash(ctx, tokenHash(token), msNow, idle)
			if (err == nil) != alive {
				t.Errorf("session %s alive = %v (%v)", token, err == nil, err)
			}
		}
	})
}

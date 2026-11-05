package isolation_test

import (
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Single sign-on configurations of the fixtures (T-287, T-288, T-296).
const (
	ssoIssuerA = "https://idp-a.example.com/isolation-a/v2.0"
	ssoIssuerB = "https://idp-b.example.org/isolation-b/v2.0"
	ssoDomainA = "entity-a.example.com"
	ssoDomainB = "entity-b.example.com"
)

// seedSSO stores a disabled configuration (no secret) for tid.
func seedSSO(t *testing.T, db *store.DB, tid tenant.ID, issuer, client, domain string) {
	t.Helper()
	if _, _, err := db.SSOSettings().Put(t.Context(), tid, store.TenantSSO{
		Issuer: issuer, ClientID: client, EmailDomains: []string{domain}, RequireMFA: true,
	}); err != nil {
		t.Fatalf("SSOSettings.Put: %v", err)
	}
}

// TestSSOSettingsIsolation checks, on both engines, that a tenant reads,
// replaces and deletes its own configuration only, and that an e-mail
// domain of tenant B cannot be claimed by tenant A (the instance-wide
// uniqueness holds although tenant A cannot see B's rows).
func TestSSOSettingsIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a, b := newTenant(t, db, fqdnA), newTenant(t, db, fqdnB)
		repo := db.SSOSettings()
		if _, err := repo.Get(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get before any configuration = %v, want ErrNotFound", err)
		}
		seedSSO(t, db, a.ID, ssoIssuerA, "client-a", ssoDomainA)
		seedSSO(t, db, b.ID, ssoIssuerB, "client-b", ssoDomainB)

		gotA, err := repo.Get(ctx, a.ID)
		if err != nil || gotA.Issuer != ssoIssuerA || gotA.TenantID != a.ID || !slices.Equal(gotA.EmailDomains, []string{ssoDomainA}) {
			t.Errorf("Get(A) = %+v, %v", gotA, err)
		}
		gotB, err := repo.Get(ctx, b.ID)
		if err != nil || gotB.Issuer != ssoIssuerB || !slices.Equal(gotB.EmailDomains, []string{ssoDomainB}) {
			t.Errorf("Get(B) = %+v, %v", gotB, err)
		}

		// A claims B's domain: refused as a conflict, nothing changes.
		_, _, err = repo.Put(ctx, a.ID, store.TenantSSO{
			Issuer: ssoIssuerA, ClientID: "client-a", EmailDomains: []string{ssoDomainA, ssoDomainB},
		})
		if !errors.Is(err, store.ErrSSODomainConflict) {
			t.Errorf("Put(A, B's domain) = %v, want ErrSSODomainConflict", err)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || !slices.Equal(got.EmailDomains, []string{ssoDomainA}) {
			t.Errorf("Get(A) after the refused claim = %+v, %v", got, err)
		}
		if got, err := repo.Get(ctx, b.ID); err != nil || !slices.Equal(got.EmailDomains, []string{ssoDomainB}) {
			t.Errorf("Get(B) after the refused claim = %+v, %v", got, err)
		}

		// A replaces its own configuration: B's is untouched.
		if _, _, err := repo.Put(ctx, a.ID, store.TenantSSO{
			Issuer: ssoIssuerA, ClientID: "client-a", EmailDomains: []string{"entity-a.example.net"}, Enforced: true,
		}); err != nil {
			t.Fatalf("Put(A) = %v", err)
		}
		if got, _ := repo.Get(ctx, b.ID); got.Enforced || got.Issuer != ssoIssuerB {
			t.Errorf("Get(B) after Put(A) = %+v", got)
		}
		// A's old domain is free again; deleting A's configuration frees its
		// domains and leaves B's.
		if _, err := repo.Delete(ctx, a.ID); err != nil {
			t.Fatalf("Delete(A) = %v", err)
		}
		if _, err := repo.Get(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(A) after the deletion = %v", err)
		}
		if got, err := repo.Get(ctx, b.ID); err != nil || got.Issuer != ssoIssuerB || !slices.Equal(got.EmailDomains, []string{ssoDomainB}) {
			t.Errorf("Get(B) after Delete(A) = %+v, %v", got, err)
		}
		if _, err := repo.Delete(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second Delete(A) = %v, want ErrNotFound", err)
		}
	})
}

// TestRLSBlocksCrossTenantSSO bypasses the application layer on PostgreSQL:
// a raw transaction scoped to A runs statements aimed at B's configuration
// and domains; row-level security alone must stop them. Also checks that
// without a tenant setting nothing is visible.
func TestRLSBlocksCrossTenantSSO(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	seedSSO(t, f.db, f.a.ID, ssoIssuerA, "client-a", ssoDomainA)
	seedSSO(t, f.db, f.b.ID, ssoIssuerB, "client-b", ssoDomainB)
	a, b := string(f.a.ID), string(f.b.ID)

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM tenant_sso_settings WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM tenant_sso_settings`, nil, 1},
			{`SELECT count(*) FROM tenant_sso_settings WHERE true OR tenant_id = $1`, []any{b}, 1},
			{`SELECT count(*) FROM sso_email_domains WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM sso_email_domains WHERE domain = $1`, []any{ssoDomainB}, 0},
			{`SELECT count(*) FROM sso_email_domains`, nil, 1},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE tenant_sso_settings SET enabled = true, issuer = 'https://evil.example.net/x' WHERE tenant_id = $1`, []any{b}},
			{`UPDATE sso_email_domains SET tenant_id = $2 WHERE tenant_id = $1`, []any{b, a}},
			{`DELETE FROM sso_email_domains WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM tenant_sso_settings WHERE tenant_id = $1`, []any{b}},
		} {
			if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
				t.Errorf("%s affected %d rows of B", s.stmt, n)
			}
		}
		return nil
	})

	for name, v := range map[string]struct {
		stmt string
		args []any
	}{
		"insert a configuration for B": {`INSERT INTO tenant_sso_settings (tenant_id, enabled, issuer, client_id, created_at, updated_at) VALUES ($1, true, 'https://evil.example.net/x', 'c', 0, 0)`, []any{b}},
		"route a domain to B":          {`INSERT INTO sso_email_domains (domain, tenant_id) VALUES ('evil.example.net', $1)`, []any{b}},
		"move A's configuration to B":  {`UPDATE tenant_sso_settings SET tenant_id = $1`, []any{b}},
		"move A's domain to B":         {`UPDATE sso_email_domains SET tenant_id = $1`, []any{b}},
	} {
		err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, v.stmt, v.args...)
			return err
		})
		assertRLSViolation(t, name, err)
	}

	// No tenant setting, an empty one or a bogus one: nothing is visible.
	empty, bogus := "", "ten_00000000000000000000000000"
	for name, setting := range map[string]*string{"unset": nil, "empty": &empty, "bogus": &bogus} {
		_ = inTenantTx(ctx, t, raw, setting, func(tx *sql.Tx) error {
			for _, table := range []string{"tenant_sso_settings", "sso_email_domains"} {
				if n := countRows(ctx, t, tx, `SELECT count(*) FROM `+table); n != 0 {
					t.Errorf("%s tenant setting sees %d rows of %s, want 0", name, n, table)
				}
			}
			return nil
		})
	}

	// Whatever happened was rolled back: both configurations are intact.
	for tid, issuer := range map[string]string{a: ssoIssuerA, b: ssoIssuerB} {
		got, err := f.db.SSOSettings().Get(ctx, tenant.ID(tid))
		if err != nil || got.Issuer != issuer || got.Enabled {
			t.Errorf("configuration of %s after the raw attacks = %+v, %v", tid, got, err)
		}
	}
}

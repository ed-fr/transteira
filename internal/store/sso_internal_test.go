package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
)

// ssoFixture is an admin fixture whose tenant tid has an enabled single
// sign-on configuration with a client secret, and whose delegated admin
// has a pinned identity.
type ssoFixture struct {
	*adminFixture
	key      string
	identity AdminIdentity
}

// Values of the single sign-on fixtures.
const (
	testSSOIssuer = "https://login.example.com/tenant/v2.0"
	testSSOApp    = "app"
)

// newSSOFixture builds an ssoFixture.
func newSSOFixture(t *testing.T) *ssoFixture {
	t.Helper()
	ctx := context.Background()
	f := &ssoFixture{adminFixture: newAdminFixture(t)}
	f.key = f.newSecret(ctx, t)
	if _, _, err := f.db.SSOSettings().Put(ctx, f.tid, f.config(f.key)); err != nil {
		t.Fatal(err)
	}
	var err error
	f.identity, err = f.db.AdminIdentities().Link(ctx, AdminIdentity{
		AdminID: f.del.ID, Issuer: testSSOIssuer, ClientID: testSSOApp, Subject: "sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// newSecret stores a client secret key of tid.
func (f *ssoFixture) newSecret(ctx context.Context, t *testing.T) string {
	t.Helper()
	k := WrappedKey{ID: id.New(id.WrappedKey), Purpose: KeyPurposeSecret, KeyID: testMK1, Blob: []byte("s")}
	if err := f.db.WrappedKeys().Create(ctx, f.tid, k); err != nil {
		t.Fatal(err)
	}
	return k.ID
}

// config returns the enabled configuration of the fixture with keyID.
func (f *ssoFixture) config(keyID string) TenantSSO {
	return TenantSSO{
		Enabled: true, Issuer: testSSOIssuer, ClientID: testSSOApp, ClientSecretKeyID: keyID,
		EmailDomains: []string{"a.example.com"}, RequireMFA: true,
	}
}

// TestSSODriverFaults injects a driver failure into each statement of the
// single sign-on repositories and checks that it surfaces as an error.
func TestSSODriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newSSOFixture(t)
	sso, ids, sessions := f.db.SSOSettings(), f.db.AdminIdentities(), f.db.AdminSessions()
	for _, c := range []struct {
		name, op, match string
		run             func() error
	}{
		{"get domains", faultQuery, "SELECT domain FROM sso_email_domains", func() error {
			_, err := sso.Get(ctx, f.tid)
			return err
		}},
		{"put read", faultQuery, "FROM tenant_sso_settings WHERE tenant_id", func() error {
			_, _, err := sso.Put(ctx, f.tid, f.config(""))
			return err
		}},
		{"put domains delete", faultExec, "DELETE FROM sso_email_domains", func() error {
			_, _, err := sso.Put(ctx, f.tid, f.config(""))
			return err
		}},
		{"put domain insert", faultExec, "INSERT INTO sso_email_domains", func() error {
			_, _, err := sso.Put(ctx, f.tid, f.config(""))
			return err
		}},
		{"put secret erase", faultExec, "DELETE FROM wrapped_keys", func() error {
			_, _, err := sso.Put(ctx, f.tid, f.config(f.newSecret(ctx, t)))
			return err
		}},
		{"delete read", faultQuery, "FROM tenant_sso_settings WHERE tenant_id", func() error {
			_, err := sso.Delete(ctx, f.tid)
			return err
		}},
		{"delete row", faultExec, "DELETE FROM tenant_sso_settings", func() error {
			_, err := sso.Delete(ctx, f.tid)
			return err
		}},
		{"delete secret", faultExec, "DELETE FROM wrapped_keys", func() error {
			_, err := sso.Delete(ctx, f.tid)
			return err
		}},
		{"route", faultQuery, "FROM sso_email_domains d JOIN", func() error {
			_, err := sso.RouteDomain(ctx, "a.example.com")
			return err
		}},
		{"route domains", faultQuery, "SELECT domain FROM sso_email_domains", func() error {
			_, err := sso.RouteDomain(ctx, "a.example.com")
			return err
		}},
		{"any enabled", faultQuery, "FROM tenant_sso_settings WHERE enabled", func() error {
			_, err := sso.AnyEnabled(ctx)
			return err
		}},
		{"for admin", faultQuery, "FROM admin_tenants a JOIN tenant_sso_settings", func() error {
			_, err := sso.ForAdmin(ctx, f.del.ID)
			return err
		}},
		{"for admin scan", faultScanNil, "FROM admin_tenants a JOIN tenant_sso_settings", func() error {
			_, err := sso.ForAdmin(ctx, f.del.ID)
			return err
		}},
		{"identity list", faultQuery, "FROM admin_identities WHERE admin_id = ? ORDER BY id", func() error {
			_, err := ids.List(ctx, f.del.ID)
			return err
		}},
		{"identity list tx", faultQuery, "FROM admin_identities WHERE admin_id = ? ORDER BY id", func() error {
			return f.db.Admins().Tx(ctx, func(tx *SystemTx) error { _, err := ids.ListTx(ctx, tx, f.del.ID); return err })
		}},
		{"identity insert", faultExec, "INSERT INTO admin_identities", func() error {
			_, err := ids.Link(ctx, AdminIdentity{AdminID: f.del.ID, Issuer: testSSOIssuer, ClientID: "other", Subject: "s"})
			return err
		}},
		{"identity touch", faultExec, "UPDATE admin_identities", func() error {
			return ids.Touch(ctx, f.identity.ID, adminTestNow)
		}},
		{"identity unpin", faultQuery, "DELETE FROM admin_identities WHERE issuer", func() error {
			_, err := ids.DeleteForTenantClient(ctx, f.tid, testSSOIssuer, testSSOApp)
			return err
		}},
		{"session revoke", faultExec, "DELETE FROM admin_sessions WHERE auth_method", func() error {
			_, err := sessions.DeleteSSOForTenant(ctx, f.tid, testSSOIssuer, testSSOApp)
			return err
		}},
		{"account session revoke", faultExec, "WHERE admin_id = ? AND auth_method = 'oidc'", func() error {
			return f.db.Admins().Tx(ctx, func(tx *SystemTx) error {
				_, err := sessions.DeleteSSOForAdminTx(ctx, tx, f.del.ID, testSSOIssuer, testSSOApp)
				return err
			})
		}},
		{"admins by email", faultQuery, "WHERE a.email = ? AND t.tenant_id = ?", func() error {
			_, err := f.db.Admins().ByEmailInTenant(ctx, f.del.Email, f.tid)
			return err
		}},
		{"admins by email scan", faultScanNil, "WHERE a.email = ? AND t.tenant_id = ?", func() error {
			_, err := f.db.Admins().ByEmailInTenant(ctx, f.del.Email, f.tid)
			return err
		}},
		{"admins by email read", faultQuery, "FROM admins WHERE id = ?", func() error {
			_, err := f.db.Admins().ByEmailInTenant(ctx, f.del.Email, f.tid)
			return err
		}},
		{"account session revoke rows", faultRows, "WHERE admin_id = ? AND auth_method = 'oidc'", func() error {
			return f.db.Admins().Tx(ctx, func(tx *SystemTx) error {
				_, err := sessions.DeleteSSOForAdminTx(ctx, tx, f.del.ID, testSSOIssuer, testSSOApp)
				return err
			})
		}},
	} {
		f.plan.reset()
		f.plan.add(c.op, c.match, 0)
		if err := c.run(); err == nil || errors.Is(err, ErrInvalid) || errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
	}
	f.plan.reset()

	// The identifier generator fails: nothing is pinned.
	gen := f.db.newID
	f.db.newID = func(id.Prefix) (string, error) { return "", errInjected }
	if _, err := ids.Link(ctx, AdminIdentity{AdminID: f.del.ID, Issuer: testSSOIssuer, ClientID: "other", Subject: "s"}); !errors.Is(err, errInjected) {
		t.Errorf("Link with a failing generator = %v", err)
	}
	f.db.newID = gen

	// A promotion fails when its identities cannot be unpinned.
	if err := f.db.Admins().SetPassword(ctx, f.del.ID, adminTestPHC); err != nil {
		t.Fatal(err)
	}
	totp := newTestSecret()
	if err := f.db.Admins().SetPendingTOTP(ctx, f.del.ID, totp); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Admins().SetTOTP(ctx, f.del.ID, totp.ID, 1); err != nil {
		t.Fatal(err)
	}
	f.plan.add(faultQuery, "DELETE FROM admin_identities WHERE admin_id = ? RETURNING", 0)
	super := RoleSuperAdmin
	if _, err := f.db.Admins().Update(ctx, f.del.ID, AdminUpdate{Role: &super}); err == nil {
		t.Error("promotion with a failing unpin succeeded")
	}
	f.plan.reset()
	if got, err := ids.List(ctx, f.del.ID); err != nil || len(got) != 1 {
		t.Errorf("identities after the failed promotion = %+v, %v", got, err)
	}

	// A successful unpinning inside a transaction.
	err := f.db.Admins().Tx(ctx, func(tx *SystemTx) error {
		got, err := ids.DeleteTx(ctx, tx, f.del.ID, f.identity.ID)
		if err == nil && got.ID != f.identity.ID {
			t.Errorf("DeleteTx = %+v", got)
		}
		return err
	})
	if err != nil {
		t.Errorf("DeleteTx = %v", err)
	}
}

// TestSSOLockStatements makes the PostgreSQL-only tenant and system locks
// fail, so that the code paths taking them return the error on SQLite.
func TestSSOLockStatements(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newSSOFixture(t)
	d := *f.db.dialect
	d.lockTenant = "SELECT bogus("
	d.lockSystem = "SELECT bogus("
	f.db.dialect = &d
	if _, _, err := f.db.SSOSettings().Put(ctx, f.tid, f.config("")); err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("Put with a failing lock = %v", err)
	}
	if _, err := f.db.SSOSettings().Delete(ctx, f.tid); err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("Delete with a failing lock = %v", err)
	}
	if _, err := f.db.AdminIdentities().Link(ctx, AdminIdentity{AdminID: f.del.ID, Issuer: testSSOIssuer, ClientID: "x", Subject: "s"}); err == nil ||
		!strings.Contains(err.Error(), "lock admins") {
		t.Errorf("Link with a failing lock = %v", err)
	}
	err := f.db.Admins().Tx(ctx, func(tx *SystemTx) error { _, err := f.db.AdminIdentities().ListTx(ctx, tx, f.del.ID); return err })
	if err == nil || !strings.Contains(err.Error(), "lock admins") {
		t.Errorf("ListTx with a failing lock = %v", err)
	}
}

package store

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// provFaultFixture is a database of the fault driver holding one
// provisioning token.
func provFaultFixture(t *testing.T) (*DB, *faultPlan, ProvisioningToken) {
	t.Helper()
	db, plan := openFault(t)
	tok, err := db.ProvisioningTokens().Create(context.Background(), ProvisioningToken{
		ID: id.New(id.ProvisioningToken), Name: "n", Prefix: "ttp_AbCd", TokenHash: make([]byte, TokenHashSize),
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, AllowedFQDNSuffixes: []string{".t.example.com"},
		MaxStorageQuotaBytes: 1, MaxTenants: 1, CreatedBy: id.New(id.Admin),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return db, plan, tok
}

// newProvisionedTenant returns a tenant to create with a token.
func newProvisionedTenant() *tenant.Tenant {
	return &tenant.Tenant{
		SetupState: tenant.SetupStateSetup, Name: "A", FQDN: "a.t.example.com", DefaultLanguage: "fr",
		MaxTransferBytes: 1, StorageQuotaBytes: 1,
	}
}

// TestProvisioningDriverFaults reaches the error paths of the provisioning
// repository that a healthy database never takes, and the decoding of
// corrupted JSON columns.
func TestProvisioningDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan, tok := provFaultFixture(t)
	repo := db.ProvisioningTokens()
	create := func() error {
		_, err := db.Tenants().CreateProvisioned(ctx, tok.ID, newProvisionedTenant(), nil)
		return err
	}
	for _, c := range []struct {
		name, op, match string
		run             func() error
	}{
		{"list query", faultQuery, "FROM provisioning_tokens ORDER BY", func() error { _, err := repo.List(ctx); return err }},
		{"revoke exec", faultExec, "SET revoked_at", func() error { _, _, err := repo.Revoke(ctx, tok.ID, time.Time{}, nil); return err }},
		{"revoke rows", faultRows, "SET revoked_at", func() error { _, _, err := repo.Revoke(ctx, tok.ID, time.Time{}, nil); return err }},
		{"touch exec", faultExec, "SET last_used_at", func() error { return repo.Touch(ctx, tok.ID, time.Time{}) }},
		{"tenants query", faultQuery, "FROM tenants t WHERE t.provisioned_by = ? AND t.status", func() error {
			_, err := repo.ListTenants(ctx, tok.ID)
			return err
		}},
		{"guard token", faultQuery, "FROM provisioning_tokens WHERE id = ?", create},
		{"guard count", faultQuery, "SELECT count(*) FROM tenants WHERE provisioned_by = ?", create},
		{"guard recent", faultQuery, "COALESCE(min(created_at), 0)", create},
	} {
		plan.reset()
		plan.add(c.op, c.match, 0)
		err := c.run()
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrProvisioningTokenUnusable) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
	}
	plan.reset()

	// Corrupted JSON columns are reported, never half-decoded.
	for _, set := range []string{
		`allowed_cidrs = 'not json'`, `allowed_cidrs = '["not a prefix"]'`, `allowed_fqdn_suffixes = 'not json'`,
	} {
		if _, err := rawSystemExec(ctx, db, `UPDATE provisioning_tokens SET `+set); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Get(ctx, tok.ID); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Get with %s = %v, want a decoding error", set, err)
		}
		if _, err := rawSystemExec(ctx, db,
			`UPDATE provisioning_tokens SET allowed_cidrs = '["192.0.2.0/24"]', allowed_fqdn_suffixes = '[".t.example.com"]'`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repo.Get(ctx, tok.ID); err != nil {
		t.Errorf("Get after repair: %v", err)
	}
}

// TestProvisioningLockStatement replaces the PostgreSQL-only system lock by
// a harmless statement, so that the provisioned creation takes it on
// SQLite, then makes it fail: nothing is created.
func TestProvisioningLockStatement(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _, tok := provFaultFixture(t)
	d := *db.dialect
	d.lockSystem = "SELECT bogus("
	db.dialect = &d
	if _, err := db.Tenants().CreateProvisioned(ctx, tok.ID, newProvisionedTenant(), nil); err == nil ||
		!strings.Contains(err.Error(), "lock provisioning") {
		t.Errorf("CreateProvisioned with a failing lock: %v", err)
	}
	d.lockSystem = "SELECT ?"
	if _, err := db.Tenants().CreateProvisioned(ctx, tok.ID, newProvisionedTenant(), nil); err != nil {
		t.Errorf("CreateProvisioned with a harmless lock: %v", err)
	}
}

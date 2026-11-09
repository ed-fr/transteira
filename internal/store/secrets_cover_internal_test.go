package store

import (
	"context"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/tenant"
)

// TestTenantCreateSecretSettingsFault injects a failure into the write of
// the custom secret settings of a created tenant (configuration import) and
// checks that the creation fails as a whole.
func TestTenantCreateSecretSettingsFault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	durations, err := tenant.NewSecretDurationSet(tenant.SecretDuration1d)
	if err != nil {
		t.Fatal(err)
	}
	settings := tenant.DefaultSecretSettings()
	settings.Durations = durations
	plan.add(faultExec, "secret_email_requires_passphrase = ?", 0)
	_, err = db.Tenants().Create(ctx, &tenant.Tenant{
		SetupState: tenant.SetupStateActive, Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr",
		MaxTransferBytes: 1, StorageQuotaBytes: 1, Secrets: settings,
	})
	if !errors.Is(err, errInjected) {
		t.Errorf("Create with a failing secret settings write = %v, want the injected error", err)
	}
}

// TestWrappedKeyGetTxUnknown checks that GetTx reports an unknown key row.
func TestWrappedKeyGetTxUnknown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := openFault(t)
	tn, err := db.Tenants().Create(ctx, &tenant.Tenant{SetupState: tenant.SetupStateActive, Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := db.Scoped(tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = sc.ReadTx(ctx, func(tx *ScopedTx) error {
		_, err := db.WrappedKeys().GetTx(ctx, tx, "wk_unknown")
		return err
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetTx of an unknown key = %v, want ErrNotFound", err)
	}
}

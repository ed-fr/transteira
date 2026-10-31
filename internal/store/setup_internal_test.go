package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// TestSetupFaults injects failures into the setup statements: the SMTP test
// stamp, the completion and the versioned SMTP write.
func TestSetupFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t, WithClock(func() time.Time { return time.Unix(1_700_000_000, 0) }))
	s, err := db.Tenants().Create(ctx, &tenant.Tenant{
		SetupState: tenant.SetupStateSetup, Name: "S", FQDN: "s.example.com", DefaultLanguage: "en",
		MaxTransferBytes: 1, StorageQuotaBytes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	relay := SMTPConfig{Host: "smtp-relay", Port: 25, Security: SMTPSecurityNone, FromAddress: "noreply@example.com"}
	if err := db.SMTPSettings().Put(ctx, s.ID, relay); err != nil {
		t.Fatal(err)
	}
	version := time.Unix(1_700_000_000, 0)

	plan.add(faultExec, "smtp_tested_at = ?", 0)
	if err := db.Tenants().SetSMTPTested(ctx, s.ID, version); !errors.Is(err, errInjected) {
		t.Errorf("stamp exec fault: %v", err)
	}
	plan.reset()
	plan.add(faultExec, "setup_state = 'active'", 0)
	if _, err := db.Tenants().CompleteSetup(ctx, s.ID, true, time.Time{}); !errors.Is(err, errInjected) {
		t.Errorf("completion exec fault: %v", err)
	}
	plan.reset()
	plan.add(faultRows, "setup_state = 'active'", 0)
	if _, err := db.Tenants().CompleteSetup(ctx, s.ID, false, time.Time{}); !errors.Is(err, errInjected) {
		t.Errorf("completion rows affected fault: %v", err)
	}
	plan.reset()
	plan.add(faultQuery, "FROM tenants WHERE id = ?", 0)
	if _, err := db.Tenants().CompleteSetup(ctx, s.ID, false, time.Time{}); !errors.Is(err, errInjected) {
		t.Errorf("completion read fault: %v", err)
	}
	plan.reset()
	plan.add(faultQuery, "FROM tenant_smtp_settings", 0)
	if err := db.SMTPSettings().Put(ctx, s.ID, relay); !errors.Is(err, errInjected) {
		t.Errorf("smtp version read fault: %v", err)
	}
	plan.reset()
	if got, err := db.Tenants().Get(ctx, s.ID); err != nil || got.SetupState != tenant.SetupStateSetup {
		t.Fatalf("a failed completion changed the tenant: %+v, %v", got, err)
	}

	// The tenant lock (PostgreSQL only) fails both statements.
	d := *sqliteDialect
	d.lockTenant = "SELECT bogus("
	db.dialect = &d
	if _, err := db.Tenants().CompleteSetup(ctx, s.ID, true, time.Time{}); err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("completion lock fault: %v", err)
	}
	if err := db.SMTPSettings().Put(ctx, s.ID, relay); err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("smtp lock fault: %v", err)
	}
}

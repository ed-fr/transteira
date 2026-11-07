package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestAntivirusDriverFaults injects a driver failure into each statement of
// the antivirus release paths and checks that it surfaces and stores
// nothing.
func TestAntivirusDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now()
	f := newTransferFixture(t)
	finalize := func() error {
		return f.tx(ctx, func(tx *ScopedTx) error {
			_, err := f.db.Transfers().FinalizeUnscannedTx(ctx, tx, f.trf.ID, now)
			return err
		})
	}
	for _, c := range []struct {
		name, op, match string
		run             func() error
	}{
		{"finalize status", faultExec, "UPDATE transfers SET status", finalize},
		{"finalize release exec", faultExec, "SET scan_status = 'not_scanned_disabled'", finalize},
		{"finalize release rows", faultRows, "SET scan_status = 'not_scanned_disabled'", finalize},
		{"release all exec", faultExec, "EXISTS (SELECT 1 FROM transfers", func() error {
			_, err := f.db.TransferFiles().ReleaseAllUnscanned(ctx)
			return err
		}},
		{"release all rows", faultRows, "EXISTS (SELECT 1 FROM transfers", func() error {
			_, err := f.db.TransferFiles().ReleaseAllUnscanned(ctx)
			return err
		}},
	} {
		f.plan.reset()
		f.plan.add(c.op, c.match, 0)
		if err := c.run(); !errors.Is(err, errInjected) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
	}
	f.plan.reset()
	// Nothing was stored: the transfer is still uploading, its file pending.
	d, err := f.db.Transfers().Get(ctx, f.tid, f.trf.ID)
	if err != nil || d.Status != TransferUploading || d.Files[0].ScanStatus != ScanPending {
		t.Fatalf("after the faults: %+v, %v", d, err)
	}
}

// TestTenantUpdateWithAntivirusAtomic checks that the general settings
// and the antivirus switch are stored in one transaction: when the second
// statement fails, the first one is rolled back.
func TestTenantUpdateWithAntivirusAtomic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTransferFixture(t)
	tenants := f.db.Tenants()
	cur, err := tenants.Get(ctx, f.tid)
	if err != nil {
		t.Fatal(err)
	}
	next := cur.Clone()
	next.Name, next.AntivirusEnabled = "Renamed", false
	for _, c := range []struct{ name, op, match string }{
		{"antivirus exec", faultExec, "SET antivirus_enabled"},
		{"antivirus rows", faultRows, "SET antivirus_enabled"},
		{"general exec", faultExec, "UPDATE tenants SET name"},
	} {
		f.plan.reset()
		f.plan.add(c.op, c.match, 0)
		if _, err := tenants.UpdateWithAntivirus(ctx, next, true, true); !errors.Is(err, errInjected) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
		got, err := tenants.Get(ctx, f.tid)
		if err != nil || got.Name != cur.Name || !got.AntivirusEnabled || !got.UpdatedAt.Equal(cur.UpdatedAt) {
			t.Errorf("%s: stored %+v, %v", c.name, got, err)
		}
	}
	f.plan.reset()
	got, err := tenants.UpdateWithAntivirus(ctx, next, true, true)
	if err != nil || got.Name != "Renamed" || got.AntivirusEnabled {
		t.Fatalf("UpdateWithAntivirus = %+v, %v", got, err)
	}
	// A tenant without ID is refused.
	got, err = tenants.UpdateWithAntivirus(ctx, &tenant.Tenant{}, false, true)
	if !errors.Is(err, ErrInvalid) || got != nil {
		t.Errorf("zero id = %+v, %v", got, err)
	}
}

// TestFinalizeE2EFaults checks that a driver failure of each statement of
// FinalizeE2ETx surfaces and stores nothing.
func TestFinalizeE2EFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	f := newTransferFixture(t)
	trf := Transfer{ID: id.New(id.Transfer), SenderEmail: fixtureEmail, SenderKind: DepositorInternal, ExpiryDays: 1, E2E: true}
	file := f.newFile(ctx, t)
	file.E2EMetadata = "AbC1_dEf2"
	file.SHA256, file.CiphertextSize, file.UploadedAt = strings.Repeat("a", 64), 64, now
	if err := f.create(ctx, trf, file); err != nil {
		t.Fatal(err)
	}
	finalize := func() error {
		return f.tx(ctx, func(tx *ScopedTx) error {
			_, err := f.db.Transfers().FinalizeE2ETx(ctx, tx, trf.ID, now)
			return err
		})
	}
	for _, c := range []struct{ name, op, match string }{
		{"read", faultQuery, "SELECT id, status"},
		{"status", faultExec, "UPDATE transfers SET status"},
		{"release exec", faultExec, "SET scan_status = 'not_scanned_e2e'"},
		{"release rows", faultRows, "SET scan_status = 'not_scanned_e2e'"},
	} {
		f.plan.reset()
		f.plan.add(c.op, c.match, 0)
		if err := finalize(); !errors.Is(err, errInjected) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
	}
	f.plan.reset()
	d, err := f.db.Transfers().Get(ctx, f.tid, trf.ID)
	if err != nil || d.Status != TransferUploading || d.Files[0].ScanStatus != ScanPending {
		t.Fatalf("after the faults: %+v, %v", d, err)
	}
}

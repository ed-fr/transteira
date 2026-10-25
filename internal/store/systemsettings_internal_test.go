package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestSystemSettingsDriverFaults reaches the error paths of the system
// settings repository that a healthy database never takes, the decoding of
// a corrupted maintenance_message column and a missing settings row.
func TestSystemSettingsDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	repo := db.SystemSettings()
	noop := func(*SystemTx, *SystemSettingsRow) error { return nil }
	for _, c := range []struct {
		name, op, match string
		run             func() error
	}{
		{"get query", faultScanNil, "FROM system_settings WHERE id = 1", func() error { _, err := repo.Get(ctx); return err }},
		{"update lock exec", faultExec, "SET updated_at = updated_at", func() error { _, err := repo.UpdateTx(ctx, noop); return err }},
		{"update lock rows", faultRows, "SET updated_at = updated_at", func() error { _, err := repo.UpdateTx(ctx, noop); return err }},
		{"update read", faultScanNil, "FROM system_settings WHERE id = 1", func() error { _, err := repo.UpdateTx(ctx, noop); return err }},
		{"update exec", faultExec, "SET disk_alert_threshold_bp", func() error { _, err := repo.UpdateTx(ctx, noop); return err }},
		{"disk level exec", faultExec, "SET disk_alert_level", func() error {
			_, err := repo.CompareAndSetDiskLevel(ctx, DiskAlertLevelNormal, DiskAlertLevelRaised, time.Time{})
			return err
		}},
		{"disk level rows", faultRows, "SET disk_alert_level", func() error {
			_, err := repo.CompareAndSetDiskLevel(ctx, DiskAlertLevelNormal, DiskAlertLevelRaised, time.Time{})
			return err
		}},
		{"claim mail exec", faultExec, "SET disk_alert_mailed_at", func() error {
			_, err := repo.ClaimDiskAlertMail(ctx, time.Time{}, time.Hour)
			return err
		}},
		{"claim mail rows", faultRows, "SET disk_alert_mailed_at", func() error {
			_, err := repo.ClaimDiskAlertMail(ctx, time.Time{}, time.Hour)
			return err
		}},
		{"claim antivirus mail exec", faultExec, "SET antivirus_alert_mailed_at", func() error {
			_, err := repo.ClaimAntivirusAlertMail(ctx, time.Time{}, time.Hour)
			return err
		}},
		{"claim antivirus mail rows", faultRows, "SET antivirus_alert_mailed_at", func() error {
			_, err := repo.ClaimAntivirusAlertMail(ctx, time.Time{}, time.Hour)
			return err
		}},
	} {
		plan.reset()
		plan.add(c.op, c.match, 0)
		if err := c.run(); err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
	}
	plan.reset()
	if got, err := repo.Get(ctx); err != nil || got.DiskAlertLevel != DiskAlertLevelNormal {
		t.Errorf("Get after the faults = %+v, %v; nothing must have changed", got, err)
	}

	// A corrupted maintenance_message column is reported, never misread;
	// the JSON null reads as no message.
	if _, err := rawSystemExec(ctx, db, `UPDATE system_settings SET maintenance_message = 'not json'`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(ctx); err == nil {
		t.Error("Get with a corrupted maintenance_message succeeded, want a decoding error")
	}
	if _, err := rawSystemExec(ctx, db, `UPDATE system_settings SET maintenance_message = 'null'`); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.Get(ctx); err != nil || got.MaintenanceMessage == nil || len(got.MaintenanceMessage) != 0 {
		t.Errorf("Get with maintenance_message null = %+v, %v", got.MaintenanceMessage, err)
	}

	// Without the settings row (never the case after the migration), Get
	// and UpdateTx report ErrNotFound and the compare-and-set never wins.
	if _, err := rawSystemExec(ctx, db, `DELETE FROM system_settings`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(no row) = %v, want ErrNotFound", err)
	}
	if _, err := repo.UpdateTx(ctx, noop); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateTx(no row) = %v, want ErrNotFound", err)
	}
	if won, err := repo.CompareAndSetDiskLevel(ctx, DiskAlertLevelNormal, DiskAlertLevelRaised, time.Time{}); err != nil || won {
		t.Errorf("CompareAndSetDiskLevel(no row) = %v, %v; want false", won, err)
	}
	if won, err := repo.ClaimDiskAlertMail(ctx, time.Time{}, time.Hour); err != nil || won {
		t.Errorf("ClaimDiskAlertMail(no row) = %v, %v; want false", won, err)
	}
	if won, err := repo.ClaimAntivirusAlertMail(ctx, time.Time{}, time.Hour); err != nil || won {
		t.Errorf("ClaimAntivirusAlertMail(no row) = %v, %v; want false", won, err)
	}
}

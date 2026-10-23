package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestSystemSettings(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.SystemSettings()

		// Defaults created by the migration.
		got, err := repo.Get(ctx)
		if err != nil || got.DiskAlertThresholdBP != store.DefaultDiskAlertThresholdBP || got.AlertEmail != "" ||
			got.AlertEmailLanguage != "" || got.MaintenanceEnabled || !got.MaintenanceSince.IsZero() ||
			got.MaintenanceMessage == nil || len(got.MaintenanceMessage) != 0 ||
			got.DiskAlertLevel != store.DiskAlertLevelNormal || !got.DiskAlertChangedAt.IsZero() || !got.DiskAlertMailedAt.IsZero() ||
			!got.UpdatedAt.Equal(time.UnixMilli(0).UTC()) {
			t.Fatalf("Get(defaults) = %+v, %v", got, err)
		}

		// A change and its audit event commit together.
		updated, err := repo.UpdateTx(ctx, func(tx *store.SystemTx, s *store.SystemSettingsRow) error {
			s.DiskAlertThresholdBP = 9000
			s.AlertEmail = "IT-Admin@Example.COM"
			s.AlertEmailLanguage = "fr"
			s.MaintenanceEnabled = true
			s.MaintenanceMessage["fr"] = "Mise à jour en cours.\nRetour vers 20 h."
			s.MaintenanceMessage["en"] = "Upgrade in progress."
			_, err := db.AuditEvents().AppendTx(ctx, tx, store.AuditEvent{
				ActorKind: store.ActorAdmin, Actor: "root", Action: "maintenance.enabled",
				ObjectKind: "system", ObjectID: "maintenance",
			})
			return err
		})
		if err != nil || updated.DiskAlertThresholdBP != 9000 || updated.AlertEmail != "it-admin@example.com" ||
			updated.AlertEmailLanguage != "fr" || !updated.MaintenanceEnabled || !updated.MaintenanceSince.Equal(msNow) ||
			len(updated.MaintenanceMessage) != 2 || !updated.UpdatedAt.Equal(msNow) {
			t.Fatalf("UpdateTx = %+v, %v", updated, err)
		}
		got, err = repo.Get(ctx)
		if err != nil || got.AlertEmail != "it-admin@example.com" || got.AlertEmailLanguage != "fr" ||
			!got.MaintenanceEnabled || !got.MaintenanceSince.Equal(msNow) ||
			got.MaintenanceMessage["fr"] != "Mise à jour en cours.\nRetour vers 20 h." ||
			got.MaintenanceMessage["en"] != "Upgrade in progress." || !got.UpdatedAt.Equal(msNow) {
			t.Errorf("Get(after update) = %+v, %v", got, err)
		}
		page, err := db.AuditEvents().List(ctx, store.AuditFilter{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Action != "maintenance.enabled" {
			t.Errorf("audit after UpdateTx = %+v, %v", page.Items, err)
		}

		// An error from fn rolls the change and the audit event back.
		boom := errors.New("boom")
		_, err = repo.UpdateTx(ctx, func(tx *store.SystemTx, s *store.SystemSettingsRow) error {
			s.DiskAlertThresholdBP = 5000
			delete(s.MaintenanceMessage, "fr")
			if _, err := db.AuditEvents().AppendTx(ctx, tx, store.AuditEvent{
				ActorKind: store.ActorAdmin, Actor: "root", Action: "config.updated",
				ObjectKind: "system", ObjectID: "settings",
			}); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Errorf("UpdateTx(fn error) = %v, want boom", err)
		}
		got, err = repo.Get(ctx)
		if err != nil || got.DiskAlertThresholdBP != 9000 || len(got.MaintenanceMessage) != 2 {
			t.Errorf("Get(after rollback) = %+v, %v", got, err)
		}
		if page, err := db.AuditEvents().List(ctx, store.AuditFilter{}); err != nil || len(page.Items) != 1 {
			t.Errorf("audit after rollback = %+v, %v", page.Items, err)
		}

		// Invalid values change nothing.
		bad := map[string]func(*store.SystemSettingsRow){
			"threshold low":    func(s *store.SystemSettingsRow) { s.DiskAlertThresholdBP = store.MinDiskAlertThresholdBP - 1 },
			"threshold high":   func(s *store.SystemSettingsRow) { s.DiskAlertThresholdBP = store.MaxDiskAlertThresholdBP + 1 },
			"email":            func(s *store.SystemSettingsRow) { s.AlertEmail = "not an address" },
			"email language":   func(s *store.SystemSettingsRow) { s.AlertEmailLanguage = "" },
			"unknown language": func(s *store.SystemSettingsRow) { s.AlertEmailLanguage = "xx" },
			"message language": func(s *store.SystemSettingsRow) { s.MaintenanceMessage["xx"] = "x" },
			"empty message":    func(s *store.SystemSettingsRow) { s.MaintenanceMessage["en"] = "" },
			"long message": func(s *store.SystemSettingsRow) {
				s.MaintenanceMessage["en"] = strings.Repeat("é", store.MaxMaintenanceMessageRunes+1)
			},
			"invalid utf-8": func(s *store.SystemSettingsRow) { s.MaintenanceMessage["en"] = "\xff" },
		}
		for name, mutate := range bad {
			_, err := repo.UpdateTx(ctx, func(_ *store.SystemTx, s *store.SystemSettingsRow) error { mutate(s); return nil })
			wantErr(t, "UpdateTx("+name+")", err, store.ErrInvalid)
		}
		_, err = repo.UpdateTx(ctx, nil)
		wantErr(t, "UpdateTx(nil)", err, store.ErrInvalid)
		if got, err := repo.Get(ctx); err != nil || got.DiskAlertThresholdBP != 9000 || got.AlertEmail != "it-admin@example.com" {
			t.Errorf("Get(after invalid updates) = %+v, %v", got, err)
		}

		// A maximal message is accepted; an explicit start is kept.
		since := msNow.Add(-time.Hour)
		long := strings.Repeat("é", store.MaxMaintenanceMessageRunes)
		updated, err = repo.UpdateTx(ctx, func(_ *store.SystemTx, s *store.SystemSettingsRow) error {
			s.MaintenanceSince = since
			s.MaintenanceMessage = map[string]string{"en": long}
			return nil
		})
		if err != nil || !updated.MaintenanceSince.Equal(since) || updated.MaintenanceMessage["en"] != long ||
			len(updated.MaintenanceMessage) != 1 {
			t.Errorf("UpdateTx(since, long message) = %+v, %v", updated, err)
		}

		// Clearing the address clears its language; turning maintenance
		// off clears its start; a nil message map stores no message.
		updated, err = repo.UpdateTx(ctx, func(_ *store.SystemTx, s *store.SystemSettingsRow) error {
			s.AlertEmail = ""
			s.MaintenanceEnabled = false
			s.MaintenanceMessage = nil
			return nil
		})
		if err != nil || updated.AlertEmail != "" || updated.AlertEmailLanguage != "" || updated.MaintenanceEnabled ||
			!updated.MaintenanceSince.IsZero() || updated.MaintenanceMessage == nil || len(updated.MaintenanceMessage) != 0 {
			t.Errorf("UpdateTx(clear) = %+v, %v", updated, err)
		}
		got, err = repo.Get(ctx)
		if err != nil || got.AlertEmail != "" || got.AlertEmailLanguage != "" || got.MaintenanceEnabled ||
			!got.MaintenanceSince.IsZero() || len(got.MaintenanceMessage) != 0 {
			t.Errorf("Get(after clear) = %+v, %v", got, err)
		}

		// The disk alert level changes by compare-and-set only.
		changed := msNow.Add(time.Minute)
		if won, err := repo.CompareAndSetDiskLevel(ctx, store.DiskAlertLevelNormal, store.DiskAlertLevelRaised, changed); err != nil || !won {
			t.Errorf("CompareAndSetDiskLevel(0→1) = %v, %v; want true", won, err)
		}
		if won, err := repo.CompareAndSetDiskLevel(ctx, store.DiskAlertLevelNormal, store.DiskAlertLevelRaised, changed); err != nil || won {
			t.Errorf("CompareAndSetDiskLevel(0→1 again) = %v, %v; want false", won, err)
		}
		got, err = repo.Get(ctx)
		if err != nil || got.DiskAlertLevel != store.DiskAlertLevelRaised || !got.DiskAlertChangedAt.Equal(changed) {
			t.Errorf("Get(after raise) = %+v, %v", got, err)
		}
		// UpdateTx leaves the level alone, whatever fn does with it.
		updated, err = repo.UpdateTx(ctx, func(_ *store.SystemTx, s *store.SystemSettingsRow) error {
			s.DiskAlertLevel = store.DiskAlertLevelNormal
			s.DiskAlertChangedAt = time.Time{}
			return nil
		})
		if err != nil || updated.DiskAlertLevel != store.DiskAlertLevelRaised || !updated.DiskAlertChangedAt.Equal(changed) {
			t.Errorf("UpdateTx(level) = %+v, %v", updated, err)
		}
		if got, err := repo.Get(ctx); err != nil || got.DiskAlertLevel != store.DiskAlertLevelRaised {
			t.Errorf("Get(after UpdateTx level) = %+v, %v", got, err)
		}
		// A zero time uses the store's clock.
		if won, err := repo.CompareAndSetDiskLevel(ctx, store.DiskAlertLevelRaised, store.DiskAlertLevelNormal, time.Time{}); err != nil || !won {
			t.Errorf("CompareAndSetDiskLevel(1→0) = %v, %v; want true", won, err)
		}
		if got, err := repo.Get(ctx); err != nil || got.DiskAlertLevel != store.DiskAlertLevelNormal || !got.DiskAlertChangedAt.Equal(msNow) {
			t.Errorf("Get(after clear) = %+v, %v", got, err)
		}
		for _, levels := range [][2]int{{2, 1}, {0, -1}} {
			_, err := repo.CompareAndSetDiskLevel(ctx, levels[0], levels[1], msNow)
			wantErr(t, "CompareAndSetDiskLevel(invalid level)", err, store.ErrInvalid)
		}

		// The disk alert mail slot is taken at most once per interval.
		mailed := msNow.Add(time.Hour)
		claim := func(now time.Time, want bool) {
			t.Helper()
			if won, err := repo.ClaimDiskAlertMail(ctx, now, time.Hour); err != nil || won != want {
				t.Errorf("ClaimDiskAlertMail(%v) = %v, %v; want %v", now, won, err, want)
			}
		}
		claim(mailed, true)                             // never mailed
		claim(mailed.Add(59*time.Minute), false)        // too soon
		claim(mailed, false)                            // same instant
		claim(mailed.Add(-time.Minute), true)           // clock set back
		claim(mailed.Add(-time.Minute+time.Hour), true) // exactly an hour later
		if got, err := repo.Get(ctx); err != nil || !got.DiskAlertMailedAt.Equal(mailed.Add(-time.Minute+time.Hour)) {
			t.Errorf("Get(after claims) = %+v, %v", got, err)
		}
		// UpdateTx leaves it alone; a zero time uses the store's clock.
		if updated, err := repo.UpdateTx(ctx, func(_ *store.SystemTx, s *store.SystemSettingsRow) error {
			s.DiskAlertMailedAt = time.Time{}
			return nil
		}); err != nil || !updated.DiskAlertMailedAt.Equal(mailed.Add(-time.Minute+time.Hour)) {
			t.Errorf("UpdateTx(mailed at) = %+v, %v", updated, err)
		}
		claim(time.Time{}, true) // msNow is before the last mail: a clock set back
		if got, err := repo.Get(ctx); err != nil || !got.DiskAlertMailedAt.Equal(msNow) {
			t.Errorf("Get(after store clock claim) = %+v, %v", got, err)
		}
		_, err = repo.ClaimDiskAlertMail(ctx, msNow, -time.Second)
		wantErr(t, "ClaimDiskAlertMail(negative interval)", err, store.ErrInvalid)
	})
}

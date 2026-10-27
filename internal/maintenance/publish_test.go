package maintenance_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/maintenance"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestSetPublishes checks that a change of the stored choice publishes
// maintenance.enabled or maintenance.disabled once committed, and that a
// change of the messages alone, a refused change or a rolled back one
// publishes nothing.
func TestSetPublishes(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, storetest.SQLite(t))
	rec := &events.Recorder{}
	m, err := maintenance.New(ctx, db.SystemSettings(), audit.New(db), maintenance.Options{Events: rec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Set(ctx, superAdmin, true, nil, clientIP); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Set(ctx, superAdmin, true, map[string]string{"en": "Back soon"}, clientIP); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Set(ctx, delegated, false, nil, clientIP); err == nil {
		t.Fatal("a delegated admin disabled the maintenance mode")
	}
	if _, err := m.Set(ctx, superAdmin, false, nil, clientIP); err != nil {
		t.Fatal(err)
	}
	got := rec.Events()
	if len(got) != 2 || got[0].Type != events.MaintenanceEnabled || got[1].Type != events.MaintenanceDisabled {
		t.Fatalf("published %+v", got)
	}
	for _, ev := range got {
		if ev.Severity != events.SeverityInfo || ev.TenantID != "" || ev.AdminPath != events.AdminPathSystem ||
			ev.OccurredAt.IsZero() || ev.Counts == nil || len(ev.Counts) != 0 {
			t.Errorf("event = %+v", ev)
		}
	}

	// While TT_MAINTENANCE forces the mode, the stored choice changes
	// nothing effective: nothing is published.
	rec = &events.Recorder{}
	m, err = maintenance.New(ctx, db.SystemSettings(), audit.New(db), maintenance.Options{Forced: true, Events: rec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Set(ctx, superAdmin, true, nil, clientIP); err != nil {
		t.Fatal(err)
	}
	if n := len(rec.Events()); n != 0 {
		t.Fatalf("published %d events while forced", n)
	}

	// A rolled back change publishes nothing.
	rec = &events.Recorder{}
	m, err = maintenance.New(ctx, db.SystemSettings(), &fakeAuditor{err: errors.New("audit down")},
		maintenance.Options{Events: rec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Set(ctx, superAdmin, true, nil, clientIP); err == nil {
		t.Fatal("Set with a failing audit succeeded")
	}
	if n := len(rec.Events()); n != 0 {
		t.Fatalf("published %d events for a rolled back change", n)
	}
}

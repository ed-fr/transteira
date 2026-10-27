package diskalert

import (
	"testing"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestPublishesAlertEvents checks the events of a raised and a cleared
// disk alert, published once per change of level.
func TestPublishesAlertEvents(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), false)
	ev.used(500)
	ev.used(900)
	ev.used(950) // still raised: nothing new
	ev.used(700)
	got := ev.published.Events()
	if len(got) != 2 {
		t.Fatalf("published %+v", got)
	}
	r, c := got[0], got[1]
	if r.Type != events.DiskAlertRaised || r.Severity != events.SeverityCritical || r.TenantID != "" ||
		r.AdminPath != events.AdminPathSystem || r.Counts["usedRatio"] != 0.9 || r.Counts["threshold"] != 0.85 ||
		len(r.Counts) != 2 || r.OccurredAt.IsZero() {
		t.Errorf("raised event = %+v", r)
	}
	if c.Type != events.DiskAlertCleared || c.Severity != events.SeverityInfo || c.Counts["usedRatio"] != 0.7 ||
		c.Counts["threshold"] != 0.85 || c.AdminPath != events.AdminPathSystem {
		t.Errorf("cleared event = %+v", c)
	}
}

// TestNoPublisher checks that a monitor built without publisher drops
// the events.
func TestNoPublisher(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), false)
	m, err := newMonitor(ev.fault, ev.auditor, Options{DataDir: t.TempDir(), AdminLink: adminLink})
	if err != nil || m.events != events.Discard {
		t.Fatalf("monitor without publisher: %v, %v", m.events, err)
	}
}

package quota

import (
	"testing"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestPublishesQuotaEvents checks the events of the warning and reached
// alerts, published once per rise of the level, and nothing when the
// level falls.
func TestPublishesQuotaEvents(t *testing.T) {
	rec := &events.Recorder{}
	ev := newEnv(t, storetest.SQLite(t), Options{Events: rec})
	tn := ev.tenant(1000)
	ev.use(tn, 800)
	ev.check(tn, false)
	ev.check(tn, false) // same level: nothing more
	ev.use(tn, 400)
	ev.check(tn, false)
	ev.setQuota(tn, 10000)
	ev.sweep() // lowered: silent
	got := rec.Events()
	if len(got) != 2 {
		t.Fatalf("published %+v", got)
	}
	w, r := got[0], got[1]
	path := "/admin/tenants/" + string(tn.ID) + "/audit"
	if w.Type != events.QuotaWarning || w.Severity != events.SeverityWarning || w.TenantID != string(tn.ID) ||
		w.AdminPath != path || w.Counts["usedRatio"] != 0.8 || w.Counts["threshold"] != 0.8 || len(w.Counts) != 2 ||
		w.OccurredAt.IsZero() || w.Addresses != nil {
		t.Errorf("warning event = %+v", w)
	}
	if r.Type != events.QuotaReached || r.Severity != events.SeverityCritical || r.TenantID != string(tn.ID) ||
		r.AdminPath != path || r.Counts["usedRatio"] != 1.2 || r.Counts["threshold"] != 1 {
		t.Errorf("reached event = %+v", r)
	}
}

// TestNoPublisher checks that a monitor built without publisher drops
// the events.
func TestNoPublisher(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), Options{})
	if ev.mon.events != events.Discard {
		t.Fatalf("monitor without publisher: %v", ev.mon.events)
	}
}

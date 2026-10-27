package avalert

import (
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestPublishesAlertEvents checks the events of a raised and cleared
// alert, with and without the count of the transfers waiting.
func TestPublishesAlertEvents(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), true)
	ev.admin(store.RoleSuperAdmin, "root@example.com", "en")
	ev.busy()
	ev.busy()
	ev.outage()
	ev.advance(time.Hour)
	ev.recover()
	raised := ev.published.OfType(events.AntivirusAlertRaised)
	cleared := ev.published.OfType(events.AntivirusAlertCleared)
	if len(raised) != 1 || len(cleared) != 1 || len(ev.published.Events()) != 2 {
		t.Fatalf("published %+v", ev.published.Events())
	}
	r := raised[0]
	if r.Severity != events.SeverityCritical || r.TenantID != "" || r.AdminPath != events.AdminPathSystem ||
		r.Counts["outageSeconds"] != 60 || r.Counts["waitingTransfers"] != 2 || len(r.Counts) != 2 ||
		r.OccurredAt.IsZero() || r.Addresses != nil {
		t.Errorf("raised event = %+v", r)
	}
	c := cleared[0]
	if c.Severity != events.SeverityInfo || c.Counts["outageSeconds"] != 3660 || len(c.Counts) != 1 ||
		c.AdminPath != events.AdminPathSystem {
		t.Errorf("cleared event = %+v", c)
	}

	// Unknown counts: the waiting transfers are left out.
	ev.fault.waitingErr = errBoom
	ev.advance(time.Hour)
	ev.outage()
	raised = ev.published.OfType(events.AntivirusAlertRaised)
	if len(raised) != 2 || len(raised[1].Counts) != 1 || raised[1].Counts["outageSeconds"] != 60 {
		t.Errorf("raised event with unknown counts = %+v", raised)
	}
}

// TestNoEventWithinGrace checks that an outage ending within the grace
// period publishes nothing, and that a monitor without publisher works.
func TestNoEventWithinGrace(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), false)
	ev.busy()
	ev.m.ClamdDown()
	ev.m.Evaluate(t.Context())
	ev.recover()
	if n := len(ev.published.Events()); n != 0 {
		t.Fatalf("published %d events for an outage within the grace period", n)
	}
	m, err := newMonitor(ev.fault, ev.auditor, Options{AdminLink: adminLink, Notifier: ev.notifier, TenantMailer: ev.tenants})
	if err != nil || m.events != events.Discard {
		t.Fatalf("monitor without publisher: %v, %v", m.events, err)
	}
}

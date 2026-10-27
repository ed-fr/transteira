package scan

import (
	"testing"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestPublishesVirusDetected checks that each infected file publishes one
// virus.detected event with the sender, once its status is recorded, and
// that a clean file publishes nothing.
func TestPublishesVirusDetected(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), Options{})
	trfID := ev.scanning(ev.a, clean(10), antivirustest.EICAR())
	ev.start()
	ev.waitStatus(ev.a, trfID, store.TransferAvailable)
	got := ev.published.Events()
	if len(got) != 1 {
		t.Fatalf("published %+v", got)
	}
	v := got[0]
	if v.Type != events.VirusDetected || v.Severity != events.SeverityCritical || v.TenantID != string(ev.a.ID) ||
		v.Counts["files"] != 1 || len(v.Counts) != 1 || v.Addresses == nil || v.Addresses.Sender != alice ||
		v.Addresses.Recipients != nil || v.AdminPath != events.AdminPathTenantAudit(string(ev.a.ID)) || v.OccurredAt.IsZero() {
		t.Errorf("virus event = %+v (addresses %+v)", v, v.Addresses)
	}
}

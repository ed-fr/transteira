package scan

import (
	"context"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// release releases the files waiting for a scan, as the start-up with the
// engine "none" does, and checks their number.
func (ev *env) release(want int) {
	ev.t.Helper()
	n, err := ev.db.TransferFiles().ReleaseAllUnscanned(context.Background())
	if err != nil || n != want {
		ev.t.Fatalf("ReleaseAllUnscanned = %d, %v; want %d", n, err, want)
	}
}

// checkDisabledMails checks the mails of a transfer whose files were
// delivered without analysis because the antivirus was disabled.
func checkDisabledMails(t *testing.T, jobs []mail.Job) {
	t.Helper()
	notScanned := byTemplate(jobs, mail.TemplateFileNotScanned)
	if len(notScanned) != 1 || !strings.Contains(notScanned[0].Message.Text, "Reason: the antivirus is disabled") {
		t.Fatalf("file_not_scanned mails %+v (templates %v)", notScanned, templates(jobs))
	}
	notifications := byTemplate(jobs, mail.TemplateTransferNotification)
	if len(notifications) == 0 {
		t.Fatalf("no recipient notification: %v", templates(jobs))
	}
	for _, j := range notifications {
		if !strings.Contains(j.Message.Text, "Not scanned: antivirus disabled.") {
			t.Errorf("recipient mail without the disabled flag:\n%s", j.Message.Text)
		}
	}
}

// TestDisabledFilesConcluded concludes a transfer whose files were released
// without analysis (finalized while the antivirus was off, or released at
// a start with the engine "none"): it becomes available without any scan,
// and the sender is told why. Turning the antivirus back on never rescans
// them.
func TestDisabledFilesConcluded(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		a, _ := ev.withAudit(nil)
		trfID := ev.scanning(ev.a, clean(10), clean(20))
		ev.release(2)
		if _, err := ev.db.Tenants().SetAntivirusEnabled(context.Background(), ev.a.ID, true); err != nil {
			t.Fatal(err)
		}
		ev.start()
		d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		for _, f := range d.Files {
			if f.ScanStatus != store.ScanNotScannedDisabled {
				t.Errorf("file %s status %s", f.ID, f.ScanStatus)
			}
		}
		if n := ev.scanner.count(); n != 0 || len(ev.clamd.Scans()) != 0 {
			t.Errorf("%d scans for released files", n)
		}
		checkDisabledMails(t, ev.waitJobs(4))
		// The worker records nothing more: the decision was audited when
		// it was taken.
		if events, _ := a.snapshot(); len(events) != 0 {
			t.Errorf("events %+v", events)
		}
	})
}

// TestWaitingFilesKeepWaiting scans the files that were waiting for the
// engine when the antivirus of their tenant was turned off (decision D8).
func TestWaitingFilesKeepWaiting(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.a, clean(10))
		if _, err := ev.db.Tenants().SetAntivirusEnabled(context.Background(), ev.a.ID, false); err != nil {
			t.Fatal(err)
		}
		ev.start()
		d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		if d.Files[0].ScanStatus != store.ScanClean || ev.scanner.count() != 1 {
			t.Errorf("file %s after %d scans", d.Files[0].ScanStatus, ev.scanner.count())
		}
	})
}

// TestEngineNone never contacts an engine: a file still waiting is
// recorded not_scanned_disabled at once, audited with reason disabled, and
// no outage is ever reported although clamd is down.
func TestEngineNone(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{Disabled: true})
		ev.w.scanner = nil
		a, _ := ev.withAudit(nil)
		ev.clamd.Stop()
		trfID := ev.scanning(ev.a, clean(10))
		ev.start()
		d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		if f := d.Files[0]; f.ScanStatus != store.ScanNotScannedDisabled || f.ScannedAt.IsZero() {
			t.Errorf("file %+v", f)
		}
		checkDisabledMails(t, ev.waitJobs(4))
		if !ev.w.Up() || ev.logs.count("antivirus unavailable: files stay unavailable until clamd answers again") != 0 {
			t.Errorf("outage reported with the engine none:\n%s", ev.logs.all())
		}
		events, _ := a.snapshot()
		if len(events) != 1 || events[0].Action != audit.ActionFileNotScanned ||
			events[0].Details["reason"] != audit.NotScannedDisabled || events[0].ObjectID != d.Files[0].ID {
			t.Errorf("events %+v", events)
		}
	})
}

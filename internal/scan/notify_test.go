package scan

import (
	"testing"

	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
)

// TestViewMapping maps every scan status to the result the mails show, and
// keeps notify's notion of a delivered file aligned with the store's.
func TestViewMapping(t *testing.T) {
	want := map[store.ScanStatus]notify.ScanResult{
		store.ScanPending:             notify.ScanWithheld,
		store.ScanScanning:            notify.ScanWithheld,
		store.ScanClean:               notify.ScanClean,
		store.ScanInfected:            notify.ScanInfected,
		store.ScanNotScannedTooLarge:  notify.ScanTooLarge,
		store.ScanNotScannedEncrypted: notify.ScanEncrypted,
		store.ScanError:               notify.ScanWithheld,
	}
	var d store.TransferDetails
	var statuses []store.ScanStatus
	for s := range want {
		statuses = append(statuses, s)
		d.Files = append(d.Files, store.TransferFile{Name: string(s), ScanStatus: s, ScanSignature: "sig-" + string(s)})
	}
	v := view(d)
	if len(v.Files) != len(statuses) {
		t.Fatalf("%d files in the view, want %d", len(v.Files), len(statuses))
	}
	for i, s := range statuses {
		f := v.Files[i]
		if f.Scan != want[s] {
			t.Errorf("%s mapped to %d, want %d", s, f.Scan, want[s])
		}
		if f.Scan.Delivered() != s.Deliverable() {
			t.Errorf("%s: notify delivered=%v, store deliverable=%v", s, f.Scan.Delivered(), s.Deliverable())
		}
		if (f.Signature != "") != (s == store.ScanInfected) {
			t.Errorf("%s: signature %q", s, f.Signature)
		}
	}
}

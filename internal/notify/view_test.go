package notify

import (
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
)

// TestViewOf maps every scan status to the result the mails show, and
// keeps the notion of a delivered file aligned with the store's.
func TestViewOf(t *testing.T) {
	want := map[store.ScanStatus]ScanResult{
		store.ScanPending:             ScanWithheld,
		store.ScanScanning:            ScanWithheld,
		store.ScanClean:               ScanClean,
		store.ScanInfected:            ScanInfected,
		store.ScanNotScannedTooLarge:  ScanTooLarge,
		store.ScanNotScannedEncrypted: ScanEncrypted,
		store.ScanError:               ScanWithheld,
	}
	exp := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	d := store.TransferDetails{
		Transfer: store.Transfer{
			ID: "trf_x", Language: "fr", SenderEmail: "alice@entity-a.example.com", Message: "m",
			ExpiresAt: exp, PasswordHash: "h",
		},
		Recipients: []string{"bob@customer.example.net"},
	}
	var statuses []store.ScanStatus
	for s := range want {
		statuses = append(statuses, s)
		d.Files = append(d.Files, store.TransferFile{Name: string(s), Size: 3, SHA256: "ab", ScanStatus: s, ScanSignature: "sig-" + string(s)})
	}
	v := ViewOf(d)
	if v.ID != "trf_x" || v.Language != "fr" || v.SenderEmail != d.SenderEmail || v.Message != "m" ||
		!v.ExpiresAt.Equal(exp) || !v.PasswordProtected || len(v.Recipients) != 1 || len(v.Files) != len(statuses) {
		t.Fatalf("view %+v", v)
	}
	for i, s := range statuses {
		f := v.Files[i]
		if f.Scan != want[s] || f.Name != string(s) || f.Size != 3 || f.SHA256 != "ab" {
			t.Errorf("%s mapped to %+v, want %d", s, f, want[s])
		}
		if f.Scan.Delivered() != s.Deliverable() {
			t.Errorf("%s: delivered=%v, store deliverable=%v", s, f.Scan.Delivered(), s.Deliverable())
		}
		if (f.Signature != "") != (s == store.ScanInfected) {
			t.Errorf("%s: signature %q", s, f.Signature)
		}
	}
}

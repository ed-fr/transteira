package scan

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// e2eScanning stores an end-to-end encrypted transfer of tn from alice to
// dave and erin, one file per content (stored as the upload engine does;
// the contents stand for TTE2 streams), and finalizes it: with released,
// as the transfer service does (its files get not_scanned_e2e), otherwise
// with the plain finalization, which leaves them pending.
func (ev *env) e2eScanning(tn *tenant.Tenant, released bool, contents ...[]byte) string {
	ev.t.Helper()
	ctx := context.Background()
	trfID := id.New(id.Transfer)
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		var files []store.TransferFile
		for i, c := range contents {
			f, err := ev.storeFile(ctx, tx, tn, c)
			if err != nil {
				return err
			}
			f.Name, f.E2EMetadata = fmt.Sprintf("file-%d.tte2", i+1), "bWV0YWRhdGE"
			files = append(files, f)
		}
		tr := store.Transfer{
			ID: trfID, SenderEmail: alice, SenderKind: store.DepositorInternal, ExpiryDays: 7,
			LinkMode: store.LinkModePerRecipient, E2E: true, E2EMessage: "bWVzc2FnZQ",
		}
		if err := ev.db.Transfers().CreateTx(ctx, tx, tr, []string{dave, erin}, files); err != nil {
			return err
		}
		if released {
			_, err := ev.db.Transfers().FinalizeE2ETx(ctx, tx, trfID, time.Now())
			return err
		}
		return ev.db.Transfers().FinalizeTx(ctx, tx, trfID, time.Now())
	})
	if err != nil {
		ev.t.Fatalf("e2e transfer: %v", err)
	}
	return trfID
}

// TestE2EConcluded concludes an end-to-end encrypted transfer without
// analyzing anything: available, its deposit proof flags the encryption,
// and the sender gets no "file not scanned" alert.
func TestE2EConcluded(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		a, _ := ev.withAudit(nil)
		trfID := ev.e2eScanning(ev.a, true, clean(100), clean(48))
		ev.start()
		d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		for _, f := range d.Files {
			if f.ScanStatus != store.ScanNotScannedE2E {
				t.Errorf("file %s status %s", f.ID, f.ScanStatus)
			}
		}
		if n := ev.scanner.count(); n != 0 || len(ev.clamd.Scans()) != 0 {
			t.Errorf("%d scans of encrypted files", n)
		}
		ev.waitIdle()
		jobs := ev.queue.snapshot()
		if len(byTemplate(jobs, mail.TemplateFileNotScanned)) != 0 {
			t.Errorf("file_not_scanned sent for an encrypted transfer: %v", templates(jobs))
		}
		if len(byTemplate(jobs, mail.TemplateTransferConfirmation)) != 1 {
			t.Errorf("no confirmation: %v", templates(jobs))
		}
		p, err := ev.depositOf(ev.a, trfID)
		if err != nil {
			t.Fatalf("deposit proof: %v", err)
		}
		if st := ev.verified(p); !st.EndToEndEncrypted || st.Files[0].Name != "file-1.tte2" ||
			st.Files[1].ScanStatus != string(store.ScanNotScannedE2E) {
			t.Errorf("statement = %+v", st)
		}
		// The worker records nothing: the decision was audited at the
		// finalization.
		if events, _ := a.snapshot(); len(events) != 0 {
			t.Errorf("events %+v", events)
		}
	})
}

// TestE2ENeverScanned leaves scanning, never analyzed nor delivered, an
// end-to-end encrypted transfer whose files were not released (which the
// finalization never does): its content never reaches an engine.
func TestE2ENeverScanned(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.e2eScanning(ev.a, false, clean(64))
		ev.start()
		ev.waitUntil("refusal logged", func() bool {
			return strings.Contains(ev.logs.all(), "end-to-end encrypted file without a final status")
		})
		ev.waitIdle()
		if d := ev.get(ev.a, trfID); d.Status != store.TransferScanning || d.Files[0].ScanStatus != store.ScanPending {
			t.Errorf("transfer %s, file %s", d.Status, d.Files[0].ScanStatus)
		}
		if n := ev.scanner.count(); n != 0 || len(ev.clamd.Scans()) != 0 {
			t.Errorf("%d scans of an encrypted file", n)
		}
		if jobs := ev.queue.snapshot(); len(jobs) != 0 {
			t.Errorf("mails %v", templates(jobs))
		}
	})
}

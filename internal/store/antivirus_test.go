package store_test

import (
	"context"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// completeTransfer creates an uploading transfer of tid whose files are
// completely uploaded, ready to be finalized.
func completeTransfer(t *testing.T, db *store.DB, tid tenant.ID, files int) store.TransferDetails {
	t.Helper()
	fs := make([]store.TransferFile, files)
	for i := range fs {
		fs[i] = newFile(t, db, tid, "f.bin", 10)
		fs[i].SHA256, fs[i].CiphertextSize, fs[i].UploadedAt = sha1111, 50, fixedNow
	}
	return mustTransfer(t, db, tid, newTransfer(), fs...)
}

// scanStatuses returns the scan status of each file of the transfer trfID.
func scanStatuses(t *testing.T, db *store.DB, tid tenant.ID, trfID string) []store.ScanStatus {
	t.Helper()
	files, err := db.TransferFiles().ListByTransfer(context.Background(), tid, trfID)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]store.ScanStatus, len(files))
	for i, f := range files {
		out[i] = f.ScanStatus
		if f.ScanStatus == store.ScanNotScannedDisabled && !f.ScannedAt.Equal(msNow) {
			t.Errorf("file %s scanned at %v, want %v", f.ID, f.ScannedAt, msNow)
		}
	}
	return out
}

// wantStatuses checks that every status of got is want.
func wantStatuses(t *testing.T, what string, got []store.ScanStatus, want store.ScanStatus) {
	t.Helper()
	for i, s := range got {
		if s != want {
			t.Errorf("%s: file %d status %q, want %q", what, i, s, want)
		}
	}
}

func TestFinalizeUnscanned(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		da := completeTransfer(t, db, a.ID, 2)
		db2 := completeTransfer(t, db, b.ID, 1)
		finalize := func(tid tenant.ID, trfID string) (int, error) {
			var n int
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				n, err = db.Transfers().FinalizeUnscannedTx(ctx, tx, trfID, fixedNow)
				return err
			})
			return n, err
		}

		// Another tenant's transfer is unknown in the scope of a.
		_, err := finalize(a.ID, db2.ID)
		wantErr(t, "FinalizeUnscannedTx(other tenant)", err, store.ErrNotFound)
		wantStatuses(t, "tenant b", scanStatuses(t, db, b.ID, db2.ID), store.ScanPending)

		n, err := finalize(a.ID, da.ID)
		if err != nil || n != 2 {
			t.Fatalf("FinalizeUnscannedTx = %d, %v; want 2", n, err)
		}
		got, err := db.Transfers().Get(ctx, a.ID, da.ID)
		if err != nil || got.Status != store.TransferScanning {
			t.Fatalf("transfer = %+v, %v; want scanning", got.Transfer, err)
		}
		wantStatuses(t, "finalized", scanStatuses(t, db, a.ID, da.ID), store.ScanNotScannedDisabled)
		for _, f := range got.Files {
			if !f.ScanStatus.Deliverable() {
				t.Errorf("file %s not deliverable", f.ID)
			}
		}

		// Finalizing twice is a conflict, and changes nothing.
		_, err = finalize(a.ID, da.ID)
		wantErr(t, "FinalizeUnscannedTx twice", err, store.ErrConflict)
		// A final status is final for the antivirus worker too.
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return db.TransferFiles().SetScanResultTx(ctx, tx, got.Files[0].ID, store.ScanClean, "", fixedNow)
		})
		wantErr(t, "SetScanResultTx(disabled)", err, store.ErrConflict)
		// The other tenant is untouched.
		wantStatuses(t, "tenant b after", scanStatuses(t, db, b.ID, db2.ID), store.ScanPending)
	})
}

func TestReleaseAllUnscanned(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		files := db.TransferFiles()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		// a: one file being scanned and one pending; another transfer with
		// a clean file and a pending one; b: one pending file; b: an
		// uploading transfer, never released.
		a1 := scanningTransfer(t, db, a.ID, fixedNow, 2)
		a2 := scanningTransfer(t, db, a.ID, fixedNow, 2)
		b1 := scanningTransfer(t, db, b.ID, fixedNow, 1)
		up := completeTransfer(t, db, b.ID, 1)
		err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			if err := files.SetScanningTx(ctx, tx, a1.Files[0].ID); err != nil {
				return err
			}
			return files.SetScanResultTx(ctx, tx, a2.Files[0].ID, store.ScanClean, "", fixedNow)
		})
		if err != nil {
			t.Fatal(err)
		}

		n, err := files.ReleaseAllUnscanned(ctx)
		if err != nil || n != 4 {
			t.Fatalf("ReleaseAllUnscanned = %d, %v; want 4", n, err)
		}
		wantStatuses(t, "a1", scanStatuses(t, db, a.ID, a1.ID), store.ScanNotScannedDisabled)
		if got := scanStatuses(t, db, a.ID, a2.ID); got[0] != store.ScanClean || got[1] != store.ScanNotScannedDisabled {
			t.Errorf("a2 = %v", got)
		}
		wantStatuses(t, "b1", scanStatuses(t, db, b.ID, b1.ID), store.ScanNotScannedDisabled)
		wantStatuses(t, "uploading", scanStatuses(t, db, b.ID, up.ID), store.ScanPending)
		// The transfers stay scanning: the worker concludes them.
		if got, err := db.Transfers().Get(ctx, a.ID, a1.ID); err != nil || got.Status != store.TransferScanning {
			t.Errorf("a1 = %+v, %v", got.Transfer, err)
		}

		// Nothing left to release.
		if n, err := files.ReleaseAllUnscanned(ctx); err != nil || n != 0 {
			t.Errorf("ReleaseAllUnscanned again = %d, %v; want 0", n, err)
		}
	})
}

func TestTenantsAntivirusEnabled(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Tenants()

		// A new tenant always starts with its antivirus enabled.
		a, err := repo.Create(ctx, &tenant.Tenant{
			Name: "Entity A", FQDN: "transfer.entity-a.example.com", DefaultLanguage: "fr",
			MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30, AntivirusEnabled: false,
		})
		if err != nil || !a.AntivirusEnabled {
			t.Fatalf("Create = %+v, %v", a, err)
		}
		b := newTenant(t, db, "transfer.entity-b.example.com")
		if got, err := repo.Get(ctx, a.ID); err != nil || !got.AntivirusEnabled {
			t.Fatalf("Get = %+v, %v", got, err)
		}

		off, err := repo.SetAntivirusEnabled(ctx, a.ID, false)
		if err != nil || off.AntivirusEnabled || off.ID != a.ID {
			t.Fatalf("SetAntivirusEnabled(false) = %+v, %v", off, err)
		}
		if got, err := repo.TenantByFQDN(ctx, a.FQDN); err != nil || got.AntivirusEnabled {
			t.Errorf("TenantByFQDN = %+v, %v", got, err)
		}
		// Only that tenant changed.
		if got, err := repo.Get(ctx, b.ID); err != nil || !got.AntivirusEnabled {
			t.Errorf("other tenant = %+v, %v", got, err)
		}
		page, err := repo.List(ctx, store.TenantListOptions{})
		if err != nil || len(page.Items) != 2 {
			t.Fatalf("List = %+v, %v", page, err)
		}
		for _, tn := range page.Items {
			if tn.AntivirusEnabled != (tn.ID == b.ID) {
				t.Errorf("listed %s antivirus %v", tn.ID, tn.AntivirusEnabled)
			}
		}

		// Update leaves the switch alone.
		next := off.Clone()
		next.Name, next.AntivirusEnabled = "Entity A2", true
		if got, err := repo.Update(ctx, next); err != nil || got.AntivirusEnabled || got.Name != "Entity A2" {
			t.Errorf("Update = %+v, %v", got, err)
		}

		if on, err := repo.SetAntivirusEnabled(ctx, a.ID, true); err != nil || !on.AntivirusEnabled {
			t.Errorf("SetAntivirusEnabled(true) = %+v, %v", on, err)
		}

		_, err = repo.SetAntivirusEnabled(ctx, "ten_01JAB00000000000000000000X", false)
		wantErr(t, "SetAntivirusEnabled(unknown)", err, store.ErrNotFound)
		_, err = repo.SetAntivirusEnabled(ctx, "bogus", false)
		wantErr(t, "SetAntivirusEnabled(malformed)", err, store.ErrNotFound)
		if err := repo.SetStatus(ctx, b.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		_, err = repo.SetAntivirusEnabled(ctx, b.ID, false)
		wantErr(t, "SetAntivirusEnabled(deleting)", err, store.ErrNotFound)
	})
}

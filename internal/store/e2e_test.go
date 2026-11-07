package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// e2eFile returns a valid file of an end-to-end encrypted transfer, with
// its generic name and encrypted metadata; complete when uploaded is set.
func e2eFile(t *testing.T, db *store.DB, tid tenant.ID, n int, uploaded bool) store.TransferFile {
	t.Helper()
	f := newFile(t, db, tid, "file-"+string(rune('0'+n))+".tte2", 64)
	f.MediaType, f.E2EMetadata = "", "AbC1_dEf2-gHi3JkLmNoPqRsTuVwXyZ0"
	if uploaded {
		f.SHA256, f.CiphertextSize, f.UploadedAt = sha1111, 128, fixedNow
	}
	return f
}

// e2eTransfer returns a valid end-to-end encrypted internal transfer.
func e2eTransfer() store.Transfer {
	tr := newTransfer()
	tr.Message, tr.E2E, tr.E2EMessage = "", true, "bWVzc2FnZQ-_"
	return tr
}

func TestTransfersE2ERoundTrip(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")

		d := mustTransfer(t, db, a.ID, e2eTransfer(), e2eFile(t, db, a.ID, 1, true), e2eFile(t, db, a.ID, 2, false))
		if !d.E2E || d.E2EMessage != "bWVzc2FnZQ-_" || d.Message != "" {
			t.Fatalf("E2E transfer read back = %+v", d.Transfer)
		}
		for _, f := range d.Files {
			if f.E2EMetadata != "AbC1_dEf2-gHi3JkLmNoPqRsTuVwXyZ0" {
				t.Errorf("file %s metadata = %q", f.ID, f.E2EMetadata)
			}
		}
		// The other readers scan the same columns.
		up, err := db.TransferFiles().GetByUploadID(ctx, a.ID, d.Files[1].UploadID)
		if err != nil || !up.Transfer.E2E || up.File.E2EMetadata == "" {
			t.Errorf("GetByUploadID = %+v, %v", up, err)
		}

		// Without an encrypted message, the column is NULL and reads "".
		tr := e2eTransfer()
		tr.E2EMessage = ""
		d2 := mustTransfer(t, db, a.ID, tr, e2eFile(t, db, a.ID, 1, true))
		if !d2.E2E || d2.E2EMessage != "" {
			t.Errorf("E2E transfer without message = %+v", d2.Transfer)
		}

		// An ordinary transfer has neither.
		d3 := mustTransfer(t, db, a.ID, newTransfer())
		if d3.E2E || d3.E2EMessage != "" || d3.Files[0].E2EMetadata != "" {
			t.Errorf("ordinary transfer = %+v", d3)
		}
	})
}

func TestTransfersE2ECreateErrors(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		create := func(tr store.Transfer, files ...store.TransferFile) error {
			return inTx(t, db, a.ID, func(tx *store.ScopedTx) error { //nolint:contextcheck // the test context is captured on purpose
				return db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@partner.example.org"}, files)
			})
		}
		for _, c := range []struct {
			name  string
			edit  func(*store.Transfer)
			files func() []store.TransferFile
		}{
			{"plaintext message", func(tr *store.Transfer) { tr.Message = "hello" }, nil},
			{"encrypted message without e2e", func(tr *store.Transfer) { tr.E2E = false }, func() []store.TransferFile {
				return []store.TransferFile{newFile(t, db, a.ID, "a.pdf", 1)}
			}},
			{"encrypted message not base64url", func(tr *store.Transfer) { tr.E2EMessage = "a+b/c=" }, nil},
			{"encrypted message too long", func(tr *store.Transfer) {
				tr.E2EMessage = strings.Repeat("A", store.MaxE2EMessageLen+1)
			}, nil},
			{"drop link sender", func(tr *store.Transfer) {
				tr.SenderKind, tr.DropLinkID = store.DepositorDropLink, id.New(id.DropLink)
			}, nil},
			{"file without metadata", nil, func() []store.TransferFile {
				f := e2eFile(t, db, a.ID, 1, false)
				f.E2EMetadata = ""
				return []store.TransferFile{e2eFile(t, db, a.ID, 1, false), f}
			}},
			{"metadata too long", nil, func() []store.TransferFile {
				f := e2eFile(t, db, a.ID, 1, false)
				f.E2EMetadata = strings.Repeat("A", store.MaxE2EMetadataLen+1)
				return []store.TransferFile{f}
			}},
			{"metadata not base64url", nil, func() []store.TransferFile {
				f := e2eFile(t, db, a.ID, 1, false)
				f.E2EMetadata = "abc="
				return []store.TransferFile{f}
			}},
			{"metadata on an ordinary transfer", func(tr *store.Transfer) { tr.E2E, tr.E2EMessage = false, "" }, nil},
		} {
			tr := e2eTransfer()
			if c.edit != nil {
				c.edit(&tr)
			}
			files := []store.TransferFile{e2eFile(t, db, a.ID, 1, false)}
			if c.files != nil {
				files = c.files()
			}
			wantErr(t, c.name, create(tr, files...), store.ErrInvalid)
		}
		// The limits themselves are accepted.
		tr := e2eTransfer()
		tr.E2EMessage = strings.Repeat("A", store.MaxE2EMessageLen)
		f := e2eFile(t, db, a.ID, 1, false)
		f.E2EMetadata = strings.Repeat("_", store.MaxE2EMetadataLen)
		if err := create(tr, f); err != nil {
			t.Errorf("CreateTx(at the limits) = %v", err)
		}
	})
}

func TestFinalizeE2E(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		da := mustTransfer(t, db, a.ID, e2eTransfer(), e2eFile(t, db, a.ID, 1, true), e2eFile(t, db, a.ID, 2, true))
		db2 := mustTransfer(t, db, b.ID, e2eTransfer(), e2eFile(t, db, b.ID, 1, true))
		plain := completeTransfer(t, db, a.ID, 1)
		finalize := func(tid tenant.ID, trfID string) (int, error) {
			var n int
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				n, err = db.Transfers().FinalizeE2ETx(ctx, tx, trfID, fixedNow)
				return err
			})
			return n, err
		}

		// Another tenant's transfer is unknown in the scope of a.
		_, err := finalize(a.ID, db2.ID)
		wantErr(t, "FinalizeE2ETx(other tenant)", err, store.ErrNotFound)
		wantStatuses(t, "tenant b", scanStatuses(t, db, b.ID, db2.ID), store.ScanPending)
		// An ordinary transfer is refused and stays uploading.
		_, err = finalize(a.ID, plain.ID)
		wantErr(t, "FinalizeE2ETx(not e2e)", err, store.ErrInvalid)
		if got, err := db.Transfers().Get(ctx, a.ID, plain.ID); err != nil || got.Status != store.TransferUploading {
			t.Errorf("ordinary transfer = %+v, %v", got.Transfer, err)
		}

		n, err := finalize(a.ID, da.ID)
		if err != nil || n != 2 {
			t.Fatalf("FinalizeE2ETx = %d, %v; want 2", n, err)
		}
		got, err := db.Transfers().Get(ctx, a.ID, da.ID)
		if err != nil || got.Status != store.TransferScanning {
			t.Fatalf("transfer = %+v, %v; want scanning", got.Transfer, err)
		}
		for _, f := range got.Files {
			if f.ScanStatus != store.ScanNotScannedE2E || !f.ScannedAt.Equal(msNow) || !f.ScanStatus.Deliverable() {
				t.Errorf("file %s = %q at %v", f.ID, f.ScanStatus, f.ScannedAt)
			}
		}
		// Finalizing twice is a conflict; the worker cannot change the
		// status, nor record it for another file.
		_, err = finalize(a.ID, da.ID)
		wantErr(t, "FinalizeE2ETx twice", err, store.ErrConflict)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return db.TransferFiles().SetScanResultTx(ctx, tx, got.Files[0].ID, store.ScanClean, "", fixedNow)
		})
		wantErr(t, "SetScanResultTx(e2e)", err, store.ErrConflict)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return db.TransferFiles().SetScanResultTx(ctx, tx, plain.Files[0].ID, store.ScanNotScannedE2E, "", fixedNow)
		})
		wantErr(t, "SetScanResultTx(not_scanned_e2e)", err, store.ErrInvalid)
		wantStatuses(t, "tenant b after", scanStatuses(t, db, b.ID, db2.ID), store.ScanPending)
	})
}

func TestTenantsE2EPolicy(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Tenants()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		if a.E2EPolicy != tenant.E2EForbidden {
			t.Fatalf("new tenant policy = %q", a.E2EPolicy)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || got.E2EPolicy != tenant.E2EForbidden {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		got, err := repo.SetE2EPolicy(ctx, a.ID, tenant.E2ERequired)
		if err != nil || got.E2EPolicy != tenant.E2ERequired {
			t.Fatalf("SetE2EPolicy = %+v, %v", got, err)
		}
		// The general update never writes it.
		upd := got.Clone()
		upd.Name, upd.E2EPolicy = "Renamed", tenant.E2EAllowed
		if got, err := repo.Update(ctx, upd); err != nil || got.E2EPolicy != tenant.E2ERequired || got.Name != "Renamed" {
			t.Errorf("Update = %+v, %v", got, err)
		}
		// UpdateWithPolicies writes the selected parts together.
		upd.Name = "Again"
		got, err = repo.UpdateWithPolicies(ctx, upd, store.TenantParts{General: true, E2E: true})
		if err != nil || got.E2EPolicy != tenant.E2EAllowed || got.Name != "Again" {
			t.Errorf("UpdateWithPolicies = %+v, %v", got, err)
		}
		// An unknown policy changes nothing.
		_, err = repo.SetE2EPolicy(ctx, a.ID, "maybe")
		wantErr(t, "SetE2EPolicy(unknown)", err, store.ErrInvalid)
		_, err = repo.SetE2EPolicy(ctx, a.ID, "")
		wantErr(t, "SetE2EPolicy(empty)", err, store.ErrInvalid)
		upd.Name, upd.E2EPolicy = "Never", "maybe"
		_, err = repo.UpdateWithPolicies(ctx, upd, store.TenantParts{General: true, E2E: true})
		wantErr(t, "UpdateWithPolicies(unknown)", err, store.ErrInvalid)
		if got, err := repo.Get(ctx, a.ID); err != nil || got.E2EPolicy != tenant.E2EAllowed || got.Name != "Again" {
			t.Errorf("Get = %+v, %v", got, err)
		}
		_, err = repo.SetE2EPolicy(ctx, "bogus", tenant.E2EAllowed)
		wantErr(t, "SetE2EPolicy(bad id)", err, store.ErrNotFound)
		_, err = repo.SetE2EPolicy(ctx, tenant.ID(id.New(id.Tenant)), tenant.E2EAllowed)
		wantErr(t, "SetE2EPolicy(missing)", err, store.ErrNotFound)

		// Create stores the value given, and refuses an unknown one.
		base := tenant.Tenant{
			SetupState: tenant.SetupStateActive, Name: "C", FQDN: "transfer.entity-c.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1, StorageQuotaBytes: 1, E2EPolicy: tenant.E2EAllowed,
		}
		c, err := repo.Create(ctx, &base)
		if err != nil || c.E2EPolicy != tenant.E2EAllowed {
			t.Errorf("Create(allowed) = %+v, %v", c, err)
		}
		base.FQDN, base.E2EPolicy = "transfer.entity-d.example.com", "maybe"
		_, err = repo.Create(ctx, &base)
		wantErr(t, "Create(unknown policy)", err, store.ErrInvalid)

		// A deleting tenant is not found.
		if err := repo.SetStatus(ctx, c.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		_, err = repo.SetE2EPolicy(ctx, c.ID, tenant.E2ERequired)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetE2EPolicy(deleting) = %v, want ErrNotFound", err)
		}
	})
}

func TestConfidentialityLevelsE2EPolicy(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		levels := db.ConfidentialityLevels()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		cur, err := levels.List(ctx, a.ID)
		if err != nil || len(cur) != 3 {
			t.Fatalf("List = %+v, %v", cur, err)
		}
		for _, l := range cur {
			if l.E2EPolicy != nil {
				t.Errorf("seeded level %s has policy %q", l.Key, *l.E2EPolicy)
			}
		}
		required, forbidden := tenant.E2ERequired, tenant.E2EForbidden
		cur[1].E2EPolicy, cur[2].E2EPolicy = &forbidden, &required
		saved, err := levels.Replace(ctx, a.ID, cur, "admin", fixedNow)
		if err != nil || saved[0].E2EPolicy != nil || *saved[1].E2EPolicy != forbidden || *saved[2].E2EPolicy != required {
			t.Fatalf("Replace = %+v, %v", saved, err)
		}
		// The result does not alias the input.
		forbidden = tenant.E2EAllowed
		if *saved[1].E2EPolicy != tenant.E2EForbidden {
			t.Error("Replace aliases the policy of its input")
		}
		got, err := levels.Get(ctx, a.ID, cur[2].Key)
		if err != nil || got.E2EPolicy == nil || *got.E2EPolicy != tenant.E2ERequired {
			t.Errorf("Get = %+v, %v", got, err)
		}
		// The other tenant keeps its own levels.
		other, err := levels.List(ctx, b.ID)
		if err != nil || other[2].E2EPolicy != nil {
			t.Errorf("tenant b levels = %+v, %v", other, err)
		}

		bad := tenant.E2EPolicy("maybe")
		cur[0].E2EPolicy = &bad
		_, err = levels.Replace(ctx, a.ID, cur, "admin", fixedNow)
		wantErr(t, "Replace(unknown policy)", err, store.ErrInvalid)
	})
}

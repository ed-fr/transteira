package store_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// newDownloadToken returns a new download token and its hash.
func newDownloadToken(t *testing.T) (string, []byte) {
	t.Helper()
	tok, err := id.NewDownloadToken()
	if err != nil {
		t.Fatal(err)
	}
	return tok, tokenHash(tok)
}

// markAvailable makes the scanning transfer trfID of tid available at
// fixedNow with a new download token and sealed key, and returns the token
// hash and the key ID.
func markAvailable(t *testing.T, db *store.DB, tid tenant.ID, trfID string) (hash []byte, keyID string) {
	t.Helper()
	_, hash = newDownloadToken(t)
	keyID = mustSecret(t, db, tid, store.KeyPurposeSecret)
	err := inTx(t, db, tid, func(tx *store.ScopedTx) error {
		return db.Transfers().MarkAvailableTx(context.Background(), tx, trfID, hash, keyID, fixedNow)
	})
	if err != nil {
		t.Fatalf("MarkAvailableTx: %v", err)
	}
	return hash, keyID
}

// scanningTransfer creates a finalized (scanning) transfer of tid at
// finalized, whose files are complete.
func scanningTransfer(t *testing.T, db *store.DB, tid tenant.ID, finalized time.Time, files int) store.TransferDetails {
	t.Helper()
	ctx := context.Background()
	fs := make([]store.TransferFile, files)
	for i := range fs {
		fs[i] = newFile(t, db, tid, "f.bin", 10)
		fs[i].SHA256, fs[i].CiphertextSize, fs[i].UploadedAt = sha1111, 50, fixedNow
	}
	d := mustTransfer(t, db, tid, newTransfer(), fs...)
	if err := inTx(t, db, tid, func(tx *store.ScopedTx) error { return db.Transfers().FinalizeTx(ctx, tx, d.ID, finalized) }); err != nil {
		t.Fatalf("FinalizeTx: %v", err)
	}
	d, err := db.Transfers().Get(ctx, tid, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTransferFilesScan(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		files := db.TransferFiles()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		tx := func(fn func(*store.ScopedTx) error) error { return inTx(t, db, a.ID, fn) }
		d := scanningTransfer(t, db, a.ID, fixedNow, 3)
		fa, fb, fc := d.Files[0], d.Files[1], d.Files[2]
		if fa.ScanStatus != store.ScanPending || !fa.ScannedAt.IsZero() || fa.ScanSignature != "" || fa.ScanAttempts != 0 {
			t.Fatalf("new file = %+v", fa)
		}
		setScanning := func(fileID string) error {
			return tx(func(tx *store.ScopedTx) error { return files.SetScanningTx(ctx, tx, fileID) })
		}
		setResult := func(fileID string, s store.ScanStatus, sig string) error {
			return tx(func(tx *store.ScopedTx) error { return files.SetScanResultTx(ctx, tx, fileID, s, sig, fixedNow) })
		}

		// pending -> scanning, twice (resumption after a restart).
		for range 2 {
			if err := setScanning(fa.ID); err != nil {
				t.Fatalf("SetScanningTx: %v", err)
			}
		}
		wantErr(t, "SetScanningTx(missing)", setScanning(id.New(id.File)), store.ErrNotFound)

		// File-specific failures are counted.
		for want := 1; want <= 2; want++ {
			if n, err := files.IncrementScanAttempt(ctx, a.ID, fa.ID); err != nil || n != want {
				t.Errorf("IncrementScanAttempt = %d, %v; want %d", n, err, want)
			}
		}
		_, err := files.IncrementScanAttempt(ctx, a.ID, id.New(id.File))
		wantErr(t, "IncrementScanAttempt(missing)", err, store.ErrNotFound)
		_, err = files.IncrementScanAttempt(ctx, "bogus", fa.ID)
		wantErr(t, "IncrementScanAttempt(bad tenant)", err, store.ErrInvalid)

		// Final results: from scanning, and directly from pending.
		sig := "Win.Test.EICAR_HDB-1"
		if err := setResult(fa.ID, store.ScanInfected, sig); err != nil {
			t.Fatalf("SetScanResultTx(infected): %v", err)
		}
		if err := setResult(fb.ID, store.ScanNotScannedTooLarge, ""); err != nil {
			t.Fatalf("SetScanResultTx(too large): %v", err)
		}
		got, err := files.ListByTransfer(ctx, a.ID, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if f := got[0]; f.ScanStatus != store.ScanInfected || f.ScanSignature != sig || !f.ScannedAt.Equal(msNow) || f.ScanAttempts != 2 {
			t.Errorf("infected file = %+v", f)
		}
		if f := got[1]; f.ScanStatus != store.ScanNotScannedTooLarge || f.ScanSignature != "" || !f.ScannedAt.Equal(msNow) {
			t.Errorf("too large file = %+v", f)
		}
		if f := got[2]; f.ScanStatus != store.ScanPending || !f.ScannedAt.IsZero() {
			t.Errorf("untouched file = %+v", f)
		}

		// Erasing an infected file destroys its data key (what the upload
		// engine's RemoveFiles does first): the row stays, without key.
		if err := db.WrappedKeys().Delete(ctx, a.ID, fa.DEKKeyID); err != nil {
			t.Fatal(err)
		}
		if got, err := files.ListByTransfer(ctx, a.ID, d.ID); err != nil || got[0].DEKKeyID != "" ||
			got[0].ScanStatus != store.ScanInfected || got[0].ScanSignature != sig {
			t.Errorf("erased infected file = %+v, %v", got[0], err)
		}

		// An encrypted archive is recorded as not scanned.
		enc := scanningTransfer(t, db, a.ID, fixedNow, 1).Files[0]
		if err := setResult(enc.ID, store.ScanNotScannedEncrypted, ""); err != nil {
			t.Fatalf("SetScanResultTx(encrypted): %v", err)
		}
		wantErr(t, "SetScanResultTx(encrypted signature)", setResult(fc.ID, store.ScanNotScannedEncrypted, sig), store.ErrInvalid)

		// A final status is final.
		wantErr(t, "SetScanResultTx twice", setResult(fa.ID, store.ScanClean, ""), store.ErrConflict)
		wantErr(t, "SetScanningTx(final)", setScanning(fa.ID), store.ErrConflict)
		_, err = files.IncrementScanAttempt(ctx, a.ID, fa.ID)
		wantErr(t, "IncrementScanAttempt(final)", err, store.ErrConflict)
		wantErr(t, "SetScanResultTx(missing)", setResult(id.New(id.File), store.ScanClean, ""), store.ErrNotFound)

		// Malformed results.
		for name, c := range map[string]struct {
			status store.ScanStatus
			sig    string
		}{
			"pending":           {store.ScanPending, ""},
			"scanning":          {store.ScanScanning, ""},
			"unknown":           {"bogus", ""},
			"clean signature":   {store.ScanClean, sig},
			"error signature":   {store.ScanError, sig},
			"long signature":    {store.ScanInfected, strings.Repeat("é", store.MaxScanSignatureBytes/2+1)},
			"control signature": {store.ScanInfected, "Win.Test\nX"},
			"invalid utf-8":     {store.ScanInfected, "\xff"},
		} {
			wantErr(t, "SetScanResultTx("+name+")", setResult(fc.ID, c.status, c.sig), store.ErrInvalid)
		}
		if err := setResult(fc.ID, store.ScanInfected, strings.Repeat("s", store.MaxScanSignatureBytes)); err != nil {
			t.Errorf("SetScanResultTx(longest signature): %v", err)
		}

		// An incomplete file cannot be scanned.
		up := mustTransfer(t, db, a.ID, newTransfer())
		inc := up.Files[0]
		wantErr(t, "SetScanningTx(incomplete)", setScanning(inc.ID), store.ErrConflict)
		wantErr(t, "SetScanResultTx(incomplete)", setResult(inc.ID, store.ScanClean, ""), store.ErrConflict)
		if n, err := files.IncrementScanAttempt(ctx, a.ID, inc.ID); err != nil || n != 1 {
			t.Errorf("IncrementScanAttempt(incomplete) = %d, %v", n, err)
		}

		// A new file carries no scan result.
		for name, mut := range map[string]func(*store.TransferFile){
			"scanned at": func(f *store.TransferFile) { f.ScannedAt = fixedNow },
			"signature":  func(f *store.TransferFile) { f.ScanSignature = sig },
			"attempts":   func(f *store.TransferFile) { f.ScanAttempts = 1 },
		} {
			f := newFile(t, db, a.ID, "x.bin", 1)
			mut(&f)
			err := tx(func(tx *store.ScopedTx) error {
				return db.Transfers().CreateTx(ctx, tx, newTransfer(), []string{"bob@partner.example.org"}, []store.TransferFile{f})
			})
			wantErr(t, "CreateTx(file "+name+")", err, store.ErrInvalid)
		}
	})
}

func TestTransfersAvailability(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers, keys := db.Transfers(), db.WrappedKeys()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		tx := func(fn func(*store.ScopedTx) error) error { return inTx(t, db, a.ID, fn) }
		mark := func(trfID string, hash []byte, keyID string) error {
			return tx(func(tx *store.ScopedTx) error {
				return transfers.MarkAvailableTx(ctx, tx, trfID, hash, keyID, fixedNow)
			})
		}
		// Finalized two days before it becomes available.
		d := scanningTransfer(t, db, a.ID, fixedNow.Add(-48*time.Hour), 1)
		_, hash := newDownloadToken(t)
		secret := mustSecret(t, db, a.ID, store.KeyPurposeSecret)

		wantErr(t, "MarkAvailableTx(short hash)", mark(d.ID, hash[:31], secret), store.ErrInvalid)
		wantErr(t, "MarkAvailableTx(bad key id)", mark(d.ID, hash, "wk_x"), store.ErrInvalid)
		wantErr(t, "MarkAvailableTx(data key)", mark(d.ID, hash, d.Files[0].DEKKeyID), store.ErrInvalid)
		wantErr(t, "MarkAvailableTx(missing key)", mark(d.ID, hash, id.New(id.WrappedKey)), store.ErrNotFound)
		wantErr(t, "MarkAvailableTx(B's key)", mark(d.ID, hash, mustSecret(t, db, b.ID, store.KeyPurposeSecret)), store.ErrNotFound)
		wantErr(t, "MarkAvailableTx(missing transfer)", mark(id.New(id.Transfer), hash, secret), store.ErrNotFound)
		up := mustTransfer(t, db, a.ID, newTransfer())
		wantErr(t, "MarkAvailableTx(uploading)", mark(up.ID, hash, secret), store.ErrConflict)

		if err := mark(d.ID, hash, secret); err != nil {
			t.Fatalf("MarkAvailableTx: %v", err)
		}
		got, err := transfers.GetByDownloadTokenHash(ctx, a.ID, hash)
		if err != nil || got.ID != d.ID || got.Status != store.TransferAvailable || !reflect.DeepEqual(got.DownloadTokenHash, hash) ||
			got.DownloadTokenKeyID != secret || !got.AvailableAt.Equal(msNow) || len(got.Files) != 1 || len(got.Recipients) != 2 {
			t.Errorf("GetByDownloadTokenHash = %+v, %v", got, err)
		}
		// The expiry restarts from the availability.
		if want := msNow.Add(time.Duration(got.ExpiryDays) * 24 * time.Hour); !got.ExpiresAt.Equal(want) || got.FinalizedAt.Equal(msNow) {
			t.Errorf("expires at %v (finalized %v), want %v", got.ExpiresAt, got.FinalizedAt, want)
		}
		wantErr(t, "MarkAvailableTx twice", mark(d.ID, tokenHash("other"), mustSecret(t, db, a.ID, store.KeyPurposeSecret)), store.ErrConflict)

		// A token hash or a sealed key serves one transfer only.
		d2 := scanningTransfer(t, db, a.ID, fixedNow, 1)
		wantErr(t, "MarkAvailableTx(hash in use)", mark(d2.ID, hash, mustSecret(t, db, a.ID, store.KeyPurposeSecret)), store.ErrConflict)
		wantErr(t, "MarkAvailableTx(key in use)", mark(d2.ID, tokenHash("other"), secret), store.ErrConflict)
		d3 := scanningTransfer(t, db, b.ID, fixedNow, 1)
		secretB := mustSecret(t, db, b.ID, store.KeyPurposeSecret)
		err = inTx(t, db, b.ID, func(tx *store.ScopedTx) error {
			return transfers.MarkAvailableTx(ctx, tx, d3.ID, hash, secretB, fixedNow)
		})
		wantErr(t, "MarkAvailableTx(hash of another tenant)", err, store.ErrConflict)

		// Lookups.
		_, err = transfers.GetByDownloadTokenHash(ctx, a.ID, tokenHash("unknown"))
		wantErr(t, "GetByDownloadTokenHash(unknown)", err, store.ErrNotFound)
		_, err = transfers.GetByDownloadTokenHash(ctx, b.ID, hash)
		wantErr(t, "GetByDownloadTokenHash(from B)", err, store.ErrNotFound)
		_, err = transfers.GetByDownloadTokenHash(ctx, a.ID, hash[:8])
		wantErr(t, "GetByDownloadTokenHash(short)", err, store.ErrInvalid)
		_, err = transfers.GetByDownloadTokenHash(ctx, "bogus", hash)
		wantErr(t, "GetByDownloadTokenHash(bad tenant)", err, store.ErrInvalid)

		// Rejection.
		reject := func(trfID string) error {
			return tx(func(tx *store.ScopedTx) error { return transfers.MarkRejectedTx(ctx, tx, trfID) })
		}
		if err := reject(d2.ID); err != nil {
			t.Fatalf("MarkRejectedTx: %v", err)
		}
		if got, err := transfers.Get(ctx, a.ID, d2.ID); err != nil || got.Status != store.TransferRejected ||
			got.DownloadTokenHash != nil || !got.AvailableAt.IsZero() {
			t.Errorf("rejected transfer = %+v, %v", got.Transfer, err)
		}
		wantErr(t, "MarkRejectedTx twice", reject(d2.ID), store.ErrConflict)
		wantErr(t, "MarkRejectedTx(available)", reject(d.ID), store.ErrConflict)
		wantErr(t, "MarkRejectedTx(missing)", reject(id.New(id.Transfer)), store.ErrNotFound)

		// A new transfer carries no download link.
		for name, mut := range map[string]func(*store.Transfer){
			"hash":         func(t *store.Transfer) { t.DownloadTokenHash = hash },
			"key":          func(t *store.Transfer) { t.DownloadTokenKeyID = secret },
			"available at": func(t *store.Transfer) { t.AvailableAt = fixedNow },
		} {
			tr := newTransfer()
			mut(&tr)
			f := newFile(t, db, a.ID, "x", 1)
			err := tx(func(tx *store.ScopedTx) error {
				return transfers.CreateTx(ctx, tx, tr, []string{"bob@partner.example.org"}, []store.TransferFile{f})
			})
			wantErr(t, "CreateTx("+name+")", err, store.ErrInvalid)
		}

		// Erasure: the sealed token is destroyed with the data keys before
		// the transfer is deleted; destroying it clears the reference.
		del := func() error { return tx(func(tx *store.ScopedTx) error { return transfers.DeleteTx(ctx, tx, d.ID) }) }
		if err := keys.Delete(ctx, a.ID, d.Files[0].DEKKeyID); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "DeleteTx(token key remains)", del(), store.ErrKeysRemain)
		if err := keys.Delete(ctx, a.ID, secret); err != nil {
			t.Fatal(err)
		}
		if got, err := transfers.Get(ctx, a.ID, d.ID); err != nil || got.DownloadTokenKeyID != "" || got.Status != store.TransferAvailable {
			t.Errorf("after token key destruction = %+v, %v", got.Transfer, err)
		}
		if err := del(); err != nil {
			t.Errorf("DeleteTx: %v", err)
		}
	})
}

func TestTransfersScanningSweep(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		if got, err := transfers.ScanningSweep(ctx); err != nil || len(got) != 0 {
			t.Fatalf("ScanningSweep(empty) = %+v, %v", got, err)
		}
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		late := scanningTransfer(t, db, a.ID, fixedNow.Add(2*time.Hour), 1)
		early := scanningTransfer(t, db, b.ID, fixedNow, 1)
		mid := scanningTransfer(t, db, a.ID, fixedNow.Add(time.Hour), 1)
		done := scanningTransfer(t, db, b.ID, fixedNow, 1)
		markAvailable(t, db, b.ID, done.ID)
		mustTransfer(t, db, a.ID, newTransfer()) // uploading

		got, err := transfers.ScanningSweep(ctx)
		want := []store.TenantTransfer{
			{TenantID: b.ID, TransferID: early.ID},
			{TenantID: a.ID, TransferID: mid.ID},
			{TenantID: a.ID, TransferID: late.ID},
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ScanningSweep = %+v, %v; want %+v", got, err, want)
		}
		if store.ScanSweepLimit < 1 {
			t.Errorf("ScanSweepLimit = %d", store.ScanSweepLimit)
		}
	})
}

func TestTransfersScanningCounts(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		if got, err := transfers.ScanningCounts(ctx); err != nil || len(got) != 0 {
			t.Fatalf("ScanningCounts(empty) = %+v, %v", got, err)
		}
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		newTenant(t, db, "transfer.entity-c.example.com") // nothing waiting
		scanningTransfer(t, db, a.ID, fixedNow, 1)
		scanningTransfer(t, db, a.ID, fixedNow.Add(time.Hour), 2)
		scanningTransfer(t, db, b.ID, fixedNow, 1)
		done := scanningTransfer(t, db, b.ID, fixedNow, 1)
		markAvailable(t, db, b.ID, done.ID)
		mustTransfer(t, db, b.ID, newTransfer()) // uploading

		got, err := transfers.ScanningCounts(ctx)
		want := []store.TenantScanning{{TenantID: a.ID, Transfers: 2}, {TenantID: b.ID, Transfers: 1}}
		if a.ID > b.ID {
			want[0], want[1] = want[1], want[0]
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ScanningCounts = %+v, %v; want %+v", got, err, want)
		}
	})
}

func TestSupervisionCounts(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		since := fixedNow.Add(-24 * time.Hour)
		if n, err := transfers.ScanQueueFiles(ctx); err != nil || n != 0 {
			t.Fatalf("ScanQueueFiles(empty) = %d, %v", n, err)
		}
		if got, err := transfers.ActiveCounts(ctx, since); err != nil || len(got) != 0 {
			t.Fatalf("ActiveCounts(empty) = %+v, %v", got, err)
		}
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		newTenant(t, db, "transfer.entity-c.example.com") // nothing

		scanningTransfer(t, db, a.ID, fixedNow, 3) // 3 files waiting
		scanningTransfer(t, db, b.ID, fixedNow, 1) // 1 file waiting
		avail := scanningTransfer(t, db, a.ID, fixedNow, 2)
		markAvailable(t, db, a.ID, avail.ID) // made available at fixedNow: no longer waiting
		mustTransfer(t, db, b.ID, newTransfer())
		if n, err := transfers.ScanQueueFiles(ctx); err != nil || n != 4 {
			t.Errorf("ScanQueueFiles = %d, %v; want 4", n, err)
		}

		got, err := transfers.ActiveCounts(ctx, since)
		want := []store.TenantTransferCounts{{TenantID: a.ID, Active: 1, MadeAvailableSince: 1}}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ActiveCounts = %+v, %v; want %+v", got, err, want)
		}
		// Made available before the window: still active, not recent.
		got, err = transfers.ActiveCounts(ctx, fixedNow.Add(time.Hour))
		want = []store.TenantTransferCounts{{TenantID: a.ID, Active: 1, MadeAvailableSince: 0}}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ActiveCounts(later) = %+v, %v; want %+v", got, err, want)
		}
	})
}

func TestScanStatusDeliverable(t *testing.T) {
	t.Parallel()
	for s, want := range map[store.ScanStatus]bool{
		store.ScanPending: false, store.ScanScanning: false, store.ScanClean: true, store.ScanInfected: false,
		store.ScanNotScannedTooLarge: true, store.ScanNotScannedEncrypted: true, store.ScanError: false, "bogus": false,
	} {
		if got := s.Deliverable(); got != want {
			t.Errorf("%q.Deliverable() = %v, want %v", s, got, want)
		}
	}
}

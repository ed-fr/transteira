package isolation_test

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// newSecretKey stores a wrapped secret of tid and returns its ID.
func newSecretKey(t *testing.T, db *store.DB, tid tenant.ID) string {
	t.Helper()
	key := store.WrappedKey{ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeSecret, KeyID: "mk_0123456789abcdef", Blob: []byte("s")}
	if err := db.WrappedKeys().Create(t.Context(), tid, key); err != nil {
		t.Fatalf("WrappedKeys.Create: %v", err)
	}
	return key.ID
}

// scanningTransfer stores a transfer of tid whose file is complete, and
// finalizes it (status scanning).
func scanningTransfer(t *testing.T, db *store.DB, tid tenant.ID) store.TransferDetails {
	t.Helper()
	ctx := t.Context()
	tr := store.Transfer{
		ID: id.New(id.Transfer), SenderEmail: "alice@entity-a.example.com", SenderKind: store.DepositorInternal, ExpiryDays: 7,
	}
	fl := newTransferFile(t, db, tid)
	fl.SHA256, fl.CiphertextSize, fl.UploadedAt = shaTransfer, 80, epoch
	s, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		if err := db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@partner.example.net"}, []store.TransferFile{fl}); err != nil {
			return err
		}
		return db.Transfers().FinalizeTx(ctx, tx, tr.ID, epoch)
	})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	d, err := db.Transfers().Get(ctx, tid, tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// downloadHash returns the SHA-256 of a new download token.
func downloadHash(t *testing.T) []byte {
	t.Helper()
	tok, err := id.NewDownloadToken()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

// TestScanIsolation attacks A's scanning transfer, its file and its
// download link from tenant B through every antivirus and download link
// method: B never reads or changes them, and every attempt reads as a
// plain not-found. The cross-tenant sweep returns identifiers only.
func TestScanIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a, b := newTenant(t, db, fqdnA), newTenant(t, db, fqdnB)
		da, avail := scanningTransfer(t, db, a.ID), scanningTransfer(t, db, a.ID)
		dbB := scanningTransfer(t, db, b.ID)
		fa := da.Files[0]
		transfers, files := db.Transfers(), db.TransferFiles()
		sa, err := db.Scoped(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		sb, err := db.Scoped(b.ID)
		if err != nil {
			t.Fatal(err)
		}
		inB := func(fn func(tx *store.ScopedTx) error) error { return sb.Tx(ctx, fn) }

		// A's second transfer becomes available with its own link.
		hashA, keyA := downloadHash(t), newSecretKey(t, db, a.ID)
		if err := sa.Tx(ctx, func(tx *store.ScopedTx) error {
			return transfers.MarkAvailableTx(ctx, tx, avail.ID, hashA, keyA, epoch)
		}); err != nil {
			t.Fatalf("MarkAvailableTx: %v", err)
		}
		avail, err = transfers.Get(ctx, a.ID, avail.ID)
		if err != nil {
			t.Fatal(err)
		}

		keyB := newSecretKey(t, db, b.ID)
		assertNotFound(t, "SetScanningTx", inB(func(tx *store.ScopedTx) error { return files.SetScanningTx(ctx, tx, fa.ID) }))
		assertNotFound(t, "SetScanResultTx", inB(func(tx *store.ScopedTx) error {
			return files.SetScanResultTx(ctx, tx, fa.ID, store.ScanInfected, "Win.Test.EICAR_HDB-1", epoch)
		}))
		_, err = files.IncrementScanAttempt(ctx, b.ID, fa.ID)
		assertNotFound(t, "IncrementScanAttempt", err)
		assertNotFound(t, "MarkAvailableTx", inB(func(tx *store.ScopedTx) error {
			return transfers.MarkAvailableTx(ctx, tx, da.ID, downloadHash(t), keyB, epoch)
		}))
		assertNotFound(t, "MarkRejectedTx", inB(func(tx *store.ScopedTx) error { return transfers.MarkRejectedTx(ctx, tx, da.ID) }))
		_, err = transfers.GetByDownloadTokenHash(ctx, b.ID, hashA)
		assertNotFound(t, "GetByDownloadTokenHash", err)
		// A's sealed token key cannot be attached to a transfer of B.
		assertNotFound(t, "MarkAvailableTx with A's key", inB(func(tx *store.ScopedTx) error {
			return transfers.MarkAvailableTx(ctx, tx, dbB.ID, downloadHash(t), keyA, epoch)
		}))
		// A's token hash cannot be reused by B (globally unique): the
		// conflict reveals nothing to whoever does not hold the token.
		if err := inB(func(tx *store.ScopedTx) error {
			return transfers.MarkAvailableTx(ctx, tx, dbB.ID, hashA, keyB, epoch)
		}); !errors.Is(err, store.ErrConflict) {
			t.Errorf("MarkAvailableTx with A's hash = %v, want ErrConflict", err)
		}

		for _, want := range []store.TransferDetails{da, avail} {
			if got, err := transfers.Get(ctx, a.ID, want.ID); err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("A's transfer changed: %+v, %v", got, err)
			}
		}

		// The sweep crosses tenants and returns identifiers only.
		got, err := transfers.ScanningSweep(ctx)
		want := map[store.TenantTransfer]bool{
			{TenantID: a.ID, TransferID: da.ID}:  true,
			{TenantID: b.ID, TransferID: dbB.ID}: true,
		}
		if err != nil || len(got) != len(want) {
			t.Fatalf("ScanningSweep = %+v, %v", got, err)
		}
		for _, tt := range got {
			if !want[tt] {
				t.Errorf("ScanningSweep returned %+v", tt)
			}
		}
	})
}

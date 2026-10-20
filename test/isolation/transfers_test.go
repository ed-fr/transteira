package isolation_test

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// shaTransfer is a fictitious SHA-256 of the transfer scenarios.
const shaTransfer = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// newTransferFile returns an incomplete file of tid with a new data key.
func newTransferFile(t *testing.T, db *store.DB, tid tenant.ID) store.TransferFile {
	t.Helper()
	key := store.WrappedKey{ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeDEK, KeyID: "mk_0123456789abcdef", Blob: []byte("k")}
	if err := db.WrappedKeys().Create(t.Context(), tid, key); err != nil {
		t.Fatalf("WrappedKeys.Create: %v", err)
	}
	upl, err := id.NewUploadToken()
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return store.TransferFile{
		ID: id.New(id.File), Name: "contract.pdf", Size: 42, DEKKeyID: key.ID,
		StorageName: hex.EncodeToString(b), UploadID: upl,
	}
}

// createTransfer stores an uploading transfer of tid with one file.
func createTransfer(t *testing.T, db *store.DB, tid tenant.ID) store.TransferDetails {
	t.Helper()
	ctx := t.Context()
	tr := store.Transfer{
		ID: id.New(id.Transfer), SenderEmail: "alice@entity-a.example.com",
		SenderKind: store.DepositorInternal, ExpiryDays: 7, IdempotencyKey: "same-key",
	}
	fl := newTransferFile(t, db, tid)
	s, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		return db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@partner.example.net"}, []store.TransferFile{fl})
	})
	if err != nil {
		t.Fatalf("CreateTx: %v", err)
	}
	d, err := db.Transfers().Get(ctx, tid, tr.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return d
}

// TestTransfersIsolation attacks A's transfer and file from tenant B
// through every transfer repository method: B never reads, changes or
// deletes them, and every attempt reads as a plain not-found.
func TestTransfersIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a, b := newTenant(t, db, fqdnA), newTenant(t, db, fqdnB)
		da := createTransfer(t, db, a.ID)
		dbB := createTransfer(t, db, b.ID) // B's own transfer, with the same sender and key
		fa := da.Files[0]
		transfers, files := db.Transfers(), db.TransferFiles()
		sb, err := db.Scoped(b.ID)
		if err != nil {
			t.Fatal(err)
		}
		inB := func(fn func(tx *store.ScopedTx) error) error { return sb.Tx(ctx, fn) }

		_, err = transfers.Get(ctx, b.ID, da.ID)
		assertNotFound(t, "Get", err)
		_, err = files.GetByUploadID(ctx, b.ID, fa.UploadID)
		assertNotFound(t, "GetByUploadID", err)
		if got, err := transfers.GetByIdempotencyKey(ctx, b.ID, da.SenderEmail, "same-key", epoch); err != nil || got.ID != dbB.ID {
			t.Errorf("GetByIdempotencyKey from B = %s, %v", got.ID, err)
		}
		if got, err := files.ListByTransfer(ctx, b.ID, da.ID); err != nil || len(got) != 0 {
			t.Errorf("ListByTransfer from B = %+v, %v", got, err)
		}
		assertNotFound(t, "CompleteUpload", files.CompleteUpload(ctx, b.ID, fa.ID, shaTransfer, 1, epoch))
		keyB := newTransferFile(t, db, b.ID).DEKKeyID // an unused data key of B
		assertNotFound(t, "GetTx", inB(func(tx *store.ScopedTx) error { _, err := transfers.GetTx(ctx, tx, da.ID); return err }))
		assertNotFound(t, "GetByUploadIDTx", inB(func(tx *store.ScopedTx) error {
			_, err := files.GetByUploadIDTx(ctx, tx, fa.UploadID)
			return err
		}))
		assertNotFound(t, "FinalizeTx", inB(func(tx *store.ScopedTx) error { return transfers.FinalizeTx(ctx, tx, da.ID, epoch) }))
		assertNotFound(t, "SetStatusTx", inB(func(tx *store.ScopedTx) error {
			return transfers.SetStatusTx(ctx, tx, da.ID, store.TransferUploading, store.TransferDeleted, epoch)
		}))
		assertNotFound(t, "DeleteTx", inB(func(tx *store.ScopedTx) error { return transfers.DeleteTx(ctx, tx, da.ID) }))
		assertNotFound(t, "file DeleteTx", inB(func(tx *store.ScopedTx) error { return files.DeleteTx(ctx, tx, fa.ID) }))
		assertNotFound(t, "CompleteUploadTx", inB(func(tx *store.ScopedTx) error {
			return files.CompleteUploadTx(ctx, tx, fa.ID, shaTransfer, 1, epoch)
		}))
		assertNotFound(t, "ReplaceDEKTx", inB(func(tx *store.ScopedTx) error {
			return files.ReplaceDEKTx(ctx, tx, fa.ID, keyB, "0123456789abcdef0123456789abcdef") // gitleaks:allow
		}))
		// A's data key cannot be attached to a file of B.
		assertNotFound(t, "ReplaceDEKTx with A's key", inB(func(tx *store.ScopedTx) error {
			return files.ReplaceDEKTx(ctx, tx, dbB.Files[0].ID, fa.DEKKeyID, "fedcba9876543210fedcba9876543210")
		}))

		if got, err := transfers.Get(ctx, a.ID, da.ID); err != nil || !reflect.DeepEqual(got, da) {
			t.Errorf("A's transfer changed: %+v, %v", got, err)
		}
		for _, table := range []string{"transfers", "transfer_recipients", "transfer_files"} {
			if n := rawCount(t, e, table, "tenant_id", a.ID); n != 1 {
				t.Errorf("A holds %d rows in %s, want 1", n, table)
			}
		}
	})
}

// TestRLSTransfersCrossTenantRawSQL checks with raw SQL, bypassing the
// store, that the row-level security policies of the transfer tables hide
// and protect B's rows from a transaction scoped to A.
func TestRLSTransfersCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	db := f.db
	createTransfer(t, db, f.a.ID)
	dbB := createTransfer(t, db, f.b.ID)
	a, b := string(f.a.ID), string(f.b.ID)
	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, table := range []string{"transfers", "transfer_recipients", "transfer_files"} {
			if n := countRows(ctx, t, tx, `SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, b); n != 0 {
				t.Errorf("A sees %d of B's rows in %s", n, table)
			}
			if n := countRows(ctx, t, tx, `SELECT count(*) FROM `+table); n != 1 {
				t.Errorf("A sees %d rows in %s, want 1", n, table)
			}
		}
		if n := countRows(ctx, t, tx, `SELECT count(*) FROM transfer_files WHERE upload_id = $1`, dbB.Files[0].UploadID); n != 0 {
			t.Errorf("A sees B's upload")
		}
		for _, stmt := range []string{
			`UPDATE transfers SET status = 'deleted' WHERE tenant_id = $1`,
			`DELETE FROM transfer_recipients WHERE tenant_id = $1`,
			`UPDATE transfer_files SET sha256 = NULL, storage_name = storage_name WHERE tenant_id = $1`,
			`DELETE FROM transfer_files WHERE tenant_id = $1`,
		} {
			if n := affected(ctx, t, tx, stmt, b); n != 0 {
				t.Errorf("%s affected %d rows of B", stmt, n)
			}
		}
		return nil
	})
	for name, stmt := range map[string]string{
		"move A's transfers to B": `UPDATE transfers SET tenant_id = $1`,
		"insert a recipient for B": `INSERT INTO transfer_recipients (tenant_id, transfer_id, position, email) VALUES ($1, '` +
			dbB.ID + `', 5, 'evil@example.net')`,
	} {
		err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, stmt, b); return err })
		assertRLSViolation(t, name, err)
	}
	if got, err := db.Transfers().Get(ctx, f.b.ID, dbB.ID); err != nil || !reflect.DeepEqual(got, dbB) {
		t.Errorf("B's transfer changed: %+v, %v", got, err)
	}
}

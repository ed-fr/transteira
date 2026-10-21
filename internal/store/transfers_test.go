package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// SHA-256 values of the transfer tests (fictitious, except emptySHA).
const (
	emptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sha1111  = "1111111111111111111111111111111111111111111111111111111111111111"
)

// randomHex returns n random bytes in lowercase hexadecimal.
func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// newFile returns a valid, incomplete file of size bytes with a new data
// key of tid.
func newFile(t *testing.T, db *store.DB, tid tenant.ID, name string, size int64) store.TransferFile {
	t.Helper()
	upl, err := id.NewUploadToken()
	if err != nil {
		t.Fatal(err)
	}
	return store.TransferFile{
		ID: id.New(id.File), Name: name, Size: size, MediaType: "application/pdf",
		DEKKeyID: mustSecret(t, db, tid, store.KeyPurposeDEK), StorageName: randomHex(t, 16), UploadID: upl,
	}
}

// newTransfer returns a valid internal transfer.
func newTransfer() store.Transfer {
	return store.Transfer{
		ID: id.New(id.Transfer), SenderEmail: "Alice@Entity-A.example.com", SenderKind: store.DepositorInternal,
		Message: "Here are the files.\nRegards.", Language: "fr", ExpiryDays: 7,
	}
}

// mustTransfer creates a transfer of tid with two recipients and the given
// files (one incomplete 10-byte file when none is given).
func mustTransfer(t *testing.T, db *store.DB, tid tenant.ID, tr store.Transfer, files ...store.TransferFile) store.TransferDetails {
	t.Helper()
	ctx := context.Background()
	if len(files) == 0 {
		files = []store.TransferFile{newFile(t, db, tid, "report.pdf", 10)}
	}
	err := inTx(t, db, tid, func(tx *store.ScopedTx) error {
		return db.Transfers().CreateTx(ctx, tx, tr, []string{"Bob@Partner.example.org", "carol@entity-a.example.com"}, files)
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

// usedBytes returns the quota usage of tid.
func usedBytes(t *testing.T, db *store.DB, tid tenant.ID) int64 {
	t.Helper()
	var n int64
	err := inTx(t, db, tid, func(tx *store.ScopedTx) error {
		var err error
		n, err = db.Transfers().UsedBytesTx(context.Background(), tx)
		return err
	})
	if err != nil {
		t.Fatalf("UsedBytesTx: %v", err)
	}
	return n
}

func TestTransfersCreateAndRead(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers, files := db.Transfers(), db.TransferFiles()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		tr := newTransfer()
		tr.PasswordHash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA"
		tr.DeleteAfterFirstDownload = true
		tr.TotalBytes = 1010
		big := newFile(t, db, a.ID, "Rapport annuel é.pdf", 1010)
		big.ExpectedSHA256 = sha1111
		empty := newFile(t, db, a.ID, "empty.txt", 0)
		empty.MediaType, empty.SHA256, empty.CiphertextSize, empty.UploadedAt = "", emptySHA, 40, fixedNow
		d := mustTransfer(t, db, a.ID, tr, big, empty)

		want := tr
		want.Status, want.SenderEmail, want.CreatedAt = store.TransferUploading, "alice@entity-a.example.com", msNow
		if !reflect.DeepEqual(d.Transfer, want) {
			t.Errorf("Get transfer = %+v, want %+v", d.Transfer, want)
		}
		if !d.PasswordProtected() || !reflect.DeepEqual(d.Recipients, []string{"bob@partner.example.org", "carol@entity-a.example.com"}) {
			t.Errorf("Get recipients = %v, password %v", d.Recipients, d.PasswordProtected())
		}
		wantBig := big
		wantBig.TransferID, wantBig.Position, wantBig.ScanStatus = tr.ID, 0, store.ScanPending
		wantEmpty := empty
		wantEmpty.TransferID, wantEmpty.Position, wantEmpty.ScanStatus, wantEmpty.UploadedAt = tr.ID, 1, store.ScanPending, msNow
		if !reflect.DeepEqual(d.Files, []store.TransferFile{wantBig, wantEmpty}) {
			t.Errorf("Get files = %+v", d.Files)
		}
		if d.Files[0].Completed() || !d.Files[1].Completed() {
			t.Error("Completed() is wrong")
		}
		if got, err := files.ListByTransfer(ctx, a.ID, tr.ID); err != nil || !reflect.DeepEqual(got, d.Files) {
			t.Errorf("ListByTransfer = %+v, %v", got, err)
		}
		err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			got, err := transfers.GetTx(ctx, tx, tr.ID)
			if err == nil && !reflect.DeepEqual(got, d) {
				t.Errorf("GetTx = %+v", got)
			}
			return err
		})
		if err != nil {
			t.Errorf("GetTx: %v", err)
		}

		// Lookup by upload identifier, with the transfer.
		u, err := files.GetByUploadID(ctx, a.ID, big.UploadID)
		if err != nil || !reflect.DeepEqual(u.File, wantBig) || !reflect.DeepEqual(u.Transfer, want) {
			t.Errorf("GetByUploadID = %+v, %v", u, err)
		}
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			got, err := files.GetByUploadIDTx(ctx, tx, empty.UploadID)
			if err == nil && !reflect.DeepEqual(got.File, wantEmpty) {
				t.Errorf("GetByUploadIDTx = %+v", got)
			}
			return err
		})
		if err != nil {
			t.Errorf("GetByUploadIDTx: %v", err)
		}
		if n := usedBytes(t, db, a.ID); n != 1010 {
			t.Errorf("UsedBytesTx(A) = %d, want 1010", n)
		}

		// Isolation: B sees and changes nothing of A.
		_, err = transfers.Get(ctx, b.ID, tr.ID)
		wantErr(t, "Get from B", err, store.ErrNotFound)
		_, err = files.GetByUploadID(ctx, b.ID, big.UploadID)
		wantErr(t, "GetByUploadID from B", err, store.ErrNotFound)
		if got, err := files.ListByTransfer(ctx, b.ID, tr.ID); err != nil || len(got) != 0 {
			t.Errorf("ListByTransfer from B = %+v, %v", got, err)
		}
		if n := usedBytes(t, db, b.ID); n != 0 {
			t.Errorf("UsedBytesTx(B) = %d, want 0", n)
		}
		wantErr(t, "CompleteUpload from B", files.CompleteUpload(ctx, b.ID, big.ID, sha1111, 1, fixedNow), store.ErrNotFound)
		bTx := func(fn func(*store.ScopedTx) error) error { return inTx(t, db, b.ID, fn) }
		wantErr(t, "GetTx from B", bTx(func(tx *store.ScopedTx) error { _, err := transfers.GetTx(ctx, tx, tr.ID); return err }), store.ErrNotFound)
		wantErr(t, "GetByUploadIDTx from B", bTx(func(tx *store.ScopedTx) error {
			_, err := files.GetByUploadIDTx(ctx, tx, big.UploadID)
			return err
		}), store.ErrNotFound)
		wantErr(t, "FinalizeTx from B", bTx(func(tx *store.ScopedTx) error { return transfers.FinalizeTx(ctx, tx, tr.ID, fixedNow) }), store.ErrNotFound)
		wantErr(t, "SetStatusTx from B", bTx(func(tx *store.ScopedTx) error {
			return transfers.SetStatusTx(ctx, tx, tr.ID, store.TransferUploading, store.TransferDeleted, fixedNow)
		}), store.ErrNotFound)
		wantErr(t, "DeleteTx from B", bTx(func(tx *store.ScopedTx) error { return transfers.DeleteTx(ctx, tx, tr.ID) }), store.ErrNotFound)
		wantErr(t, "file DeleteTx from B", bTx(func(tx *store.ScopedTx) error { return files.DeleteTx(ctx, tx, big.ID) }), store.ErrNotFound)
		keyB := mustSecret(t, db, b.ID, store.KeyPurposeDEK)
		wantErr(t, "ReplaceDEKTx from B", bTx(func(tx *store.ScopedTx) error {
			return files.ReplaceDEKTx(ctx, tx, big.ID, keyB, randomHex(t, 16))
		}), store.ErrNotFound)
		if again, err := transfers.Get(ctx, a.ID, tr.ID); err != nil || !reflect.DeepEqual(again, d) {
			t.Errorf("A's transfer changed: %+v, %v", again, err)
		}

		// B may reuse A's storage name (per-tenant uniqueness) but never an
		// upload identifier (global), and never A's data key.
		fb := newFile(t, db, b.ID, "b.bin", 1)
		fb.StorageName = big.StorageName
		mustTransfer(t, db, b.ID, newTransfer(), fb)
		for name, mutate := range map[string]func(*store.TransferFile){
			"upload id of A": func(f *store.TransferFile) { f.UploadID = big.UploadID },
		} {
			f := newFile(t, db, b.ID, "b.bin", 1)
			mutate(&f)
			err := bTx(func(tx *store.ScopedTx) error {
				return transfers.CreateTx(ctx, tx, newTransfer(), []string{"x@example.com"}, []store.TransferFile{f})
			})
			wantErr(t, "CreateTx("+name+")", err, store.ErrConflict)
		}
		f := newFile(t, db, b.ID, "b.bin", 1)
		f.DEKKeyID = big.DEKKeyID
		err = bTx(func(tx *store.ScopedTx) error {
			return transfers.CreateTx(ctx, tx, newTransfer(), []string{"x@example.com"}, []store.TransferFile{f})
		})
		wantErr(t, "CreateTx(data key of A)", err, store.ErrNotFound)
	})
}

func TestTransfersCreateErrors(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		invA, invB := mustInvitation(t, db, a.ID), mustInvitation(t, db, b.ID)
		create := func(tid tenant.ID, tr store.Transfer, rcpts []string, fs []store.TransferFile) error {
			return inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error { return transfers.CreateTx(ctx, tx, tr, rcpts, fs) })
		}
		one := []string{"bob@partner.example.org"}

		// External sender through an invitation of the same tenant.
		ext := newTransfer()
		ext.SenderEmail, ext.SenderKind, ext.InvitationID, ext.Language, ext.Message = "bob@partner.example.org", store.DepositorExternal, invA.ID, "", ""
		if err := create(a.ID, ext, []string{"alice@entity-a.example.com"}, []store.TransferFile{newFile(t, db, a.ID, "x", 1)}); err != nil {
			t.Fatalf("CreateTx(external): %v", err)
		}
		if got, err := transfers.Get(ctx, a.ID, ext.ID); err != nil || got.InvitationID != invA.ID || got.SenderKind != store.DepositorExternal ||
			got.Language != "" || got.Message != "" || got.PasswordProtected() || got.DeleteAfterFirstDownload {
			t.Errorf("Get(external) = %+v, %v", got, err)
		}
		// The invitation cannot be deleted while a transfer references it.
		if err := db.Invitations().Delete(ctx, a.ID, invA.ID); err == nil {
			t.Error("Invitations.Delete of a referenced invitation succeeded")
		}

		// Not found: tenant, invitation, data key.
		wantErr(t, "CreateTx(missing tenant)", create(tenant.ID(id.New(id.Tenant)), newTransfer(), one,
			[]store.TransferFile{newFile(t, db, a.ID, "x", 1)}), store.ErrNotFound)
		for name, invID := range map[string]string{"invitation of B": invB.ID, "missing invitation": id.New(id.Invitation)} {
			x := ext
			x.ID, x.InvitationID = id.New(id.Transfer), invID
			wantErr(t, "CreateTx("+name+")", create(a.ID, x, one, []store.TransferFile{newFile(t, db, a.ID, "x", 1)}), store.ErrNotFound)
		}
		missingKey := newFile(t, db, a.ID, "x", 1)
		missingKey.DEKKeyID = id.New(id.WrappedKey)
		wantErr(t, "CreateTx(missing key)", create(a.ID, newTransfer(), one, []store.TransferFile{missingKey}), store.ErrNotFound)
		secret := newFile(t, db, a.ID, "x", 1)
		secret.DEKKeyID = mustSecret(t, db, a.ID, store.KeyPurposeSecret)
		wantErr(t, "CreateTx(secret key)", create(a.ID, newTransfer(), one, []store.TransferFile{secret}), store.ErrInvalid)

		// Conflicts: transfer ID, file ID, upload ID, storage name, data key.
		base := mustTransfer(t, db, a.ID, newTransfer())
		f0 := base.Files[0]
		dupTransfer := newTransfer()
		dupTransfer.ID = base.ID
		wantErr(t, "CreateTx(duplicate id)", create(a.ID, dupTransfer, one, []store.TransferFile{newFile(t, db, a.ID, "x", 1)}), store.ErrConflict)
		for name, mutate := range map[string]func(*store.TransferFile){
			"file id":      func(f *store.TransferFile) { f.ID = f0.ID },
			"upload id":    func(f *store.TransferFile) { f.UploadID = f0.UploadID },
			"storage name": func(f *store.TransferFile) { f.StorageName = f0.StorageName },
			"data key":     func(f *store.TransferFile) { f.DEKKeyID = f0.DEKKeyID },
		} {
			f := newFile(t, db, a.ID, "x", 1)
			mutate(&f)
			wantErr(t, "CreateTx(duplicate "+name+")", create(a.ID, newTransfer(), one, []store.TransferFile{f}), store.ErrConflict)
		}
		// Nothing of a failed creation remains.
		if n := usedBytes(t, db, a.ID); n != 11 {
			t.Errorf("UsedBytesTx = %d, want 11", n)
		}

		// Invalid transfers.
		invalidTransfers := map[string]func(*store.Transfer){
			"id":                    func(tr *store.Transfer) { tr.ID = id.New(id.File) },
			"status":                func(tr *store.Transfer) { tr.Status = store.TransferScanning },
			"sender":                func(tr *store.Transfer) { tr.SenderEmail = "nope" },
			"kind":                  func(tr *store.Transfer) { tr.SenderKind = "reply" },
			"external no inv":       func(tr *store.Transfer) { tr.SenderKind = store.DepositorExternal },
			"internal with inv":     func(tr *store.Transfer) { tr.InvitationID = invA.ID },
			"malformed inv":         func(tr *store.Transfer) { tr.SenderKind, tr.InvitationID = store.DepositorExternal, "inv_x" },
			"message too long":      func(tr *store.Transfer) { tr.Message = strings.Repeat("é", store.MaxTransferMessageLen+1) },
			"message not utf8":      func(tr *store.Transfer) { tr.Message = "\xff" },
			"language":              func(tr *store.Transfer) { tr.Language = "de" },
			"expiry":                func(tr *store.Transfer) { tr.ExpiryDays = 2 },
			"password not phc":      func(tr *store.Transfer) { tr.PasswordHash = "plain" },
			"password with space":   func(tr *store.Transfer) { tr.PasswordHash = "$argon2id $x" },
			"password too long":     func(tr *store.Transfer) { tr.PasswordHash = "$" + strings.Repeat("a", store.MaxPasswordHashLen) },
			"total":                 func(tr *store.Transfer) { tr.TotalBytes = 2 },
			"idempotency key":       func(tr *store.Transfer) { tr.IdempotencyKey = "with space" },
			"idempotency too long":  func(tr *store.Transfer) { tr.IdempotencyKey = strings.Repeat("k", store.MaxIdempotencyKeyLen+1) },
			"idempotency not ascii": func(tr *store.Transfer) { tr.IdempotencyKey = "clé" },
			"finalized":             func(tr *store.Transfer) { tr.FinalizedAt = fixedNow },
			"expires":               func(tr *store.Transfer) { tr.ExpiresAt = fixedNow },
		}
		for name, mutate := range invalidTransfers {
			tr := newTransfer()
			mutate(&tr)
			wantErr(t, "CreateTx(bad "+name+")", create(a.ID, tr, one, []store.TransferFile{newFile(t, db, a.ID, "x", 1)}), store.ErrInvalid)
		}
		// Invalid recipients.
		tooMany := make([]string, store.MaxTransferRecipients+1)
		for i := range tooMany {
			tooMany[i] = "r" + strings.Repeat("x", i) + "@example.com"
		}
		for name, rcpts := range map[string][]string{
			"none": nil, "too many": tooMany, "malformed": {"nope"}, "duplicate": {"bob@example.com", "BOB@example.com"},
		} {
			wantErr(t, "CreateTx(recipients "+name+")", create(a.ID, newTransfer(), rcpts, []store.TransferFile{newFile(t, db, a.ID, "x", 1)}), store.ErrInvalid)
		}
		// Invalid files.
		wantErr(t, "CreateTx(no file)", create(a.ID, newTransfer(), one, nil), store.ErrInvalid)
		wantErr(t, "CreateTx(too many files)", create(a.ID, newTransfer(), one, make([]store.TransferFile, store.MaxTransferFiles+1)), store.ErrInvalid)
		overflow := []store.TransferFile{newFile(t, db, a.ID, "x", 1<<62), newFile(t, db, a.ID, "y", 1<<62), newFile(t, db, a.ID, "z", 1<<62)}
		wantErr(t, "CreateTx(size overflow)", create(a.ID, newTransfer(), one, overflow), store.ErrInvalid)
		invalidFiles := map[string]func(*store.TransferFile){
			"id":                   func(f *store.TransferFile) { f.ID = id.New(id.Transfer) },
			"transfer id":          func(f *store.TransferFile) { f.TransferID = id.New(id.Transfer) },
			"empty name":           func(f *store.TransferFile) { f.Name = "" },
			"long name":            func(f *store.TransferFile) { f.Name = strings.Repeat("é", 128) },
			"control in name":      func(f *store.TransferFile) { f.Name = "a\nb" },
			"name not utf8":        func(f *store.TransferFile) { f.Name = "\xff" },
			"size":                 func(f *store.TransferFile) { f.Size = -1 },
			"media type":           func(f *store.TransferFile) { f.MediaType = "text/plain\r\nX: y" },
			"long media type":      func(f *store.TransferFile) { f.MediaType = strings.Repeat("a", store.MaxMediaTypeLen+1) },
			"expected sha":         func(f *store.TransferFile) { f.ExpectedSHA256 = strings.Repeat("A", 64) },
			"data key":             func(f *store.TransferFile) { f.DEKKeyID = "" },
			"storage name":         func(f *store.TransferFile) { f.StorageName = strings.ToUpper(f.StorageName) },
			"short storage name":   func(f *store.TransferFile) { f.StorageName = f.StorageName[:31] },
			"upload id":            func(f *store.TransferFile) { f.UploadID = "upl_short" },
			"scan status":          func(f *store.TransferFile) { f.ScanStatus = store.ScanClean },
			"completed no sha":     func(f *store.TransferFile) { f.UploadedAt = fixedNow },
			"completed neg size":   func(f *store.TransferFile) { f.UploadedAt, f.SHA256, f.CiphertextSize = fixedNow, emptySHA, -1 },
			"incomplete with sha":  func(f *store.TransferFile) { f.SHA256 = emptySHA },
			"incomplete with size": func(f *store.TransferFile) { f.CiphertextSize = 1 },
		}
		for name, mutate := range invalidFiles {
			f := newFile(t, db, a.ID, "x", 1)
			mutate(&f)
			wantErr(t, "CreateTx(bad file "+name+")", create(a.ID, newTransfer(), one, []store.TransferFile{f}), store.ErrInvalid)
		}
		// Bad tenants.
		for _, tid := range badTenants {
			_, err := transfers.Get(ctx, tid, base.ID)
			wantErr(t, "Get(bad tenant)", err, store.ErrInvalid)
			_, err = transfers.GetByIdempotencyKey(ctx, tid, "alice@entity-a.example.com", "k", fixedNow)
			wantErr(t, "GetByIdempotencyKey(bad tenant)", err, store.ErrInvalid)
			_, err = db.TransferFiles().GetByUploadID(ctx, tid, f0.UploadID)
			wantErr(t, "GetByUploadID(bad tenant)", err, store.ErrInvalid)
			_, err = db.TransferFiles().ListByTransfer(ctx, tid, base.ID)
			wantErr(t, "ListByTransfer(bad tenant)", err, store.ErrInvalid)
			wantErr(t, "CompleteUpload(bad tenant)", db.TransferFiles().CompleteUpload(ctx, tid, f0.ID, sha1111, 1, fixedNow), store.ErrInvalid)
		}
	})
}

func TestTransfersIdempotency(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		const key = "5f0c6c1e-8b7a-4a8e-9f0d-2c3b4a5d6e7f" // gitleaks:allow
		since := fixedNow.Add(-store.IdempotencyRetention)

		old := newTransfer()
		old.IdempotencyKey, old.CreatedAt = key, fixedNow.Add(-25*time.Hour)
		mustTransfer(t, db, a.ID, old)
		_, err := transfers.GetByIdempotencyKey(ctx, a.ID, old.SenderEmail, key, since)
		wantErr(t, "GetByIdempotencyKey(expired key)", err, store.ErrNotFound)
		if got, err := transfers.GetByIdempotencyKey(ctx, a.ID, "ALICE@entity-a.example.com", key, old.CreatedAt); err != nil || got.ID != old.ID {
			t.Errorf("GetByIdempotencyKey(old window) = %+v, %v", got, err)
		}

		// A new transfer with the same key releases the expired one.
		cur := newTransfer()
		cur.IdempotencyKey = key
		d := mustTransfer(t, db, a.ID, cur)
		got, err := transfers.GetByIdempotencyKey(ctx, a.ID, cur.SenderEmail, key, since)
		if err != nil || !reflect.DeepEqual(got, d) {
			t.Errorf("GetByIdempotencyKey = %+v, %v; want %+v", got, err, d)
		}
		if o, err := transfers.Get(ctx, a.ID, old.ID); err != nil || o.IdempotencyKey != "" {
			t.Errorf("old transfer kept its key: %+v, %v", o, err)
		}

		// Reusing the key within the retention conflicts; another sender
		// or another tenant may use it.
		dup := newTransfer()
		dup.IdempotencyKey = key
		dupFile := newFile(t, db, a.ID, "x", 1)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return transfers.CreateTx(ctx, tx, dup, []string{"x@example.com"}, []store.TransferFile{dupFile})
		})
		wantErr(t, "CreateTx(key in use)", err, store.ErrConflict)
		other := newTransfer()
		other.IdempotencyKey, other.SenderEmail = key, "dave@entity-a.example.com"
		mustTransfer(t, db, a.ID, other)
		inB := newTransfer()
		inB.IdempotencyKey = key
		mustTransfer(t, db, b.ID, inB)
		if got, err := transfers.GetByIdempotencyKey(ctx, b.ID, cur.SenderEmail, key, since); err != nil || got.ID != inB.ID {
			t.Errorf("GetByIdempotencyKey(B) = %+v, %v", got, err)
		}
		// B never reaches A's transfer through the key.
		if got, _ := transfers.GetByIdempotencyKey(ctx, b.ID, cur.SenderEmail, key, since); got.ID == cur.ID {
			t.Error("B reached A's transfer")
		}

		_, err = transfers.GetByIdempotencyKey(ctx, a.ID, "nope", key, since)
		wantErr(t, "GetByIdempotencyKey(bad sender)", err, store.ErrInvalid)
		_, err = transfers.GetByIdempotencyKey(ctx, a.ID, cur.SenderEmail, "", since)
		wantErr(t, "GetByIdempotencyKey(empty key)", err, store.ErrInvalid)
		_, err = transfers.GetByIdempotencyKey(ctx, a.ID, cur.SenderEmail, "other-key", since)
		wantErr(t, "GetByIdempotencyKey(unknown key)", err, store.ErrNotFound)
	})
}

func TestTransfersStatus(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		tx := func(fn func(*store.ScopedTx) error) error { return inTx(t, db, a.ID, fn) }
		setStatus := func(trfID string, from, to store.TransferStatus) error {
			return tx(func(tx *store.ScopedTx) error { return transfers.SetStatusTx(ctx, tx, trfID, from, to, fixedNow) })
		}

		tr := newTransfer()
		tr.ExpiryDays = 30
		d := mustTransfer(t, db, a.ID, tr)
		at := fixedNow.Add(time.Hour)
		if err := tx(func(tx *store.ScopedTx) error { return transfers.FinalizeTx(ctx, tx, tr.ID, at) }); err != nil {
			t.Fatalf("FinalizeTx: %v", err)
		}
		got, err := transfers.Get(ctx, a.ID, tr.ID)
		wantAt := at.Truncate(time.Millisecond)
		if err != nil || got.Status != store.TransferScanning || !got.FinalizedAt.Equal(wantAt) ||
			!got.ExpiresAt.Equal(wantAt.Add(30*24*time.Hour)) {
			t.Fatalf("after FinalizeTx = %+v, %v", got.Transfer, err)
		}
		wantErr(t, "FinalizeTx twice", tx(func(tx *store.ScopedTx) error { return transfers.FinalizeTx(ctx, tx, tr.ID, at) }), store.ErrConflict)
		wantErr(t, "FinalizeTx(missing)", tx(func(tx *store.ScopedTx) error {
			return transfers.FinalizeTx(ctx, tx, id.New(id.Transfer), at)
		}), store.ErrNotFound)
		if n := usedBytes(t, db, a.ID); n != d.TotalBytes {
			t.Errorf("UsedBytesTx(scanning) = %d", n)
		}
		wantErr(t, "SetStatusTx(scanning -> available)", setStatus(tr.ID, store.TransferScanning, store.TransferAvailable), store.ErrInvalid)
		markAvailable(t, db, a.ID, tr.ID)
		// Expiry and deletion refuse while a key remains: file keys first,
		// then the sealed download token (T-110).
		wantErr(t, "SetStatusTx(available -> expired) with file keys", setStatus(tr.ID, store.TransferAvailable, store.TransferExpired), store.ErrKeysRemain)
		av, err := transfers.Get(ctx, a.ID, tr.ID)
		if err != nil {
			t.Fatal(err)
		}
		deleteFileKeys(t, db, a.ID, av)
		wantErr(t, "SetStatusTx(available -> deleted) with the token key", setStatus(tr.ID, store.TransferAvailable, store.TransferDeleted), store.ErrKeysRemain)
		if err := db.WrappedKeys().Delete(ctx, a.ID, av.DownloadTokenKeyID); err != nil {
			t.Fatal(err)
		}
		if err := setStatus(tr.ID, store.TransferAvailable, store.TransferExpired); err != nil {
			t.Fatalf("SetStatusTx(available -> expired): %v", err)
		}
		if got, err := transfers.Get(ctx, a.ID, tr.ID); err != nil || got.Status != store.TransferExpired || !got.FinalizedAt.Equal(wantAt) {
			t.Errorf("after SetStatusTx = %+v, %v", got.Transfer, err)
		}
		if n := usedBytes(t, db, a.ID); n != 0 {
			t.Errorf("UsedBytesTx(expired) = %d, want 0", n)
		}
		wantErr(t, "SetStatusTx(stale from)", setStatus(tr.ID, store.TransferAvailable, store.TransferDeleted), store.ErrConflict)
		wantErr(t, "SetStatusTx(missing)", setStatus(id.New(id.Transfer), store.TransferAvailable, store.TransferDeleted), store.ErrNotFound)

		// An unfinalized transfer may be deleted or expire.
		up := mustTransfer(t, db, a.ID, newTransfer())
		wantErr(t, "SetStatusTx(uploading -> deleted) with a file key", setStatus(up.ID, store.TransferUploading, store.TransferDeleted), store.ErrKeysRemain)
		deleteFileKeys(t, db, a.ID, up)
		if err := setStatus(up.ID, store.TransferUploading, store.TransferDeleted); err != nil {
			t.Errorf("SetStatusTx(uploading -> deleted): %v", err)
		}
		for name, step := range map[string][2]store.TransferStatus{
			"unknown from":         {"bogus", store.TransferDeleted},
			"unknown to":           {store.TransferUploading, "bogus"},
			"same":                 {store.TransferAvailable, store.TransferAvailable},
			"back to uploading":    {store.TransferScanning, store.TransferUploading},
			"uploading->available": {store.TransferUploading, store.TransferAvailable},
			"uploading->rejected":  {store.TransferUploading, store.TransferRejected},
			"deleted->scanning":    {store.TransferDeleted, store.TransferScanning},
			"available->scanning":  {store.TransferAvailable, store.TransferScanning},
			"available->rejected":  {store.TransferAvailable, store.TransferRejected},
		} {
			wantErr(t, "SetStatusTx("+name+")", setStatus(up.ID, step[0], step[1]), store.ErrInvalid)
		}
	})
}

func TestTransferFilesUploadAndErasure(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers, files, keys := db.Transfers(), db.TransferFiles(), db.WrappedKeys()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		tx := func(fn func(*store.ScopedTx) error) error { return inTx(t, db, a.ID, fn) }
		d := mustTransfer(t, db, a.ID, newTransfer(),
			newFile(t, db, a.ID, "a.bin", 100), newFile(t, db, a.ID, "b.bin", 200), newFile(t, db, a.ID, "c.bin", 300))
		fa, fb, fc := d.Files[0], d.Files[1], d.Files[2]

		// Reset after a stale checkpoint: new key and storage name, old key
		// destroyed in the same transaction.
		newKey, newName := mustSecret(t, db, a.ID, store.KeyPurposeDEK), randomHex(t, 16)
		err := tx(func(tx *store.ScopedTx) error {
			if err := files.ReplaceDEKTx(ctx, tx, fa.ID, newKey, newName); err != nil {
				return err
			}
			return keys.DeleteTx(ctx, tx, fa.DEKKeyID)
		})
		if err != nil {
			t.Fatalf("ReplaceDEKTx: %v", err)
		}
		if u, err := files.GetByUploadID(ctx, a.ID, fa.UploadID); err != nil || u.File.DEKKeyID != newKey || u.File.StorageName != newName {
			t.Errorf("after ReplaceDEKTx = %+v, %v", u.File, err)
		}
		replace := func(fileID, keyID, name string) error {
			return tx(func(tx *store.ScopedTx) error { return files.ReplaceDEKTx(ctx, tx, fileID, keyID, name) })
		}
		wantErr(t, "ReplaceDEKTx(key in use)", replace(fa.ID, fb.DEKKeyID, randomHex(t, 16)), store.ErrConflict)
		wantErr(t, "ReplaceDEKTx(name in use)", replace(fa.ID, mustSecret(t, db, a.ID, store.KeyPurposeDEK), fb.StorageName), store.ErrConflict)
		wantErr(t, "ReplaceDEKTx(missing key)", replace(fa.ID, id.New(id.WrappedKey), randomHex(t, 16)), store.ErrNotFound)
		wantErr(t, "ReplaceDEKTx(secret key)", replace(fa.ID, mustSecret(t, db, a.ID, store.KeyPurposeSecret), randomHex(t, 16)), store.ErrInvalid)
		wantErr(t, "ReplaceDEKTx(bad key id)", replace(fa.ID, "wk_x", randomHex(t, 16)), store.ErrInvalid)
		wantErr(t, "ReplaceDEKTx(bad name)", replace(fa.ID, newKey, "x"), store.ErrInvalid)
		wantErr(t, "ReplaceDEKTx(missing file)", replace(id.New(id.File), mustSecret(t, db, a.ID, store.KeyPurposeDEK), randomHex(t, 16)), store.ErrNotFound)

		// Completion.
		if err := files.CompleteUpload(ctx, a.ID, fa.ID, sha1111, 160, fixedNow); err != nil {
			t.Fatalf("CompleteUpload: %v", err)
		}
		if u, err := files.GetByUploadID(ctx, a.ID, fa.UploadID); err != nil || !u.File.Completed() || u.File.SHA256 != sha1111 ||
			u.File.CiphertextSize != 160 || !u.File.UploadedAt.Equal(msNow) {
			t.Errorf("after CompleteUpload = %+v, %v", u.File, err)
		}
		wantErr(t, "CompleteUpload twice", files.CompleteUpload(ctx, a.ID, fa.ID, sha1111, 160, fixedNow), store.ErrConflict)
		wantErr(t, "ReplaceDEKTx(completed)", replace(fa.ID, mustSecret(t, db, a.ID, store.KeyPurposeDEK), randomHex(t, 16)), store.ErrConflict)
		wantErr(t, "CompleteUpload(missing)", files.CompleteUpload(ctx, a.ID, id.New(id.File), sha1111, 1, fixedNow), store.ErrNotFound)
		wantErr(t, "CompleteUpload(bad sha)", files.CompleteUpload(ctx, a.ID, fb.ID, "x", 1, fixedNow), store.ErrInvalid)
		wantErr(t, "CompleteUpload(negative size)", files.CompleteUpload(ctx, a.ID, fb.ID, sha1111, -1, fixedNow), store.ErrInvalid)
		err = tx(func(tx *store.ScopedTx) error { return files.CompleteUploadTx(ctx, tx, fb.ID, emptySHA, 240, fixedNow) })
		if err != nil {
			t.Errorf("CompleteUploadTx: %v", err)
		}
		wantErr(t, "CompleteUploadTx twice", tx(func(tx *store.ScopedTx) error {
			return files.CompleteUploadTx(ctx, tx, fb.ID, emptySHA, 240, fixedNow)
		}), store.ErrConflict)

		// Termination of one file: its key must be destroyed first; the
		// transfer total, and so the quota, shrink.
		deleteFile := func(fileID string) error {
			return tx(func(tx *store.ScopedTx) error { return files.DeleteTx(ctx, tx, fileID) })
		}
		wantErr(t, "DeleteTx(key remains)", deleteFile(fc.ID), store.ErrKeysRemain)
		err = tx(func(tx *store.ScopedTx) error {
			if err := keys.DeleteTx(ctx, tx, fc.DEKKeyID); err != nil {
				return err
			}
			if u, err := files.GetByUploadIDTx(ctx, tx, fc.UploadID); err != nil || u.File.DEKKeyID != "" {
				t.Errorf("file after key destruction = %+v, %v", u.File, err)
			}
			return files.DeleteTx(ctx, tx, fc.ID)
		})
		if err != nil {
			t.Fatalf("erase file: %v", err)
		}
		wantErr(t, "DeleteTx twice", deleteFile(fc.ID), store.ErrNotFound)
		got, err := transfers.Get(ctx, a.ID, d.ID)
		if err != nil || got.TotalBytes != 300 || len(got.Files) != 2 {
			t.Errorf("after file DeleteTx = %+v, %v", got, err)
		}
		if n := usedBytes(t, db, a.ID); n != 300 {
			t.Errorf("UsedBytesTx = %d, want 300", n)
		}

		// Transfer deletion: keys first, then the rows (cascade).
		deleteTransfer := func(trfID string) error {
			return tx(func(tx *store.ScopedTx) error { return transfers.DeleteTx(ctx, tx, trfID) })
		}
		wantErr(t, "DeleteTx(keys remain)", deleteTransfer(d.ID), store.ErrKeysRemain)
		err = tx(func(tx *store.ScopedTx) error {
			for _, k := range []string{newKey, fb.DEKKeyID} {
				if err := keys.DeleteTx(ctx, tx, k); err != nil {
					return err
				}
			}
			return transfers.DeleteTx(ctx, tx, d.ID)
		})
		if err != nil {
			t.Fatalf("erase transfer: %v", err)
		}
		_, err = transfers.Get(ctx, a.ID, d.ID)
		wantErr(t, "Get(deleted)", err, store.ErrNotFound)
		if got, err := files.ListByTransfer(ctx, a.ID, d.ID); err != nil || len(got) != 0 {
			t.Errorf("files after transfer deletion = %+v, %v", got, err)
		}
		wantErr(t, "DeleteTx(deleted)", deleteTransfer(d.ID), store.ErrNotFound)
		if n := usedBytes(t, db, a.ID); n != 0 {
			t.Errorf("UsedBytesTx after deletion = %d", n)
		}

		// Malformed upload identifiers.
		_, err = files.GetByUploadID(ctx, a.ID, "upl_bad")
		wantErr(t, "GetByUploadID(malformed)", err, store.ErrInvalid)
		_, err = files.GetByUploadID(ctx, a.ID, fa.UploadID)
		wantErr(t, "GetByUploadID(deleted)", err, store.ErrNotFound)
		wantErr(t, "GetByUploadIDTx(malformed)", tx(func(tx *store.ScopedTx) error {
			_, err := files.GetByUploadIDTx(ctx, tx, "nope")
			return err
		}), store.ErrInvalid)
	})
}

// TestTransfersTenantDeletion checks that deleting a tenant removes its
// transfers, recipients, files and the invitations they reference, and
// nothing of another tenant.
func TestTransfersTenantDeletion(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		inv := mustInvitation(t, db, a.ID)
		ext := newTransfer()
		ext.SenderEmail, ext.SenderKind, ext.InvitationID = "bob@partner.example.org", store.DepositorExternal, inv.ID
		da := mustTransfer(t, db, a.ID, ext)
		db2 := mustTransfer(t, db, b.ID, newTransfer())
		if err := db.Tenants().Delete(ctx, a.ID); err != nil {
			t.Fatalf("Tenants.Delete: %v", err)
		}
		_, err := db.Transfers().Get(ctx, a.ID, da.ID)
		wantErr(t, "transfer after tenant deletion", err, store.ErrNotFound)
		_, err = db.TransferFiles().GetByUploadID(ctx, a.ID, da.Files[0].UploadID)
		wantErr(t, "file after tenant deletion", err, store.ErrNotFound)
		if got, err := db.Transfers().Get(ctx, b.ID, db2.ID); err != nil || !reflect.DeepEqual(got, db2) {
			t.Errorf("B's transfer = %+v, %v", got, err)
		}
	})
}

func TestTransfersFingerprintAndOpenCount(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		count := func(tid tenant.ID, sender string) (int, error) {
			var n int
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				n, err = transfers.CountUploadingTx(ctx, tx, sender, time.Time{})
				return err
			})
			return n, err
		}

		fp := randomHex(t, 32)
		tr := newTransfer()
		tr.IdempotencyKey, tr.RequestFingerprint = "key-1", fp
		if d := mustTransfer(t, db, a.ID, tr); d.RequestFingerprint != fp {
			t.Errorf("RequestFingerprint = %q, want %q", d.RequestFingerprint, fp)
		}
		bad := newTransfer()
		bad.RequestFingerprint = strings.ToUpper(fp)
		badFile := newFile(t, db, a.ID, "x", 1)
		err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return transfers.CreateTx(ctx, tx, bad, []string{"x@example.com"}, []store.TransferFile{badFile})
		})
		wantErr(t, "CreateTx(bad fingerprint)", err, store.ErrInvalid)

		// Open transfers: per sender and tenant, uploading only.
		mustTransfer(t, db, a.ID, newTransfer())
		fin := mustTransfer(t, db, a.ID, newTransfer())
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return transfers.FinalizeTx(ctx, tx, fin.ID, fixedNow)
		})
		if err != nil {
			t.Fatal(err)
		}
		other := newTransfer()
		other.SenderEmail = "dave@entity-a.example.com"
		mustTransfer(t, db, a.ID, other)
		mustTransfer(t, db, b.ID, newTransfer())
		if n, err := count(a.ID, "ALICE@entity-a.example.com"); err != nil || n != 2 {
			t.Errorf("CountUploadingTx(A, alice) = %d, %v; want 2", n, err)
		}
		if n, err := count(b.ID, "alice@entity-a.example.com"); err != nil || n != 1 {
			t.Errorf("CountUploadingTx(B, alice) = %d, %v; want 1", n, err)
		}
		_, err = count(a.ID, "nope")
		wantErr(t, "CountUploadingTx(bad sender)", err, store.ErrInvalid)

		// Only the transfers created since the given time count, and the
		// list returns them newest first, up to the limit.
		late := newTransfer()
		late.CreatedAt = fixedNow.Add(time.Hour)
		lateD := mustTransfer(t, db, a.ID, late)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			n, err := transfers.CountUploadingTx(ctx, tx, "alice@entity-a.example.com", late.CreatedAt)
			if err != nil || n != 1 {
				t.Errorf("CountUploadingTx(since) = %d, %v; want 1", n, err)
			}
			all, err := transfers.ListUploadingTx(ctx, tx, "Alice@entity-a.example.com", time.Time{}, 10)
			if err != nil || len(all) != 3 || all[0].ID != late.ID || all[0].Status != store.TransferUploading {
				t.Errorf("ListUploadingTx = %+v, %v", all, err)
			}
			if one, err := transfers.ListUploadingTx(ctx, tx, "alice@entity-a.example.com", time.Time{}, 1); err != nil || len(one) != 1 {
				t.Errorf("ListUploadingTx(limit 1) = %d, %v", len(one), err)
			}
			if recent, err := transfers.ListUploadingTx(ctx, tx, "alice@entity-a.example.com", late.CreatedAt, 10); err != nil || len(recent) != 1 {
				t.Errorf("ListUploadingTx(since) = %d, %v", len(recent), err)
			}
			_, err = transfers.ListUploadingTx(ctx, tx, "nope", time.Time{}, 10)
			wantErr(t, "ListUploadingTx(bad sender)", err, store.ErrInvalid)
			for _, limit := range []int{0, store.MaxTransferFiles + 1} {
				_, err = transfers.ListUploadingTx(ctx, tx, "alice@entity-a.example.com", time.Time{}, limit)
				wantErr(t, "ListUploadingTx(bad limit)", err, store.ErrInvalid)
			}
			files, err := db.TransferFiles().ListByTransferTx(ctx, tx, late.ID)
			if err != nil || !reflect.DeepEqual(files, lateD.Files) {
				t.Errorf("ListByTransferTx = %+v, %v", files, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		ctxDone, cancel := context.WithCancel(ctx)
		cancel()
		calls := []func(tx *store.ScopedTx) error{
			func(tx *store.ScopedTx) error {
				_, err := transfers.CountUploadingTx(ctxDone, tx, "alice@entity-a.example.com", time.Time{})
				return err
			},
			func(tx *store.ScopedTx) error {
				_, err := transfers.ListUploadingTx(ctxDone, tx, "alice@entity-a.example.com", time.Time{}, 10)
				return err
			},
			func(tx *store.ScopedTx) error {
				_, err := db.TransferFiles().ListByTransferTx(ctxDone, tx, late.ID)
				return err
			},
		}
		for i, call := range calls {
			if err := inTx(t, db, a.ID, call); err == nil {
				t.Errorf("call %d with a canceled context succeeded", i)
			}
		}
	})
}

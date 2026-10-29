package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Recipients of mustTransfer, normalized, in position order.
const (
	rcptBob   = "bob@partner.example.org"
	rcptCarol = "carol@entity-a.example.com"
)

// newLinkTokens returns n new link tokens of tid, each with a new sealed
// key, and their raw hashes.
func newLinkTokens(t *testing.T, db *store.DB, tid tenant.ID, n int) []store.LinkToken {
	t.Helper()
	out := make([]store.LinkToken, n)
	for i := range out {
		_, hash := newDownloadToken(t)
		out[i] = store.LinkToken{Hash: hash, KeyID: mustSecret(t, db, tid, store.KeyPurposeSecret)}
	}
	return out
}

// scanningPerRecipient creates a scanning per-recipient transfer of tid
// (two recipients, one clean complete file), modified by mod.
func scanningPerRecipient(t *testing.T, db *store.DB, tid tenant.ID, mod func(*store.Transfer)) store.TransferDetails {
	t.Helper()
	ctx := context.Background()
	fl := newFile(t, db, tid, "f.bin", 10)
	fl.SHA256, fl.CiphertextSize, fl.UploadedAt = sha1111, 50, fixedNow
	tr := newTransfer()
	tr.LinkMode = store.LinkModePerRecipient
	if mod != nil {
		mod(&tr)
	}
	d := mustTransfer(t, db, tid, tr, fl)
	err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
		if err := db.Transfers().FinalizeTx(ctx, tx, d.ID, fixedNow); err != nil {
			return err
		}
		return db.TransferFiles().SetScanResultTx(ctx, tx, d.Files[0].ID, store.ScanClean, "", fixedNow)
	})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	d, err = db.Transfers().Get(ctx, tid, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// availablePerRecipient makes a new per-recipient transfer of tid available
// at fixedNow with one link per recipient, and returns it with its links
// and their tokens.
func availablePerRecipient(t *testing.T, db *store.DB, tid tenant.ID, mod func(*store.Transfer)) (store.TransferDetails, []store.RecipientLink, []store.LinkToken) {
	t.Helper()
	ctx := context.Background()
	d := scanningPerRecipient(t, db, tid, mod)
	tokens := newLinkTokens(t, db, tid, 2)
	var links []store.RecipientLink
	err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
		var err error
		links, err = db.Transfers().MarkAvailableLinksTx(ctx, tx, d.ID, tokens, fixedNow)
		return err
	})
	if err != nil {
		t.Fatalf("MarkAvailableLinksTx: %v", err)
	}
	d, err = db.Transfers().Get(ctx, tid, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d, links, tokens
}

// eraseFileKeys destroys the data key of every file of d.
func eraseFileKeys(t *testing.T, db *store.DB, tid tenant.ID, d store.TransferDetails) {
	t.Helper()
	ctx := context.Background()
	err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
		for _, f := range d.Files {
			if err := db.WrappedKeys().DeleteTx(ctx, tx, f.DEKKeyID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("erase file keys: %v", err)
	}
}

func TestTransfersLinkModeCreation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		create := func(tr store.Transfer, fl store.TransferFile) error {
			return inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				return db.Transfers().CreateTx(ctx, tx, tr, []string{rcptBob}, []store.TransferFile{fl})
			})
		}
		bad := newTransfer()
		bad.LinkMode = "bogus"
		wantErr(t, "unknown link mode", create(bad, newFile(t, db, a.ID, "f", 1)), store.ErrInvalid)
		bad = newTransfer()
		bad.RecipientVerification = true
		wantErr(t, "verification on a shared transfer", create(bad, newFile(t, db, a.ID, "f", 1)), store.ErrInvalid)
		bad = newTransfer()
		bad.LinkMode, bad.ExpiryReminderAt = store.LinkModePerRecipient, fixedNow
		wantErr(t, "reminded new transfer", create(bad, newFile(t, db, a.ID, "f", 1)), store.ErrInvalid)

		d := scanningPerRecipient(t, db, a.ID, func(tr *store.Transfer) { tr.RecipientVerification = true })
		if d.LinkMode != store.LinkModePerRecipient || !d.RecipientVerification || !d.ExpiryReminderAt.IsZero() {
			t.Errorf("per-recipient transfer = %+v", d.Transfer)
		}
		if s := scanningTransfer(t, db, a.ID, fixedNow, 1); s.LinkMode != store.LinkModeShared || s.RecipientVerification {
			t.Errorf("default transfer = %+v", s.Transfer)
		}
	})
}

func TestRecipientLinksAvailability(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers, links := db.Transfers(), db.RecipientLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		markLinks := func(trfID string, tokens []store.LinkToken) ([]store.RecipientLink, error) {
			var out []store.RecipientLink
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				var err error
				out, err = transfers.MarkAvailableLinksTx(ctx, tx, trfID, tokens, fixedNow)
				return err
			})
			return out, err
		}
		d := scanningPerRecipient(t, db, a.ID, nil)

		// The shared path refuses a per-recipient transfer, and the reverse.
		_, hash := newDownloadToken(t)
		secret := mustSecret(t, db, a.ID, store.KeyPurposeSecret)
		err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			return transfers.MarkAvailableTx(ctx, tx, d.ID, hash, secret, fixedNow)
		})
		wantErr(t, "MarkAvailableTx(per recipient)", err, store.ErrInvalid)
		shared := scanningTransfer(t, db, a.ID, fixedNow, 1)
		_, err = markLinks(shared.ID, newLinkTokens(t, db, a.ID, 2))
		wantErr(t, "MarkAvailableLinksTx(shared)", err, store.ErrInvalid)

		// Malformed tokens.
		good := newLinkTokens(t, db, a.ID, 2)
		for name, tokens := range map[string][]store.LinkToken{
			"none":        nil,
			"too many":    make([]store.LinkToken, store.MaxTransferRecipients+1),
			"one missing": good[:1],
			"short hash":  {good[0], {Hash: good[1].Hash[:8], KeyID: good[1].KeyID}},
			"bad key id":  {good[0], {Hash: good[1].Hash, KeyID: "wk_bogus"}},
			"dek key":     {good[0], {Hash: good[1].Hash, KeyID: mustSecret(t, db, a.ID, store.KeyPurposeDEK)}},
		} {
			_, err := markLinks(d.ID, tokens)
			wantErr(t, "MarkAvailableLinksTx("+name+")", err, store.ErrInvalid)
		}
		_, err = markLinks(d.ID, []store.LinkToken{good[0], {Hash: good[1].Hash, KeyID: id.New(id.WrappedKey)}})
		wantErr(t, "MarkAvailableLinksTx(missing key)", err, store.ErrNotFound)
		_, err = markLinks(d.ID, []store.LinkToken{good[0], {Hash: good[0].Hash, KeyID: good[1].KeyID}})
		wantErr(t, "MarkAvailableLinksTx(duplicate hash)", err, store.ErrConflict)
		_, err = markLinks(id.New(id.Transfer), good)
		wantErr(t, "MarkAvailableLinksTx(missing transfer)", err, store.ErrNotFound)

		got, err := markLinks(d.ID, good)
		if err != nil {
			t.Fatalf("MarkAvailableLinksTx: %v", err)
		}
		if len(got) != 2 || got[0].Email != rcptBob || got[1].Email != rcptCarol || got[0].Position != 0 ||
			got[1].Position != 1 || got[0].TokenKeyID != good[0].KeyID || string(got[1].TokenHash) != string(good[1].Hash) ||
			!id.Valid(id.RecipientLink, got[0].ID) || got[0].TransferID != d.ID || !got[0].CreatedAt.Equal(msNow) ||
			got[0].DownloadCount != 0 || !got[0].VerifiedAt.IsZero() {
			t.Fatalf("links = %+v", got)
		}
		av, err := transfers.Get(ctx, a.ID, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if av.Status != store.TransferAvailable || av.DownloadTokenHash != nil || av.DownloadTokenKeyID != "" ||
			!av.AvailableAt.Equal(msNow) || !av.ExpiresAt.Equal(msNow.Add(7*24*time.Hour)) || !av.ExpiryReminderAt.IsZero() {
			t.Errorf("available transfer = %+v", av.Transfer)
		}
		_, err = markLinks(d.ID, newLinkTokens(t, db, a.ID, 2))
		wantErr(t, "MarkAvailableLinksTx(twice)", err, store.ErrConflict)

		// CreateTx on its own.
		createLinks := func(trfID string, tokens []store.LinkToken) error {
			return inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				_, err := links.CreateTx(ctx, tx, trfID, tokens, fixedNow)
				return err
			})
		}
		wantErr(t, "CreateTx(existing links)", createLinks(d.ID, newLinkTokens(t, db, a.ID, 2)), store.ErrConflict)
		wantErr(t, "CreateTx(shared)", createLinks(shared.ID, newLinkTokens(t, db, a.ID, 2)), store.ErrInvalid)
		wantErr(t, "CreateTx(no token)", createLinks(d.ID, nil), store.ErrInvalid)
		wantErr(t, "CreateTx(missing transfer)", createLinks(id.New(id.Transfer), newLinkTokens(t, db, a.ID, 2)), store.ErrNotFound)
		fresh := scanningPerRecipient(t, db, a.ID, nil)
		if err := createLinks(fresh.ID, newLinkTokens(t, db, a.ID, 2)); err != nil {
			t.Errorf("CreateTx: %v", err)
		}

		// A one-day transfer never gets a reminder (D16).
		short, _, _ := availablePerRecipient(t, db, a.ID, func(tr *store.Transfer) { tr.ExpiryDays = 1 })
		if !short.ExpiryReminderAt.Equal(msNow) {
			t.Errorf("1-day transfer reminder mark = %v, want %v", short.ExpiryReminderAt, msNow)
		}
	})
}

func TestRecipientLinksReads(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		links := db.RecipientLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		d, ls, tokens := availablePerRecipient(t, db, a.ID, nil)

		got, err := links.GetByTokenHash(ctx, a.ID, tokens[1].Hash)
		if err != nil || got.ID != ls[1].ID || got.Email != rcptCarol || got.TransferID != d.ID || got.TokenKeyID != tokens[1].KeyID {
			t.Errorf("GetByTokenHash = %+v, %v", got, err)
		}
		_, err = links.GetByTokenHash(ctx, a.ID, tokenHash("unknown"))
		wantErr(t, "GetByTokenHash(unknown)", err, store.ErrNotFound)
		_, err = links.GetByTokenHash(ctx, a.ID, tokens[0].Hash[:8])
		wantErr(t, "GetByTokenHash(short)", err, store.ErrInvalid)
		for _, bad := range badTenants {
			_, err = links.GetByTokenHash(ctx, bad, tokens[0].Hash)
			wantErr(t, "GetByTokenHash(bad tenant)", err, store.ErrInvalid)
			_, err = links.ListByTransfer(ctx, bad, d.ID)
			wantErr(t, "ListByTransfer(bad tenant)", err, store.ErrInvalid)
			_, err = links.TrackingByTransfer(ctx, bad, d.ID)
			wantErr(t, "TrackingByTransfer(bad tenant)", err, store.ErrInvalid)
			wantErr(t, "ResetReminderSent(bad tenant)", links.ResetReminderSent(ctx, bad, d.ID, []string{ls[0].ID}, msNow), store.ErrInvalid)
		}

		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			if l, err := links.GetTx(ctx, tx, ls[0].ID); err != nil || l.Email != rcptBob {
				t.Errorf("GetTx = %+v, %v", l, err)
			}
			_, err := links.GetTx(ctx, tx, "rcl_bogus")
			wantErr(t, "GetTx(malformed)", err, store.ErrInvalid)
			_, err = links.GetTx(ctx, tx, id.New(id.RecipientLink))
			wantErr(t, "GetTx(missing)", err, store.ErrNotFound)
			l, err := links.ListByTransferTx(ctx, tx, d.ID)
			if err != nil || len(l) != 2 || l[0].ID != ls[0].ID || l[1].ID != ls[1].ID {
				t.Errorf("ListByTransferTx = %+v, %v", l, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if l, err := links.ListByTransfer(ctx, a.ID, d.ID); err != nil || len(l) != 2 {
			t.Errorf("ListByTransfer = %+v, %v", l, err)
		}
		shared := availableTransfer(t, db, a.ID, false)
		if l, err := links.ListByTransfer(ctx, a.ID, shared.ID); err != nil || len(l) != 0 {
			t.Errorf("ListByTransfer(shared) = %+v, %v", l, err)
		}
	})
}

func TestRecipientLinksDownloads(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers, links := db.Transfers(), db.RecipientLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		d, ls, _ := availablePerRecipient(t, db, a.ID, func(tr *store.Transfer) { tr.DeleteAfterFirstDownload = true })
		file := d.Files[0].ID
		at := func(min int) time.Time { return msNow.Add(time.Duration(min) * time.Minute) }
		tx := func(fn func(*store.ScopedTx) error) error { return inTxCtx(ctx, t, db, a.ID, fn) }
		claim := func(linkID, fileID string, now time.Time) error {
			return tx(func(tx *store.ScopedTx) error { return links.ClaimTx(ctx, tx, linkID, fileID, now) })
		}
		completeItem := func(linkID, fileID string) (bool, error) {
			var first bool
			err := tx(func(tx *store.ScopedTx) error {
				var err error
				first, err = links.CompleteItemTx(ctx, tx, linkID, fileID, at(5))
				return err
			})
			return first, err
		}
		// complete records a link completion then the first download of the
		// transfer, in one transaction, as the download layer does.
		complete := func(linkID string, now, deleteAfter time.Time) (store.LinkCompletion, bool, error) {
			var (
				c     store.LinkCompletion
				first bool
			)
			err := tx(func(tx *store.ScopedTx) error {
				var err error
				if c, err = links.CompleteTx(ctx, tx, linkID, now); err != nil {
					return err
				}
				first, err = transfers.MarkFirstDownloadTx(ctx, tx, d.ID, now, deleteAfter)
				return err
			})
			return c, first, err
		}

		// Verification (display only).
		if err := tx(func(tx *store.ScopedTx) error { return links.MarkVerifiedTx(ctx, tx, ls[0].ID, at(1)) }); err != nil {
			t.Fatalf("MarkVerifiedTx: %v", err)
		}
		wantErr(t, "MarkVerifiedTx(missing)", tx(func(tx *store.ScopedTx) error {
			return links.MarkVerifiedTx(ctx, tx, id.New(id.RecipientLink), at(1))
		}), store.ErrNotFound)
		wantErr(t, "MarkVerifiedTx(malformed)", tx(func(tx *store.ScopedTx) error {
			return links.MarkVerifiedTx(ctx, tx, "bogus", at(1))
		}), store.ErrInvalid)

		// Starts: the archive twice, the file once.
		for i, c := range []struct {
			file string
			at   time.Time
		}{{"", at(2)}, {file, at(3)}, {"", at(4)}} {
			if err := claim(ls[0].ID, c.file, c.at); err != nil {
				t.Fatalf("ClaimTx %d: %v", i, err)
			}
		}
		wantErr(t, "ClaimTx(malformed file)", claim(ls[0].ID, "fil_bogus", at(4)), store.ErrInvalid)
		wantErr(t, "ClaimTx(malformed link)", claim("bogus", "", at(4)), store.ErrInvalid)
		wantErr(t, "ClaimTx(missing link)", claim(id.New(id.RecipientLink), "", at(4)), store.ErrNotFound)

		// Item completion, at most once.
		for i, want := range []bool{true, false} {
			if first, err := completeItem(ls[0].ID, ""); err != nil || first != want {
				t.Errorf("CompleteItemTx(archive) %d = %v, %v; want %v", i, first, err, want)
			}
		}
		_, err := completeItem(ls[1].ID, "")
		wantErr(t, "CompleteItemTx(not claimed)", err, store.ErrNotFound)
		_, err = completeItem(ls[0].ID, "fil_bogus")
		wantErr(t, "CompleteItemTx(malformed file)", err, store.ErrInvalid)
		_, err = completeItem("bogus", "")
		wantErr(t, "CompleteItemTx(malformed link)", err, store.ErrInvalid)

		// Link completion: the link never claimed is refused, the first
		// complete link records the first download without the deletion.
		_, _, err = complete(ls[1].ID, at(5), at(65))
		wantErr(t, "CompleteTx(not claimed)", err, store.ErrConflict)
		_, _, err = complete(id.New(id.RecipientLink), at(5), at(65))
		wantErr(t, "CompleteTx(missing)", err, store.ErrNotFound)
		_, _, err = complete("bogus", at(5), at(65))
		wantErr(t, "CompleteTx(malformed)", err, store.ErrInvalid)
		_, _, err = complete(ls[0].ID, at(5), time.Time{})
		wantErr(t, "MarkFirstDownloadTx(no deletion time)", err, store.ErrInvalid)
		c, first, err := complete(ls[0].ID, at(5), at(65))
		if err != nil || !c.First || c.AllComplete || !first {
			t.Fatalf("complete link 0 = %+v, %v, %v", c, first, err)
		}
		got, err := transfers.Get(ctx, a.ID, d.ID)
		if err != nil || !got.FirstDownloadedAt.Equal(at(5)) || !got.DeleteAfter.IsZero() {
			t.Errorf("after the first link: %+v, %v", got.Transfer, err)
		}
		c, first, err = complete(ls[0].ID, at(6), at(66))
		if err != nil || c.First || c.AllComplete || first {
			t.Errorf("complete link 0 again = %+v, %v, %v", c, first, err)
		}

		// The last link makes the transfer due for deletion.
		if err := claim(ls[1].ID, file, at(7)); err != nil {
			t.Fatal(err)
		}
		c, first, err = complete(ls[1].ID, at(8), at(68))
		if err != nil || !c.First || !c.AllComplete || first {
			t.Fatalf("complete link 1 = %+v, %v, %v", c, first, err)
		}
		got, err = transfers.Get(ctx, a.ID, d.ID)
		if err != nil || !got.FirstDownloadedAt.Equal(at(5)) || !got.DeleteAfter.Equal(at(68)) {
			t.Errorf("after every link: %+v, %v", got.Transfer, err)
		}

		// Tracking.
		tr, err := links.TrackingByTransfer(ctx, a.ID, d.ID)
		if err != nil || len(tr) != 2 {
			t.Fatalf("TrackingByTransfer = %+v, %v", tr, err)
		}
		t0, t1 := tr[0], tr[1]
		if t0.LinkID != ls[0].ID || t0.Email != rcptBob || !t0.VerifiedAt.Equal(at(1)) || !t0.FirstDownloadedAt.Equal(at(2)) ||
			!t0.LastDownloadedAt.Equal(at(4)) || !t0.CompletedAt.Equal(at(5)) || len(t0.Downloads) != 2 {
			t.Errorf("tracking 0 = %+v", t0)
		}
		if dl := t0.Downloads[0]; dl.FileID != "" || dl.Count != 2 || !dl.FirstAt.Equal(at(2)) || !dl.LastAt.Equal(at(4)) ||
			!dl.CompletedAt.Equal(at(5)) {
			t.Errorf("tracking 0 archive = %+v", dl)
		}
		if dl := t0.Downloads[1]; dl.FileID != file || dl.Count != 1 || !dl.CompletedAt.IsZero() {
			t.Errorf("tracking 0 file = %+v", dl)
		}
		if t1.Email != rcptCarol || t1.Position != 1 || !t1.VerifiedAt.IsZero() || !t1.CompletedAt.Equal(at(8)) ||
			len(t1.Downloads) != 1 || t1.Downloads[0].FileID != file {
			t.Errorf("tracking 1 = %+v", t1)
		}
		if l, err := links.GetByTokenHash(ctx, a.ID, ls[0].TokenHash); err != nil || l.DownloadCount != 3 {
			t.Errorf("link 0 = %+v, %v", l, err)
		}
		err = tx(func(tx *store.ScopedTx) error {
			tr, err := links.TrackingByTransferTx(ctx, tx, d.ID)
			if err != nil || len(tr) != 2 {
				t.Errorf("TrackingByTransferTx = %+v, %v", tr, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// A transfer without the option records the first link only.
		plain, pl, _ := availablePerRecipient(t, db, a.ID, nil)
		if err := claim(pl[0].ID, "", at(2)); err != nil {
			t.Fatal(err)
		}
		err = tx(func(tx *store.ScopedTx) error {
			if _, err := links.CompleteTx(ctx, tx, pl[0].ID, at(3)); err != nil {
				return err
			}
			_, err := transfers.MarkFirstDownloadTx(ctx, tx, plain.ID, at(3), at(63))
			wantErr(t, "MarkFirstDownloadTx(deletion time without option)", err, store.ErrInvalid)
			first, err := transfers.MarkFirstDownloadTx(ctx, tx, plain.ID, at(3), time.Time{})
			if err != nil || !first {
				t.Errorf("MarkFirstDownloadTx(plain) = %v, %v", first, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// An ended per-recipient transfer: an already recorded first
		// download answers false, an unrecorded one ErrConflict.
		for _, c := range []struct {
			d    store.TransferDetails
			want error
		}{{plain, nil}, {scanningPerRecipient(t, db, a.ID, nil), store.ErrConflict}} {
			eraseFileKeys(t, db, a.ID, c.d)
			err := tx(func(tx *store.ScopedTx) error {
				if _, err := links.DestroyKeysTx(ctx, tx, c.d.ID); err != nil {
					return err
				}
				return transfers.SetStatusTx(ctx, tx, c.d.ID, c.d.Status, store.TransferDeleted, at(9))
			})
			if err != nil {
				t.Fatal(err)
			}
			err = tx(func(tx *store.ScopedTx) error {
				first, err := transfers.MarkFirstDownloadTx(ctx, tx, c.d.ID, at(10), time.Time{})
				if first {
					t.Error("MarkFirstDownloadTx(ended) = true")
				}
				return err
			})
			wantErr(t, "MarkFirstDownloadTx(ended)", err, c.want)
		}
	})
}

// TestRecipientLinksEraseGuards checks the cryptographic erasure guard of
// every path ending or deleting a per-recipient transfer (T-110): each
// refuses with ErrKeysRemain while a link keeps its sealed token, and goes
// through once DestroyKeysTx (or DestroyRecipientKeyTx) destroyed it in the
// same transaction.
func TestRecipientLinksEraseGuards(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers, links := db.Transfers(), db.RecipientLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		now := msNow.Add(time.Hour)
		paths := map[string]func(tx *store.ScopedTx, trfID string) error{
			"expire": func(tx *store.ScopedTx, trfID string) error { return transfers.MarkExpiredTx(ctx, tx, trfID, now) },
			"delete after download": func(tx *store.ScopedTx, trfID string) error {
				return transfers.MarkDeletedTx(ctx, tx, trfID)
			},
			"admin delete": func(tx *store.ScopedTx, trfID string) error {
				return transfers.SetStatusTx(ctx, tx, trfID, store.TransferAvailable, store.TransferDeleted, now)
			},
			"tenant or subject erasure": func(tx *store.ScopedTx, trfID string) error { return transfers.DeleteTx(ctx, tx, trfID) },
		}
		for name, end := range paths {
			d, ls, _ := availablePerRecipient(t, db, a.ID, nil)
			eraseFileKeys(t, db, a.ID, d)
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error { return end(tx, d.ID) })
			wantErr(t, name+" with link keys", err, store.ErrKeysRemain)
			err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				n, err := links.DestroyKeysTx(ctx, tx, d.ID)
				if err != nil {
					return err
				}
				if n != 2 {
					t.Errorf("%s: DestroyKeysTx = %d, want 2", name, n)
				}
				return end(tx, d.ID)
			})
			if err != nil {
				t.Errorf("%s after DestroyKeysTx: %v", name, err)
			}
			for _, l := range ls {
				_, err := db.WrappedKeys().Get(ctx, a.ID, l.TokenKeyID)
				wantErr(t, name+": link key", err, store.ErrNotFound)
			}
			err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				n, err := links.DestroyKeysTx(ctx, tx, d.ID)
				if n != 0 {
					t.Errorf("%s: DestroyKeysTx again = %d", name, n)
				}
				return err
			})
			if err != nil {
				t.Errorf("%s: DestroyKeysTx again: %v", name, err)
			}
		}

		// Data-subject erasure of one recipient: its link key only.
		d, ls, _ := availablePerRecipient(t, db, a.ID, nil)
		remove := func(destroy bool) error {
			return inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				if destroy {
					done, err := links.DestroyRecipientKeyTx(ctx, tx, d.ID, "BOB@partner.example.org")
					if err != nil || !done {
						t.Errorf("DestroyRecipientKeyTx = %v, %v", done, err)
					}
				}
				return transfers.RemoveRecipientTx(ctx, tx, d.ID, rcptBob)
			})
		}
		wantErr(t, "RemoveRecipientTx with link key", remove(false), store.ErrKeysRemain)
		if err := remove(true); err != nil {
			t.Fatalf("RemoveRecipientTx after DestroyRecipientKeyTx: %v", err)
		}
		left, err := links.ListByTransfer(ctx, a.ID, d.ID)
		if err != nil || len(left) != 1 || left[0].ID != ls[1].ID || left[0].TokenKeyID == "" {
			t.Errorf("links left = %+v, %v", left, err)
		}
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			for _, email := range []string{rcptBob, "nobody@example.org"} {
				if done, err := links.DestroyRecipientKeyTx(ctx, tx, d.ID, email); err != nil || done {
					t.Errorf("DestroyRecipientKeyTx(%s) = %v, %v", email, done, err)
				}
			}
			_, err := links.DestroyRecipientKeyTx(ctx, tx, d.ID, "not an address")
			wantErr(t, "DestroyRecipientKeyTx(malformed)", err, store.ErrInvalid)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// Tenant deletion: refused while a link key remains (every wrapped
		// key of the tenant must be destroyed first).
		wantErr(t, "Tenants.Delete with link keys", db.Tenants().Delete(ctx, a.ID), store.ErrKeysRemain)
	})
}

func TestRecipientLinksReminders(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers, links := db.Transfers(), db.RecipientLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		d, ls, _ := availablePerRecipient(t, db, a.ID, nil)
		availablePerRecipient(t, db, a.ID, func(tr *store.Transfer) { tr.ExpiryDays = 1 }) // never listed (D16)
		availableTransfer(t, db, a.ID, false)                                              // shared: never listed
		page := store.SweepPage{Limit: store.ReminderSweepLimit}
		due := func(now time.Time) []store.TenantTransfer {
			t.Helper()
			got, err := links.DueReminders(ctx, now, page)
			if err != nil {
				t.Fatalf("DueReminders: %v", err)
			}
			return got
		}
		if got := due(msNow); len(got) != 0 {
			t.Errorf("DueReminders(availability) = %+v", got)
		}
		eve := d.ExpiresAt.Add(-time.Hour)
		got := due(eve)
		if len(got) != 1 || got[0].TenantID != a.ID || got[0].TransferID != d.ID || !got[0].SortKey.Equal(d.ExpiresAt) {
			t.Fatalf("DueReminders(eve) = %+v", got)
		}
		if got := due(d.ExpiresAt); len(got) != 0 {
			t.Errorf("DueReminders(expired) = %+v", got)
		}
		if got, err := links.DueReminders(ctx, eve, store.SweepPage{After: got[0], Limit: 1}); err != nil || len(got) != 0 {
			t.Errorf("DueReminders(after) = %+v, %v", got, err)
		}
		_, err := links.DueReminders(ctx, eve, store.SweepPage{})
		wantErr(t, "DueReminders(no limit)", err, store.ErrInvalid)

		tx := func(fn func(*store.ScopedTx) error) error { return inTxCtx(ctx, t, db, a.ID, fn) }
		targets := func() []store.RecipientLink {
			t.Helper()
			var out []store.RecipientLink
			if err := tx(func(tx *store.ScopedTx) error {
				var err error
				out, err = links.ReminderTargetsTx(ctx, tx, d.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return out
		}
		markSent := func(ids ...string) error {
			return tx(func(tx *store.ScopedTx) error { return links.MarkReminderSentTx(ctx, tx, ids, eve) })
		}
		if got := targets(); len(got) != 2 {
			t.Fatalf("ReminderTargetsTx = %+v", got)
		}
		// A recipient who started a download gets no reminder.
		if err := tx(func(tx *store.ScopedTx) error { return links.ClaimTx(ctx, tx, ls[0].ID, "", msNow) }); err != nil {
			t.Fatal(err)
		}
		if got := targets(); len(got) != 1 || got[0].ID != ls[1].ID {
			t.Fatalf("ReminderTargetsTx after a download = %+v", got)
		}
		if err := markSent(ls[1].ID); err != nil {
			t.Fatalf("MarkReminderSentTx: %v", err)
		}
		if got := targets(); len(got) != 0 {
			t.Errorf("ReminderTargetsTx after the reminder = %+v", got)
		}
		wantErr(t, "MarkReminderSentTx(twice)", markSent(ls[1].ID), store.ErrConflict)
		wantErr(t, "MarkReminderSentTx(missing)", markSent(id.New(id.RecipientLink)), store.ErrNotFound)
		wantErr(t, "MarkReminderSentTx(malformed)", markSent("bogus"), store.ErrInvalid)
		markTransfer := func(trfID string) error {
			return tx(func(tx *store.ScopedTx) error { return transfers.MarkExpiryReminderTx(ctx, tx, trfID, eve) })
		}
		if err := markTransfer(d.ID); err != nil {
			t.Fatalf("MarkExpiryReminderTx: %v", err)
		}
		if got := due(eve); len(got) != 0 {
			t.Errorf("DueReminders after the pass = %+v", got)
		}
		if got, err := transfers.Get(ctx, a.ID, d.ID); err != nil || !got.ExpiryReminderAt.Equal(eve) {
			t.Errorf("reminder mark = %v, %v", got.ExpiryReminderAt, err)
		}
		wantErr(t, "MarkExpiryReminderTx(twice)", markTransfer(d.ID), store.ErrConflict)
		wantErr(t, "MarkExpiryReminderTx(missing)", markTransfer(id.New(id.Transfer)), store.ErrNotFound)

		// A failed reminder mail: the link and the pass of the transfer are
		// reset, so that the next sweep lists it again for that link only.
		reset := func(trfID string, now time.Time, ids ...string) error {
			return links.ResetReminderSent(ctx, a.ID, trfID, ids, now)
		}
		wantErr(t, "ResetReminderSent(missing)", reset(d.ID, eve, id.New(id.RecipientLink)), store.ErrNotFound)
		wantErr(t, "ResetReminderSent(malformed)", reset(d.ID, eve, "bogus"), store.ErrInvalid)
		wantErr(t, "ResetReminderSent(other transfer)", reset(id.New(id.Transfer), eve, ls[1].ID), store.ErrNotFound)
		if got := due(eve); len(got) != 0 {
			t.Errorf("DueReminders after a refused reset = %+v", got)
		}
		if err := reset(d.ID, eve); err != nil {
			t.Fatalf("ResetReminderSent(no link): %v", err)
		}
		if got := due(eve); len(got) != 0 {
			t.Errorf("DueReminders after a reset without link = %+v", got)
		}
		if err := reset(d.ID, eve, ls[1].ID); err != nil {
			t.Fatalf("ResetReminderSent: %v", err)
		}
		if got := targets(); len(got) != 1 || got[0].ID != ls[1].ID {
			t.Errorf("ReminderTargetsTx after the reset = %+v", got)
		}
		if got := due(eve); len(got) != 1 || got[0].TransferID != d.ID {
			t.Errorf("DueReminders after the reset = %+v", got)
		}
		// Once expired, the pass of the transfer stays recorded.
		if err := markSent(ls[1].ID); err != nil {
			t.Fatal(err)
		}
		if err := markTransfer(d.ID); err != nil {
			t.Fatal(err)
		}
		if err := reset(d.ID, d.ExpiresAt, ls[1].ID); err != nil {
			t.Fatalf("ResetReminderSent(expired): %v", err)
		}
		if got, err := transfers.Get(ctx, a.ID, d.ID); err != nil || !got.ExpiryReminderAt.Equal(eve) {
			t.Errorf("reminder mark after a reset at the expiry = %v, %v", got.ExpiryReminderAt, err)
		}
		if got := targets(); len(got) != 1 {
			t.Errorf("ReminderTargetsTx after the reset at the expiry = %+v", got)
		}
	})
}

func TestRecipientChallenges(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Challenges()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		_, ls, _ := availablePerRecipient(t, db, a.ID, nil)
		_, lsB, _ := availablePerRecipient(t, db, b.ID, nil)
		recipient := func(email, linkID string, intent store.RecipientIntent) store.Challenge {
			c := newChallenge(t, email, ipA)
			c.Purpose, c.RecipientLinkID, c.RecipientIntent = store.ChallengeRecipient, linkID, intent
			return c
		}
		good := recipient("Bob@Partner.example.org", ls[0].ID, store.IntentDownload)
		if err := repo.Create(ctx, a.ID, good); err != nil {
			t.Fatalf("Create(recipient): %v", err)
		}
		got, err := repo.Get(ctx, a.ID, good.ID)
		if err != nil || got.Purpose != store.ChallengeRecipient || got.RecipientLinkID != ls[0].ID ||
			got.RecipientIntent != store.IntentDownload || got.Email != rcptBob {
			t.Errorf("Get(recipient) = %+v, %v", got, err)
		}
		deposit := newChallenge(t, rcptBob, ipA)
		if err := repo.Create(ctx, a.ID, deposit); err != nil {
			t.Fatalf("Create(deposit): %v", err)
		}
		if got, err := repo.Get(ctx, a.ID, deposit.ID); err != nil || got.Purpose != store.ChallengeDeposit ||
			got.RecipientLinkID != "" || got.RecipientIntent != "" {
			t.Errorf("Get(deposit) = %+v, %v", got, err)
		}
		if err := repo.Create(ctx, a.ID, recipient(rcptCarol, ls[1].ID, store.IntentReply)); err != nil {
			t.Errorf("Create(reply): %v", err)
		}

		withInvitation := recipient(rcptBob, ls[0].ID, store.IntentDownload)
		withInvitation.InvitationID = id.New(id.Invitation)
		depositWithLink := newChallenge(t, rcptBob, ipA)
		depositWithLink.RecipientLinkID = ls[0].ID
		depositWithIntent := newChallenge(t, rcptBob, ipA)
		depositWithIntent.RecipientIntent = store.IntentDownload
		unknown := newChallenge(t, rcptBob, ipA)
		unknown.Purpose = "reply"
		for name, c := range map[string]store.Challenge{
			"other address":  recipient(rcptCarol, ls[0].ID, store.IntentDownload),
			"no intent":      recipient(rcptBob, ls[0].ID, ""),
			"unknown intent": recipient(rcptBob, ls[0].ID, "upload"),
			"no link":        recipient(rcptBob, "", store.IntentDownload),
			"invitation":     withInvitation,
			"deposit link":   depositWithLink,
			"deposit intent": depositWithIntent,
			"purpose":        unknown,
		} {
			wantErr(t, "Create("+name+")", repo.Create(ctx, a.ID, c), store.ErrInvalid)
		}
		wantErr(t, "Create(missing link)", repo.Create(ctx, a.ID, recipient(rcptBob, id.New(id.RecipientLink), store.IntentDownload)), store.ErrNotFound)
		wantErr(t, "Create(link of B)", repo.Create(ctx, a.ID, recipient(rcptBob, lsB[0].ID, store.IntentDownload)), store.ErrNotFound)

		// Budgets: per link for the recipient codes, deposit codes only per
		// address, every code per IP.
		since := fixedNow.Add(-time.Hour)
		if n, err := repo.CountByLinkSince(ctx, a.ID, ls[0].ID, since); err != nil || n != 1 {
			t.Errorf("CountByLinkSince = %d, %v; want 1", n, err)
		}
		if n, err := repo.CountSince(ctx, a.ID, rcptBob, since); err != nil || n != 1 {
			t.Errorf("CountSince(deposit only) = %d, %v; want 1", n, err)
		}
		if n, err := repo.CountByIPSince(ctx, a.ID, ipA, since); err != nil || n != 3 {
			t.Errorf("CountByIPSince(shared) = %d, %v; want 3", n, err)
		}
		_, err = repo.CountByLinkSince(ctx, a.ID, "bogus", since)
		wantErr(t, "CountByLinkSince(malformed)", err, store.ErrInvalid)
		if n, err := repo.CountByLinkSince(ctx, b.ID, ls[0].ID, since); err != nil || n != 0 {
			t.Errorf("CountByLinkSince(from B) = %d, %v", n, err)
		}
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			if n, err := repo.CountByLinkSinceTx(ctx, tx, ls[1].ID, since); err != nil || n != 1 {
				t.Errorf("CountByLinkSinceTx = %d, %v; want 1", n, err)
			}
			_, err := repo.CountByLinkSinceTx(ctx, tx, "bogus", since)
			wantErr(t, "CountByLinkSinceTx(malformed)", err, store.ErrInvalid)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		// The data-subject erasure deletes every purpose.
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			n, err := repo.DeleteByEmailTx(ctx, tx, rcptBob)
			if n != 2 {
				t.Errorf("DeleteByEmailTx = %d, want 2", n)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestChallengesLatestByLink(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Challenges()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		_, ls, _ := availablePerRecipient(t, db, a.ID, nil)
		_, lsB, _ := availablePerRecipient(t, db, b.ID, nil)
		recipient := func(email, linkID string, created time.Time) store.Challenge {
			c := newChallenge(t, email, ipA)
			c.Purpose, c.RecipientLinkID, c.RecipientIntent = store.ChallengeRecipient, linkID, store.IntentDownload
			created = created.Truncate(time.Millisecond) // the stored precision
			c.CreatedAt, c.ExpiresAt = created, created.Add(15*time.Minute)
			return c
		}

		_, err := repo.LatestByLink(ctx, a.ID, ls[0].ID)
		wantErr(t, "LatestByLink(none)", err, store.ErrNotFound)
		// A deposit code of the same address is never a code of the link.
		if err := repo.Create(ctx, a.ID, newChallenge(t, rcptBob, ipA)); err != nil {
			t.Fatal(err)
		}
		older := recipient(rcptBob, ls[0].ID, fixedNow.Add(-2*time.Minute))
		newest := recipient(rcptBob, ls[0].ID, fixedNow)
		late := recipient(rcptBob, ls[0].ID, fixedNow.Add(-time.Minute)) // created last, but older
		other := recipient(rcptCarol, ls[1].ID, fixedNow.Add(time.Minute))
		inB := recipient(rcptBob, lsB[0].ID, fixedNow.Add(time.Hour))
		for _, c := range []store.Challenge{older, newest, late, other} {
			if err := repo.Create(ctx, a.ID, c); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}
		if err := repo.Create(ctx, b.ID, inB); err != nil {
			t.Fatalf("Create(B): %v", err)
		}
		got, err := repo.LatestByLink(ctx, a.ID, ls[0].ID)
		if err != nil || got.ID != newest.ID || got.Email != rcptBob || got.Purpose != store.ChallengeRecipient ||
			got.RecipientLinkID != ls[0].ID || got.RecipientIntent != store.IntentDownload ||
			!got.CreatedAt.Equal(newest.CreatedAt) || !got.ExpiresAt.Equal(newest.ExpiresAt) || !got.ConsumedAt.IsZero() ||
			got.AttemptsRemaining != store.MaxChallengeAttempts || got.ClientIP != ipA {
			t.Errorf("LatestByLink = %+v, %v; want %s", got, err, newest.ID)
		}
		// Returned in whatever state it is: a consumed code stays the latest.
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			if err := repo.ConsumeTx(ctx, tx, newest.ID, fixedNow); err != nil {
				return err
			}
			got, err := repo.LatestByLinkTx(ctx, tx, ls[0].ID)
			if err != nil || got.ID != newest.ID || !got.ConsumedAt.Equal(newest.CreatedAt) {
				t.Errorf("LatestByLinkTx(consumed) = %+v, %v", got, err)
			}
			if got, err := repo.LatestByLinkTx(ctx, tx, ls[1].ID); err != nil || got.ID != other.ID {
				t.Errorf("LatestByLinkTx(other link) = %+v, %v", got, err)
			}
			_, err = repo.LatestByLinkTx(ctx, tx, "bogus")
			wantErr(t, "LatestByLinkTx(malformed)", err, store.ErrInvalid)
			_, err = repo.LatestByLinkTx(ctx, tx, lsB[0].ID)
			wantErr(t, "LatestByLinkTx(link of B)", err, store.ErrNotFound)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// Isolation: B never reads the codes of A, nor A those of B.
		_, err = repo.LatestByLink(ctx, b.ID, ls[0].ID)
		wantErr(t, "LatestByLink(A's link from B)", err, store.ErrNotFound)
		_, err = repo.LatestByLink(ctx, a.ID, lsB[0].ID)
		wantErr(t, "LatestByLink(B's link from A)", err, store.ErrNotFound)
		if got, err := repo.LatestByLink(ctx, b.ID, lsB[0].ID); err != nil || got.ID != inB.ID {
			t.Errorf("LatestByLink(B) = %+v, %v", got, err)
		}
		_, err = repo.LatestByLink(ctx, a.ID, "bogus")
		wantErr(t, "LatestByLink(malformed)", err, store.ErrInvalid)
		for _, tid := range badTenants {
			if _, err := repo.LatestByLink(ctx, tid, ls[0].ID); err == nil {
				t.Errorf("LatestByLink(tenant %q) succeeded", tid)
			}
		}
	})
}

func TestTransfersByLink(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		repo := db.RecipientLinks()
		if got, err := repo.TransfersByLink(ctx, a.ID); err != nil || len(got) != 0 {
			t.Errorf("TransfersByLink(empty) = %v, %v", got, err)
		}
		d, ls, _ := availablePerRecipient(t, db, a.ID, nil)
		dB, lsB, _ := availablePerRecipient(t, db, b.ID, nil)
		got, err := repo.TransfersByLink(ctx, a.ID)
		if err != nil || len(got) != len(ls) {
			t.Fatalf("TransfersByLink = %v, %v", got, err)
		}
		for _, l := range ls {
			if got[l.ID] != d.ID {
				t.Errorf("link %s: transfer %q, want %s", l.ID, got[l.ID], d.ID)
			}
		}
		// Isolation: each tenant lists its own links only.
		gotB, err := repo.TransfersByLink(ctx, b.ID)
		if err != nil || len(gotB) != len(lsB) || gotB[lsB[0].ID] != dB.ID {
			t.Errorf("TransfersByLink(B) = %v, %v", gotB, err)
		}
		for _, tid := range badTenants {
			if _, err := repo.TransfersByLink(ctx, tid); err == nil {
				t.Errorf("TransfersByLink(tenant %q) succeeded", tid)
			}
		}
	})
}

func TestLinkFailureKey(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		linkA, linkB := id.New(id.RecipientLink), id.New(id.RecipientLink)
		if k := store.LinkFailureKey(linkA); k.Scope != store.FailureScopeTransfer || k.Key != linkA {
			t.Errorf("LinkFailureKey = %+v", k)
		}
		pf := db.PasswordFailures()
		// Three failures lock link A only: link B keeps its tries.
		for range store.MaxPasswordFailures {
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				_, err := pf.RecordFailureTx(ctx, tx, []store.FailureKey{store.LinkFailureKey(linkA)}, fixedNow)
				return err
			})
			if err != nil {
				t.Fatalf("RecordFailureTx: %v", err)
			}
		}
		check := func(linkID string) time.Time {
			var until time.Time
			if err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				var err error
				until, err = pf.CheckTx(ctx, tx, []store.FailureKey{store.LinkFailureKey(linkID)}, fixedNow)
				return err
			}); err != nil {
				t.Fatalf("CheckTx: %v", err)
			}
			return until
		}
		if check(linkA).IsZero() || !check(linkB).IsZero() {
			t.Errorf("locks: A %v, B %v", check(linkA), check(linkB))
		}
		err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := pf.CheckTx(ctx, tx, []store.FailureKey{store.LinkFailureKey("rcl_bogus")}, fixedNow)
			return err
		})
		wantErr(t, "CheckTx(malformed link)", err, store.ErrInvalid)
	})
}

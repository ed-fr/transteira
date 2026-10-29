package store_test

import (
	"cmp"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// senderAlice is the normalized sender of newTransfer.
const senderAlice = "alice@entity-a.example.com"

// senderFixture is a tenant A with transfers of every kind sent by alice,
// and transfers of others.
type senderFixture struct {
	db   *store.DB
	a, b *tenant.Tenant
	// shared is an available shared transfer of alice; linked an available
	// per-recipient transfer of alice with a download started through its
	// first link; scanning and uploading are transfers of alice in these
	// states.
	shared, linked, scanning, uploading store.TransferDetails
	links                               []store.RecipientLink
	// byToken is a transfer of alice's address created with an API token,
	// ofBob an available transfer of another sender, inB an available
	// transfer of alice's address in tenant B.
	byToken, ofBob, inB store.TransferDetails
}

// newSenderFixture builds a senderFixture.
func newSenderFixture(t *testing.T, e storetest.Engine) *senderFixture {
	t.Helper()
	ctx := context.Background()
	db := openDB(t, e)
	f := &senderFixture{db: db}
	f.a = newTenant(t, db, "transfer.entity-a.example.com")
	f.b = newTenant(t, db, "transfer.entity-b.example.com")
	f.shared = availableTransfer(t, db, f.a.ID, false)
	f.linked, f.links, _ = availablePerRecipient(t, db, f.a.ID, nil)
	err := inTxCtx(ctx, t, db, f.a.ID, func(tx *store.ScopedTx) error {
		if err := db.RecipientLinks().ClaimTx(ctx, tx, f.links[0].ID, "", fixedNow); err != nil {
			return err
		}
		return db.Transfers().IncrementDownloadsTx(ctx, tx, f.linked.ID)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.scanning = scanningPerRecipient(t, db, f.a.ID, nil)
	f.uploading = mustTransfer(t, db, f.a.ID, newTransfer())
	tok := mustAPIToken(t, db, f.a.ID, newAPIToken(t))
	byToken := newTransfer()
	byToken.APITokenID = tok.ID
	f.byToken = mustTransfer(t, db, f.a.ID, byToken)
	f.ofBob, _, _ = availablePerRecipient(t, db, f.a.ID, func(tr *store.Transfer) { tr.SenderEmail = "bob@entity-a.example.com" })
	f.inB, _, _ = availablePerRecipient(t, db, f.b.ID, nil)
	return f
}

// get reads the transfer trfID of tenant A.
func (f *senderFixture) get(t *testing.T, trfID string) store.TransferDetails {
	t.Helper()
	d, err := f.db.Transfers().Get(context.Background(), f.a.ID, trfID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTransfersListBySender(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSenderFixture(t, e)
		transfers := f.db.Transfers()

		// Only alice's session transfers in progress, newest first.
		want := []store.TransferDetails{f.shared, f.linked, f.scanning}
		slices.SortFunc(want, func(x, y store.TransferDetails) int {
			if c := y.CreatedAt.Compare(x.CreatedAt); c != 0 {
				return c
			}
			return cmp.Compare(y.ID, x.ID)
		})
		page, err := transfers.ListBySender(ctx, f.a.ID, "Alice@Entity-A.example.com", "", 0)
		if err != nil || len(page.Items) != len(want) || page.NextCursor != "" {
			t.Fatalf("ListBySender = %+v, %v", page, err)
		}
		for i, it := range page.Items {
			if it.ID != want[i].ID {
				t.Errorf("item %d = %s, want %s", i, it.ID, want[i].ID)
			}
			if it.FileCount != 1 || !slices.Equal(it.Recipients, want[i].Recipients) {
				t.Errorf("item %s = %+v", it.ID, it)
			}
			wantBy := 0
			if it.ID == f.linked.ID {
				wantBy = 1
			}
			if it.DownloadedBy != wantBy {
				t.Errorf("item %s DownloadedBy = %d, want %d", it.ID, it.DownloadedBy, wantBy)
			}
		}

		// Pages of one.
		var got []string
		cursor := ""
		for range len(want) + 1 {
			p, err := transfers.ListBySender(ctx, f.a.ID, senderAlice, cursor, 1)
			if err != nil || len(p.Items) != 1 {
				t.Fatalf("page after %q = %+v, %v", cursor, p, err)
			}
			got = append(got, p.Items[0].ID)
			if cursor = p.NextCursor; cursor == "" {
				break
			}
		}
		if len(got) != len(want) {
			t.Errorf("paged %d items, want %d", len(got), len(want))
		}

		// Other addresses and tenants.
		if p, err := transfers.ListBySender(ctx, f.a.ID, "nobody@entity-a.example.com", "", 0); err != nil || len(p.Items) != 0 {
			t.Errorf("unknown sender = %+v, %v", p, err)
		}
		if p, err := transfers.ListBySender(ctx, f.b.ID, senderAlice, "", 0); err != nil || len(p.Items) != 1 || p.Items[0].ID != f.inB.ID {
			t.Errorf("tenant B = %+v, %v", p, err)
		}

		// Invalid input.
		_, err = transfers.ListBySender(ctx, f.a.ID, "nope", "", 0)
		wantErr(t, "bad address", err, store.ErrInvalid)
		_, err = transfers.ListBySender(ctx, f.a.ID, senderAlice, "garbage", 0)
		wantErr(t, "bad cursor", err, store.ErrInvalid)
		_, err = transfers.ListBySender(ctx, badTenant, senderAlice, "", 0)
		wantErr(t, "bad tenant", err, store.ErrInvalid)
	})
}

func TestTransfersGetBySender(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSenderFixture(t, e)
		transfers := f.db.Transfers()

		d, err := transfers.GetBySender(ctx, f.a.ID, f.linked.ID, "ALICE@entity-a.example.com")
		if err != nil || d.ID != f.linked.ID || len(d.Files) != 1 || len(d.Recipients) != 2 || d.DownloadedBy != 1 ||
			len(d.Tracking) != 2 || d.Tracking[0].LinkID != f.links[0].ID || len(d.Tracking[0].Downloads) != 1 ||
			d.DownloadCount != 1 {
			t.Fatalf("GetBySender(linked) = %+v, %v", d, err)
		}
		d, err = transfers.GetBySender(ctx, f.a.ID, f.shared.ID, senderAlice)
		if err != nil || d.ID != f.shared.ID || d.DownloadedBy != 0 || len(d.Tracking) != 0 {
			t.Errorf("GetBySender(shared) = %+v, %v", d, err)
		}
		if d, err := transfers.GetBySender(ctx, f.a.ID, f.scanning.ID, senderAlice); err != nil || d.Status != store.TransferScanning {
			t.Errorf("GetBySender(scanning) = %+v, %v", d, err)
		}

		// Everything else is the same not-found.
		for name, c := range map[string]struct {
			tid   tenant.ID
			trfID string
			email string
		}{
			"uploading":       {f.a.ID, f.uploading.ID, senderAlice},
			"api token":       {f.a.ID, f.byToken.ID, senderAlice},
			"other sender":    {f.a.ID, f.ofBob.ID, senderAlice},
			"as other sender": {f.a.ID, f.linked.ID, "bob@entity-a.example.com"},
			"other tenant":    {f.b.ID, f.linked.ID, senderAlice},
			"of other tenant": {f.a.ID, f.inB.ID, senderAlice},
			"unknown":         {f.a.ID, "trf_unknown", senderAlice},
		} {
			_, err := transfers.GetBySender(ctx, c.tid, c.trfID, c.email)
			wantErr(t, "GetBySender("+name+")", err, store.ErrNotFound)
			err = inTxCtx(ctx, t, f.db, c.tid, func(tx *store.ScopedTx) error {
				_, err := transfers.GetBySenderTx(ctx, tx, c.trfID, c.email)
				return err
			})
			wantErr(t, "GetBySenderTx("+name+")", err, store.ErrNotFound)
		}
		_, err = transfers.GetBySender(ctx, f.a.ID, f.shared.ID, "nope")
		wantErr(t, "bad address", err, store.ErrInvalid)
		_, err = transfers.GetBySender(ctx, badTenant, f.shared.ID, senderAlice)
		wantErr(t, "bad tenant", err, store.ErrInvalid)
		err = inTxCtx(ctx, t, f.db, f.a.ID, func(tx *store.ScopedTx) error {
			d, err := transfers.GetBySenderTx(ctx, tx, f.linked.ID, senderAlice)
			if err != nil || d.DownloadedBy != 1 || len(d.Tracking) != 2 {
				t.Errorf("GetBySenderTx = %+v, %v", d, err)
			}
			_, err = transfers.GetBySenderTx(ctx, tx, f.linked.ID, "nope")
			wantErr(t, "GetBySenderTx(bad address)", err, store.ErrInvalid)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestTransfersSenderStatus(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSenderFixture(t, e)
		transfers := f.db.Transfers()
		for trfID, want := range map[string]store.TransferStatus{
			f.uploading.ID: store.TransferUploading, f.scanning.ID: store.TransferScanning, f.shared.ID: store.TransferAvailable,
		} {
			if got, err := transfers.SenderStatus(ctx, f.a.ID, trfID, "Alice@entity-a.example.com"); err != nil || got != want {
				t.Errorf("SenderStatus(%s) = %q, %v, want %q", trfID, got, err, want)
			}
		}
		for name, trfID := range map[string]string{"api token": f.byToken.ID, "other sender": f.ofBob.ID, "other tenant": f.inB.ID} {
			_, err := transfers.SenderStatus(ctx, f.a.ID, trfID, senderAlice)
			wantErr(t, "SenderStatus("+name+")", err, store.ErrNotFound)
		}
		_, err := transfers.SenderStatus(ctx, f.b.ID, f.shared.ID, senderAlice)
		wantErr(t, "SenderStatus(from B)", err, store.ErrNotFound)
		_, err = transfers.SenderStatus(ctx, f.a.ID, f.shared.ID, "nope")
		wantErr(t, "bad address", err, store.ErrInvalid)
		_, err = transfers.SenderStatus(ctx, badTenant, f.shared.ID, senderAlice)
		wantErr(t, "bad tenant", err, store.ErrInvalid)
	})
}

func TestTransfersExtend(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSenderFixture(t, e)
		db, transfers := f.db, f.db.Transfers()
		extend := func(tid tenant.ID, trfID, email string, expiresAt, now time.Time) (store.TransferExtension, error) {
			var x store.TransferExtension
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				x, err = transfers.ExtendTx(ctx, tx, trfID, email, expiresAt, now)
				return err
			})
			return x, err
		}
		created := f.shared.CreatedAt
		limit := created.Add(store.MaxTransferLifetime)
		now := fixedNow.Add(24 * time.Hour)
		day := func(n int) time.Time { return now.Add(time.Duration(n) * 24 * time.Hour) }

		// Invalid input, scope and state.
		_, err := extend(f.a.ID, f.shared.ID, "nope", day(30), now)
		wantErr(t, "bad address", err, store.ErrInvalid)
		_, err = extend(f.a.ID, f.shared.ID, senderAlice, now, now)
		wantErr(t, "expiry not after now", err, store.ErrInvalid)
		for name, c := range map[string]struct {
			tid          tenant.ID
			trfID, email string
		}{
			"uploading":       {f.a.ID, f.uploading.ID, senderAlice},
			"api token":       {f.a.ID, f.byToken.ID, senderAlice},
			"other sender":    {f.a.ID, f.ofBob.ID, senderAlice},
			"as other sender": {f.a.ID, f.shared.ID, "bob@entity-a.example.com"},
			"from tenant B":   {f.b.ID, f.shared.ID, senderAlice},
			"of tenant B":     {f.a.ID, f.inB.ID, senderAlice},
		} {
			_, err := extend(c.tid, c.trfID, c.email, day(30), now)
			wantErr(t, "extend "+name, err, store.ErrNotFound)
		}
		_, err = extend(f.a.ID, f.scanning.ID, senderAlice, day(30), now)
		wantErr(t, "scanning", err, store.ErrNotExtendable)
		_, err = extend(f.a.ID, f.shared.ID, senderAlice, f.shared.ExpiresAt.Add(30*24*time.Hour), f.shared.ExpiresAt)
		wantErr(t, "past its expiry", err, store.ErrNotExtendable)
		_, err = extend(f.a.ID, f.shared.ID, senderAlice, f.shared.ExpiresAt, now)
		wantErr(t, "same expiry", err, store.ErrExtensionShortens)
		_, err = extend(f.a.ID, f.shared.ID, senderAlice, day(1), now)
		wantErr(t, "shorter", err, store.ErrExtensionShortens)
		_, err = extend(f.a.ID, f.shared.ID, senderAlice, limit.Add(time.Millisecond), now)
		wantErr(t, "beyond 90 days", err, store.ErrExtensionLimit)
		if d := f.get(t, f.shared.ID); d.ExtensionCount != 0 || !d.ExtendedAt.IsZero() || !d.ExpiresAt.Equal(f.shared.ExpiresAt) {
			t.Fatalf("refused extensions changed the transfer: %+v", d.Transfer)
		}

		// Two extensions, the second up to the 90-day limit.
		x, err := extend(f.a.ID, f.shared.ID, "Alice@Entity-A.example.com", day(30), now)
		if err != nil || !x.PreviousExpiresAt.Equal(f.shared.ExpiresAt) || !x.ExpiresAt.Equal(day(30)) || x.Count != 1 ||
			x.ReminderSkipped {
			t.Fatalf("first extension = %+v, %v", x, err)
		}
		d := f.get(t, f.shared.ID)
		if d.ExtensionCount != 1 || !d.ExtendedAt.Equal(now.Truncate(time.Millisecond)) ||
			!d.ExpiresAt.Equal(day(30).Truncate(time.Millisecond)) || !d.ExpiryReminderAt.IsZero() {
			t.Errorf("after the first extension: %+v", d.Transfer)
		}
		later := day(29)
		x, err = extend(f.a.ID, f.shared.ID, senderAlice, limit, later)
		if err != nil || x.Count != 2 || !x.ExpiresAt.Equal(limit) {
			t.Fatalf("extension to the limit = %+v, %v", x, err)
		}
		if d := f.get(t, f.shared.ID); d.ExtensionCount != 2 || !d.ExtendedAt.Equal(later.Truncate(time.Millisecond)) ||
			!d.ExpiresAt.Equal(limit.Truncate(time.Millisecond)) {
			t.Errorf("after the second extension: %+v", d.Transfer)
		}
		_, err = extend(f.a.ID, f.shared.ID, senderAlice, limit.Add(time.Hour), later)
		wantErr(t, "past the limit", err, store.ErrExtensionLimit)
		if p, err := transfers.GetBySender(ctx, f.a.ID, f.shared.ID, senderAlice); err != nil || p.ExtensionCount != 2 {
			t.Errorf("GetBySender after extensions = %+v, %v", p.Transfer, err)
		}

		// Downloads over: due for deletion, or the maximum reached.
		del := availableTransfer(t, db, f.a.ID, true)
		err = inTxCtx(ctx, t, db, f.a.ID, func(tx *store.ScopedTx) error {
			_, err := transfers.MarkFirstDownloadTx(ctx, tx, del.ID, fixedNow, fixedNow.Add(time.Hour))
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = extend(f.a.ID, del.ID, senderAlice, day(30), now)
		wantErr(t, "due for deletion", err, store.ErrNotExtendable)
		one := 1
		capped, _, _ := availablePerRecipient(t, db, f.a.ID, func(tr *store.Transfer) { tr.MaxDownloads = &one })
		err = inTxCtx(ctx, t, db, f.a.ID, func(tx *store.ScopedTx) error {
			return transfers.IncrementDownloadsTx(ctx, tx, capped.ID)
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = extend(f.a.ID, capped.ID, senderAlice, day(30), now)
		wantErr(t, "maximum downloads reached", err, store.ErrNotExtendable)
	})
}

// TestTransfersExtendReminder checks the re-arm of the expiry reminder by
// an extension (D3), and its skip under ReminderMinLifetime (D16).
func TestTransfersExtendReminder(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers, links := db.Transfers(), db.RecipientLinks()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		d, ls, _ := availablePerRecipient(t, db, a.ID, nil)
		other, otherLinks, _ := availablePerRecipient(t, db, a.ID, nil)
		remind := func(trfID string, ls []store.RecipientLink, at time.Time) {
			t.Helper()
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				if err := links.MarkReminderSentTx(ctx, tx, []string{ls[0].ID, ls[1].ID}, at); err != nil {
					return err
				}
				return transfers.MarkExpiryReminderTx(ctx, tx, trfID, at)
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		check := func(what string, trfID string, wantReminder time.Time, wantLinksSent bool) {
			t.Helper()
			got, err := transfers.Get(ctx, a.ID, trfID)
			if err != nil {
				t.Fatal(err)
			}
			if !got.ExpiryReminderAt.Equal(wantReminder.Truncate(time.Millisecond)) {
				t.Errorf("%s: ExpiryReminderAt = %v, want %v", what, got.ExpiryReminderAt, wantReminder)
			}
			lks, err := links.ListByTransfer(ctx, a.ID, trfID)
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range lks {
				if l.ReminderSentAt.IsZero() == wantLinksSent {
					t.Errorf("%s: link %d ReminderSentAt = %v", what, l.Position, l.ReminderSentAt)
				}
			}
		}
		extend := func(expiresAt, now time.Time) store.TransferExtension {
			t.Helper()
			var x store.TransferExtension
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				var err error
				x, err = transfers.ExtendTx(ctx, tx, d.ID, senderAlice, expiresAt, now)
				return err
			})
			if err != nil {
				t.Fatalf("ExtendTx: %v", err)
			}
			return x
		}

		// Reminded the day before the expiry, then extended by 7 days: the
		// reminder is re-armed, on the transfer and on every link.
		sent := d.ExpiresAt.Add(-23 * time.Hour)
		remind(d.ID, ls, sent)
		remind(other.ID, otherLinks, sent)
		now := d.ExpiresAt.Add(-time.Hour)
		if x := extend(now.Add(7*24*time.Hour), now); x.ReminderSkipped {
			t.Errorf("7-day extension skipped the reminder: %+v", x)
		}
		check("re-armed", d.ID, time.Time{}, false)
		check("other transfer", other.ID, sent, true)

		// Reminded again, then extended by one day only: under 36 hours
		// left, the reminder pass is marked done at now (D16), the link
		// marks still cleared.
		now = now.Add(7*24*time.Hour - time.Hour)
		remind(d.ID, ls, now.Add(-time.Minute))
		x := extend(now.Add(24*time.Hour), now)
		if !x.ReminderSkipped || x.Count != 2 {
			t.Errorf("1-day extension = %+v", x)
		}
		check("skipped", d.ID, now, false)
		// Just at the limit, the reminder is re-armed.
		now = now.Add(time.Hour)
		if x := extend(now.Add(store.ReminderMinLifetime), now); x.ReminderSkipped {
			t.Errorf("extension of exactly 36 hours skipped the reminder: %+v", x)
		}
		check("36 hours", d.ID, time.Time{}, false)
	})
}

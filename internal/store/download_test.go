package store_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// availableTransfer creates an available transfer of tid (one complete,
// clean file) with the "delete after the first download" option set to
// deleteOpt.
func availableTransfer(t *testing.T, db *store.DB, tid tenant.ID, deleteOpt bool) store.TransferDetails {
	t.Helper()
	ctx := context.Background()
	fl := newFile(t, db, tid, "f.bin", 10)
	fl.SHA256, fl.CiphertextSize, fl.UploadedAt = sha1111, 50, fixedNow
	tr := newTransfer()
	tr.DeleteAfterFirstDownload = deleteOpt
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
	markAvailable(t, db, tid, d.ID)
	d, err = db.Transfers().Get(ctx, tid, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTransfersFirstDownload(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		mark := func(trfID string, now, deleteAfter time.Time) (bool, error) {
			var first bool
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				var err error
				first, err = transfers.MarkFirstDownloadTx(ctx, tx, trfID, now, deleteAfter)
				return err
			})
			return first, err
		}
		plain, del := availableTransfer(t, db, a.ID, false), availableTransfer(t, db, a.ID, true)
		if !plain.FirstDownloadedAt.IsZero() || !plain.DeleteAfter.IsZero() {
			t.Fatalf("new available transfer = %+v", plain.Transfer)
		}
		later := fixedNow.Add(time.Hour)
		grace := later.Add(15 * time.Minute)

		// Inconsistent deletion times are refused, nothing is recorded.
		_, err := mark(plain.ID, later, later.Add(-time.Millisecond))
		wantErr(t, "deleteAfter before now", err, store.ErrInvalid)
		_, err = mark(plain.ID, later, grace)
		wantErr(t, "deleteAfter without the option", err, store.ErrInvalid)
		_, err = mark(del.ID, later, time.Time{})
		wantErr(t, "option without deleteAfter", err, store.ErrInvalid)
		_, err = mark(id.New(id.Transfer), later, time.Time{})
		wantErr(t, "missing transfer", err, store.ErrNotFound)
		scanning := scanningTransfer(t, db, a.ID, fixedNow, 1)
		_, err = mark(scanning.ID, later, time.Time{})
		wantErr(t, "scanning transfer", err, store.ErrConflict)

		// The first call records it, the next ones report false.
		for i, want := range []bool{true, false} {
			if first, err := mark(plain.ID, later.Add(time.Duration(i)*time.Minute), time.Time{}); err != nil || first != want {
				t.Errorf("MarkFirstDownloadTx(plain) #%d = %v, %v; want %v", i, first, err, want)
			}
		}
		for i, want := range []bool{true, false} {
			if first, err := mark(del.ID, later.Add(time.Duration(i)*time.Minute), grace); err != nil || first != want {
				t.Errorf("MarkFirstDownloadTx(delete) #%d = %v, %v; want %v", i, first, err, want)
			}
		}
		// deleteAfter equal to now is accepted.
		exact := availableTransfer(t, db, a.ID, true)
		if first, err := mark(exact.ID, later, later); err != nil || !first {
			t.Errorf("MarkFirstDownloadTx(deleteAfter = now) = %v, %v", first, err)
		}
		// Once recorded, an inconsistent second call still reports false.
		if first, err := mark(plain.ID, later, grace); err != nil || first {
			t.Errorf("MarkFirstDownloadTx(plain, again with deleteAfter) = %v, %v", first, err)
		}

		msLater, msGrace := later.Truncate(time.Millisecond), grace.Truncate(time.Millisecond)
		got, err := transfers.Get(ctx, a.ID, plain.ID)
		if err != nil || !got.FirstDownloadedAt.Equal(msLater) || !got.DeleteAfter.IsZero() {
			t.Errorf("plain after first download = %+v, %v", got.Transfer, err)
		}
		got, err = transfers.Get(ctx, a.ID, del.ID)
		if err != nil || !got.FirstDownloadedAt.Equal(msLater) || !got.DeleteAfter.Equal(msGrace) {
			t.Errorf("delete after first download = %+v, %v", got.Transfer, err)
		}

		// A deleted transfer already downloaded still reports false.
		eraseKeys(t, db, a.ID, got)
		if err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error { return transfers.MarkDeletedTx(ctx, tx, del.ID) }); err != nil {
			t.Fatalf("MarkDeletedTx: %v", err)
		}
		if first, err := mark(del.ID, later, grace); err != nil || first {
			t.Errorf("MarkFirstDownloadTx(deleted) = %v, %v", first, err)
		}

		// A new transfer cannot carry download times.
		for _, tr := range []store.Transfer{{FirstDownloadedAt: fixedNow}, {DeleteAfter: fixedNow}} {
			base := newTransfer()
			base.FirstDownloadedAt, base.DeleteAfter = tr.FirstDownloadedAt, tr.DeleteAfter
			fl := newFile(t, db, a.ID, "x", 1)
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				return transfers.CreateTx(ctx, tx, base, []string{"bob@partner.example.org"}, []store.TransferFile{fl})
			})
			wantErr(t, "CreateTx with download times", err, store.ErrInvalid)
		}
	})
}

// eraseKeys destroys the data keys of the files and the sealed download
// token of d (cryptographic erasure).
func eraseKeys(t *testing.T, db *store.DB, tid tenant.ID, d store.TransferDetails) {
	t.Helper()
	ctx := context.Background()
	err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
		for _, f := range d.Files {
			if err := db.WrappedKeys().DeleteTx(ctx, tx, f.DEKKeyID); err != nil {
				return err
			}
		}
		return db.WrappedKeys().DeleteTx(ctx, tx, d.DownloadTokenKeyID)
	})
	if err != nil {
		t.Fatalf("erase keys: %v", err)
	}
}

func TestTransfersDeletionAfterDownload(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		markDeleted := func(tid tenant.ID, trfID string) error {
			return inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error { return transfers.MarkDeletedTx(ctx, tx, trfID) })
		}
		download := func(tid tenant.ID, trfID string, at, deleteAfter time.Time) {
			t.Helper()
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				_, err := transfers.MarkFirstDownloadTx(ctx, tx, trfID, at, deleteAfter)
				return err
			})
			if err != nil {
				t.Fatalf("MarkFirstDownloadTx: %v", err)
			}
		}
		base := fixedNow.Add(time.Hour)
		late := availableTransfer(t, db, a.ID, true)
		early := availableTransfer(t, db, b.ID, true)
		same := availableTransfer(t, db, a.ID, true)
		plain := availableTransfer(t, db, a.ID, false)
		availableTransfer(t, db, a.ID, true) // never downloaded: never due
		download(a.ID, late.ID, base, base.Add(20*time.Minute))
		download(b.ID, early.ID, base, base.Add(10*time.Minute))
		download(a.ID, same.ID, base, base.Add(20*time.Minute))
		download(a.ID, plain.ID, base, time.Time{})

		due := func(now time.Time) []store.TenantTransfer {
			t.Helper()
			got, err := transfers.DueDeletions(ctx, now)
			if err != nil {
				t.Fatalf("DueDeletions: %v", err)
			}
			return got
		}
		if got := due(base.Add(10*time.Minute - time.Millisecond)); len(got) != 0 {
			t.Errorf("DueDeletions before any due time = %+v", got)
		}
		if got := due(base.Add(10 * time.Minute)); len(got) != 1 || got[0] != (store.TenantTransfer{TenantID: b.ID, TransferID: early.ID}) {
			t.Errorf("DueDeletions at the first due time = %+v", got)
		}
		got := due(base.Add(time.Hour))
		first, second := late.ID, same.ID
		if second < first {
			first, second = second, first
		}
		want := []store.TenantTransfer{{TenantID: b.ID, TransferID: early.ID}, {TenantID: a.ID, TransferID: first}, {TenantID: a.ID, TransferID: second}}
		if len(got) != len(want) {
			t.Fatalf("DueDeletions = %+v, want %+v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("DueDeletions[%d] = %+v, want %+v", i, got[i], want[i])
			}
		}

		// Deletion refuses while keys remain: file keys first, then the
		// token key.
		wantErr(t, "MarkDeletedTx with file keys", markDeleted(a.ID, late.ID), store.ErrKeysRemain)
		if err := db.WrappedKeys().Delete(ctx, a.ID, late.Files[0].DEKKeyID); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "MarkDeletedTx with the token key", markDeleted(a.ID, late.ID), store.ErrKeysRemain)
		if err := db.WrappedKeys().Delete(ctx, a.ID, late.DownloadTokenKeyID); err != nil {
			t.Fatal(err)
		}
		if err := markDeleted(a.ID, late.ID); err != nil {
			t.Fatalf("MarkDeletedTx: %v", err)
		}
		wantErr(t, "MarkDeletedTx twice", markDeleted(a.ID, late.ID), store.ErrConflict)
		wantErr(t, "MarkDeletedTx(missing)", markDeleted(a.ID, id.New(id.Transfer)), store.ErrNotFound)
		scanning := scanningTransfer(t, db, a.ID, fixedNow, 1)
		if err := db.WrappedKeys().Delete(ctx, a.ID, scanning.Files[0].DEKKeyID); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "MarkDeletedTx(scanning)", markDeleted(a.ID, scanning.ID), store.ErrConflict)

		d, err := transfers.Get(ctx, a.ID, late.ID)
		if err != nil || d.Status != store.TransferDeleted || d.DownloadTokenKeyID != "" || d.DownloadTokenHash == nil || d.Files[0].DEKKeyID != "" {
			t.Errorf("deleted transfer = %+v, %v", d, err)
		}
		// A deleted transfer leaves the sweep; the others stay until done.
		got = due(base.Add(time.Hour))
		if len(got) != 2 || got[0].TransferID != early.ID || got[1].TransferID != same.ID {
			t.Errorf("DueDeletions after a deletion = %+v", got)
		}
	})
}

func TestPasswordFailureKeys(t *testing.T) {
	t.Parallel()
	trf := id.New(id.Transfer)
	if k := store.TransferFailureKey(trf); k.Scope != store.FailureScopeTransfer || k.Key != trf {
		t.Errorf("TransferFailureKey = %+v", k)
	}
	for in, want := range map[string]string{
		"192.0.2.1":                       "192.0.2.1",
		"::ffff:192.0.2.1":                "192.0.2.1",
		"2001:db8:1:2:3:4:5:6":            "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff:ffff:fff": "2001:db8:1:2::/64",
		"fe80::1%eth0":                    "fe80::/64",
	} {
		if k := store.IPFailureKey(netip.MustParseAddr(in)); k.Scope != store.FailureScopeIP || k.Key != want {
			t.Errorf("IPFailureKey(%s) = %+v, want %s", in, k, want)
		}
	}
	if k := store.IPFailureKey(netip.Addr{}); k.Key != "" {
		t.Errorf("IPFailureKey(zero) = %+v", k)
	}
}

func TestPasswordFailures(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		pf := db.PasswordFailures()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		trfKey := store.TransferFailureKey(id.New(id.Transfer))
		ipKey := store.IPFailureKey(netip.MustParseAddr("2001:db8::7"))
		otherIP := store.IPFailureKey(netip.MustParseAddr("192.0.2.9"))
		both := []store.FailureKey{trfKey, ipKey}
		check := func(keys []store.FailureKey, now time.Time) (time.Time, error) {
			var until time.Time
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				var err error
				until, err = pf.CheckTx(ctx, tx, keys, now)
				return err
			})
			return until, err
		}
		record := func(keys []store.FailureKey, now time.Time) (store.FailureOutcome, error) {
			var out store.FailureOutcome
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				var err error
				out, err = pf.RecordFailureTx(ctx, tx, keys, now)
				return err
			})
			return out, err
		}
		reset := func(keys []store.FailureKey) error {
			return inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error { return pf.ResetTx(ctx, tx, keys) })
		}
		refund := func(keys []store.FailureKey, at time.Time) error {
			return inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error { return pf.RefundTx(ctx, tx, keys, at) })
		}
		wantOutcome := func(what string, got store.FailureOutcome, err error, remaining int, locked time.Time) {
			t.Helper()
			if err != nil || got.Remaining != remaining || !got.LockedUntil.Equal(locked) {
				t.Errorf("%s = %+v, %v; want remaining %d, locked until %v", what, got, err, remaining, locked)
			}
		}
		now := fixedNow.Truncate(time.Millisecond)
		lockEnd := now.Add(2*time.Minute + store.PasswordLockDuration)

		// Malformed key lists are refused by every method.
		for _, keys := range [][]store.FailureKey{
			nil,
			{trfKey, ipKey, otherIP, store.TransferFailureKey(id.New(id.Transfer)), store.TransferFailureKey(id.New(id.Transfer))},
			{trfKey, trfKey},
			{{Scope: "user", Key: "x"}},
			{store.TransferFailureKey("trf_bogus")},
			{store.IPFailureKey(netip.Addr{})},
			{{Scope: store.FailureScopeIP, Key: "::ffff:192.0.2.1"}},
			{{Scope: store.FailureScopeIP, Key: "192.0.2.0/24"}},
			{{Scope: store.FailureScopeIP, Key: "2001:db8::1"}},
			{{Scope: store.FailureScopeIP, Key: "2001:db8::/48"}},
			{{Scope: store.FailureScopeIP, Key: "2001:db8::1/64"}},
			{{Scope: store.FailureScopeIP, Key: "2001:0db8::/64"}},
		} {
			_, err := check(keys, now)
			wantErr(t, "CheckTx(bad keys)", err, store.ErrInvalid)
			_, err = record(keys, now)
			wantErr(t, "RecordFailureTx(bad keys)", err, store.ErrInvalid)
			wantErr(t, "ResetTx(bad keys)", reset(keys), store.ErrInvalid)
			wantErr(t, "RefundTx(bad keys)", refund(keys, now), store.ErrInvalid)
		}

		// Nothing locked at first; a reset without rows is a no-op.
		if until, err := check(both, now); err != nil || !until.IsZero() {
			t.Fatalf("CheckTx(new) = %v, %v", until, err)
		}
		if err := reset(both); err != nil {
			t.Fatal(err)
		}

		// Three failures lock both keys.
		out, err := record(both, now)
		wantOutcome("failure 1", out, err, 2, time.Time{})
		out, err = record(both, now.Add(time.Minute))
		wantOutcome("failure 2", out, err, 1, time.Time{})
		// The other IP has its own counter, on the same transfer.
		out, err = record([]store.FailureKey{trfKey, otherIP}, now.Add(time.Minute))
		wantOutcome("failure on the transfer from another IP", out, err, 0, now.Add(time.Minute+store.PasswordLockDuration))
		out, err = record(both, now.Add(2*time.Minute))
		// The transfer key is already locked (unchanged), the IP key locks
		// now: the latest end of lock wins.
		wantOutcome("failure 3", out, err, 0, lockEnd)
		if until, err := check(both, now.Add(3*time.Minute)); err != nil || !until.Equal(lockEnd) {
			t.Errorf("CheckTx(locked) = %v, %v; want %v", until, err, lockEnd)
		}
		if until, err := check([]store.FailureKey{otherIP}, now.Add(3*time.Minute)); err != nil || !until.IsZero() {
			t.Errorf("CheckTx(other ip) = %v, %v", until, err)
		}
		// While locked, a failure changes nothing.
		out, err = record(both, now.Add(4*time.Minute))
		wantOutcome("failure while locked", out, err, 0, lockEnd)
		if until, err := check(both, lockEnd.Add(-time.Millisecond)); err != nil || !until.Equal(lockEnd) {
			t.Errorf("CheckTx(just before the end) = %v, %v", until, err)
		}
		// The lock expires by time; by then every failure has left the
		// window, so the next one counts alone.
		if until, err := check(both, lockEnd); err != nil || !until.IsZero() {
			t.Errorf("CheckTx(at the end) = %v, %v", until, err)
		}
		out, err = record(both, lockEnd)
		wantOutcome("failure after the lock", out, err, 2, time.Time{})

		// The window slides: a failure leaves it PasswordFailureWindow after
		// it happened, whatever the others.
		out, err = record(both, lockEnd.Add(10*time.Minute))
		wantOutcome("failure 10 minutes later", out, err, 1, time.Time{})
		out, err = record(both, lockEnd.Add(store.PasswordFailureWindow+5*time.Minute))
		wantOutcome("failure once the first left the window", out, err, 1, time.Time{})
		slide := lockEnd.Add(store.PasswordFailureWindow + 9*time.Minute)
		out, err = record(both, slide)
		wantOutcome("third failure within 14 minutes", out, err, 0, slide.Add(store.PasswordLockDuration))

		// A right password resets the counters it is given.
		if err := reset(both); err != nil {
			t.Fatal(err)
		}
		out, err = record(both, slide.Add(time.Second))
		wantOutcome("failure after a reset", out, err, 2, time.Time{})

		// A refund withdraws one failure, and the lock only when that
		// failure set it.
		ip := []store.FailureKey{store.IPFailureKey(netip.MustParseAddr("192.0.2.50"))}
		t1 := slide.Add(time.Hour)
		t2, t3, t4 := t1.Add(time.Minute), t1.Add(2*time.Minute), t1.Add(3*time.Minute)
		if err := refund(ip, t1); err != nil {
			t.Fatalf("refund without row: %v", err)
		}
		for _, at := range []time.Time{t1, t2, t3} {
			out, err = record(ip, at)
		}
		wantOutcome("third failure", out, err, 0, t3.Add(store.PasswordLockDuration))
		if err := refund(ip, t3); err != nil {
			t.Fatal(err)
		}
		if until, err := check(ip, t3); err != nil || !until.IsZero() {
			t.Errorf("CheckTx after the refund of the locking failure = %v, %v", until, err)
		}
		out, err = record(ip, t4)
		wantOutcome("failure after a refund", out, err, 0, t4.Add(store.PasswordLockDuration))
		// Refunding another failure keeps the lock; an unknown time changes
		// nothing.
		if err := refund(ip, t1); err != nil {
			t.Fatal(err)
		}
		if err := refund(ip, t1.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if until, err := check(ip, t4); err != nil || !until.Equal(t4.Add(store.PasswordLockDuration)) {
			t.Errorf("CheckTx after the refund of another failure = %v, %v", until, err)
		}
		// Refunding t2, then t4, the failure that set the lock, clears it:
		// the row is kept, empty, and counts nothing.
		if err := refund(ip, t2); err != nil {
			t.Fatal(err)
		}
		if err := refund(ip, t4); err != nil {
			t.Fatal(err)
		}
		if until, err := check(ip, t4); err != nil || !until.IsZero() {
			t.Errorf("CheckTx after refunding every failure = %v, %v", until, err)
		}
		out, err = record(ip, t4.Add(time.Second))
		wantOutcome("failure on an emptied row", out, err, 2, time.Time{})
	})
}

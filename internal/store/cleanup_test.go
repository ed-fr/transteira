package store_test

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// getTransfer returns the transfer trfID of tid without its recipients and
// files.
func getTransfer(t *testing.T, db *store.DB, tid tenant.ID, trfID string) store.Transfer {
	t.Helper()
	d, err := db.Transfers().Get(context.Background(), tid, trfID)
	if err != nil {
		t.Fatalf("Get(%s): %v", trfID, err)
	}
	return d.Transfer
}

// endTransfer creates an uploading transfer of tid, destroys its file key
// and deletes it at at with SetStatusTx, and returns its ID.
func endTransfer(t *testing.T, db *store.DB, tid tenant.ID, at time.Time) string {
	t.Helper()
	d := mustTransfer(t, db, tid, newTransfer())
	deleteFileKeys(t, db, tid, d)
	err := inTx(t, db, tid, func(tx *store.ScopedTx) error {
		return db.Transfers().SetStatusTx(context.Background(), tx, d.ID, store.TransferUploading, store.TransferDeleted, at)
	})
	if err != nil {
		t.Fatalf("SetStatusTx: %v", err)
	}
	return d.ID
}

// rejectTransfer creates a scanning transfer of tid and rejects it.
func rejectTransfer(t *testing.T, db *store.DB, tid tenant.ID) store.TransferDetails {
	t.Helper()
	ctx := context.Background()
	d := scanningTransfer(t, db, tid, fixedNow, 1)
	if err := inTx(t, db, tid, func(tx *store.ScopedTx) error { return db.Transfers().MarkRejectedTx(ctx, tx, d.ID) }); err != nil {
		t.Fatalf("MarkRejectedTx: %v", err)
	}
	d, err := db.Transfers().Get(ctx, tid, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// withoutKeys returns the identifiers of a sweep page, without their sort
// keys.
func withoutKeys(page []store.TenantTransfer) []store.TenantTransfer {
	out := make([]store.TenantTransfer, len(page))
	for i, tt := range page {
		out[i] = store.TenantTransfer{TenantID: tt.TenantID, TransferID: tt.TransferID}
	}
	return out
}

// deleteFileKeys destroys the data key of every file of d.
func deleteFileKeys(t *testing.T, db *store.DB, tid tenant.ID, d store.TransferDetails) {
	t.Helper()
	for _, f := range d.Files {
		if err := db.WrappedKeys().Delete(context.Background(), tid, f.DEKKeyID); err != nil {
			t.Fatalf("delete file key: %v", err)
		}
	}
}

func TestTransfersEndedAt(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		in := func(fn func(*store.ScopedTx) error) error { return inTxCtx(ctx, t, db, a.ID, fn) }

		up := mustTransfer(t, db, a.ID, newTransfer())
		av := availableTransfer(t, db, a.ID, false)
		sc := scanningTransfer(t, db, a.ID, fixedNow, 1)
		for _, d := range []store.TransferDetails{up, av, sc} {
			if !d.EndedAt.IsZero() {
				t.Errorf("%s transfer has an end: %v", d.Status, d.EndedAt)
			}
		}

		// MarkDeletedTx and MarkRejectedTx use the store's clock.
		eraseKeys(t, db, a.ID, av)
		if err := in(func(tx *store.ScopedTx) error { return transfers.MarkDeletedTx(ctx, tx, av.ID) }); err != nil {
			t.Fatalf("MarkDeletedTx: %v", err)
		}
		if got := getTransfer(t, db, a.ID, av.ID); got.Status != store.TransferDeleted || !got.EndedAt.Equal(msNow) {
			t.Errorf("deleted transfer = %s ended %v, want %v", got.Status, got.EndedAt, msNow)
		}
		if err := in(func(tx *store.ScopedTx) error { return transfers.MarkRejectedTx(ctx, tx, sc.ID) }); err != nil {
			t.Fatalf("MarkRejectedTx: %v", err)
		}
		if got := getTransfer(t, db, a.ID, sc.ID); got.Status != store.TransferRejected || !got.EndedAt.Equal(msNow) {
			t.Errorf("rejected transfer = %s ended %v, want %v", got.Status, got.EndedAt, msNow)
		}

		// SetStatusTx records now on the first terminal transition only.
		at := fixedNow.Add(time.Hour)
		setStatus := func(trfID string, from, to store.TransferStatus, now time.Time) {
			t.Helper()
			if err := in(func(tx *store.ScopedTx) error { return transfers.SetStatusTx(ctx, tx, trfID, from, to, now) }); err != nil {
				t.Fatalf("SetStatusTx(%s -> %s): %v", from, to, err)
			}
		}
		deleteFileKeys(t, db, a.ID, up)
		setStatus(up.ID, store.TransferUploading, store.TransferDeleted, at)
		if got := getTransfer(t, db, a.ID, up.ID); !got.EndedAt.Equal(at.Truncate(time.Millisecond)) {
			t.Errorf("SetStatusTx end = %v, want %v", got.EndedAt, at)
		}
		setStatus(up.ID, store.TransferDeleted, store.TransferExpired, at.Add(time.Hour))
		if got := getTransfer(t, db, a.ID, up.ID); got.Status != store.TransferExpired || !got.EndedAt.Equal(at.Truncate(time.Millisecond)) {
			t.Errorf("second terminal transition = %s ended %v, want the first end %v", got.Status, got.EndedAt, at)
		}
		up2 := mustTransfer(t, db, a.ID, newTransfer())
		deleteFileKeys(t, db, a.ID, up2)
		setStatus(up2.ID, store.TransferUploading, store.TransferExpired, time.Time{})
		if got := getTransfer(t, db, a.ID, up2.ID); !got.EndedAt.Equal(msNow) {
			t.Errorf("SetStatusTx(zero now) end = %v, want the store's clock", got.EndedAt)
		}

		// A new transfer cannot carry an end.
		tr := newTransfer()
		tr.EndedAt = fixedNow
		fl := newFile(t, db, a.ID, "x", 1)
		err := in(func(tx *store.ScopedTx) error {
			return transfers.CreateTx(ctx, tx, tr, []string{"bob@partner.example.org"}, []store.TransferFile{fl})
		})
		wantErr(t, "CreateTx with an end", err, store.ErrInvalid)
	})
}

func TestTransfersMarkExpired(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		later := fixedNow.Add(2 * time.Hour)
		expire := func(trfID string) error {
			return inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error { return transfers.MarkExpiredTx(ctx, tx, trfID, later) })
		}
		check := func(what, trfID string) store.Transfer {
			t.Helper()
			got := getTransfer(t, db, a.ID, trfID)
			if got.Status != store.TransferExpired || !got.EndedAt.Equal(later.Truncate(time.Millisecond)) {
				t.Errorf("%s: expired transfer = %s ended %v", what, got.Status, got.EndedAt)
			}
			return got
		}

		// Uploading: refused while its file key remains.
		up := mustTransfer(t, db, a.ID, newTransfer())
		sc := scanningTransfer(t, db, a.ID, fixedNow, 1)
		av := availableTransfer(t, db, a.ID, false)
		if n := usedBytes(t, db, a.ID); n != 30 {
			t.Fatalf("used bytes = %d, want 30", n)
		}
		wantErr(t, "MarkExpiredTx(uploading with key)", expire(up.ID), store.ErrKeysRemain)
		deleteFileKeys(t, db, a.ID, up)
		if err := expire(up.ID); err != nil {
			t.Fatalf("MarkExpiredTx(uploading): %v", err)
		}
		check("uploading", up.ID)
		wantErr(t, "MarkExpiredTx twice", expire(up.ID), store.ErrConflict)
		wantErr(t, "MarkExpiredTx(missing)", expire(id.New(id.Transfer)), store.ErrNotFound)

		// Scanning.
		wantErr(t, "MarkExpiredTx(scanning with key)", expire(sc.ID), store.ErrKeysRemain)
		deleteFileKeys(t, db, a.ID, sc)
		if err := expire(sc.ID); err != nil {
			t.Fatalf("MarkExpiredTx(scanning): %v", err)
		}
		check("scanning", sc.ID)

		// Available: the token key must go too; the token hash stays.
		deleteFileKeys(t, db, a.ID, av)
		wantErr(t, "MarkExpiredTx(available with token key)", expire(av.ID), store.ErrKeysRemain)
		if err := db.WrappedKeys().Delete(ctx, a.ID, av.DownloadTokenKeyID); err != nil {
			t.Fatal(err)
		}
		if err := expire(av.ID); err != nil {
			t.Fatalf("MarkExpiredTx(available): %v", err)
		}
		if got := check("available", av.ID); got.DownloadTokenHash == nil || got.DownloadTokenKeyID != "" {
			t.Errorf("expired available transfer = %+v", got)
		}
		if n := usedBytes(t, db, a.ID); n != 0 {
			t.Errorf("used bytes after expiry = %d, want 0 (quota released)", n)
		}

		// Rejected (or any terminal status): conflict.
		rj := rejectTransfer(t, db, a.ID)
		deleteFileKeys(t, db, a.ID, rj)
		wantErr(t, "MarkExpiredTx(rejected)", expire(rj.ID), store.ErrConflict)
		if got := getTransfer(t, db, a.ID, rj.ID); got.Status != store.TransferRejected {
			t.Errorf("rejected transfer became %s", got.Status)
		}
	})
}

func TestTransfersDueExpirations(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		page := store.SweepPage{Limit: store.ExpirySweepLimit}
		wantDue := func(what string, now time.Time, want ...store.TenantTransfer) {
			t.Helper()
			got, err := transfers.DueExpirations(ctx, now, store.ScanningMaxAge, page)
			if err != nil {
				t.Fatalf("%s: DueExpirations: %v", what, err)
			}
			if !reflect.DeepEqual(got, append([]store.TenantTransfer{}, want...)) {
				t.Errorf("%s: DueExpirations = %+v, want %+v", what, got, want)
			}
		}
		fin := fixedNow.Add(time.Hour).Truncate(time.Millisecond)
		avA := availableTransfer(t, db, a.ID, false) // expires fixedNow + 7 days
		scB := scanningTransfer(t, db, b.ID, fin, 1) // provisional expiry fin + 7 days, never enforced
		mustTransfer(t, db, a.ID, newTransfer())     // uploading: never due here
		endTransfer(t, db, a.ID, fixedNow)           // deleted: not due
		rejectTransfer(t, db, b.ID)                  // rejected with a key: RejectedKeyed only
		exp := fixedNow.Add(7 * 24 * time.Hour).Truncate(time.Millisecond)
		stuck := fin.Add(store.ScanningMaxAge)
		ta := store.TenantTransfer{TenantID: a.ID, TransferID: avA.ID, SortKey: exp}
		tb := store.TenantTransfer{TenantID: b.ID, TransferID: scB.ID, SortKey: stuck}
		if got := getTransfer(t, db, b.ID, scB.ID).ExpiresAt; !got.Before(exp.Add(time.Hour + time.Millisecond)) {
			t.Fatalf("provisional expiry of the scanning transfer = %v", got)
		}

		wantDue("before any expiry", exp.Add(-time.Millisecond))
		wantDue("at the first expiry", exp, ta)
		// The scanning transfer is past its provisional expiry, but still
		// under ScanningMaxAge: untouched.
		wantDue("past the provisional expiry", exp.Add(2*time.Hour), ta)
		wantDue("just before the scanning maximum age", stuck.Add(-time.Millisecond), ta)
		wantDue("at the scanning maximum age", stuck, ta, tb)
		// A shorter maximum age (the tests of the sweeper) moves the due time.
		got, err := transfers.DueExpirations(ctx, fin.Add(time.Hour), time.Hour, page)
		if want := []store.TenantTransfer{{TenantID: b.ID, TransferID: scB.ID, SortKey: fin.Add(time.Hour)}}; err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("DueExpirations(1 h) = %+v, %v; want %+v", got, err, want)
		}

		// An expired transfer leaves the sweep.
		eraseKeys(t, db, a.ID, avA)
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return transfers.MarkExpiredTx(ctx, tx, avA.ID, exp) }); err != nil {
			t.Fatalf("MarkExpiredTx: %v", err)
		}
		wantDue("after an expiry", stuck, tb)

		for _, age := range []time.Duration{0, -time.Hour} {
			_, err := transfers.DueExpirations(ctx, stuck, age, page)
			wantErr(t, "DueExpirations(bad maximum age)", err, store.ErrInvalid)
		}
	})
}

func TestTransfersRejectedKeyed(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		list := func() []store.TenantTransfer {
			t.Helper()
			got, err := db.Transfers().RejectedKeyed(ctx, store.SweepPage{Limit: store.ExpirySweepLimit})
			if err != nil {
				t.Fatalf("RejectedKeyed: %v", err)
			}
			return got
		}
		availableTransfer(t, db, a.ID, false) // keyed, not rejected
		rj := rejectTransfer(t, db, b.ID)
		want := []store.TenantTransfer{{TenantID: b.ID, TransferID: rj.ID, SortKey: msNow}}
		if got := list(); !reflect.DeepEqual(got, want) {
			t.Errorf("RejectedKeyed = %+v, want %+v", got, want)
		}
		deleteFileKeys(t, db, b.ID, rj)
		if got := list(); len(got) != 0 {
			t.Errorf("RejectedKeyed without key = %+v", got)
		}
	})
}

func TestTransfersAbandonedUploads(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		mk := func(tid tenant.ID, created time.Time) store.TenantTransfer {
			tr := newTransfer()
			tr.CreatedAt = created
			return store.TenantTransfer{TenantID: tid, TransferID: mustTransfer(t, db, tid, tr).ID}
		}
		t1, t2, t3 := mk(a.ID, fixedNow.Add(-3*time.Hour)), mk(b.ID, fixedNow.Add(-2*time.Hour)), mk(a.ID, fixedNow)
		scanningTransfer(t, db, a.ID, fixedNow, 1) // finalized: never abandoned
		for _, c := range []struct {
			before time.Time
			want   []store.TenantTransfer
		}{
			{fixedNow.Add(-3*time.Hour - time.Millisecond), []store.TenantTransfer{}},
			{fixedNow.Add(-2*time.Hour - time.Millisecond), []store.TenantTransfer{t1}},
			{fixedNow.Add(-2 * time.Hour), []store.TenantTransfer{t1, t2}},
			{fixedNow.Add(time.Hour), []store.TenantTransfer{t1, t2, t3}},
		} {
			got, err := db.Transfers().AbandonedUploads(ctx, c.before, store.SweepPage{Limit: store.AbandonedSweepLimit})
			if err != nil || !reflect.DeepEqual(withoutKeys(got), c.want) {
				t.Errorf("AbandonedUploads(%v) = %+v, %v; want %+v", c.before, got, err, c.want)
			}
		}
		got, err := db.Transfers().AbandonedUploads(ctx, fixedNow, store.SweepPage{Limit: 1})
		if err != nil || len(got) != 1 || !got[0].SortKey.Equal(fixedNow.Add(-3*time.Hour).Truncate(time.Millisecond)) {
			t.Errorf("AbandonedUploads sort key = %+v, %v", got, err)
		}
	})
}

// TestSweepPages walks every keyset-paginated sweep one entry per page and
// checks that it reaches every entry once, in order, whatever the tenant,
// even when the entries share their sort key.
func TestSweepPages(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		later := fixedNow.Add(365 * 24 * time.Hour)
		for _, tid := range []tenant.ID{a.ID, b.ID, a.ID, b.ID} {
			// Same sort keys in both tenants: the tie is broken by tenant,
			// then transfer.
			for _, deleteOpt := range []bool{false, true} {
				d := availableTransfer(t, db, tid, deleteOpt)
				if deleteOpt {
					if err := inTx(t, db, tid, func(tx *store.ScopedTx) error {
						_, err := transfers.MarkFirstDownloadTx(ctx, tx, d.ID, fixedNow, fixedNow)
						return err
					}); err != nil {
						t.Fatal(err)
					}
				}
			}
			scanningTransfer(t, db, tid, fixedNow, 1)
			rejectTransfer(t, db, tid)
			tr := newTransfer()
			tr.CreatedAt = fixedNow
			mustTransfer(t, db, tid, tr)
		}
		sweeps := map[string]struct {
			limit int
			list  func(store.SweepPage) ([]store.TenantTransfer, error)
		}{
			"deletions": {store.DeletionSweepLimit, func(p store.SweepPage) ([]store.TenantTransfer, error) {
				return transfers.DueDeletions(ctx, later, p)
			}},
			"expirations": {store.ExpirySweepLimit, func(p store.SweepPage) ([]store.TenantTransfer, error) {
				return transfers.DueExpirations(ctx, later, store.ScanningMaxAge, p)
			}},
			"rejected": {store.ExpirySweepLimit, func(p store.SweepPage) ([]store.TenantTransfer, error) {
				return transfers.RejectedKeyed(ctx, p)
			}},
			"abandoned": {store.AbandonedSweepLimit, func(p store.SweepPage) ([]store.TenantTransfer, error) {
				return transfers.AbandonedUploads(ctx, later, p)
			}},
		}
		for name, sw := range sweeps {
			all, err := sw.list(store.SweepPage{Limit: sw.limit})
			if err != nil || len(all) < 4 {
				t.Fatalf("%s: full listing = %+v, %v", name, all, err)
			}
			var walked []store.TenantTransfer
			var after store.TenantTransfer
			for {
				page, err := sw.list(store.SweepPage{After: after, Limit: 1})
				if err != nil {
					t.Fatalf("%s: page: %v", name, err)
				}
				if len(page) == 0 {
					break
				}
				walked = append(walked, page...)
				after = page[0]
			}
			if !reflect.DeepEqual(walked, all) {
				t.Errorf("%s: walked %+v, want %+v", name, walked, all)
			}
			for _, limit := range []int{0, -1, sw.limit + 1} {
				_, err := sw.list(store.SweepPage{Limit: limit})
				wantErr(t, name+" with a bad limit", err, store.ErrInvalid)
			}
		}
	})
}

func TestTransfersListEnded(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		e1, e2 := endTransfer(t, db, a.ID, fixedNow), endTransfer(t, db, a.ID, fixedNow.Add(time.Hour))
		e3 := endTransfer(t, db, b.ID, fixedNow)
		mustTransfer(t, db, a.ID, newTransfer()) // open: never listed
		list := func(tid tenant.ID, before time.Time, limit int) []string {
			t.Helper()
			got, err := transfers.ListEnded(ctx, tid, before, limit)
			if err != nil {
				t.Fatalf("ListEnded: %v", err)
			}
			return got
		}
		for _, c := range []struct {
			tid    tenant.ID
			before time.Time
			limit  int
			want   []string
		}{
			{a.ID, fixedNow.Add(-time.Millisecond), 10, []string{}},
			{a.ID, fixedNow, 10, []string{e1}},
			{a.ID, fixedNow.Add(time.Hour), store.PurgeBatchSize, []string{e1, e2}},
			{a.ID, fixedNow.Add(time.Hour), 1, []string{e1}},
			{b.ID, fixedNow.Add(time.Hour), 10, []string{e3}},
		} {
			if got := list(c.tid, c.before, c.limit); !reflect.DeepEqual(got, c.want) {
				t.Errorf("ListEnded(%v, %d) = %v, want %v", c.before, c.limit, got, c.want)
			}
		}
		for _, limit := range []int{0, store.PurgeBatchSize + 1} {
			_, err := transfers.ListEnded(ctx, a.ID, fixedNow, limit)
			wantErr(t, "ListEnded(bad limit)", err, store.ErrInvalid)
		}
		for _, tid := range badTenants {
			_, err := transfers.ListEnded(ctx, tid, fixedNow, 1)
			wantErr(t, "ListEnded(bad tenant)", err, store.ErrInvalid)
		}

		// The cleanup task deletes a listed transfer (its keys are gone).
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return transfers.DeleteTx(ctx, tx, e1) }); err != nil {
			t.Fatalf("DeleteTx: %v", err)
		}
		if got := list(a.ID, fixedNow.Add(time.Hour), 10); !reflect.DeepEqual(got, []string{e2}) {
			t.Errorf("ListEnded after a deletion = %v", got)
		}
	})
}

func TestTransfersIDsByStatus(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		up := mustTransfer(t, db, a.ID, newTransfer())
		sc := scanningTransfer(t, db, a.ID, fixedNow, 1)
		avB := availableTransfer(t, db, b.ID, false)
		for _, c := range []struct {
			tid      tenant.ID
			statuses []store.TransferStatus
			want     []string
		}{
			{a.ID, []store.TransferStatus{store.TransferUploading}, []string{up.ID}},
			{a.ID, []store.TransferStatus{store.TransferScanning, store.TransferUploading}, []string{sc.ID, up.ID}},
			{a.ID, []store.TransferStatus{store.TransferAvailable}, []string{}},
			{b.ID, []store.TransferStatus{store.TransferAvailable, store.TransferUploading}, []string{avB.ID}},
		} {
			got, err := transfers.IDsByStatus(ctx, c.tid, c.statuses...)
			if err != nil || !reflect.DeepEqual(got, c.want) {
				t.Errorf("IDsByStatus(%v) = %v, %v; want %v", c.statuses, got, err, c.want)
			}
		}
		for _, bad := range [][]store.TransferStatus{
			nil,
			{store.TransferUploading, store.TransferUploading},
			{"bogus"},
		} {
			_, err := transfers.IDsByStatus(ctx, a.ID, bad...)
			wantErr(t, "IDsByStatus(bad statuses)", err, store.ErrInvalid)
		}
		for _, tid := range badTenants {
			_, err := transfers.IDsByStatus(ctx, tid, store.TransferUploading)
			wantErr(t, "IDsByStatus(bad tenant)", err, store.ErrInvalid)
		}
	})
}

func TestTransferFilesStorageRefs(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		c := newTenant(t, db, "transfer.entity-c.example.com")
		av := availableTransfer(t, db, a.ID, false)
		up := mustTransfer(t, db, a.ID, newTransfer())
		rj := rejectTransfer(t, db, a.ID)
		deleteFileKeys(t, db, a.ID, rj)
		availableTransfer(t, db, b.ID, false)

		got, err := db.TransferFiles().StorageRefs(ctx, a.ID)
		want := map[string]store.StorageRef{
			av.Files[0].StorageName: {FileID: av.Files[0].ID, TransferID: av.ID, TransferStatus: store.TransferAvailable, Keyed: true, Completed: true},
			up.Files[0].StorageName: {FileID: up.Files[0].ID, TransferID: up.ID, TransferStatus: store.TransferUploading, Keyed: true},
			rj.Files[0].StorageName: {FileID: rj.Files[0].ID, TransferID: rj.ID, TransferStatus: store.TransferRejected, Completed: true},
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("StorageRefs(A) = %+v, %v; want %+v", got, err, want)
		}
		if got, err := db.TransferFiles().StorageRefs(ctx, c.ID); err != nil || len(got) != 0 {
			t.Errorf("StorageRefs(empty tenant) = %+v, %v", got, err)
		}
		for _, tid := range badTenants {
			_, err := db.TransferFiles().StorageRefs(ctx, tid)
			wantErr(t, "StorageRefs(bad tenant)", err, store.ErrInvalid)
		}
	})
}

func TestChallengesPurge(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Challenges()
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		now := fixedNow.Add(24 * time.Hour)
		mk := func(tid tenant.ID, created, expires, consumed time.Time) string {
			t.Helper()
			c := newChallenge(t, "alice@entity-a.example.com", ipA)
			c.CreatedAt, c.ExpiresAt = created, expires
			if err := repo.Create(ctx, tid, c); err != nil {
				t.Fatalf("Create challenge: %v", err)
			}
			if !consumed.IsZero() {
				if err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error { return repo.ConsumeTx(ctx, tx, c.ID, consumed) }); err != nil {
					t.Fatalf("ConsumeTx: %v", err)
				}
			}
			return c.ID
		}
		old, young, edge := now.Add(-61*time.Minute), now.Add(-59*time.Minute), now.Add(-store.RateLimitRetention)
		var none time.Time
		gone := []string{
			mk(a.ID, old, old.Add(15*time.Minute), none),            // expired
			mk(a.ID, old, now.Add(time.Hour), old.Add(time.Minute)), // consumed
			mk(a.ID, old, now, none),                                // expires exactly now
		}
		kept := []string{
			mk(a.ID, young, young.Add(15*time.Minute), none),            // expired, but counted by the rate limits
			mk(a.ID, edge, edge.Add(15*time.Minute), none),              // created exactly an hour ago
			mk(a.ID, old, now.Add(time.Millisecond), none),              // still open
			mk(a.ID, young, now.Add(time.Hour), young.Add(time.Minute)), // consumed, young
		}
		other := mk(b.ID, old, old.Add(15*time.Minute), none)

		if n, err := repo.Purge(ctx, a.ID, now); err != nil || n != int64(len(gone)) {
			t.Fatalf("Purge = %d, %v; want %d", n, err, len(gone))
		}
		for _, chID := range gone {
			_, err := repo.Get(ctx, a.ID, chID)
			wantErr(t, "purged challenge", err, store.ErrNotFound)
		}
		for _, chID := range kept {
			if _, err := repo.Get(ctx, a.ID, chID); err != nil {
				t.Errorf("kept challenge: %v", err)
			}
		}
		if _, err := repo.Get(ctx, b.ID, other); err != nil {
			t.Errorf("B's challenge purged by A's purge: %v", err)
		}
		if n, err := repo.Purge(ctx, a.ID, now); err != nil || n != 0 {
			t.Errorf("second Purge = %d, %v", n, err)
		}
		for _, tid := range badTenants {
			_, err := repo.Purge(ctx, tid, now)
			wantErr(t, "Purge(bad tenant)", err, store.ErrInvalid)
		}
	})
}

func TestDepositSessionsPurge(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.DepositSessions()
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		now := fixedNow.Add(10 * time.Hour)
		mk := func(tid tenant.ID, expires time.Time) store.DepositSession {
			t.Helper()
			s := newSession(t, "alice@entity-a.example.com")
			s.ExpiresAt = expires
			if err := repo.Create(ctx, tid, s); err != nil {
				t.Fatalf("Create session: %v", err)
			}
			return s
		}
		mk(a.ID, now.Add(-time.Millisecond)) // expired
		mk(a.ID, now)                        // expires exactly now
		ended := mk(a.ID, now.Add(time.Hour))
		if err := repo.End(ctx, a.ID, ended.TokenHash, fixedNow.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		active := mk(a.ID, now.Add(time.Millisecond))
		mk(b.ID, now.Add(-time.Millisecond))

		if n, err := repo.Purge(ctx, a.ID, now); err != nil || n != 3 {
			t.Fatalf("Purge = %d, %v; want 3", n, err)
		}
		if _, err := repo.GetByTokenHash(ctx, a.ID, active.TokenHash, now); err != nil {
			t.Errorf("active session purged: %v", err)
		}
		if n, err := repo.Purge(ctx, a.ID, now.Add(time.Hour)); err != nil || n != 1 {
			t.Errorf("Purge once the last session expired = %d, %v; want 1", n, err)
		}
		if n, err := repo.Purge(ctx, b.ID, now); err != nil || n != 1 {
			t.Errorf("Purge(B) = %d, %v; want 1 (untouched by A's purge)", n, err)
		}
		for _, tid := range badTenants {
			_, err := repo.Purge(ctx, tid, now)
			wantErr(t, "Purge(bad tenant)", err, store.ErrInvalid)
		}
	})
}

func TestPasswordFailuresPurge(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		pf := db.PasswordFailures()
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		now := fixedNow.Add(24 * time.Hour)
		ip := func(i byte) store.FailureKey { return store.IPFailureKey(netip.AddrFrom4([4]byte{192, 0, 2, i})) }
		record := func(tid tenant.ID, k store.FailureKey, at ...time.Time) {
			t.Helper()
			for _, when := range at {
				if err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
					_, err := pf.RecordFailureTx(ctx, tx, []store.FailureKey{k}, when)
					return err
				}); err != nil {
					t.Fatalf("RecordFailureTx: %v", err)
				}
			}
		}
		w := store.PasswordFailureWindow
		record(a.ID, ip(1), now.Add(-w))                                                                  // stale exactly at the window
		record(a.ID, ip(2), now.Add(-w+time.Millisecond))                                                 // still counting
		record(a.ID, ip(3), now.Add(-w-2*time.Minute), now.Add(-w-time.Minute), now.Add(-w))              // lock ends exactly now
		record(a.ID, ip(4), now.Add(-14*time.Minute), now.Add(-13*time.Minute), now.Add(-12*time.Minute)) // locked
		record(a.ID, store.TransferFailureKey(id.New(id.Transfer)), now.Add(-time.Hour))                  // transfer scope
		refunded := ip(5)
		record(a.ID, refunded, now.Add(-time.Minute))
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return pf.RefundTx(ctx, tx, []store.FailureKey{refunded}, now.Add(-time.Minute))
		}); err != nil {
			t.Fatal(err)
		}
		record(b.ID, ip(1), now.Add(-time.Hour))

		if n, err := pf.Purge(ctx, a.ID, now); err != nil || n != 4 {
			t.Fatalf("Purge = %d, %v; want 4", n, err)
		}
		var until time.Time
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			var err error
			until, err = pf.CheckTx(ctx, tx, []store.FailureKey{ip(4)}, now)
			return err
		}); err != nil || until.IsZero() {
			t.Errorf("running lock purged: until %v, %v", until, err)
		}
		if n, err := pf.Purge(ctx, a.ID, now.Add(time.Hour)); err != nil || n != 2 {
			t.Errorf("Purge an hour later = %d, %v; want 2", n, err)
		}
		if n, err := pf.Purge(ctx, b.ID, now); err != nil || n != 1 {
			t.Errorf("Purge(B) = %d, %v; want 1 (untouched by A's purge)", n, err)
		}
		for _, tid := range badTenants {
			_, err := pf.Purge(ctx, tid, now)
			wantErr(t, "Purge(bad tenant)", err, store.ErrInvalid)
		}
	})
}

func TestVerifiedAddressesPurge(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.VerifiedAddresses()
		newT := func(host string) tenant.ID { return newTenant(t, db, host).ID }
		a, b := newT("transfer.entity-a.example.com"), newT("transfer.entity-b.example.com")
		upsert := func(tid tenant.ID, email string, first, last time.Time) {
			t.Helper()
			if err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				_, err := repo.UpsertTx(ctx, tx, store.VerifiedAddress{Email: email, FirstVerifiedAt: first, FirstVerifiedIP: ipA, LastUsedAt: last})
				return err
			}); err != nil {
				t.Fatalf("UpsertTx: %v", err)
			}
		}
		// purgeAndCheck purges tid at now, expecting n deletions, then
		// checks that each address is present exactly when Active.
		purgeAndCheck := func(tid tenant.ID, now time.Time, n int64, emails ...string) {
			t.Helper()
			active := map[string]bool{}
			for _, m := range emails {
				v, err := repo.Get(ctx, tid, m)
				if err != nil {
					t.Fatal(err)
				}
				active[m] = v.Active(now)
			}
			if got, err := repo.Purge(ctx, tid, now); err != nil || got != n {
				t.Fatalf("Purge(%v) = %d, %v; want %d", now, got, err, n)
			}
			for _, m := range emails {
				_, err := repo.Get(ctx, tid, m)
				if present := err == nil; present != active[m] {
					t.Errorf("%s at %v: present %v, active %v (%v)", m, now, present, active[m], err)
				}
			}
		}

		now := time.Date(2027, 6, 15, 10, 0, 0, 0, time.UTC)
		cut := now.AddDate(0, -store.VerifiedRetentionMonths, 0)
		day := 24 * time.Hour
		upsert(a, "old@entity-a.example.com", cut.Add(-day), time.Time{})
		upsert(a, "edge@entity-a.example.com", cut, time.Time{})
		upsert(a, "young@entity-a.example.com", cut.Add(day), time.Time{})
		upsert(a, "recent@entity-a.example.com", cut.Add(time.Millisecond), time.Time{})
		upsert(a, "used@entity-a.example.com", cut.Add(-2*day), cut.Add(day))
		upsert(b, "old@entity-a.example.com", cut.Add(-day), time.Time{})
		purgeAndCheck(a, now, 2, "old@entity-a.example.com", "edge@entity-a.example.com",
			"young@entity-a.example.com", "recent@entity-a.example.com", "used@entity-a.example.com")
		if _, err := repo.Get(ctx, b, "old@entity-a.example.com"); err != nil {
			t.Errorf("B's address purged by A's purge: %v", err)
		}

		// Calendar months: the database preselection includes an address
		// still active (March 1st + 12 months is after February 29th), which
		// the exact rule keeps.
		c := newT("transfer.entity-c.example.com")
		upsert(c, "march@entity-a.example.com", time.Date(2027, 3, 1, 5, 0, 0, 0, time.UTC), time.Time{})
		upsert(c, "feb@entity-a.example.com", time.Date(2027, 2, 28, 12, 0, 0, 0, time.UTC), time.Time{})
		purgeAndCheck(c, time.Date(2028, 2, 29, 10, 0, 0, 0, time.UTC), 1, "march@entity-a.example.com", "feb@entity-a.example.com")
		// February 29th + 12 months is March 1st.
		d := newT("transfer.entity-d.example.com")
		upsert(d, "leap@entity-a.example.com", time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC), time.Time{})
		leapEnd := time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)
		purgeAndCheck(d, leapEnd.Add(-time.Millisecond), 0, "leap@entity-a.example.com")
		purgeAndCheck(d, leapEnd, 1, "leap@entity-a.example.com")

		for _, tid := range badTenants {
			_, err := repo.Purge(ctx, tid, now)
			wantErr(t, "Purge(bad tenant)", err, store.ErrInvalid)
		}
	})
}

func TestInvitationsPurge(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Invitations()
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		now := fixedNow.Add(24 * time.Hour)
		year := 365 * 24 * time.Hour
		mk := func(tid tenant.ID, created, expires time.Time, revoke bool) string {
			t.Helper()
			inv := newInvitation(t)
			inv.CreatedAt, inv.ExpiresAt = created, expires
			if err := repo.Create(ctx, tid, inv); err != nil {
				t.Fatalf("Create invitation: %v", err)
			}
			if revoke {
				if err := repo.Revoke(ctx, tid, inv.ID, created.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			return inv.ID
		}
		old, young, edge := now.Add(-61*time.Minute), now.Add(-59*time.Minute), now.Add(-store.RateLimitRetention)
		revokedOld := mk(a.ID, old, now.Add(year), true)
		gone := []string{revokedOld, mk(a.ID, old, now, false)} // revoked; expires exactly now
		kept := []string{
			mk(a.ID, young, now.Add(year), true),            // revoked, but counted by the rate limit
			mk(a.ID, edge, now.Add(year), true),             // created exactly an hour ago
			mk(a.ID, old, now.Add(time.Millisecond), false), // active
		}
		referenced := mk(a.ID, old, now.Add(year), true)
		other := mk(b.ID, old, now.Add(year), true)

		// A challenge of the purged invitation follows by cascade.
		ch := newChallenge(t, "bob@partner.example.org", ipA)
		ch.InvitationID = revokedOld
		if err := db.Challenges().Create(ctx, a.ID, ch); err != nil {
			t.Fatal(err)
		}
		// A transfer references the last one.
		tr := newTransfer()
		tr.SenderEmail, tr.SenderKind, tr.InvitationID = "bob@partner.example.org", store.DepositorExternal, referenced
		ref := mustTransfer(t, db, a.ID, tr)

		if n, err := repo.Purge(ctx, a.ID, now); err != nil || n != int64(len(gone)) {
			t.Fatalf("Purge = %d, %v; want %d", n, err, len(gone))
		}
		for _, invID := range gone {
			_, err := repo.Get(ctx, a.ID, invID)
			wantErr(t, "purged invitation", err, store.ErrNotFound)
		}
		_, err := db.Challenges().Get(ctx, a.ID, ch.ID)
		wantErr(t, "challenge of a purged invitation", err, store.ErrNotFound)
		for _, invID := range append(kept, referenced) {
			if _, err := repo.Get(ctx, a.ID, invID); err != nil {
				t.Errorf("kept invitation: %v", err)
			}
		}
		if _, err := repo.Get(ctx, b.ID, other); err != nil {
			t.Errorf("B's invitation purged by A's purge: %v", err)
		}

		// Once the rows of its transfer are deleted, the invitation goes.
		deleteFileKeys(t, db, a.ID, ref)
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			return db.Transfers().SetStatusTx(ctx, tx, ref.ID, store.TransferUploading, store.TransferDeleted, now)
		}); err != nil {
			t.Fatal(err)
		}
		if err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error { return db.Transfers().DeleteTx(ctx, tx, ref.ID) }); err != nil {
			t.Fatal(err)
		}
		if n, err := repo.Purge(ctx, a.ID, now); err != nil || n != 1 {
			t.Errorf("Purge after the transfer deletion = %d, %v; want 1", n, err)
		}
		if n, err := repo.Purge(ctx, b.ID, now); err != nil || n != 1 {
			t.Errorf("Purge(B) = %d, %v; want 1", n, err)
		}
		for _, tid := range badTenants {
			_, err := repo.Purge(ctx, tid, now)
			wantErr(t, "Purge(bad tenant)", err, store.ErrInvalid)
		}
	})
}

func TestTenantsIDs(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		if got, err := db.Tenants().IDs(ctx); err != nil || len(got) != 0 {
			t.Errorf("IDs(no tenant) = %v, %v", got, err)
		}
		a, b := newTenant(t, db, "transfer.entity-a.example.com"), newTenant(t, db, "transfer.entity-b.example.com")
		want := []tenant.ID{a.ID, b.ID}
		if b.ID < a.ID {
			want = []tenant.ID{b.ID, a.ID}
		}
		if got, err := db.Tenants().IDs(ctx); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("IDs = %v, %v; want %v", got, err, want)
		}
	})
}

func TestBackup(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		dir := t.TempDir()
		path := filepath.Join(dir, "copy.db")
		if e.Driver == config.DriverPostgres {
			wantErr(t, "Backup(postgres)", db.Backup(ctx, path), store.ErrBackupUnsupported)
			return
		}
		wantErr(t, "Backup(relative path)", db.Backup(ctx, "copy.db"), store.ErrInvalid)
		if err := db.Backup(ctx, filepath.Join(dir, "missing", "copy.db")); err == nil {
			t.Error("Backup into a missing directory succeeded")
		}
		// An empty file pre-created with a restricted mode is filled in
		// place, keeping its mode.
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := db.Backup(ctx, path); err != nil {
			t.Fatalf("Backup into an empty file: %v", err)
		}
		if fi, err := os.Stat(path); err != nil || fi.Size() == 0 || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
			t.Errorf("copy = %v, %v; want a filled file of mode 0600", fi, err)
		}
		if err := db.Backup(ctx, path); !errors.Is(err, fs.ErrExist) {
			t.Errorf("Backup over a non-empty file = %v, want fs.ErrExist", err)
		}
		if err := db.Backup(ctx, filepath.Join(dir, "fresh.db")); err != nil {
			t.Errorf("Backup into a new file: %v", err)
		}
		if err := db.Backup(ctx, dir); !errors.Is(err, fs.ErrExist) {
			t.Errorf("Backup over a directory = %v, want fs.ErrExist", err)
		}
		empty := filepath.Join(dir, "empty.db")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if link := filepath.Join(dir, "link.db"); os.Symlink(empty, link) == nil {
			if err := db.Backup(ctx, link); !errors.Is(err, fs.ErrExist) {
				t.Errorf("Backup through a symbolic link = %v, want fs.ErrExist", err)
			}
		}
		if err := db.Backup(ctx, filepath.Join(dir, "bad\x00name")); err == nil || errors.Is(err, fs.ErrExist) {
			t.Errorf("Backup(unreadable path) = %v", err)
		}

		// The copy is a complete database.
		cfg := *e.Config()
		cfg.DBDSN = config.NewSecret(path)
		cp, err := store.Open(ctx, &cfg)
		if err != nil {
			t.Fatalf("Open(copy): %v", err)
		}
		defer func() { _ = cp.Close() }()
		if got, err := cp.Tenants().Get(ctx, a.ID); err != nil || got.FQDN != a.FQDN {
			t.Errorf("tenant in the copy = %+v, %v", got, err)
		}
		if st, err := cp.Status(ctx); err != nil || st[len(st)-1].State != store.MigrationApplied {
			t.Errorf("copy schema = %+v, %v", st, err)
		}
	})
}

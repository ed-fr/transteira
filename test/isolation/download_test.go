package isolation_test

import (
	"database/sql"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// availableTransfer stores an available transfer of tid, with the "delete
// after the first download" option.
func availableTransfer(t *testing.T, db *store.DB, tid tenant.ID) store.TransferDetails {
	t.Helper()
	ctx := t.Context()
	tr := store.Transfer{
		ID: id.New(id.Transfer), SenderEmail: "alice@entity-a.example.com", SenderKind: store.DepositorInternal,
		ExpiryDays: 7, DeleteAfterFirstDownload: true,
	}
	fl := newTransferFile(t, db, tid)
	fl.SHA256, fl.CiphertextSize, fl.UploadedAt = shaTransfer, 80, epoch
	tokenKey := newSecretKey(t, db, tid)
	s, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		if err := db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@partner.example.net"}, []store.TransferFile{fl}); err != nil {
			return err
		}
		if err := db.Transfers().FinalizeTx(ctx, tx, tr.ID, epoch); err != nil {
			return err
		}
		return db.Transfers().MarkAvailableTx(ctx, tx, tr.ID, downloadHash(t), tokenKey, epoch)
	})
	if err != nil {
		t.Fatalf("available transfer: %v", err)
	}
	d, err := db.Transfers().Get(ctx, tid, tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestDownloadIsolation attacks A's available transfer and A's password
// failure counters from tenant B: B never records A's first download,
// never deletes A's transfer, never sees, raises or clears A's locks, and
// every transfer attempt reads as a plain not-found. The cross-tenant
// deletion sweep returns identifiers only.
func TestDownloadIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a, b := newTenant(t, db, fqdnA), newTenant(t, db, fqdnB)
		da, dbB := availableTransfer(t, db, a.ID), availableTransfer(t, db, b.ID)
		transfers, pf := db.Transfers(), db.PasswordFailures()
		sa, err := db.Scoped(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		sb, err := db.Scoped(b.ID)
		if err != nil {
			t.Fatal(err)
		}
		inA := func(fn func(tx *store.ScopedTx) error) error { return sa.Tx(ctx, fn) }
		inB := func(fn func(tx *store.ScopedTx) error) error { return sb.Tx(ctx, fn) }
		now := epoch.Add(time.Hour)

		// Transfers: B cannot mark or delete A's transfer.
		assertNotFound(t, "MarkFirstDownloadTx", inB(func(tx *store.ScopedTx) error {
			_, err := transfers.MarkFirstDownloadTx(ctx, tx, da.ID, now, now)
			return err
		}))
		assertNotFound(t, "MarkDeletedTx", inB(func(tx *store.ScopedTx) error { return transfers.MarkDeletedTx(ctx, tx, da.ID) }))
		if got, err := transfers.Get(ctx, a.ID, da.ID); err != nil || !reflect.DeepEqual(got, da) {
			t.Errorf("A's transfer changed: %+v, %v", got, err)
		}

		// Both tenants' transfers become due; the sweep crosses tenants
		// and returns identifiers only.
		for _, c := range []struct {
			in  func(func(*store.ScopedTx) error) error
			trf string
		}{{inA, da.ID}, {inB, dbB.ID}} {
			if err := c.in(func(tx *store.ScopedTx) error {
				_, err := transfers.MarkFirstDownloadTx(ctx, tx, c.trf, now, now)
				return err
			}); err != nil {
				t.Fatalf("MarkFirstDownloadTx: %v", err)
			}
		}
		got, err := transfers.DueDeletions(ctx, now)
		want := map[store.TenantTransfer]bool{
			{TenantID: a.ID, TransferID: da.ID}:  true,
			{TenantID: b.ID, TransferID: dbB.ID}: true,
		}
		if err != nil || len(got) != len(want) {
			t.Fatalf("DueDeletions = %+v, %v", got, err)
		}
		for _, tt := range got {
			if !want[tt] {
				t.Errorf("DueDeletions returned %+v", tt)
			}
		}

		// Password failures: A's keys locked in A are invisible to B, and
		// B's failures and resets on the same keys only touch B's rows.
		keys := []store.FailureKey{store.TransferFailureKey(da.ID), store.IPFailureKey(netip.MustParseAddr("203.0.113.7"))}
		for range store.MaxPasswordFailures {
			if err := inA(func(tx *store.ScopedTx) error { _, err := pf.RecordFailureTx(ctx, tx, keys, now); return err }); err != nil {
				t.Fatalf("RecordFailureTx(A): %v", err)
			}
		}
		lockEnd := now.Add(store.PasswordLockDuration)
		checkIn := func(in func(func(*store.ScopedTx) error) error) time.Time {
			t.Helper()
			var until time.Time
			if err := in(func(tx *store.ScopedTx) error {
				var err error
				until, err = pf.CheckTx(ctx, tx, keys, now)
				return err
			}); err != nil {
				t.Fatalf("CheckTx: %v", err)
			}
			return until
		}
		if until := checkIn(inB); !until.IsZero() {
			t.Errorf("B sees A's lock until %v", until)
		}
		var out store.FailureOutcome
		if err := inB(func(tx *store.ScopedTx) error {
			var err error
			out, err = pf.RecordFailureTx(ctx, tx, keys, now)
			return err
		}); err != nil || out.Remaining != store.MaxPasswordFailures-1 || !out.LockedUntil.IsZero() {
			t.Errorf("RecordFailureTx(B) = %+v, %v: B must start its own count", out, err)
		}
		if err := inB(func(tx *store.ScopedTx) error { return pf.ResetTx(ctx, tx, keys) }); err != nil {
			t.Fatalf("ResetTx(B): %v", err)
		}
		if until := checkIn(inA); !until.Equal(lockEnd.Truncate(time.Millisecond)) {
			t.Errorf("A's lock after B's reset = %v, want %v", until, lockEnd)
		}
		if n := rawCount(t, e, "password_failures", "tenant_id", a.ID); n != 2 {
			t.Errorf("A holds %d password failure rows, want 2", n)
		}
		if n := rawCount(t, e, "password_failures", "tenant_id", b.ID); n != 0 {
			t.Errorf("B holds %d password failure rows after its reset, want 0", n)
		}
	})
}

// TestRLSPasswordFailuresCrossTenantRawSQL checks with raw SQL, bypassing
// the store, that the row-level security policy of password_failures hides
// and protects B's rows from a transaction scoped to A.
func TestRLSPasswordFailuresCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	db := f.db
	keys := []store.FailureKey{store.IPFailureKey(netip.MustParseAddr("2001:db8::1"))}
	for _, tid := range []tenant.ID{f.a.ID, f.b.ID} {
		s, err := db.Scoped(tid)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Tx(ctx, func(tx *store.ScopedTx) error {
			_, err := db.PasswordFailures().RecordFailureTx(ctx, tx, keys, epoch)
			return err
		}); err != nil {
			t.Fatalf("RecordFailureTx: %v", err)
		}
	}
	a, b := string(f.a.ID), string(f.b.ID)
	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		if n := countRows(ctx, t, tx, `SELECT count(*) FROM password_failures WHERE tenant_id = $1`, b); n != 0 {
			t.Errorf("A sees %d of B's password failure rows", n)
		}
		if n := countRows(ctx, t, tx, `SELECT count(*) FROM password_failures`); n != 1 {
			t.Errorf("A sees %d password failure rows, want 1", n)
		}
		for _, stmt := range []string{
			`UPDATE password_failures SET fail_1 = NULL, fail_2 = NULL, fail_3 = NULL, locked_until = NULL WHERE tenant_id = $1`,
			`DELETE FROM password_failures WHERE tenant_id = $1`,
		} {
			if n := affected(ctx, t, tx, stmt, b); n != 0 {
				t.Errorf("%s affected %d rows of B", stmt, n)
			}
		}
		return nil
	})
	for name, stmt := range map[string]string{
		"move A's rows to B": `UPDATE password_failures SET tenant_id = $1`,
		"insert a lock for B": `INSERT INTO password_failures (tenant_id, scope, key, fail_1, fail_2, fail_3, locked_until) ` +
			`VALUES ($1, 'ip', '192.0.2.1', 1, 2, 3, 9999999999999)`,
	} {
		err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, stmt, b); return err })
		assertRLSViolation(t, name, err)
	}
	// B's counter is intact: its second failure leaves one attempt.
	s, err := db.Scoped(f.b.ID)
	if err != nil {
		t.Fatal(err)
	}
	var out store.FailureOutcome
	if err := s.Tx(ctx, func(tx *store.ScopedTx) error {
		var err error
		out, err = db.PasswordFailures().RecordFailureTx(ctx, tx, keys, epoch)
		return err
	}); err != nil || out.Remaining != store.MaxPasswordFailures-2 {
		t.Errorf("B's second failure = %+v, %v", out, err)
	}
}

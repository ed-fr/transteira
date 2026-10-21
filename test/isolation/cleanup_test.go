package isolation_test

import (
	"crypto/sha256"
	"database/sql"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// purgedTables lists the tables the periodic cleanup purges per tenant.
var purgedTables = []string{"verification_challenges", "deposit_sessions", "verified_addresses", "invitations", "password_failures"}

// seedCleanup stores, for tid at the test clock (epoch), one purgeable row
// of every purged table, an uploading transfer and a transfer deleted at
// epoch (its file key destroyed first, its file row kept), and returns the
// two transfers.
func seedCleanup(t *testing.T, db *store.DB, tid tenant.ID) (open, ended store.TransferDetails) {
	t.Helper()
	ctx := t.Context()
	ip := netip.MustParseAddr("192.0.2.1")
	email := "alice@entity-a.example.com"
	chID, err := id.NewToken(id.ChallengeTokenPrefix, id.MinTokenBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Challenges().Create(ctx, tid, store.Challenge{
		ID: chID, Email: email, CodeMAC: []byte{1}, AttemptsRemaining: 1, ClientIP: ip, ExpiresAt: epoch.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(chID))
	if err := db.DepositSessions().Create(ctx, tid, store.DepositSession{
		ID: id.New(id.DepositSession), TokenHash: h[:], Email: email, Kind: store.DepositorInternal, ExpiresAt: epoch.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	h = sha256.Sum256([]byte("invitation " + chID))
	if err := db.Invitations().Create(ctx, tid, store.Invitation{
		ID: id.New(id.Invitation), TokenHash: h[:], Email: "bob@partner.example.net", InvitedBy: email,
	}); err != nil {
		t.Fatal(err)
	}
	s, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		if _, err := db.VerifiedAddresses().UpsertTx(ctx, tx, store.VerifiedAddress{Email: email, FirstVerifiedIP: ip}); err != nil {
			return err
		}
		_, err := db.PasswordFailures().RecordFailureTx(ctx, tx, []store.FailureKey{store.IPFailureKey(ip)}, epoch)
		return err
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	mk := func(fl store.TransferFile) store.TransferDetails {
		tr := store.Transfer{ID: id.New(id.Transfer), SenderEmail: email, SenderKind: store.DepositorInternal, ExpiryDays: 1}
		if err := s.Tx(ctx, func(tx *store.ScopedTx) error {
			return db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@partner.example.net"}, []store.TransferFile{fl})
		}); err != nil {
			t.Fatalf("CreateTx: %v", err)
		}
		d, err := db.Transfers().Get(ctx, tid, tr.ID)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	open, ended = mk(newTransferFile(t, db, tid)), mk(newTransferFile(t, db, tid))
	if err := db.WrappedKeys().Delete(ctx, tid, ended.Files[0].DEKKeyID); err != nil {
		t.Fatal(err)
	}
	if err := s.Tx(ctx, func(tx *store.ScopedTx) error {
		return db.Transfers().SetStatusTx(ctx, tx, ended.ID, store.TransferUploading, store.TransferDeleted, epoch)
	}); err != nil {
		t.Fatalf("SetStatusTx: %v", err)
	}
	return open, ended
}

// TestCleanupIsolation runs every cleanup operation of tenant A and checks
// that B's rows are untouched and never listed for A; B cannot expire A's
// transfer. The cross-tenant sweeps return identifiers paired with their
// own tenant.
func TestCleanupIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a, b := newTenant(t, db, fqdnA), newTenant(t, db, fqdnB)
		openA, _ := seedCleanup(t, db, a.ID)
		openB, endedB := seedCleanup(t, db, b.ID)
		future := epoch.Add(400 * 24 * time.Hour)
		sb, err := db.Scoped(b.ID)
		if err != nil {
			t.Fatal(err)
		}

		// B cannot expire A's transfer, keys or not.
		assertNotFound(t, "MarkExpiredTx", sb.Tx(ctx, func(tx *store.ScopedTx) error {
			return db.Transfers().MarkExpiredTx(ctx, tx, openA.ID, future)
		}))

		// The tenant-scoped listings of B never show A's rows.
		if got, err := db.Transfers().ListEnded(ctx, b.ID, future, store.PurgeBatchSize); err != nil || !slices.Equal(got, []string{endedB.ID}) {
			t.Errorf("ListEnded(B) = %v, %v; want only %s", got, err, endedB.ID)
		}
		if got, err := db.Transfers().IDsByStatus(ctx, b.ID, store.TransferUploading, store.TransferDeleted); err != nil ||
			!slices.Equal(got, []string{openB.ID, endedB.ID}) {
			t.Errorf("IDsByStatus(B) = %v, %v", got, err)
		}
		refs, err := db.TransferFiles().StorageRefs(ctx, b.ID)
		if err != nil || len(refs) != 2 {
			t.Fatalf("StorageRefs(B) = %+v, %v", refs, err)
		}
		for name, ref := range refs {
			if ref.TransferID != openB.ID && ref.TransferID != endedB.ID {
				t.Errorf("StorageRefs(B) lists %s of %s", name, ref.TransferID)
			}
		}

		// The cross-tenant sweep pairs each transfer with its tenant, and
		// its keyset cursor walks from one tenant to the other.
		want := map[store.TenantTransfer]bool{
			{TenantID: a.ID, TransferID: openA.ID}: true, {TenantID: b.ID, TransferID: openB.ID}: true,
		}
		var after store.TenantTransfer
		for range 3 {
			page, err := db.Transfers().AbandonedUploads(ctx, future, store.SweepPage{After: after, Limit: 1})
			if err != nil {
				t.Fatalf("AbandonedUploads: %v", err)
			}
			if len(page) == 0 {
				break
			}
			after = page[0]
			id := store.TenantTransfer{TenantID: after.TenantID, TransferID: after.TransferID}
			if !want[id] {
				t.Errorf("AbandonedUploads returned %+v", after)
			}
			delete(want, id)
		}
		if len(want) != 0 {
			t.Errorf("AbandonedUploads missed %+v", want)
		}

		// A's purges leave B's rows.
		before := map[string]int{}
		for _, table := range purgedTables {
			before[table] = rawCount(t, e, table, "tenant_id", b.ID)
			if before[table] != 1 || rawCount(t, e, table, "tenant_id", a.ID) != 1 {
				t.Fatalf("%s not seeded", table)
			}
		}
		for name, purge := range map[string]func() (int64, error){
			"challenges":        func() (int64, error) { return db.Challenges().Purge(ctx, a.ID, future) },
			"sessions":          func() (int64, error) { return db.DepositSessions().Purge(ctx, a.ID, future) },
			"verified":          func() (int64, error) { return db.VerifiedAddresses().Purge(ctx, a.ID, future) },
			"invitations":       func() (int64, error) { return db.Invitations().Purge(ctx, a.ID, future) },
			"password failures": func() (int64, error) { return db.PasswordFailures().Purge(ctx, a.ID, future) },
		} {
			if n, err := purge(); err != nil || n != 1 {
				t.Errorf("Purge %s (A) = %d, %v; want 1", name, n, err)
			}
		}
		for _, table := range purgedTables {
			if n := rawCount(t, e, table, "tenant_id", a.ID); n != 0 {
				t.Errorf("A keeps %d rows of %s after its purge", n, table)
			}
			if n := rawCount(t, e, table, "tenant_id", b.ID); n != before[table] {
				t.Errorf("B holds %d rows of %s after A's purge, want %d", n, table, before[table])
			}
		}
		if _, err := db.Transfers().Get(ctx, b.ID, endedB.ID); err != nil {
			t.Errorf("B's ended transfer: %v", err)
		}
	})
}

// TestRLSCleanupCrossTenantRawSQL checks with raw SQL, bypassing the store,
// that a transaction scoped to A neither sees nor changes the end of B's
// transfers, nor deletes B's rows of the purged tables.
func TestRLSCleanupCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	seedCleanup(t, f.db, f.a.ID)
	_, endedB := seedCleanup(t, f.db, f.b.ID)
	a, b := string(f.a.ID), string(f.b.ID)
	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		if n := countRows(ctx, t, tx, `SELECT count(*) FROM transfers WHERE tenant_id = $1 AND ended_at IS NOT NULL`, b); n != 0 {
			t.Errorf("A sees %d of B's ended transfers", n)
		}
		if n := countRows(ctx, t, tx, `SELECT count(*) FROM transfers WHERE ended_at IS NOT NULL`); n != 1 {
			t.Errorf("A sees %d ended transfers, want 1", n)
		}
		if n := affected(ctx, t, tx, `UPDATE transfers SET ended_at = 0 WHERE tenant_id = $1`, b); n != 0 {
			t.Errorf("A changed the end of %d of B's transfers", n)
		}
		if n := affected(ctx, t, tx, `DELETE FROM transfers WHERE id = $1`, endedB.ID); n != 0 {
			t.Errorf("A deleted B's ended transfer")
		}
		for _, table := range purgedTables {
			if n := affected(ctx, t, tx, `DELETE FROM `+table+` WHERE tenant_id = $1`, b); n != 0 {
				t.Errorf("A deleted %d of B's rows of %s", n, table)
			}
		}
		return nil
	})
	got, err := f.db.Transfers().Get(ctx, f.b.ID, endedB.ID)
	if err != nil || !got.EndedAt.Equal(epoch) {
		t.Errorf("B's ended transfer after A's attempts = %+v, %v", got.Transfer, err)
	}
	for _, table := range purgedTables {
		if n := rawCount(t, f.e, table, "tenant_id", f.b.ID); n != 1 {
			t.Errorf("B holds %d rows of %s, want 1", n, table)
		}
	}
}

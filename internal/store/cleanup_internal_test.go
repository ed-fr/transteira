package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// cleanupFuture is far enough after the fixtures' creation for every
// seeded row to be purgeable (beyond VerifiedRetentionMonths and the
// invitation validity).
const cleanupFuture = 400 * 24 * time.Hour

// seedPurgeable stores, for the fixture's tenant, one purgeable row of each
// purged table at the fixture's (real) clock: a challenge, a deposit
// session, a verified address, an invitation and a password failure.
func seedPurgeable(t *testing.T, f *transferFixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	chID, err := id.NewToken(id.ChallengeTokenPrefix, id.MinTokenBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Challenges().Create(ctx, f.tid, Challenge{
		ID: chID, Email: fixtureEmail, CodeMAC: []byte{1}, AttemptsRemaining: 1, ClientIP: ip, ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(chID))
	if err := f.db.DepositSessions().Create(ctx, f.tid, DepositSession{
		ID: id.New(id.DepositSession), TokenHash: h[:], Email: fixtureEmail, Kind: DepositorInternal, ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	h2 := sha256.Sum256([]byte("inv" + chID))
	if err := f.db.Invitations().Create(ctx, f.tid, Invitation{
		ID: id.New(id.Invitation), TokenHash: h2[:], Email: "bob@b.example.org", InvitedBy: fixtureEmail,
	}); err != nil {
		t.Fatal(err)
	}
	err = f.tx(ctx, func(tx *ScopedTx) error {
		if _, err := f.db.VerifiedAddresses().UpsertTx(ctx, tx, VerifiedAddress{Email: fixtureEmail, FirstVerifiedIP: ip}); err != nil {
			return err
		}
		_, err := f.db.PasswordFailures().RecordFailureTx(ctx, tx, []FailureKey{IPFailureKey(ip)}, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestCleanupDriverFaults injects a driver failure into each statement of
// the cleanup operations and checks that it surfaces as an error.
func TestCleanupDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	future := time.Now().Add(cleanupFuture)
	finalize := func(f *transferFixture) {
		if err := f.db.TransferFiles().CompleteUpload(ctx, f.tid, f.file.ID, faultSHA, 1, time.Now()); err != nil {
			panic(err)
		}
		if err := f.tx(ctx, func(tx *ScopedTx) error { return f.db.Transfers().FinalizeTx(ctx, tx, f.trf.ID, time.Now()) }); err != nil {
			panic(err)
		}
	}
	dueExpirations := func(f *transferFixture) func() error {
		finalize(f)
		return func() error {
			_, err := f.db.Transfers().DueExpirations(ctx, future, time.Millisecond, SweepPage{Limit: 1})
			return err
		}
	}
	rejectedKeyed := func(f *transferFixture) func() error {
		return func() error { _, err := f.db.Transfers().RejectedKeyed(ctx, SweepPage{Limit: 1}); return err }
	}
	abandoned := func(f *transferFixture) func() error {
		return func() error {
			_, err := f.db.Transfers().AbandonedUploads(ctx, future, SweepPage{Limit: 1})
			return err
		}
	}
	expire := func(f *transferFixture) func() error {
		return func() error {
			return f.tx(ctx, func(tx *ScopedTx) error { return f.db.Transfers().MarkExpiredTx(ctx, tx, f.trf.ID, future) })
		}
	}
	expireUnkeyed := func(f *transferFixture) func() error {
		if err := f.db.WrappedKeys().Delete(ctx, f.tid, f.file.DEKKeyID); err != nil {
			panic(err)
		}
		return expire(f)
	}
	expireDeleted := func(f *transferFixture) func() error {
		run := expireUnkeyed(f)
		if err := f.tx(ctx, func(tx *ScopedTx) error {
			return f.db.Transfers().SetStatusTx(ctx, tx, f.trf.ID, TransferUploading, TransferDeleted, time.Now())
		}); err != nil {
			panic(err)
		}
		return run
	}
	listEnded := func(f *transferFixture) func() error {
		return func() error { _, err := f.db.Transfers().ListEnded(ctx, f.tid, future, 1); return err }
	}
	byStatus := func(f *transferFixture) func() error {
		return func() error { _, err := f.db.Transfers().IDsByStatus(ctx, f.tid, TransferUploading); return err }
	}
	refs := func(f *transferFixture) func() error {
		return func() error { _, err := f.db.TransferFiles().StorageRefs(ctx, f.tid); return err }
	}
	purge := func(fn func(f *transferFixture) (int64, error)) func(*testing.T, *transferFixture) func() error {
		return func(t *testing.T, f *transferFixture) func() error {
			seedPurgeable(t, f)
			return func() error { _, err := fn(f); return err }
		}
	}
	challenges := purge(func(f *transferFixture) (int64, error) { return f.db.Challenges().Purge(ctx, f.tid, future) })
	verified := purge(func(f *transferFixture) (int64, error) { return f.db.VerifiedAddresses().Purge(ctx, f.tid, future) })
	invitations := purge(func(f *transferFixture) (int64, error) { return f.db.Invitations().Purge(ctx, f.tid, future) })
	tenantIDs := func(f *transferFixture) func() error {
		return func() error { _, err := f.db.Tenants().IDs(ctx); return err }
	}

	steps := []struct {
		name, op, match string
		run             func(*testing.T, *transferFixture) func() error
	}{
		{"due expirations", faultQuery, "ORDER BY due_at, tenant_id, id", func(_ *testing.T, f *transferFixture) func() error { return dueExpirations(f) }},
		{"rejected keyed", faultQuery, "t.status = 'rejected'", func(_ *testing.T, f *transferFixture) func() error { return rejectedKeyed(f) }},
		{"abandoned", faultQuery, "status = 'uploading' AND created_at <=", func(_ *testing.T, f *transferFixture) func() error { return abandoned(f) }},
		{"expire count keys", faultQuery, "dek_key_id IS NOT NULL", func(_ *testing.T, f *transferFixture) func() error { return expire(f) }},
		{"expire", faultExec, "SET status = 'expired'", func(_ *testing.T, f *transferFixture) func() error { return expireUnkeyed(f) }},
		{"expire rows", faultRows, "SET status = 'expired'", func(_ *testing.T, f *transferFixture) func() error { return expireUnkeyed(f) }},
		{"expire probe", faultQuery, "download_count FROM transfers WHERE tenant_id = ? AND id = ?", func(_ *testing.T, f *transferFixture) func() error {
			return expireDeleted(f)
		}},
		{"list ended", faultQuery, "ORDER BY ended_at, id LIMIT", func(_ *testing.T, f *transferFixture) func() error { return listEnded(f) }},
		{"ids by status", faultQuery, "AND status = ? ORDER BY id LIMIT", func(_ *testing.T, f *transferFixture) func() error { return byStatus(f) }},
		{"storage refs", faultQuery, "FROM transfer_files WHERE tenant_id = ? LIMIT", func(_ *testing.T, f *transferFixture) func() error { return refs(f) }},
		{"storage refs scan", faultScanNil, "FROM transfer_files WHERE tenant_id = ? LIMIT", func(_ *testing.T, f *transferFixture) func() error { return refs(f) }},
		{"transfer statuses", faultQuery, "SELECT id, status FROM transfers", func(_ *testing.T, f *transferFixture) func() error { return refs(f) }},
		{"transfer statuses scan", faultScanNil, "SELECT id, status FROM transfers", func(_ *testing.T, f *transferFixture) func() error { return refs(f) }},
		{"purge list", faultQuery, "AND (consumed_at IS NOT NULL OR expires_at <= ?) AND created_at < ? AND id > ?", challenges},
		{"purge delete", faultExec, "WHERE tenant_id = ? AND id = ? AND (consumed_at", challenges},
		{"purge rows", faultRows, "WHERE tenant_id = ? AND id = ? AND (consumed_at", challenges},
		{"verified list", faultQuery, "SELECT email, last_used_at FROM verified_addresses", verified},
		{"verified scan", faultScanNil, "SELECT email, last_used_at FROM verified_addresses", verified},
		{"verified delete", faultExec, "AND email = ? AND last_used_at = ?", verified},
		{"verified rows", faultRows, "AND email = ? AND last_used_at = ?", verified},
		{"invitations list", faultQuery, "AND (revoked_at IS NOT NULL OR expires_at <= ?) AND created_at < ? AND id > ?", invitations},
		{"invitation references", faultQuery, "AND invitation_id = ?", invitations},
		{"invitations delete", faultExec, "WHERE tenant_id = ? AND id = ? AND (revoked_at", invitations},
		{"invitations rows", faultRows, "WHERE tenant_id = ? AND id = ? AND (revoked_at", invitations},
		{"tenant ids", faultQuery, "SELECT id FROM tenants ORDER BY id", func(_ *testing.T, f *transferFixture) func() error { return tenantIDs(f) }},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			f := newTransferFixture(t)
			run := s.run(t, f)
			f.plan.add(s.op, s.match, 0)
			if err := run(); err == nil {
				t.Fatalf("%s: no error with an injected %s fault", s.name, s.op)
			}
		})
	}
}

// TestPurgeBatches lowers the batch size so that every purge needs several
// transactions, and checks that the cursor resumes after each batch.
func TestPurgeBatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTransferFixture(t)
	for range 3 {
		seedPurgeable(t, f)
	}
	f.db.purgeBatch = 2
	future := time.Now().Add(cleanupFuture)
	for name, fn := range map[string]func() (int64, error){
		"challenges":  func() (int64, error) { return f.db.Challenges().Purge(ctx, f.tid, future) },
		"sessions":    func() (int64, error) { return f.db.DepositSessions().Purge(ctx, f.tid, future) },
		"invitations": func() (int64, error) { return f.db.Invitations().Purge(ctx, f.tid, future) },
	} {
		if n, err := fn(); err != nil || n != 3 {
			t.Errorf("%s: Purge = %d, %v; want 3", name, n, err)
		}
	}
	// One verified address and one failure key: seed others.
	err := f.tx(ctx, func(tx *ScopedTx) error {
		for _, m := range []string{"b@a.example.com", "c@a.example.com"} {
			if _, err := f.db.VerifiedAddresses().UpsertTx(ctx, tx, VerifiedAddress{Email: m, FirstVerifiedIP: netip.MustParseAddr("192.0.2.9")}); err != nil {
				return err
			}
		}
		for _, k := range []FailureKey{IPFailureKey(netip.MustParseAddr("192.0.2.2")), IPFailureKey(netip.MustParseAddr("192.0.2.3"))} {
			if _, err := f.db.PasswordFailures().RecordFailureTx(ctx, tx, []FailureKey{k}, time.Now()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := f.db.VerifiedAddresses().Purge(ctx, f.tid, future); err != nil || n != 3 {
		t.Errorf("verified: Purge = %d, %v; want 3", n, err)
	}
	if n, err := f.db.PasswordFailures().Purge(ctx, f.tid, future); err != nil || n != 3 {
		t.Errorf("failures: Purge = %d, %v; want 3", n, err)
	}
}

// TestPurgeLockFailure checks that a failing tenant lock (PostgreSQL only)
// aborts a purge.
func TestPurgeLockFailure(t *testing.T) {
	t.Parallel()
	f := newTransferFixture(t)
	d := *f.db.dialect
	d.lockTenant = "SELECT bogus("
	f.db.dialect = &d
	n, err := f.db.PasswordFailures().Purge(context.Background(), f.tid, time.Now())
	if n != 0 || err == nil || !strings.Contains(err.Error(), "lock tenant") {
		t.Errorf("Purge with a failing lock = %d, %v", n, err)
	}
}

// TestReconcileLimits lowers MaxReconcileRows to reach ErrTooManyRows.
func TestReconcileLimits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTransferFixture(t)
	f.db.reconcileRows = 0
	if _, err := f.db.Transfers().IDsByStatus(ctx, f.tid, TransferUploading); !errors.Is(err, ErrTooManyRows) {
		t.Errorf("IDsByStatus above the limit = %v", err)
	}
	if _, err := f.db.TransferFiles().StorageRefs(ctx, f.tid); !errors.Is(err, ErrTooManyRows) {
		t.Errorf("StorageRefs with too many files = %v", err)
	}
	// One file, two transfers (the fixture's lost its only file).
	if err := f.db.WrappedKeys().Delete(ctx, f.tid, f.file.DEKKeyID); err != nil {
		t.Fatal(err)
	}
	if err := f.tx(ctx, func(tx *ScopedTx) error { return f.db.TransferFiles().DeleteTx(ctx, tx, f.file.ID) }); err != nil {
		t.Fatal(err)
	}
	trf := Transfer{ID: id.New(id.Transfer), SenderEmail: fixtureEmail, SenderKind: DepositorInternal, ExpiryDays: 1}
	if err := f.create(ctx, trf, f.newFile(ctx, t)); err != nil {
		t.Fatal(err)
	}
	f.db.reconcileRows = 1
	if _, err := f.db.TransferFiles().StorageRefs(ctx, f.tid); !errors.Is(err, ErrTooManyRows) {
		t.Errorf("StorageRefs with too many transfers = %v", err)
	}
	f.db.reconcileRows = 2
	if refs, err := f.db.TransferFiles().StorageRefs(ctx, f.tid); err != nil || len(refs) != 1 {
		t.Errorf("StorageRefs at the limit = %+v, %v", refs, err)
	}
}

// migrationsUpTo returns the embedded migrations of both engines up to
// version last.
func migrationsUpTo(t *testing.T, last int) fs.FS {
	t.Helper()
	out := fstest.MapFS{}
	for _, dir := range []string{"migrations/sqlite", "migrations/postgres"} {
		ms, err := loadMigrations(migrationFiles, dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms[:last] {
			name := path.Join(dir, fmt.Sprintf("%04d_%s.sql", m.version, m.name))
			out[name] = &fstest.MapFile{Data: []byte(m.body)}
		}
	}
	return out
}

// TestMigration0007Upgrade applies 0007_cleanup on a database at 0006
// holding transfers in every status of interest: the terminal ones get the
// migration time as ended_at, the others none.
func TestMigration0007Upgrade(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		db.migrationsFS = migrationsUpTo(t, 6)
		if n, err := db.Migrate(ctx); err != nil || n != 6 {
			t.Fatalf("Migrate to 0006 = %d, %v", n, err)
		}
		tn := &tenant.Tenant{ID: createLegacyTenant(ctx, t, db, "a.example.com", 1)} // schema before 0009
		ids := map[TransferStatus]string{}
		err := db.runTx(ctx, db.write, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
			for _, st := range []TransferStatus{TransferRejected, TransferExpired, TransferDeleted, TransferUploading} {
				ids[st] = id.New(id.Transfer)
				fin := "1, 2"
				if st == TransferUploading {
					fin = "NULL, NULL"
				}
				q := `INSERT INTO transfers (id, tenant_id, status, sender_email, sender_kind, expiry_days,
					delete_after_first_download, total_bytes, created_at, finalized_at, expires_at)
					VALUES ('` + ids[st] + `', '` + string(tn.ID) + `', '` + string(st) + `', 'a@a.example.com', 'internal', 1,
					false, 0, 1, ` + fin + `)`
				if _, err := tx.ExecContext(ctx, q); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("insert transfers at 0006: %v", err)
		}

		db.migrationsFS = migrationFiles
		before := time.Now().Add(-time.Minute) // tolerance for the server clock
		if n, err := db.Migrate(ctx); err != nil || n != len(mustMigrations(t, db))-6 {
			t.Fatalf("Migrate to the latest = %d, %v", n, err)
		}
		after := time.Now().Add(time.Minute)
		for st, trfID := range ids {
			got, err := db.Transfers().Get(ctx, tn.ID, trfID)
			if err != nil {
				t.Fatalf("Get(%s): %v", st, err)
			}
			switch {
			case st == TransferUploading && !got.EndedAt.IsZero():
				t.Errorf("uploading transfer got an end: %v", got.EndedAt)
			case st != TransferUploading && (got.EndedAt.Before(before) || got.EndedAt.After(after)):
				t.Errorf("%s transfer ended at %v, want the migration time (%v to %v)", st, got.EndedAt, before, after)
			}
		}
		// The check refuses an end on a transfer that is not terminal.
		err = db.runTx(ctx, db.write, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE transfers SET ended_at = 1 WHERE id = '`+ids[TransferUploading]+`'`)
			return err
		})
		if err == nil {
			t.Error("an uploading transfer accepted an end")
		}
	})
}

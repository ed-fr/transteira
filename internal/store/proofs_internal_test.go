package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// proofTestNow is the clock of the proof tests.
var proofTestNow = time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)

// newTestProofKey stores an active proof key in db and returns it.
func newTestProofKey(ctx context.Context, t *testing.T, db *DB, b byte) ProofKey {
	t.Helper()
	k := ProofKey{ID: id.New(id.ProofKey), PublicKey: bytes.Repeat([]byte{b}, ProofPublicKeySize)}
	s := SystemSecret{ID: id.New(id.SystemSecret), Purpose: SecretPurposeProofSigning, KeyID: testMK1, Blob: []byte{b}}
	if err := db.systemScope("test").Tx(ctx, func(tx *SystemTx) error { return db.ProofKeys().CreateTx(ctx, tx, k, s) }); err != nil {
		t.Fatalf("create proof key: %v", err)
	}
	k.PrivateKeySecretID = s.ID
	return k
}

// newTestProof returns a valid proof of trfID signed by keyID, expiring at
// expires.
func newTestProof(trfID, keyID string, statement string, expires time.Time) TransferProof {
	return TransferProof{
		TransferID: trfID, Kind: ProofDeposit, Statement: []byte(statement),
		Signature: bytes.Repeat([]byte{7}, ProofSignatureSize), KeyID: keyID,
		CreatedAt: proofTestNow.Add(-24 * time.Hour), ExpiresAt: expires,
	}
}

// insertTestProof stores p in tenant tid.
func insertTestProof(ctx context.Context, t *testing.T, db *DB, tid tenant.ID, p TransferProof) {
	t.Helper()
	if err := writeScoped(ctx, db, tid, "test", func(tx *ScopedTx) error { return db.TransferProofs().InsertTx(ctx, tx, p) }); err != nil {
		t.Fatalf("insert proof: %v", err)
	}
}

// TestTransferProofsImmutable checks, on both engines, that the database
// refuses any update of a proof in the tenant scope and in the system
// scope, and that the proof is unchanged afterwards.
func TestTransferProofsImmutable(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e, WithClock(func() time.Time { return proofTestNow }))
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		tid := newTestTenant(ctx, t, db, "a.example.com")
		key := newTestProofKey(ctx, t, db, 1)
		trf := id.New(id.Transfer)
		p := newTestProof(trf, key.ID, `{"a":1}`, proofTestNow.AddDate(1, 0, 0))
		insertTestProof(ctx, t, db, tid, p)

		immutable := func(name string, err error) {
			t.Helper()
			if err == nil {
				t.Errorf("%s: update accepted", name)
				return
			}
			var pe *pgconn.PgError
			trigger := strings.Contains(err.Error(), "proofs are immutable") || errors.As(err, &pe) && pe.Code == "TTP01"
			if !trigger {
				t.Errorf("%s: %v, want the immutability trigger", name, err)
			}
		}
		updates := []string{
			`UPDATE transfer_proofs SET expires_at = expires_at + 1`,
			`UPDATE transfer_proofs SET statement = '{"a":2}' WHERE transfer_id = '` + trf + `'`,
			`UPDATE transfer_proofs SET key_id = key_id`,
		}
		s, err := db.Scoped(tid)
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range updates {
			immutable("tenant scope "+u, s.Tx(ctx, func(tx *ScopedTx) error {
				_, err := tx.tx.ExecContext(ctx, u)
				return err
			}))
			immutable("system scope "+u, db.systemScope("test").Tx(ctx, func(tx *SystemTx) error {
				_, err := tx.tx.ExecContext(ctx, u)
				return err
			}))
		}
		got, err := db.TransferProofs().Get(ctx, tid, trf, ProofDeposit, "")
		if err != nil || string(got.Statement) != `{"a":1}` || !got.ExpiresAt.Equal(p.ExpiresAt) || got.KeyID != key.ID {
			t.Errorf("proof after the refused updates = %+v, %v", got, err)
		}
	})
}

// TestTransferProofsPurgeBatches checks that the purge goes through
// several full batches.
func TestTransferProofsPurgeBatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := openFault(t, WithClock(func() time.Time { return proofTestNow }))
	db.purgeBatch = 2
	tid := newTestTenant(ctx, t, db, "a.example.com")
	key := newTestProofKey(ctx, t, db, 1)
	for i := range 5 {
		insertTestProof(ctx, t, db, tid, newTestProof(id.New(id.Transfer), key.ID, "{}", proofTestNow.Add(-time.Duration(i+1)*time.Minute)))
	}
	keep := id.New(id.Transfer)
	insertTestProof(ctx, t, db, tid, newTestProof(keep, key.ID, "{}", proofTestNow.Add(time.Minute)))
	if n, err := db.TransferProofs().Purge(ctx, tid, proofTestNow); err != nil || n != 5 {
		t.Errorf("Purge = %d, %v, want 5", n, err)
	}
	if _, err := db.TransferProofs().Get(ctx, tid, keep, ProofDeposit, ""); err != nil {
		t.Errorf("unexpired proof = %v", err)
	}
}

// TestProofsDriverFaults injects a driver failure into each statement of
// the proof repositories and checks that it surfaces as an error.
func TestProofsDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t, WithClock(func() time.Time { return proofTestNow }))
	tid := newTestTenant(ctx, t, db, "a.example.com")
	key := newTestProofKey(ctx, t, db, 1)
	const addr = "jo@example.org"
	insertTestProof(ctx, t, db, tid, newTestProof(id.New(id.Transfer), key.ID, `{"senderEmail":"`+addr+`"}`, proofTestNow.Add(-time.Minute)))
	// A per-recipient delivery proof, read by the recipient lookups.
	trfD := id.New(id.Transfer)
	delivery := newTestProof(trfD, key.ID, `{"recipientDownloads":[{"email":"`+addr+`"}]}`, proofTestNow.Add(time.Hour))
	delivery.Kind, delivery.RecipientLinkID = ProofDelivery, id.New(id.RecipientLink)
	insertTestProof(ctx, t, db, tid, delivery)
	keys, proofs := db.ProofKeys(), db.TransferProofs()
	sys := func(fn func(tx *SystemTx) error) error { return db.systemScope("test").Tx(ctx, fn) }
	scoped := func(fn func(tx *ScopedTx) error) error { return writeScoped(ctx, db, tid, "test", fn) }
	// rotate retires the active key then creates another one in one
	// transaction (rolled back by the injected fault).
	rotate := func() error {
		return sys(func(tx *SystemTx) error {
			if _, err := keys.RetireActiveTx(ctx, tx, proofTestNow); err != nil {
				return err
			}
			return keys.CreateTx(ctx, tx, ProofKey{ID: id.New(id.ProofKey), PublicKey: bytes.Repeat([]byte{2}, 32)},
				SystemSecret{ID: id.New(id.SystemSecret), Purpose: SecretPurposeProofSigning, KeyID: testMK1, Blob: []byte{2}})
		})
	}
	erase := func() error {
		return scoped(func(tx *ScopedTx) error { _, err := proofs.DeleteByAddressTx(ctx, tx, addr); return err })
	}
	for _, c := range []struct {
		name, op, match string
		after           int
		run             func() error
	}{
		{"active", faultQuery, "WHERE retired_at IS NULL", 0, func() error { _, err := keys.Active(ctx); return err }},
		{"active tx", faultQuery, "WHERE retired_at IS NULL", 0, func() error {
			return sys(func(tx *SystemTx) error { _, err := keys.ActiveTx(ctx, tx); return err })
		}},
		{"get key", faultQuery, "FROM proof_signing_keys WHERE id", 0, func() error { _, err := keys.Get(ctx, key.ID); return err }},
		{"list keys", faultQuery, "ORDER BY created_at DESC", 0, func() error { _, err := keys.List(ctx); return err }},
		{"list keys scan", faultScanNil, "ORDER BY created_at DESC", 0, func() error { _, err := keys.List(ctx); return err }},
		{"retire read", faultQuery, "WHERE retired_at IS NULL", 0, rotate},
		{"retire update", faultExec, "UPDATE proof_signing_keys", 0, rotate},
		{"retire count", faultRows, "UPDATE proof_signing_keys", 0, rotate},
		{"retire erase", faultExec, "DELETE FROM system_secrets", 0, rotate},
		{"create check", faultQuery, "WHERE retired_at IS NULL", 1, rotate},
		{"create secret", faultExec, "INSERT INTO system_secrets", 0, rotate},
		{"create key", faultExec, "INSERT INTO proof_signing_keys", 0, rotate},
		{"insert proof", faultExec, "INSERT INTO transfer_proofs", 0, func() error {
			return scoped(func(tx *ScopedTx) error {
				return proofs.InsertTx(ctx, tx, newTestProof(id.New(id.Transfer), key.ID, "{}", proofTestNow.Add(time.Hour)))
			})
		}},
		{"get proof", faultQuery, "FROM transfer_proofs", 0, func() error {
			_, err := proofs.Get(ctx, tid, id.New(id.Transfer), ProofDeposit, "")
			return err
		}},
		{"get proof tx", faultQuery, "FROM transfer_proofs", 0, func() error {
			return scoped(func(tx *ScopedTx) error {
				_, err := proofs.GetTx(ctx, tx, id.New(id.Transfer), ProofDelivery, id.New(id.RecipientLink))
				return err
			})
		}},
		{"purge list", faultQuery, "SELECT id FROM transfer_proofs", 0, func() error { _, err := proofs.Purge(ctx, tid, proofTestNow); return err }},
		{"purge delete", faultExec, "DELETE FROM transfer_proofs", 0, func() error { _, err := proofs.Purge(ctx, tid, proofTestNow); return err }},
		{"erase list", faultQuery, "SELECT id, statement FROM transfer_proofs", 0, erase},
		{"erase scan", faultScanNil, "SELECT id, statement FROM transfer_proofs", 0, erase},
		{"recipient delivery list", faultQuery, "kind = 'delivery'", 0, func() error {
			_, err := proofs.GetRecipientDelivery(ctx, tid, trfD, addr)
			return err
		}},
		{"recipient delivery scan", faultScanNil, "kind = 'delivery'", 0, func() error {
			_, err := proofs.GetRecipientDelivery(ctx, tid, trfD, addr)
			return err
		}},
		{"count list", faultQuery, "SELECT id, statement FROM transfer_proofs", 0, func() error { _, err := proofs.CountByAddress(ctx, tid, addr); return err }},
		{"count scan", faultScanNil, "SELECT id, statement FROM transfer_proofs", 0, func() error { _, err := proofs.CountByAddress(ctx, tid, addr); return err }},
		{"erase delete", faultExec, "DELETE FROM transfer_proofs", 0, erase},
	} {
		plan.reset()
		plan.add(c.op, c.match, c.after)
		if err := c.run(); err == nil || errors.Is(err, ErrInvalid) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
			t.Errorf("%s: %v, want the injected fault", c.name, err)
		}
	}
	plan.reset()

	// The identifier generator fails: nothing is inserted.
	gen := db.newID
	db.newID = func(id.Prefix) (string, error) { return "", errInjected }
	err := scoped(func(tx *ScopedTx) error {
		return proofs.InsertTx(ctx, tx, newTestProof(id.New(id.Transfer), key.ID, "{}", proofTestNow.Add(time.Hour)))
	})
	if !errors.Is(err, errInjected) {
		t.Errorf("InsertTx with a failing generator = %v", err)
	}
	db.newID = gen

	// Without faults, the rotation and the erasure succeed.
	if err := rotate(); err != nil {
		t.Errorf("rotate = %v", err)
	}
	if err := erase(); err != nil {
		t.Errorf("erase = %v", err)
	}
}

func TestProofNeedle(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"jo.doe+x_y-z@example.org": "jo.doe+x_y-z@example.org",
		"a&b@example.org":          "@example.org",
		"a/b@example.org":          "@example.org",
		"é@example.org":            "@example.org",
		`a"b@example.org`:          "@example.org",
	} {
		if got := proofNeedle(in); got != want {
			t.Errorf("proofNeedle(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStatementNames(t *testing.T) {
	t.Parallel()
	const email = "jo@example.org"
	for st, want := range map[string]bool{
		`not json`:                         false,
		`[]`:                               false,
		`{}`:                               false,
		`{"senderEmail":"JO@example.org"}`: true,
		`{"senderEmail":"x@example.org","recipients":["jo@example.org"]}`:                   true,
		`{"recipients":[1,"jo@example.org"]}`:                                               false,
		`{"recipients":"jo@example.org","recipientDownloads":[{"email":"jo@example.org"}]}`: true,
		`{"recipientDownloads":{"email":"jo@example.org"}}`:                                 false,
		`{"files":[{"name":"jo@example.org"}]}`:                                             false,
		`{"senderEmail":"bjo@example.org","recipients":["jo@example.org.example"]}`:         false,
	} {
		if got := statementNames(st, email); got != want {
			t.Errorf("statementNames(%s) = %v, want %v", st, got, want)
		}
	}
	// A statement value that does not normalize is compared lower-cased.
	if !sameAddress(" Not An Address ", "not an address") || sameAddress("x", "y") {
		t.Error("sameAddress fallback")
	}
}

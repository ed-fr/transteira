package masterkey_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestRotateProofSigningKey checks, on both engines, that the private key
// of a proof signing key is a system secret of purpose proof-signing
// (threat T-299): it can be sealed, the master key rotation rewraps it
// under the new key, it opens with the new key alone, and retiring the
// proof key destroys it.
func TestRotateProofSigningKey(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		k1, k2 := newKey(t), newKey(t)
		if _, err := masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow); err != nil {
			t.Fatalf("Check: %v", err)
		}
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		row, err := vault(db, keyring(t, k1, nil)).WrapSystem(crypto.PurposeProofSigning, priv.Seed())
		if err != nil || row.Purpose != store.SecretPurposeProofSigning {
			t.Fatalf("WrapSystem = %+v, %v", row, err)
		}
		pk := store.ProofKey{ID: id.New(id.ProofKey), PublicKey: pub}
		sys, err := db.System("tests: proof signing key")
		if err != nil {
			t.Fatal(err)
		}
		if err := sys.Tx(ctx, func(tx *store.SystemTx) error { return db.ProofKeys().CreateTx(ctx, tx, pk, row) }); err != nil {
			t.Fatalf("CreateTx: %v", err)
		}

		rot, err := masterkey.Rotate(ctx, db, keyring(t, k1, k2), nil, masterkey.Options{BatchSize: 10})
		if err != nil || rot.Status != store.RotationCompleted || rot.RewrappedKeys != 1 {
			t.Fatalf("Rotate = %+v, %v", rot, err)
		}
		s := sealedSystem{id: row.ID, purpose: crypto.PurposeProofSigning, secret: priv.Seed()}
		if got := secretKeyIDOf(t, db, s); got != k2.ID() {
			t.Errorf("proof private key under %s after the rotation, want %s", got, k2.ID())
		}
		expectSystemOpens(t, vault(db, keyring(t, k2, nil)), []sealedSystem{s})
		seed, err := vault(db, keyring(t, k2, nil)).OpenSystem(ctx, crypto.PurposeProofSigning, row.ID)
		if err != nil || !bytes.Equal(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), pub) {
			t.Errorf("reopened private key does not match the public key: %v", err)
		}
		// The proof purpose never opens as another system purpose.
		if _, err := vault(db, keyring(t, k2, nil)).OpenSystem(ctx, crypto.PurposeWebhook, row.ID); !errors.Is(err, masterkey.ErrPurposeMismatch) {
			t.Errorf("OpenSystem(webhook) = %v", err)
		}

		// Retirement destroys the private key.
		if err := sys.Tx(ctx, func(tx *store.SystemTx) error { _, err := db.ProofKeys().RetireActiveTx(ctx, tx, testNow); return err }); err != nil {
			t.Fatalf("RetireActiveTx: %v", err)
		}
		if _, err := vault(db, keyring(t, k2, nil)).OpenSystem(ctx, crypto.PurposeProofSigning, row.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OpenSystem after retirement = %v", err)
		}
	})
}

package masterkey_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestVaultSealOpenDestroy(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		k1 := newKey(t)
		v := vault(db, keyring(t, k1, nil))

		dek := seal(t, v, a, crypto.PurposeDEK)
		secret := seal(t, v, a, crypto.PurposeSecret)
		if !id.Valid(id.WrappedKey, dek.id) || keyIDOf(t, db, dek) != k1.ID() {
			t.Errorf("sealed row %s under %s", dek.id, keyIDOf(t, db, dek))
		}
		expectOpens(t, v, []sealed{dek, secret})

		// Isolation and purpose.
		if _, err := v.Open(ctx, b, crypto.PurposeDEK, dek.id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Open from another tenant = %v", err)
		}
		if err := v.Destroy(ctx, b, dek.id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Destroy from another tenant = %v", err)
		}
		if _, err := v.Open(ctx, a, crypto.PurposeSecret, dek.id); !errors.Is(err, masterkey.ErrPurposeMismatch) {
			t.Errorf("Open(wrong purpose) = %v", err)
		}

		// A blob copied to another row does not unwrap.
		row, err := db.WrappedKeys().Get(ctx, a, dek.id)
		if err != nil {
			t.Fatal(err)
		}
		row.ID = id.New(id.WrappedKey)
		if err := db.WrappedKeys().Create(ctx, a, row); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Open(ctx, a, crypto.PurposeDEK, row.ID); !errors.Is(err, crypto.ErrUnwrap) {
			t.Errorf("Open(copied blob) = %v", err)
		}

		// Crypto-erase.
		if err := v.Destroy(ctx, a, dek.id); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if _, err := v.Open(ctx, a, crypto.PurposeDEK, dek.id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Open after Destroy = %v", err)
		}
		if err := v.Destroy(ctx, a, dek.id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second Destroy = %v", err)
		}

		// NewDEK.
		wkID, key, err := v.NewDEK(ctx, b)
		if err != nil || len(key) != crypto.DEKSize {
			t.Fatalf("NewDEK: %d bytes, %v", len(key), err)
		}
		if got, err := v.Open(ctx, b, crypto.PurposeDEK, wkID); err != nil || !bytes.Equal(got, key) {
			t.Errorf("Open(NewDEK) failed or differs: %v", err)
		}
		if _, _, err := v.NewDEK(ctx, tenant.ID("")); !errors.Is(err, crypto.ErrInvalidBinding) {
			t.Errorf("NewDEK(no tenant) = %v", err)
		}

		// Seal errors.
		if _, err := v.Seal(ctx, a, crypto.Purpose("bogus"), []byte("x")); !errors.Is(err, crypto.ErrUnknownPurpose) {
			t.Errorf("Seal(bogus purpose) = %v", err)
		}
		if _, err := v.Seal(ctx, tenant.ID(id.New(id.Tenant)), crypto.PurposeDEK, []byte("x")); err == nil {
			t.Error("Seal for a missing tenant succeeded")
		}
	})
}

func TestVaultKeysDuringRotation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		k1, k2 := newKey(t), newKey(t)
		old := vault(db, keyring(t, k1, nil))
		both := vault(db, keyring(t, k1, k2))
		onlyNew := vault(db, keyring(t, k2, nil))

		underOld := seal(t, old, a, crypto.PurposeSecret)
		underNew := seal(t, both, a, crypto.PurposeDEK)
		if keyIDOf(t, db, underNew) != k2.ID() {
			t.Fatal("the keyring with a new key must wrap with it")
		}
		expectOpens(t, both, []sealed{underOld, underNew})
		expectOpens(t, onlyNew, []sealed{underNew})

		_, err := old.Open(ctx, a, crypto.PurposeDEK, underNew.id)
		if !errors.Is(err, masterkey.ErrUnknownKey) || !strings.Contains(err.Error(), k2.ID()) ||
			!strings.Contains(err.Error(), underNew.id) || !strings.Contains(err.Error(), masterkey.DocLink) {
			t.Errorf("Open(row under an unknown key) = %v", err)
		}
		if _, err := onlyNew.Open(ctx, a, crypto.PurposeSecret, underOld.id); !errors.Is(err, masterkey.ErrUnknownKey) {
			t.Errorf("Open(row under the old key) = %v", err)
		}
	})
}

func TestVaultInTransactions(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		v := vault(db, keyring(t, newKey(t), nil))
		scoped, err := db.Scoped(a)
		if err != nil {
			t.Fatal(err)
		}

		// A rolled-back transaction leaves nothing.
		var rolledBack string
		boom := errors.New("abort")
		err = scoped.Tx(ctx, func(tx *store.ScopedTx) error {
			rolledBack, err = v.SealTx(ctx, tx, crypto.PurposeDEK, []byte("rolled back"))
			if err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("Tx = %v", err)
		}
		if _, err := v.Open(ctx, a, crypto.PurposeDEK, rolledBack); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Open(rolled back) = %v", err)
		}

		// Committed seal, then destroy in a transaction and scrub.
		var wkID string
		if err := scoped.Tx(ctx, func(tx *store.ScopedTx) error {
			wkID, err = v.SealTx(ctx, tx, crypto.PurposeSecret, []byte("committed"))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if got, err := v.Open(ctx, a, crypto.PurposeSecret, wkID); err != nil || string(got) != "committed" {
			t.Fatalf("Open(committed) = %q, %v", got, err)
		}
		if err := scoped.Tx(ctx, func(tx *store.ScopedTx) error { return v.DestroyTx(ctx, tx, wkID) }); err != nil {
			t.Fatalf("DestroyTx: %v", err)
		}
		if err := v.Scrub(ctx); err != nil {
			t.Errorf("Scrub: %v", err)
		}
		if _, err := v.Open(ctx, a, crypto.PurposeSecret, wkID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Open after DestroyTx = %v", err)
		}

		// Errors inside the transaction.
		err = scoped.Tx(ctx, func(tx *store.ScopedTx) error {
			if err := v.DestroyTx(ctx, tx, wkID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("DestroyTx(missing) = %v", err)
			}
			if _, err := v.SealTx(ctx, tx, crypto.Purpose("bogus"), []byte("x")); !errors.Is(err, crypto.ErrUnknownPurpose) {
				t.Errorf("SealTx(bogus purpose) = %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		err = scoped.Tx(ctx, func(tx *store.ScopedTx) error {
			// A blob larger than the store accepts.
			_, err := v.SealTx(ctx, tx, crypto.PurposeDEK, make([]byte, store.MaxWrappedKeyBytes))
			return err
		})
		if !errors.Is(err, store.ErrInvalid) {
			t.Errorf("SealTx(oversized) = %v", err)
		}
	})
}

func TestVaultRefusesRetiredKey(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		k1, k2 := newKey(t), newKey(t)
		if _, err := masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow); err != nil {
			t.Fatal(err)
		}
		seal(t, vault(db, keyring(t, k1, nil)), a, crypto.PurposeDEK)
		if _, err := masterkey.Rotate(ctx, db, keyring(t, k1, k2), nil, masterkey.Options{}); err != nil {
			t.Fatal(err)
		}
		// A process still running with the retired key cannot wrap with it.
		_, err := vault(db, keyring(t, k1, nil)).Seal(ctx, a, crypto.PurposeDEK, []byte("late"))
		if !errors.Is(err, store.ErrKeyRetired) || !strings.Contains(err.Error(), k1.ID()) || !strings.Contains(err.Error(), "retired") {
			t.Errorf("Seal under a retired key = %v", err)
		}
		scoped, _ := db.Scoped(a)
		err = scoped.Tx(ctx, func(tx *store.ScopedTx) error {
			_, err := vault(db, keyring(t, k1, nil)).SealTx(ctx, tx, crypto.PurposeDEK, []byte("late"))
			return err
		})
		if !errors.Is(err, store.ErrKeyRetired) {
			t.Errorf("SealTx under a retired key = %v", err)
		}
	})
}

// TestPurposesAndKeyIDsAgree checks the contract between crypto and store:
// every purpose of one is accepted by the other, and the ID of a generated
// master key is a valid store key ID.
func TestPurposesAndKeyIDsAgree(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		k1, k2 := newKey(t), newKey(t)
		v := vault(db, keyring(t, k1, nil))
		for _, p := range []crypto.Purpose{crypto.PurposeDEK, crypto.PurposeSecret} {
			k := seal(t, v, a, p)
			expectOpens(t, v, []sealed{k})
		}
		for _, p := range []string{store.KeyPurposeDEK, store.KeyPurposeSecret} {
			if _, err := k1.Wrap(crypto.Purpose(p), string(a), id.New(id.WrappedKey), []byte("x")); err != nil {
				t.Errorf("crypto refuses store purpose %q: %v", p, err)
			}
		}
		if registered, err := db.MasterKeys().EnsureActive(ctx, k1.ID(), testNow); err != nil || !registered {
			t.Errorf("EnsureActive(generated key ID) = %v, %v", registered, err)
		}
		rot := store.Rotation{ID: id.New(id.Rotation), FromKeyID: k1.ID(), ToKeyID: k2.ID()}
		if err := db.KeyRotations().Start(ctx, rot); err != nil {
			t.Errorf("Start(generated key IDs) = %v", err)
		}
	})
}

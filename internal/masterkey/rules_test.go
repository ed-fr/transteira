package masterkey_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestVaultNewDEKTx(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		v := vault(db, keyring(t, newKey(t), nil))
		scoped, err := db.Scoped(a)
		if err != nil {
			t.Fatal(err)
		}
		var wkID string
		var dek []byte
		if err := scoped.Tx(ctx, func(tx *store.ScopedTx) error {
			wkID, dek, err = v.NewDEKTx(ctx, tx)
			return err
		}); err != nil {
			t.Fatalf("NewDEKTx: %v", err)
		}
		if got, err := v.Open(ctx, a, crypto.PurposeDEK, wkID); err != nil || len(dek) != crypto.DEKSize || !bytes.Equal(got, dek) {
			t.Errorf("Open(NewDEKTx) failed or differs: %v", err)
		}

		// A rolled-back transaction leaves no key.
		boom := errors.New("abort")
		err = scoped.Tx(ctx, func(tx *store.ScopedTx) error {
			wkID, _, err = v.NewDEKTx(ctx, tx)
			if err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatal(err)
		}
		if _, err := v.Open(ctx, a, crypto.PurposeDEK, wkID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Open(rolled back NewDEKTx) = %v", err)
		}
	})
}

func TestVaultNewDEKTxRetiredKey(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		if _, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{}); err != nil {
			t.Fatal(err)
		}
		scoped, err := f.db.Scoped(f.tenants[0])
		if err != nil {
			t.Fatal(err)
		}
		err = scoped.Tx(ctx, func(tx *store.ScopedTx) error {
			_, _, err := vault(f.db, keyring(t, f.k1, nil)).NewDEKTx(ctx, tx)
			return err
		})
		if !errors.Is(err, store.ErrKeyRetired) {
			t.Errorf("NewDEKTx under a retired key = %v", err)
		}
	})
}

// TestCheckRefusesRetiredCurrentKey covers a retired current key whatever
// the latest rotation: A to B completed, B to C abandoned, then A current
// and B new.
func TestCheckRefusesRetiredCurrentKey(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		if _, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{}); err != nil {
			t.Fatal(err)
		}
		k3 := newKey(t)
		// Started after the completed rotation, so that it is the latest one.
		later := time.Now().Add(time.Minute)
		if _, err := masterkey.StartRotation(ctx, f.db, keyring(t, f.k2, k3), later); err != nil {
			t.Fatal(err)
		}
		if _, err := masterkey.Abandon(ctx, f.db, later); err != nil {
			t.Fatal(err)
		}
		_, err := masterkey.Check(ctx, f.db, keyring(t, f.k1, f.k2), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonRetiredKey, f.k1.ID())
		_, err = masterkey.Check(ctx, f.db, keyring(t, f.k1, nil), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonRetiredKey, f.k1.ID())
		if _, err := masterkey.Check(ctx, f.db, keyring(t, f.k2, nil), nil, testNow); err != nil {
			t.Errorf("Check(active key) = %v", err)
		}
	})
}

// TestAbandonInterruptedRecovery covers a clean-up rotation interrupted
// after its last batch, whose old key is then gone: it can be abandoned
// although the active key has rows, and a new rotation can start.
func TestAbandonInterruptedRecovery(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		if _, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{}); err != nil {
			t.Fatal(err)
		}
		f.keys = append(f.keys, plantStraggler(t, e, f.db, f.k1, f.tenants[1]))
		onlyK2 := keyring(t, f.k2, nil)
		rctx, cancel := context.WithCancel(ctx)
		last := int64(-1)
		rot, err := masterkey.Recover(rctx, f.db, onlyK2, f.k1, nil, masterkey.Options{
			OnProgress: func(r store.Rotation) {
				if r.RewrappedKeys == last { // the final empty batch: everything is re-wrapped
					cancel()
				}
				last = r.RewrappedKeys
			},
		})
		if !errors.Is(err, context.Canceled) || rot.Status != store.RotationRunning {
			t.Fatalf("Recover(canceled after the last batch) = %+v, %v", rot, err)
		}
		done, err := masterkey.Abandon(ctx, f.db, testNow)
		if err != nil || done.ID != rot.ID || done.Status != store.RotationFailed {
			t.Fatalf("Abandon(clean-up) = %+v, %v", done, err)
		}
		f.expectRotated(t)
		k3 := newKey(t)
		if _, err := masterkey.StartRotation(ctx, f.db, keyring(t, f.k2, k3), testNow); err != nil {
			t.Errorf("StartRotation after abandoning the clean-up = %v", err)
		}
	})
}

package masterkey_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestStartRotationThenRotate(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		if _, err := masterkey.StartRotation(ctx, f.db, keyring(t, f.k1, nil), testNow); !errors.Is(err, masterkey.ErrNoNewKey) {
			t.Errorf("StartRotation(no new key) = %v", err)
		}
		rot, err := masterkey.StartRotation(ctx, f.db, f.both(t), testNow)
		if err != nil || rot.Status != store.RotationRunning || rot.TotalKeys != f.underOld || rot.RewrappedKeys != 0 {
			t.Fatalf("StartRotation = %+v, %v", rot, err)
		}
		if _, err := masterkey.StartRotation(ctx, f.db, f.both(t), testNow); !errors.Is(err, store.ErrRotationRunning) {
			t.Errorf("second StartRotation = %v", err)
		}
		// Nothing was re-wrapped yet.
		if n, err := f.db.WrappedKeys().CountByKey(ctx, f.k1.ID()); err != nil || n != f.underOld {
			t.Errorf("keys under k1 = %d, %v", n, err)
		}
		done, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{})
		if err != nil || done.ID != rot.ID || done.Status != store.RotationCompleted {
			t.Fatalf("Rotate = %+v, %v", done, err)
		}
		f.expectRotated(t)
	})
}

func TestAbandon(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		if _, err := masterkey.Abandon(ctx, f.db, testNow); !errors.Is(err, masterkey.ErrNoRotation) {
			t.Errorf("Abandon(nothing running) = %v", err)
		}
		// The fixture holds keys under k2: a rotation to k2 cannot be
		// abandoned.
		rot, err := masterkey.StartRotation(ctx, f.db, f.both(t), testNow)
		if err != nil {
			t.Fatal(err)
		}
		_, err = masterkey.Abandon(ctx, f.db, testNow)
		if !errors.Is(err, masterkey.ErrCannotAbandon) || !strings.Contains(err.Error(), f.k2.ID()) || !strings.Contains(err.Error(), rot.ID) {
			t.Errorf("Abandon(keys under the target) = %v", err)
		}
		if err := f.db.KeyRotations().Fail(ctx, rot.ID, "test", testNow); err != nil {
			t.Fatal(err)
		}

		// A rotation to k3, under which nothing is wrapped: abandoned.
		k3 := newKey(t)
		rot, err = masterkey.StartRotation(ctx, f.db, keyring(t, f.k1, k3), testNow)
		if err != nil {
			t.Fatal(err)
		}
		done, err := masterkey.Abandon(ctx, f.db, testNow)
		if err != nil || done.ID != rot.ID || done.Status != store.RotationFailed {
			t.Fatalf("Abandon = %+v, %v", done, err)
		}
		stored, err := f.db.KeyRotations().Get(ctx, rot.ID)
		if err != nil || stored.Status != store.RotationFailed || !strings.Contains(stored.Error, "abandoned") {
			t.Errorf("stored = %+v, %v", stored, err)
		}
		// Another rotation can start, and k1 is still the active key.
		if _, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{}); err != nil {
			t.Fatalf("Rotate after abandon: %v", err)
		}
		f.expectRotated(t)
	})
}

func TestAbandonStoreFailures(t *testing.T) {
	t.Parallel()
	for name, fault := range map[string]string{
		"running": `DROP TABLE key_rotations`,
		"count":   `DROP TABLE wrapped_keys`,
		"fail":    `CREATE TRIGGER f BEFORE UPDATE ON key_rotations BEGIN SELECT RAISE(ABORT, 'fault'); END`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := storetest.SQLite(t)
			f := newFixture(t, e)
			if _, err := masterkey.StartRotation(context.Background(), f.db, keyring(t, f.k1, newKey(t)), testNow); err != nil {
				t.Fatal(err)
			}
			execRaw(t, rawSQLite(t, e), fault)
			if _, err := masterkey.Abandon(context.Background(), f.db, testNow); err == nil ||
				errors.Is(err, masterkey.ErrCannotAbandon) || errors.Is(err, masterkey.ErrNoRotation) {
				t.Errorf("Abandon = %v, want a store error", err)
			}
		})
	}
}

func TestRecover(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		if _, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{}); err != nil {
			t.Fatal(err)
		}
		f.keys = append(f.keys, plantStraggler(t, e, f.db, f.k1, f.tenants[2]), plantStraggler(t, e, f.db, f.k1, f.tenants[0]))
		onlyK2 := keyring(t, f.k2, nil)
		_, err := masterkey.Check(ctx, f.db, onlyK2, nil, testNow)
		expectCheckError(t, err, masterkey.ReasonMissingKey, f.k1.ID())

		// Refusals: a key that is not retired, a current key that is not
		// the active one.
		k3 := newKey(t)
		if _, err := masterkey.Recover(ctx, f.db, onlyK2, k3, nil, masterkey.Options{}); !errors.Is(err, masterkey.ErrRecoveryKey) {
			t.Errorf("Recover(unknown key) = %v", err)
		}
		if _, err := masterkey.Recover(ctx, f.db, onlyK2, f.k2, nil, masterkey.Options{}); !errors.Is(err, masterkey.ErrRecoveryKey) {
			t.Errorf("Recover(active key) = %v", err)
		}
		if _, err := masterkey.Recover(ctx, f.db, keyring(t, k3, nil), f.k1, nil, masterkey.Options{}); !errors.Is(err, masterkey.ErrRecoveryKey) ||
			!strings.Contains(err.Error(), f.k2.ID()) {
			t.Errorf("Recover(current key not active) = %v", err)
		}

		// Interrupted, then resumed.
		rctx, cancel := context.WithCancel(ctx)
		_, err = masterkey.Recover(rctx, f.db, onlyK2, f.k1, nil, masterkey.Options{
			BatchSize: 1, OnProgress: func(store.Rotation) { cancel() },
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Recover(canceled) = %v", err)
		}
		// A regular rotation cannot run meanwhile.
		if _, err := masterkey.Rotate(ctx, f.db, keyring(t, f.k2, k3), nil, masterkey.Options{}); !errors.Is(err, masterkey.ErrRotationMismatch) {
			t.Errorf("Rotate during the recovery = %v", err)
		}
		logs := &syncBuffer{}
		rot, err := masterkey.Recover(ctx, f.db, onlyK2, f.k1, slog.New(slog.NewTextHandler(logs, nil)), masterkey.Options{})
		if err != nil || rot.Status != store.RotationCompleted || rot.FromKeyID != f.k1.ID() || rot.ToKeyID != f.k2.ID() ||
			rot.RewrappedKeys != 2 {
			t.Fatalf("Recover = %+v, %v", rot, err)
		}
		if !strings.Contains(logs.String(), "resuming master key rotation") {
			t.Errorf("logs = %s", logs)
		}
		// Every key is under k2, k1 is still retired, and the server starts.
		f.expectRotated(t)
		if rep, err := masterkey.Check(ctx, f.db, onlyK2, nil, testNow); err != nil || rep.ActiveID != f.k2.ID() {
			t.Errorf("Check after the recovery = %+v, %v", rep, err)
		}
		// A recovery while a regular rotation runs is refused.
		if _, err := masterkey.StartRotation(ctx, f.db, keyring(t, f.k2, k3), testNow); err != nil {
			t.Fatal(err)
		}
		if _, err := masterkey.Recover(ctx, f.db, onlyK2, f.k1, nil, masterkey.Options{}); !errors.Is(err, masterkey.ErrRotationMismatch) {
			t.Errorf("Recover during a rotation = %v", err)
		}
	})
}

func TestRecoverStoreFailure(t *testing.T) {
	t.Parallel()
	e := storetest.SQLite(t)
	f := newFixture(t, e)
	execRaw(t, rawSQLite(t, e), `DROP TABLE master_keys`)
	if _, err := masterkey.Recover(context.Background(), f.db, keyring(t, f.k2, nil), f.k1, nil, masterkey.Options{}); err == nil ||
		errors.Is(err, masterkey.ErrRecoveryKey) {
		t.Errorf("Recover = %v, want a store error", err)
	}
}

func TestRotateFailureNotRecorded(t *testing.T) {
	t.Parallel()
	e := storetest.SQLite(t)
	f := newFixture(t, e)
	bad := store.WrappedKey{ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeDEK, KeyID: f.k1.ID(), Blob: []byte("corrupted")}
	if err := f.db.WrappedKeys().Create(context.Background(), f.tenants[0], bad); err != nil {
		t.Fatal(err)
	}
	execRaw(t, rawSQLite(t, e),
		`CREATE TRIGGER f BEFORE UPDATE ON key_rotations WHEN NEW.status = 'failed' BEGIN SELECT RAISE(ABORT, 'fault'); END`)
	rot, err := masterkey.Rotate(context.Background(), f.db, f.both(t), nil, masterkey.Options{})
	if !errors.Is(err, masterkey.ErrRewrap) || !strings.Contains(err.Error(), "fault") || rot.Status != store.RotationRunning {
		t.Errorf("Rotate = %+v, %v", rot, err)
	}
}

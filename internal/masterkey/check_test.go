package masterkey_test

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// expectCheckError asserts that err is a CheckError with reason and keyIDs,
// whose message names the keys and points to the documentation.
func expectCheckError(t *testing.T, err error, reason masterkey.CheckReason, keyIDs ...string) {
	t.Helper()
	ce, ok := errors.AsType[*masterkey.CheckError](err)
	if !ok || !errors.Is(err, masterkey.ErrKeyCheck) {
		t.Fatalf("Check = %v, want a CheckError %s", err, reason)
	}
	if ce.Reason != reason || !slices.Equal(ce.KeyIDs, keyIDs) {
		t.Errorf("CheckError = %s %v, want %s %v", ce.Reason, ce.KeyIDs, reason, keyIDs)
	}
	for _, s := range append(keyIDs, masterkey.DocLink) {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("message %q lacks %q", err.Error(), s)
		}
	}
}

func TestCheck(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		k1, k2, k3 := newKey(t), newKey(t), newKey(t)
		logs := &syncBuffer{}
		logger := slog.New(slog.NewTextHandler(logs, nil))

		// Fresh database: the current key is registered.
		rep, err := masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow)
		if err != nil || !rep.Registered || rep.ActiveID != k1.ID() || rep.CurrentID != k1.ID() || rep.NewID != "" || rep.Running != nil {
			t.Fatalf("Check(fresh) = %+v, %v", rep, err)
		}
		// Same key again: nothing to register.
		if rep, err := masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow); err != nil || rep.Registered {
			t.Fatalf("Check(again) = %+v, %v", rep, err)
		}
		// Another key, no wrapped key yet: the active key is missing.
		_, err = masterkey.Check(ctx, db, keyring(t, k2, nil), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonActiveKeyMissing, k1.ID())

		// Rows under k1: a wrong key is refused with the missing key ID.
		a := newTenant(t, db, "transfer.entity-a.example.com")
		seal(t, vault(db, keyring(t, k1, nil)), a, crypto.PurposeDEK)
		_, err = masterkey.Check(ctx, db, keyring(t, k2, nil), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonMissingKey, k1.ID())
		_, err = masterkey.Check(ctx, db, keyring(t, k2, k3), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonMissingKey, k1.ID())
		if !strings.Contains(err.Error(), config.EnvMasterKeyNewFile+" is "+k3.ID()) {
			t.Errorf("message does not describe the configured keys: %v", err)
		}

		// New key configured, no rotation yet.
		rep, err = masterkey.Check(ctx, db, keyring(t, k1, k2), logger, testNow)
		if err != nil || rep.ActiveID != k1.ID() || rep.NewID != k2.ID() || rep.Running != nil {
			t.Fatalf("Check(new key) = %+v, %v", rep, err)
		}
		if !strings.Contains(logs.String(), "run rotate-master-key to re-wrap") {
			t.Errorf("logs = %s", logs)
		}
		// Rows under the new key (sealed while it is configured): removing
		// it before the rotation is refused.
		seal(t, vault(db, keyring(t, k1, k2)), a, crypto.PurposeSecret)
		_, err = masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonMissingKey, k2.ID())

		// Interrupted rotation: reported as running.
		rctx, cancel := context.WithCancel(ctx)
		_, err = masterkey.Rotate(rctx, db, keyring(t, k1, k2), nil, masterkey.Options{
			BatchSize: 1, OnProgress: func(store.Rotation) { cancel() },
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Rotate(canceled) = %v", err)
		}
		rep, err = masterkey.Check(ctx, db, keyring(t, k1, k2), logger, testNow)
		if err != nil || rep.Running == nil || rep.Running.FromKeyID != k1.ID() || rep.Running.ToKeyID != k2.ID() {
			t.Fatalf("Check(running rotation) = %+v, %v", rep, err)
		}
		if !strings.Contains(logs.String(), "run rotate-master-key to resume it") {
			t.Errorf("logs = %s", logs)
		}

		// Completed rotation: the old current key is refused, with or
		// without the new key, until TT_MASTER_KEY_FILE is switched.
		if _, err := masterkey.Rotate(ctx, db, keyring(t, k1, k2), nil, masterkey.Options{}); err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		for _, kr := range []*masterkey.Keyring{keyring(t, k1, k2), keyring(t, k1, nil)} {
			_, err = masterkey.Check(ctx, db, kr, nil, testNow)
			expectCheckError(t, err, masterkey.ReasonRotationCompleted, k2.ID())
			if !strings.Contains(err.Error(), "set "+config.EnvMasterKeyFile) {
				t.Errorf("message lacks the instruction: %v", err)
			}
		}
		rep, err = masterkey.Check(ctx, db, keyring(t, k2, nil), nil, testNow)
		if err != nil || rep.ActiveID != k2.ID() || rep.Registered {
			t.Fatalf("Check(switched) = %+v, %v", rep, err)
		}
	})
}

func TestCheckStoreFailures(t *testing.T) {
	t.Parallel()
	k1 := newKey(t)
	kr := keyring(t, k1, nil)
	tests := []struct {
		name  string
		fault []string
	}{
		{"register", []string{`CREATE TRIGGER no_mk BEFORE INSERT ON master_keys BEGIN SELECT RAISE(ABORT, 'fault'); END`}},
		{"latest rotation", []string{`DROP TABLE key_rotations`}},
		{"master keys", []string{`DROP TABLE master_keys`}},
		{"keys in use", []string{`DROP TABLE wrapped_keys`}},
		{"active key", []string{
			`INSERT INTO master_keys (id, status, created_at) VALUES ('mk_00000000000000aa', 'retired', 0)`,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := storetest.SQLite(t)
			db := openDB(t, e)
			execRaw(t, rawSQLite(t, e), tt.fault...)
			if _, err := masterkey.Check(context.Background(), db, kr, nil, testNow); err == nil || errors.Is(err, masterkey.ErrKeyCheck) {
				t.Errorf("Check = %v, want a store error", err)
			}
		})
	}
}

func TestCheckRefusals(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		k1, k2, k3 := newKey(t), newKey(t), newKey(t)

		// No master key registered, but rows under another key: nothing is
		// recorded.
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		seal(t, vault(db, keyring(t, k1, nil)), a, crypto.PurposeDEK)
		_, err := masterkey.Check(ctx, db, keyring(t, k2, k3), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonMissingKey, k1.ID())
		if !strings.Contains(err.Error(), "no master key is registered yet") {
			t.Errorf("message = %v", err)
		}
		if keys, err := db.MasterKeys().List(ctx); err != nil || len(keys) != 0 {
			t.Fatalf("a wrong key was recorded: %+v, %v", keys, err)
		}
		if _, err := masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow); err != nil {
			t.Fatalf("Check(right key) = %v", err)
		}

		// Running rotation k1 -> k2: another new key is refused, and so is
		// no new key once keys are wrapped under k2.
		rctx, cancel := context.WithCancel(ctx)
		seal(t, vault(db, keyring(t, k1, nil)), a, crypto.PurposeDEK)
		_, err = masterkey.Rotate(rctx, db, keyring(t, k1, k2), nil, masterkey.Options{
			BatchSize: 1, OnProgress: func(store.Rotation) { cancel() },
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Rotate(canceled) = %v", err)
		}
		_, err = masterkey.Check(ctx, db, keyring(t, k1, k3), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonRotationMismatch, k2.ID(), k3.ID())
		_, err = masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonRotationMismatch, k2.ID())

		// Completed: k1 retired. Using it as the new key is refused.
		if _, err := masterkey.Rotate(ctx, db, keyring(t, k1, k2), nil, masterkey.Options{}); err != nil {
			t.Fatal(err)
		}
		_, err = masterkey.Check(ctx, db, keyring(t, k2, k1), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonRetiredKey, k1.ID())

		// A key left under the retired k1: the refusal points to the
		// recovery command.
		plantStraggler(t, e, db, k1, a)
		_, err = masterkey.Check(ctx, db, keyring(t, k2, nil), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonMissingKey, k1.ID())
		if !strings.Contains(err.Error(), "-recover-from") {
			t.Errorf("message does not point to the recovery: %v", err)
		}
	})
}

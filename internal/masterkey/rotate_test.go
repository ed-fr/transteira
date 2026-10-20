package masterkey_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fixture is a database holding keys of three tenants and both purposes,
// most under k1 and some under k2.
type fixture struct {
	db      *store.DB
	k1, k2  *crypto.MasterKey
	tenants []tenant.ID
	keys    []sealed
	// underOld counts the keys created under k1.
	underOld int64
}

func newFixture(t *testing.T, e storetest.Engine) *fixture {
	t.Helper()
	f := &fixture{db: openDB(t, e), k1: newKey(t), k2: newKey(t)}
	if _, err := masterkey.Check(context.Background(), f.db, keyring(t, f.k1, nil), nil, testNow); err != nil {
		t.Fatalf("Check: %v", err)
	}
	old := vault(f.db, keyring(t, f.k1, nil))
	both := vault(f.db, keyring(t, f.k1, f.k2))
	for i, host := range []string{"a", "b", "c"} {
		tid := newTenant(t, f.db, "transfer.entity-"+host+".example.com")
		f.tenants = append(f.tenants, tid)
		for j := range 3 + i {
			p := crypto.PurposeDEK
			if j%2 == 1 {
				p = crypto.PurposeSecret
			}
			f.keys = append(f.keys, seal(t, old, tid, p))
			f.underOld++
		}
		f.keys = append(f.keys, seal(t, both, tid, crypto.PurposeSecret))
	}
	return f
}

// both returns a keyring with k1 current and k2 new.
func (f *fixture) both(t *testing.T) *masterkey.Keyring { return keyring(t, f.k1, f.k2) }

// expectRotated checks that every key is under k2 and opens with k2 alone.
func (f *fixture) expectRotated(t *testing.T) {
	t.Helper()
	for _, k := range f.keys {
		if got := keyIDOf(t, f.db, k); got != f.k2.ID() {
			t.Errorf("key %s is under %s after the rotation", k.id, got)
		}
	}
	expectOpens(t, vault(f.db, keyring(t, f.k2, nil)), f.keys)
	keys, err := f.db.MasterKeys().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]store.MasterKeyStatus{}
	for _, k := range keys {
		status[k.ID] = k.Status
	}
	if status[f.k1.ID()] != store.MasterKeyRetired || status[f.k2.ID()] != store.MasterKeyActive {
		t.Errorf("master keys = %+v", keys)
	}
}

func TestRotate(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		logs := &syncBuffer{}
		var batches int
		done := testNow.Add(time.Hour)
		rot, err := masterkey.Rotate(ctx, f.db, f.both(t), slog.New(slog.NewTextHandler(logs, nil)), masterkey.Options{
			BatchSize:  2,
			Now:        func() time.Time { return done },
			OnProgress: func(store.Rotation) { batches++ },
		})
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if !id.Valid(id.Rotation, rot.ID) || rot.Status != store.RotationCompleted || rot.FromKeyID != f.k1.ID() ||
			rot.ToKeyID != f.k2.ID() || rot.TotalKeys != f.underOld || rot.RewrappedKeys != f.underOld ||
			!rot.CompletedAt.Equal(done) {
			t.Errorf("rotation = %+v", rot)
		}
		// 12 keys by 2, plus the final empty batch.
		if want := int(f.underOld/2) + 1; batches != want {
			t.Errorf("batches = %d, want %d", batches, want)
		}
		stored, err := f.db.KeyRotations().Get(ctx, rot.ID)
		if err != nil || stored.Status != store.RotationCompleted || stored.RewrappedKeys != f.underOld {
			t.Errorf("stored rotation = %+v, %v", stored, err)
		}
		f.expectRotated(t)
		for _, want := range []string{"master key rotation started", "master key rotation progress", "master key rotation completed"} {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("logs lack %q", want)
			}
		}
		for _, k := range f.keys {
			if strings.Contains(logs.String(), fmt.Sprintf("%x", k.secret)) {
				t.Fatal("the logs contain a secret")
			}
		}
	})
}

func TestRotateInterruptedThenResumed(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		f := newFixture(t, e)
		ctx, cancel := context.WithCancel(context.Background())
		rot, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{
			BatchSize: 5, OnProgress: func(store.Rotation) { cancel() },
		})
		if !errors.Is(err, context.Canceled) || rot.Status != store.RotationRunning || rot.RewrappedKeys != 5 {
			t.Fatalf("Rotate(canceled) = %+v, %v", rot, err)
		}
		running, err := f.db.KeyRotations().Running(context.Background())
		if err != nil || running.ID != rot.ID || running.RewrappedKeys != 5 {
			t.Fatalf("Running = %+v, %v", running, err)
		}
		// Every key is still readable while the rotation is half done.
		expectOpens(t, vault(f.db, f.both(t)), f.keys)

		logs := &syncBuffer{}
		resumed, err := masterkey.Rotate(context.Background(), f.db, f.both(t), slog.New(slog.NewTextHandler(logs, nil)),
			masterkey.Options{BatchSize: 5})
		if err != nil || resumed.ID != rot.ID || resumed.RewrappedKeys != f.underOld || resumed.Status != store.RotationCompleted {
			t.Fatalf("Rotate(resume) = %+v, %v", resumed, err)
		}
		if !strings.Contains(logs.String(), "resuming master key rotation") {
			t.Errorf("logs = %s", logs)
		}
		f.expectRotated(t)
	})
}

func TestRotateCatchesKeysCreatedUnderTheOldKey(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		f := newFixture(t, e)
		// A process still running with the old key only keeps creating keys
		// under it: after the first batch, and when the rotation believes it
		// is done (forcing a second completion attempt).
		old := vault(f.db, keyring(t, f.k1, nil))
		calls, last := 0, int64(-1)
		emptyBatches := 0
		rot, err := masterkey.Rotate(context.Background(), f.db, f.both(t), nil, masterkey.Options{
			BatchSize: 4,
			OnProgress: func(r store.Rotation) {
				calls++
				if r.RewrappedKeys == last {
					emptyBatches++
				}
				if calls == 1 || (r.RewrappedKeys == last && emptyBatches == 1) {
					f.keys = append(f.keys, seal(t, old, f.tenants[calls%3], crypto.PurposeDEK))
				}
				last = r.RewrappedKeys
			},
		})
		if err != nil || rot.Status != store.RotationCompleted || rot.RewrappedKeys != f.underOld+2 {
			t.Fatalf("Rotate = %+v, %v", rot, err)
		}
		f.expectRotated(t)
	})
}

func TestRotateGivesUpWhenKeysKeepComing(t *testing.T) {
	t.Parallel()
	e := storetest.SQLite(t)
	f := newFixture(t, e)
	old := vault(f.db, keyring(t, f.k1, nil))
	last := int64(-1)
	rot, err := masterkey.Rotate(context.Background(), f.db, f.both(t), nil, masterkey.Options{
		OnProgress: func(r store.Rotation) {
			if r.RewrappedKeys == last {
				seal(t, old, f.tenants[0], crypto.PurposeDEK)
			}
			last = r.RewrappedKeys
		},
	})
	if !errors.Is(err, masterkey.ErrKeysStillCreated) || !strings.Contains(err.Error(), rot.ID) || rot.Status != store.RotationRunning {
		t.Fatalf("Rotate = %+v, %v", rot, err)
	}
	if running, err := f.db.KeyRotations().Running(context.Background()); err != nil || running.ID != rot.ID {
		t.Errorf("the rotation must stay running: %+v, %v", running, err)
	}
}

func TestRotateUnwrapFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		// A corrupted row under k1.
		garbage := make([]byte, 60)
		if _, err := rand.Read(garbage); err != nil {
			t.Fatal(err)
		}
		bad := store.WrappedKey{ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeDEK, KeyID: f.k1.ID(), Blob: garbage}
		if err := f.db.WrappedKeys().Create(ctx, f.tenants[1], bad); err != nil {
			t.Fatal(err)
		}
		rot, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{BatchSize: 100})
		if !errors.Is(err, masterkey.ErrRewrap) || !errors.Is(err, crypto.ErrUnwrap) || rot.Status != store.RotationFailed {
			t.Fatalf("Rotate = %+v, %v", rot, err)
		}
		for _, s := range []string{bad.ID, string(f.tenants[1]), f.k1.ID()} {
			if !strings.Contains(err.Error(), s) || !strings.Contains(rot.Error, s) {
				t.Errorf("error %q / %q lacks %q", err, rot.Error, s)
			}
		}
		stored, err := f.db.KeyRotations().Get(ctx, rot.ID)
		if err != nil || stored.Status != store.RotationFailed || stored.Error != rot.Error || stored.RewrappedKeys != 0 {
			t.Errorf("stored rotation = %+v, %v", stored, err)
		}
		// The failed batch was rolled back: every key is still under k1 or k2.
		expectOpens(t, vault(f.db, f.both(t)), f.keys)
	})
}

func TestRotateRefusals(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		if _, err := masterkey.Rotate(ctx, f.db, keyring(t, f.k1, nil), nil, masterkey.Options{}); !errors.Is(err, masterkey.ErrNoNewKey) {
			t.Errorf("Rotate(no new key) = %v", err)
		}
		// A rotation to another key is running.
		k3 := newKey(t)
		other := store.Rotation{ID: id.New(id.Rotation), FromKeyID: f.k1.ID(), ToKeyID: k3.ID()}
		if err := f.db.KeyRotations().Start(ctx, other); err != nil {
			t.Fatal(err)
		}
		_, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{})
		if !errors.Is(err, masterkey.ErrRotationMismatch) || !strings.Contains(err.Error(), other.ID) ||
			!strings.Contains(err.Error(), k3.ID()) || !strings.Contains(err.Error(), f.k2.ID()) {
			t.Errorf("Rotate(mismatch) = %v", err)
		}
		expectOpens(t, vault(f.db, f.both(t)), f.keys)
	})
}

func TestRotateStoreFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		fault string
	}{
		{"running rotation", `DROP TABLE key_rotations`},
		{"count", `DROP TABLE wrapped_keys`},
		{"start", `CREATE TRIGGER f BEFORE INSERT ON key_rotations BEGIN SELECT RAISE(ABORT, 'fault'); END`},
		{"rewrap", `CREATE TRIGGER f BEFORE UPDATE ON wrapped_keys BEGIN SELECT RAISE(ABORT, 'fault'); END`},
		{"complete", `CREATE TRIGGER f BEFORE UPDATE ON master_keys BEGIN SELECT RAISE(ABORT, 'fault'); END`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := storetest.SQLite(t)
			f := newFixture(t, e)
			execRaw(t, rawSQLite(t, e), tt.fault)
			_, err := masterkey.Rotate(context.Background(), f.db, f.both(t), nil, masterkey.Options{})
			if err == nil || errors.Is(err, masterkey.ErrRewrap) || errors.Is(err, context.Canceled) {
				t.Errorf("Rotate = %v, want a store error", err)
			}
		})
	}
}

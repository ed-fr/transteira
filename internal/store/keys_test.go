package store_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Master key identifiers of the tests.
const (
	mk1 = "mk_0123456789abcdef"
	mk2 = "mk_fedcba9876543210"
	mk3 = "mk_00000000000000ff"
)

// newWrappedKey returns a valid wrapped key under master key keyID.
func newWrappedKey(keyID string, blob string) store.WrappedKey {
	return store.WrappedKey{ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeDEK, KeyID: keyID, Blob: []byte(blob)}
}

// mustCreateKey stores k for tid.
func mustCreateKey(t *testing.T, db *store.DB, tid tenant.ID, k store.WrappedKey) store.WrappedKey {
	t.Helper()
	if err := db.WrappedKeys().Create(context.Background(), tid, k); err != nil {
		t.Fatalf("Create wrapped key: %v", err)
	}
	return k
}

func TestWrappedKeysCRUD(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.WrappedKeys()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		// Creation time defaults to the store clock; an explicit one is kept.
		k := mustCreateKey(t, db, a.ID, newWrappedKey(mk1, "wrapped-a"))
		got, err := repo.Get(ctx, a.ID, k.ID)
		if err != nil || got.ID != k.ID || got.Purpose != store.KeyPurposeDEK || got.KeyID != mk1 ||
			!bytes.Equal(got.Blob, k.Blob) || !got.CreatedAt.Equal(fixedNow.Truncate(time.Millisecond)) {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		at := time.Date(2025, 1, 2, 3, 4, 5, 6_000_000, time.UTC)
		secret := newWrappedKey(mk2, "wrapped-secret")
		secret.Purpose = store.KeyPurposeSecret
		secret.CreatedAt = at
		mustCreateKey(t, db, a.ID, secret)
		if got, err := repo.Get(ctx, a.ID, secret.ID); err != nil || !got.CreatedAt.Equal(at) || got.Purpose != store.KeyPurposeSecret {
			t.Errorf("Get(secret) = %+v, %v", got, err)
		}

		// Isolation: B can neither read nor destroy A's keys.
		if _, err := repo.Get(ctx, b.ID, k.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get from another tenant: %v", err)
		}
		if err := repo.Delete(ctx, b.ID, k.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete from another tenant: %v", err)
		}
		if _, err := repo.Get(ctx, a.ID, k.ID); err != nil {
			t.Errorf("A's key was affected by B: %v", err)
		}

		// Errors.
		if err := repo.Create(ctx, b.ID, k); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create(duplicate id) = %v", err)
		}
		if err := repo.Create(ctx, tenant.ID(id.New(id.Tenant)), newWrappedKey(mk1, "x")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create(missing tenant) = %v", err)
		}
		for _, tid := range []tenant.ID{"", "bogus"} {
			if err := repo.Create(ctx, tid, newWrappedKey(mk1, "x")); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Create(tenant %q) = %v", tid, err)
			}
			if _, err := repo.Get(ctx, tid, k.ID); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Get(tenant %q) = %v", tid, err)
			}
			if err := repo.Delete(ctx, tid, k.ID); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Delete(tenant %q) = %v", tid, err)
			}
		}
		bad := map[string]func(*store.WrappedKey){
			"id":             func(w *store.WrappedKey) { w.ID = id.New(id.Blocklist) },
			"purpose":        func(w *store.WrappedKey) { w.Purpose = "kek" },
			"key id prefix":  func(w *store.WrappedKey) { w.KeyID = "xx_0123456789abcdef" },
			"key id case":    func(w *store.WrappedKey) { w.KeyID = "mk_0123456789ABCDEF" },
			"key id length":  func(w *store.WrappedKey) { w.KeyID = "mk_0123" },
			"empty blob":     func(w *store.WrappedKey) { w.Blob = nil },
			"oversized blob": func(w *store.WrappedKey) { w.Blob = make([]byte, store.MaxWrappedKeyBytes+1) },
		}
		for name, mutate := range bad {
			w := newWrappedKey(mk1, "x")
			mutate(&w)
			if err := repo.Create(ctx, a.ID, w); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Create(bad %s) = %v", name, err)
			}
		}
		big := newWrappedKey(mk1, "")
		big.Blob = make([]byte, store.MaxWrappedKeyBytes)
		mustCreateKey(t, db, a.ID, big)

		// Cross-tenant views for the master key operations.
		mustCreateKey(t, db, b.ID, newWrappedKey(mk3, "wrapped-b"))
		ids, err := repo.KeyIDsInUse(ctx)
		if err != nil || !slices.Equal(ids, []string{mk3, mk1, mk2}) {
			t.Errorf("KeyIDsInUse = %v, %v", ids, err)
		}
		if n, err := repo.CountByKey(ctx, mk1); err != nil || n != 2 {
			t.Errorf("CountByKey(mk1) = %d, %v", n, err)
		}
		if _, err := repo.CountByKey(ctx, "mk_bad"); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("CountByKey(malformed) = %v", err)
		}

		// Cryptographic erasure.
		if err := repo.Delete(ctx, a.ID, k.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := repo.Delete(ctx, a.ID, k.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete twice = %v", err)
		}
		if _, err := repo.Get(ctx, a.ID, k.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(deleted) = %v", err)
		}

		// Deleting a tenant requires its keys erased first (T-110).
		if err := db.Tenants().Delete(ctx, b.ID); !errors.Is(err, store.ErrKeysRemain) {
			t.Fatalf("Delete(tenant with keys) = %v, want ErrKeysRemain", err)
		}
		eraseTenantKeys(t, db, b.ID)
		if err := db.Tenants().Delete(ctx, b.ID); err != nil {
			t.Fatal(err)
		}
		if n, err := repo.CountByKey(ctx, mk3); err != nil || n != 0 {
			t.Errorf("CountByKey(mk3) after tenant deletion = %d, %v", n, err)
		}
		if ids, err := repo.KeyIDsInUse(ctx); err != nil || !slices.Equal(ids, []string{mk1, mk2}) {
			t.Errorf("KeyIDsInUse after tenant deletion = %v, %v", ids, err)
		}
	})
}

func TestMasterKeys(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		repo := openDB(t, e).MasterKeys()

		if _, err := repo.Active(ctx); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Active(empty) = %v", err)
		}
		if keys, err := repo.List(ctx); err != nil || len(keys) != 0 || keys == nil {
			t.Errorf("List(empty) = %#v, %v", keys, err)
		}
		if _, err := repo.EnsureActive(ctx, "mk_short", fixedNow); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("EnsureActive(malformed) = %v", err)
		}
		if reg, err := repo.EnsureActive(ctx, mk1, fixedNow); err != nil || !reg {
			t.Fatalf("EnsureActive(first) = %v, %v", reg, err)
		}
		// Another key never replaces the registered one.
		for _, k := range []string{mk1, mk2} {
			if reg, err := repo.EnsureActive(ctx, k, fixedNow); err != nil || reg {
				t.Errorf("EnsureActive(%s) = %v, %v; want false", k, reg, err)
			}
		}
		if active, err := repo.Active(ctx); err != nil || active != mk1 {
			t.Errorf("Active = %q, %v", active, err)
		}
		keys, err := repo.List(ctx)
		want := []store.MasterKeyRecord{{ID: mk1, Status: store.MasterKeyActive, CreatedAt: fixedNow.Truncate(time.Millisecond)}}
		if err != nil || !slices.Equal(keys, want) {
			t.Errorf("List = %+v, %v", keys, err)
		}
	})
}

func TestKeyRotations(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		rots, keys, mks := db.KeyRotations(), db.WrappedKeys(), db.MasterKeys()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		if _, err := mks.EnsureActive(ctx, mk1, fixedNow); err != nil {
			t.Fatal(err)
		}
		owner := map[string]tenant.ID{}
		for i, tid := range []tenant.ID{a.ID, a.ID, a.ID, b.ID, b.ID} {
			k := mustCreateKey(t, db, tid, newWrappedKey(mk1, "old-"+string(rune('0'+i))))
			owner[k.ID] = tid
		}
		// A key created under the new master key before the rotation.
		mustCreateKey(t, db, a.ID, newWrappedKey(mk2, "already-new"))

		for name, f := range map[string]func() (store.Rotation, error){
			"Running": func() (store.Rotation, error) { return rots.Running(ctx) },
			"Latest":  func() (store.Rotation, error) { return rots.Latest(ctx) },
			"Get":     func() (store.Rotation, error) { return rots.Get(ctx, id.New(id.Rotation)) },
		} {
			if _, err := f(); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s(none) = %v", name, err)
			}
		}

		// Start validation.
		valid := store.Rotation{ID: id.New(id.Rotation), FromKeyID: mk1, ToKeyID: mk2, TotalKeys: 5}
		bad := map[string]func(*store.Rotation){
			"id":       func(r *store.Rotation) { r.ID = id.New(id.Tenant) },
			"from":     func(r *store.Rotation) { r.FromKeyID = "mk_x" },
			"to":       func(r *store.Rotation) { r.ToKeyID = "" },
			"same key": func(r *store.Rotation) { r.ToKeyID = mk1 },
			"total":    func(r *store.Rotation) { r.TotalKeys = -1 },
		}
		for name, mutate := range bad {
			r := valid
			mutate(&r)
			if err := rots.Start(ctx, r); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Start(bad %s) = %v", name, err)
			}
		}
		total, err := keys.CountByKey(ctx, mk1)
		if err != nil || total != 5 {
			t.Fatalf("CountByKey = %d, %v", total, err)
		}
		if err := rots.Start(ctx, valid); err != nil {
			t.Fatalf("Start: %v", err)
		}
		other := valid
		other.ID = id.New(id.Rotation)
		if err := rots.Start(ctx, other); !errors.Is(err, store.ErrRotationRunning) {
			t.Errorf("Start(second) = %v, want ErrRotationRunning", err)
		}
		want := store.Rotation{
			ID: valid.ID, FromKeyID: mk1, ToKeyID: mk2, Status: store.RotationRunning,
			TotalKeys: 5, StartedAt: fixedNow.Truncate(time.Millisecond),
		}
		for name, f := range map[string]func() (store.Rotation, error){
			"Running": func() (store.Rotation, error) { return rots.Running(ctx) },
			"Latest":  func() (store.Rotation, error) { return rots.Latest(ctx) },
			"Get":     func() (store.Rotation, error) { return rots.Get(ctx, valid.ID) },
		} {
			if got, err := f(); err != nil || got != want {
				t.Errorf("%s = %+v, %v; want %+v", name, got, err, want)
			}
		}

		// Completing before every key is rewrapped is refused.
		if err := rots.Complete(ctx, valid.ID, fixedNow); !errors.Is(err, store.ErrRotationIncomplete) {
			t.Errorf("Complete(incomplete) = %v", err)
		}

		// RewrapBatch argument and state checks.
		rewrap := func(k store.WrappedKey, tid tenant.ID) ([]byte, error) {
			if k.KeyID != mk1 || owner[k.ID] != tid || !strings.HasPrefix(string(k.Blob), "old-") {
				t.Errorf("rewrap got %+v for %s", k, tid)
			}
			return append([]byte("new-"), k.Blob...), nil
		}
		if _, err := rots.RewrapBatch(ctx, valid.ID, mk1, mk2, 0, rewrap); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("RewrapBatch(limit 0) = %v", err)
		}
		if _, err := rots.RewrapBatch(ctx, valid.ID, mk1, mk2, 1, nil); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("RewrapBatch(nil func) = %v", err)
		}
		if _, err := rots.RewrapBatch(ctx, id.New(id.Rotation), mk1, mk2, 1, rewrap); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RewrapBatch(unknown) = %v", err)
		}
		if _, err := rots.RewrapBatch(ctx, valid.ID, mk1, mk3, 1, rewrap); !errors.Is(err, store.ErrRotationNotRunning) {
			t.Errorf("RewrapBatch(other target) = %v", err)
		}
		if _, err := rots.RewrapBatch(ctx, valid.ID, mk3, mk2, 1, rewrap); !errors.Is(err, store.ErrRotationNotRunning) {
			t.Errorf("RewrapBatch(other source) = %v", err)
		}

		// A failing callback, or an invalid blob, rolls the batch back.
		errCallback := errors.New("unwrap failed")
		calls := 0
		_, err = rots.RewrapBatch(ctx, valid.ID, mk1, mk2, 3, func(k store.WrappedKey, tid tenant.ID) ([]byte, error) {
			calls++
			if calls == 2 {
				return nil, errCallback
			}
			return rewrap(k, tid)
		})
		if !errors.Is(err, errCallback) {
			t.Errorf("RewrapBatch(callback error) = %v", err)
		}
		for name, blob := range map[string][]byte{"empty": {}, "oversized": make([]byte, store.MaxWrappedKeyBytes+1)} {
			_, err := rots.RewrapBatch(ctx, valid.ID, mk1, mk2, 3, func(store.WrappedKey, tenant.ID) ([]byte, error) { return blob, nil })
			if !errors.Is(err, store.ErrInvalid) {
				t.Errorf("RewrapBatch(%s blob) = %v", name, err)
			}
		}
		if n, err := keys.CountByKey(ctx, mk1); err != nil || n != 5 {
			t.Errorf("CountByKey after rolled back batches = %d, %v", n, err)
		}
		if got, _ := rots.Get(ctx, valid.ID); got.RewrappedKeys != 0 {
			t.Errorf("progress after rolled back batches = %d", got.RewrappedKeys)
		}

		// Batches until no key is left.
		var sizes []int
		for {
			n, err := rots.RewrapBatch(ctx, valid.ID, mk1, mk2, 2, rewrap)
			if err != nil {
				t.Fatalf("RewrapBatch: %v", err)
			}
			sizes = append(sizes, n)
			if n == 0 {
				break
			}
		}
		if !slices.Equal(sizes, []int{2, 2, 1, 0}) {
			t.Errorf("batch sizes = %v", sizes)
		}
		for kid, tid := range owner {
			k, err := keys.Get(ctx, tid, kid)
			if err != nil || k.KeyID != mk2 || !strings.HasPrefix(string(k.Blob), "new-old-") {
				t.Errorf("rewrapped key = %+v, %v", k, err)
			}
		}
		if got, _ := rots.Get(ctx, valid.ID); got.RewrappedKeys != 5 || got.Status != store.RotationRunning {
			t.Errorf("rotation after batches = %+v", got)
		}

		// Completion switches the master keys.
		done := fixedNow.Add(time.Hour)
		if err := rots.Complete(ctx, valid.ID, done); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if active, err := mks.Active(ctx); err != nil || active != mk2 {
			t.Errorf("Active after rotation = %q, %v", active, err)
		}
		list, err := mks.List(ctx)
		wantKeys := []store.MasterKeyRecord{
			{ID: mk1, Status: store.MasterKeyRetired, CreatedAt: fixedNow.Truncate(time.Millisecond), RetiredAt: done.Truncate(time.Millisecond)},
			{ID: mk2, Status: store.MasterKeyActive, CreatedAt: done.Truncate(time.Millisecond)},
		}
		if err != nil || !slices.Equal(list, wantKeys) {
			t.Errorf("List after rotation = %+v, %v", list, err)
		}
		got, err := rots.Get(ctx, valid.ID)
		if err != nil || got.Status != store.RotationCompleted || !got.CompletedAt.Equal(done.Truncate(time.Millisecond)) || got.Error != "" {
			t.Errorf("completed rotation = %+v, %v", got, err)
		}
		if _, err := rots.Running(ctx); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Running after completion = %v", err)
		}

		// A finished rotation accepts nothing more.
		if err := rots.Complete(ctx, valid.ID, done); !errors.Is(err, store.ErrRotationNotRunning) {
			t.Errorf("Complete twice = %v", err)
		}
		if err := rots.Fail(ctx, valid.ID, "x", done); !errors.Is(err, store.ErrRotationNotRunning) {
			t.Errorf("Fail(completed) = %v", err)
		}
		if _, err := rots.RewrapBatch(ctx, valid.ID, mk1, mk2, 1, rewrap); !errors.Is(err, store.ErrRotationNotRunning) {
			t.Errorf("RewrapBatch(completed) = %v", err)
		}
		if err := rots.Complete(ctx, id.New(id.Rotation), done); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Complete(unknown) = %v", err)
		}
		if err := rots.Fail(ctx, id.New(id.Rotation), "x", done); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Fail(unknown) = %v", err)
		}

		// A retired key wraps nothing again: neither new keys nor a rotation.
		if err := keys.Create(ctx, a.ID, newWrappedKey(mk1, "late")); !errors.Is(err, store.ErrKeyRetired) {
			t.Errorf("Create under a retired key = %v, want ErrKeyRetired", err)
		}
		toRetired := store.Rotation{ID: id.New(id.Rotation), FromKeyID: mk2, ToKeyID: mk1}
		if err := rots.Start(ctx, toRetired); !errors.Is(err, store.ErrKeyRetired) {
			t.Errorf("Start towards a retired key = %v, want ErrKeyRetired", err)
		}

		// A failed rotation leaves the master keys unchanged; its message
		// is truncated to valid UTF-8.
		failed := store.Rotation{ID: id.New(id.Rotation), FromKeyID: mk2, ToKeyID: mk3, StartedAt: done.Add(time.Minute)}
		if err := rots.Start(ctx, failed); err != nil {
			t.Fatalf("Start(second rotation): %v", err)
		}
		msg := "x" + strings.Repeat("é", 600)
		if err := rots.Fail(ctx, failed.ID, msg, done.Add(2*time.Minute)); err != nil {
			t.Fatalf("Fail: %v", err)
		}
		got, err = rots.Get(ctx, failed.ID)
		if err != nil || got.Status != store.RotationFailed || len(got.Error) != 999 || !utf8.ValidString(got.Error) ||
			!strings.HasPrefix(msg, got.Error) || !got.CompletedAt.Equal(done.Add(2*time.Minute).Truncate(time.Millisecond)) {
			t.Errorf("failed rotation = %+v (%d bytes), %v", got, len(got.Error), err)
		}
		if active, _ := mks.Active(ctx); active != mk2 {
			t.Errorf("Active after failure = %q", active)
		}

		// A new rotation after the failure registers its target on completion.
		next := store.Rotation{ID: id.New(id.Rotation), FromKeyID: mk2, ToKeyID: mk3, TotalKeys: 6, StartedAt: done.Add(3 * time.Minute)}
		if err := rots.Start(ctx, next); err != nil {
			t.Fatalf("Start(next): %v", err)
		}
		if latest, err := rots.Latest(ctx); err != nil || latest.ID != next.ID {
			t.Errorf("Latest = %+v, %v", latest, err)
		}
		n, err := rots.RewrapBatch(ctx, next.ID, mk2, mk3, 100, func(k store.WrappedKey, _ tenant.ID) ([]byte, error) { return k.Blob, nil })
		if err != nil || n != 6 {
			t.Fatalf("RewrapBatch(next) = %d, %v", n, err)
		}
		if err := rots.Complete(ctx, next.ID, done.Add(4*time.Minute)); err != nil {
			t.Fatalf("Complete(next): %v", err)
		}
		list, err = mks.List(ctx)
		if err != nil || len(list) != 3 || list[0].Status != store.MasterKeyRetired ||
			list[1].ID != mk2 || list[1].Status != store.MasterKeyRetired || !list[1].RetiredAt.Equal(done.Add(4*time.Minute).Truncate(time.Millisecond)) ||
			list[2].ID != mk3 || list[2].Status != store.MasterKeyActive {
			t.Errorf("List after the next rotation = %+v, %v", list, err)
		}
		if got, _ := rots.Get(ctx, next.ID); got.RewrappedKeys != 6 {
			t.Errorf("progress = %d", got.RewrappedKeys)
		}
	})
}

func TestMasterKeysFirstRegistration(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		mks := db.MasterKeys()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		mustCreateKey(t, db, a.ID, newWrappedKey(mk1, "k1"))
		k3 := mustCreateKey(t, db, a.ID, newWrappedKey(mk3, "k3"))

		// The keyring holds another key: nothing is recorded, and the error
		// names the unknown keys only.
		reg, err := mks.EnsureActive(ctx, mk1, fixedNow)
		if !errors.Is(err, store.ErrUnregisteredKeys) || reg || !strings.Contains(err.Error(), mk3) || strings.Contains(err.Error(), mk1) {
			t.Errorf("EnsureActive with foreign keys = %v, %v", reg, err)
		}
		if _, err := mks.EnsureActive(ctx, mk2, fixedNow); !errors.Is(err, store.ErrUnregisteredKeys) {
			t.Errorf("EnsureActive(wrong key) = %v", err)
		}
		if keys, err := mks.List(ctx); err != nil || len(keys) != 0 {
			t.Errorf("master keys after refusals = %+v, %v", keys, err)
		}

		// Once every key is under the keyring's key, it is registered.
		if err := db.WrappedKeys().Delete(ctx, a.ID, k3.ID); err != nil {
			t.Fatal(err)
		}
		if reg, err := mks.EnsureActive(ctx, mk1, fixedNow); err != nil || !reg {
			t.Errorf("EnsureActive(matching keys) = %v, %v", reg, err)
		}
		if active, err := mks.Active(ctx); err != nil || active != mk1 {
			t.Errorf("Active = %q, %v", active, err)
		}
	})
}

func TestWrappedKeysInTransaction(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.WrappedKeys()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		sa, err := db.Scoped(a.ID)
		if err != nil {
			t.Fatal(err)
		}

		// A rolled back transaction leaves no key.
		lost := newWrappedKey(mk1, "lost")
		errAbort := errors.New("abort")
		err = sa.Tx(ctx, func(tx *store.ScopedTx) error {
			if err := repo.CreateTx(ctx, tx, lost); err != nil {
				return err
			}
			return errAbort
		})
		if !errors.Is(err, errAbort) {
			t.Fatalf("Tx = %v", err)
		}
		if _, err := repo.Get(ctx, a.ID, lost.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(rolled back) = %v", err)
		}

		// Committed keys belong to the transaction's tenant.
		kept := newWrappedKey(mk1, "kept")
		err = sa.Tx(ctx, func(tx *store.ScopedTx) error {
			if err := repo.CreateTx(ctx, tx, kept); err != nil {
				return err
			}
			bad := newWrappedKey(mk1, "")
			if err := repo.CreateTx(ctx, tx, bad); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("CreateTx(empty blob) = %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Get(ctx, b.ID, kept.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get from B = %v", err)
		}
		sb, _ := db.Scoped(b.ID)
		err = sb.Tx(ctx, func(tx *store.ScopedTx) error { return repo.DeleteTx(ctx, tx, kept.ID) })
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteTx from B = %v", err)
		}
		err = sa.Tx(ctx, func(tx *store.ScopedTx) error { return repo.DeleteTx(ctx, tx, kept.ID) })
		if err != nil {
			t.Errorf("DeleteTx = %v", err)
		}
		if _, err := repo.Get(ctx, a.ID, kept.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(deleted) = %v", err)
		}
	})
}

func TestScrubDeleted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := storetest.SQLite(t)
	db := openDB(t, e)
	a := newTenant(t, db, "transfer.entity-a.example.com")
	pattern := bytes.Repeat([]byte("SCRUB-ME-7f3a9c!"), 8)
	k := newWrappedKey(mk1, "")
	k.Blob = pattern
	mustCreateKey(t, db, a.ID, k)
	// found reports whether the raw database or WAL file holds the pattern.
	found := func() bool {
		t.Helper()
		for _, p := range []string{e.DSN, e.DSN + "-wal"} {
			b, err := os.ReadFile(p)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if bytes.Contains(b, pattern) {
				return true
			}
		}
		return false
	}
	if !found() {
		t.Fatal("the blob is not on disk before deletion: the test would pass vacuously")
	}
	if err := db.WrappedKeys().Delete(ctx, a.ID, k.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.ScrubDeleted(ctx); err != nil {
		t.Fatalf("ScrubDeleted: %v", err)
	}
	if found() {
		t.Error("the deleted blob is still readable in the database or WAL file")
	}

	// PostgreSQL: nothing to do.
	if pg, ok := storetest.Postgres(t); ok {
		if err := openDB(t, pg).ScrubDeleted(ctx); err != nil {
			t.Errorf("ScrubDeleted(postgres) = %v", err)
		}
	}
}

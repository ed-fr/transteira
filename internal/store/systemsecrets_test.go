package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestSystemSecrets(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.SystemSecrets()

		s := newTOTPSecret("sealed")
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create = %v", err)
		}
		got, err := repo.Get(ctx, s.ID)
		if err != nil || got.ID != s.ID || got.Purpose != store.SecretPurposeAdminTOTP || got.KeyID != mk1 ||
			string(got.Blob) != "sealed" || !got.CreatedAt.Equal(msNow) {
			t.Errorf("Get = %+v, %v", got, err)
		}
		wantErr(t, "Create(duplicate)", repo.Create(ctx, s), store.ErrConflict)
		whk := newTOTPSecret("webhook url")
		whk.Purpose = store.SecretPurposeWebhook
		if err := repo.Create(ctx, whk); err != nil {
			t.Fatalf("Create(webhook) = %v", err)
		}
		if got, err := repo.Get(ctx, whk.ID); err != nil || got.Purpose != store.SecretPurposeWebhook {
			t.Errorf("Get(webhook) = %+v, %v", got, err)
		}
		bad := map[string]func(*store.SystemSecret){
			"id":      func(s *store.SystemSecret) { s.ID = id.New(id.WrappedKey) },
			"purpose": func(s *store.SystemSecret) { s.Purpose = store.KeyPurposeSecret },
			"key":     func(s *store.SystemSecret) { s.KeyID = "mk_x" },
			"blob":    func(s *store.SystemSecret) { s.Blob = nil },
			"big":     func(s *store.SystemSecret) { s.Blob = make([]byte, store.MaxWrappedKeyBytes+1) },
		}
		for name, mutate := range bad {
			x := newTOTPSecret("x")
			mutate(&x)
			wantErr(t, "Create("+name+")", repo.Create(ctx, x), store.ErrInvalid)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			x := newTOTPSecret("tx")
			if err := repo.CreateTx(ctx, tx, x); err != nil {
				return err
			}
			got, err := repo.GetTx(ctx, tx, x.ID)
			if err == nil && string(got.Blob) != "tx" {
				t.Errorf("GetTx = %+v", got)
			}
			return err
		})
		if err != nil {
			t.Errorf("CreateTx/GetTx = %v", err)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return repo.CreateTx(ctx, tx, s) })
		wantErr(t, "CreateTx(duplicate)", err, store.ErrConflict)
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error { _, err := repo.GetTx(ctx, tx, "ss_unknown"); return err })
		wantErr(t, "GetTx(unknown)", err, store.ErrNotFound)

		// A secret referenced by an admin cannot be deleted directly.
		a := newSuperAdmin(t, db, "root")
		pending := newTOTPSecret("pending")
		if err := db.Admins().SetPendingTOTP(ctx, a.ID, pending); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "Delete(referenced)", repo.Delete(ctx, pending.ID), store.ErrNotFound)
		if err := repo.Delete(ctx, s.ID); err != nil {
			t.Errorf("Delete = %v", err)
		}
		wantErr(t, "Delete(unknown)", repo.Delete(ctx, s.ID), store.ErrNotFound)
		_, err = repo.Get(ctx, s.ID)
		wantErr(t, "Get(deleted)", err, store.ErrNotFound)
	})
}

// TestSystemSecretsRotation checks that the master key operations cover
// the system secrets: keys in use, counts, rewrap and completion.
func TestSystemSecretsRotation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		tn := newTenant(t, db, "transfer.entity-a.example.com")
		if _, err := db.MasterKeys().EnsureActive(ctx, mk1, msNow); err != nil {
			t.Fatal(err)
		}
		mustCreateKey(t, db, tn.ID, newWrappedKey(mk1, "dek"))
		var secrets []string
		for range 3 {
			s := newTOTPSecret("totp")
			if err := db.SystemSecrets().Create(ctx, s); err != nil {
				t.Fatal(err)
			}
			secrets = append(secrets, s.ID)
		}
		// A system secret under an unregistered key shows in the keys in use.
		orphan := newTOTPSecret("orphan")
		orphan.KeyID = mk3
		if err := db.SystemSecrets().Create(ctx, orphan); err != nil {
			t.Fatal(err)
		}
		if ids, err := db.WrappedKeys().KeyIDsInUse(ctx); err != nil || !slices.Equal(ids, []string{mk3, mk1}) && !slices.Equal(ids, []string{mk1, mk3}) {
			t.Errorf("KeyIDsInUse = %v, %v", ids, err)
		}
		if err := db.SystemSecrets().Delete(ctx, orphan.ID); err != nil {
			t.Fatal(err)
		}
		if n, err := db.WrappedKeys().CountByKey(ctx, mk1); err != nil || n != 4 {
			t.Errorf("CountByKey = %d, %v; want 1 wrapped key + 3 system secrets", n, err)
		}

		rot := id.New(id.Rotation)
		if err := db.KeyRotations().Start(ctx, store.Rotation{ID: rot, FromKeyID: mk1, ToKeyID: mk2, TotalKeys: 4}); err != nil {
			t.Fatal(err)
		}
		if n, err := db.KeyRotations().RewrapBatch(ctx, rot, mk1, mk2, 10, func(k store.WrappedKey, _ tenant.ID) ([]byte, error) {
			return k.Blob, nil
		}); err != nil || n != 1 {
			t.Fatalf("RewrapBatch = %d, %v", n, err)
		}
		wantErr(t, "Complete(system secrets left)", db.KeyRotations().Complete(ctx, rot, msNow), store.ErrRotationIncomplete)
		var seen []string
		n, err := db.KeyRotations().RewrapSystemSecretsBatch(ctx, rot, mk1, mk2, 2, func(s store.SystemSecret) ([]byte, error) {
			seen = append(seen, s.ID)
			if s.Purpose != store.SecretPurposeAdminTOTP || s.KeyID != mk1 {
				t.Errorf("rewrap got %+v", s)
			}
			return append([]byte("r:"), s.Blob...), nil
		})
		if err != nil || n != 2 {
			t.Fatalf("RewrapSystemSecretsBatch = %d, %v", n, err)
		}
		if n, err := db.KeyRotations().RewrapSystemSecretsBatch(ctx, rot, mk1, mk2, 10, func(s store.SystemSecret) ([]byte, error) {
			seen = append(seen, s.ID)
			return append([]byte("r:"), s.Blob...), nil
		}); err != nil || n != 1 {
			t.Fatalf("RewrapSystemSecretsBatch(rest) = %d, %v", n, err)
		}
		if n, err := db.KeyRotations().RewrapSystemSecretsBatch(ctx, rot, mk1, mk2, 10, func(store.SystemSecret) ([]byte, error) {
			return nil, errors.New("not called")
		}); err != nil || n != 0 {
			t.Errorf("RewrapSystemSecretsBatch(none left) = %d, %v", n, err)
		}
		slices.Sort(seen)
		slices.Sort(secrets)
		if !slices.Equal(seen, secrets) {
			t.Errorf("rewrapped %v, want %v", seen, secrets)
		}
		if r, _ := db.KeyRotations().Get(ctx, rot); r.RewrappedKeys != 4 {
			t.Errorf("rotation progress = %d, want 4", r.RewrappedKeys)
		}
		if err := db.KeyRotations().Complete(ctx, rot, msNow.Add(time.Second)); err != nil {
			t.Fatalf("Complete = %v", err)
		}
		got, _ := db.SystemSecrets().Get(ctx, secrets[0])
		if got.KeyID != mk2 || string(got.Blob) != "r:totp" {
			t.Errorf("rewrapped secret = %+v", got)
		}
		// The retired key can no longer seal anything.
		wantErr(t, "Create(retired key)", db.SystemSecrets().Create(ctx, newTOTPSecret("late")), store.ErrKeyRetired)

		// Errors of RewrapSystemSecretsBatch.
		_, err = db.KeyRotations().RewrapSystemSecretsBatch(ctx, rot, mk1, mk2, 0, nil)
		wantErr(t, "RewrapSystemSecretsBatch(no limit)", err, store.ErrInvalid)
		_, err = db.KeyRotations().RewrapSystemSecretsBatch(ctx, rot, mk1, mk2, 1, func(store.SystemSecret) ([]byte, error) { return nil, nil })
		wantErr(t, "RewrapSystemSecretsBatch(completed)", err, store.ErrRotationNotRunning)
		_, err = db.KeyRotations().RewrapSystemSecretsBatch(ctx, id.New(id.Rotation), mk1, mk2, 1, func(store.SystemSecret) ([]byte, error) { return nil, nil })
		wantErr(t, "RewrapSystemSecretsBatch(unknown)", err, store.ErrNotFound)
		rot2 := id.New(id.Rotation)
		if err := db.KeyRotations().Start(ctx, store.Rotation{ID: rot2, FromKeyID: mk2, ToKeyID: mk3}); err != nil {
			t.Fatal(err)
		}
		_, err = db.KeyRotations().RewrapSystemSecretsBatch(ctx, rot2, mk1, mk3, 1, func(store.SystemSecret) ([]byte, error) { return nil, nil })
		wantErr(t, "RewrapSystemSecretsBatch(other keys)", err, store.ErrRotationNotRunning)
		boom := errors.New("boom")
		_, err = db.KeyRotations().RewrapSystemSecretsBatch(ctx, rot2, mk2, mk3, 1, func(store.SystemSecret) ([]byte, error) { return nil, boom })
		wantErr(t, "RewrapSystemSecretsBatch(rewrap error)", err, boom)
		_, err = db.KeyRotations().RewrapSystemSecretsBatch(ctx, rot2, mk2, mk3, 1, func(store.SystemSecret) ([]byte, error) { return nil, nil })
		wantErr(t, "RewrapSystemSecretsBatch(empty blob)", err, store.ErrInvalid)
		// Abandoning a rotation whose target already seals a secret is refused.
		if _, err := db.KeyRotations().RewrapSystemSecretsBatch(ctx, rot2, mk2, mk3, 1, func(s store.SystemSecret) ([]byte, error) {
			return s.Blob, nil
		}); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "Abandon(target in use)", db.KeyRotations().Abandon(ctx, rot2, "x", msNow), store.ErrRotationInUse)
	})
}

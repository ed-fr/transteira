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
)

func TestVaultSystemSecrets(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		k1 := newKey(t)
		if _, err := masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow); err != nil {
			t.Fatal(err)
		}
		v := vault(db, keyring(t, k1, nil))

		// WrapSystem returns the row without storing it.
		secret := []byte("12345678901234567890")
		row, err := v.WrapSystem(crypto.PurposeAdminTOTP, secret)
		if err != nil || !id.Valid(id.SystemSecret, row.ID) || row.Purpose != store.SecretPurposeAdminTOTP ||
			row.KeyID != k1.ID() || len(row.Blob) == 0 || bytes.Contains(row.Blob, secret) {
			t.Fatalf("WrapSystem = %+v, %v", row, err)
		}
		if _, err := v.OpenSystem(ctx, crypto.PurposeAdminTOTP, row.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OpenSystem(not stored) = %v", err)
		}
		if err := db.SystemSecrets().Create(ctx, row); err != nil {
			t.Fatal(err)
		}
		got, err := v.OpenSystem(ctx, crypto.PurposeAdminTOTP, row.ID)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("OpenSystem = %v", err)
		}
		if again, err := v.WrapSystem(crypto.PurposeAdminTOTP, secret); err != nil || again.ID == row.ID ||
			bytes.Equal(again.Blob, row.Blob) {
			t.Errorf("a second WrapSystem must use a new ID and nonce: %v", err)
		}

		// The webhook purpose is a system purpose too, and a webhook secret
		// never opens as a TOTP secret (nor the reverse).
		whk, err := v.WrapSystem(crypto.PurposeWebhook, []byte("https://hooks.example.com/x"))
		if err != nil || whk.Purpose != store.SecretPurposeWebhook {
			t.Fatalf("WrapSystem(webhook) = %+v, %v", whk, err)
		}
		if err := db.SystemSecrets().Create(ctx, whk); err != nil {
			t.Fatal(err)
		}
		if got, err := v.OpenSystem(ctx, crypto.PurposeWebhook, whk.ID); err != nil || string(got) != "https://hooks.example.com/x" {
			t.Errorf("OpenSystem(webhook) = %q, %v", got, err)
		}
		if _, err := v.OpenSystem(ctx, crypto.PurposeAdminTOTP, whk.ID); !errors.Is(err, masterkey.ErrPurposeMismatch) {
			t.Errorf("OpenSystem(webhook row as TOTP) = %v", err)
		}
		if _, err := v.OpenSystem(ctx, crypto.PurposeWebhook, row.ID); !errors.Is(err, masterkey.ErrPurposeMismatch) {
			t.Errorf("OpenSystem(TOTP row as webhook) = %v", err)
		}

		// Purposes: only system purposes are wrapped, and the stored
		// purpose must match.
		for _, p := range []crypto.Purpose{crypto.PurposeDEK, crypto.PurposeSecret, "bogus"} {
			if _, err := v.WrapSystem(p, secret); !errors.Is(err, masterkey.ErrPurposeMismatch) {
				t.Errorf("WrapSystem(%s) = %v", p, err)
			}
			if _, err := v.OpenSystem(ctx, p, row.ID); !errors.Is(err, masterkey.ErrPurposeMismatch) ||
				!strings.Contains(err.Error(), row.ID) {
				t.Errorf("OpenSystem(%s) = %v", p, err)
			}
		}

		// A tampered blob fails closed.
		tampered := row
		tampered.ID = id.New(id.SystemSecret)
		tampered.Blob = bytes.Clone(row.Blob)
		tampered.Blob[len(tampered.Blob)-1] ^= 1
		if err := db.SystemSecrets().Create(ctx, tampered); err != nil {
			t.Fatal(err)
		}
		if got, err := v.OpenSystem(ctx, crypto.PurposeAdminTOTP, tampered.ID); !errors.Is(err, crypto.ErrUnwrap) || got != nil ||
			!strings.Contains(err.Error(), tampered.ID) {
			t.Errorf("OpenSystem(tampered) = %v", err)
		}

		// A blob copied to another secret ID does not open: the ID is bound.
		swapped := row
		swapped.ID = id.New(id.SystemSecret)
		if err := db.SystemSecrets().Create(ctx, swapped); err != nil {
			t.Fatal(err)
		}
		if _, err := v.OpenSystem(ctx, crypto.PurposeAdminTOTP, swapped.ID); !errors.Is(err, crypto.ErrUnwrap) {
			t.Errorf("OpenSystem(blob of another secret) = %v", err)
		}

		// A blob bound to a tenant instead of the system binding does not
		// open, even under the right ID, key and purpose.
		tenantBound := store.SystemSecret{ID: id.New(id.SystemSecret), Purpose: store.SecretPurposeAdminTOTP, KeyID: k1.ID()}
		if tenantBound.Blob, err = k1.Wrap(crypto.PurposeAdminTOTP, id.New(id.Tenant), tenantBound.ID, secret); err != nil {
			t.Fatal(err)
		}
		if err := db.SystemSecrets().Create(ctx, tenantBound); err != nil {
			t.Fatal(err)
		}
		if _, err := v.OpenSystem(ctx, crypto.PurposeAdminTOTP, tenantBound.ID); !errors.Is(err, crypto.ErrUnwrap) {
			t.Errorf("OpenSystem(tenant-bound blob) = %v", err)
		}

		// A secret under a master key that is not provided.
		k2 := newKey(t)
		_, err = vault(db, keyring(t, k2, nil)).OpenSystem(ctx, crypto.PurposeAdminTOTP, row.ID)
		if !errors.Is(err, masterkey.ErrUnknownKey) || !strings.Contains(err.Error(), k1.ID()) ||
			!strings.Contains(err.Error(), row.ID) || !strings.Contains(err.Error(), masterkey.DocLink) {
			t.Errorf("OpenSystem(unknown key) = %v", err)
		}
	})
}

func TestVaultSystemSecretsDuringRotation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		k1, k2 := newKey(t), newKey(t)
		if _, err := masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow); err != nil {
			t.Fatal(err)
		}
		old := vault(db, keyring(t, k1, nil))
		both := vault(db, keyring(t, k1, k2))
		underOld := sealSystem(t, db, old)
		underNew := sealSystem(t, db, both)
		if secretKeyIDOf(t, db, underNew) != k2.ID() {
			t.Fatal("the keyring with a new key must wrap system secrets with it")
		}
		expectSystemOpens(t, both, []sealedSystem{underOld, underNew})
		if _, err := old.OpenSystem(ctx, crypto.PurposeAdminTOTP, underNew.id); !errors.Is(err, masterkey.ErrUnknownKey) {
			t.Errorf("OpenSystem(secret under the new key, old keyring) = %v", err)
		}
	})
}

func TestRotateSystemSecretsInterruptedThenResumed(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		// Batches of one key: cancel once every tenant key and all but one of
		// the system secrets under k1 are re-wrapped.
		rctx, cancel := context.WithCancel(ctx)
		rot, err := masterkey.Rotate(rctx, f.db, f.both(t), nil, masterkey.Options{
			BatchSize: 1,
			OnProgress: func(r store.Rotation) {
				if r.RewrappedKeys == f.underOld-1 {
					cancel()
				}
			},
		})
		if !errors.Is(err, context.Canceled) || rot.Status != store.RotationRunning || rot.RewrappedKeys != f.underOld-1 {
			t.Fatalf("Rotate(canceled) = %+v, %v", rot, err)
		}
		if n, err := f.db.WrappedKeys().CountByKey(ctx, f.k1.ID()); err != nil || n != 1 {
			t.Fatalf("rows left under k1 = %d, %v", n, err)
		}
		under := map[string]int{}
		for _, s := range f.secrets {
			under[secretKeyIDOf(t, f.db, s)]++
		}
		if under[f.k1.ID()] != 1 || under[f.k2.ID()] != len(f.secrets)-1 {
			t.Fatalf("system secrets by master key = %v", under)
		}
		// Everything opens with both keys while the rotation is half done,
		// and the server may start.
		expectOpens(t, vault(f.db, f.both(t)), f.keys)
		expectSystemOpens(t, vault(f.db, f.both(t)), f.secrets)
		if _, err := masterkey.Check(ctx, f.db, f.both(t), nil, testNow); err != nil {
			t.Errorf("Check during the rotation = %v", err)
		}
		// The rotation cannot complete while a system secret is under k1.
		if err := f.db.KeyRotations().Complete(ctx, rot.ID, testNow); !errors.Is(err, store.ErrRotationIncomplete) {
			t.Errorf("Complete with a system secret left = %v", err)
		}

		resumed, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{BatchSize: 1})
		if err != nil || resumed.ID != rot.ID || resumed.Status != store.RotationCompleted || resumed.RewrappedKeys != f.underOld {
			t.Fatalf("Rotate(resume) = %+v, %v", resumed, err)
		}
		f.expectRotated(t)
	})
}

func TestRotateSystemSecretUnwrapFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		bad := store.SystemSecret{
			ID: id.New(id.SystemSecret), Purpose: store.SecretPurposeAdminTOTP, KeyID: f.k1.ID(),
			Blob: bytes.Repeat([]byte{1}, 49),
		}
		if err := f.db.SystemSecrets().Create(ctx, bad); err != nil {
			t.Fatal(err)
		}
		rot, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{BatchSize: 100})
		if !errors.Is(err, masterkey.ErrRewrap) || !errors.Is(err, crypto.ErrUnwrap) || rot.Status != store.RotationFailed {
			t.Fatalf("Rotate = %+v, %v", rot, err)
		}
		for _, s := range []string{"system secret " + bad.ID, f.k1.ID()} {
			if !strings.Contains(err.Error(), s) || !strings.Contains(rot.Error, s) {
				t.Errorf("error %q / %q lacks %q", err, rot.Error, s)
			}
		}
		// The tenant keys were re-wrapped, the failed batch of system
		// secrets was rolled back.
		stored, err := f.db.KeyRotations().Get(ctx, rot.ID)
		if err != nil || stored.Status != store.RotationFailed || stored.RewrappedKeys != f.underOld-f.systemUnderOld {
			t.Errorf("stored rotation = %+v, %v", stored, err)
		}
		expectOpens(t, vault(f.db, f.both(t)), f.keys)
		expectSystemOpens(t, vault(f.db, f.both(t)), f.secrets)
	})
}

func TestRecoverSystemSecret(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		f := newFixture(t, e)
		if _, err := masterkey.Rotate(ctx, f.db, f.both(t), nil, masterkey.Options{}); err != nil {
			t.Fatal(err)
		}
		f.secrets = append(f.secrets, plantSystemStraggler(t, e, f.db, f.k1))
		onlyK2 := keyring(t, f.k2, nil)
		_, err := masterkey.Check(ctx, f.db, onlyK2, nil, testNow)
		expectCheckError(t, err, masterkey.ReasonMissingKey, f.k1.ID())

		rot, err := masterkey.Recover(ctx, f.db, onlyK2, f.k1, nil, masterkey.Options{})
		if err != nil || rot.Status != store.RotationCompleted || rot.TotalKeys != 1 || rot.RewrappedKeys != 1 {
			t.Fatalf("Recover = %+v, %v", rot, err)
		}
		f.expectRotated(t)
		if _, err := masterkey.Check(ctx, f.db, onlyK2, nil, testNow); err != nil {
			t.Errorf("Check after the recovery = %v", err)
		}
	})
}

func TestAbandonRefusedAfterSystemSecretsRewrapped(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		k1, k2 := newKey(t), newKey(t)
		if _, err := masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow); err != nil {
			t.Fatal(err)
		}
		old := vault(db, keyring(t, k1, nil))
		secrets := []sealedSystem{sealSystem(t, db, old), sealSystem(t, db, old)}
		// Only system secrets: the first one is re-wrapped, then the
		// rotation is interrupted.
		rctx, cancel := context.WithCancel(ctx)
		rot, err := masterkey.Rotate(rctx, db, keyring(t, k1, k2), nil, masterkey.Options{
			BatchSize: 1, OnProgress: func(store.Rotation) { cancel() },
		})
		if !errors.Is(err, context.Canceled) || rot.TotalKeys != 2 || rot.RewrappedKeys != 1 {
			t.Fatalf("Rotate(canceled) = %+v, %v", rot, err)
		}
		_, err = masterkey.Abandon(ctx, db, testNow)
		if !errors.Is(err, masterkey.ErrCannotAbandon) || !strings.Contains(err.Error(), k2.ID()) {
			t.Fatalf("Abandon(system secret under the target) = %v", err)
		}
		// Without the new key the server refuses to start.
		_, err = masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonRotationMismatch, k2.ID())

		done, err := masterkey.Rotate(ctx, db, keyring(t, k1, k2), nil, masterkey.Options{})
		if err != nil || done.ID != rot.ID || done.Status != store.RotationCompleted || done.RewrappedKeys != 2 {
			t.Fatalf("Rotate(resume) = %+v, %v", done, err)
		}
		expectSystemOpens(t, vault(db, keyring(t, k2, nil)), secrets)
	})
}

func TestCheckSystemSecrets(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		k1, k2 := newKey(t), newKey(t)

		// No master key registered yet, but a system secret under k1: k2 is
		// refused and not registered.
		sealSystem(t, db, vault(db, keyring(t, k1, nil)))
		_, err := masterkey.Check(ctx, db, keyring(t, k2, nil), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonMissingKey, k1.ID())

		// k1 registers; then a keyring without k1 is refused, naming it.
		if rep, err := masterkey.Check(ctx, db, keyring(t, k1, nil), nil, testNow); err != nil || !rep.Registered {
			t.Fatalf("Check(k1) = %+v, %v", rep, err)
		}
		_, err = masterkey.Check(ctx, db, keyring(t, k2, nil), nil, testNow)
		expectCheckError(t, err, masterkey.ReasonMissingKey, k1.ID())
	})
}

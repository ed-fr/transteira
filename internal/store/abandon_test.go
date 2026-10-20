package store

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestStartKeyRules covers the pairs of keys Start accepts: a regular
// rotation (active to unregistered) and a clean-up rotation (retired to
// active), and nothing else.
func TestStartKeyRules(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		rots := db.KeyRotations()
		start := func(from, to string) error {
			return rots.Start(ctx, Rotation{ID: id.New(id.Rotation), FromKeyID: from, ToKeyID: to})
		}
		// Nothing registered: the source is not the active key.
		if err := start(testMK1, testMK2); !errors.Is(err, ErrRotationKeys) {
			t.Errorf("Start(unregistered source) = %v, want ErrRotationKeys", err)
		}
		if _, err := db.MasterKeys().EnsureActive(ctx, testMK1, time.Now()); err != nil {
			t.Fatal(err)
		}
		// Regular rotation MK1 (active) -> MK2, completed: MK1 retired.
		rot := Rotation{ID: id.New(id.Rotation), FromKeyID: testMK1, ToKeyID: testMK2}
		if err := rots.Start(ctx, rot); err != nil {
			t.Fatalf("Start(regular) = %v", err)
		}
		if err := rots.Complete(ctx, rot.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
		for _, tt := range []struct {
			from, to string
			want     error
		}{
			{testMK3, testMK1, ErrKeyRetired},   // retired target
			{testMK3, testMK2, ErrRotationKeys}, // unregistered source to the active key
			{testMK1, testMK3, ErrRotationKeys}, // retired source to an unregistered key
			{testMK3, "mk_4444444444444444", ErrRotationKeys},
		} {
			if err := start(tt.from, tt.to); !errors.Is(err, tt.want) {
				t.Errorf("Start(%s -> %s) = %v, want %v", tt.from, tt.to, err, tt.want)
			}
		}
		// Clean-up rotation MK1 (retired) -> MK2 (active).
		if err := start(testMK1, testMK2); err != nil {
			t.Errorf("Start(clean-up) = %v", err)
		}
	})
}

// TestAbandon covers the abandon rule: a rotation whose target is not
// registered is abandoned only while no key uses it; a clean-up rotation
// (target active) always is.
func TestAbandon(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		keys, rots := db.WrappedKeys(), db.KeyRotations()
		if _, err := db.MasterKeys().EnsureActive(ctx, testMK1, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := rots.Abandon(ctx, id.New(id.Rotation), "x", time.Now()); !errors.Is(err, ErrNotFound) {
			t.Errorf("Abandon(unknown) = %v", err)
		}

		// Regular rotation to MK2, nothing under MK2: abandoned.
		rot := Rotation{ID: id.New(id.Rotation), FromKeyID: testMK1, ToKeyID: testMK2}
		if err := rots.Start(ctx, rot); err != nil {
			t.Fatal(err)
		}
		if err := rots.Abandon(ctx, rot.ID, strings.Repeat("é", maxRotationErrorLen), time.Now()); err != nil {
			t.Fatalf("Abandon(unused target) = %v", err)
		}
		if got, err := rots.Get(ctx, rot.ID); err != nil || got.Status != RotationFailed || len(got.Error) > maxRotationErrorLen {
			t.Errorf("abandoned rotation = %+v, %v", got, err)
		}
		if err := rots.Abandon(ctx, rot.ID, "x", time.Now()); !errors.Is(err, ErrRotationNotRunning) {
			t.Errorf("Abandon(failed) = %v", err)
		}

		// Regular rotation to MK2 with a key under MK2: refused.
		rot = Rotation{ID: id.New(id.Rotation), FromKeyID: testMK1, ToKeyID: testMK2}
		if err := rots.Start(ctx, rot); err != nil {
			t.Fatal(err)
		}
		if err := keys.Create(ctx, tn.ID, WrappedKey{ID: id.New(id.WrappedKey), Purpose: KeyPurposeDEK, KeyID: testMK2, Blob: []byte("b")}); err != nil {
			t.Fatal(err)
		}
		err = rots.Abandon(ctx, rot.ID, "x", time.Now())
		if !errors.Is(err, ErrRotationInUse) || !strings.Contains(err.Error(), "1 key(s)") || !strings.Contains(err.Error(), testMK2) {
			t.Errorf("Abandon(used target) = %v", err)
		}
		if _, err := rots.RewrapBatch(ctx, rot.ID, testMK1, testMK2, 100, identityRewrap); err != nil {
			t.Fatal(err)
		}
		if err := rots.Complete(ctx, rot.ID, time.Now()); err != nil {
			t.Fatal(err)
		}

		// Clean-up rotation MK1 (retired) -> MK2 (active, used): abandoned.
		rot = Rotation{ID: id.New(id.Rotation), FromKeyID: testMK1, ToKeyID: testMK2}
		if err := rots.Start(ctx, rot); err != nil {
			t.Fatal(err)
		}
		if err := rots.Abandon(ctx, rot.ID, "x", time.Now()); err != nil {
			t.Errorf("Abandon(clean-up) = %v", err)
		}
		if active, err := db.MasterKeys().Active(ctx); err != nil || active != testMK2 {
			t.Errorf("Active after abandoning the clean-up = %q, %v", active, err)
		}
	})
}

// TestTenantDeleteScrubs covers the scrub after a tenant deletion: a busy
// checkpoint is a warning, a failure is returned.
func TestTenantDeleteScrubs(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, scrub, wantLog string
		wantErr              bool
	}{
		{"busy", "SELECT 1, 10, 5", "may remain in the database WAL", false},
		{"failure", "SELECT no_such_column", "", true},
		{"done", "SELECT 0, 0, 0", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			db, _ := openFault(t, WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
			ctx := context.Background()
			d := *db.dialect
			d.scrubDeleted = tt.scrub
			db.dialect = &d
			tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
			if err != nil {
				t.Fatal(err)
			}
			err = db.Tenants().Delete(ctx, tn.ID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Delete = %v, want error %v", err, tt.wantErr)
			}
			if !strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("logs = %s, want %q", logs.String(), tt.wantLog)
			}
			if _, err := db.Tenants().Get(ctx, tn.ID); !errors.Is(err, ErrNotFound) {
				t.Errorf("tenant still there: %v", err)
			}
		})
	}
}

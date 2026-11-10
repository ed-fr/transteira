package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// activationColumns reads the delivery and language columns of the link.
func activationColumns(t *testing.T, db *DB, hash []byte) (delivery string, language sql.NullString) {
	t.Helper()
	ctx := context.Background()
	found := false
	err := db.runTx(ctx, db.read, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT token_hash, delivery, language FROM admin_activations`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var h []byte
			var d string
			var l sql.NullString
			if err := rows.Scan(&h, &d, &l); err != nil {
				return err
			}
			if bytes.Equal(h, hash) {
				delivery, language, found = d, l, true
			}
		}
		return rows.Err()
	})
	if err != nil || !found {
		t.Fatalf("read activation: found=%v err=%v", found, err)
	}
	return delivery, language
}

// TestAdminActivationDelivery checks that the delivery and the language of
// an activation link are validated and stored (migration 0024), and that an
// empty delivery means a copied link.
func TestAdminActivationDelivery(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openMigratedEngine(t, e, WithClock(func() time.Time { return adminTestNow }))
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{SetupState: tenant.SetupStateActive, Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		adm, err := db.Admins().Create(ctx, Admin{Username: "delegated", Email: "d@example.com", Role: RoleDelegatedAdmin, TenantIDs: []tenant.ID{tn.ID}})
		if err != nil {
			t.Fatal(err)
		}
		act := func(token string, d ActivationDelivery, lang string) AdminActivation {
			return AdminActivation{
				ID: id.New(id.AdminActivation), AdminID: adm.ID, TokenHash: hashOf(token),
				CreatedAt: adminTestNow, ExpiresAt: adminTestNow.Add(time.Hour), Delivery: d, Language: lang,
			}
		}
		for _, tc := range []struct {
			name         string
			in           AdminActivation
			wantDelivery string
			wantLanguage string
		}{
			{"empty means copy", act("t1", "", ""), "copy", ""},
			{"copy", act("t2", DeliveryCopy, ""), "copy", ""},
			{"mail", act("t3", DeliveryMail, "fr"), "mail", "fr"},
			{"mail, longest language", act("t4", DeliveryMail, "abcdefghijklmnop"), "mail", "abcdefghijklmnop"},
		} {
			if err := db.AdminActivations().Create(ctx, tc.in); err != nil {
				t.Errorf("%s: Create = %v", tc.name, err)
				continue
			}
			d, l := activationColumns(t, db, tc.in.TokenHash)
			if d != tc.wantDelivery || l.String != tc.wantLanguage || l.Valid != (tc.wantLanguage != "") {
				t.Errorf("%s: stored (%q, %+v), want (%q, %q)", tc.name, d, l, tc.wantDelivery, tc.wantLanguage)
			}
		}
		// Through a transaction as well.
		tx3 := act("t5", DeliveryMail, "en")
		err = db.Admins().Tx(ctx, func(tx *SystemTx) error { return db.AdminActivations().CreateTx(ctx, tx, tx3) })
		if err != nil {
			t.Fatalf("CreateTx = %v", err)
		}
		if d, l := activationColumns(t, db, tx3.TokenHash); d != "mail" || l.String != "en" {
			t.Errorf("CreateTx stored (%q, %+v)", d, l)
		}

		for name, in := range map[string]AdminActivation{
			"unknown delivery":      act("b1", "pigeon", ""),
			"copy with a language":  act("b2", DeliveryCopy, "fr"),
			"empty with language":   act("b3", "", "fr"),
			"mail without language": act("b4", DeliveryMail, ""),
			"mail, 1 byte":          act("b5", DeliveryMail, "f"),
			"mail, 17 bytes":        act("b6", DeliveryMail, "abcdefghijklmnopq"),
		} {
			if err := db.AdminActivations().Create(ctx, in); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: Create = %v, want ErrInvalid", name, err)
			}
		}
	})
}

// TestTenantsCreateWith checks that the callback runs in the transaction
// creating the tenant: committed with it, rolled back with it on error, with
// the after-commit hooks run only on success.
func TestTenantsCreateWith(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openMigratedEngine(t, e, WithClock(func() time.Time { return adminTestNow }))
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		newT := func(fqdn string) *tenant.Tenant {
			return &tenant.Tenant{SetupState: tenant.SetupStateActive, Name: "T", FQDN: fqdn, DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1}
		}

		// nil callback: Create.
		a, err := db.Tenants().CreateWith(ctx, newT("a.example.com"), nil)
		if err != nil || a.ID.IsZero() {
			t.Fatalf("CreateWith(nil) = %v, %v", a, err)
		}

		// Callback: sees the stored tenant, its writes are committed with it,
		// the hooks run after the commit.
		var (
			seen   *tenant.Tenant
			hooked bool
			admin  Admin
		)
		b, err := db.Tenants().CreateWith(ctx, newT("b.example.com"), func(tx *SystemTx, created *tenant.Tenant) error {
			seen = created
			var err error
			admin, err = db.Admins().CreateTx(ctx, tx, Admin{Username: "first", Email: "f@example.com", Role: RoleDelegatedAdmin, TenantIDs: []tenant.ID{created.ID}})
			tx.AfterCommit(func() { hooked = true })
			if hooked {
				t.Error("hook ran before the commit")
			}
			return err
		})
		if err != nil || seen == nil || seen.ID != b.ID || !hooked {
			t.Fatalf("CreateWith = %v, %v (seen=%v hooked=%v)", b, err, seen, hooked)
		}
		if got, err := db.Admins().Get(ctx, admin.ID); err != nil || len(got.TenantIDs) != 1 || got.TenantIDs[0] != b.ID {
			t.Errorf("admin = %+v, %v", got, err)
		}

		// Error: everything is rolled back, no hook, the error is returned.
		boom := errors.New("boom")
		hooked = false
		_, err = db.Tenants().CreateWith(ctx, newT("c.example.com"), func(tx *SystemTx, created *tenant.Tenant) error {
			if _, err := db.Admins().CreateTx(ctx, tx, Admin{Username: "second", Email: "s@example.com", Role: RoleDelegatedAdmin, TenantIDs: []tenant.ID{created.ID}}); err != nil {
				return err
			}
			tx.AfterCommit(func() { hooked = true })
			return boom
		})
		if !errors.Is(err, boom) || hooked {
			t.Fatalf("CreateWith(error) = %v, hooked=%v", err, hooked)
		}
		if _, err := db.Tenants().TenantByFQDN(ctx, "c.example.com"); !errors.Is(err, ErrNotFound) {
			t.Errorf("tenant kept after the rollback: %v", err)
		}
		if _, err := db.Admins().GetByUsername(ctx, "second"); !errors.Is(err, ErrNotFound) {
			t.Errorf("admin kept after the rollback: %v", err)
		}
	})
}

// TestConsumeTxReturnsDelivery checks that consuming a link returns its
// admin and its delivery.
func TestConsumeTxReturnsDelivery(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openMigratedEngine(t, e, WithClock(func() time.Time { return adminTestNow }))
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{SetupState: tenant.SetupStateActive, Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		adm, err := db.Admins().Create(ctx, Admin{Username: "delegated", Email: "d@example.com", Role: RoleDelegatedAdmin, TenantIDs: []tenant.ID{tn.ID}})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			token string
			in    ActivationDelivery
			lang  string
			want  ActivationDelivery
		}{
			{"c1", "", "", DeliveryCopy},
			{"c2", DeliveryCopy, "", DeliveryCopy},
			{"m1", DeliveryMail, "fr", DeliveryMail},
		} {
			err := db.AdminActivations().Create(ctx, AdminActivation{
				ID: id.New(id.AdminActivation), AdminID: adm.ID, TokenHash: hashOf(tc.token),
				CreatedAt: adminTestNow, ExpiresAt: adminTestNow.Add(time.Hour), Delivery: tc.in, Language: tc.lang,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = db.Admins().Tx(ctx, func(tx *SystemTx) error {
				got, delivery, err := db.AdminActivations().ConsumeTx(ctx, tx, hashOf(tc.token), adminTestNow)
				if err == nil && (got != adm.ID || delivery != tc.want) {
					t.Errorf("%s: ConsumeTx = %q, %q, want %q, %q", tc.token, got, delivery, adm.ID, tc.want)
				}
				return err
			})
			if err != nil {
				t.Errorf("%s: %v", tc.token, err)
			}
		}
	})
}

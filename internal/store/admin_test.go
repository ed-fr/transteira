package store_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// testPHC is a syntactically valid password hash.
const testPHC = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"

// newSuperAdmin creates a usable super admin named username: a password
// and TOTP enabled.
func newSuperAdmin(t *testing.T, db *store.DB, username string) store.Admin {
	t.Helper()
	a, err := db.Admins().Create(context.Background(), store.Admin{
		Username: username, Email: username + "@example.com", Role: store.RoleSuperAdmin, PasswordHash: testPHC,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", username, err)
	}
	enableTOTP(t, db, a.ID)
	a.TOTPEnabled = true
	return a
}

// enableTOTP enrolls TOTP for adminID.
func enableTOTP(t *testing.T, db *store.DB, adminID string) {
	t.Helper()
	ctx := context.Background()
	s := newTOTPSecret("enabled")
	if err := db.Admins().SetPendingTOTP(ctx, adminID, s); err != nil {
		t.Fatal(err)
	}
	if err := db.Admins().SetTOTP(ctx, adminID, s.ID, 1); err != nil {
		t.Fatal(err)
	}
}

// usableSuperAdmins counts the usable super admins.
func usableSuperAdmins(t *testing.T, db *store.DB) int64 {
	t.Helper()
	var n int64
	err := db.Admins().Tx(context.Background(), func(tx *store.SystemTx) error {
		var err error
		n, err = db.Admins().CountUsableSuperAdminsTx(context.Background(), tx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// newDelegated creates a delegated admin attached to tids.
func newDelegated(t *testing.T, db *store.DB, username string, tids ...tenant.ID) store.Admin {
	t.Helper()
	a, err := db.Admins().Create(context.Background(), store.Admin{
		Username: username, Email: username + "@example.com", Role: store.RoleDelegatedAdmin, TenantIDs: tids, RequireTOTP: true,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", username, err)
	}
	return a
}

// newTOTPSecret returns a valid admin TOTP system secret under mk1.
func newTOTPSecret(blob string) store.SystemSecret {
	return store.SystemSecret{ID: id.New(id.SystemSecret), Purpose: store.SecretPurposeAdminTOTP, KeyID: mk1, Blob: []byte(blob)}
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T { return &v }

func TestAdminsCRUD(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Admins()
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		tb := newTenant(t, db, "transfer.entity-b.example.com")

		if n, err := repo.CountAll(ctx); err != nil || n != 0 {
			t.Fatalf("CountAll(empty) = %d, %v", n, err)
		}
		sa, err := repo.Create(ctx, store.Admin{
			Username: " SuperAdmin ", Email: "Root@Example.COM", Role: store.RoleSuperAdmin, PasswordHash: testPHC,
			Language: "fr",
		})
		if err != nil {
			t.Fatalf("Create(super) = %v", err)
		}
		ms := fixedNow.Truncate(time.Millisecond)
		if !id.Valid(id.Admin, sa.ID) || sa.Username != "superadmin" || sa.Email != "root@example.com" || !sa.RequireTOTP ||
			len(sa.TenantIDs) != 0 || sa.TOTPLastCounter != -1 || sa.TOTPEnabled || !sa.CreatedAt.Equal(ms) ||
			!sa.CredentialsChangedAt.Equal(ms) || sa.Language != "fr" {
			t.Errorf("created super admin = %+v", sa)
		}
		got, err := repo.Get(ctx, sa.ID)
		if err != nil || got.Username != sa.Username || got.PasswordHash != testPHC || !got.RequireTOTP ||
			got.TOTPLastCounter != -1 || !got.CredentialsChangedAt.Equal(ms) || got.TenantIDs == nil || !got.LastLoginAt.IsZero() {
			t.Errorf("Get = %+v, %v", got, err)
		}
		if _, err := repo.Create(ctx, store.Admin{Username: "SUPERADMIN", Email: "x@example.com", Role: store.RoleSuperAdmin}); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create(duplicate username) err = %v, want ErrConflict", err)
		}

		del, err := repo.Create(ctx, store.Admin{
			Username: "admin.entity-a", Email: "a@entity-a.example.com", Role: store.RoleDelegatedAdmin,
			TenantIDs: []tenant.ID{tb.ID, ta.ID, tb.ID},
		})
		if err != nil {
			t.Fatalf("Create(delegated) = %v", err)
		}
		want := []tenant.ID{ta.ID, tb.ID}
		slices.Sort(want)
		if !slices.Equal(del.TenantIDs, want) || del.RequireTOTP || !del.CredentialsChangedAt.IsZero() || del.PasswordHash != "" {
			t.Errorf("created delegated admin = %+v", del)
		}
		if ids, err := repo.TenantIDs(ctx, del.ID); err != nil || !slices.Equal(ids, want) {
			t.Errorf("TenantIDs = %v, %v", ids, err)
		}
		if got, err := repo.GetByUsername(ctx, "ADMIN.Entity-A"); err != nil || got.ID != del.ID || !slices.Equal(got.TenantIDs, want) {
			t.Errorf("GetByUsername = %+v, %v", got, err)
		}
		for _, u := range []string{"unknown", "é", ""} {
			if _, err := repo.GetByUsername(ctx, u); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("GetByUsername(%q) err = %v, want ErrNotFound", u, err)
			}
		}
		if _, err := repo.Get(ctx, id.New(id.Admin)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(unknown) err = %v", err)
		}

		// Validation.
		many := make([]tenant.ID, store.MaxAdminTenants+1)
		for i := range many {
			many[i] = ta.ID
		}
		bad := map[string]store.Admin{
			"username":        {Username: "a", Email: "a@example.com", Role: store.RoleSuperAdmin},
			"unicode":         {Username: "admKin", Email: "a@example.com", Role: store.RoleSuperAdmin},
			"email":           {Username: "valid", Email: "nope", Role: store.RoleSuperAdmin},
			"role":            {Username: "valid", Email: "a@example.com", Role: "auditor"},
			"super tenants":   {Username: "valid", Email: "a@example.com", Role: store.RoleSuperAdmin, TenantIDs: []tenant.ID{ta.ID}},
			"no tenants":      {Username: "valid", Email: "a@example.com", Role: store.RoleDelegatedAdmin},
			"bad tenant":      {Username: "valid", Email: "a@example.com", Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{"bogus"}},
			"too many":        {Username: "valid", Email: "a@example.com", Role: store.RoleDelegatedAdmin, TenantIDs: many},
			"hash":            {Username: "valid", Email: "a@example.com", Role: store.RoleSuperAdmin, PasswordHash: "plain"},
			"hash whitespace": {Username: "valid", Email: "a@example.com", Role: store.RoleSuperAdmin, PasswordHash: "$a b"},
			"language":        {Username: "valid", Email: "a@example.com", Role: store.RoleSuperAdmin, Language: "de"},
		}
		for name, a := range bad {
			if _, err := repo.Create(ctx, a); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Create(%s) err = %v, want ErrInvalid", name, err)
			}
		}
		_, err = repo.Create(ctx, store.Admin{
			Username: "ghost", Email: "g@example.com", Role: store.RoleDelegatedAdmin,
			TenantIDs: []tenant.ID{tenant.ID(id.New(id.Tenant))},
		})
		wantErr(t, "Create(unknown tenant)", err, store.ErrNotFound)

		// List, one per page.
		var seen []store.Admin
		cursor := ""
		for {
			page, err := repo.List(ctx, store.AdminListOptions{Cursor: cursor, Limit: 1})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			seen = append(seen, page.Items...)
			if cursor = page.NextCursor; cursor == "" {
				break
			}
		}
		if len(seen) != 2 {
			t.Fatalf("List saw %d admins", len(seen))
		}
		for _, a := range seen {
			if a.ID == del.ID && !slices.Equal(a.TenantIDs, want) || a.ID == sa.ID && len(a.TenantIDs) != 0 {
				t.Errorf("listed admin %+v", a)
			}
		}
		if page, err := repo.List(ctx, store.AdminListOptions{}); err != nil || len(page.Items) != 2 || page.NextCursor != "" {
			t.Errorf("List(all) = %+v, %v", page, err)
		}
		if page, err := repo.List(ctx, store.AdminListOptions{Cursor: seen[1].ID}); err != nil || len(page.Items) != 0 {
			t.Errorf("List(past the end) = %+v, %v", page, err)
		}
		_, err = repo.List(ctx, store.AdminListOptions{Cursor: "bogus"})
		wantErr(t, "List(bad cursor)", err, store.ErrInvalid)

		// Update.
		up, err := repo.Update(ctx, del.ID, store.AdminUpdate{
			Email: ptr("New@Entity-A.example.com"), TenantIDs: &[]tenant.ID{ta.ID}, RequireTOTP: ptr(true), Language: ptr("en"),
		})
		if err != nil || up.Email != "new@entity-a.example.com" || !slices.Equal(up.TenantIDs, []tenant.ID{ta.ID}) ||
			!up.RequireTOTP || up.Language != "en" {
			t.Errorf("Update = %+v, %v", up, err)
		}
		if got, _ := repo.Get(ctx, del.ID); got.Email != up.Email || !slices.Equal(got.TenantIDs, up.TenantIDs) || got.Language != "en" {
			t.Errorf("Get after Update = %+v", got)
		}
		if up, err := repo.Update(ctx, del.ID, store.AdminUpdate{Language: ptr("")}); err != nil || up.Language != "" {
			t.Errorf("Update(language default) = %+v, %v", up, err)
		}
		_, err = repo.Update(ctx, del.ID, store.AdminUpdate{TenantIDs: &[]tenant.ID{}})
		wantErr(t, "Update(no tenant)", err, store.ErrInvalid)
		_, err = repo.Update(ctx, del.ID, store.AdminUpdate{Role: ptr(store.RoleSuperAdmin), TenantIDs: &[]tenant.ID{ta.ID}})
		wantErr(t, "Update(super with tenants)", err, store.ErrInvalid)
		_, err = repo.Update(ctx, del.ID, store.AdminUpdate{Email: ptr("bad")})
		wantErr(t, "Update(bad email)", err, store.ErrInvalid)
		_, err = repo.Update(ctx, del.ID, store.AdminUpdate{TenantIDs: &[]tenant.ID{tenant.ID(id.New(id.Tenant))}})
		wantErr(t, "Update(unknown tenant)", err, store.ErrNotFound)
		_, err = repo.Update(ctx, id.New(id.Admin), store.AdminUpdate{})
		wantErr(t, "Update(unknown admin)", err, store.ErrNotFound)

		// Last super admin rule: only usable super admins count. Without
		// TOTP, sa is not usable yet, so nothing protects it.
		if n := usableSuperAdmins(t, db); n != 0 {
			t.Errorf("usable super admins without totp = %d", n)
		}
		enableTOTP(t, db, sa.ID)
		_, err = repo.Update(ctx, sa.ID, store.AdminUpdate{Disabled: ptr(true)})
		wantErr(t, "disable the last super admin", err, store.ErrLastSuperAdmin)
		_, err = repo.Update(ctx, sa.ID, store.AdminUpdate{Role: ptr(store.RoleDelegatedAdmin), TenantIDs: &[]tenant.ID{ta.ID}})
		wantErr(t, "demote the last super admin", err, store.ErrLastSuperAdmin)
		wantErr(t, "delete the last super admin", repo.Delete(ctx, sa.ID), store.ErrLastSuperAdmin)
		if up, err := repo.Update(ctx, sa.ID, store.AdminUpdate{RequireTOTP: ptr(false), Language: ptr("en")}); err != nil || !up.RequireTOTP {
			t.Errorf("Update(super require totp false) = %+v, %v; want forced true", up, err)
		}

		// Promotion needs an activated account with TOTP enabled.
		_, err = repo.Update(ctx, del.ID, store.AdminUpdate{Role: ptr(store.RoleSuperAdmin)})
		wantErr(t, "promote without password", err, store.ErrPromotionRefused)
		if err := repo.SetPassword(ctx, del.ID, testPHC); err != nil {
			t.Fatal(err)
		}
		_, err = repo.Update(ctx, del.ID, store.AdminUpdate{Role: ptr(store.RoleSuperAdmin)})
		wantErr(t, "promote without totp", err, store.ErrPromotionRefused)
		enableTOTP(t, db, del.ID)

		// Promotion clears the tenants; then there are two super admins.
		prom, err := repo.Update(ctx, del.ID, store.AdminUpdate{Role: ptr(store.RoleSuperAdmin), RequireTOTP: ptr(false)})
		if err != nil || prom.Role != store.RoleSuperAdmin || len(prom.TenantIDs) != 0 || !prom.RequireTOTP {
			t.Fatalf("Update(promote) = %+v, %v", prom, err)
		}
		if ids, _ := repo.TenantIDs(ctx, del.ID); len(ids) != 0 {
			t.Errorf("tenants after promotion = %v", ids)
		}
		if n := usableSuperAdmins(t, db); n != 2 {
			t.Errorf("usable super admins = %d, want 2", n)
		}
		if _, err := repo.Update(ctx, sa.ID, store.AdminUpdate{Disabled: ptr(true)}); err != nil {
			t.Errorf("disable one of two super admins: %v", err)
		}
		// Unusable super admins (disabled sa, one never activated) do not
		// count: del is the last usable one.
		if _, err := repo.Create(ctx, store.Admin{Username: "inactive", Email: "i@example.com", Role: store.RoleSuperAdmin}); err != nil {
			t.Fatal(err)
		}
		_, err = repo.Update(ctx, del.ID, store.AdminUpdate{Disabled: ptr(true)})
		wantErr(t, "disable the last usable super admin", err, store.ErrLastSuperAdmin)
		_, err = repo.Update(ctx, del.ID, store.AdminUpdate{Role: ptr(store.RoleDelegatedAdmin), TenantIDs: &[]tenant.ID{ta.ID}})
		wantErr(t, "demote the last usable super admin", err, store.ErrLastSuperAdmin)
		wantErr(t, "delete the last usable super admin", repo.Delete(ctx, del.ID), store.ErrLastSuperAdmin)
		inactive, err := repo.GetByUsername(ctx, "inactive")
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Delete(ctx, inactive.ID); err != nil {
			t.Errorf("Delete(unusable super admin) = %v", err)
		}
		// A disabled super admin is not counted: deleting it is allowed.
		if err := repo.Delete(ctx, sa.ID); err != nil {
			t.Errorf("Delete(disabled super admin) = %v", err)
		}
		wantErr(t, "Delete(unknown)", repo.Delete(ctx, sa.ID), store.ErrNotFound)

		// Demotion back to delegated admin.
		dem, err := repo.Update(ctx, newSuperAdmin(t, db, "second").ID, store.AdminUpdate{
			Role: ptr(store.RoleDelegatedAdmin), TenantIDs: &[]tenant.ID{tb.ID}, RequireTOTP: ptr(false),
		})
		if err != nil || dem.Role != store.RoleDelegatedAdmin || dem.RequireTOTP || !slices.Equal(dem.TenantIDs, []tenant.ID{tb.ID}) {
			t.Errorf("Update(demote) = %+v, %v", dem, err)
		}

		// Password, login.
		if err := repo.SetPassword(ctx, dem.ID, testPHC); err != nil {
			t.Errorf("SetPassword = %v", err)
		}
		if got, _ := repo.Get(ctx, dem.ID); got.PasswordHash != testPHC || !got.CredentialsChangedAt.Equal(ms) {
			t.Errorf("after SetPassword = %+v", got)
		}
		wantErr(t, "SetPassword(bad hash)", repo.SetPassword(ctx, dem.ID, "x"), store.ErrInvalid)
		wantErr(t, "SetPassword(unknown)", repo.SetPassword(ctx, id.New(id.Admin), testPHC), store.ErrNotFound)
		if err := repo.Tx(ctx, func(tx *store.SystemTx) error { return repo.SetPasswordTx(ctx, tx, dem.ID, "") }); err != nil {
			t.Errorf("SetPasswordTx(remove) = %v", err)
		}
		if got, _ := repo.Get(ctx, dem.ID); got.PasswordHash != "" {
			t.Errorf("password not removed: %+v", got)
		}
		err = repo.Tx(ctx, func(tx *store.SystemTx) error { return repo.SetPasswordTx(ctx, tx, dem.ID, "x") })
		wantErr(t, "SetPasswordTx(bad)", err, store.ErrInvalid)
		if err := repo.TouchLogin(ctx, dem.ID); err != nil {
			t.Errorf("TouchLogin = %v", err)
		}
		if got, _ := repo.Get(ctx, dem.ID); !got.LastLoginAt.Equal(ms) {
			t.Errorf("LastLoginAt = %v", got.LastLoginAt)
		}
		wantErr(t, "TouchLogin(unknown)", repo.TouchLogin(ctx, id.New(id.Admin)), store.ErrNotFound)

		// Tx variants.
		err = repo.Tx(ctx, func(tx *store.SystemTx) error {
			n, err := repo.CountAllTx(ctx, tx)
			if err != nil || n != 2 {
				t.Errorf("CountAllTx = %d, %v", n, err)
			}
			n, err = repo.CountUsableSuperAdminsTx(ctx, tx)
			if err != nil || n != 1 {
				t.Errorf("CountUsableSuperAdminsTx = %d, %v", n, err)
			}
			a, err := repo.CreateTx(ctx, tx, store.Admin{
				Username: "intx", Email: "i@example.com", Role: store.RoleDelegatedAdmin,
				TenantIDs: []tenant.ID{ta.ID},
			})
			if err != nil {
				return err
			}
			if got, err := repo.GetTx(ctx, tx, a.ID); err != nil || got.Username != "intx" {
				t.Errorf("GetTx = %+v, %v", got, err)
			}
			before, after, err := repo.UpdateTx(ctx, tx, a.ID, store.AdminUpdate{Disabled: ptr(true)})
			if err != nil || before.Disabled || !after.Disabled || before.ID != a.ID || after.ID != a.ID {
				t.Errorf("UpdateTx = %+v, %+v, %v", before, after, err)
			}
			return repo.DeleteTx(ctx, tx, a.ID)
		})
		if err != nil {
			t.Errorf("admin tx = %v", err)
		}
		err = repo.Tx(ctx, func(tx *store.SystemTx) error {
			_, err := repo.CreateTx(ctx, tx, store.Admin{Username: "x"})
			return err
		})
		wantErr(t, "CreateTx(invalid)", err, store.ErrInvalid)
		err = repo.Tx(ctx, func(tx *store.SystemTx) error { _, err := repo.GetTx(ctx, tx, id.New(id.Admin)); return err })
		wantErr(t, "GetTx(unknown)", err, store.ErrNotFound)
		err = repo.Tx(ctx, func(tx *store.SystemTx) error {
			_, _, err := repo.UpdateTx(ctx, tx, id.New(id.Admin), store.AdminUpdate{})
			return err
		})
		wantErr(t, "UpdateTx(unknown)", err, store.ErrNotFound)
		err = repo.Tx(ctx, func(tx *store.SystemTx) error { return repo.DeleteTx(ctx, tx, id.New(id.Admin)) })
		wantErr(t, "DeleteTx(unknown)", err, store.ErrNotFound)

		// Deleting a tenant removes the attachments.
		if err := db.Tenants().Delete(ctx, tb.ID); err != nil {
			t.Fatal(err)
		}
		if ids, err := repo.TenantIDs(ctx, dem.ID); err != nil || len(ids) != 0 {
			t.Errorf("tenants after tenant deletion = %v, %v", ids, err)
		}
	})
}

func TestNormalizeUsername(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ in, want string }{{"Admin.Entity-A", "admin.entity-a"}, {"\tabc ", "abc"}, {"a_b", "a_b"}} {
		if got, err := store.NormalizeUsername(c.in); err != nil || got != c.want {
			t.Errorf("NormalizeUsername(%q) = %q, %v", c.in, got, err)
		}
	}
	for _, in := range []string{"", "ab", ".abc", "abc def", "abcK", strings.Repeat("a", 65), "ab@c"} {
		if _, err := store.NormalizeUsername(in); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("NormalizeUsername(%q) err = %v", in, err)
		}
	}
}

func TestAdminTOTP(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo, secrets := db.Admins(), db.SystemSecrets()
		a := newDelegated(t, db, "root", newTenant(t, db, "transfer.entity-a.example.com").ID)

		if ok, err := repo.AdvanceTOTPCounter(ctx, a.ID, 1); err != nil || ok {
			t.Errorf("AdvanceTOTPCounter(not enrolled) = %v, %v", ok, err)
		}
		s1 := newTOTPSecret("first")
		if err := repo.SetPendingTOTP(ctx, a.ID, s1); err != nil {
			t.Fatalf("SetPendingTOTP = %v", err)
		}
		s2 := newTOTPSecret("second")
		if err := repo.SetPendingTOTP(ctx, a.ID, s2); err != nil {
			t.Fatalf("SetPendingTOTP(again) = %v", err)
		}
		if _, err := secrets.Get(ctx, s1.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("replaced pending secret still exists: %v", err)
		}
		if got, _ := repo.Get(ctx, a.ID); got.PendingTOTPSecretID != s2.ID || got.TOTPEnabled {
			t.Errorf("after SetPendingTOTP = %+v", got)
		}
		wantErr(t, "SetTOTP(stale pending)", repo.SetTOTP(ctx, a.ID, s1.ID, 10), store.ErrNotFound)
		wantErr(t, "SetTOTP(negative)", repo.SetTOTP(ctx, a.ID, s2.ID, -1), store.ErrInvalid)
		wantErr(t, "SetTOTP(unknown admin)", repo.SetTOTP(ctx, id.New(id.Admin), s2.ID, 1), store.ErrNotFound)
		if err := repo.SetTOTP(ctx, a.ID, s2.ID, 100); err != nil {
			t.Fatalf("SetTOTP = %v", err)
		}
		got, _ := repo.Get(ctx, a.ID)
		if !got.TOTPEnabled || got.TOTPSecretID != s2.ID || got.PendingTOTPSecretID != "" || got.TOTPLastCounter != 100 {
			t.Errorf("after SetTOTP = %+v", got)
		}

		// Replay refusal (T-60).
		for _, c := range []int64{100, 99} {
			if ok, err := repo.AdvanceTOTPCounter(ctx, a.ID, c); err != nil || ok {
				t.Errorf("AdvanceTOTPCounter(%d) = %v, %v; want refused", c, ok, err)
			}
		}
		if ok, err := repo.AdvanceTOTPCounter(ctx, a.ID, 101); err != nil || !ok {
			t.Errorf("AdvanceTOTPCounter(101) = %v, %v", ok, err)
		}
		if ok, err := repo.AdvanceTOTPCounter(ctx, a.ID, 101); err != nil || ok {
			t.Errorf("AdvanceTOTPCounter(101 replayed) = %v, %v", ok, err)
		}
		_, err := repo.AdvanceTOTPCounter(ctx, a.ID, -1)
		wantErr(t, "AdvanceTOTPCounter(negative)", err, store.ErrInvalid)
		// Concurrent logins with the same code: exactly one wins.
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 8 {
			wg.Go(func() {
				ok, err := repo.AdvanceTOTPCounter(ctx, a.ID, 200)
				if err != nil {
					t.Errorf("concurrent AdvanceTOTPCounter: %v", err)
				}
				if ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if wins != 1 {
			t.Errorf("%d concurrent logins accepted the same code, want 1", wins)
		}

		// Re-enrollment destroys the previous secret.
		s3 := newTOTPSecret("third")
		err = repo.Tx(ctx, func(tx *store.SystemTx) error {
			if err := repo.SetPendingTOTPTx(ctx, tx, a.ID, s3); err != nil {
				return err
			}
			return repo.SetTOTPTx(ctx, tx, a.ID, s3.ID, 300)
		})
		if err != nil {
			t.Fatalf("re-enrollment = %v", err)
		}
		if _, err := secrets.Get(ctx, s2.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("previous totp secret still exists: %v", err)
		}
		if err := db.AdminRecoveryCodes().Replace(ctx, a.ID, [][]byte{tokenHash("rc1")}); err != nil {
			t.Fatal(err)
		}
		// A pending enrollment while enrolled, then cleared.
		s4 := newTOTPSecret("fourth")
		if err := repo.SetPendingTOTP(ctx, a.ID, s4); err != nil {
			t.Fatal(err)
		}
		if err := repo.ClearTOTP(ctx, a.ID); err != nil {
			t.Fatalf("ClearTOTP = %v", err)
		}
		got, _ = repo.Get(ctx, a.ID)
		if got.TOTPEnabled || got.TOTPSecretID != "" || got.PendingTOTPSecretID != "" || got.TOTPLastCounter != -1 {
			t.Errorf("after ClearTOTP = %+v", got)
		}
		for _, s := range []string{s3.ID, s4.ID} {
			if _, err := secrets.Get(ctx, s); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("secret %s survived ClearTOTP: %v", s, err)
			}
		}
		if n, _ := db.AdminRecoveryCodes().CountUnused(ctx, a.ID); n != 0 {
			t.Errorf("%d recovery codes survived ClearTOTP", n)
		}
		if ok, _ := repo.AdvanceTOTPCounter(ctx, a.ID, 400); ok {
			t.Error("AdvanceTOTPCounter accepted after ClearTOTP")
		}
		wantErr(t, "ClearTOTP(unknown)", repo.ClearTOTP(ctx, id.New(id.Admin)), store.ErrNotFound)
		err = repo.Tx(ctx, func(tx *store.SystemTx) error { return repo.ClearTOTPTx(ctx, tx, id.New(id.Admin)) })
		wantErr(t, "ClearTOTPTx(unknown)", err, store.ErrNotFound)
		err = repo.Tx(ctx, func(tx *store.SystemTx) error { return repo.SetTOTPTx(ctx, tx, a.ID, "", -1) })
		wantErr(t, "SetTOTPTx(negative)", err, store.ErrInvalid)

		wantErr(t, "SetPendingTOTP(unknown admin)", repo.SetPendingTOTP(ctx, id.New(id.Admin), newTOTPSecret("x")), store.ErrNotFound)
		bad := newTOTPSecret("x")
		bad.Purpose = "secret"
		wantErr(t, "SetPendingTOTP(bad purpose)", repo.SetPendingTOTP(ctx, a.ID, bad), store.ErrInvalid)
		err = repo.Tx(ctx, func(tx *store.SystemTx) error { return repo.SetPendingTOTPTx(ctx, tx, a.ID, bad) })
		wantErr(t, "SetPendingTOTPTx(bad purpose)", err, store.ErrInvalid)

		// Deleting the admin destroys its secrets.
		s5 := newTOTPSecret("fifth")
		if err := repo.SetPendingTOTP(ctx, a.ID, s5); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetTOTP(ctx, a.ID, s5.ID, 500); err != nil {
			t.Fatal(err)
		}
		s6 := newTOTPSecret("sixth")
		if err := repo.SetPendingTOTP(ctx, a.ID, s6); err != nil {
			t.Fatal(err)
		}
		newSuperAdmin(t, db, "other")
		if err := repo.Delete(ctx, a.ID); err != nil {
			t.Fatalf("Delete = %v", err)
		}
		for _, s := range []string{s5.ID, s6.ID} {
			if _, err := secrets.Get(ctx, s); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("secret %s survived the admin: %v", s, err)
			}
		}
	})
}

// TestAdminSetupConcurrency runs concurrent first-run setups: only one may
// create an administrator.
func TestAdminSetupConcurrency(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Admins()
		errDone := errors.New("setup already done")
		const n = 8
		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			wins int
		)
		for i := range n {
			wg.Go(func() {
				err := repo.Tx(ctx, func(tx *store.SystemTx) error {
					count, err := repo.CountAllTx(ctx, tx)
					if err != nil {
						return err
					}
					if count > 0 {
						return errDone
					}
					_, err = repo.CreateTx(ctx, tx, store.Admin{
						Username: "root" + string(rune('a'+i)), Email: "root@example.com", Role: store.RoleSuperAdmin, PasswordHash: testPHC,
					})
					return err
				})
				switch {
				case err == nil:
					mu.Lock()
					wins++
					mu.Unlock()
				case !errors.Is(err, errDone):
					t.Errorf("setup: %v", err)
				}
			})
		}
		wg.Wait()
		if count, err := repo.CountAll(ctx); wins != 1 || count != 1 || err != nil {
			t.Errorf("%d setups succeeded, %d admins (%v); want exactly 1", wins, count, err)
		}
	})
}

// holdTx runs first in an admin transaction, signals once it returned,
// keeps the transaction open for a while, then commits. It returns the
// error of the transaction on the channel.
func holdTx(ctx context.Context, db *store.DB, first func(*store.SystemTx) error) (started <-chan struct{}, done <-chan error) {
	s, d := make(chan struct{}), make(chan error, 1)
	go func() {
		d <- db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			err := first(tx)
			close(s)
			time.Sleep(300 * time.Millisecond)
			return err
		})
	}()
	return s, d
}

// TestAdminLocksSerialize checks the administrators lock deterministically:
// a transaction that counts or changes super admins waits for another one
// holding the lock, then sees its committed changes (PostgreSQL READ
// COMMITTED; SQLite serializes writers anyway).
func TestAdminLocksSerialize(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Admins()

		// Setup: the second setup counts the admin created by the first.
		started, done := holdTx(ctx, db, func(tx *store.SystemTx) error {
			if n, err := repo.CountAllTx(ctx, tx); err != nil || n != 0 {
				t.Errorf("first CountAllTx = %d, %v", n, err)
			}
			_, err := repo.CreateTx(ctx, tx, store.Admin{Username: "first", Email: "f@example.com", Role: store.RoleSuperAdmin})
			return err
		})
		<-started
		err := repo.Tx(ctx, func(tx *store.SystemTx) error {
			n, err := repo.CountAllTx(ctx, tx)
			if err == nil && n != 1 {
				t.Errorf("second setup counted %d admins, want 1: the setup lock does not serialize", n)
			}
			return err
		})
		if err != nil || <-done != nil {
			t.Fatalf("setups: %v", err)
		}

		// Last super admin: B cannot be disabled while A's disabling holds
		// the lock, then commits.
		a := newSuperAdmin(t, db, "alpha")
		first, _ := repo.GetByUsername(ctx, "first")
		if err := repo.Delete(ctx, first.ID); err != nil {
			t.Fatal(err)
		}
		b := newSuperAdmin(t, db, "bravo")
		started, done = holdTx(ctx, db, func(tx *store.SystemTx) error {
			_, _, err := repo.UpdateTx(ctx, tx, a.ID, store.AdminUpdate{Disabled: ptr(true)})
			return err
		})
		<-started
		_, err = repo.Update(ctx, b.ID, store.AdminUpdate{Disabled: ptr(true)})
		wantErr(t, "disable the other super admin concurrently", err, store.ErrLastSuperAdmin)
		if err := <-done; err != nil {
			t.Fatalf("first disabling: %v", err)
		}
		if n := usableSuperAdmins(t, db); n != 1 {
			t.Errorf("usable super admins = %d, want 1", n)
		}
	})
}

// TestLastSuperAdminConcurrency disables two super admins concurrently,
// each by the other: one must fail.
func TestLastSuperAdminConcurrency(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a, b := newSuperAdmin(t, db, "alpha"), newSuperAdmin(t, db, "bravo")
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, target := range []string{a.ID, b.ID} {
			wg.Go(func() {
				_, errs[i] = db.Admins().Update(ctx, target, store.AdminUpdate{Disabled: ptr(true)})
			})
		}
		wg.Wait()
		ok, refused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrLastSuperAdmin):
				refused++
			default:
				t.Errorf("Update: %v", err)
			}
		}
		if n := usableSuperAdmins(t, db); ok != 1 || refused != 1 || n != 1 {
			t.Errorf("ok %d, refused %d, usable super admins %d; want 1, 1, 1", ok, refused, n)
		}
	})
}

// TestTOTPSecretsConcurrency starts and clears enrollments of one account
// concurrently: the administrators lock serializes the reads of the secret
// IDs with their replacement, so that no system secret is left orphaned
// (PostgreSQL READ COMMITTED would otherwise let two transactions destroy
// the same old secret and both keep their new one).
func TestTOTPSecretsConcurrency(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newSuperAdmin(t, db, "root")
		const workers = 8
		secrets := make([]store.SystemSecret, workers)
		errs := make([]error, workers)
		var wg sync.WaitGroup
		for i := range workers {
			secrets[i] = newTOTPSecret("concurrent")
			wg.Go(func() {
				if i%4 == 3 {
					errs[i] = db.Admins().ClearTOTP(ctx, a.ID)
					return
				}
				errs[i] = db.Admins().SetPendingTOTP(ctx, a.ID, secrets[i])
			})
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("worker %d: %v", i, err)
			}
		}
		got, err := db.Admins().Get(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range secrets {
			_, err := db.SystemSecrets().Get(ctx, s.ID)
			kept := err == nil
			if referenced := s.ID == got.PendingTOTPSecretID || s.ID == got.TOTPSecretID; kept != referenced || (!kept && !errors.Is(err, store.ErrNotFound)) {
				t.Errorf("secret %d: kept %v, referenced %v (%v)", i, kept, referenced, err)
			}
		}
	})
}

// newAdminSession returns a valid authenticated session of adminID created
// at msNow, expiring 12 hours later.
func newAdminSession(adminID, token string) store.AdminSession {
	return store.AdminSession{
		ID: id.New(id.AdminSession), TokenHash: tokenHash(token), AdminID: adminID, State: store.SessionAuthenticated,
		CreatedAt: msNow, ExpiresAt: msNow.Add(12 * time.Hour),
	}
}

func TestAdminSessions(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AdminSessions()
		a := newSuperAdmin(t, db, "root")
		const idle = 30 * time.Minute

		s := newAdminSession(a.ID, "tok-1")
		s.ClientIP = netip.MustParseAddr("::ffff:192.0.2.7")
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create = %v", err)
		}
		got, err := repo.GetByTokenHash(ctx, tokenHash("tok-1"), msNow.Add(time.Minute), idle)
		if err != nil || got.ID != s.ID || got.AdminID != a.ID || got.State != store.SessionAuthenticated ||
			!got.LastSeenAt.Equal(msNow) || !got.StateExpiresAt.IsZero() || got.ClientIP != netip.MustParseAddr("192.0.2.7") ||
			!got.ExpiresAt.Equal(s.ExpiresAt) {
			t.Errorf("GetByTokenHash = %+v, %v", got, err)
		}
		_, err = repo.GetByTokenHash(ctx, tokenHash("tok-1"), msNow.Add(idle), idle)
		wantErr(t, "GetByTokenHash(idle)", err, store.ErrNotFound)
		_, err = repo.GetByTokenHash(ctx, []byte("short"), msNow, idle)
		wantErr(t, "GetByTokenHash(bad hash)", err, store.ErrInvalid)

		// Touch slides the idle timeout, never past the absolute expiry.
		if err := repo.Touch(ctx, s.ID, msNow.Add(20*time.Minute), idle); err != nil {
			t.Fatalf("Touch = %v", err)
		}
		if _, err := repo.GetByTokenHash(ctx, tokenHash("tok-1"), msNow.Add(40*time.Minute), idle); err != nil {
			t.Errorf("GetByTokenHash after Touch = %v", err)
		}
		wantErr(t, "Touch(idle)", repo.Touch(ctx, s.ID, msNow.Add(time.Hour), idle), store.ErrNotFound)
		wantErr(t, "Touch(absolute)", repo.Touch(ctx, s.ID, msNow.Add(12*time.Hour), 24*time.Hour), store.ErrNotFound)
		_, err = repo.GetByTokenHash(ctx, tokenHash("tok-1"), msNow.Add(12*time.Hour), 24*time.Hour)
		wantErr(t, "GetByTokenHash(absolute)", err, store.ErrNotFound)

		// Intermediate state, then rotation.
		p := newAdminSession(a.ID, "tok-2")
		p.State, p.StateExpiresAt = store.SessionTOTPRequired, msNow.Add(5*time.Minute)
		if err := repo.Create(ctx, p); err != nil {
			t.Fatalf("Create(intermediate) = %v", err)
		}
		if got, err := repo.GetByTokenHash(ctx, tokenHash("tok-2"), msNow, idle); err != nil || !got.StateExpiresAt.Equal(p.StateExpiresAt) ||
			got.ClientIP.IsValid() {
			t.Errorf("GetByTokenHash(intermediate) = %+v, %v", got, err)
		}
		_, err = repo.GetByTokenHash(ctx, tokenHash("tok-2"), msNow.Add(5*time.Minute), idle)
		wantErr(t, "GetByTokenHash(state expired)", err, store.ErrNotFound)
		for i := 1; i <= 2; i++ {
			if n, err := repo.IncrementTOTPFailures(ctx, p.ID); err != nil || n != i {
				t.Errorf("IncrementTOTPFailures = %d, %v; want %d", n, err, i)
			}
		}
		_, err = repo.IncrementTOTPFailures(ctx, id.New(id.AdminSession))
		wantErr(t, "IncrementTOTPFailures(unknown)", err, store.ErrNotFound)
		at := msNow.Add(time.Minute)
		if err := repo.Rotate(ctx, p.ID, tokenHash("tok-2"), tokenHash("tok-3"), store.SessionAuthenticated, time.Time{}, at, idle); err != nil {
			t.Fatalf("Rotate = %v", err)
		}
		_, err = repo.GetByTokenHash(ctx, tokenHash("tok-2"), at, idle)
		wantErr(t, "old token after Rotate", err, store.ErrNotFound)
		got, err = repo.GetByTokenHash(ctx, tokenHash("tok-3"), msNow.Add(10*time.Minute), idle)
		if err != nil || got.State != store.SessionAuthenticated || got.TOTPFailures != 0 || !got.LastSeenAt.Equal(at) {
			t.Errorf("after Rotate = %+v, %v", got, err)
		}
		err = repo.Rotate(ctx, p.ID, tokenHash("tok-2"), tokenHash("tok-4"), store.SessionAuthenticated, time.Time{}, at, idle)
		wantErr(t, "Rotate(stale token)", err, store.ErrNotFound)
		err = repo.Rotate(ctx, p.ID, tokenHash("tok-3"), tokenHash("tok-1"), store.SessionAuthenticated, time.Time{}, at, idle)
		wantErr(t, "Rotate(duplicate hash)", err, store.ErrConflict)
		err = repo.Rotate(ctx, p.ID, []byte("x"), tokenHash("tok-4"), store.SessionAuthenticated, time.Time{}, at, idle)
		wantErr(t, "Rotate(bad hash)", err, store.ErrInvalid)
		err = repo.Rotate(ctx, p.ID, tokenHash("tok-3"), tokenHash("tok-4"), store.SessionTOTPRequired, time.Time{}, at, idle)
		wantErr(t, "Rotate(intermediate without expiry)", err, store.ErrInvalid)
		// Rotation into an intermediate state (setup: enrollment required),
		// then back.
		if err := repo.Rotate(ctx, p.ID, tokenHash("tok-3"), tokenHash("tok-5"), store.SessionTOTPEnrollmentRequired,
			at.Add(5*time.Minute), at, idle); err != nil {
			t.Fatalf("Rotate(enrollment) = %v", err)
		}
		if got, err := repo.GetByTokenHash(ctx, tokenHash("tok-5"), at, idle); err != nil ||
			got.State != store.SessionTOTPEnrollmentRequired || !got.StateExpiresAt.Equal(at.Add(5*time.Minute)) {
			t.Errorf("after Rotate(enrollment) = %+v, %v", got, err)
		}
		if err := repo.Rotate(ctx, p.ID, tokenHash("tok-5"), tokenHash("tok-3"), store.SessionAuthenticated, time.Time{}, at, idle); err != nil {
			t.Fatalf("Rotate(back) = %v", err)
		}

		// Validation.
		bad := map[string]func(*store.AdminSession){
			"id":            func(s *store.AdminSession) { s.ID = "bogus" },
			"hash":          func(s *store.AdminSession) { s.TokenHash = []byte("x") },
			"admin":         func(s *store.AdminSession) { s.AdminID = "bogus" },
			"expiry":        func(s *store.AdminSession) { s.ExpiresAt = s.CreatedAt },
			"failures":      func(s *store.AdminSession) { s.TOTPFailures = 1 },
			"state":         func(s *store.AdminSession) { s.State = "bogus" },
			"auth expiry":   func(s *store.AdminSession) { s.StateExpiresAt = msNow.Add(time.Minute) },
			"no state exp.": func(s *store.AdminSession) { s.State = store.SessionTOTPEnrollmentRequired },
		}
		for name, mutate := range bad {
			s := newAdminSession(a.ID, "bad")
			mutate(&s)
			wantErr(t, "Create("+name+")", repo.Create(ctx, s), store.ErrInvalid)
		}
		wantErr(t, "Create(unknown admin)", repo.Create(ctx, newAdminSession(id.New(id.Admin), "orphan")), store.ErrNotFound)
		wantErr(t, "Create(duplicate hash)", repo.Create(ctx, newAdminSession(a.ID, "tok-1")), store.ErrConflict)
		zero := newAdminSession(a.ID, "tok-zero")
		zero.CreatedAt, zero.ExpiresAt = time.Time{}, fixedNow.Add(time.Hour) // store clock
		if err := repo.Create(ctx, zero); err != nil {
			t.Errorf("Create(zero creation time) = %v", err)
		}

		// Revocation.
		other := newSuperAdmin(t, db, "other")
		o := newAdminSession(other.ID, "tok-other")
		if err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return repo.CreateTx(ctx, tx, o) }); err != nil {
			t.Fatal(err)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return repo.CreateTx(ctx, tx, o) })
		wantErr(t, "CreateTx(duplicate)", err, store.ErrConflict)
		if n, err := repo.DeleteByAdmin(ctx, a.ID, p.ID); err != nil || n != 2 {
			t.Errorf("DeleteByAdmin(except one) = %d, %v", n, err)
		}
		if _, err := repo.GetByTokenHash(ctx, tokenHash("tok-3"), msNow, idle); err != nil {
			t.Errorf("excepted session revoked: %v", err)
		}
		if _, err := repo.GetByTokenHash(ctx, tokenHash("tok-other"), msNow, idle); err != nil {
			t.Errorf("session of another admin revoked: %v", err)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			n, err := repo.DeleteByAdminTx(ctx, tx, a.ID, "")
			if n != 1 {
				t.Errorf("DeleteByAdminTx = %d", n)
			}
			return err
		})
		if err != nil {
			t.Errorf("DeleteByAdminTx = %v", err)
		}
		if err := repo.Delete(ctx, o.ID); err != nil {
			t.Errorf("Delete = %v", err)
		}
		wantErr(t, "Delete(unknown)", repo.Delete(ctx, o.ID), store.ErrNotFound)

		// Purge: one session per expiry rule, plus a valid one.
		mk := func(token string, mutate func(*store.AdminSession)) {
			s := newAdminSession(a.ID, token)
			mutate(&s)
			if err := repo.Create(ctx, s); err != nil {
				t.Fatal(err)
			}
		}
		mk("p-absolute", func(s *store.AdminSession) { s.ExpiresAt = msNow.Add(time.Minute) })
		mk("p-idle", func(*store.AdminSession) {})
		mk("p-state", func(s *store.AdminSession) {
			s.State, s.StateExpiresAt, s.LastSeenAt = store.SessionTOTPRequired, msNow.Add(5*time.Minute), msNow.Add(50*time.Minute)
		})
		mk("p-valid", func(s *store.AdminSession) { s.LastSeenAt = msNow.Add(50 * time.Minute) })
		if n, err := repo.Purge(ctx, msNow.Add(time.Hour), idle); err != nil || n != 3 {
			t.Errorf("Purge = %d, %v; want 3", n, err)
		}
		if _, err := repo.GetByTokenHash(ctx, tokenHash("p-valid"), msNow.Add(time.Hour), idle); err != nil {
			t.Errorf("valid session purged: %v", err)
		}

		// Deleting the admin deletes its sessions.
		if err := db.Admins().Delete(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		_, err = repo.GetByTokenHash(ctx, tokenHash("p-valid"), msNow.Add(time.Hour), idle)
		wantErr(t, "session of a deleted admin", err, store.ErrNotFound)
	})
}

func TestAdminRecoveryCodes(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AdminRecoveryCodes()
		a, b := newSuperAdmin(t, db, "alpha"), newSuperAdmin(t, db, "bravo")
		var hashes [][]byte
		for i := range 8 {
			hashes = append(hashes, tokenHash("rc-"+string(rune('a'+i))))
		}
		if err := repo.Replace(ctx, a.ID, hashes); err != nil {
			t.Fatalf("Replace = %v", err)
		}
		if n, err := repo.CountUnused(ctx, a.ID); err != nil || n != 8 {
			t.Errorf("CountUnused = %d, %v", n, err)
		}
		if ok, err := repo.Consume(ctx, b.ID, hashes[0], msNow); err != nil || ok {
			t.Errorf("Consume(other admin) = %v, %v", ok, err)
		}
		if ok, err := repo.Consume(ctx, a.ID, hashes[0], msNow); err != nil || !ok {
			t.Errorf("Consume = %v, %v", ok, err)
		}
		if ok, err := repo.Consume(ctx, a.ID, hashes[0], msNow); err != nil || ok {
			t.Errorf("Consume(used) = %v, %v", ok, err)
		}
		for _, h := range [][]byte{tokenHash("wrong"), []byte("short")} {
			if ok, err := repo.Consume(ctx, a.ID, h, msNow); err != nil || ok {
				t.Errorf("Consume(%x) = %v, %v", h, ok, err)
			}
		}
		if n, _ := repo.CountUnused(ctx, a.ID); n != 7 {
			t.Errorf("CountUnused after a use = %d", n)
		}
		// Concurrent uses of one code: exactly one succeeds.
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 8 {
			wg.Go(func() {
				ok, err := repo.Consume(ctx, a.ID, hashes[1], msNow)
				if err != nil {
					t.Errorf("concurrent Consume: %v", err)
				}
				if ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if wins != 1 {
			t.Errorf("a recovery code was consumed %d times", wins)
		}
		// Replace forgets every previous code.
		err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return repo.ReplaceTx(ctx, tx, a.ID, hashes[:2]) })
		if err != nil {
			t.Fatalf("ReplaceTx = %v", err)
		}
		if n, _ := repo.CountUnused(ctx, a.ID); n != 2 {
			t.Errorf("CountUnused after ReplaceTx = %d", n)
		}
		tooMany := make([][]byte, store.MaxRecoveryCodes+1)
		for i := range tooMany {
			tooMany[i] = tokenHash(string(rune('A' + i)))
		}
		for name, hs := range map[string][][]byte{
			"too many": tooMany, "bad size": {[]byte("x")}, "duplicate": {hashes[0], hashes[0]},
		} {
			wantErr(t, "Replace("+name+")", repo.Replace(ctx, a.ID, hs), store.ErrInvalid)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return repo.ReplaceTx(ctx, tx, a.ID, tooMany) })
		wantErr(t, "ReplaceTx(too many)", err, store.ErrInvalid)
		wantErr(t, "Replace(unknown admin)", repo.Replace(ctx, id.New(id.Admin), hashes[:1]), store.ErrNotFound)
		if err := db.Admins().Delete(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		if n, _ := repo.CountUnused(ctx, a.ID); n != 0 {
			t.Errorf("codes of a deleted admin = %d", n)
		}
	})
}

func TestAdminActivations(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AdminActivations()
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		a := newDelegated(t, db, "admin.a", ta.ID)
		act := func(token string) store.AdminActivation {
			return store.AdminActivation{
				ID: id.New(id.AdminActivation), AdminID: a.ID, TokenHash: tokenHash(token),
				CreatedAt: msNow, ExpiresAt: msNow.Add(72 * time.Hour),
			}
		}
		if err := repo.Create(ctx, act("link-1")); err != nil {
			t.Fatalf("Create = %v", err)
		}
		_, err := repo.Consume(ctx, tokenHash("link-1"), msNow.Add(72*time.Hour))
		wantErr(t, "Consume(expired)", err, store.ErrNotFound)
		if got, err := repo.Consume(ctx, tokenHash("link-1"), msNow.Add(time.Hour)); err != nil || got != a.ID {
			t.Errorf("Consume = %q, %v", got, err)
		}
		_, err = repo.Consume(ctx, tokenHash("link-1"), msNow.Add(time.Hour))
		wantErr(t, "Consume(used)", err, store.ErrNotFound)
		_, err = repo.Consume(ctx, []byte("x"), msNow)
		wantErr(t, "Consume(bad hash)", err, store.ErrInvalid)

		// Concurrent consumptions: exactly one succeeds.
		if err := repo.Create(ctx, act("link-2")); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 8 {
			wg.Go(func() {
				err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
					_, err := repo.ConsumeTx(ctx, tx, tokenHash("link-2"), msNow)
					return err
				})
				switch {
				case err == nil:
					mu.Lock()
					wins++
					mu.Unlock()
				case !errors.Is(err, store.ErrNotFound):
					t.Errorf("ConsumeTx: %v", err)
				}
			})
		}
		wg.Wait()
		if wins != 1 {
			t.Errorf("an activation link was consumed %d times", wins)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			_, err := repo.ConsumeTx(ctx, tx, []byte("x"), msNow)
			return err
		})
		wantErr(t, "ConsumeTx(bad hash)", err, store.ErrInvalid)

		bad := map[string]func(*store.AdminActivation){
			"id":     func(a *store.AdminActivation) { a.ID = "bogus" },
			"admin":  func(a *store.AdminActivation) { a.AdminID = "bogus" },
			"hash":   func(a *store.AdminActivation) { a.TokenHash = nil },
			"expiry": func(a *store.AdminActivation) { a.ExpiresAt = a.CreatedAt },
		}
		for name, mutate := range bad {
			x := act("bad")
			mutate(&x)
			wantErr(t, "Create("+name+")", repo.Create(ctx, x), store.ErrInvalid)
		}
		orphan := act("orphan")
		orphan.AdminID = id.New(id.Admin)
		wantErr(t, "Create(unknown admin)", repo.Create(ctx, orphan), store.ErrNotFound)
		wantErr(t, "Create(duplicate hash)", repo.Create(ctx, act("link-1")), store.ErrConflict)
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return repo.CreateTx(ctx, tx, act("link-1")) })
		wantErr(t, "CreateTx(duplicate hash)", err, store.ErrConflict)

		// Revocation and purge.
		for _, tok := range []string{"link-3", "link-4"} {
			if err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return repo.CreateTx(ctx, tx, act(tok)) }); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := repo.DeleteByAdmin(ctx, a.ID); err != nil || n != 4 {
			t.Errorf("DeleteByAdmin = %d, %v", n, err)
		}
		zero := act("link-5")
		zero.CreatedAt, zero.ExpiresAt = time.Time{}, fixedNow.Add(time.Hour)
		if err := repo.Create(ctx, zero); err != nil {
			t.Fatal(err)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error {
			n, err := repo.DeleteByAdminTx(ctx, tx, a.ID)
			if n != 1 {
				t.Errorf("DeleteByAdminTx = %d", n)
			}
			return err
		})
		if err != nil {
			t.Error(err)
		}
		for _, tok := range []string{"p-used", "p-expired", "p-valid"} {
			if err := repo.Create(ctx, act(tok)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := repo.Consume(ctx, tokenHash("p-used"), msNow); err != nil {
			t.Fatal(err)
		}
		if n, err := repo.Purge(ctx, msNow.Add(time.Hour)); err != nil || n != 1 {
			t.Errorf("Purge(used) = %d, %v", n, err)
		}
		if n, err := repo.Purge(ctx, msNow.Add(72*time.Hour)); err != nil || n != 2 {
			t.Errorf("Purge(expired) = %d, %v", n, err)
		}
		// Deleting the admin deletes its links.
		if err := repo.Create(ctx, act("p-last")); err != nil {
			t.Fatal(err)
		}
		if err := db.Admins().Delete(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		_, err = repo.Consume(ctx, tokenHash("p-last"), msNow)
		wantErr(t, "link of a deleted admin", err, store.ErrNotFound)
	})
}

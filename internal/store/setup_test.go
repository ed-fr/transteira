package store_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// newSetupTenant creates a tenant in the setup state.
func newSetupTenant(t *testing.T, db *store.DB, fqdn string) *tenant.Tenant {
	t.Helper()
	tn, err := db.Tenants().Create(context.Background(), &tenant.Tenant{
		SetupState: tenant.SetupStateSetup,
		Name:       "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "en",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn
}

// The creation needs an explicit setup state, never the column default
// (T-261, P51), and the general update never writes it.
func TestTenantsSetupStateCreation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Tenants()
		base := tenant.Tenant{
			Name: "S", FQDN: "transfer.entity-s.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
		}
		for _, state := range []tenant.SetupState{"", "suspended", "Active"} {
			in := base
			in.SetupState = state
			_, err := repo.Create(ctx, &in)
			wantErr(t, "Create(setup state "+string(state)+")", err, store.ErrInvalid)
			_, err = repo.CreateWith(ctx, &in, func(*store.SystemTx, *tenant.Tenant) error {
				t.Error("the callback ran for an invalid setup state")
				return nil
			})
			wantErr(t, "CreateWith(setup state "+string(state)+")", err, store.ErrInvalid)
		}

		s := newSetupTenant(t, db, "transfer.entity-a.example.com")
		if s.SetupState != tenant.SetupStateSetup || !s.SMTPTestedAt.IsZero() || !s.MailTemplatesReviewedAt.IsZero() {
			t.Fatalf("created %+v", s)
		}
		a := newTenant(t, db, "transfer.entity-b.example.com")
		if a.SetupState != tenant.SetupStateActive {
			t.Fatalf("created %+v", a)
		}
		for _, tn := range []*tenant.Tenant{s, a} {
			if got, err := repo.Get(ctx, tn.ID); err != nil || *got != *tn {
				t.Errorf("Get = %+v, %v; want %+v", got, err, tn)
			}
		}
		// The resolution reads the state too (the public side needs it).
		if got, err := repo.TenantByFQDN(ctx, s.FQDN); err != nil || got.SetupState != tenant.SetupStateSetup {
			t.Errorf("TenantByFQDN = %+v, %v", got, err)
		}

		// The update ignores the state it is given.
		upd := s.Clone()
		upd.SetupState = tenant.SetupStateActive
		upd.Name = "Renamed"
		got, err := repo.Update(ctx, upd)
		if err != nil || got.SetupState != tenant.SetupStateSetup || got.Name != "Renamed" {
			t.Fatalf("Update = %+v, %v", got, err)
		}
		// An invalid state is refused by the validation.
		upd.SetupState = ""
		_, err = repo.Update(ctx, upd)
		wantErr(t, "Update(no setup state)", err, store.ErrInvalid)
	})
}

// Every write of the SMTP settings moves their modification time (their
// version) strictly forward.
func TestSMTPSettingsVersion(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.SMTPSettings()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		relay := store.SMTPConfig{Host: "smtp-relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-a.example.com"}

		var prev time.Time
		for i := range 3 { // same clock reading every time
			if err := repo.Put(ctx, a.ID, relay); err != nil {
				t.Fatal(err)
			}
			got, err := repo.Get(ctx, a.ID)
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 && !got.UpdatedAt.Equal(msNow) {
				t.Errorf("first version %v, want %v", got.UpdatedAt, msNow)
			}
			if i > 0 && !got.UpdatedAt.Equal(prev.Add(time.Millisecond)) {
				t.Errorf("version %d = %v, want %v", i, got.UpdatedAt, prev.Add(time.Millisecond))
			}
			prev = got.UpdatedAt
		}
		// A time given in the past never moves the version back.
		past := relay
		past.UpdatedAt = msNow.Add(-time.Hour)
		if err := repo.Put(ctx, a.ID, past); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || !got.UpdatedAt.Equal(prev.Add(time.Millisecond)) {
			t.Errorf("past version: %+v, %v", got, err)
		}
		// A later one is kept.
		later := relay
		later.UpdatedAt = msNow.Add(time.Hour)
		if err := repo.Put(ctx, a.ID, later); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || !got.UpdatedAt.Equal(later.UpdatedAt) {
			t.Errorf("later version: %+v, %v", got, err)
		}
	})
}

func TestTenantsSetSMTPTested(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Tenants()
		a := newSetupTenant(t, db, "transfer.entity-a.example.com")
		b := newSetupTenant(t, db, "transfer.entity-b.example.com")
		version := msNow.Add(-time.Minute)
		if err := repo.SetSMTPTested(ctx, a.ID, version); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || !got.SMTPTestedAt.Equal(version) {
			t.Errorf("Get(A) = %+v, %v", got, err)
		}
		if got, err := repo.Get(ctx, b.ID); err != nil || !got.SMTPTestedAt.IsZero() {
			t.Errorf("B changed: %+v, %v", got, err)
		}
		wantErr(t, "SetSMTPTested(zero)", repo.SetSMTPTested(ctx, a.ID, time.Time{}), store.ErrInvalid)
		wantErr(t, "SetSMTPTested(unknown)", repo.SetSMTPTested(ctx, tenant.ID(id.New(id.Tenant)), version), store.ErrNotFound)
		for _, tid := range badTenants {
			wantErr(t, "SetSMTPTested(bad tenant)", repo.SetSMTPTested(ctx, tid, version), store.ErrNotFound)
		}
		if err := repo.SetStatus(ctx, b.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "SetSMTPTested(deleting)", repo.SetSMTPTested(ctx, b.ID, version), store.ErrNotFound)
	})
}

func TestTenantsCompleteSetup(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Tenants()
		smtp := db.SMTPSettings()
		relay := store.SMTPConfig{Host: "smtp-relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@example.com"}
		version := func(tid tenant.ID) time.Time {
			t.Helper()
			c, err := smtp.Get(ctx, tid)
			if err != nil {
				t.Fatal(err)
			}
			return c.UpdatedAt
		}

		// Without SMTP settings, the guard fails (nothing to compare).
		a := newSetupTenant(t, db, "transfer.entity-a.example.com")
		_, err := repo.CompleteSetup(ctx, a.ID, false, time.Time{})
		wantErr(t, "CompleteSetup(no smtp)", err, store.ErrConflict)

		// Settings never tested: refused.
		if err := smtp.Put(ctx, a.ID, relay); err != nil {
			t.Fatal(err)
		}
		_, err = repo.CompleteSetup(ctx, a.ID, false, time.Time{})
		wantErr(t, "CompleteSetup(untested)", err, store.ErrConflict)

		// Tested, then changed: the stamp no longer matches, refused.
		if err := repo.SetSMTPTested(ctx, a.ID, version(a.ID)); err != nil {
			t.Fatal(err)
		}
		if err := smtp.Put(ctx, a.ID, relay); err != nil { // same values, new version
			t.Fatal(err)
		}
		_, err = repo.CompleteSetup(ctx, a.ID, false, time.Time{})
		wantErr(t, "CompleteSetup(changed since the test)", err, store.ErrConflict)
		if got, err := repo.Get(ctx, a.ID); err != nil || got.SetupState != tenant.SetupStateSetup {
			t.Fatalf("a refused completion changed the tenant: %+v, %v", got, err)
		}

		// Tested with the current settings, but no network rule nor legal
		// document: each guard of the statement refuses in turn.
		if err := repo.SetSMTPTested(ctx, a.ID, version(a.ID)); err != nil {
			t.Fatal(err)
		}
		legal := func(tid tenant.ID, doc, lang, content string) {
			t.Helper()
			if _, err := db.TenantLegalDocuments().Put(ctx, tid, store.LegalDocument{Document: doc, Language: lang, Content: content}); err != nil {
				t.Fatal(err)
			}
		}
		steps := []struct {
			name string
			do   func()
		}{
			{"no network rule", func() {
				_, err := db.NetworkRules().Replace(ctx, a.ID, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil)
				mustNil(t, err)
			}},
			{"no internal domain", func() {
				_, err := db.NetworkRules().Replace(ctx, a.ID, nil, []string{"entity-a.example.com"})
				mustNil(t, err)
			}},
			{"no internal range", func() {
				_, err := db.NetworkRules().Replace(ctx, a.ID, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"entity-a.example.com"})
				mustNil(t, err)
			}},
			// Legal documents in another language, or blank, do not count.
			{"no legal document", func() {
				legal(a.ID, store.LegalNotice, "fr", "Mentions")
				legal(a.ID, store.PrivacyPolicy, "fr", "Politique")
			}},
			{"legal documents in another language", func() { legal(a.ID, store.LegalNotice, "en", " 	 ") }},
			{"blank legal notice", func() { legal(a.ID, store.LegalNotice, "en", "Notice") }},
			{"no privacy policy", func() {}},
		}
		for _, st := range steps {
			_, err = repo.CompleteSetup(ctx, a.ID, false, time.Time{})
			wantErr(t, "CompleteSetup("+st.name+")", err, store.ErrConflict)
			st.do()
		}
		// Configured C (rules, documents) never opens A: the guards are
		// bound to the tenant of the statement.
		c0 := newSetupTenant(t, db, "transfer.entity-c0.example.com")
		if err := smtp.Put(ctx, c0.ID, relay); err != nil {
			t.Fatal(err)
		}
		mustNil(t, repo.SetSMTPTested(ctx, c0.ID, version(c0.ID)))
		_, err = repo.CompleteSetup(ctx, c0.ID, false, time.Time{})
		wantErr(t, "CompleteSetup(C0 without rules, A configured)", err, store.ErrConflict)
		legal(a.ID, store.PrivacyPolicy, "en", "Policy")

		// Everything in place: completed, review recorded.
		reviewed := msNow.Add(-time.Second)
		got, err := repo.CompleteSetup(ctx, a.ID, false, reviewed)
		if err != nil || got.SetupState != tenant.SetupStateActive || !got.MailTemplatesReviewedAt.Equal(reviewed) ||
			!got.UpdatedAt.Equal(msNow) {
			t.Fatalf("CompleteSetup = %+v, %v", got, err)
		}
		if res, err := repo.TenantByFQDN(ctx, a.FQDN); err != nil || res.SetupState != tenant.SetupStateActive {
			t.Errorf("TenantByFQDN = %+v, %v", res, err)
		}
		// No way back, forced or not.
		_, err = repo.CompleteSetup(ctx, a.ID, false, time.Time{})
		wantErr(t, "CompleteSetup(active)", err, store.ErrSetupComplete)
		_, err = repo.CompleteSetup(ctx, a.ID, true, time.Time{})
		wantErr(t, "CompleteSetup(active, forced)", err, store.ErrSetupComplete)

		// Forced: no SMTP needed; a zero review time keeps the mark (none).
		b := newSetupTenant(t, db, "transfer.entity-b.example.com")
		c := newSetupTenant(t, db, "transfer.entity-c.example.com")
		got, err = repo.CompleteSetup(ctx, b.ID, true, time.Time{})
		if err != nil || got.SetupState != tenant.SetupStateActive || !got.MailTemplatesReviewedAt.IsZero() {
			t.Fatalf("CompleteSetup(forced) = %+v, %v", got, err)
		}
		// Isolation: the tested settings of A never open C.
		if err := repo.SetSMTPTested(ctx, c.ID, version(a.ID)); err != nil {
			t.Fatal(err)
		}
		_, err = repo.CompleteSetup(ctx, c.ID, false, time.Time{})
		wantErr(t, "CompleteSetup(C with the version of A)", err, store.ErrConflict)
		if got, err := repo.Get(ctx, c.ID); err != nil || got.SetupState != tenant.SetupStateSetup {
			t.Errorf("C changed: %+v, %v", got, err)
		}

		// Missing, malformed or deleting tenants.
		_, err = repo.CompleteSetup(ctx, tenant.ID(id.New(id.Tenant)), true, time.Time{})
		wantErr(t, "CompleteSetup(unknown)", err, store.ErrNotFound)
		for _, tid := range badTenants {
			_, err = repo.CompleteSetup(ctx, tid, false, time.Time{})
			wantErr(t, "CompleteSetup(bad tenant)", err, store.ErrNotFound)
		}
		if err := repo.SetStatus(ctx, c.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		_, err = repo.CompleteSetup(ctx, c.ID, true, time.Time{})
		wantErr(t, "CompleteSetup(deleting)", err, store.ErrNotFound)
		if errors.Is(err, store.ErrSetupComplete) {
			t.Error("a deleting tenant reported as complete")
		}
	})
}

// mustNil fails on err.
func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

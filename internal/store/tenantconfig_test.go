package store_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// eraseTenantKeys destroys every wrapped key of tenant tid, as the tenant
// deletion does before [store.Tenants.Delete].
func eraseTenantKeys(t *testing.T, db *store.DB, tid tenant.ID) {
	t.Helper()
	ctx := context.Background()
	for {
		ids, err := db.WrappedKeys().ListIDs(ctx, tid, "", 2)
		if err != nil {
			t.Fatalf("ListIDs: %v", err)
		}
		if len(ids) == 0 {
			return
		}
		for _, k := range ids {
			if err := db.WrappedKeys().Delete(ctx, tid, k); err != nil {
				t.Fatalf("Delete key: %v", err)
			}
		}
	}
}

func TestTenantsConfigFields(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Tenants()

		// Defaults on creation.
		a := newTenant(t, db, "transfer.entity-a.example.com")
		if a.MaxTransferCeiling != a.MaxTransferBytes || a.Status != tenant.StatusActive ||
			a.PrimaryColor != tenant.DefaultPrimaryColor || a.AccentColor != tenant.DefaultAccentColor || a.HasLogo || a.HasBackground ||
			a.WebhookIncludeAddresses {
			t.Fatalf("created tenant = %+v", a)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || *got != *a {
			t.Fatalf("Get = %+v, %v; want %+v", got, err, a)
		}

		// Explicit settings are kept.
		b, err := repo.Create(ctx, &tenant.Tenant{
			Name: "B", FQDN: "transfer.entity-b.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1 << 30, MaxTransferCeiling: tenant.MaxTransferLimit, StorageQuotaBytes: 1 << 40,
			PrimaryColor: "#000000", AccentColor: "#abcdef", HasLogo: true, HasBackground: true,
			WebhookIncludeAddresses: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, b.ID); err != nil || *got != *b || got.MaxTransferCeiling != tenant.MaxTransferLimit ||
			got.AccentColor != "#abcdef" || !got.HasLogo || !got.HasBackground || !got.WebhookIncludeAddresses {
			t.Fatalf("Get(B) = %+v, %v", got, err)
		}

		// The ceiling rule: limit <= ceiling <= 20 GiB.
		base := tenant.Tenant{Name: "C", FQDN: "c.example.com", DefaultLanguage: "fr", StorageQuotaBytes: 1}
		for name, mutate := range map[string]func(*tenant.Tenant){
			"limit over ceiling":   func(x *tenant.Tenant) { x.MaxTransferBytes, x.MaxTransferCeiling = 11, 10 },
			"ceiling over 20 GiB":  func(x *tenant.Tenant) { x.MaxTransferBytes, x.MaxTransferCeiling = 1, tenant.MaxTransferLimit+1 },
			"limit over 20 GiB":    func(x *tenant.Tenant) { x.MaxTransferBytes = tenant.MaxTransferLimit + 1 },
			"negative ceiling":     func(x *tenant.Tenant) { x.MaxTransferBytes, x.MaxTransferCeiling = 1, -1 },
			"deleting on creation": func(x *tenant.Tenant) { x.MaxTransferBytes, x.Status = 1, tenant.StatusDeleting },
			"unknown status":       func(x *tenant.Tenant) { x.MaxTransferBytes, x.Status = 1, "archived" },
			"bad color":            func(x *tenant.Tenant) { x.MaxTransferBytes, x.PrimaryColor = 1, "blue" },
		} {
			c := base
			mutate(&c)
			if _, err := repo.Create(ctx, &c); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Create(%s) err = %v, want ErrInvalid", name, err)
			}
		}
		upd := b.Clone()
		upd.MaxTransferBytes = upd.MaxTransferCeiling + 1
		if _, err := repo.Update(ctx, upd); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Update(limit over ceiling) err = %v", err)
		}
		upd = b.Clone()
		upd.MaxTransferCeiling = tenant.MaxTransferLimit + 1
		if _, err := repo.Update(ctx, upd); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Update(ceiling over 20 GiB) err = %v", err)
		}
		upd = b.Clone()
		upd.AccentColor = "#12345"
		if _, err := repo.Update(ctx, upd); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Update(bad color) err = %v", err)
		}

		// Update stores every configurable field, but never the status.
		upd = a.Clone()
		upd.MaxTransferCeiling, upd.MaxTransferBytes = 2<<30, 2<<30
		upd.PrimaryColor, upd.AccentColor = "#111111", "#222222"
		upd.HasLogo, upd.HasBackground = true, false
		upd.WebhookIncludeAddresses = true
		upd.Status = tenant.StatusDeleting
		out, err := repo.Update(ctx, upd)
		if err != nil || out.MaxTransferCeiling != 2<<30 || out.MaxTransferBytes != 2<<30 || out.PrimaryColor != "#111111" ||
			out.AccentColor != "#222222" || !out.HasLogo || out.HasBackground || !out.WebhookIncludeAddresses ||
			out.Status != tenant.StatusActive {
			t.Fatalf("Update = %+v, %v", out, err)
		}
		upd = out.Clone()
		upd.WebhookIncludeAddresses = false
		if out, err := repo.Update(ctx, upd); err != nil || out.WebhookIncludeAddresses {
			t.Fatalf("Update(webhook addresses off) = %+v, %v", out, err)
		}
		upd = out.Clone()
		upd.Status = "bogus"
		if _, err := repo.Update(ctx, upd); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Update(bogus status) err = %v", err)
		}
	})
}

func TestTenantsDeletingStatus(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.Tenants()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		if ids, err := repo.ListDeleting(ctx); err != nil || len(ids) != 0 {
			t.Fatalf("ListDeleting(none) = %v, %v", ids, err)
		}
		if err := repo.SetStatus(ctx, a.ID, tenant.StatusDeleting); err != nil {
			t.Fatalf("SetStatus(deleting): %v", err)
		}
		// Hidden from the Host resolution, as an unknown host.
		_, err := repo.TenantByFQDN(ctx, a.FQDN)
		if !errors.Is(err, tenant.ErrUnknownTenant) || !errors.Is(err, store.ErrNotFound) {
			t.Errorf("TenantByFQDN(deleting) err = %v, want unknown tenant", err)
		}
		if _, err := tenant.NewResolver(repo).Resolve(ctx, a.FQDN); !errors.Is(err, tenant.ErrUnknownTenant) {
			t.Errorf("Resolve(deleting) err = %v", err)
		}
		if got, err := repo.TenantByFQDN(ctx, b.FQDN); err != nil || got.ID != b.ID {
			t.Errorf("TenantByFQDN(B) = %+v, %v", got, err)
		}
		// Still visible to the super admin, with its status.
		got, err := repo.Get(ctx, a.ID)
		if err != nil || got.Status != tenant.StatusDeleting {
			t.Fatalf("Get(deleting) = %+v, %v", got, err)
		}
		page, err := repo.List(ctx, store.TenantListOptions{})
		if err != nil || len(page.Items) != 2 {
			t.Errorf("List = %+v, %v", page, err)
		}
		// No more configuration change.
		upd := got.Clone()
		upd.Name = "Renamed"
		if _, err := repo.Update(ctx, upd); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update(deleting) err = %v, want ErrNotFound", err)
		}
		// The FQDN stays taken until the final deletion.
		if _, err := repo.Create(ctx, &tenant.Tenant{Name: "X", FQDN: a.FQDN, DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1}); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create(fqdn of a deleting tenant) err = %v", err)
		}
		if ids, err := repo.ListDeleting(ctx); err != nil || !slices.Equal(ids, []tenant.ID{a.ID}) {
			t.Errorf("ListDeleting = %v, %v", ids, err)
		}
		if err := repo.SetStatus(ctx, b.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		want := []tenant.ID{a.ID, b.ID}
		slices.Sort(want)
		if ids, err := repo.ListDeleting(ctx); err != nil || !slices.Equal(ids, want) {
			t.Errorf("ListDeleting(two) = %v, %v; want %v", ids, err, want)
		}

		// Back to active: it resolves again.
		if err := repo.SetStatus(ctx, a.ID, tenant.StatusActive); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.TenantByFQDN(ctx, a.FQDN); err != nil || got.ID != a.ID || got.Status != tenant.StatusActive {
			t.Errorf("TenantByFQDN(reactivated) = %+v, %v", got, err)
		}

		// Errors.
		if err := repo.SetStatus(ctx, a.ID, "archived"); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("SetStatus(unknown) err = %v", err)
		}
		if err := repo.SetStatus(ctx, tenant.ID(id.New(id.Tenant)), tenant.StatusDeleting); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetStatus(missing) err = %v", err)
		}
		if err := repo.SetStatus(ctx, "bogus", tenant.StatusDeleting); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetStatus(malformed id) err = %v", err)
		}
	})
}

func TestTenantsDeleteRefusedWhileKeysRemain(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		keys := db.WrappedKeys()

		// A file key and the SMTP password of A, a key of B.
		var aKeys []string
		for range 3 {
			aKeys = append(aKeys, mustCreateKey(t, db, a.ID, newWrappedKey(mk1, "dek")).ID)
		}
		secret := newWrappedKey(mk1, "smtp")
		secret.Purpose = store.KeyPurposeSecret
		aKeys = append(aKeys, mustCreateKey(t, db, a.ID, secret).ID)
		smtp := store.SMTPConfig{
			Host: "smtp.example.com", Port: 587, Security: store.SMTPSecuritySTARTTLS,
			Username: "u", PasswordKeyID: secret.ID, FromAddress: "a@example.com",
		}
		if err := db.SMTPSettings().Put(ctx, a.ID, smtp); err != nil {
			t.Fatal(err)
		}
		bKey := mustCreateKey(t, db, b.ID, newWrappedKey(mk2, "b")).ID
		slices.Sort(aKeys)
		if _, err := db.TenantLegalDocuments().Put(ctx, a.ID, store.LegalDocument{Document: store.LegalNotice, Language: "fr", Content: "A"}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.TenantEmailTemplates().Put(ctx, a.ID, store.EmailTemplate{Key: store.EmailTemplateInvitation, Language: "fr", Subject: "A"}); err != nil {
			t.Fatal(err)
		}

		// IDs only, paginated, of one tenant.
		first, err := keys.ListIDs(ctx, a.ID, "", 2)
		if err != nil || !slices.Equal(first, aKeys[:2]) {
			t.Fatalf("ListIDs(first page) = %v, %v; want %v", first, err, aKeys[:2])
		}
		rest, err := keys.ListIDs(ctx, a.ID, first[1], 0)
		if err != nil || !slices.Equal(rest, aKeys[2:]) {
			t.Fatalf("ListIDs(next page) = %v, %v; want %v", rest, err, aKeys[2:])
		}
		if ids, err := keys.ListIDs(ctx, b.ID, "", store.MaxPageSize+1); err != nil || !slices.Equal(ids, []string{bKey}) {
			t.Errorf("ListIDs(B) = %v, %v", ids, err)
		}
		if ids, err := keys.ListIDs(ctx, tenant.ID(id.New(id.Tenant)), "", 0); err != nil || len(ids) != 0 {
			t.Errorf("ListIDs(missing tenant) = %v, %v", ids, err)
		}
		if _, err := keys.ListIDs(ctx, a.ID, "blk_bad", 0); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("ListIDs(bad cursor) err = %v", err)
		}
		if _, err := keys.ListIDs(ctx, "bogus", "", 0); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("ListIDs(bad tenant) err = %v", err)
		}

		// Refused, and nothing is deleted, while one key remains.
		for len(aKeys) > 0 {
			if err := db.Tenants().Delete(ctx, a.ID); !errors.Is(err, store.ErrKeysRemain) {
				t.Fatalf("Delete with %d keys left err = %v, want ErrKeysRemain", len(aKeys), err)
			}
			if _, err := db.Tenants().Get(ctx, a.ID); err != nil {
				t.Fatalf("tenant gone after a refused delete: %v", err)
			}
			if err := keys.Delete(ctx, a.ID, aKeys[0]); err != nil {
				t.Fatal(err)
			}
			aKeys = aKeys[1:]
		}
		if c, err := db.SMTPSettings().Get(ctx, a.ID); err != nil || c.PasswordKeyID != "" {
			t.Errorf("SMTP after the erasure of its password = %+v, %v", c, err)
		}
		if err := db.Tenants().Delete(ctx, a.ID); err != nil {
			t.Fatalf("Delete without keys: %v", err)
		}
		// Cascades.
		if _, err := db.TenantLegalDocuments().Get(ctx, a.ID, store.LegalNotice, "fr"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("legal document after tenant deletion: %v", err)
		}
		if l, err := db.TenantEmailTemplates().List(ctx, a.ID); err != nil || len(l) != 0 {
			t.Errorf("templates after tenant deletion = %v, %v", l, err)
		}
		if _, err := db.SMTPSettings().Get(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SMTP after tenant deletion: %v", err)
		}
		// B is untouched, and the FQDN of A is free again.
		if _, err := keys.Get(ctx, b.ID, bKey); err != nil {
			t.Errorf("B's key: %v", err)
		}
		newTenant(t, db, a.FQDN)
	})
}

func TestEmailTemplateKeys(t *testing.T) {
	t.Parallel()
	keys := store.EmailTemplateKeys()
	if len(keys) != 10 || !slices.IsSorted(keys) {
		t.Fatalf("EmailTemplateKeys = %v", keys)
	}
	for _, k := range keys {
		if !store.IsEmailTemplateKey(k) {
			t.Errorf("IsEmailTemplateKey(%q) = false", k)
		}
	}
	keys[0] = "x"
	if store.EmailTemplateKeys()[0] == "x" {
		t.Error("EmailTemplateKeys returns shared state")
	}
	for _, k := range []string{"", "expiry-reminder", "disk-alert", "Invitation", "invitation "} {
		if store.IsEmailTemplateKey(k) {
			t.Errorf("IsEmailTemplateKey(%q) = true", k)
		}
	}
	if !store.IsLegalDocument(store.LegalNotice) || !store.IsLegalDocument(store.PrivacyPolicy) || store.IsLegalDocument("terms") {
		t.Error("IsLegalDocument is wrong")
	}
}

func TestTenantEmailTemplates(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.TenantEmailTemplates()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		admin := id.New(id.Admin)

		if l, err := repo.List(ctx, a.ID); err != nil || l == nil || len(l) != 0 {
			t.Fatalf("List(empty) = %#v, %v", l, err)
		}
		if _, err := repo.Get(ctx, a.ID, store.EmailTemplateInvitation, "fr"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get(default) err = %v", err)
		}

		tpl := store.EmailTemplate{
			Key: store.EmailTemplateInvitation, Language: "fr", Subject: "Invitation de {{inviter}}",
			BodyHTML: "<p>{{link}}</p>", BodyText: "{{link}}", UpdatedBy: admin,
		}
		put, err := repo.Put(ctx, a.ID, tpl)
		if err != nil || !put.UpdatedAt.Equal(fixedNow.Truncate(time.Millisecond)) || put.Subject != tpl.Subject {
			t.Fatalf("Put = %+v, %v", put, err)
		}
		if got, err := repo.Get(ctx, a.ID, tpl.Key, "fr"); err != nil || got != put {
			t.Fatalf("Get = %+v, %v; want %+v", got, err, put)
		}

		// Replacement, with an explicit time and no author.
		at := time.Date(2026, 1, 2, 3, 4, 5, 6_789_000, time.UTC)
		tpl2 := tpl
		tpl2.Subject, tpl2.BodyHTML, tpl2.BodyText, tpl2.UpdatedBy, tpl2.UpdatedAt = "Nouveau", "", "", "", at
		if _, err := repo.Put(ctx, a.ID, tpl2); err != nil {
			t.Fatal(err)
		}
		got, err := repo.Get(ctx, a.ID, tpl.Key, "fr")
		if err != nil || got.Subject != "Nouveau" || got.BodyHTML != "" || got.UpdatedBy != "" || !got.UpdatedAt.Equal(at.Truncate(time.Millisecond)) {
			t.Fatalf("Get(replaced) = %+v, %v", got, err)
		}
		en := tpl
		en.Language = "en"
		if _, err := repo.Put(ctx, a.ID, en); err != nil {
			t.Fatal(err)
		}
		code := tpl
		code.Key = store.EmailTemplateVerificationCode
		if _, err := repo.Put(ctx, a.ID, code); err != nil {
			t.Fatal(err)
		}
		list, err := repo.List(ctx, a.ID)
		want := []store.EmailTemplateSummary{
			{Key: store.EmailTemplateInvitation, Language: "en", UpdatedAt: fixedNow.Truncate(time.Millisecond)},
			{Key: store.EmailTemplateInvitation, Language: "fr", UpdatedAt: at.Truncate(time.Millisecond)},
			{Key: store.EmailTemplateVerificationCode, Language: "fr", UpdatedAt: fixedNow.Truncate(time.Millisecond)},
		}
		if err != nil || !slices.Equal(list, want) {
			t.Fatalf("List = %+v, %v; want %+v", list, err, want)
		}

		// Limits: at the bounds, accepted; beyond, ErrInvalid.
		max := tpl
		max.Subject = strings.Repeat("é", store.MaxEmailSubjectLen)
		max.BodyHTML = strings.Repeat("h", store.MaxEmailBodyLen)
		max.BodyText = strings.Repeat("ü", store.MaxEmailBodyLen)
		if _, err := repo.Put(ctx, a.ID, max); err != nil {
			t.Errorf("Put(at the limits): %v", err)
		}
		for name, mutate := range map[string]func(*store.EmailTemplate){
			"unknown key":     func(x *store.EmailTemplate) { x.Key = "welcome" },
			"reserved key":    func(x *store.EmailTemplate) { x.Key = "expiry-reminder" },
			"language":        func(x *store.EmailTemplate) { x.Language = "de" },
			"empty subject":   func(x *store.EmailTemplate) { x.Subject = "" },
			"long subject":    func(x *store.EmailTemplate) { x.Subject = strings.Repeat("a", store.MaxEmailSubjectLen+1) },
			"subject newline": func(x *store.EmailTemplate) { x.Subject = "a\r\nBcc: x@example.com" },
			"subject utf8":    func(x *store.EmailTemplate) { x.Subject = "a\xff" },
			"long html":       func(x *store.EmailTemplate) { x.BodyHTML = strings.Repeat("a", store.MaxEmailBodyLen+1) },
			"long text":       func(x *store.EmailTemplate) { x.BodyText = strings.Repeat("a", store.MaxEmailBodyLen+1) },
			"html nul":        func(x *store.EmailTemplate) { x.BodyHTML = "a\x00b" },
			"text utf8":       func(x *store.EmailTemplate) { x.BodyText = "\xc3" },
			"author":          func(x *store.EmailTemplate) { x.UpdatedBy = "root" },
			"author prefix":   func(x *store.EmailTemplate) { x.UpdatedBy = id.New(id.Tenant) },
		} {
			x := tpl
			mutate(&x)
			if _, err := repo.Put(ctx, a.ID, x); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Put(%s) err = %v, want ErrInvalid", name, err)
			}
		}
		if _, err := repo.Get(ctx, a.ID, "welcome", "fr"); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Get(unknown key) err = %v", err)
		}
		if _, err := repo.Get(ctx, a.ID, tpl.Key, "xx"); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Get(unknown language) err = %v", err)
		}
		if err := repo.Delete(ctx, a.ID, "welcome", "fr"); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Delete(unknown key) err = %v", err)
		}
		for _, tid := range []tenant.ID{"", "bogus"} {
			if _, err := repo.Get(ctx, tid, tpl.Key, "fr"); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Get(tenant %q) err = %v", tid, err)
			}
			if _, err := repo.List(ctx, tid); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("List(tenant %q) err = %v", tid, err)
			}
			if _, err := repo.Put(ctx, tid, tpl); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Put(tenant %q) err = %v", tid, err)
			}
			if err := repo.Delete(ctx, tid, tpl.Key, "fr"); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Delete(tenant %q) err = %v", tid, err)
			}
		}
		if _, err := repo.Put(ctx, tenant.ID(id.New(id.Tenant)), tpl); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Put(missing tenant) err = %v", err)
		}

		// Isolation: B sees, replaces and deletes nothing of A.
		if _, err := repo.Get(ctx, b.ID, tpl.Key, "fr"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get from B err = %v", err)
		}
		if l, err := repo.List(ctx, b.ID); err != nil || len(l) != 0 {
			t.Errorf("List(B) = %v, %v", l, err)
		}
		if err := repo.Delete(ctx, b.ID, tpl.Key, "fr"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete from B err = %v", err)
		}
		bTpl := tpl
		bTpl.Subject = "B"
		if _, err := repo.Put(ctx, b.ID, bTpl); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, a.ID, tpl.Key, "fr"); err != nil || got.Subject == "B" {
			t.Errorf("A's template after B's Put = %+v, %v", got, err)
		}

		// Tx variants, in one transaction.
		s, err := db.Scoped(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			x := tpl
			x.Key, x.Subject = store.EmailTemplateAntivirusUnavailable, "Tx"
			if _, err := repo.PutTx(ctx, tx, x); err != nil {
				return err
			}
			got, err := repo.GetTx(ctx, tx, x.Key, "fr")
			if err != nil || got.Subject != "Tx" {
				t.Errorf("GetTx = %+v, %v", got, err)
			}
			if _, err := repo.GetTx(ctx, tx, "bogus", "fr"); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("GetTx(bad key) err = %v", err)
			}
			if _, err := repo.GetTx(ctx, tx, store.EmailTemplateQuotaReached, "fr"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("GetTx(default) err = %v", err)
			}
			x.Subject = ""
			if _, err := repo.PutTx(ctx, tx, x); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("PutTx(invalid) err = %v", err)
			}
			if err := repo.DeleteTx(ctx, tx, store.EmailTemplateQuotaReached, "fr"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("DeleteTx(default) err = %v", err)
			}
			return repo.DeleteTx(ctx, tx, x.Key, "fr")
		})
		if err != nil {
			t.Fatal(err)
		}

		// Reset to the default.
		if err := repo.Delete(ctx, a.ID, tpl.Key, "fr"); err != nil {
			t.Fatal(err)
		}
		if err := repo.Delete(ctx, a.ID, tpl.Key, "fr"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete twice err = %v", err)
		}
		if _, err := repo.Get(ctx, b.ID, tpl.Key, "fr"); err != nil {
			t.Errorf("B's template after A's reset: %v", err)
		}
	})
}

func TestTenantLegalDocuments(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.TenantLegalDocuments()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		if _, err := repo.Get(ctx, a.ID, store.PrivacyPolicy, "en"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get(none) err = %v", err)
		}
		doc := store.LegalDocument{Document: store.PrivacyPolicy, Language: "en", Content: "# Privacy\n\nText.", UpdatedBy: id.New(id.Admin)}
		put, err := repo.Put(ctx, a.ID, doc)
		if err != nil || !put.UpdatedAt.Equal(fixedNow.Truncate(time.Millisecond)) {
			t.Fatalf("Put = %+v, %v", put, err)
		}
		if got, err := repo.Get(ctx, a.ID, doc.Document, "en"); err != nil || got != put {
			t.Fatalf("Get = %+v, %v; want %+v", got, err, put)
		}
		// Replacement; the other language and document stay apart.
		doc2 := doc
		doc2.Content, doc2.UpdatedBy = "", ""
		if _, err := repo.Put(ctx, a.ID, doc2); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, a.ID, doc.Document, "en"); err != nil || got.Content != "" || got.UpdatedBy != "" {
			t.Errorf("Get(replaced) = %+v, %v", got, err)
		}
		if _, err := repo.Get(ctx, a.ID, doc.Document, "fr"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(other language) err = %v", err)
		}
		if _, err := repo.Get(ctx, a.ID, store.LegalNotice, "en"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(other document) err = %v", err)
		}

		max := doc
		max.Content = strings.Repeat("é", store.MaxLegalContentLen)
		if _, err := repo.Put(ctx, a.ID, max); err != nil {
			t.Errorf("Put(at the limit): %v", err)
		}
		for name, mutate := range map[string]func(*store.LegalDocument){
			"document": func(x *store.LegalDocument) { x.Document = "terms" },
			"language": func(x *store.LegalDocument) { x.Language = "EN" },
			"long":     func(x *store.LegalDocument) { x.Content = strings.Repeat("a", store.MaxLegalContentLen+1) },
			"nul":      func(x *store.LegalDocument) { x.Content = "\x00" },
			"utf8":     func(x *store.LegalDocument) { x.Content = "\xff" },
			"author":   func(x *store.LegalDocument) { x.UpdatedBy = "adm_bad" },
		} {
			x := doc
			mutate(&x)
			if _, err := repo.Put(ctx, a.ID, x); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Put(%s) err = %v, want ErrInvalid", name, err)
			}
		}
		if _, err := repo.Get(ctx, a.ID, "terms", "en"); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Get(unknown document) err = %v", err)
		}
		if err := repo.Delete(ctx, a.ID, doc.Document, "de"); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Delete(unknown language) err = %v", err)
		}
		for _, tid := range []tenant.ID{"", "bogus"} {
			if _, err := repo.Get(ctx, tid, doc.Document, "en"); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Get(tenant %q) err = %v", tid, err)
			}
			if _, err := repo.Put(ctx, tid, doc); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Put(tenant %q) err = %v", tid, err)
			}
			if err := repo.Delete(ctx, tid, doc.Document, "en"); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Delete(tenant %q) err = %v", tid, err)
			}
		}
		if _, err := repo.Put(ctx, tenant.ID(id.New(id.Tenant)), doc); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Put(missing tenant) err = %v", err)
		}

		// Isolation.
		if _, err := repo.Get(ctx, b.ID, doc.Document, "en"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get from B err = %v", err)
		}
		if err := repo.Delete(ctx, b.ID, doc.Document, "en"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete from B err = %v", err)
		}
		bDoc := doc
		bDoc.Content = "B"
		if _, err := repo.Put(ctx, b.ID, bDoc); err != nil {
			t.Fatal(err)
		}
		if got, err := repo.Get(ctx, a.ID, doc.Document, "en"); err != nil || got.Content == "B" {
			t.Errorf("A's document after B's Put = %+v, %v", got, err)
		}

		// Tx variants.
		s, err := db.Scoped(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			x := doc
			x.Document, x.Language, x.Content = store.LegalNotice, "fr", "Tx"
			if _, err := repo.PutTx(ctx, tx, x); err != nil {
				return err
			}
			x.Content = "\x00"
			if _, err := repo.PutTx(ctx, tx, x); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("PutTx(invalid) err = %v", err)
			}
			if err := repo.DeleteTx(ctx, tx, store.LegalNotice, "en"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("DeleteTx(missing) err = %v", err)
			}
			return repo.DeleteTx(ctx, tx, store.LegalNotice, "fr")
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Get(ctx, a.ID, store.LegalNotice, "fr"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get after DeleteTx err = %v", err)
		}

		if err := repo.Delete(ctx, a.ID, doc.Document, "en"); err != nil {
			t.Fatal(err)
		}
		if err := repo.Delete(ctx, a.ID, doc.Document, "en"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete twice err = %v", err)
		}
		if got, err := repo.Get(ctx, b.ID, doc.Document, "en"); err != nil || got.Content != "B" {
			t.Errorf("B's document after A's delete = %+v, %v", got, err)
		}
	})
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// createLegacyTenant inserts a tenant with the columns of migrations 0001
// to 0008 only, for the upgrade tests run on an older schema.
func createLegacyTenant(ctx context.Context, t *testing.T, db *DB, fqdn string, maxTransfer int64) tenant.ID {
	t.Helper()
	tid := tenant.ID(id.New(id.Tenant))
	q := `INSERT INTO tenants (id, name, fqdn, default_language, max_transfer_bytes, storage_quota_bytes,
		created_at, updated_at) VALUES (?, 'Legacy', ?, 'fr', ?, 1000, 1, 1)`
	if db.dialect.numbered {
		q = rebindNumbered(q)
	}
	err := db.runTx(ctx, db.write, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, q, string(tid), fqdn, maxTransfer)
		return err
	})
	if err != nil {
		t.Fatalf("insert legacy tenant: %v", err)
	}
	return tid
}

// TestMigration0009Upgrade applies 0009_tenant_config on a database at
// 0008 holding tenants: each one gets its transfer limit as ceiling, the
// active status, the default colors and no asset, and the new tables work.
func TestMigration0009Upgrade(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		db.migrationsFS = migrationsUpTo(t, 8)
		if n, err := db.Migrate(ctx); err != nil || n != 8 {
			t.Fatalf("Migrate to 0008 = %d, %v", n, err)
		}
		small := createLegacyTenant(ctx, t, db, "a.example.com", 5)
		full := createLegacyTenant(ctx, t, db, "b.example.com", tenant.MaxTransferLimit)

		db.migrationsFS = migrationFiles
		if n, err := db.Migrate(ctx); err != nil || n != len(mustMigrations(t, db))-8 {
			t.Fatalf("Migrate to the latest = %d, %v", n, err)
		}
		for tid, want := range map[tenant.ID]int64{small: 5, full: tenant.MaxTransferLimit} {
			got, err := db.Tenants().Get(ctx, tid)
			if err != nil {
				t.Fatal(err)
			}
			if got.MaxTransferCeiling != want || got.MaxTransferBytes != want || got.Status != tenant.StatusActive ||
				got.PrimaryColor != tenant.DefaultPrimaryColor || got.AccentColor != tenant.DefaultAccentColor ||
				got.HasLogo || got.HasBackground || got.Validate() != nil {
				t.Errorf("tenant after 0009 = %+v", got)
			}
		}
		if _, err := db.TenantLegalDocuments().Put(ctx, small, LegalDocument{Document: LegalNotice, Language: "fr", Content: "x"}); err != nil {
			t.Errorf("legal document after 0009: %v", err)
		}
		if _, err := db.TenantEmailTemplates().Put(ctx, small, EmailTemplate{Key: EmailTemplateInvitation, Language: "en", Subject: "s"}); err != nil {
			t.Errorf("mail template after 0009: %v", err)
		}
	})
}

// TestTenantConfigSchemaConstraints checks every check constraint of
// migration 0009 directly in the database, on both engines.
func TestTenantConfigSchemaConstraints(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openEngine(t, e)
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 10, StorageQuotaBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		tid := "'" + string(tn.ID) + "'"
		boolean := func(v bool) string {
			switch {
			case e.Driver == "postgres" && v:
				return "true"
			case e.Driver == "postgres":
				return "false"
			case v:
				return "1"
			}
			return "0"
		}
		upd := `UPDATE tenants SET `
		where := ` WHERE id = ` + tid
		rejected := map[string]string{
			"ceiling under the limit":    upd + `max_transfer_ceiling = 9` + where,
			"ceiling over 20 GiB":        upd + `max_transfer_bytes = 21474836481, max_transfer_ceiling = 21474836481` + where,
			"unknown status":             upd + `status = 'archived'` + where,
			"empty status":               upd + `status = ''` + where,
			"short primary color":        upd + `primary_color = '#FFF'` + where,
			"primary color not hex":      upd + `primary_color = '#GGGGGG'` + where,
			"primary color without hash": upd + `primary_color = '1F4E799'` + where,
			"long accent color":          upd + `accent_color = '#1F4E7900'` + where,
			"accent color not hex":       upd + `accent_color = '#1F4E7Z'` + where,
		}
		if e.Driver != "postgres" {
			// PostgreSQL booleans hold nothing else by type.
			rejected["logo flag"] = upd + `has_logo = 2` + where
			rejected["background flag"] = upd + `has_background = -1` + where
		}
		tpl := `INSERT INTO tenant_email_templates (tenant_id, template_key, language, subject, body_html, body_text, updated_at, updated_by) VALUES (` + tid + `, `
		long := func(n int) string { return "'" + strings.Repeat("a", n) + "'" }
		rejected["unknown template"] = tpl + `'welcome', 'fr', 's', '', '', 0, '')`
		rejected["reserved v1.1 template"] = tpl + `'expiry-reminder', 'fr', 's', '', '', 0, '')`
		rejected["template language"] = tpl + `'invitation', 'de', 's', '', '', 0, '')`
		rejected["empty subject"] = tpl + `'invitation', 'fr', '', '', '', 0, '')`
		rejected["long subject"] = tpl + `'invitation', 'fr', ` + long(256) + `, '', '', 0, '')`
		rejected["long html body"] = tpl + `'invitation', 'fr', 's', ` + long(100_001) + `, '', 0, '')`
		rejected["long text body"] = tpl + `'invitation', 'fr', 's', '', ` + long(100_001) + `, 0, '')`
		rejected["long template author"] = tpl + `'invitation', 'fr', 's', '', '', 0, ` + long(65) + `)`
		rejected["template of no tenant"] = `INSERT INTO tenant_email_templates (tenant_id, template_key, language, subject, body_html, body_text, updated_at) VALUES ('ten_01JZZZZZZZZZZZZZZZZZZZZZZZ', 'invitation', 'fr', 's', '', '', 0)`
		legal := `INSERT INTO tenant_legal_documents (tenant_id, document, language, content, updated_at, updated_by) VALUES (` + tid + `, `
		rejected["unknown document"] = legal + `'terms', 'fr', '', 0, '')`
		rejected["document language"] = legal + `'legal-notice', 'it', '', 0, '')`
		rejected["long document"] = legal + `'legal-notice', 'fr', ` + long(100_001) + `, 0, '')`
		rejected["long document author"] = legal + `'legal-notice', 'fr', '', 0, ` + long(65) + `)`
		for name, q := range rejected {
			if _, err := rawSystemExec(ctx, db, q); err == nil {
				t.Errorf("%s accepted", name)
			}
		}

		accepted := []string{
			upd + `max_transfer_ceiling = 10` + where,
			upd + `max_transfer_bytes = 21474836480, max_transfer_ceiling = 21474836480` + where,
			upd + `status = 'deleting'` + where,
			upd + `status = 'active', primary_color = '#abcdef', accent_color = '#ABCDEF', has_logo = ` + boolean(true) +
				`, has_background = ` + boolean(true) + where,
			tpl + `'invitation', 'fr', ` + long(255) + `, ` + long(100_000) + `, ` + long(100_000) + `, 0, ` + long(64) + `)`,
			legal + `'privacy-policy', 'en', ` + long(100_000) + `, 0, '')`,
			// Length counts characters, not bytes.
			tpl + `'invitation', 'en', '` + strings.Repeat("é", 255) + `', '', '', 0, '')`,
		}
		for _, q := range accepted {
			if _, err := rawSystemExec(ctx, db, q); err != nil {
				t.Errorf("%.120s: %v", q, err)
			}
		}
		// Primary keys: one template per key and language, one document
		// per kind and language.
		if _, err := rawSystemExec(ctx, db, tpl+`'invitation', 'fr', 's', '', '', 0, '')`); err == nil {
			t.Error("duplicate template accepted")
		}
		if _, err := rawSystemExec(ctx, db, legal+`'privacy-policy', 'en', '', 0, '')`); err == nil {
			t.Error("duplicate legal document accepted")
		}
	})
}

// TestTenantConfigDriverFaults injects a driver failure into each step of
// the tenant configuration operations and checks that it surfaces as an
// error.
func TestTenantConfigDriverFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	a, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "D", FQDN: "d.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Tenants().SetStatus(ctx, d.ID, tenant.StatusDeleting); err != nil {
		t.Fatal(err)
	}
	if err := db.WrappedKeys().Create(ctx, a.ID, WrappedKey{ID: id.New(id.WrappedKey), Purpose: KeyPurposeDEK, KeyID: testMK1, Blob: []byte("k")}); err != nil {
		t.Fatal(err)
	}
	tpl := EmailTemplate{Key: EmailTemplateInvitation, Language: "fr", Subject: "s"}
	doc := LegalDocument{Document: LegalNotice, Language: "fr", Content: "c"}
	seed := func() {
		plan.reset()
		if _, err := db.TenantEmailTemplates().Put(ctx, a.ID, tpl); err != nil {
			t.Fatal(err)
		}
		if _, err := db.TenantLegalDocuments().Put(ctx, a.ID, doc); err != nil {
			t.Fatal(err)
		}
	}
	ops := map[string]func() error{
		"tenants.setstatus":    func() error { return db.Tenants().SetStatus(ctx, d.ID, tenant.StatusDeleting) },
		"tenants.listdeleting": func() error { _, err := db.Tenants().ListDeleting(ctx); return err },
		"tenants.delete":       func() error { return db.Tenants().Delete(ctx, a.ID) },
		"keys.listids":         func() error { _, err := db.WrappedKeys().ListIDs(ctx, a.ID, "", 0); return err },
		"templates.get":        func() error { _, err := db.TenantEmailTemplates().Get(ctx, a.ID, tpl.Key, "fr"); return err },
		"templates.list":       func() error { _, err := db.TenantEmailTemplates().List(ctx, a.ID); return err },
		"templates.put":        func() error { _, err := db.TenantEmailTemplates().Put(ctx, a.ID, tpl); return err },
		"templates.delete":     func() error { return db.TenantEmailTemplates().Delete(ctx, a.ID, tpl.Key, "fr") },
		"legal.get":            func() error { _, err := db.TenantLegalDocuments().Get(ctx, a.ID, doc.Document, "fr"); return err },
		"legal.put":            func() error { _, err := db.TenantLegalDocuments().Put(ctx, a.ID, doc); return err },
		"legal.delete":         func() error { return db.TenantLegalDocuments().Delete(ctx, a.ID, doc.Document, "fr") },
		"templates.tx": func() error {
			s, _ := db.Scoped(a.ID)
			return s.Tx(ctx, func(tx *ScopedTx) error {
				if _, err := db.TenantEmailTemplates().PutTx(ctx, tx, tpl); err != nil {
					return err
				}
				if _, err := db.TenantEmailTemplates().GetTx(ctx, tx, tpl.Key, "fr"); err != nil {
					return err
				}
				return db.TenantEmailTemplates().DeleteTx(ctx, tx, tpl.Key, "fr")
			})
		},
		"legal.tx": func() error {
			s, _ := db.Scoped(a.ID)
			return s.Tx(ctx, func(tx *ScopedTx) error {
				if _, err := db.TenantLegalDocuments().PutTx(ctx, tx, doc); err != nil {
					return err
				}
				return db.TenantLegalDocuments().DeleteTx(ctx, tx, doc.Document, "fr")
			})
		},
	}
	faults := []struct{ op, match string }{
		{faultBegin, ""},
		{faultCommit, ""},
		{faultExec, ""},
		{faultExec, "INSERT"},
		{faultExec, "DELETE"},
		{faultQuery, ""},
		{faultNext, ""},
		{faultScanNil, ""},
		{faultRows, ""},
	}
	for name, op := range ops {
		for _, f := range faults {
			for after := 0; after < 4; after++ {
				seed()
				plan.add(f.op, f.match, after)
				_ = op() // must not panic; errors are checked below
			}
		}
		seed()
		if err := op(); err != nil && !errors.Is(err, ErrKeysRemain) {
			t.Errorf("%s fails without faults: %v", name, err)
		}
	}

	// Specific expectations: a failure is never reported as success.
	for name, op := range ops {
		seed()
		plan.add(faultBegin, "", 0)
		if err := op(); !errors.Is(err, errInjected) {
			t.Errorf("%s ignores a begin fault: %v", name, err)
		}
	}
	for _, f := range []struct{ name, op, match string }{
		{"listdeleting scan", faultScanNil, "FROM tenants"},
		{"listdeleting rows", faultNext, "FROM tenants"},
	} {
		plan.reset()
		plan.add(f.op, f.match, 0)
		if _, err := db.Tenants().ListDeleting(ctx); err == nil {
			t.Errorf("%s ignored", f.name)
		}
	}
	for _, f := range []string{faultScanNil, faultNext} {
		plan.reset()
		plan.add(f, "FROM wrapped_keys", 0)
		if _, err := db.WrappedKeys().ListIDs(ctx, a.ID, "", 0); err == nil {
			t.Errorf("listids %s ignored", f)
		}
		seed()
		plan.add(f, "FROM tenant_email_templates", 0)
		if _, err := db.TenantEmailTemplates().List(ctx, a.ID); err == nil {
			t.Errorf("templates list %s ignored", f)
		}
	}
	for name, op := range map[string]func() error{
		"setstatus":       func() error { return db.Tenants().SetStatus(ctx, d.ID, tenant.StatusActive) },
		"template delete": func() error { return db.TenantEmailTemplates().Delete(ctx, a.ID, tpl.Key, "fr") },
		"legal delete":    func() error { return db.TenantLegalDocuments().Delete(ctx, a.ID, doc.Document, "fr") },
	} {
		seed()
		plan.add(faultRows, "", 0)
		if err := op(); !errors.Is(err, errInjected) {
			t.Errorf("%s rows affected fault: %v", name, err)
		}
	}
	plan.reset()
}

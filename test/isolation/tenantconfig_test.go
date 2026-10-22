package isolation_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// seedTenantConfig gives A and B the same customized template and legal
// document keys, with distinct contents.
func seedTenantConfig(t *testing.T, f *fixture) {
	t.Helper()
	ctx := t.Context()
	for tid, who := range map[tenant.ID]string{f.a.ID: "A", f.b.ID: "B"} {
		if _, err := f.db.TenantEmailTemplates().Put(ctx, tid, store.EmailTemplate{
			Key: store.EmailTemplateInvitation, Language: "fr", Subject: "subject of " + who, BodyText: "secret of " + who,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.TenantLegalDocuments().Put(ctx, tid, store.LegalDocument{
			Document: store.LegalNotice, Language: "fr", Content: "notice of " + who,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// assertConfigOf checks that tid still holds its own template and legal
// document, written by seedTenantConfig.
func assertConfigOf(t *testing.T, f *fixture, tid tenant.ID, who string) {
	t.Helper()
	ctx := t.Context()
	tpl, err := f.db.TenantEmailTemplates().Get(ctx, tid, store.EmailTemplateInvitation, "fr")
	if err != nil || tpl.Subject != "subject of "+who || tpl.BodyText != "secret of "+who {
		t.Errorf("template of %s = %+v, %v", who, tpl, err)
	}
	doc, err := f.db.TenantLegalDocuments().Get(ctx, tid, store.LegalNotice, "fr")
	if err != nil || doc.Content != "notice of "+who {
		t.Errorf("legal document of %s = %+v, %v", who, doc, err)
	}
}

// TestTenantConfigIsolation checks, through the repositories, that a
// tenant can neither read, replace nor delete the mail templates and legal
// documents of another tenant holding the same keys.
func TestTenantConfigIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		seedTenantConfig(t, f)

		// A's operations only ever reach A's rows.
		if l, err := f.db.TenantEmailTemplates().List(ctx, f.a.ID); err != nil || len(l) != 1 {
			t.Errorf("List(A) = %+v, %v", l, err)
		}
		if _, err := f.db.TenantEmailTemplates().Put(ctx, f.a.ID, store.EmailTemplate{
			Key: store.EmailTemplateInvitation, Language: "fr", Subject: "subject of A", BodyText: "secret of A",
		}); err != nil {
			t.Fatal(err)
		}
		assertConfigOf(t, f, f.b.ID, "B")
		if err := f.db.TenantEmailTemplates().Delete(ctx, f.a.ID, store.EmailTemplateInvitation, "fr"); err != nil {
			t.Fatal(err)
		}
		if err := f.db.TenantLegalDocuments().Delete(ctx, f.a.ID, store.LegalNotice, "fr"); err != nil {
			t.Fatal(err)
		}
		assertConfigOf(t, f, f.b.ID, "B")
		// A, now without customization, sees nothing of B.
		_, err := f.db.TenantEmailTemplates().Get(ctx, f.a.ID, store.EmailTemplateInvitation, "fr")
		assertNotFound(t, "Get(A's deleted template)", err)
		_, err = f.db.TenantLegalDocuments().Get(ctx, f.a.ID, store.LegalNotice, "fr")
		assertNotFound(t, "Get(A's deleted document)", err)
		assertNotFound(t, "Delete(A's deleted template)", f.db.TenantEmailTemplates().Delete(ctx, f.a.ID, store.EmailTemplateInvitation, "fr"))
		assertNotFound(t, "Delete(A's deleted document)", f.db.TenantLegalDocuments().Delete(ctx, f.a.ID, store.LegalNotice, "fr"))
		if l, err := f.db.TenantEmailTemplates().List(ctx, f.a.ID); err != nil || len(l) != 0 {
			t.Errorf("List(A) after reset = %+v, %v", l, err)
		}

		// A transaction bound to A cannot reach B either.
		s, err := f.db.Scoped(f.a.ID)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Tx(ctx, func(tx *store.ScopedTx) error {
			_, err := f.db.TenantEmailTemplates().GetTx(ctx, tx, store.EmailTemplateInvitation, "fr")
			assertNotFound(t, "GetTx(B's template) from A", err)
			assertNotFound(t, "DeleteTx(B's template) from A", f.db.TenantEmailTemplates().DeleteTx(ctx, tx, store.EmailTemplateInvitation, "fr"))
			assertNotFound(t, "DeleteTx(B's document) from A", f.db.TenantLegalDocuments().DeleteTx(ctx, tx, store.LegalNotice, "fr"))
			return nil
		})
		assertConfigOf(t, f, f.b.ID, "B")

		// Deleting B (keys erased first) removes only B's configuration.
		seedTenantConfig(t, f)
		if err := f.db.Tenants().Delete(ctx, f.b.ID); err != nil {
			t.Fatalf("Delete(B): %v", err)
		}
		for _, table := range []string{"tenant_email_templates", "tenant_legal_documents"} {
			if n := rawCount(t, e, table, "tenant_id", f.b.ID); n != 0 {
				t.Errorf("%s holds %d rows of deleted B", table, n)
			}
			if n := rawCount(t, e, table, "tenant_id", f.a.ID); n != 1 {
				t.Errorf("%s holds %d rows of A, want 1", table, n)
			}
		}
		assertConfigOf(t, f, f.a.ID, "A")
	})
}

// TestTenantDeletingNeverResolves checks that a tenant whose deletion has
// started is unknown to the Host resolution, exactly like a host that no
// tenant serves, while the other tenant keeps resolving.
func TestTenantDeletingNeverResolves(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		res := tenant.NewResolver(f.db.Tenants())
		if got, err := res.Resolve(ctx, fqdnA); err != nil || got.ID != f.a.ID {
			t.Fatalf("Resolve(A) = %+v, %v", got, err)
		}
		if err := f.db.Tenants().SetStatus(ctx, f.a.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		res.Invalidate(fqdnA)
		_, errDeleting := f.db.Tenants().TenantByFQDN(ctx, fqdnA)
		_, errUnknown := f.db.Tenants().TenantByFQDN(ctx, "transfer.entity-z.example.com")
		for name, err := range map[string]error{"deleting": errDeleting, "unknown": errUnknown} {
			if !errors.Is(err, tenant.ErrUnknownTenant) || !errors.Is(err, store.ErrNotFound) {
				t.Errorf("TenantByFQDN(%s) err = %v", name, err)
			}
		}
		if errDeleting.Error() != errUnknown.Error() {
			t.Errorf("a deleting tenant is distinguishable: %q vs %q", errDeleting, errUnknown)
		}
		if got, err := res.Resolve(ctx, fqdnA); !errors.Is(err, tenant.ErrUnknownTenant) {
			t.Errorf("Resolve(deleting A) = %+v, %v", got, err)
		}
		if got, err := res.Resolve(ctx, fqdnB); err != nil || got.ID != f.b.ID {
			t.Errorf("Resolve(B) = %+v, %v", got, err)
		}
		if ids, err := f.db.Tenants().ListDeleting(ctx); err != nil || len(ids) != 1 || ids[0] != f.a.ID {
			t.Errorf("ListDeleting = %v, %v", ids, err)
		}
	})
}

// TestRLSTenantConfigCrossTenantRawSQL bypasses the application layer: a
// raw transaction scoped to A aims SELECT, UPDATE, DELETE and INSERT
// statements at B's mail templates and legal documents. Row-level security
// alone must stop them.
func TestRLSTenantConfigCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	seedTenantConfig(t, f)
	a, b := string(f.a.ID), string(f.b.ID)

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM tenant_email_templates WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM tenant_email_templates`, nil, 1},
			{`SELECT count(*) FROM tenant_email_templates WHERE body_text = 'secret of B'`, nil, 0},
			{`SELECT count(*) FROM tenant_legal_documents WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM tenant_legal_documents`, nil, 1},
			{`SELECT count(*) FROM tenant_legal_documents WHERE true OR tenant_id = $1`, []any{b}, 1},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE tenant_email_templates SET subject = 'pwned' WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM tenant_email_templates WHERE tenant_id = $1`, []any{b}},
			{`UPDATE tenant_legal_documents SET content = 'pwned' WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM tenant_legal_documents WHERE tenant_id = $1`, []any{b}},
			{`UPDATE tenants SET status = 'deleting' WHERE id = $1`, []any{b}},
		} {
			if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
				t.Errorf("%s affected %d rows of B", s.stmt, n)
			}
		}
		return nil
	})

	for _, v := range []struct {
		name string
		stmt string
		args []any
	}{
		{"insert a template for B", `INSERT INTO tenant_email_templates (tenant_id, template_key, language, subject, body_html, body_text, updated_at) VALUES ($1, 'verification-code', 'fr', 'x', '', '', 0)`, []any{b}},
		{"insert a legal document for B", `INSERT INTO tenant_legal_documents (tenant_id, document, language, content, updated_at) VALUES ($1, 'privacy-policy', 'fr', 'x', 0)`, []any{b}},
		{"move A's templates to B", `UPDATE tenant_email_templates SET tenant_id = $1`, []any{b}},
		{"move A's legal documents to B", `UPDATE tenant_legal_documents SET tenant_id = $1`, []any{b}},
	} {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			assertRLSViolation(t, v.name, err)
		})
	}
	assertConfigOf(t, f, f.a.ID, "A")
	assertConfigOf(t, f, f.b.ID, "B")
	if got, err := f.db.Tenants().Get(ctx, f.b.ID); err != nil || got.Status != tenant.StatusActive {
		t.Errorf("B after the attacks = %+v, %v", got, err)
	}
}

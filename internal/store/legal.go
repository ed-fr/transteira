package store

import (
	"context"
	"database/sql"

	"github.com/ed-fr/transteira/internal/tenant"
)

// qLegalList lists the legal documents written by a tenant, without their
// content.
var qLegalList = tenantQuery(
	`SELECT document, language FROM tenant_legal_documents
	WHERE tenant_id = ? ORDER BY document, language`)

// LegalDocumentKey names a legal document written by a tenant in one
// language.
type LegalDocumentKey struct {
	// Document is LegalNotice or PrivacyPolicy.
	Document string
	// Language is the language of the document.
	Language string
}

// List returns the legal documents tenant tid has written, without their
// content, ordered by document then language: one query serves the public
// configuration of the tenant and the language fallback of the public
// pages. It returns an empty slice when the tenant has written none (or
// does not exist).
func (r *TenantLegalDocuments) List(ctx context.Context, tid tenant.ID) ([]LegalDocumentKey, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return nil, err
	}
	var out []LegalDocumentKey
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		rows, err := tx.Query(ctx, qLegalList)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (LegalDocumentKey, error) {
			var k LegalDocumentKey
			err := r.Scan(&k.Document, &k.Language)
			return k, err
		})
		return err
	})
	if err != nil {
		return nil, wrap("list legal documents", err)
	}
	return out, nil
}

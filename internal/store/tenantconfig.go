package store

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Mail template keys (OpenAPI EmailTemplateKey), as stored in
// tenant_email_templates.template_key. Adding one requires a migration of
// the table's check.
const (
	EmailTemplateVerificationCode     = "verification-code"
	EmailTemplateTransferNotification = "transfer-notification"
	EmailTemplateTransferConfirmation = "transfer-confirmation"
	EmailTemplateFirstDownload        = "first-download"
	EmailTemplateFileProblems         = "file-problems"
	EmailTemplateFileNotScanned       = "file-not-scanned"
	EmailTemplateInvitation           = "invitation"
	EmailTemplateQuotaWarning         = "quota-warning"
	EmailTemplateQuotaReached         = "quota-reached"
	EmailTemplateDiskAlert            = "disk-alert"
	EmailTemplateAntivirusUnavailable = "antivirus-unavailable"
)

// Legal documents of a tenant (OpenAPI LegalDocumentPath), as stored in
// tenant_legal_documents.document.
const (
	LegalNotice   = "legal-notice"
	PrivacyPolicy = "privacy-policy"
)

// Length limits of the tenant texts, in characters (OpenAPI
// EmailTemplateUpdate and LegalDocumentUpdate).
const (
	// MaxEmailSubjectLen bounds a mail template subject (at least 1).
	MaxEmailSubjectLen = 255
	// MaxEmailBodyLen bounds each body of a mail template.
	MaxEmailBodyLen = 100_000
	// MaxLegalContentLen bounds the Markdown of a legal document.
	MaxLegalContentLen = 100_000
)

// emailTemplateKeys lists the known template keys, sorted.
var emailTemplateKeys = []string{
	EmailTemplateAntivirusUnavailable, EmailTemplateDiskAlert, EmailTemplateFileNotScanned,
	EmailTemplateFileProblems, EmailTemplateFirstDownload, EmailTemplateInvitation,
	EmailTemplateQuotaReached, EmailTemplateQuotaWarning, EmailTemplateTransferConfirmation,
	EmailTemplateTransferNotification, EmailTemplateVerificationCode,
}

// EmailTemplateKeys returns the known mail template keys, sorted. The slice
// is a copy.
func EmailTemplateKeys() []string { return slices.Clone(emailTemplateKeys) }

// IsEmailTemplateKey reports whether key is a known mail template key.
func IsEmailTemplateKey(key string) bool {
	_, found := slices.BinarySearch(emailTemplateKeys, key)
	return found
}

// IsLegalDocument reports whether doc names a legal document.
func IsLegalDocument(doc string) bool { return doc == LegalNotice || doc == PrivacyPolicy }

// Statements of the TenantEmailTemplates and TenantLegalDocuments
// repositories.
var (
	qTemplateGet = tenantQuery(
		`SELECT subject, body_html, body_text, updated_at, updated_by FROM tenant_email_templates
		WHERE tenant_id = ? AND template_key = ? AND language = ?`)
	qTemplateList = tenantQuery(
		`SELECT template_key, language, updated_at FROM tenant_email_templates
		WHERE tenant_id = ? ORDER BY template_key, language`)
	qTemplateUpdate = tenantQuery(
		`UPDATE tenant_email_templates SET subject = ?, body_html = ?, body_text = ?, updated_at = ?, updated_by = ?
		WHERE tenant_id = ? AND template_key = ? AND language = ?`)
	qTemplateInsert = tenantQuery(
		`INSERT INTO tenant_email_templates (tenant_id, template_key, language, subject, body_html, body_text,
		updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	qTemplateDelete = tenantQuery(
		`DELETE FROM tenant_email_templates WHERE tenant_id = ? AND template_key = ? AND language = ?`)

	qLegalGet = tenantQuery(
		`SELECT content, updated_at, updated_by FROM tenant_legal_documents
		WHERE tenant_id = ? AND document = ? AND language = ?`)
	qLegalUpdate = tenantQuery(
		`UPDATE tenant_legal_documents SET content = ?, updated_at = ?, updated_by = ?
		WHERE tenant_id = ? AND document = ? AND language = ?`)
	qLegalInsert = tenantQuery(
		`INSERT INTO tenant_legal_documents (tenant_id, document, language, content, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?, ?)`)
	qLegalDelete = tenantQuery(
		`DELETE FROM tenant_legal_documents WHERE tenant_id = ? AND document = ? AND language = ?`)
)

// EmailTemplate is a mail template customized by a tenant (spec 12.3), for
// one template key and one language. The store only bounds the texts: the
// variable syntax and the HTML sanitizing are checked by internal/mail
// before storing.
type EmailTemplate struct {
	// Key is the template key (see [EmailTemplateKeys]).
	Key string
	// Language is a supported UI language ([tenant.IsLanguage]).
	Language string
	// Subject is the subject line: 1 to MaxEmailSubjectLen characters, no
	// control character (it becomes a mail header).
	Subject string
	// BodyHTML and BodyText are the bodies, at most MaxEmailBodyLen
	// characters each, valid UTF-8 without NUL.
	BodyHTML string
	BodyText string
	// UpdatedAt is the time of the last change; the store's clock is used
	// when it is zero.
	UpdatedAt time.Time
	// UpdatedBy is the administrator who saved it ("adm_" ID), "" when
	// unknown.
	UpdatedBy string
}

// EmailTemplateSummary describes a customized template without its texts.
type EmailTemplateSummary struct {
	// Key is the template key.
	Key string
	// Language is the template language.
	Language string
	// UpdatedAt is the time of the last change.
	UpdatedAt time.Time
}

// LegalDocument is a legal notice or privacy policy of a tenant (spec 13),
// in one language.
type LegalDocument struct {
	// Document is LegalNotice or PrivacyPolicy.
	Document string
	// Language is a supported UI language ([tenant.IsLanguage]).
	Language string
	// Content is the limited Markdown source, at most MaxLegalContentLen
	// characters, valid UTF-8 without NUL. It is rendered and sanitized on
	// output.
	Content string
	// UpdatedAt is the time of the last change; the store's clock is used
	// when it is zero.
	UpdatedAt time.Time
	// UpdatedBy is the administrator who saved it ("adm_" ID), "" when
	// unknown.
	UpdatedBy string
}

// TenantEmailTemplates is the tenant-scoped repository of customized mail
// templates. A template without a row uses the default one. Obtain it with
// [DB.TenantEmailTemplates].
type TenantEmailTemplates struct {
	db *DB
}

// TenantEmailTemplates returns the mail template repository.
func (db *DB) TenantEmailTemplates() *TenantEmailTemplates { return &TenantEmailTemplates{db: db} }

// TenantLegalDocuments is the tenant-scoped repository of legal documents.
// Obtain it with [DB.TenantLegalDocuments].
type TenantLegalDocuments struct {
	db *DB
}

// TenantLegalDocuments returns the legal document repository.
func (db *DB) TenantLegalDocuments() *TenantLegalDocuments { return &TenantLegalDocuments{db: db} }

// validBody reports whether s is valid UTF-8 of at most maxRunes
// characters without NUL (which PostgreSQL text cannot hold).
func validBody(s string, maxRunes int) bool {
	return validText(s, maxRunes, false) && !strings.ContainsRune(s, 0)
}

// validUpdatedBy reports whether s is "" or an administrator ID.
func validUpdatedBy(s string) bool {
	return s == "" || id.Valid(id.Admin, s)
}

// checkTemplateKey validates a template key and language.
func checkTemplateKey(key, lang string) error {
	switch {
	case !IsEmailTemplateKey(key):
		return invalid("unknown mail template")
	case !tenant.IsLanguage(lang):
		return invalid("unsupported language")
	}
	return nil
}

// checkLegalKey validates a legal document and language.
func checkLegalKey(doc, lang string) error {
	switch {
	case !IsLegalDocument(doc):
		return invalid("unknown legal document")
	case !tenant.IsLanguage(lang):
		return invalid("unsupported language")
	}
	return nil
}

// Get returns the template key in language lang customized by tenant tid,
// or ErrNotFound when the tenant uses the default one (or does not exist).
// It returns ErrInvalid for an unknown key or language.
func (r *TenantEmailTemplates) Get(ctx context.Context, tid tenant.ID, key, lang string) (EmailTemplate, error) {
	if err := checkTemplateKey(key, lang); err != nil {
		return EmailTemplate{}, err
	}
	s, err := r.db.Scoped(tid)
	if err != nil {
		return EmailTemplate{}, err
	}
	var t EmailTemplate
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		var err error
		t, err = getTemplate(ctx, tx, key, lang)
		return err
	})
	if err != nil {
		return EmailTemplate{}, wrap("get mail template", err)
	}
	return t, nil
}

// GetTx is [TenantEmailTemplates.Get] inside tx, for the tenant tx is bound
// to (for example to choose the template of a mail being queued).
func (r *TenantEmailTemplates) GetTx(ctx context.Context, tx *ScopedTx, key, lang string) (EmailTemplate, error) {
	if err := checkTemplateKey(key, lang); err != nil {
		return EmailTemplate{}, err
	}
	t, err := getTemplate(ctx, tx, key, lang)
	if err != nil {
		return EmailTemplate{}, wrap("get mail template", err)
	}
	return t, nil
}

// getTemplate reads one template in tx, returning raw errors.
func getTemplate(ctx context.Context, tx *ScopedTx, key, lang string) (EmailTemplate, error) {
	t := EmailTemplate{Key: key, Language: lang}
	var updated int64
	if err := tx.QueryRow(ctx, qTemplateGet, key, lang).Scan(&t.Subject, &t.BodyHTML, &t.BodyText, &updated, &t.UpdatedBy); err != nil {
		return EmailTemplate{}, err
	}
	t.UpdatedAt = fromMillis(updated)
	return t, nil
}

// List returns the templates customized by tenant tid, ordered by key and
// language (empty for a tenant using only the defaults, or unknown).
func (r *TenantEmailTemplates) List(ctx context.Context, tid tenant.ID) ([]EmailTemplateSummary, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return nil, err
	}
	var out []EmailTemplateSummary
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		rows, err := tx.Query(ctx, qTemplateList)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (EmailTemplateSummary, error) {
			var (
				e       EmailTemplateSummary
				updated int64
			)
			err := r.Scan(&e.Key, &e.Language, &updated)
			e.UpdatedAt = fromMillis(updated)
			return e, err
		})
		return err
	})
	if err != nil {
		return nil, wrap("list mail templates", err)
	}
	return out, nil
}

// Put creates or replaces the customized template t of tenant tid in its
// own transaction (see [TenantEmailTemplates.PutTx]).
func (r *TenantEmailTemplates) Put(ctx context.Context, tid tenant.ID, t EmailTemplate) (EmailTemplate, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return EmailTemplate{}, err
	}
	var out EmailTemplate
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		var err error
		out, err = r.put(ctx, tx, t)
		return err
	})
	if err != nil {
		return EmailTemplate{}, wrap("put mail template", err)
	}
	return out, nil
}

// PutTx creates or replaces the customized template t of the tenant tx is
// bound to, inside tx (so that the audit event commits with it), and
// returns it as stored. It returns ErrInvalid for an unknown key or
// language or a text out of bounds, and ErrNotFound when the tenant does
// not exist. After an error, the caller must abort the transaction.
func (r *TenantEmailTemplates) PutTx(ctx context.Context, tx *ScopedTx, t EmailTemplate) (EmailTemplate, error) {
	out, err := r.put(ctx, tx, t)
	if err != nil {
		return EmailTemplate{}, wrap("put mail template", err)
	}
	return out, nil
}

// put validates and upserts t in tx, returning raw errors.
func (r *TenantEmailTemplates) put(ctx context.Context, tx *ScopedTx, t EmailTemplate) (EmailTemplate, error) {
	if err := checkTemplateKey(t.Key, t.Language); err != nil {
		return EmailTemplate{}, err
	}
	switch {
	case t.Subject == "" || !validText(t.Subject, MaxEmailSubjectLen, true):
		return EmailTemplate{}, invalid("subject must be 1 to %d characters on one line", MaxEmailSubjectLen)
	case !validBody(t.BodyHTML, MaxEmailBodyLen), !validBody(t.BodyText, MaxEmailBodyLen):
		return EmailTemplate{}, invalid("mail bodies must be text of at most %d characters", MaxEmailBodyLen)
	case !validUpdatedBy(t.UpdatedBy):
		return EmailTemplate{}, invalid("malformed administrator id")
	}
	t.UpdatedAt = r.db.orNow(t.UpdatedAt).UTC().Truncate(time.Millisecond)
	at := toMillis(t.UpdatedAt)
	err := upsert(ctx, tx,
		qTemplateUpdate, []any{t.Subject, t.BodyHTML, t.BodyText, at, t.UpdatedBy, t.Key, t.Language},
		qTemplateInsert, []any{t.Key, t.Language, t.Subject, t.BodyHTML, t.BodyText, at, t.UpdatedBy})
	if err != nil {
		return EmailTemplate{}, err
	}
	return t, nil
}

// Delete removes the customized template key in language lang of tenant
// tid in its own transaction (see [TenantEmailTemplates.DeleteTx]).
func (r *TenantEmailTemplates) Delete(ctx context.Context, tid tenant.ID, key, lang string) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if err := s.Tx(ctx, func(tx *ScopedTx) error { return deleteTemplate(ctx, tx, key, lang) }); err != nil {
		return wrap("delete mail template", err)
	}
	return nil
}

// DeleteTx removes the customized template key in language lang of the
// tenant tx is bound to, inside tx: the default template applies again. It
// returns ErrInvalid for an unknown key or language and ErrNotFound when
// the template was not customized.
func (r *TenantEmailTemplates) DeleteTx(ctx context.Context, tx *ScopedTx, key, lang string) error {
	if err := deleteTemplate(ctx, tx, key, lang); err != nil {
		return wrap("delete mail template", err)
	}
	return nil
}

// deleteTemplate deletes one template in tx, returning raw errors.
func deleteTemplate(ctx context.Context, tx *ScopedTx, key, lang string) error {
	if err := checkTemplateKey(key, lang); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, qTemplateDelete, key, lang)
	if err != nil {
		return err
	}
	return expectOne(res)
}

// Get returns the legal document doc in language lang of tenant tid, or
// ErrNotFound when the tenant has not written it (or does not exist). It
// returns ErrInvalid for an unknown document or language.
func (r *TenantLegalDocuments) Get(ctx context.Context, tid tenant.ID, doc, lang string) (LegalDocument, error) {
	if err := checkLegalKey(doc, lang); err != nil {
		return LegalDocument{}, err
	}
	s, err := r.db.Scoped(tid)
	if err != nil {
		return LegalDocument{}, err
	}
	d := LegalDocument{Document: doc, Language: lang}
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		var updated int64
		if err := tx.QueryRow(ctx, qLegalGet, doc, lang).Scan(&d.Content, &updated, &d.UpdatedBy); err != nil {
			return err
		}
		d.UpdatedAt = fromMillis(updated)
		return nil
	})
	if err != nil {
		return LegalDocument{}, wrap("get legal document", err)
	}
	return d, nil
}

// Put creates or replaces the legal document d of tenant tid in its own
// transaction (see [TenantLegalDocuments.PutTx]).
func (r *TenantLegalDocuments) Put(ctx context.Context, tid tenant.ID, d LegalDocument) (LegalDocument, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return LegalDocument{}, err
	}
	var out LegalDocument
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		var err error
		out, err = r.put(ctx, tx, d)
		return err
	})
	if err != nil {
		return LegalDocument{}, wrap("put legal document", err)
	}
	return out, nil
}

// PutTx creates or replaces the legal document d of the tenant tx is bound
// to, inside tx, and returns it as stored. It returns ErrInvalid for an
// unknown document or language or a content out of bounds, and ErrNotFound
// when the tenant does not exist. After an error, the caller must abort
// the transaction.
func (r *TenantLegalDocuments) PutTx(ctx context.Context, tx *ScopedTx, d LegalDocument) (LegalDocument, error) {
	out, err := r.put(ctx, tx, d)
	if err != nil {
		return LegalDocument{}, wrap("put legal document", err)
	}
	return out, nil
}

// put validates and upserts d in tx, returning raw errors.
func (r *TenantLegalDocuments) put(ctx context.Context, tx *ScopedTx, d LegalDocument) (LegalDocument, error) {
	if err := checkLegalKey(d.Document, d.Language); err != nil {
		return LegalDocument{}, err
	}
	switch {
	case !validBody(d.Content, MaxLegalContentLen):
		return LegalDocument{}, invalid("legal document must be text of at most %d characters", MaxLegalContentLen)
	case !validUpdatedBy(d.UpdatedBy):
		return LegalDocument{}, invalid("malformed administrator id")
	}
	d.UpdatedAt = r.db.orNow(d.UpdatedAt).UTC().Truncate(time.Millisecond)
	at := toMillis(d.UpdatedAt)
	err := upsert(ctx, tx,
		qLegalUpdate, []any{d.Content, at, d.UpdatedBy, d.Document, d.Language},
		qLegalInsert, []any{d.Document, d.Language, d.Content, at, d.UpdatedBy})
	if err != nil {
		return LegalDocument{}, err
	}
	return d, nil
}

// Delete removes the legal document doc in language lang of tenant tid in
// its own transaction (see [TenantLegalDocuments.DeleteTx]).
func (r *TenantLegalDocuments) Delete(ctx context.Context, tid tenant.ID, doc, lang string) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if err := s.Tx(ctx, func(tx *ScopedTx) error { return deleteLegal(ctx, tx, doc, lang) }); err != nil {
		return wrap("delete legal document", err)
	}
	return nil
}

// DeleteTx removes the legal document doc in language lang of the tenant tx
// is bound to, inside tx. It returns ErrInvalid for an unknown document or
// language and ErrNotFound when the document does not exist.
func (r *TenantLegalDocuments) DeleteTx(ctx context.Context, tx *ScopedTx, doc, lang string) error {
	if err := deleteLegal(ctx, tx, doc, lang); err != nil {
		return wrap("delete legal document", err)
	}
	return nil
}

// deleteLegal deletes one legal document in tx, returning raw errors.
func deleteLegal(ctx context.Context, tx *ScopedTx, doc, lang string) error {
	if err := checkLegalKey(doc, lang); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, qLegalDelete, doc, lang)
	if err != nil {
		return err
	}
	return expectOne(res)
}

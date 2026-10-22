package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/markup"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// LegalDocument is a legal notice or privacy policy of a tenant in one
// language (OpenAPI LegalDocument).
type LegalDocument struct {
	Document string
	Language string
	// Markdown is the limited Markdown source, "" when not written.
	Markdown string
	// UpdatedAt is the time of the last change, zero when not written.
	UpdatedAt time.Time
}

// PublicLegalDocument is a legal document served on the public pages.
type PublicLegalDocument struct {
	LegalDocument
	// HTML is the Markdown rendered to sanitized HTML ([markup.Markdown]).
	HTML string
}

// legalDocuments lists the legal documents, in the API order.
var legalDocuments = []string{store.LegalNotice, store.PrivacyPolicy}

// checkLegal returns ErrNotFound for an unknown document or language.
func checkLegal(doc, lang string) error {
	if !store.IsLegalDocument(doc) || !tenant.IsLanguage(lang) {
		return ErrNotFound
	}
	return nil
}

// GetLegal returns the legal document doc in lang of tenant tid, with an
// empty source when the tenant has not written it.
func (s *Service) GetLegal(ctx context.Context, p adminauth.Principal, tid tenant.ID, doc, lang string) (LegalDocument, error) {
	if err := checkLegal(doc, lang); err != nil {
		return LegalDocument{}, err
	}
	if _, err := s.readable(ctx, p, tid); err != nil {
		return LegalDocument{}, err
	}
	d, err := s.repo.legal(ctx, tid, doc, lang)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return LegalDocument{Document: doc, Language: lang}, nil
	case err != nil:
		return LegalDocument{}, fmt.Errorf("tenantadmin: get legal document: %w", err)
	}
	return LegalDocument{Document: doc, Language: lang, Markdown: d.Content, UpdatedAt: d.UpdatedAt}, nil
}

// UpdateLegal replaces the legal document doc in lang of tenant tid with
// the Markdown source markdown (at most store.MaxLegalContentLen
// characters, valid UTF-8 without NUL). A blank source removes the
// document. The source is stored as is and rendered without raw HTML on
// output.
func (s *Service) UpdateLegal(ctx context.Context, p adminauth.Principal, tid tenant.ID, doc, lang, markdown string, ip netip.Addr) (LegalDocument, error) {
	if err := checkLegal(doc, lang); err != nil {
		return LegalDocument{}, err
	}
	// Access goes first: the refusal on a tenant out of reach never
	// depends on the body.
	if _, err := s.writable(ctx, p, tid); err != nil {
		return LegalDocument{}, err
	}
	if !utf8.ValidString(markdown) || strings.ContainsRune(markdown, 0) ||
		utf8.RuneCountInString(markdown) > store.MaxLegalContentLen {
		return LegalDocument{}, invalid(FieldMarkdown, "must be text of at most %d characters", store.MaxLegalContentLen)
	}
	out := LegalDocument{Document: doc, Language: lang}
	if strings.TrimSpace(markdown) == "" {
		err := s.repo.deleteLegal(ctx, tid, doc, lang)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return LegalDocument{}, fmt.Errorf("tenantadmin: delete legal document: %w", err)
		}
	} else {
		d, err := s.repo.putLegal(ctx, tid, store.LegalDocument{
			Document: doc, Language: lang, Content: markdown, UpdatedBy: p.Admin.ID,
		})
		switch {
		case errors.Is(err, store.ErrInvalid):
			return LegalDocument{}, invalid(FieldMarkdown, "invalid document")
		case errors.Is(err, store.ErrNotFound):
			return LegalDocument{}, ErrNotFound
		case err != nil:
			return LegalDocument{}, fmt.Errorf("tenantadmin: put legal document: %w", err)
		}
		out.Markdown, out.UpdatedAt = d.Content, d.UpdatedAt
	}
	s.record(ctx, p, ip, tid, ActionTenantLegalUpdated, map[string]any{
		"document": doc, "language": lang, "removed": out.Markdown == "",
	})
	return out, nil
}

// PublicLegal returns the legal document doc of tenant t for the public
// pages, rendered to sanitized HTML, in the first language written among:
// lang (the negotiated language), the default language of the tenant, then
// any other language in the order of [tenant.Languages]. Every document
// listed by [Service.LegalDocuments] is thus reachable. It returns
// ErrNotFound for an unknown document or when no version is written.
func (s *Service) PublicLegal(ctx context.Context, t *tenant.Tenant, doc, lang string) (PublicLegalDocument, error) {
	if !store.IsLegalDocument(doc) {
		return PublicLegalDocument{}, ErrNotFound
	}
	keys, err := s.repo.listLegal(ctx, t.ID)
	if err != nil {
		return PublicLegalDocument{}, fmt.Errorf("tenantadmin: list legal documents: %w", err)
	}
	written := func(l string) bool {
		return slices.Contains(keys, store.LegalDocumentKey{Document: doc, Language: l})
	}
	order := append([]string{lang, t.DefaultLanguage}, tenant.Languages()...)
	i := slices.IndexFunc(order, written)
	if i < 0 {
		return PublicLegalDocument{}, ErrNotFound
	}
	l := order[i]
	d, err := s.repo.legal(ctx, t.ID, doc, l)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Removed since the listing.
		return PublicLegalDocument{}, ErrNotFound
	case err != nil:
		return PublicLegalDocument{}, fmt.Errorf("tenantadmin: get legal document: %w", err)
	}
	return PublicLegalDocument{
		LegalDocument: LegalDocument{Document: doc, Language: l, Markdown: d.Content, UpdatedAt: d.UpdatedAt},
		HTML:          markup.Markdown(d.Content),
	}, nil
}

// LegalDocuments returns the legal documents tenant t has written in at
// least one language, in the API order, for the public configuration
// (OpenAPI PublicTenant.legalDocuments). It costs one store query.
func (s *Service) LegalDocuments(ctx context.Context, t *tenant.Tenant) ([]string, error) {
	keys, err := s.repo.listLegal(ctx, t.ID)
	if err != nil {
		return nil, fmt.Errorf("tenantadmin: list legal documents: %w", err)
	}
	out := []string{}
	for _, doc := range legalDocuments {
		if slices.ContainsFunc(keys, func(k store.LegalDocumentKey) bool { return k.Document == doc }) {
			out = append(out, doc)
		}
	}
	return out, nil
}

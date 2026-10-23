package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TemplateSummary tells whether a template is customized (OpenAPI
// EmailTemplateSummary).
type TemplateSummary struct {
	Key        string
	Language   string
	Customized bool
	// UpdatedAt is the time of the customization, zero for a default.
	UpdatedAt time.Time
}

// Template is a mail template, customized or default (OpenAPI
// EmailTemplate), in the {{name}} syntax.
type Template struct {
	Key        string
	Language   string
	Customized bool
	Subject    string
	HTML       string
	Text       string
	// Variables are the variables available in this template.
	Variables []mail.Variable
	// UpdatedAt is the time of the customization, zero for a default.
	UpdatedAt time.Time
}

// TemplateInput is a template submitted by an administrator (OpenAPI
// EmailTemplateUpdate).
type TemplateInput struct {
	Subject string
	HTML    string
	Text    string
}

// Preview is a template rendered with sample data (OpenAPI EmailPreview).
// HTML is the complete HTML body of the mail.
type Preview struct {
	Subject string
	HTML    string
	Text    string
}

// The template functions of package mail, replaced by the tests to reach
// failures the built-in templates never produce.
var (
	defaultSource     = mail.DefaultSource
	normalizeTemplate = mail.NormalizeTemplate
	previewTemplate   = mail.Preview
)

// templateKeys returns the template keys an administrator can customize:
// the keys of the API that have a built-in template.
func templateKeys() []string {
	var out []string
	for _, k := range store.EmailTemplateKeys() {
		if _, err := mail.Variables(k); err == nil {
			out = append(out, k)
		}
	}
	return out
}

// checkTemplate returns the variables of template key, or ErrNotFound for
// an unknown key or language.
func checkTemplate(key, lang string) ([]mail.Variable, error) {
	// A key of the API without a built-in template is unknown too.
	vars, err := mail.Variables(key)
	if err != nil || !store.IsEmailTemplateKey(key) || !tenant.IsLanguage(lang) {
		return nil, ErrNotFound
	}
	return vars, nil
}

// ListTemplates lists every template key and language of tenant tid and
// whether the tenant customized it.
func (s *Service) ListTemplates(ctx context.Context, p adminauth.Principal, tid tenant.ID) ([]TemplateSummary, error) {
	if _, err := s.readable(ctx, p, tid); err != nil {
		return nil, err
	}
	custom, err := s.repo.listTemplates(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("tenantadmin: list templates: %w", err)
	}
	at := make(map[[2]string]time.Time, len(custom))
	for _, c := range custom {
		at[[2]string{c.Key, c.Language}] = c.UpdatedAt
	}
	var out []TemplateSummary
	for _, key := range templateKeys() {
		for _, lang := range tenant.Languages() {
			updated, ok := at[[2]string{key, lang}]
			out = append(out, TemplateSummary{Key: key, Language: lang, Customized: ok, UpdatedAt: updated})
		}
	}
	return out, nil
}

// GetTemplate returns the customization of template key in lang of tenant
// tid, or the built-in template when there is none.
func (s *Service) GetTemplate(ctx context.Context, p adminauth.Principal, tid tenant.ID, key, lang string) (Template, error) {
	vars, err := checkTemplate(key, lang)
	if err != nil {
		return Template{}, err
	}
	if _, err := s.readable(ctx, p, tid); err != nil {
		return Template{}, err
	}
	out := Template{Key: key, Language: lang, Variables: vars}
	t, err := s.repo.template(ctx, tid, key, lang)
	switch {
	case err == nil:
		out.Customized, out.Subject, out.HTML, out.Text, out.UpdatedAt = true, t.Subject, t.BodyHTML, t.BodyText, t.UpdatedAt
		return out, nil
	case !errors.Is(err, store.ErrNotFound):
		return Template{}, fmt.Errorf("tenantadmin: get template: %w", err)
	}
	src, err := defaultSource(key, lang)
	if err != nil {
		return Template{}, fmt.Errorf("tenantadmin: default template: %w", err)
	}
	out.Subject, out.HTML, out.Text = src.Subject, src.HTML, src.Text
	return out, nil
}

// UpdateTemplate stores the customization of template key in lang of
// tenant tid: validated (variables, required variables, syntax) and with
// its HTML sanitized by [mail.NormalizeTemplate]. An invalid template is an
// *InvalidError on [FieldTemplate] listing the issues.
func (s *Service) UpdateTemplate(ctx context.Context, p adminauth.Principal, tid tenant.ID, key, lang string, in TemplateInput, ip netip.Addr) (Template, error) {
	vars, err := checkTemplate(key, lang)
	if err != nil {
		return Template{}, err
	}
	if _, err := s.writable(ctx, p, tid); err != nil {
		return Template{}, err
	}
	src, err := normalizeTemplate(key, mail.TemplateSource{Subject: in.Subject, HTML: in.HTML, Text: in.Text})
	if err != nil {
		return Template{}, templateError(err)
	}
	t, err := s.repo.putTemplate(ctx, tid, store.EmailTemplate{
		Key: key, Language: lang, Subject: src.Subject, BodyHTML: src.HTML, BodyText: src.Text, UpdatedBy: p.Admin.ID,
	})
	switch {
	case errors.Is(err, store.ErrInvalid):
		return Template{}, invalid(FieldTemplate, "template out of bounds")
	case errors.Is(err, store.ErrNotFound):
		return Template{}, ErrNotFound
	case err != nil:
		return Template{}, fmt.Errorf("tenantadmin: put template: %w", err)
	}
	s.record(ctx, p, ip, tid, ActionTenantTemplateUpdated, map[string]any{"template": key, "language": lang})
	return Template{
		Key: key, Language: lang, Customized: true, Subject: t.Subject, HTML: t.BodyHTML, Text: t.BodyText,
		Variables: vars, UpdatedAt: t.UpdatedAt,
	}, nil
}

// templateError maps a template validation error.
func templateError(err error) error {
	var ve *mail.ValidationError
	if errors.As(err, &ve) {
		return &InvalidError{Field: FieldTemplate, Reason: "invalid template", Issues: ve.Issues}
	}
	return fmt.Errorf("tenantadmin: template: %w", err)
}

// ResetTemplate removes the customization of template key in lang of
// tenant tid: the built-in template applies again. Resetting a template
// that is not customized succeeds.
func (s *Service) ResetTemplate(ctx context.Context, p adminauth.Principal, tid tenant.ID, key, lang string, ip netip.Addr) error {
	if _, err := checkTemplate(key, lang); err != nil {
		return err
	}
	if _, err := s.writable(ctx, p, tid); err != nil {
		return err
	}
	err := s.repo.deleteTemplate(ctx, tid, key, lang)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("tenantadmin: delete template: %w", err)
	}
	s.record(ctx, p, ip, tid, ActionTenantTemplateReset, map[string]any{"template": key, "language": lang})
	return nil
}

// PreviewTemplate renders template key in lang with sample data: in when
// not nil (unsaved), else the customization of tenant tid, else the
// built-in template. A stored customization that no longer validates is
// replaced by the built-in template, as when mails are sent.
func (s *Service) PreviewTemplate(ctx context.Context, p adminauth.Principal, tid tenant.ID, key, lang string, in *TemplateInput) (Preview, error) {
	if _, err := checkTemplate(key, lang); err != nil {
		return Preview{}, err
	}
	if _, err := s.readable(ctx, p, tid); err != nil {
		return Preview{}, err
	}
	var override *mail.TemplateSource
	if in != nil {
		override = &mail.TemplateSource{Subject: in.Subject, HTML: in.HTML, Text: in.Text}
	} else {
		t, err := s.repo.template(ctx, tid, key, lang)
		switch {
		case err == nil:
			override = &mail.TemplateSource{Subject: t.Subject, HTML: t.BodyHTML, Text: t.BodyText}
		case !errors.Is(err, store.ErrNotFound):
			return Preview{}, fmt.Errorf("tenantadmin: get template: %w", err)
		}
	}
	msg, err := previewTemplate(key, lang, override)
	if err != nil && in == nil && override != nil {
		msg, err = previewTemplate(key, lang, nil)
	}
	if err != nil {
		return Preview{}, templateError(err)
	}
	return Preview{Subject: msg.Subject, HTML: msg.HTML, Text: msg.Text}, nil
}

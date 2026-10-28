package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// fakeTenantService records the calls and answers err, or canned values.
type fakeTenantService struct {
	err error
	// errAt makes only the named method fail with err.
	errAt string
	calls []string
	args  map[string][]any
	// body is the uploaded image read by UploadAsset.
	body []byte
}

func (f *fakeTenantService) record(name string, args ...any) error {
	f.calls = append(f.calls, name)
	if f.args == nil {
		f.args = map[string][]any{}
	}
	f.args[name] = args
	if f.errAt != "" && f.errAt != name {
		return nil
	}
	return f.err
}

var (
	created = now.Add(-24 * time.Hour)
	viewA   = tenantadmin.TenantView{
		ID: "ten_a", Name: "Entity A", FQDN: "transfer.entity-a.example.com", DefaultLanguage: "fr",
		MaxTransferBytes: 5 << 30, MaxTransferCeiling: 10 << 30, StorageQuotaBytes: 1 << 40, StorageUsedBytes: 1 << 30,
		Status: tenant.StatusActive, WebhookIncludeAddresses: true, CreatedAt: created, UpdatedAt: now,
	}
	brandingA = tenantadmin.Branding{
		PrimaryColor: "#0B5FFF", AccentColor: "#00875A", HasLogo: true,
		Contrast: []branding.ContrastResult{{Pair: "primary-on-light", Ratio: 5.1, Level: "AA"}},
	}
	smtpA = tenantadmin.SMTPView{
		Host: "smtp.example.com", Port: 587, Security: store.SMTPSecuritySTARTTLS, Username: "transfer@entity-a.example.com",
		PasswordSet: true, FromAddress: "transfer@entity-a.example.com",
	}
	templateA = tenantadmin.Template{
		Key: "transfer-notification", Language: "en", Customized: true, Subject: "Files from {{sender_email}}",
		HTML: "<p>{{download_link}}</p>", Text: "{{download_link}}",
		Variables: []mail.Variable{{Name: "sender_email"}, {Name: "download_link", Required: true}}, UpdatedAt: now,
	}
	legalA = tenantadmin.LegalDocument{
		Document: "legal-notice", Language: "fr", Markdown: "# Mentions", UpdatedAt: now, HTML: "<h2>Mentions</h2>",
	}
)

func (f *fakeTenantService) ListTenants(_ context.Context, p adminauth.Principal, cursor string, limit int) (tenantadmin.TenantPage, error) {
	return tenantadmin.TenantPage{Items: []tenantadmin.TenantView{viewA}, NextCursor: "next"}, f.record("ListTenants", p.SessionID, cursor, limit)
}

func (f *fakeTenantService) GetTenant(_ context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.TenantView, error) {
	return viewA, f.record("GetTenant", p.SessionID, tid)
}

func (f *fakeTenantService) CreateTenant(_ context.Context, p adminauth.Principal, in tenantadmin.TenantCreate, ip netip.Addr) (tenantadmin.TenantView, error) {
	v := viewA
	v.MaxTransferBytes, v.MaxTransferCeiling = in.MaxTransferBytes, in.MaxTransferBytes
	return v, f.record("CreateTenant", p.SessionID, in, ip)
}

func (f *fakeTenantService) UpdateTenant(_ context.Context, p adminauth.Principal, tid tenant.ID, in tenantadmin.TenantUpdate, ip netip.Addr) (tenantadmin.TenantView, error) {
	return viewA, f.record("UpdateTenant", p.SessionID, tid, in, ip)
}

func (f *fakeTenantService) DeleteTenant(_ context.Context, p adminauth.Principal, tid tenant.ID, confirm string, ip netip.Addr) error {
	return f.record("DeleteTenant", p.SessionID, tid, confirm, ip)
}

func (f *fakeTenantService) GetBranding(_ context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.Branding, error) {
	return brandingA, f.record("GetBranding", p.SessionID, tid)
}

func (f *fakeTenantService) UpdateBranding(_ context.Context, p adminauth.Principal, tid tenant.ID, primary, accent string, ip netip.Addr) (tenantadmin.Branding, error) {
	return brandingA, f.record("UpdateBranding", p.SessionID, tid, primary, accent, ip)
}

func (f *fakeTenantService) GetAsset(_ context.Context, p adminauth.Principal, tid tenant.ID, asset string) (branding.Image, error) {
	return branding.Image{Data: []byte("png"), ContentType: branding.ContentTypePNG, ETag: `"e1"`},
		f.record("GetAsset", p.SessionID, tid, asset)
}

func (f *fakeTenantService) UploadAsset(_ context.Context, p adminauth.Principal, tid tenant.ID, asset string, r io.Reader, ip netip.Addr) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	f.body = b
	return f.record("UploadAsset", p.SessionID, tid, asset, ip)
}

func (f *fakeTenantService) DeleteAsset(_ context.Context, p adminauth.Principal, tid tenant.ID, asset string, ip netip.Addr) error {
	return f.record("DeleteAsset", p.SessionID, tid, asset, ip)
}

func (f *fakeTenantService) GetNetworkRules(_ context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.NetworkRules, error) {
	return tenantadmin.NetworkRules{}, f.record("GetNetworkRules", p.SessionID, tid)
}

func (f *fakeTenantService) UpdateNetworkRules(_ context.Context, p adminauth.Principal, tid tenant.ID, cidrs, domains []string, ip netip.Addr) (tenantadmin.NetworkRules, error) {
	return tenantadmin.NetworkRules{CIDRs: cidrs, Domains: domains}, f.record("UpdateNetworkRules", p.SessionID, tid, cidrs, domains, ip)
}

func (f *fakeTenantService) GetConfidentialityLevels(_ context.Context, p adminauth.Principal, tid tenant.ID) ([]tenantadmin.ConfidentialityLevel, error) {
	return nil, f.record("GetConfidentialityLevels", p.SessionID, tid)
}

func (f *fakeTenantService) UpdateConfidentialityLevels(_ context.Context, p adminauth.Principal, tid tenant.ID, levels []tenantadmin.ConfidentialityLevel, ip netip.Addr) ([]tenantadmin.ConfidentialityLevel, error) {
	return levels, f.record("UpdateConfidentialityLevels", p.SessionID, tid, levels, ip)
}

func (f *fakeTenantService) GetRecipientRules(_ context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.RecipientRules, error) {
	return tenantadmin.RecipientRules{}, f.record("GetRecipientRules", p.SessionID, tid)
}

func (f *fakeTenantService) UpdateRecipientRules(_ context.Context, p adminauth.Principal, tid tenant.ID, allowed, denied []string, ip netip.Addr) (tenantadmin.RecipientRules, error) {
	return tenantadmin.RecipientRules{Allowed: allowed, Denied: denied}, f.record("UpdateRecipientRules", p.SessionID, tid, allowed, denied, ip)
}

func (f *fakeTenantService) GetSMTP(_ context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.SMTPView, error) {
	return smtpA, f.record("GetSMTP", p.SessionID, tid)
}

func (f *fakeTenantService) UpdateSMTP(_ context.Context, p adminauth.Principal, tid tenant.ID, in tenantadmin.SMTPUpdate, ip netip.Addr) (tenantadmin.SMTPView, error) {
	return tenantadmin.SMTPView{Host: in.Host, Port: in.Port, Security: in.Security, FromAddress: in.FromAddress},
		f.record("UpdateSMTP", p.SessionID, tid, in, ip)
}

func (f *fakeTenantService) TestSMTP(_ context.Context, p adminauth.Principal, tid tenant.ID, to string, ip netip.Addr) (tenantadmin.SMTPTestResult, error) {
	return tenantadmin.SMTPTestResult{Duration: 1500 * time.Millisecond, Stage: tenantadmin.StageConnect, Error: "refused"},
		f.record("TestSMTP", p.SessionID, tid, to, ip)
}

func (f *fakeTenantService) CheckMailDNS(_ context.Context, p adminauth.Principal, tid tenant.ID, selectors []string) (tenantadmin.MailDNSCheck, error) {
	return tenantadmin.MailDNSCheck{
		Domain: "entity-a.example.com",
		SPF:    tenantadmin.DNSRecordCheck{Status: tenantadmin.DNSOK, Record: "v=spf1 -all"},
		DKIM: tenantadmin.DKIMCheck{Status: tenantadmin.DNSOK, Selectors: []tenantadmin.DKIMSelectorCheck{
			{Selector: "selector1", Found: true},
		}},
		DMARC: tenantadmin.DNSRecordCheck{Status: tenantadmin.DNSMissing, Message: "no record"},
	}, f.record("CheckMailDNS", p.SessionID, tid, selectors)
}

func (f *fakeTenantService) ListTemplates(_ context.Context, p adminauth.Principal, tid tenant.ID) ([]tenantadmin.TemplateSummary, error) {
	return []tenantadmin.TemplateSummary{
		{Key: "verification-code", Language: "fr"},
		{Key: "transfer-notification", Language: "fr", Customized: true, UpdatedAt: now},
	}, f.record("ListTemplates", p.SessionID, tid)
}

func (f *fakeTenantService) GetTemplate(_ context.Context, p adminauth.Principal, tid tenant.ID, key, lang string) (tenantadmin.Template, error) {
	return templateA, f.record("GetTemplate", p.SessionID, tid, key, lang)
}

func (f *fakeTenantService) UpdateTemplate(_ context.Context, p adminauth.Principal, tid tenant.ID, key, lang string, in tenantadmin.TemplateInput, ip netip.Addr) (tenantadmin.Template, error) {
	return templateA, f.record("UpdateTemplate", p.SessionID, tid, key, lang, in, ip)
}

func (f *fakeTenantService) ResetTemplate(_ context.Context, p adminauth.Principal, tid tenant.ID, key, lang string, ip netip.Addr) error {
	return f.record("ResetTemplate", p.SessionID, tid, key, lang, ip)
}

func (f *fakeTenantService) PreviewTemplate(_ context.Context, p adminauth.Principal, tid tenant.ID, key, lang string, in *tenantadmin.TemplateInput) (tenantadmin.Preview, error) {
	return tenantadmin.Preview{Subject: "s", HTML: "<p>h</p>", Text: "t"}, f.record("PreviewTemplate", p.SessionID, tid, key, lang, in)
}

func (f *fakeTenantService) GetLegal(_ context.Context, p adminauth.Principal, tid tenant.ID, doc, lang string) (tenantadmin.LegalDocument, error) {
	return legalA, f.record("GetLegal", p.SessionID, tid, doc, lang)
}

func (f *fakeTenantService) UpdateLegal(_ context.Context, p adminauth.Principal, tid tenant.ID, doc, lang, markdown string, ip netip.Addr) (tenantadmin.LegalDocument, error) {
	return tenantadmin.LegalDocument{Document: doc, Language: lang}, f.record("UpdateLegal", p.SessionID, tid, doc, lang, markdown, ip)
}

// patchBody returns a raw tenant merge patch.
func patchBody(s string) *gen.TenantUpdate {
	b := gen.TenantUpdate(s)
	return &b
}

func TestUpdateTenantPatchErrors(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	cases := []struct {
		name, body string
		want       []problem.FieldError
	}{
		{"null name", `{"name": null}`, []problem.FieldError{{Field: "/name", Code: fieldNotNullable}}},
		{"every null, in order", `{"webhookIncludeAddresses":null,"maxTransferCeiling":null,"maxTransferBytes":null,"storageQuotaBytes":null,"defaultLanguage":null,"fqdn":null,"name":null}`, []problem.FieldError{
			{Field: "/name", Code: fieldNotNullable},
			{Field: "/fqdn", Code: fieldNotNullable},
			{Field: "/defaultLanguage", Code: fieldNotNullable},
			{Field: "/storageQuotaBytes", Code: fieldNotNullable},
			{Field: "/maxTransferBytes", Code: fieldNotNullable},
			{Field: "/maxTransferCeiling", Code: fieldNotNullable},
			{Field: "/webhookIncludeAddresses", Code: fieldNotNullable},
		}},
		{"null among valid fields", `{"defaultLanguage": "en", "maxTransferBytes": null}`, []problem.FieldError{{Field: "/maxTransferBytes", Code: fieldNotNullable}}},
		{"null body", `null`, []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{"array body", `[]`, []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{"string body", `"x"`, []problem.FieldError{{Field: "", Code: fieldInvalidFormat}}},
		{"wrong type", `{"storageQuotaBytes": "big"}`, []problem.FieldError{{Field: "/storageQuotaBytes", Code: fieldInvalidFormat}}},
		{"object instead of string", `{"name": {"first": "A"}}`, []problem.FieldError{{Field: "/name", Code: fieldInvalidFormat}}},
		{"string instead of boolean", `{"webhookIncludeAddresses": "yes"}`, []problem.FieldError{{Field: "/webhookIncludeAddresses", Code: fieldInvalidFormat}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.UpdateTenant(ctx, gen.UpdateTenantRequestObject{TenantId: "ten_a", Body: patchBody(tc.body)})
			p := expectProblem(t, err, problem.CodeValidationFailed)
			if !reflect.DeepEqual(p.Errors, tc.want) {
				t.Errorf("errors %+v, want %+v", p.Errors, tc.want)
			}
		})
	}
	if len(svc.calls) != 0 {
		t.Errorf("the service was called (%v): nothing may change", svc.calls)
	}
}

// tenantOps calls every tenant operation of s with a minimal valid request
// and returns the errors, by operation name.
func tenantOps(ctx context.Context, s *Server) map[string]error {
	out := map[string]error{}
	call := func(name string, err error) { out[name] = err }
	_, err := s.ListTenants(ctx, gen.ListTenantsRequestObject{})
	call("ListTenants", err)
	_, err = s.CreateTenant(ctx, gen.CreateTenantRequestObject{Body: &gen.TenantCreate{Name: "B"}})
	call("CreateTenant", err)
	_, err = s.GetTenant(ctx, gen.GetTenantRequestObject{TenantId: "ten_a"})
	call("GetTenant", err)
	_, err = s.UpdateTenant(ctx, gen.UpdateTenantRequestObject{TenantId: "ten_a", Body: patchBody(`{}`)})
	call("UpdateTenant", err)
	_, err = s.DeleteTenant(ctx, gen.DeleteTenantRequestObject{TenantId: "ten_a"})
	call("DeleteTenant", err)
	_, err = s.GetBranding(ctx, gen.GetBrandingRequestObject{TenantId: "ten_a"})
	call("GetBranding", err)
	_, err = s.UpdateBranding(ctx, gen.UpdateBrandingRequestObject{TenantId: "ten_a", Body: &gen.BrandingUpdate{}})
	call("UpdateBranding", err)
	_, err = s.GetBrandingAsset(ctx, gen.GetBrandingAssetRequestObject{TenantId: "ten_a", Asset: "logo"})
	call("GetAsset", err)
	_, err = s.UploadBrandingAsset(ctx, gen.UploadBrandingAssetRequestObject{
		TenantId: "ten_a", Asset: "logo", ContentType: "image/png", Body: strings.NewReader("png"),
	})
	call("UploadAsset", err)
	_, err = s.DeleteBrandingAsset(ctx, gen.DeleteBrandingAssetRequestObject{TenantId: "ten_a", Asset: "logo"})
	call("DeleteAsset", err)
	_, err = s.GetNetworkRules(ctx, gen.GetNetworkRulesRequestObject{TenantId: "ten_a"})
	call("GetNetworkRules", err)
	_, err = s.UpdateNetworkRules(ctx, gen.UpdateNetworkRulesRequestObject{TenantId: "ten_a", Body: &gen.NetworkRules{}})
	call("UpdateNetworkRules", err)
	_, err = s.GetConfidentialityLevels(ctx, gen.GetConfidentialityLevelsRequestObject{TenantId: "ten_a"})
	call("GetConfidentialityLevels", err)
	_, err = s.UpdateConfidentialityLevels(ctx, gen.UpdateConfidentialityLevelsRequestObject{TenantId: "ten_a", Body: &gen.ConfidentialityLevelList{}})
	call("UpdateConfidentialityLevels", err)
	_, err = s.GetRecipientRules(ctx, gen.GetRecipientRulesRequestObject{TenantId: "ten_a"})
	call("GetRecipientRules", err)
	_, err = s.UpdateRecipientRules(ctx, gen.UpdateRecipientRulesRequestObject{TenantId: "ten_a", Body: &gen.RecipientRules{}})
	call("UpdateRecipientRules", err)
	_, err = s.GetSmtpSettings(ctx, gen.GetSmtpSettingsRequestObject{TenantId: "ten_a"})
	call("GetSMTP", err)
	_, err = s.UpdateSmtpSettings(ctx, gen.UpdateSmtpSettingsRequestObject{TenantId: "ten_a", Body: &gen.SmtpSettingsUpdate{}})
	call("UpdateSMTP", err)
	_, err = s.TestSmtp(ctx, gen.TestSmtpRequestObject{TenantId: "ten_a", Body: &gen.SmtpTest{}})
	call("TestSMTP", err)
	_, err = s.CheckMailDns(ctx, gen.CheckMailDnsRequestObject{TenantId: "ten_a"})
	call("CheckMailDNS", err)
	_, err = s.ListEmailTemplates(ctx, gen.ListEmailTemplatesRequestObject{TenantId: "ten_a"})
	call("ListTemplates", err)
	_, err = s.GetEmailTemplate(ctx, gen.GetEmailTemplateRequestObject{TenantId: "ten_a"})
	call("GetTemplate", err)
	_, err = s.UpdateEmailTemplate(ctx, gen.UpdateEmailTemplateRequestObject{TenantId: "ten_a", Body: &gen.EmailTemplateUpdate{}})
	call("UpdateTemplate", err)
	_, err = s.ResetEmailTemplate(ctx, gen.ResetEmailTemplateRequestObject{TenantId: "ten_a"})
	call("ResetTemplate", err)
	_, err = s.PreviewEmailTemplate(ctx, gen.PreviewEmailTemplateRequestObject{TenantId: "ten_a"})
	call("PreviewTemplate", err)
	_, err = s.GetLegalDocumentAdmin(ctx, gen.GetLegalDocumentAdminRequestObject{TenantId: "ten_a"})
	call("GetLegal", err)
	_, err = s.UpdateLegalDocument(ctx, gen.UpdateLegalDocumentRequestObject{TenantId: "ten_a", Body: &gen.LegalDocumentUpdate{}})
	call("UpdateLegal", err)
	return out
}

// tenantServer returns a server over svc with a fixed clock.
func tenantServer(svc TenantService) *Server {
	s := NewServer(WithTenantService(svc))
	s.now = func() time.Time { return now }
	return s
}

func TestTenantOperationsWiring(t *testing.T) {
	t.Parallel()
	// Without service: 500 (wiring error), whatever the session.
	for name, err := range tenantOps(ctxWith(store.SessionAuthenticated, superRoot), NewServer()) {
		if !errors.Is(err, errNoTenantService) {
			t.Errorf("%s without service: %v", name, err)
		}
	}
	// Without session in the context: 401 before the service.
	svc := &fakeTenantService{}
	for name, err := range tenantOps(ctxWith("", superRoot), tenantServer(svc)) {
		expectProblem(t, err, problem.CodeUnauthenticated)
		_ = name
	}
	if len(svc.calls) != 0 {
		t.Errorf("service called without session: %v", svc.calls)
	}
	// Every operation reaches the service with the session; a service
	// error is mapped.
	svc = &fakeTenantService{err: tenantadmin.ErrNotFound}
	ops := tenantOps(ctxWith(store.SessionAuthenticated, delegated), tenantServer(svc))
	if len(ops) != 27 {
		t.Fatalf("%d operations, want 27", len(ops))
	}
	for name, err := range ops {
		expectProblem(t, err, problem.CodeNotFound)
		if args := svc.args[name]; len(args) == 0 || args[0] != "as_01" {
			t.Errorf("%s: service args %v", name, args)
		}
	}
}

func TestTenantErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	tests := []struct {
		err  error
		code problem.Code
	}{
		{&tenantadmin.InvalidError{Field: tenantadmin.FieldFQDN}, problem.CodeValidationFailed},
		{tenantadmin.ErrInvalid, problem.CodeValidationFailed},
		{&tenantadmin.RateLimitError{RetryAfter: 90 * time.Second}, problem.CodeRateLimited},
		{tenantadmin.ErrRateLimited, problem.CodeRateLimited},
		{tenantadmin.ErrUnauthenticated, problem.CodeUnauthenticated},
		{tenantadmin.ErrForbidden, problem.CodeForbidden},
		{tenantadmin.ErrNotFound, problem.CodeNotFound},
		{tenantadmin.ErrAlreadyExists, problem.CodeAlreadyExists},
		{fmt.Errorf("x: %w", tenantadmin.ErrPayloadTooLarge), problem.CodePayloadTooLarge},
		{fmt.Errorf("read: %w", &http.MaxBytesError{Limit: 5}), problem.CodePayloadTooLarge},
		{fmt.Errorf("x: %w", tenantadmin.ErrUnsupportedMediaType), problem.CodeUnsupportedMediaType},
	}
	for _, tt := range tests {
		expectProblem(t, tenantError(tt.err), tt.code)
	}
	if err := tenantError(boom); !errors.Is(err, boom) {
		t.Errorf("internal error: %v", err)
	}
	p := expectProblem(t, tenantError(&tenantadmin.RateLimitError{RetryAfter: 90 * time.Second}), problem.CodeRateLimited)
	if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 90 {
		t.Errorf("retry after %v", p.RetryAfterSeconds)
	}
	p = expectProblem(t, tenantError(&tenantadmin.InvalidError{Field: tenantadmin.FieldFQDN, Reason: "admin host"}), problem.CodeValidationFailed)
	if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: "/fqdn", Code: fieldInvalidFormat}}) {
		t.Errorf("field errors %+v", p.Errors)
	}
	reserved := &tenantadmin.InvalidError{Field: tenantadmin.FieldFQDN, Reason: "admin host", Code: tenantadmin.CodeAdminHost}
	p = expectProblem(t, tenantError(reserved), problem.CodeValidationFailed)
	if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: "/fqdn", Code: "reserved-host"}}) {
		t.Errorf("reserved host: field errors %+v", p.Errors)
	}
	for _, field := range []string{tenantadmin.FieldFromAddress, tenantadmin.FieldTo} {
		p = expectProblem(t, tenantError(&tenantadmin.InvalidError{Field: field, Reason: "must be a mail address"}), problem.CodeValidationFailed)
		if !reflect.DeepEqual(p.Errors, []problem.FieldError{{Field: field, Code: fieldInvalidEmail}}) {
			t.Errorf("%s: field errors %+v", field, p.Errors)
		}
	}
	p = expectProblem(t, tenantError(&tenantadmin.InvalidError{Reason: "invalid smtp settings"}), problem.CodeValidationFailed)
	if len(p.Errors) != 0 {
		t.Errorf("request-wide error has field errors %+v", p.Errors)
	}
	p = expectProblem(t, tenantError(&tenantadmin.InvalidError{Field: tenantadmin.FieldTemplate, Issues: []mail.Issue{
		{Part: mail.PartSubject, Message: "required variable {{code}} is missing"},
		{Part: mail.PartHTML, Line: 3, Column: 7, Message: "unknown variable {{x}}"},
		{Part: mail.PartText, Line: 1, Column: 1, Message: "template syntax is not allowed"},
		{Part: "other", Message: "odd"},
	}}), problem.CodeValidationFailed)
	want := []problem.FieldError{
		{Field: "/subject", Code: fieldInvalidTemplate, Message: "required variable {{code}} is missing"},
		{Field: "/bodyHtml", Code: fieldInvalidTemplate, Line: 3, Column: 7, Message: "unknown variable {{x}}"},
		{Field: "/bodyText", Code: fieldInvalidTemplate, Line: 1, Column: 1, Message: "template syntax is not allowed"},
		{Field: tenantadmin.FieldTemplate, Code: fieldInvalidTemplate, Message: "odd"},
	}
	if !reflect.DeepEqual(p.Errors, want) {
		t.Errorf("template errors %+v", p.Errors)
	}
}

func TestTenantMissingBodies(t *testing.T) {
	t.Parallel()
	s := tenantServer(&fakeTenantService{})
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	var errs []error
	_, err := s.CreateTenant(ctx, gen.CreateTenantRequestObject{})
	errs = append(errs, err)
	_, err = s.UpdateTenant(ctx, gen.UpdateTenantRequestObject{})
	errs = append(errs, err)
	_, err = s.UpdateBranding(ctx, gen.UpdateBrandingRequestObject{})
	errs = append(errs, err)
	_, err = s.UpdateNetworkRules(ctx, gen.UpdateNetworkRulesRequestObject{})
	errs = append(errs, err)
	_, err = s.UpdateConfidentialityLevels(ctx, gen.UpdateConfidentialityLevelsRequestObject{})
	errs = append(errs, err)
	_, err = s.UpdateRecipientRules(ctx, gen.UpdateRecipientRulesRequestObject{})
	errs = append(errs, err)
	_, err = s.UpdateSmtpSettings(ctx, gen.UpdateSmtpSettingsRequestObject{})
	errs = append(errs, err)
	_, err = s.TestSmtp(ctx, gen.TestSmtpRequestObject{})
	errs = append(errs, err)
	_, err = s.UpdateEmailTemplate(ctx, gen.UpdateEmailTemplateRequestObject{})
	errs = append(errs, err)
	_, err = s.UpdateLegalDocument(ctx, gen.UpdateLegalDocumentRequestObject{})
	errs = append(errs, err)
	for i, err := range errs {
		p := expectProblem(t, err, problem.CodeValidationFailed)
		if len(p.Errors) != 1 || p.Errors[0].Code != fieldRequired {
			t.Errorf("missing body %d: %+v", i, p.Errors)
		}
	}
}

func TestTenantsHandlers(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	wantTenant := gen.Tenant{
		Id: "ten_a", Name: "Entity A", Fqdn: "transfer.entity-a.example.com", DefaultLanguage: "fr",
		MaxTransferBytes: 5 << 30, MaxTransferCeiling: 10 << 30, Status: gen.Active, StorageQuotaBytes: 1 << 40,
		StorageUsedBytes: 1 << 30, WebhookIncludeAddresses: new(true), CreatedAt: created, UpdatedAt: now,
	}

	cursor, limit := "c1", 10
	resp, err := s.ListTenants(ctx, gen.ListTenantsRequestObject{Params: gen.ListTenantsParams{Cursor: &cursor, Limit: &limit}})
	if err != nil {
		t.Fatal(err)
	}
	list := resp.(gen.ListTenants200JSONResponse)
	if len(list.Items) != 1 || !reflect.DeepEqual(list.Items[0], wantTenant) || *list.NextCursor != "next" {
		t.Errorf("list %+v", list)
	}
	if !reflect.DeepEqual(svc.args["ListTenants"], []any{"as_01", "c1", 10}) {
		t.Errorf("list args %v", svc.args["ListTenants"])
	}

	got, err := s.GetTenant(ctx, gen.GetTenantRequestObject{TenantId: "ten_a"})
	if err != nil || !reflect.DeepEqual(gen.Tenant(got.(gen.GetTenant200JSONResponse)), wantTenant) {
		t.Errorf("get %+v %v", got, err)
	}

	upd, err := s.UpdateTenant(ctx, gen.UpdateTenantRequestObject{TenantId: "ten_a", Body: patchBody(
		`{"name": "Entity A2", "defaultLanguage": "en", "maxTransferBytes": 1073741824, "webhookIncludeAddresses": false, "unknown": null}`,
	)})
	if err != nil || upd.(gen.UpdateTenant200JSONResponse).Id != "ten_a" {
		t.Fatalf("update %+v %v", upd, err)
	}
	in := svc.args["UpdateTenant"][2].(tenantadmin.TenantUpdate)
	if *in.Name != "Entity A2" || *in.DefaultLanguage != "en" || *in.MaxTransferBytes != 1<<30 || in.FQDN != nil ||
		in.MaxTransferCeiling != nil || in.StorageQuotaBytes != nil || in.WebhookIncludeAddresses == nil ||
		*in.WebhookIncludeAddresses || svc.args["UpdateTenant"][3] != clientIP {
		t.Errorf("update input %+v", svc.args["UpdateTenant"])
	}
	// No language: left unchanged.
	if _, err := s.UpdateTenant(ctx, gen.UpdateTenantRequestObject{TenantId: "ten_a", Body: patchBody(` { } `)}); err != nil {
		t.Fatal(err)
	}
	if in := svc.args["UpdateTenant"][2].(tenantadmin.TenantUpdate); in.DefaultLanguage != nil || in.WebhookIncludeAddresses != nil {
		t.Errorf("language set: %+v", in)
	}

	del, err := s.DeleteTenant(ctx, gen.DeleteTenantRequestObject{TenantId: "ten_a", Params: gen.DeleteTenantParams{Confirm: "Entity A"}})
	if err != nil || visit(t, del).Code != http.StatusNoContent {
		t.Fatalf("delete %v", err)
	}
	if !reflect.DeepEqual(svc.args["DeleteTenant"], []any{"as_01", tenant.ID("ten_a"), "Entity A", clientIP}) {
		t.Errorf("delete args %v", svc.args["DeleteTenant"])
	}
}

func TestCreateTenant(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	body := func(limit, ceiling *int64) *gen.TenantCreate {
		return &gen.TenantCreate{
			Name: "Entity B", Fqdn: "transfer.entity-b.example.com", DefaultLanguage: "en", StorageQuotaBytes: 1 << 40,
			MaxTransferBytes: limit, MaxTransferCeiling: ceiling,
		}
	}
	gib := func(n int64) *int64 { v := n << 30; return &v }
	tests := []struct {
		name           string
		limit, ceiling *int64
	}{
		{"defaults", nil, nil},
		{"limit only", gib(5), nil},
		{"ceiling only", nil, gib(10)},
		{"limit under the ceiling", gib(5), gib(10)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := &fakeTenantService{}
			resp, err := tenantServer(svc).CreateTenant(ctx, gen.CreateTenantRequestObject{Body: body(tt.limit, tt.ceiling)})
			if err != nil {
				t.Fatal(err)
			}
			if visit(t, resp).Code != http.StatusCreated {
				t.Error("status")
			}
			in := svc.args["CreateTenant"][1].(tenantadmin.TenantCreate)
			if in.Name != "Entity B" || in.FQDN != "transfer.entity-b.example.com" || in.DefaultLanguage != "en" ||
				in.StorageQuotaBytes != 1<<40 || in.MaxTransferBytes != deref(tt.limit) ||
				in.MaxTransferCeiling != tt.ceiling {
				t.Errorf("create input %+v", in)
			}
			if len(svc.calls) != 1 {
				t.Errorf("calls %v", svc.calls)
			}
		})
	}

	// The creation failing is reported, a limit above the ceiling included.
	svc := &fakeTenantService{err: tenantadmin.ErrAlreadyExists}
	_, err := tenantServer(svc).CreateTenant(ctx, gen.CreateTenantRequestObject{Body: body(nil, nil)})
	expectProblem(t, err, problem.CodeAlreadyExists)
	svc = &fakeTenantService{err: &tenantadmin.InvalidError{Field: tenantadmin.FieldMaxTransferBytes, Reason: "must not exceed the ceiling"}}
	_, err = tenantServer(svc).CreateTenant(ctx, gen.CreateTenantRequestObject{Body: body(gib(10), gib(5))})
	p := expectProblem(t, err, problem.CodeValidationFailed)
	if len(p.Errors) != 1 || p.Errors[0].Field != "/maxTransferBytes" {
		t.Errorf("limit above ceiling: %+v", p.Errors)
	}
}

func TestBrandingHandlers(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	want := gen.Branding{
		PrimaryColor: "#0B5FFF", AccentColor: "#00875A", HasLogo: true,
		Contrast: []gen.ContrastResult{{Pair: "primary-on-light", Ratio: 5.1, Level: "AA"}},
	}
	got, err := s.GetBranding(ctx, gen.GetBrandingRequestObject{TenantId: "ten_a"})
	if err != nil || !reflect.DeepEqual(gen.Branding(got.(gen.GetBranding200JSONResponse)), want) {
		t.Errorf("get %+v %v", got, err)
	}
	upd, err := s.UpdateBranding(ctx, gen.UpdateBrandingRequestObject{TenantId: "ten_a", Body: &gen.BrandingUpdate{
		PrimaryColor: "#112233", AccentColor: "#445566",
	}})
	if err != nil || !reflect.DeepEqual(gen.Branding(upd.(gen.UpdateBranding200JSONResponse)), want) {
		t.Errorf("update %+v %v", upd, err)
	}
	if !reflect.DeepEqual(svc.args["UpdateBranding"], []any{"as_01", tenant.ID("ten_a"), "#112233", "#445566", clientIP}) {
		t.Errorf("update args %v", svc.args["UpdateBranding"])
	}

	asset, err := s.GetBrandingAsset(ctx, gen.GetBrandingAssetRequestObject{TenantId: "ten_a", Asset: "logo"})
	if err != nil {
		t.Fatal(err)
	}
	rec := visit(t, asset)
	if h := rec.Header(); rec.Code != http.StatusOK || rec.Body.String() != "png" || h.Get("Content-Type") != "image/png" ||
		h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("ETag") != `"e1"` ||
		h.Get("Content-Length") != "3" {
		t.Errorf("get asset %d %q %v", rec.Code, rec.Body.String(), h)
	}
	if !reflect.DeepEqual(svc.args["GetAsset"], []any{"as_01", tenant.ID("ten_a"), "logo"}) {
		t.Errorf("get asset args %v", svc.args["GetAsset"])
	}

	for _, ct := range []string{"image/png", "IMAGE/JPEG; charset=binary", "image/svg+xml"} {
		resp, err := s.UploadBrandingAsset(ctx, gen.UploadBrandingAssetRequestObject{
			TenantId: "ten_a", Asset: "background", ContentType: ct, Body: strings.NewReader("bytes"),
		})
		if err != nil || visit(t, resp).Code != http.StatusNoContent || string(svc.body) != "bytes" {
			t.Errorf("upload %s: %v", ct, err)
		}
	}
	if !reflect.DeepEqual(svc.args["UploadAsset"], []any{"as_01", tenant.ID("ten_a"), "background", clientIP}) {
		t.Errorf("upload args %v", svc.args["UploadAsset"])
	}
	// A nil body is an empty image (refused by the service).
	if _, err := s.UploadBrandingAsset(ctx, gen.UploadBrandingAssetRequestObject{
		TenantId: "ten_a", Asset: "logo", ContentType: "image/png",
	}); err != nil || len(svc.body) != 0 {
		t.Errorf("nil body: %v %q", err, svc.body)
	}
	for _, ct := range []string{"", "application/octet-stream", "text/plain", ";;"} {
		svc.calls = nil
		_, err := s.UploadBrandingAsset(ctx, gen.UploadBrandingAssetRequestObject{
			TenantId: "ten_a", Asset: "logo", ContentType: ct, Body: strings.NewReader("x"),
		})
		expectProblem(t, err, problem.CodeUnsupportedMediaType)
		if len(svc.calls) != 0 {
			t.Errorf("content type %q reached the service", ct)
		}
	}
	del, err := s.DeleteBrandingAsset(ctx, gen.DeleteBrandingAssetRequestObject{TenantId: "ten_a", Asset: "logo"})
	if err != nil || visit(t, del).Code != http.StatusNoContent {
		t.Errorf("delete %v", err)
	}
	if !reflect.DeepEqual(svc.args["DeleteAsset"], []any{"as_01", tenant.ID("ten_a"), "logo", clientIP}) {
		t.Errorf("delete args %v", svc.args["DeleteAsset"])
	}
}

func TestNetworkHandlers(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	got, err := s.GetNetworkRules(ctx, gen.GetNetworkRulesRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	// Empty lists, never null.
	if r := got.(gen.GetNetworkRules200JSONResponse); r.InternalCidrs == nil || r.InternalDomains == nil {
		t.Errorf("get %+v", r)
	}
	upd, err := s.UpdateNetworkRules(ctx, gen.UpdateNetworkRulesRequestObject{TenantId: "ten_a", Body: &gen.NetworkRules{
		InternalCidrs: []string{"10.0.0.0/8"}, InternalDomains: []string{"entity-a.example.com"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := upd.(gen.UpdateNetworkRules200JSONResponse)
	if !reflect.DeepEqual(r.InternalCidrs, []string{"10.0.0.0/8"}) || !reflect.DeepEqual(r.InternalDomains, []string{"entity-a.example.com"}) {
		t.Errorf("update %+v", r)
	}
	if svc.args["UpdateNetworkRules"][4] != clientIP {
		t.Errorf("update args %v", svc.args["UpdateNetworkRules"])
	}
}

func TestConfidentialityHandlers(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	got, err := s.GetConfidentialityLevels(ctx, gen.GetConfidentialityLevelsRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	if l := got.(gen.GetConfidentialityLevels200JSONResponse); l.Items == nil || len(l.Items) != 0 {
		t.Errorf("get %+v", l)
	}
	cap5 := 5
	upd, err := s.UpdateConfidentialityLevels(ctx, gen.UpdateConfidentialityLevelsRequestObject{TenantId: "ten_a", Body: &gen.ConfidentialityLevelList{
		Items: []gen.ConfidentialityLevel{{
			Key: "secret", Labels: map[string]string{"en": "Secret", "fr": "Secret"}, IsDefault: true,
			Rules: gen.ConfidentialityRules{
				AllowedExpiryDays: []gen.ExpiryDays{1, 7}, MaxDownloads: &cap5, RequirePassword: true,
				RequireRecipientVerification: true, InternalRecipientsOnly: true, ForceDeleteAfterFirstDownload: true,
			},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	in := svc.args["UpdateConfidentialityLevels"][2].([]tenantadmin.ConfidentialityLevel)
	want := tenantadmin.ConfidentialityLevel{
		Key: "secret", Labels: map[string]string{"en": "Secret", "fr": "Secret"}, IsDefault: true,
		Rules: tenantadmin.ConfidentialityRules{
			AllowedExpiryDays: []int{1, 7}, MaxDownloads: &cap5, RequirePassword: true,
			RequireRecipientVerification: true, InternalRecipientsOnly: true, ForceDeleteAfterFirstDownload: true,
		},
	}
	if len(in) != 1 || !reflect.DeepEqual(in[0], want) || svc.args["UpdateConfidentialityLevels"][3] != clientIP {
		t.Errorf("service args %+v", svc.args["UpdateConfidentialityLevels"])
	}
	out := upd.(gen.UpdateConfidentialityLevels200JSONResponse).Items
	if len(out) != 1 || out[0].Descriptions == nil || !reflect.DeepEqual(out[0].Rules.AllowedExpiryDays, []gen.ExpiryDays{1, 7}) ||
		*out[0].Rules.MaxDownloads != 5 || !out[0].Rules.RequirePassword || !out[0].Rules.ForceDeleteAfterFirstDownload {
		t.Errorf("update %+v", out)
	}
	desc := map[string]string{"en": "d"}
	body := levelListBody([]tenantadmin.ConfidentialityLevel{{Key: "k", Descriptions: desc}})
	if !reflect.DeepEqual(*body.Items[0].Descriptions, desc) {
		t.Errorf("descriptions %+v", body.Items[0].Descriptions)
	}
}

func TestRecipientRulesHandlers(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	got, err := s.GetRecipientRules(ctx, gen.GetRecipientRulesRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	// Empty lists, never null.
	if r := got.(gen.GetRecipientRules200JSONResponse); r.AllowedDomains == nil || r.DeniedDomains == nil {
		t.Errorf("get %+v", r)
	}
	upd, err := s.UpdateRecipientRules(ctx, gen.UpdateRecipientRulesRequestObject{TenantId: "ten_a", Body: &gen.RecipientRules{
		AllowedDomains: []string{"partner.example.com"}, DeniedDomains: []string{"mail.example.com"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := upd.(gen.UpdateRecipientRules200JSONResponse)
	if !reflect.DeepEqual(r.AllowedDomains, []string{"partner.example.com"}) || !reflect.DeepEqual(r.DeniedDomains, []string{"mail.example.com"}) {
		t.Errorf("update %+v", r)
	}
	if svc.args["UpdateRecipientRules"][4] != clientIP {
		t.Errorf("update args %v", svc.args["UpdateRecipientRules"])
	}
}

func TestSMTPHandlers(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	got, err := s.GetSmtpSettings(ctx, gen.GetSmtpSettingsRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	b := got.(gen.GetSmtpSettings200JSONResponse)
	if b.Host != "smtp.example.com" || b.Port != 587 || b.Security != "starttls" || *b.Username != "transfer@entity-a.example.com" ||
		!b.PasswordSet || string(b.FromAddress) != "transfer@entity-a.example.com" || b.FromName != nil {
		t.Errorf("get %+v", b)
	}

	user, pw, name, remove := "u@example.com", "secret-pw", "Entity A", true
	upd, err := s.UpdateSmtpSettings(ctx, gen.UpdateSmtpSettingsRequestObject{TenantId: "ten_a", Body: &gen.SmtpSettingsUpdate{
		Host: "smtp-relay", Port: 25, Security: "none", Username: &user, Password: &pw, RemovePassword: &remove,
		FromAddress: "no-reply@entity-a.example.com", FromName: &name,
	}})
	if err != nil {
		t.Fatal(err)
	}
	in := svc.args["UpdateSMTP"][2].(tenantadmin.SMTPUpdate)
	if in.Host != "smtp-relay" || in.Port != 25 || in.Security != store.SMTPSecurityNone || in.Username != user ||
		*in.Password != pw || !in.RemovePassword || in.FromAddress != "no-reply@entity-a.example.com" || in.FromName != name {
		t.Errorf("update input %+v", in)
	}
	if u := upd.(gen.UpdateSmtpSettings200JSONResponse); u.Host != "smtp-relay" || u.Username != nil {
		t.Errorf("update answer %+v", u)
	}

	res, err := s.TestSmtp(ctx, gen.TestSmtpRequestObject{TenantId: "ten_a", Body: &gen.SmtpTest{To: "admin@entity-a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	r := res.(gen.TestSmtp200JSONResponse)
	if r.Success || r.DurationMs != 1500 || r.Stage != "connect" || *r.Error != "refused" {
		t.Errorf("test %+v", r)
	}
	if !reflect.DeepEqual(svc.args["TestSMTP"], []any{"as_01", tenant.ID("ten_a"), "admin@entity-a.example.com", clientIP}) {
		t.Errorf("test args %v", svc.args["TestSMTP"])
	}

	sel := []string{"selector1"}
	dns, err := s.CheckMailDns(ctx, gen.CheckMailDnsRequestObject{TenantId: "ten_a", Params: gen.CheckMailDnsParams{DkimSelector: &sel}})
	if err != nil {
		t.Fatal(err)
	}
	d := dns.(gen.CheckMailDns200JSONResponse)
	if d.Domain != "entity-a.example.com" || d.Spf.Status != "ok" || *d.Spf.Record != "v=spf1 -all" || d.Spf.Message != nil ||
		d.Dmarc.Status != "missing" || *d.Dmarc.Message != "no record" || d.Dkim.Status != "ok" ||
		len(d.Dkim.Selectors) != 1 || d.Dkim.Selectors[0].Selector != "selector1" || !d.Dkim.Selectors[0].Found {
		t.Errorf("dns %+v", d)
	}
	if !reflect.DeepEqual(svc.args["CheckMailDNS"][2], sel) {
		t.Errorf("dns args %v", svc.args["CheckMailDNS"])
	}
}

func TestTemplateHandlers(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	list, err := s.ListEmailTemplates(ctx, gen.ListEmailTemplatesRequestObject{TenantId: "ten_a"})
	if err != nil {
		t.Fatal(err)
	}
	l := list.(gen.ListEmailTemplates200JSONResponse)
	//nolint:misspell // field name of the generated OpenAPI type (spec spelling)
	if len(l) != 2 || l[0].Customised || l[0].UpdatedAt != nil || !l[1].Customised || !l[1].UpdatedAt.Equal(now) || l[1].Key != "transfer-notification" {
		t.Errorf("list %+v", l)
	}
	want := gen.EmailTemplate{
		Key: "transfer-notification", Language: "en", Subject: "Files from {{sender_email}}",
		BodyHtml: "<p>{{download_link}}</p>", BodyText: "{{download_link}}", Variables: []string{"sender_email", "download_link"},
		RequiredVariables: []string{"download_link"}, UpdatedAt: &now,
	}
	want.Customised = true //nolint:misspell // field name of the generated OpenAPI type (spec spelling)
	got, err := s.GetEmailTemplate(ctx, gen.GetEmailTemplateRequestObject{TenantId: "ten_a", TemplateKey: "transfer-notification", Language: "en"})
	if err != nil || !reflect.DeepEqual(gen.EmailTemplate(got.(gen.GetEmailTemplate200JSONResponse)), want) {
		t.Errorf("get %+v %v", got, err)
	}
	if !reflect.DeepEqual(svc.args["GetTemplate"], []any{"as_01", tenant.ID("ten_a"), "transfer-notification", "en"}) {
		t.Errorf("get args %v", svc.args["GetTemplate"])
	}
	body := &gen.EmailTemplateUpdate{Subject: "S", BodyHtml: "<p>H</p>", BodyText: "T"}
	upd, err := s.UpdateEmailTemplate(ctx, gen.UpdateEmailTemplateRequestObject{
		TenantId: "ten_a", TemplateKey: "transfer-notification", Language: "en", Body: body,
	})
	if err != nil || !reflect.DeepEqual(gen.EmailTemplate(upd.(gen.UpdateEmailTemplate200JSONResponse)), want) {
		t.Errorf("update %+v %v", upd, err)
	}
	if in := svc.args["UpdateTemplate"][4]; !reflect.DeepEqual(in, tenantadmin.TemplateInput{Subject: "S", HTML: "<p>H</p>", Text: "T"}) {
		t.Errorf("update input %+v", in)
	}
	reset, err := s.ResetEmailTemplate(ctx, gen.ResetEmailTemplateRequestObject{TenantId: "ten_a", TemplateKey: "transfer-notification", Language: "en"})
	if err != nil || visit(t, reset).Code != http.StatusNoContent {
		t.Errorf("reset %v", err)
	}
	pv, err := s.PreviewEmailTemplate(ctx, gen.PreviewEmailTemplateRequestObject{
		TenantId: "ten_a", TemplateKey: "transfer-notification", Language: "en", Body: body,
	})
	if err != nil || !reflect.DeepEqual(gen.EmailPreview(pv.(gen.PreviewEmailTemplate200JSONResponse)), gen.EmailPreview{
		Subject: "s", BodyHtml: "<p>h</p>", BodyText: "t",
	}) {
		t.Errorf("preview %+v %v", pv, err)
	}
	if in := svc.args["PreviewTemplate"][4].(*tenantadmin.TemplateInput); in == nil || in.Subject != "S" {
		t.Errorf("preview input %+v", in)
	}
	if _, err := s.PreviewEmailTemplate(ctx, gen.PreviewEmailTemplateRequestObject{TenantId: "ten_a"}); err != nil {
		t.Fatal(err)
	}
	if in := svc.args["PreviewTemplate"][4].(*tenantadmin.TemplateInput); in != nil {
		t.Errorf("preview without body: %+v", in)
	}
}

func TestLegalHandlers(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantService{}
	s := tenantServer(svc)
	ctx := ctxWith(store.SessionAuthenticated, delegated)
	got, err := s.GetLegalDocumentAdmin(ctx, gen.GetLegalDocumentAdminRequestObject{TenantId: "ten_a", Document: "legal-notice", Language: "fr"})
	if err != nil {
		t.Fatal(err)
	}
	if b := got.(gen.GetLegalDocumentAdmin200JSONResponse); b.Document != "legal-notice" || b.Language != "fr" ||
		b.Markdown != "# Mentions" || !b.UpdatedAt.Equal(now) || b.Html == nil || *b.Html != "<h2>Mentions</h2>" {
		t.Errorf("get %+v", b)
	}
	upd, err := s.UpdateLegalDocument(ctx, gen.UpdateLegalDocumentRequestObject{
		TenantId: "ten_a", Document: "privacy-policy", Language: "en", Body: &gen.LegalDocumentUpdate{Markdown: "  "},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A removed document: empty source, no time.
	if b := upd.(gen.UpdateLegalDocument200JSONResponse); b.Markdown != "" || b.UpdatedAt != nil || b.Document != "privacy-policy" ||
		b.Html == nil || *b.Html != "" {
		t.Errorf("update %+v", b)
	}
	if !reflect.DeepEqual(svc.args["UpdateLegal"], []any{"as_01", tenant.ID("ten_a"), "privacy-policy", "en", "  ", clientIP}) {
		t.Errorf("update args %v", svc.args["UpdateLegal"])
	}
}

func TestOptionalHelpers(t *testing.T) {
	t.Parallel()
	if optional("") != nil || *optional("x") != "x" || optionalTime(time.Time{}) != nil || !optionalTime(now).Equal(now) {
		t.Error("optional helpers")
	}
}

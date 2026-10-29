package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/apiutil"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// TenantService configures the tenants (*tenantadmin.Service). Every
// method checks the principal itself: a tenant the administrator is not
// attached to answers tenantadmin.ErrNotFound, like an unknown one.
type TenantService interface {
	ListTenants(ctx context.Context, p adminauth.Principal, cursor string, limit int) (tenantadmin.TenantPage, error)
	GetTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.TenantView, error)
	CreateTenant(ctx context.Context, p adminauth.Principal, in tenantadmin.TenantCreate, ip netip.Addr) (tenantadmin.TenantView, error)
	UpdateTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, in tenantadmin.TenantUpdate, ip netip.Addr) (tenantadmin.TenantView, error)
	DeleteTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, confirm string, ip netip.Addr) error
	GetBranding(ctx context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.Branding, error)
	UpdateBranding(ctx context.Context, p adminauth.Principal, tid tenant.ID, primary, accent string, ip netip.Addr) (tenantadmin.Branding, error)
	GetAsset(ctx context.Context, p adminauth.Principal, tid tenant.ID, asset string) (branding.Image, error)
	UploadAsset(ctx context.Context, p adminauth.Principal, tid tenant.ID, asset string, r io.Reader, ip netip.Addr) error
	DeleteAsset(ctx context.Context, p adminauth.Principal, tid tenant.ID, asset string, ip netip.Addr) error
	GetNetworkRules(ctx context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.NetworkRules, error)
	UpdateNetworkRules(ctx context.Context, p adminauth.Principal, tid tenant.ID, cidrs, domains []string, ip netip.Addr) (tenantadmin.NetworkRules, error)
	GetConfidentialityLevels(ctx context.Context, p adminauth.Principal, tid tenant.ID) ([]tenantadmin.ConfidentialityLevel, error)
	UpdateConfidentialityLevels(ctx context.Context, p adminauth.Principal, tid tenant.ID, levels []tenantadmin.ConfidentialityLevel, ip netip.Addr) ([]tenantadmin.ConfidentialityLevel, error)
	GetRecipientRules(ctx context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.RecipientRules, error)
	UpdateRecipientRules(ctx context.Context, p adminauth.Principal, tid tenant.ID, allowed, denied []string, ip netip.Addr) (tenantadmin.RecipientRules, error)
	AbuseThresholds(ctx context.Context, p adminauth.Principal, tid tenant.ID) (store.AbuseSettings, error)
	UpdateAbuseThresholds(ctx context.Context, p adminauth.Principal, tid tenant.ID, in store.AbuseSettings, ip netip.Addr) (store.AbuseSettings, error)
	GetSMTP(ctx context.Context, p adminauth.Principal, tid tenant.ID) (tenantadmin.SMTPView, error)
	UpdateSMTP(ctx context.Context, p adminauth.Principal, tid tenant.ID, in tenantadmin.SMTPUpdate, ip netip.Addr) (tenantadmin.SMTPView, error)
	TestSMTP(ctx context.Context, p adminauth.Principal, tid tenant.ID, to string, ip netip.Addr) (tenantadmin.SMTPTestResult, error)
	CheckMailDNS(ctx context.Context, p adminauth.Principal, tid tenant.ID, selectors []string) (tenantadmin.MailDNSCheck, error)
	ListTemplates(ctx context.Context, p adminauth.Principal, tid tenant.ID) ([]tenantadmin.TemplateSummary, error)
	GetTemplate(ctx context.Context, p adminauth.Principal, tid tenant.ID, key, lang string) (tenantadmin.Template, error)
	UpdateTemplate(ctx context.Context, p adminauth.Principal, tid tenant.ID, key, lang string, in tenantadmin.TemplateInput, ip netip.Addr) (tenantadmin.Template, error)
	ResetTemplate(ctx context.Context, p adminauth.Principal, tid tenant.ID, key, lang string, ip netip.Addr) error
	PreviewTemplate(ctx context.Context, p adminauth.Principal, tid tenant.ID, key, lang string, in *tenantadmin.TemplateInput) (tenantadmin.Preview, error)
	GetLegal(ctx context.Context, p adminauth.Principal, tid tenant.ID, doc, lang string) (tenantadmin.LegalDocument, error)
	UpdateLegal(ctx context.Context, p adminauth.Principal, tid tenant.ID, doc, lang, markdown string, ip netip.Addr) (tenantadmin.LegalDocument, error)
}

// Compile-time check that the tenant configuration service fits.
var _ TenantService = (*tenantadmin.Service)(nil)

// WithTenantService serves the tenant configuration operations with svc.
// Without it they answer 500.
func WithTenantService(svc TenantService) Option {
	return func(s *Server) { s.tenantSvc = svc }
}

// errNoTenantService reports a server built without WithTenantService: a
// wiring error, answered 500.
var errNoTenantService = errors.New("admin: no tenant configuration service configured")

// fieldInvalidTemplate is the field error code of a mail template issue.
const fieldInvalidTemplate = "invalid-template"

// templateFields maps the parts of a mail template to the JSON pointers of
// the request body (OpenAPI EmailTemplateUpdate).
var templateFields = map[string]string{
	mail.PartSubject: "/subject",
	mail.PartHTML:    "/bodyHtml",
	mail.PartText:    "/bodyText",
}

// tenantError maps an error of the tenant configuration service to the
// error the strict handler renders. Server errors keep their cause, which
// is logged (the service never puts a secret in it).
func tenantError(err error) error {
	var (
		invalid *tenantadmin.InvalidError
		limited *tenantadmin.RateLimitError
	)
	switch {
	case errors.As(err, &invalid):
		return invalidProblem(invalid)
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.Is(err, tenantadmin.ErrInvalid):
		return problem.New(problem.CodeValidationFailed)
	case errors.Is(err, tenantadmin.ErrRateLimited):
		return problem.New(problem.CodeRateLimited)
	case errors.Is(err, tenantadmin.ErrUnauthenticated):
		return problem.New(problem.CodeUnauthenticated)
	case errors.Is(err, tenantadmin.ErrForbidden):
		return problem.New(problem.CodeForbidden)
	case errors.Is(err, tenantadmin.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, tenantadmin.ErrAlreadyExists):
		return problem.New(problem.CodeAlreadyExists)
	case errors.Is(err, tenantadmin.ErrPayloadTooLarge), middleware.IsBodyTooLarge(err):
		return problem.New(problem.CodePayloadTooLarge)
	case errors.Is(err, tenantadmin.ErrUnsupportedMediaType):
		return problem.New(problem.CodeUnsupportedMediaType)
	default:
		return err
	}
}

// invalidProblem renders an invalid input: one field error per mail
// template issue (with its part, line, column and message), else one
// naming the field, with the code of the error when it has one (an admin
// host: reserved-host); none when the request as a whole is invalid.
func invalidProblem(e *tenantadmin.InvalidError) *problem.Problem {
	var fields []problem.FieldError
	for _, is := range e.Issues {
		field, ok := templateFields[is.Part]
		if !ok {
			field = e.Field
		}
		fields = append(fields, problem.FieldError{
			Field: field, Code: fieldInvalidTemplate, Line: is.Line, Column: is.Column, Message: is.Message,
		})
	}
	if len(fields) == 0 && e.Field != "" {
		code := e.Code
		if code == "" {
			code = formatCode(e.Field == tenantadmin.FieldFromAddress || e.Field == tenantadmin.FieldTo)
		}
		fields = append(fields, problem.FieldError{Field: e.Field, Code: code})
	}
	return problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(fields...))
}

// tenantSession returns the tenant configuration service and the session
// of the request, or the error to answer. The login state and the role
// are checked by the service.
func (s *Server) tenantSession(ctx context.Context) (TenantService, adminauth.Principal, error) {
	if s.tenantSvc == nil {
		return nil, adminauth.Principal{}, errNoTenantService
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.tenantSvc, p, nil
}

// --- Tenants -----------------------------------------------------------------

// ListTenants lists the tenants visible to the administrator.
func (s *Server) ListTenants(ctx context.Context, req gen.ListTenantsRequestObject) (gen.ListTenantsResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := svc.ListTenants(ctx, p, deref(req.Params.Cursor), deref(req.Params.Limit))
	if err != nil {
		return nil, tenantError(err)
	}
	resp := gen.ListTenants200JSONResponse{Items: make([]gen.Tenant, len(page.Items))}
	for i, v := range page.Items {
		resp.Items[i] = tenantBody(v)
	}
	if page.NextCursor != "" {
		next := page.NextCursor
		resp.NextCursor = &next
	}
	return resp, nil
}

// CreateTenant creates a tenant (super admin, 201), with its transfer
// limit and ceiling set in one step by the service.
func (s *Server) CreateTenant(ctx context.Context, req gen.CreateTenantRequestObject) (gen.CreateTenantResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(tenantadmin.FieldName, fieldRequired)
	}
	b := req.Body
	v, err := svc.CreateTenant(ctx, p, tenantadmin.TenantCreate{
		Name: b.Name, FQDN: b.Fqdn, DefaultLanguage: string(b.DefaultLanguage), StorageQuotaBytes: b.StorageQuotaBytes,
		MaxTransferBytes: deref(b.MaxTransferBytes), MaxTransferCeiling: b.MaxTransferCeiling,
	}, middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.CreateTenant201JSONResponse(tenantBody(v)), nil
}

// GetTenant returns the general settings of a tenant.
func (s *Server) GetTenant(ctx context.Context, req gen.GetTenantRequestObject) (gen.GetTenantResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	v, err := svc.GetTenant(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetTenant200JSONResponse(tenantBody(v)), nil
}

// UpdateTenant applies a JSON merge patch to the general settings of a
// tenant: absent fields are left unchanged, and null on a field (none can
// be removed) is refused with 400 validation-failed naming it.
func (s *Server) UpdateTenant(ctx context.Context, req gen.UpdateTenantRequestObject) (gen.UpdateTenantResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed("", fieldRequired)
	}
	in, err := decodeTenantUpdate(*req.Body)
	if err != nil {
		return nil, err
	}
	v, err := svc.UpdateTenant(ctx, p, tenant.ID(req.TenantId), in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.UpdateTenant200JSONResponse(tenantBody(v)), nil
}

// tenantPatch is the OpenAPI TenantUpdate, decoded by the handler itself
// (the generated type is raw JSON) so that a null field can be told from
// an absent one.
type tenantPatch struct {
	Name                       *string `json:"name"`
	FQDN                       *string `json:"fqdn"`
	DefaultLanguage            *string `json:"defaultLanguage"`
	StorageQuotaBytes          *int64  `json:"storageQuotaBytes"`
	MaxTransferBytes           *int64  `json:"maxTransferBytes"`
	MaxTransferCeiling         *int64  `json:"maxTransferCeiling"`
	WebhookIncludeAddresses    *bool   `json:"webhookIncludeAddresses"`
	AllowRemoteInternalDeposit *bool   `json:"allowRemoteInternalDeposit"`
}

// tenantPatchFields lists the members of a tenant merge patch, in the order
// their errors are reported.
var tenantPatchFields = []string{
	"name", "fqdn", "defaultLanguage", "storageQuotaBytes", "maxTransferBytes", "maxTransferCeiling",
	"webhookIncludeAddresses", "allowRemoteInternalDeposit",
}

// decodeTenantUpdate decodes a tenant merge patch: a JSON object whose
// members are absent (unchanged) or set, never null. A body that is not an
// object answers validation-failed on the whole body (""), null members
// one not-nullable entry each, and a member of the wrong type
// invalid-format on its pointer. Unknown members are ignored.
func decodeTenantUpdate(raw []byte) (tenantadmin.TenantUpdate, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return tenantadmin.TenantUpdate{}, validationFailed("", fieldInvalidFormat)
	}
	var nulls []problem.FieldError
	for _, name := range tenantPatchFields {
		if v, ok := members[name]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			nulls = append(nulls, problem.FieldError{Field: "/" + name, Code: fieldNotNullable})
		}
	}
	if len(nulls) > 0 {
		return tenantadmin.TenantUpdate{}, problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(nulls...))
	}
	var b tenantPatch
	if err := json.Unmarshal(raw, &b); err != nil {
		field := ""
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			field = "/" + typeErr.Field
		}
		return tenantadmin.TenantUpdate{}, validationFailed(field, fieldInvalidFormat)
	}
	return tenantadmin.TenantUpdate{
		Name: b.Name, FQDN: b.FQDN, DefaultLanguage: b.DefaultLanguage, StorageQuotaBytes: b.StorageQuotaBytes,
		MaxTransferBytes: b.MaxTransferBytes, MaxTransferCeiling: b.MaxTransferCeiling,
		WebhookIncludeAddresses:    b.WebhookIncludeAddresses,
		AllowRemoteInternalDeposit: b.AllowRemoteInternalDeposit,
	}, nil
}

// DeleteTenant deletes a tenant and all its data (super admin, 204 once
// erased). A failure leaves the tenant deleting; a new call resumes it.
func (s *Server) DeleteTenant(ctx context.Context, req gen.DeleteTenantRequestObject) (gen.DeleteTenantResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.DeleteTenant(ctx, p, tenant.ID(req.TenantId), req.Params.Confirm, middleware.ClientIP(ctx)); err != nil {
		return nil, tenantError(err)
	}
	return gen.DeleteTenant204Response{}, nil
}

// tenantBody renders v as the OpenAPI Tenant.
func tenantBody(v tenantadmin.TenantView) gen.Tenant {
	return gen.Tenant{
		Id: string(v.ID), Name: v.Name, Fqdn: v.FQDN, DefaultLanguage: gen.Language(v.DefaultLanguage),
		MaxTransferBytes: v.MaxTransferBytes, MaxTransferCeiling: v.MaxTransferCeiling,
		Status: gen.TenantStatus(v.Status), StorageQuotaBytes: v.StorageQuotaBytes, StorageUsedBytes: v.StorageUsedBytes,
		WebhookIncludeAddresses: &v.WebhookIncludeAddresses, AllowRemoteInternalDeposit: &v.AllowRemoteInternalDeposit, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
	}
}

// --- Branding ----------------------------------------------------------------

// GetBranding returns the colors and images of a tenant, with the
// contrast diagnostics.
func (s *Server) GetBranding(ctx context.Context, req gen.GetBrandingRequestObject) (gen.GetBrandingResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	b, err := svc.GetBranding(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetBranding200JSONResponse(brandingBody(b)), nil
}

// UpdateBranding sets the colors of a tenant; a poor contrast is reported,
// never refused.
func (s *Server) UpdateBranding(ctx context.Context, req gen.UpdateBrandingRequestObject) (gen.UpdateBrandingResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(tenantadmin.FieldPrimaryColor, fieldRequired)
	}
	b, err := svc.UpdateBranding(ctx, p, tenant.ID(req.TenantId), req.Body.PrimaryColor, req.Body.AccentColor, middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.UpdateBranding200JSONResponse(brandingBody(b)), nil
}

// AssetCacheControl is the Cache-Control of a branding image served to
// the administration: never cached, the preview always shows the image
// stored at the time of the request.
const AssetCacheControl = "no-store"

// GetBrandingAsset returns the custom logo or background image of a
// tenant, as re-encoded by the server, with its exact media type, nosniff,
// a strong ETag and no-store; 404 without a custom image (the default
// background is never returned here).
func (s *Server) GetBrandingAsset(ctx context.Context, req gen.GetBrandingAssetRequestObject) (gen.GetBrandingAssetResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	img, err := svc.GetAsset(ctx, p, tenant.ID(req.TenantId), req.Asset)
	if err != nil {
		return nil, tenantError(err)
	}
	return brandingAssetResponse(img), nil
}

// brandingAssetResponse writes a branding image to the administration.
type brandingAssetResponse branding.Image

// VisitGetBrandingAssetResponse implements gen.GetBrandingAssetResponseObject.
func (a brandingAssetResponse) VisitGetBrandingAssetResponse(w http.ResponseWriter) error {
	return apiutil.WriteImage(w, branding.Image(a), AssetCacheControl, false)
}

// UploadBrandingAsset stores the logo or background image of a tenant
// (204). The declared type must be an image/* type, but the format is
// detected from the content; the per-kind size limit is enforced by the
// service while reading (and by the body limit of the route).
func (s *Server) UploadBrandingAsset(ctx context.Context, req gen.UploadBrandingAssetRequestObject) (gen.UploadBrandingAssetResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if !isImageType(req.ContentType) {
		return nil, problem.New(problem.CodeUnsupportedMediaType)
	}
	body := req.Body
	if body == nil {
		body = strings.NewReader("")
	}
	if err := svc.UploadAsset(ctx, p, tenant.ID(req.TenantId), req.Asset, body, middleware.ClientIP(ctx)); err != nil {
		return nil, tenantError(err)
	}
	return gen.UploadBrandingAsset204Response{}, nil
}

// isImageType reports whether the Content-Type value ct is an image/*
// media type.
func isImageType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.HasPrefix(strings.ToLower(mt), "image/")
}

// DeleteBrandingAsset removes the logo or background image of a tenant
// (204): the default one is served again.
func (s *Server) DeleteBrandingAsset(ctx context.Context, req gen.DeleteBrandingAssetRequestObject) (gen.DeleteBrandingAssetResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.DeleteAsset(ctx, p, tenant.ID(req.TenantId), req.Asset, middleware.ClientIP(ctx)); err != nil {
		return nil, tenantError(err)
	}
	return gen.DeleteBrandingAsset204Response{}, nil
}

// brandingBody renders b as the OpenAPI Branding.
func brandingBody(b tenantadmin.Branding) gen.Branding {
	out := gen.Branding{
		PrimaryColor: b.PrimaryColor, AccentColor: b.AccentColor, HasLogo: b.HasLogo, HasBackground: b.HasBackground,
		Contrast: make([]gen.ContrastResult, len(b.Contrast)),
	}
	for i, c := range b.Contrast {
		out.Contrast[i] = gen.ContrastResult{
			Pair: gen.ContrastResultPair(c.Pair), Ratio: float32(c.Ratio), Level: gen.ContrastResultLevel(c.Level),
		}
	}
	return out
}

// --- Network rules -----------------------------------------------------------

// GetNetworkRules returns the internal IP ranges and mail domains of a
// tenant.
func (s *Server) GetNetworkRules(ctx context.Context, req gen.GetNetworkRulesRequestObject) (gen.GetNetworkRulesResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	r, err := svc.GetNetworkRules(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetNetworkRules200JSONResponse(networkBody(r)), nil
}

// UpdateNetworkRules replaces the network rules of a tenant and returns
// them normalized.
func (s *Server) UpdateNetworkRules(ctx context.Context, req gen.UpdateNetworkRulesRequestObject) (gen.UpdateNetworkRulesResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(tenantadmin.FieldInternalCIDRs, fieldRequired)
	}
	r, err := svc.UpdateNetworkRules(ctx, p, tenant.ID(req.TenantId), req.Body.InternalCidrs, req.Body.InternalDomains,
		middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.UpdateNetworkRules200JSONResponse(networkBody(r)), nil
}

// networkBody renders r as the OpenAPI NetworkRules, with empty lists
// rather than null.
func networkBody(r tenantadmin.NetworkRules) gen.NetworkRules {
	return gen.NetworkRules{
		InternalCidrs: append([]string{}, r.CIDRs...), InternalDomains: append([]string{}, r.Domains...),
	}
}

// --- SMTP --------------------------------------------------------------------

// GetSmtpSettings returns the SMTP settings of a tenant, never its
// password.
func (s *Server) GetSmtpSettings(ctx context.Context, req gen.GetSmtpSettingsRequestObject) (gen.GetSmtpSettingsResponseObject, error) { //nolint:revive // method name set by the generated gen.StrictServerInterface
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	v, err := svc.GetSMTP(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetSmtpSettings200JSONResponse(smtpBody(v)), nil
}

// UpdateSmtpSettings replaces the SMTP settings of a tenant.
func (s *Server) UpdateSmtpSettings(ctx context.Context, req gen.UpdateSmtpSettingsRequestObject) (gen.UpdateSmtpSettingsResponseObject, error) { //nolint:revive // method name set by the generated gen.StrictServerInterface
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(tenantadmin.FieldHost, fieldRequired)
	}
	b := req.Body
	v, err := svc.UpdateSMTP(ctx, p, tenant.ID(req.TenantId), tenantadmin.SMTPUpdate{
		Host: b.Host, Port: b.Port, Security: store.SMTPSecurity(b.Security), Username: deref(b.Username),
		Password: b.Password, RemovePassword: deref(b.RemovePassword),
		FromAddress: string(b.FromAddress), FromName: deref(b.FromName),
	}, middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.UpdateSmtpSettings200JSONResponse(smtpBody(v)), nil
}

// smtpBody renders v as the OpenAPI SmtpSettings: an empty username or
// sender name is null.
func smtpBody(v tenantadmin.SMTPView) gen.SmtpSettings {
	return gen.SmtpSettings{
		Host: v.Host, Port: v.Port, Security: gen.SmtpSecurity(v.Security), Username: optional(v.Username),
		PasswordSet: v.PasswordSet, FromAddress: gen.Email(v.FromAddress), FromName: optional(v.FromName),
	}
}

// TestSmtp sends a test mail with the SMTP settings of a tenant and
// reports how the exchange went (200, even when the delivery failed).
func (s *Server) TestSmtp(ctx context.Context, req gen.TestSmtpRequestObject) (gen.TestSmtpResponseObject, error) { //nolint:revive // method name set by the generated gen.StrictServerInterface
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(tenantadmin.FieldTo, fieldRequired)
	}
	res, err := svc.TestSMTP(ctx, p, tenant.ID(req.TenantId), string(req.Body.To), middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.TestSmtp200JSONResponse{
		Success: res.Success, DurationMs: int(res.Duration.Milliseconds()), Stage: gen.SmtpTestResultStage(res.Stage),
		Error: optional(res.Error),
	}, nil
}

// CheckMailDns runs the indicative SPF, DKIM and DMARC check of the sender
// domain of a tenant.
func (s *Server) CheckMailDns(ctx context.Context, req gen.CheckMailDnsRequestObject) (gen.CheckMailDnsResponseObject, error) { //nolint:revive // method name set by the generated gen.StrictServerInterface
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	c, err := svc.CheckMailDNS(ctx, p, tenant.ID(req.TenantId), deref(req.Params.DkimSelector))
	if err != nil {
		return nil, tenantError(err)
	}
	resp := gen.CheckMailDns200JSONResponse{Domain: c.Domain, Spf: dnsBody(c.SPF), Dmarc: dnsBody(c.DMARC)}
	resp.Dkim.Status = gen.MailDnsCheckDkimStatus(c.DKIM.Status)
	resp.Dkim.Selectors = make([]struct {
		Found    bool   `json:"found"`
		Selector string `json:"selector"`
	}, len(c.DKIM.Selectors))
	for i, sel := range c.DKIM.Selectors {
		resp.Dkim.Selectors[i].Found, resp.Dkim.Selectors[i].Selector = sel.Found, sel.Selector
	}
	return resp, nil
}

// dnsBody renders c as the OpenAPI DnsRecordCheck.
func dnsBody(c tenantadmin.DNSRecordCheck) gen.DnsRecordCheck {
	return gen.DnsRecordCheck{Status: gen.DnsRecordCheckStatus(c.Status), Record: optional(c.Record), Message: optional(c.Message)}
}

// --- Mail templates ----------------------------------------------------------

// ListEmailTemplates lists every template of a tenant and whether it is
// customized.
func (s *Server) ListEmailTemplates(ctx context.Context, req gen.ListEmailTemplatesRequestObject) (gen.ListEmailTemplatesResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	list, err := svc.ListTemplates(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, tenantError(err)
	}
	resp := make(gen.ListEmailTemplates200JSONResponse, len(list))
	for i, t := range list {
		resp[i] = gen.EmailTemplateSummary{
			Key: gen.EmailTemplateKey(t.Key), Language: gen.Language(t.Language), Customised: t.Customized, //nolint:misspell // field name of the generated OpenAPI type (spec spelling)
			UpdatedAt: optionalTime(t.UpdatedAt),
		}
	}
	return resp, nil
}

// GetEmailTemplate returns a template of a tenant, customized or default.
func (s *Server) GetEmailTemplate(ctx context.Context, req gen.GetEmailTemplateRequestObject) (gen.GetEmailTemplateResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	t, err := svc.GetTemplate(ctx, p, tenant.ID(req.TenantId), string(req.TemplateKey), string(req.Language))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetEmailTemplate200JSONResponse(templateBody(t)), nil
}

// UpdateEmailTemplate customizes a template of a tenant and returns it as
// saved (sanitized).
func (s *Server) UpdateEmailTemplate(ctx context.Context, req gen.UpdateEmailTemplateRequestObject) (gen.UpdateEmailTemplateResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(templateFields[mail.PartSubject], fieldRequired)
	}
	t, err := svc.UpdateTemplate(ctx, p, tenant.ID(req.TenantId), string(req.TemplateKey), string(req.Language),
		templateInput(*req.Body), middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.UpdateEmailTemplate200JSONResponse(templateBody(t)), nil
}

// ResetEmailTemplate removes the customization of a template (204).
func (s *Server) ResetEmailTemplate(ctx context.Context, req gen.ResetEmailTemplateRequestObject) (gen.ResetEmailTemplateResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.ResetTemplate(ctx, p, tenant.ID(req.TenantId), string(req.TemplateKey), string(req.Language),
		middleware.ClientIP(ctx)); err != nil {
		return nil, tenantError(err)
	}
	return gen.ResetEmailTemplate204Response{}, nil
}

// PreviewEmailTemplate renders the submitted template, or the stored one
// without body, with sample data.
func (s *Server) PreviewEmailTemplate(ctx context.Context, req gen.PreviewEmailTemplateRequestObject) (gen.PreviewEmailTemplateResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	var in *tenantadmin.TemplateInput
	if req.Body != nil {
		v := templateInput(*req.Body)
		in = &v
	}
	pv, err := svc.PreviewTemplate(ctx, p, tenant.ID(req.TenantId), string(req.TemplateKey), string(req.Language), in)
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.PreviewEmailTemplate200JSONResponse{Subject: pv.Subject, BodyHtml: pv.HTML, BodyText: pv.Text}, nil
}

// templateInput converts a submitted template.
func templateInput(b gen.EmailTemplateUpdate) tenantadmin.TemplateInput {
	return tenantadmin.TemplateInput{Subject: b.Subject, HTML: b.BodyHtml, Text: b.BodyText}
}

// templateBody renders t as the OpenAPI EmailTemplate.
func templateBody(t tenantadmin.Template) gen.EmailTemplate {
	out := gen.EmailTemplate{
		Key: gen.EmailTemplateKey(t.Key), Language: gen.Language(t.Language), Customised: t.Customized, //nolint:misspell // field name of the generated OpenAPI type (spec spelling)
		Subject: t.Subject, BodyHtml: t.HTML, BodyText: t.Text, Variables: make([]string, len(t.Variables)),
		RequiredVariables: []string{}, UpdatedAt: optionalTime(t.UpdatedAt),
	}
	for i, v := range t.Variables {
		out.Variables[i] = v.Name
		if v.Required {
			out.RequiredVariables = append(out.RequiredVariables, v.Name)
		}
	}
	return out
}

// --- Legal documents ---------------------------------------------------------

// GetLegalDocumentAdmin returns the Markdown source of a legal document of
// a tenant in one language (empty when not written).
func (s *Server) GetLegalDocumentAdmin(ctx context.Context, req gen.GetLegalDocumentAdminRequestObject) (gen.GetLegalDocumentAdminResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	d, err := svc.GetLegal(ctx, p, tenant.ID(req.TenantId), string(req.Document), string(req.Language))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetLegalDocumentAdmin200JSONResponse(legalBody(d)), nil
}

// UpdateLegalDocument replaces a legal document of a tenant; a blank text
// removes it.
func (s *Server) UpdateLegalDocument(ctx context.Context, req gen.UpdateLegalDocumentRequestObject) (gen.UpdateLegalDocumentResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(tenantadmin.FieldMarkdown, fieldRequired)
	}
	d, err := svc.UpdateLegal(ctx, p, tenant.ID(req.TenantId), string(req.Document), string(req.Language), req.Body.Markdown,
		middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.UpdateLegalDocument200JSONResponse(legalBody(d)), nil
}

// legalBody renders d as the OpenAPI LegalDocument, with the sanitized
// HTML rendering served on the public pages ("" when not written).
func legalBody(d tenantadmin.LegalDocument) gen.LegalDocument {
	html := d.HTML
	return gen.LegalDocument{
		Document: gen.LegalDocumentDocument(d.Document), Language: gen.Language(d.Language), Markdown: d.Markdown,
		Html: &html, UpdatedAt: optionalTime(d.UpdatedAt),
	}
}

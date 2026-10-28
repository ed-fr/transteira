package public

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ed-fr/transteira/internal/api/apiutil"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// Paths and cache policy of the branding images (getTenantAsset).
const (
	// LogoPath is the URL of the logo of the current tenant.
	LogoPath = "/api/v1/tenant/assets/logo"
	// BackgroundPath is the URL of the background image of the current
	// tenant.
	BackgroundPath = "/api/v1/tenant/assets/background"
	// AssetCacheControl is the Cache-Control of a branding image: a short
	// public lifetime (the URL does not change when the image does), then
	// a revalidation with the ETag.
	AssetCacheControl = "public, max-age=300"
)

// expiryDays are the validities offered to the senders (spec 8.2).
var expiryDays = []gen.ExpiryDays{gen.N1, gen.N7, gen.N30}

// TenantService serves the public configuration of a tenant
// (*tenantadmin.Service): its branding images and legal documents.
type TenantService interface {
	Asset(ctx context.Context, t *tenant.Tenant, asset string) (branding.Image, error)
	PublicLegal(ctx context.Context, t *tenant.Tenant, doc, lang string) (tenantadmin.PublicLegalDocument, error)
	LegalDocuments(ctx context.Context, t *tenant.Tenant) ([]string, error)
	PublicConfidentialityLevels(ctx context.Context, t *tenant.Tenant, lang string) ([]tenantadmin.PublicConfidentialityLevel, error)
	HasRecipientRules(ctx context.Context, t *tenant.Tenant) (bool, error)
}

// Compile-time check that the tenant configuration service fits.
var _ TenantService = (*tenantadmin.Service)(nil)

// WithTenantService serves the public tenant configuration (getPublicTenant,
// getTenantAsset, getTenantLegalDocument) with svc. Without it these
// operations answer 500.
func WithTenantService(svc TenantService) Option {
	return func(s *Server) { s.tenants = svc }
}

// MaintenanceMode reports the maintenance mode (*maintenance.Mode).
type MaintenanceMode interface {
	// Active reports whether the maintenance mode is in effect.
	Active() bool
	// Message returns the maintenance message for the negotiated language
	// lang on a tenant whose default language is tenantDefault, with the
	// language it is written in (which may be a fallback); two empty
	// strings when the mode is off or no message is set.
	Message(lang, tenantDefault string) (msg, msgLang string)
}

// WithMaintenance reports the maintenance mode and its message in the
// public configuration with m (the mode of the maintenance middleware).
// Without it the maintenance mode is reported off.
func WithMaintenance(m MaintenanceMode) Option {
	return func(s *Server) { s.maintenance = m }
}

// errNoTenantService reports a server built without WithTenantService: a
// wiring error, answered 500.
var errNoTenantService = errors.New("public: no tenant configuration service configured")

// publicTenant returns the tenant of the request and the tenant
// configuration service, or the error to answer.
func (s *Server) publicTenant(ctx context.Context) (*tenant.Tenant, TenantService, error) {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return nil, nil, problem.New(problem.CodeUnknownTenant)
	}
	if s.tenants == nil {
		return nil, nil, errNoTenantService
	}
	return t, s.tenants, nil
}

// publicError maps an error of the tenant configuration service.
func publicError(err error) error {
	if errors.Is(err, tenantadmin.ErrNotFound) {
		return problem.New(problem.CodeNotFound)
	}
	return err
}

// GetPublicTenant returns the public configuration of the current tenant:
// name, negotiated language, branding, limits, maintenance mode with its
// message in the negotiated language (else the tenant default, English or
// any language set) together with the language it is written in, so that
// the client can mark it up (RGAA 8.7), and the legal documents it has
// written.
func (s *Server) GetPublicTenant(ctx context.Context, req gen.GetPublicTenantRequestObject) (gen.GetPublicTenantResponseObject, error) {
	t, svc, err := s.publicTenant(ctx)
	if err != nil {
		return nil, err
	}
	docs, err := svc.LegalDocuments(ctx, t)
	if err != nil {
		return nil, err
	}
	lang := i18n.Negotiate(deref(req.Params.AcceptLanguage), t.DefaultLanguage)
	levels, err := svc.PublicConfidentialityLevels(ctx, t, lang)
	if err != nil {
		return nil, err
	}
	restricted, err := svc.HasRecipientRules(ctx, t)
	if err != nil {
		return nil, err
	}
	body := gen.PublicTenant{
		Name: t.Name, Language: gen.Language(lang),
		LegalDocuments: make([]gen.PublicTenantLegalDocuments, len(docs)),
	}
	if s.maintenance != nil && s.maintenance.Active() {
		body.Maintenance = true
		if msg, msgLang := s.maintenance.Message(lang, t.DefaultLanguage); msg != "" {
			ml := gen.Language(msgLang)
			body.MaintenanceMessage, body.MaintenanceMessageLanguage = &msg, &ml
		}
	}
	for _, l := range i18n.Supported() {
		body.AvailableLanguages = append(body.AvailableLanguages, gen.Language(l))
	}
	for i, d := range docs {
		body.LegalDocuments[i] = gen.PublicTenantLegalDocuments(d)
	}
	body.Branding.PrimaryColor, body.Branding.AccentColor = t.PrimaryColor, t.AccentColor
	body.Branding.HasLogo, body.Branding.HasBackground = t.HasLogo, t.HasBackground
	body.Branding.BackgroundUrl = BackgroundPath
	if t.HasLogo {
		logo := LogoPath
		body.Branding.LogoUrl = &logo
	}
	body.Limits.MaxTransferBytes = t.MaxTransferBytes
	body.Limits.ExpiryDays = append([]gen.ExpiryDays{}, expiryDays...)
	body.ConfidentialityLevels = publicLevels(levels)
	// The features announce what the server really offers. The options
	// of later steps (per-recipient links and their verification, replies,
	// folders, remote deposit, antivirus switch) stay off or at their
	// default until they exist.
	body.Features = &gen.TenantFeatures{
		MaxDownloads:          true,
		RecipientVerification: false, // per-recipient links come with step 6
		RecipientRestrictions: restricted,
		Antivirus:             gen.Enabled,
	}
	return gen.GetPublicTenant200JSONResponse{
		Body: body, Headers: gen.GetPublicTenant200ResponseHeaders{ContentLanguage: &lang},
	}, nil
}

// publicLevels renders the confidentiality levels of the public
// configuration.
func publicLevels(levels []tenantadmin.PublicConfidentialityLevel) *[]gen.PublicConfidentialityLevel {
	out := make([]gen.PublicConfidentialityLevel, len(levels))
	for i, l := range levels {
		days := make([]gen.ExpiryDays, len(l.Rules.AllowedExpiryDays))
		for j, d := range l.Rules.AllowedExpiryDays {
			days[j] = gen.ExpiryDays(d)
		}
		out[i] = gen.PublicConfidentialityLevel{
			Key: l.Key, Label: l.Label, IsDefault: l.IsDefault,
			Rules: gen.ConfidentialityRules{
				AllowedExpiryDays: days, MaxDownloads: l.Rules.MaxDownloads,
				RequirePassword:               l.Rules.RequirePassword,
				RequireRecipientVerification:  l.Rules.RequireRecipientVerification,
				InternalRecipientsOnly:        l.Rules.InternalRecipientsOnly,
				ForceDeleteAfterFirstDownload: l.Rules.ForceDeleteAfterFirstDownload,
			},
		}
		if l.Description != "" {
			d := l.Description
			out[i].Description = &d
		}
	}
	return &out
}

// GetTenantAsset serves the logo or background image of the current
// tenant: always an image re-encoded by the server (or the default
// background), with its exact media type, nosniff, a strong ETag and a
// short public cache lifetime; 304 when If-None-Match names it.
func (s *Server) GetTenantAsset(ctx context.Context, req gen.GetTenantAssetRequestObject) (gen.GetTenantAssetResponseObject, error) {
	t, svc, err := s.publicTenant(ctx)
	if err != nil {
		return nil, err
	}
	img, err := svc.Asset(ctx, t, string(req.Asset))
	if err != nil {
		return nil, publicError(err)
	}
	return assetResponse{img: img, notModified: etagMatches(deref(req.Params.IfNoneMatch), img.ETag)}, nil
}

// assetResponse writes a branding image, or 304 Not Modified.
type assetResponse struct {
	img         branding.Image
	notModified bool
}

// VisitGetTenantAssetResponse implements gen.GetTenantAssetResponseObject.
func (a assetResponse) VisitGetTenantAssetResponse(w http.ResponseWriter) error {
	return apiutil.WriteImage(w, a.img, AssetCacheControl, a.notModified)
}

// etagMatches reports whether the If-None-Match value header names etag
// (RFC 9110 section 13.1.2: weak comparison, "*" matches any).
func etagMatches(header, etag string) bool {
	for v := range strings.SplitSeq(header, ",") {
		v = strings.TrimSpace(v)
		if v == "*" || strings.TrimPrefix(v, "W/") == etag {
			return true
		}
	}
	return false
}

// GetTenantLegalDocument returns a legal document of the current tenant in
// the negotiated language, or else its default language, with the
// sanitized HTML rendering of its Markdown source.
func (s *Server) GetTenantLegalDocument(ctx context.Context, req gen.GetTenantLegalDocumentRequestObject) (gen.GetTenantLegalDocumentResponseObject, error) {
	t, svc, err := s.publicTenant(ctx)
	if err != nil {
		return nil, err
	}
	lang := i18n.Negotiate(deref(req.Params.AcceptLanguage), t.DefaultLanguage)
	d, err := svc.PublicLegal(ctx, t, string(req.Document), lang)
	if err != nil {
		return nil, publicError(err)
	}
	html, served := d.HTML, d.Language
	body := gen.LegalDocument{
		Document: gen.LegalDocumentDocument(d.Document), Language: gen.Language(d.Language), Markdown: d.Markdown,
		Html: &html,
	}
	if !d.UpdatedAt.IsZero() {
		at := d.UpdatedAt
		body.UpdatedAt = &at
	}
	return gen.GetTenantLegalDocument200JSONResponse{
		Body: body, Headers: gen.GetTenantLegalDocument200ResponseHeaders{ContentLanguage: &served},
	}, nil
}

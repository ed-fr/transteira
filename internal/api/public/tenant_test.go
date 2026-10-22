package public

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// fakeTenantConfig serves the public configuration of tenant ten_x.
type fakeTenantConfig struct {
	err     error
	docs    []string
	img     branding.Image
	legal   tenantadmin.PublicLegalDocument
	gotLang string
}

func (f *fakeTenantConfig) Asset(_ context.Context, t *tenant.Tenant, asset string) (branding.Image, error) {
	if t.ID != "ten_x" || asset != "logo" {
		return branding.Image{}, errors.New("unexpected arguments")
	}
	return f.img, f.err
}

func (f *fakeTenantConfig) PublicLegal(_ context.Context, t *tenant.Tenant, doc, lang string) (tenantadmin.PublicLegalDocument, error) {
	if t.ID != "ten_x" || doc != "privacy-policy" {
		return tenantadmin.PublicLegalDocument{}, errors.New("unexpected arguments")
	}
	f.gotLang = lang
	return f.legal, f.err
}

func (f *fakeTenantConfig) LegalDocuments(context.Context, *tenant.Tenant) ([]string, error) {
	return f.docs, f.err
}

// brandedCtx returns a context holding a branded tenant.
func brandedCtx(hasLogo bool) context.Context {
	return tenant.WithTenant(context.Background(), &tenant.Tenant{
		ID: "ten_x", Name: "Entity A", FQDN: "transfer.entity-a.example.com", DefaultLanguage: "fr",
		MaxTransferBytes: 5 << 30, PrimaryColor: "#0B5FFF", AccentColor: "#00875A", HasLogo: hasLogo,
	})
}

func TestPublicTenantWithoutTenantOrService(t *testing.T) {
	t.Parallel()
	s := NewServer(WithTenantService(&fakeTenantConfig{}))
	ctx := context.Background()
	calls := []func() error{
		func() error { _, err := s.GetPublicTenant(ctx, gen.GetPublicTenantRequestObject{}); return err },
		func() error { _, err := s.GetTenantAsset(ctx, gen.GetTenantAssetRequestObject{}); return err },
		func() error {
			_, err := s.GetTenantLegalDocument(ctx, gen.GetTenantLegalDocumentRequestObject{})
			return err
		},
	}
	for i, call := range calls {
		var p *problem.Problem
		if err := call(); !errors.As(err, &p) || p.Code != problem.CodeUnknownTenant {
			t.Errorf("call %d without tenant: %v", i, err)
		}
	}
	bare := NewServer()
	if _, err := bare.GetPublicTenant(tenantCtx(), gen.GetPublicTenantRequestObject{}); !errors.Is(err, errNoTenantService) {
		t.Errorf("without service: %v", err)
	}
}

func TestGetPublicTenant(t *testing.T) {
	t.Parallel()
	svc := &fakeTenantConfig{docs: []string{"privacy-policy"}}
	maintenance := true
	s := NewServer(WithTenantService(svc), WithMaintenance(func() bool { return maintenance }))
	accept := "en-GB,en;q=0.9"
	resp, err := s.GetPublicTenant(brandedCtx(true), gen.GetPublicTenantRequestObject{
		Params: gen.GetPublicTenantParams{AcceptLanguage: &accept},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.GetPublicTenant200JSONResponse)
	b := got.Body
	if b.Name != "Entity A" || b.Language != "en" || *got.Headers.ContentLanguage != "en" || !b.Maintenance {
		t.Errorf("body %+v", b)
	}
	if !reflect.DeepEqual(b.AvailableLanguages, []gen.Language{"fr", "en"}) && !reflect.DeepEqual(b.AvailableLanguages, []gen.Language{"en", "fr"}) {
		t.Errorf("languages %v", b.AvailableLanguages)
	}
	if b.Branding.PrimaryColor != "#0B5FFF" || b.Branding.AccentColor != "#00875A" || !b.Branding.HasLogo || b.Branding.HasBackground ||
		b.Branding.LogoUrl == nil || *b.Branding.LogoUrl != LogoPath || b.Branding.BackgroundUrl != BackgroundPath {
		t.Errorf("branding %+v", b.Branding)
	}
	if b.Limits.MaxTransferBytes != 5<<30 || !reflect.DeepEqual(b.Limits.ExpiryDays, []gen.ExpiryDays{1, 7, 30}) {
		t.Errorf("limits %+v", b.Limits)
	}
	if !reflect.DeepEqual(b.LegalDocuments, []gen.PublicTenantLegalDocuments{"privacy-policy"}) {
		t.Errorf("legal documents %v", b.LegalDocuments)
	}

	// Without logo, without maintenance flag, default language.
	resp, err = NewServer(WithTenantService(&fakeTenantConfig{})).GetPublicTenant(brandedCtx(false), gen.GetPublicTenantRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	b = resp.(gen.GetPublicTenant200JSONResponse).Body
	if b.Branding.LogoUrl != nil || b.Branding.HasLogo || b.Maintenance || b.Language != "fr" || b.LegalDocuments == nil {
		t.Errorf("body without logo %+v", b)
	}

	boom := errors.New("database down")
	if _, err := NewServer(WithTenantService(&fakeTenantConfig{err: boom})).GetPublicTenant(brandedCtx(false),
		gen.GetPublicTenantRequestObject{}); !errors.Is(err, boom) {
		t.Errorf("failure: %v", err)
	}
}

func TestGetTenantAsset(t *testing.T) {
	t.Parallel()
	img := branding.Image{Data: []byte("\x89PNG-data"), ContentType: branding.ContentTypePNG, ETag: `"abc"`}
	s := NewServer(WithTenantService(&fakeTenantConfig{img: img}))
	resp, err := s.GetTenantAsset(brandedCtx(true), gen.GetTenantAssetRequestObject{Asset: "logo"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitGetTenantAssetResponse(rec); err != nil {
		t.Fatal(err)
	}
	h := rec.Header()
	if rec.Code != http.StatusOK || rec.Body.String() != "\x89PNG-data" || h.Get("Content-Type") != "image/png" ||
		h.Get("Content-Length") != "9" || h.Get("ETag") != `"abc"` || h.Get("Cache-Control") != AssetCacheControl ||
		h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("200: %d %v %q", rec.Code, h, rec.Body.String())
	}

	for _, inm := range []string{`"abc"`, `W/"abc"`, `"x", "abc"`, "*"} {
		resp, err := s.GetTenantAsset(brandedCtx(true), gen.GetTenantAssetRequestObject{
			Asset: "logo", Params: gen.GetTenantAssetParams{IfNoneMatch: &inm},
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		if err := resp.VisitGetTenantAssetResponse(rec); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 || rec.Header().Get("ETag") != `"abc"` ||
			rec.Header().Get("Content-Type") != "" || rec.Header().Get("Cache-Control") != AssetCacheControl {
			t.Errorf("If-None-Match %s: %d %v", inm, rec.Code, rec.Header())
		}
	}
	other := `"other"`
	resp, _ = s.GetTenantAsset(brandedCtx(true), gen.GetTenantAssetRequestObject{
		Asset: "logo", Params: gen.GetTenantAssetParams{IfNoneMatch: &other},
	})
	if a := resp.(assetResponse); a.notModified {
		t.Error("another entity tag matched")
	}

	missing := NewServer(WithTenantService(&fakeTenantConfig{err: tenantadmin.ErrNotFound}))
	_, err = missing.GetTenantAsset(brandedCtx(false), gen.GetTenantAssetRequestObject{Asset: "logo"})
	var p *problem.Problem
	if !errors.As(err, &p) || p.Code != problem.CodeNotFound {
		t.Errorf("missing logo: %v", err)
	}
	boom := errors.New("disk failure")
	if _, err := NewServer(WithTenantService(&fakeTenantConfig{err: boom})).GetTenantAsset(brandedCtx(true),
		gen.GetTenantAssetRequestObject{Asset: "logo"}); !errors.Is(err, boom) {
		t.Errorf("failure: %v", err)
	}
}

func TestAssetResponseWriteFailure(t *testing.T) {
	t.Parallel()
	a := assetResponse{img: branding.Image{Data: []byte("x"), ContentType: branding.ContentTypeJPEG, ETag: `"e"`}}
	if err := a.VisitGetTenantAssetResponse(failingWriter{httptest.NewRecorder()}); err == nil {
		t.Error("write failure not reported")
	}
}

func TestGetTenantLegalDocument(t *testing.T) {
	t.Parallel()
	updated := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	svc := &fakeTenantConfig{legal: tenantadmin.PublicLegalDocument{
		LegalDocument: tenantadmin.LegalDocument{Document: "privacy-policy", Language: "fr", Markdown: "# Politique", UpdatedAt: updated},
		HTML:          "<h1>Politique</h1>\n",
	}}
	s := NewServer(WithTenantService(svc))
	accept := "en"
	resp, err := s.GetTenantLegalDocument(brandedCtx(false), gen.GetTenantLegalDocumentRequestObject{
		Document: "privacy-policy", Params: gen.GetTenantLegalDocumentParams{AcceptLanguage: &accept},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.(gen.GetTenantLegalDocument200JSONResponse)
	if svc.gotLang != "en" {
		t.Errorf("negotiated %q, want en", svc.gotLang)
	}
	// The service fell back to the default language: the answer says so.
	if got.Body.Language != "fr" || *got.Headers.ContentLanguage != "fr" || got.Body.Markdown != "# Politique" ||
		*got.Body.Html != "<h1>Politique</h1>\n" || !got.Body.UpdatedAt.Equal(updated) || got.Body.Document != "privacy-policy" {
		t.Errorf("answer %+v", got.Body)
	}

	svc.legal.UpdatedAt = time.Time{}
	resp, _ = s.GetTenantLegalDocument(brandedCtx(false), gen.GetTenantLegalDocumentRequestObject{Document: "privacy-policy"})
	if got := resp.(gen.GetTenantLegalDocument200JSONResponse); got.Body.UpdatedAt != nil || svc.gotLang != "fr" {
		t.Errorf("zero time: %+v (lang %q)", got.Body, svc.gotLang)
	}

	_, err = NewServer(WithTenantService(&fakeTenantConfig{err: tenantadmin.ErrNotFound})).GetTenantLegalDocument(brandedCtx(false),
		gen.GetTenantLegalDocumentRequestObject{Document: "privacy-policy"})
	var p *problem.Problem
	if !errors.As(err, &p) || p.Code != problem.CodeNotFound {
		t.Errorf("missing: %v", err)
	}
}

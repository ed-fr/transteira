package httpserver

import (
	"context"
	"io"

	"github.com/ed-fr/transteira/internal/api/admin"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/stubs"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// noLogoTenants is the public configuration of tenants without logo nor
// legal document: GET /api/v1/tenant/assets/logo answers 404 not-found.
type noLogoTenants struct{}

func (noLogoTenants) Asset(context.Context, *tenant.Tenant, string) (branding.Image, error) {
	return branding.Image{}, tenantadmin.ErrNotFound
}

func (noLogoTenants) PublicLegal(context.Context, *tenant.Tenant, string, string) (tenantadmin.PublicLegalDocument, error) {
	return tenantadmin.PublicLegalDocument{}, tenantadmin.ErrNotFound
}

func (noLogoTenants) LegalDocuments(context.Context, *tenant.Tenant) ([]string, error) {
	return nil, nil
}

// stubTenantAdmin answers the tenant operations used by the middleware
// tests like stubs: the merge patch of a tenant, and the branding upload
// after reading its whole body (so that the body limit applies).
type stubTenantAdmin struct{ *admin.Server }

func (stubTenantAdmin) UpdateTenant(context.Context, gen.UpdateTenantRequestObject) (gen.UpdateTenantResponseObject, error) {
	return nil, stubs.ErrNotImplemented
}

func (stubTenantAdmin) UploadBrandingAsset(_ context.Context, req gen.UploadBrandingAssetRequestObject) (gen.UploadBrandingAssetResponseObject, error) {
	if _, err := io.Copy(io.Discard, req.Body); err != nil {
		return nil, err
	}
	return nil, stubs.ErrNotImplemented
}

package tenantadmin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"strings"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Branding is the branding of a tenant (OpenAPI Branding).
type Branding struct {
	PrimaryColor  string
	AccentColor   string
	HasLogo       bool
	HasBackground bool
	// Contrast is the WCAG contrast of the colors, a warning only.
	Contrast []branding.ContrastResult
}

// brandingOf returns the branding of t with its contrast diagnostics.
func brandingOf(t *tenant.Tenant) Branding {
	// The store only holds valid colors.
	primary, _ := branding.ParseHexColor(t.PrimaryColor)
	accent, _ := branding.ParseHexColor(t.AccentColor)
	return Branding{
		PrimaryColor: t.PrimaryColor, AccentColor: t.AccentColor, HasLogo: t.HasLogo, HasBackground: t.HasBackground,
		Contrast: branding.Check(primary, accent),
	}
}

// GetBranding returns the branding of tenant tid.
func (s *Service) GetBranding(ctx context.Context, p adminauth.Principal, tid tenant.ID) (Branding, error) {
	t, err := s.readable(ctx, p, tid)
	if err != nil {
		return Branding{}, err
	}
	return brandingOf(t), nil
}

// UpdateBranding sets the colors of tenant tid ("#RRGGBB", stored in upper
// case). A poor contrast is reported in the result, never refused. Access
// is checked first: the refusal on a tenant out of reach never depends on
// the colors.
func (s *Service) UpdateBranding(ctx context.Context, p adminauth.Principal, tid tenant.ID, primary, accent string, ip netip.Addr) (Branding, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return Branding{}, err
	}
	if !tenant.ValidColor(primary) {
		return Branding{}, invalid(FieldPrimaryColor, "must be #RRGGBB")
	}
	if !tenant.ValidColor(accent) {
		return Branding{}, invalid(FieldAccentColor, "must be #RRGGBB")
	}
	t, err := s.changeTenant(ctx, p, tid, func(t *tenant.Tenant) {
		t.PrimaryColor, t.AccentColor = strings.ToUpper(primary), strings.ToUpper(accent)
	})
	if err != nil {
		return Branding{}, err
	}
	s.record(ctx, p, ip, tid, ActionTenantBrandingUpdated, map[string]any{
		"primaryColor": t.PrimaryColor, "accentColor": t.AccentColor,
	})
	return brandingOf(t), nil
}

// UploadAsset stores the logo or background image of tenant tid. asset is
// "logo" or "background" (else ErrNotFound). The image is decoded and
// re-encoded by [branding.Process]: ErrUnsupportedMediaType for a format
// other than PNG, JPEG or WebP (SVG included), ErrPayloadTooLarge above
// the limits, an *InvalidError for a corrupt image.
func (s *Service) UploadAsset(ctx context.Context, p adminauth.Principal, tid tenant.ID, asset string, r io.Reader, ip netip.Addr) error {
	kind, err := branding.ParseKind(asset)
	if err != nil {
		return ErrNotFound
	}
	if _, err := s.writable(ctx, p, tid); err != nil {
		return err
	}
	img, err := branding.ProcessContext(ctx, kind, r, 0)
	switch {
	case errors.Is(err, branding.ErrUnsupportedFormat):
		return fmt.Errorf("%w: %w", ErrUnsupportedMediaType, err)
	case errors.Is(err, branding.ErrTooLarge):
		return fmt.Errorf("%w: %w", ErrPayloadTooLarge, err)
	case errors.Is(err, branding.ErrInvalid):
		return invalid(FieldImage, "corrupt or unreadable image")
	case err != nil:
		return fmt.Errorf("tenantadmin: read image: %w", err)
	}
	if err := s.assets.Put(tid, kind, img.Data); err != nil {
		return fmt.Errorf("tenantadmin: store %s: %w", kind, err)
	}
	if _, err := s.changeTenant(ctx, p, tid, func(t *tenant.Tenant) { setAssetFlag(t, kind, true) }); err != nil {
		return err
	}
	s.record(ctx, p, ip, tid, ActionTenantAssetUploaded, map[string]any{
		"asset": kind.String(), "width": img.Width, "height": img.Height, "bytes": len(img.Data),
	})
	return nil
}

// DeleteAsset removes the logo or background image of tenant tid: the
// default one is served again. asset is "logo" or "background" (else
// ErrNotFound).
func (s *Service) DeleteAsset(ctx context.Context, p adminauth.Principal, tid tenant.ID, asset string, ip netip.Addr) error {
	kind, err := branding.ParseKind(asset)
	if err != nil {
		return ErrNotFound
	}
	// The flag goes first: a failure afterwards leaves an unused file,
	// never a flag pointing to a missing one.
	if _, err := s.changeTenant(ctx, p, tid, func(t *tenant.Tenant) { setAssetFlag(t, kind, false) }); err != nil {
		return err
	}
	if err := s.assets.Delete(tid, kind); err != nil {
		return fmt.Errorf("tenantadmin: delete %s: %w", kind, err)
	}
	s.record(ctx, p, ip, tid, ActionTenantAssetDeleted, map[string]any{"asset": kind.String()})
	return nil
}

// GetAsset returns the logo or background image stored for tenant tid, for
// the administration: always an image re-encoded by the server, with its
// exact content type and a strong ETag. It returns ErrNotFound for an
// unknown asset name, a tenant out of reach of p, or when the tenant has
// no such custom image (the default background is never returned here).
func (s *Service) GetAsset(ctx context.Context, p adminauth.Principal, tid tenant.ID, asset string) (branding.Image, error) {
	kind, err := branding.ParseKind(asset)
	if err != nil {
		return branding.Image{}, ErrNotFound
	}
	t, err := s.readable(ctx, p, tid)
	if err != nil {
		return branding.Image{}, err
	}
	img, ok, err := s.storedAsset(t, kind)
	switch {
	case err != nil:
		return branding.Image{}, err
	case !ok:
		return branding.Image{}, ErrNotFound
	}
	return img, nil
}

// Asset returns the logo or background image of tenant t for the public
// pages: the stored image, the default background when the tenant has
// none, ErrNotFound for a missing logo or an unknown asset name. The image
// is always one re-encoded by the server, with its exact content type and
// a strong ETag.
func (s *Service) Asset(_ context.Context, t *tenant.Tenant, asset string) (branding.Image, error) {
	kind, err := branding.ParseKind(asset)
	if err != nil {
		return branding.Image{}, ErrNotFound
	}
	img, ok, err := s.storedAsset(t, kind)
	switch {
	case err != nil:
		return branding.Image{}, err
	case ok:
		return img, nil
	case kind == branding.KindBackground:
		return branding.DefaultBackground(), nil
	}
	return branding.Image{}, ErrNotFound
}

// storedAsset returns the custom image of kind stored for t, and whether
// there is one: false when the tenant has no such image, or when its flag
// is set but the file is missing (the caller then acts as without flag).
func (s *Service) storedAsset(t *tenant.Tenant, kind branding.Kind) (branding.Image, bool, error) {
	if (kind == branding.KindLogo && !t.HasLogo) || (kind == branding.KindBackground && !t.HasBackground) {
		return branding.Image{}, false, nil
	}
	data, err := s.assets.Get(t.ID, kind)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return branding.Image{}, false, nil
	case err != nil:
		return branding.Image{}, false, fmt.Errorf("tenantadmin: read %s: %w", kind, err)
	}
	sum := sha256.Sum256(data)
	return branding.Image{
		Data: data, ContentType: kind.ContentType(), ETag: `"` + hex.EncodeToString(sum[:]) + `"`,
	}, true, nil
}

// setAssetFlag sets the flag of kind on t.
func setAssetFlag(t *tenant.Tenant, kind branding.Kind, on bool) {
	if kind == branding.KindLogo {
		t.HasLogo = on
		return
	}
	t.HasBackground = on
}

// changeTenant applies change to the active tenant tid after checking that
// p may change it, stores it and invalidates the resolver cache.
func (s *Service) changeTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, change func(*tenant.Tenant)) (*tenant.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.writable(ctx, p, tid)
	if err != nil {
		return nil, err
	}
	change(t)
	out, err := s.repo.updateTenant(ctx, t)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("tenantadmin: update tenant: %w", err)
	}
	s.invalidate(tid)
	return out, nil
}

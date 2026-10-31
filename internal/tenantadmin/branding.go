package tenantadmin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
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
	// BackgroundPreset is the background preset of the tenant, served when
	// HasBackground is false: never "", [branding.DefaultPresetID] for the
	// default (stored as NULL) or for a stale value unknown to this
	// version.
	BackgroundPreset string
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
		BackgroundPreset: presetOf(t), Contrast: branding.Check(primary, accent),
	}
}

// presetOf returns the background preset served for t: its stored preset
// when it is one of [branding.Presets], else [branding.DefaultPresetID]
// (NULL, or a stale value, is never an error).
func presetOf(t *tenant.Tenant) string {
	if branding.ValidPreset(t.BackgroundPreset) {
		return t.BackgroundPreset
	}
	return branding.DefaultPresetID
}

// storedPreset validates a requested background preset against the
// compiled library and returns the value to store: "" (NULL) for nil or
// [branding.DefaultPresetID], the identifier otherwise, and
// ErrUnknownBackgroundPreset for anything else, an empty string or a path
// included (threat model T-252).
func storedPreset(preset *string) (string, error) {
	switch {
	case preset == nil || *preset == branding.DefaultPresetID:
		return "", nil
	case branding.ValidPreset(*preset):
		return *preset, nil
	}
	return "", ErrUnknownBackgroundPreset
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

// SetBackgroundPreset chooses the background preset of tenant tid, served
// while the tenant has no uploaded background: nil or
// [branding.DefaultPresetID] resets it to the default (stored as NULL), an
// identifier outside [branding.Presets] is ErrUnknownBackgroundPreset.
// Access is checked first: the refusal on a tenant out of reach never
// depends on the preset. Audited as tenant.branding_updated with the
// served preset.
func (s *Service) SetBackgroundPreset(ctx context.Context, p adminauth.Principal, tid tenant.ID, preset *string, ip netip.Addr) (Branding, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return Branding{}, err
	}
	id, err := storedPreset(preset)
	if err != nil {
		return Branding{}, err
	}
	t, err := s.changeTenant(ctx, p, tid, func(t *tenant.Tenant) { t.BackgroundPreset = id })
	if err != nil {
		return Branding{}, err
	}
	b := brandingOf(t)
	s.record(ctx, p, ip, tid, ActionTenantBrandingUpdated, map[string]any{"backgroundPreset": b.BackgroundPreset})
	return b, nil
}

// ListBackgroundPresets returns the library of background presets in
// display order ([branding.DefaultPresetID] first), to any authenticated
// administrator.
func (s *Service) ListBackgroundPresets(_ context.Context, p adminauth.Principal) ([]branding.Preset, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return nil, err
	}
	return branding.Presets(), nil
}

// BackgroundPreset returns the image of the background preset id (JPEG,
// generated once and kept in memory, with a strong ETag) to any
// authenticated administrator; ErrNotFound for an identifier outside
// [branding.Presets].
func (s *Service) BackgroundPreset(_ context.Context, p adminauth.Principal, id string) (branding.Image, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return branding.Image{}, err
	}
	img, ok := branding.PresetBackground(id)
	if !ok {
		return branding.Image{}, ErrNotFound
	}
	return img, nil
}

// UploadAsset stores the logo or background image of tenant tid. asset is
// "logo" or "background" (else ErrNotFound). The image is decoded and
// re-encoded by [branding.Process]: ErrUnsupportedMediaType for a format
// other than PNG, JPEG or WebP (SVG included), ErrPayloadTooLarge above
// the limits, an *InvalidError for a corrupt image.
//
// A logo comes with the favicons generated from the re-encoded logo
// ([branding.GenerateFavicons], never from the uploaded bytes): a failed
// generation refuses the upload before anything is written, and the four
// files are written together, the previous ones being restored when one
// of the writes, or the update of the flag, fails (threat model T-249).
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
	files := []assetFile{{kind, img.Data}}
	if kind == branding.KindLogo {
		icons, err := s.favicons(ctx, img.Data)
		if err != nil {
			return fmt.Errorf("tenantadmin: generate favicons: %w", err)
		}
		for _, k := range branding.FaviconKinds() {
			icon, _ := icons.Get(k)
			files = append(files, assetFile{k, icon.Data})
		}
	}
	s.assetMu.Lock()
	defer s.assetMu.Unlock()
	restore, err := s.putAssets(tid, files)
	if err != nil {
		return err
	}
	// The flag is set once every file is written.
	if _, err := s.changeTenant(ctx, p, tid, func(t *tenant.Tenant) { setAssetFlag(t, kind, true) }); err != nil {
		restore()
		return err
	}
	s.record(ctx, p, ip, tid, ActionTenantAssetUploaded, map[string]any{
		"asset": kind.String(), "width": img.Width, "height": img.Height, "bytes": len(img.Data),
	})
	return nil
}

// assetFile is a branding image to write.
type assetFile struct {
	kind branding.Kind
	data []byte
}

// putAssets writes files for tenant tid, all or none: the previous content
// of each file is read first (a read failure writes nothing), and when a
// write fails the files already written are restored, or removed when
// there was none, before the error is returned. The returned restore
// function does the same after a later failure. The restoration is best
// effort: its own failures are logged, the files then being at worst those
// of the new upload, consistent with each other, behind an unchanged flag.
func (s *Service) putAssets(tid tenant.ID, files []assetFile) (restore func(), err error) {
	prev := make([][]byte, len(files))
	for i, f := range files {
		data, err := s.assets.Get(tid, f.kind)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf("tenantadmin: read %s: %w", f.kind, err)
		default:
			prev[i] = data
		}
	}
	written := 0
	restore = func() {
		for i := range written {
			f := files[i]
			var err error
			if prev[i] == nil {
				err = s.assets.Delete(tid, f.kind)
			} else {
				err = s.assets.Put(tid, f.kind, prev[i])
			}
			if err != nil {
				s.logger.Error("branding image restore failed", slog.String("tenant", string(tid)),
					slog.String("asset", f.kind.String()), slog.String("error", err.Error()))
			}
		}
	}
	for _, f := range files {
		if err := s.assets.Put(tid, f.kind, f.data); err != nil {
			restore()
			return nil, fmt.Errorf("tenantadmin: store %s: %w", f.kind, err)
		}
		written++
	}
	return restore, nil
}

// DeleteAsset removes the logo or background image of tenant tid: the
// default one is served again (the background preset for a background,
// the default favicons for a logo, whose generated favicons are removed
// with it). asset is "logo" or "background" (else ErrNotFound).
func (s *Service) DeleteAsset(ctx context.Context, p adminauth.Principal, tid tenant.ID, asset string, ip netip.Addr) error {
	kind, err := branding.ParseKind(asset)
	if err != nil {
		return ErrNotFound
	}
	s.assetMu.Lock()
	defer s.assetMu.Unlock()
	// The flag goes first: a failure afterwards leaves an unused file,
	// never a flag pointing to a missing one.
	if _, err := s.changeTenant(ctx, p, tid, func(t *tenant.Tenant) { setAssetFlag(t, kind, false) }); err != nil {
		return err
	}
	kinds := []branding.Kind{kind}
	if kind == branding.KindLogo {
		kinds = append(kinds, branding.FaviconKinds()...)
	}
	// Every file is attempted, so that one failure leaves as few unused
	// files as possible.
	var errs []error
	for _, k := range kinds {
		if err := s.assets.Delete(tid, k); err != nil {
			errs = append(errs, fmt.Errorf("tenantadmin: delete %s: %w", k, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
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

// Asset returns a branding image of tenant t for the public pages (asset
// is one of the names of [branding.ParseAsset]): the stored image; without
// one, the background of its preset ([branding.BackgroundFor], the default
// background for an unknown stored value) or the default favicon of the
// kind; ErrNotFound for a missing logo or an unknown asset name. The
// image is always one re-encoded or generated by the server, with its
// exact content type and a strong ETag. The favicons of a logo uploaded
// before TransTeira 1.2 are generated from it on first use
// ([Service.backfillFavicons]).
func (s *Service) Asset(ctx context.Context, t *tenant.Tenant, asset string) (branding.Image, error) {
	kind, err := branding.ParseAsset(asset)
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
		return branding.BackgroundFor(t.BackgroundPreset), nil
	case kind.IsFavicon():
		if t.HasLogo {
			if img, ok := s.backfillFavicons(ctx, t.ID, kind); ok {
				return img, nil
			}
		}
		img, _ = branding.DefaultFavicon(kind)
		return img, nil
	}
	return branding.Image{}, ErrNotFound
}

// backfillFavicons generates and stores the favicons of the logo of tenant
// tid when they are missing (a logo uploaded before TransTeira 1.2), and
// returns the one of kind. It works on the stored logo, re-encoded by the
// server, under the same decoding budget as an upload; false when there
// is no logo or on any failure (logged), the caller then serving the
// default favicon. Under assetMu, a concurrent upload or deletion either
// happened before (its files are used as they are) or waits.
func (s *Service) backfillFavicons(ctx context.Context, tid tenant.ID, kind branding.Kind) (branding.Image, bool) {
	s.assetMu.Lock()
	defer s.assetMu.Unlock()
	if data, err := s.assets.Get(tid, kind); err == nil {
		return imageOf(kind, data), true // written by a concurrent request
	}
	logo, err := s.assets.Get(tid, branding.KindLogo)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.logBackfill(tid, err)
		}
		return branding.Image{}, false
	}
	icons, err := s.favicons(ctx, logo)
	if err != nil {
		s.logBackfill(tid, err)
		return branding.Image{}, false
	}
	for _, k := range branding.FaviconKinds() {
		icon, _ := icons.Get(k)
		if err := s.assets.Put(tid, k, icon.Data); err != nil {
			// Served anyway: the next request tries to store it again.
			s.logBackfill(tid, err)
			break
		}
	}
	img, _ := icons.Get(kind)
	return img, true
}

// logBackfill logs a failed favicon backfill of tenant tid.
func (s *Service) logBackfill(tid tenant.ID, err error) {
	s.logger.Error("favicon backfill failed", slog.String("tenant", string(tid)), slog.String("error", err.Error()))
}

// storedAsset returns the custom image of kind stored for t, and whether
// there is one: false when the tenant has no such image (the favicons
// follow the logo flag), or when its flag is set but the file is missing
// (the caller then acts as without flag).
func (s *Service) storedAsset(t *tenant.Tenant, kind branding.Kind) (branding.Image, bool, error) {
	if (kind == branding.KindBackground && !t.HasBackground) || (kind != branding.KindBackground && !t.HasLogo) {
		return branding.Image{}, false, nil
	}
	data, err := s.assets.Get(t.ID, kind)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return branding.Image{}, false, nil
	case err != nil:
		return branding.Image{}, false, fmt.Errorf("tenantadmin: read %s: %w", kind, err)
	}
	return imageOf(kind, data), true, nil
}

// imageOf wraps stored data of kind with its content type and strong ETag.
func imageOf(kind branding.Kind, data []byte) branding.Image {
	sum := sha256.Sum256(data)
	return branding.Image{Data: data, ContentType: kind.ContentType(), ETag: `"` + hex.EncodeToString(sum[:]) + `"`}
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
	if t.BackgroundPreset != "" && !branding.ValidPreset(t.BackgroundPreset) {
		// A stored value outside the library is served as the default
		// (T-252): it is cleared rather than blocking every update.
		t.BackgroundPreset = ""
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

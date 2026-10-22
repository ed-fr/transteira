package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Fixed names of the branding assets of a tenant (<tenantID>/<name>.asset).
const (
	// AssetLogo is the re-encoded logo of the tenant.
	AssetLogo = "logo"
	// AssetBackground is the re-encoded background image of the tenant.
	AssetBackground = "background"
)

// MaxAssetSize bounds the size of a branding asset. The assets are images
// re-encoded by package branding (at most 512 px PNG logos and 3840 px
// JPEG backgrounds), far below this bound.
const MaxAssetSize = 32 << 20

// assetExt is the extension of a branding asset.
const assetExt = ".asset"

// validAsset reports whether name is one of the fixed asset names.
func validAsset(name string) bool {
	return name == AssetLogo || name == AssetBackground
}

// checkAsset validates the identifiers that make up an asset path.
func checkAsset(tid tenant.ID, name string) error {
	if tid.Validate() != nil {
		return fmt.Errorf("%w: tenant id", ErrInvalid)
	}
	if !validAsset(name) {
		return fmt.Errorf("%w: asset name", ErrInvalid)
	}
	return nil
}

// WriteAsset atomically replaces the branding asset name ([AssetLogo] or
// [AssetBackground]) of tenant tid with data, at most [MaxAssetSize] bytes,
// like [Store.WriteCheckpoint]. Any other name fails with ErrInvalid before
// the file system is touched. The data must already be re-encoded by the
// caller: the store never inspects it.
func (s *Store) WriteAsset(tid tenant.ID, name string, data []byte) error {
	if err := checkAsset(tid, name); err != nil {
		return err
	}
	return s.writeAtomicChecked("write asset", tid, name, assetExt, data, MaxAssetSize)
}

// ReadAsset returns the branding asset name of tenant tid. It fails with an
// error matching ErrNotFound and fs.ErrNotExist when the asset is missing,
// and with ErrInvalid for another name, a non regular file or an asset
// above MaxAssetSize.
func (s *Store) ReadAsset(tid tenant.ID, name string) ([]byte, error) {
	if err := checkAsset(tid, name); err != nil {
		return nil, err
	}
	data, _, err := s.readBoundedChecked("read asset", tid, name, assetExt, MaxAssetSize)
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("%w: %w", err, fs.ErrNotExist)
	}
	return data, err
}

// RemoveAsset deletes the branding asset name of tenant tid. A missing
// asset is not an error, so RemoveAsset is idempotent.
func (s *Store) RemoveAsset(tid tenant.ID, name string) error {
	if err := checkAsset(tid, name); err != nil {
		return err
	}
	return s.removeIfExists("remove asset", filepath.Join(string(tid), name+assetExt), name)
}

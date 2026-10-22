package storage

import (
	"fmt"
	"os"

	"github.com/ed-fr/transteira/internal/tenant"
)

// removeTree removes name and everything under it inside root; tests
// replace it to inject faults.
var removeTree = (*os.Root).RemoveAll

// RemoveTenantDir removes the directory of tenant tid with everything it
// holds (encrypted files, checkpoints, states, temporary files, branding
// assets), for the deletion of the tenant. A missing directory is not an
// error, so RemoveTenantDir is idempotent. The removal is confined to the
// data directory: a symbolic link in place of the directory, or inside it,
// is removed itself, never followed. Following threat model T-110, callers
// destroy every data key of the tenant in the database first.
func (s *Store) RemoveTenantDir(tid tenant.ID) error {
	if tid.Validate() != nil {
		return fmt.Errorf("%w: tenant id", ErrInvalid)
	}
	if err := removeTree(s.root, string(tid)); err != nil {
		return wrap("remove tenant directory", "", err)
	}
	return nil
}

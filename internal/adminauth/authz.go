package adminauth

import (
	"slices"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Authorization (threat T-63). Every operation of the administration
// checks the caller with one of these helpers, after [RequireAuthenticated]:
// the instance-wide operations with [RequireSuperAdmin], the tenant
// operations with [RequireTenantAccess] (reads) or [RequireTenantWrite]
// (changes). Unknown roles are denied everything: the V2 auditor role will
// be granted the reads only.

// RequireSuperAdmin returns ErrForbidden unless a is an active super
// admin.
func RequireSuperAdmin(a Account) error {
	if a.Role != store.RoleSuperAdmin || a.Disabled {
		return ErrForbidden
	}
	return nil
}

// CanAccessTenant reports whether a may read the data of tenant tid: a
// super admin reaches every tenant, a delegated admin the tenants it is
// attached to.
func CanAccessTenant(a Account, tid tenant.ID) bool {
	if a.Disabled || tid == "" {
		return false
	}
	switch a.Role {
	case store.RoleSuperAdmin:
		return true
	case store.RoleDelegatedAdmin:
		return slices.Contains(a.TenantIDs, tid)
	}
	return false
}

// RequireTenantAccess returns ErrNotFound unless a may read the data of
// tenant tid (see [CanAccessTenant]). A tenant the administrator is not
// attached to is answered exactly like a tenant that does not exist (404
// not-found, not 403), so that a delegated admin cannot probe the tenant
// IDs of the instance.
func RequireTenantAccess(a Account, tid tenant.ID) error {
	if !CanAccessTenant(a, tid) {
		return ErrNotFound
	}
	return nil
}

// RequireTenantWrite returns ErrNotFound unless a may change the data or
// configuration of tenant tid, like [RequireTenantAccess]. Today every
// role that reads a tenant may change it; a read-only role (V2 auditor)
// will fail here, with ErrForbidden since it may see the tenant.
func RequireTenantWrite(a Account, tid tenant.ID) error {
	return RequireTenantAccess(a, tid)
}

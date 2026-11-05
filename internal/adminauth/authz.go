package adminauth

import (
	"slices"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Authorization (threats T-63 and T-281). Every operation of the
// administration checks the caller with one of these helpers, after
// [RequireAuthenticated]:
//
//   - the instance-wide operations with [RequireSuperAdmin];
//   - the reads of a tenant's configuration with [RequireTenantAccess];
//   - the changes of a tenant with [RequireTenantWrite];
//   - the few reads open to the read-only auditor role (tenant summary,
//     audit log, security log, statistics, transfers) with
//     [RequireTenantAuditRead].
//
// The auditor is denied by default: [RequireTenantAccess] and
// [RequireTenantWrite] refuse it with ErrReadOnlyRole on its tenants, so
// that a new read only opens to it by calling [RequireTenantAuditRead]
// explicitly. Unknown roles are denied everything. The HTTP layer adds a
// second, independent lock: an auditor session may only call the
// operations of [AuditorOperations].

// RequireSuperAdmin returns ErrForbidden unless a is an active super
// admin.
func RequireSuperAdmin(a Account) error {
	if a.Role != store.RoleSuperAdmin || a.Disabled {
		return ErrForbidden
	}
	return nil
}

// CanAccessTenant reports whether a may see tenant tid at all: a super
// admin reaches every tenant, a delegated admin and an auditor the tenants
// they are attached to. It answers whether the tenant exists for a (list
// filtering, 404 versus 403), not what a may do on it.
func CanAccessTenant(a Account, tid tenant.ID) bool {
	if a.Disabled || tid == "" {
		return false
	}
	switch a.Role {
	case store.RoleSuperAdmin:
		return true
	case store.RoleDelegatedAdmin, store.RoleAuditor:
		return slices.Contains(a.TenantIDs, tid)
	}
	return false
}

// RequireTenantAccess returns nil if a may read the configuration of
// tenant tid: a super admin, or a delegated admin attached to it. A tenant
// the administrator is not attached to is answered exactly like a tenant
// that does not exist (ErrNotFound, 404 not-found, not 403), so that an
// administrator cannot probe the tenant IDs of the instance. An auditor
// attached to the tenant gets ErrReadOnlyRole: configuration reads are
// closed to it by default (T-281).
func RequireTenantAccess(a Account, tid tenant.ID) error {
	if !CanAccessTenant(a, tid) {
		return ErrNotFound
	}
	if a.Role == store.RoleAuditor {
		return ErrReadOnlyRole
	}
	return nil
}

// RequireTenantWrite returns nil if a may change the data or configuration
// of tenant tid, with the same answers as [RequireTenantAccess]:
// ErrNotFound outside the caller's tenants, ErrReadOnlyRole for an
// auditor attached to it.
func RequireTenantWrite(a Account, tid tenant.ID) error {
	return RequireTenantAccess(a, tid)
}

// RequireTenantAuditRead returns nil if a may call one of the reads open
// to the auditor role on tenant tid (tenant summary, audit log, security
// log, statistics, transfer list and metadata): a super admin, or a
// delegated admin or an auditor attached to it. It returns ErrNotFound
// otherwise. Only the operations of [AuditorOperations] call it.
func RequireTenantAuditRead(a Account, tid tenant.ID) error {
	if !CanAccessTenant(a, tid) {
		return ErrNotFound
	}
	return nil
}

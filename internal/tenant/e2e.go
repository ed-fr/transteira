package tenant

// E2EPolicy is the end-to-end encryption policy of a tenant or of a
// confidentiality level (OpenAPI E2ePolicy, since 2.0, spec 22): whether
// the senders may, must or must not encrypt their transfers in the browser.
// The tenant policy is set by the super admin only (database default
// E2EForbidden); a level may only tighten it ([EffectiveE2EPolicy]).
type E2EPolicy string

// End-to-end encryption policies.
const (
	// E2EForbidden refuses end-to-end encrypted transfers (the default).
	E2EForbidden E2EPolicy = "forbidden"
	// E2EAllowed lets each sender choose.
	E2EAllowed E2EPolicy = "allowed"
	// E2ERequired refuses the transfers that are not end-to-end encrypted:
	// a depositor that cannot encrypt (a drop link session) cannot deposit.
	E2ERequired E2EPolicy = "required"
)

// Valid reports whether p is a known policy ("" is not).
func (p E2EPolicy) Valid() bool {
	return p == E2EForbidden || p == E2EAllowed || p == E2ERequired
}

// EffectiveE2EPolicy returns the policy that applies to a transfer of a
// tenant whose policy is tenantPolicy, at a confidentiality level whose
// policy is levelPolicy (nil when the level follows the tenant, or when the
// transfer has no level). The tenant decides when it forbids or requires
// end-to-end encryption; when it allows it, the level decides. An unknown
// tenant policy (including "") is treated as E2EForbidden and an unknown
// level policy as following the tenant, so that a malformed value never
// loosens the rule. It is the single rule shared by the transfer creation
// and the public tenant features.
func EffectiveE2EPolicy(tenantPolicy E2EPolicy, levelPolicy *E2EPolicy) E2EPolicy {
	switch tenantPolicy {
	case E2ERequired:
		return E2ERequired
	case E2EAllowed:
		if levelPolicy != nil && levelPolicy.Valid() {
			return *levelPolicy
		}
		return E2EAllowed
	default:
		return E2EForbidden
	}
}

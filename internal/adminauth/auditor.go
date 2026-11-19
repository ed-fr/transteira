package adminauth

// AuditorOperations is the set of the OpenAPI operationIds an auditor
// session may call (P55, T-281): its own account (logout, profile,
// password, TOTP), the tenant list and summary, and the reads of its
// tenants: audit events, security events, statistics, transfers and their
// proof, the drop links, the secret list and lookup, and the transfer
// search by identifier. The HTTP layer refuses every other operation of an
// auditor session with 403 read-only-role before its handler runs; the
// services check again on their side ([RequireTenantAuditRead]). The
// login steps served without a session (setup status, login, second
// factor, activation, single sign-on, version) never carry an auditor
// session and need no entry.
//
// Opening an operation to the auditor takes both an entry here and a
// [RequireTenantAuditRead] call in its service. The map must not be
// changed at run time.
var AuditorOperations = map[string]bool{
	// Own account.
	"adminLogout":           true,
	"getAdminMe":            true,
	"changeAdminPassword":   true,
	"startTotpEnrollment":   true,
	"confirmTotpEnrollment": true,
	"disableTotp":           true,
	// Tenants, filtered to the attached ones.
	"listTenants": true,
	"getTenant":   true,
	// Reads of an attached tenant.
	"listTenantAuditEvents":    true,
	"listTenantSecurityEvents": true,
	"getTenantStats":           true,
	"listTenantTransfers":      true,
	"getTenantTransfer":        true,
	"getTenantTransferProof":   true,
	// The single sign-on configuration of an attached tenant (read only,
	// without its secret; since 2.0).
	"getTenantSso": true,
	// The permanent drop links of an attached tenant (read only, without
	// their tokens; since 2.0).
	"listDropLinks": true,
	"getDropLink":   true,
	// The one-time secrets of an attached tenant (metadata only, never the
	// content; the creator filter is refused to the auditor; since 2.1).
	"listTenantSecrets": true,
	// The lookup of a secret of an attached tenant from its link (metadata
	// only, never the content nor the token; a read despite its POST;
	// since 2.3). The purge of the express secrets stays refused.
	"lookupTenantSecret": true,
	// The transfer search across the attached tenants, by transfer
	// identifier only: the service refuses a query holding "@" to an
	// auditor (T-411; a read despite its POST; since 2.3).
	"searchTransfers": true,
}

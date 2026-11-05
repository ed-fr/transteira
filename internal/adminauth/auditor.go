package adminauth

// AuditorOperations is the set of the OpenAPI operationIds an auditor
// session may call (P55, T-281): its own account (logout, profile,
// password, TOTP), the tenant list and summary, and the reads of its
// tenants: audit events, security events, statistics, transfers and their
// proof. The HTTP layer refuses every other operation of an auditor
// session with 403 read-only-role before its handler runs; the services
// check again on their side ([RequireTenantAuditRead]). The login steps
// served without a session (setup status, login, second factor,
// activation, single sign-on, version) never carry an auditor session and
// need no entry.
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
}

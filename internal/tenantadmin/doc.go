// Package tenantadmin is the configuration service of the tenants (CLAUDE.md
// sections 5, 6.5, 12, 13 and 20): creation and deletion of a tenant by the
// super admin, general settings, branding, internal network rules, SMTP
// settings with their test and DNS check, mail templates and legal
// documents, plus the public reads of the branding images and legal
// documents.
//
// # Authorization (threats T-63, T-64)
//
// Every administration method takes the [adminauth.Principal] of the
// caller and checks it first: an authenticated session
// ([adminauth.RequireAuthenticated]), then [adminauth.RequireSuperAdmin]
// for the instance-wide operations (create and delete a tenant) or
// [adminauth.RequireTenantAccess] / [adminauth.RequireTenantWrite] for the
// operations of one tenant. A tenant the caller is not attached to, and a
// tenant being deleted, are answered exactly like a missing tenant
// ([ErrNotFound]). A delegated admin may change the default language and
// lower the transfer limit under the ceiling set by the super admin; any
// other change of the general settings is [ErrForbidden].
//
// # Audit
//
// Every change writes an audit event (tenant.created, tenant.updated with
// the names of the changed fields, tenant.deletion_started (the eraser
// records tenant.deleted once the data is gone), tenant.branding_updated,
// tenant.asset_uploaded, tenant.asset_deleted, tenant.network_updated,
// tenant.smtp_updated, tenant.smtp_tested, tenant.template_updated,
// tenant.template_reset, tenant.legal_updated). The actor is the username
// of the administrator, as in package adminauth. No event holds a secret:
// the SMTP password never leaves the vault, and an event only tells that
// the credentials changed.
//
// # SMTP and SSRF (P21)
//
// A tenant SMTP host given as an IP literal inside the denied networks
// (TT_SMTP_DENY_NETWORKS) is refused when saved. Host names are checked
// when connecting: [netpolicy.DialGuard] resolves the name, refuses the
// connection if any resolved address is denied, and dials the checked
// address itself, so that a DNS answer changed between the check and the
// connection (DNS rebinding) cannot reach a denied address. The mail sender
// of the application must dial through [netpolicy.DialGuard.DialContext].
package tenantadmin

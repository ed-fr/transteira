// Package adminauth authenticates the administrators of TransTeira and
// manages their accounts (CLAUDE.md sections 6.5, 6.6, 16.2 and 21.1). It
// is a critical package: its tests cover every statement.
//
// # First run
//
// While no administrator exists, [Service.CreateSuperAdmin] creates the
// super admin, given the setup token of the deployment (compared in
// constant time), in one transaction holding the administrators lock. It
// returns a session in state totp_enrollment_required with the TOTP secret
// to confirm: nothing else is usable before the confirmation.
//
// # Login
//
// [Service.Login] checks the password (argon2id, bounded concurrency). The
// attempt is counted before the verification, on two limits kept in the
// database: 5 failures per (username, IP) and 20 per IP within 15 minutes
// lock for 15 minutes; there is no lock per username alone, which would let
// anyone lock the super admin out. An unknown username, a disabled account
// or one without a password is verified against a fixed hash, for the same
// work and the same answer (T-65). A password never grants a full session
// when TOTP is enrolled or required, which it always is for a super admin:
// the session is then in an intermediate state (5 minutes) that only opens
// the next step, [Service.VerifyTOTP] or the enrollment.
//
// [Service.VerifyTOTP] accepts a TOTP code (RFC 6238, ±1 step, each step
// once: T-60) or a single-use recovery code. Wrong second factors are
// counted per administrator (5 within 15 minutes, from any IP) and per IP,
// and 5 of them end the session. Each step rotates the session token
// (session fixation, T-59).
//
// # Sessions
//
// The session token ("as_" + 256 bits, the __Host-tt_admin cookie) is
// stored as its SHA-256 only. A session ends after an idle timeout
// (30 minutes by default, sliding) and a maximum age (12 hours by
// default). [Service.Resolve] returns the session of a request and its
// account; the CSRF token is a MAC of the session token under the
// admin-csrf key of the current master key ([Service.CheckCSRF]): after a
// master key rotation the client fetches it again. Sessions are revoked
// at logout, at a password change, a TOTP re-enrollment or a TOTP
// disabling (the others), and when an account is disabled, changes role
// or tenants, or has its credentials reset. Re-enrolling TOTP needs the
// current password.
//
// # Accounts
//
// Only a super admin manages accounts ([RequireSuperAdmin]). A delegated
// admin is created attached to at least one tenant with an activation link
// valid 72 hours, which is never mailed: [Service.Create] and
// [Service.ResetCredentials] return it once, and the super admin hands it
// over out of band. [Service.Activate] sets the password and opens a
// session, which must enroll TOTP when it is required (the default). Only
// an activated account with TOTP enabled can be promoted to super admin.
// The last usable super admin (not disabled, password set, TOTP enabled)
// can be neither deleted, nor disabled, nor demoted, nor reset, and nobody
// can delete, disable, demote or reset their own account. Inside the
// container, [Service.ResetTOTPLocal] and [Service.ResetPasswordLocal]
// (transteira admin reset-totp and reset-password) recover a locked-out
// account, the last super admin included.
//
// [RequireTenantAccess] and [RequireTenantWrite] guard the tenant
// operations: a super admin reaches every tenant, a delegated admin its own
// tenants only, any other tenant being answered as missing (404); unknown
// roles are denied, so that the read-only auditor of V2 fits in.
//
// # Secrets and logs
//
// TOTP secrets are sealed by the master key (purpose admin-totp) through
// the [Vault]; recovery codes are stored as HMAC-SHA256 values keyed by the
// TOTP secret in use (crypto.RecoveryCodeMAC), so that they survive a
// master key rotation. Every failure writes an admin_login_failed security
// event (reason password, totp, recovery_code or setup_token) and every
// lock a rate_limited one (scope admin_login). The failed logins of an
// unknown username are audited under the actor "unknown", never under the
// typed name.
// Every account change and login is written to the audit log, inside the
// transaction of the change when there is one. No password, token, TOTP
// secret or code is ever logged; operational logs name an account by its
// ID only.
package adminauth

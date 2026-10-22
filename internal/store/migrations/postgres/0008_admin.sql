-- 0008_admin (PostgreSQL): administrator accounts, sessions, recovery
-- codes, activation links, login failure counters, system secrets and the
-- audit log (spec 6.5, 6.6, 16 and 21.1). Keep in sync with
-- migrations/sqlite/0008_admin.sql. Timestamps are Unix milliseconds (UTC).
-- Conventions of 0001_init: "C" collation on identifiers, row-level
-- security ENABLE + FORCE.
--
-- Every table but admin_tenants and audit_events is a system table, without
-- tenant_id: an administrator is not owned by a tenant. The policies only
-- open them to the system scope, so a tenant-scoped transaction can neither
-- read nor write them. audit_events is readable and appendable by a
-- tenant-scoped transaction for its own tenant's rows only: only the system
-- scope (the 12-month purge) may update or delete an audit event.

-- Secrets sealed by the master key that belong to no tenant: the TOTP
-- secrets of the administrators (purpose 'admin-totp'). Same columns as
-- wrapped_keys minus tenant_id; the master key rotation rewraps them too.
-- Deleting a row is the cryptographic erasure of the secret (dead tuples
-- remain until VACUUM, threat model T-109).
CREATE TABLE system_secrets (
    id         TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    purpose    TEXT   NOT NULL CHECK (purpose IN ('admin-totp')),
    key_id     TEXT   COLLATE "C" NOT NULL,
    blob       BYTEA  NOT NULL,
    created_at BIGINT NOT NULL
);

-- Rotation scans the secrets still sealed under the old master key.
CREATE INDEX system_secrets_key_id_idx ON system_secrets (key_id, id);

-- A retired master key never seals anything again: the trigger function of
-- migration 0002 applies as is (it only reads NEW.key_id).
CREATE TRIGGER system_secrets_reject_retired BEFORE INSERT OR UPDATE OF key_id ON system_secrets
    FOR EACH ROW EXECUTE FUNCTION wrapped_keys_reject_retired();

-- Administrator accounts. username is stored normalized (lower case) by the
-- store, so the unique constraint is case-insensitive. password_hash (PHC
-- string) is NULL until the account is activated. The TOTP secrets are
-- system_secrets rows, deleted by the store with the account; the active
-- one is used once totp_enabled, the pending one during enrollment.
-- totp_last_counter is the last accepted TOTP time step (replay refusal,
-- T-60). role is extensible (V2 'auditor') with a migration of the check.
-- A super admin always requires TOTP.
CREATE TABLE admins (
    id                     TEXT    COLLATE "C" NOT NULL PRIMARY KEY,
    username               TEXT    COLLATE "C" NOT NULL UNIQUE,
    email                  TEXT    NOT NULL,
    role                   TEXT    NOT NULL CHECK (role IN ('super_admin', 'delegated_admin')),
    password_hash          TEXT,
    totp_secret_id         TEXT    COLLATE "C" REFERENCES system_secrets (id),
    totp_enabled           BOOLEAN NOT NULL DEFAULT false,
    totp_last_counter      BIGINT,
    pending_totp_secret_id TEXT    COLLATE "C" REFERENCES system_secrets (id),
    require_totp           BOOLEAN NOT NULL DEFAULT true,
    disabled               BOOLEAN NOT NULL DEFAULT false,
    language               TEXT,
    created_at             BIGINT  NOT NULL,
    updated_at             BIGINT  NOT NULL,
    last_login_at          BIGINT,
    credentials_changed_at BIGINT,
    CHECK (NOT totp_enabled OR totp_secret_id IS NOT NULL),
    CHECK (role <> 'super_admin' OR require_totp)
);

-- Super admin count (last super admin rule).
CREATE INDEX admins_role_idx ON admins (role, disabled);

-- Tenants a delegated admin is attached to. Deleting the admin or the
-- tenant removes the attachment.
CREATE TABLE admin_tenants (
    admin_id  TEXT COLLATE "C" NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    tenant_id TEXT COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    PRIMARY KEY (admin_id, tenant_id)
);

CREATE INDEX admin_tenants_tenant_id_idx ON admin_tenants (tenant_id, admin_id);

-- Administrator sessions. Only the SHA-256 of the cookie token is stored.
-- A session is valid while expires_at (absolute end) and, for the
-- intermediate states, state_expires_at are in the future and its last use
-- (last_seen_at) is within the idle timeout given by the caller.
CREATE TABLE admin_sessions (
    id               TEXT    COLLATE "C" NOT NULL PRIMARY KEY,
    token_hash       BYTEA   NOT NULL UNIQUE,
    admin_id         TEXT    COLLATE "C" NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    state            TEXT    NOT NULL CHECK (state IN ('totp_required', 'totp_enrollment_required', 'authenticated')),
    created_at       BIGINT  NOT NULL,
    last_seen_at     BIGINT  NOT NULL,
    expires_at       BIGINT  NOT NULL,
    state_expires_at BIGINT,
    totp_failures    INTEGER NOT NULL DEFAULT 0 CHECK (totp_failures >= 0),
    client_ip        TEXT,
    CHECK (expires_at > created_at),
    CHECK ((state = 'authenticated') = (state_expires_at IS NULL))
);

CREATE INDEX admin_sessions_admin_idx ON admin_sessions (admin_id);
-- Purge of the expired sessions.
CREATE INDEX admin_sessions_expires_idx ON admin_sessions (expires_at);

-- Single-use TOTP recovery codes, stored as HMAC-SHA256 values keyed by a
-- key derived from the TOTP secret of the administrator (purpose
-- admin-recovery, internal/crypto RecoveryCodeMAC): a stolen database alone
-- cannot test guesses offline. used_at is set when a code is consumed.
CREATE TABLE admin_recovery_codes (
    admin_id  TEXT   COLLATE "C" NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    code_hash BYTEA  NOT NULL,
    used_at   BIGINT,
    PRIMARY KEY (admin_id, code_hash)
);

-- Single-use activation links of new or reset accounts. Only the SHA-256 of
-- the link token is stored.
CREATE TABLE admin_activations (
    id         TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    admin_id   TEXT   COLLATE "C" NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    token_hash BYTEA  NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at    BIGINT,
    CHECK (expires_at > created_at)
);

CREATE INDEX admin_activations_admin_idx ON admin_activations (admin_id);
CREATE INDEX admin_activations_expires_idx ON admin_activations (expires_at);

-- Failed admin logins, counted per scope: 'user_ip' (key = hex SHA-256 of
-- the normalized username and the client IP key, so that no username is
-- stored next to an IP) and 'ip' (key = the client IP key: an IPv4 address,
-- or the /64 prefix of an IPv6 address) and 'admin_totp' (key = the
-- administrator ID: the wrong second factors of one administrator, from any
-- IP). failures lists the times of the
-- latest failures, oldest first, as comma-separated Unix milliseconds (at
-- most 20, enforced by the store): a true sliding window for any limit up
-- to 20. last_failure_at (the latest of them) drives the purge.
CREATE TABLE admin_login_failures (
    scope           TEXT   NOT NULL CHECK (scope IN ('user_ip', 'ip', 'admin_totp')),
    key             TEXT   COLLATE "C" NOT NULL CHECK (key <> ''),
    failures        TEXT   NOT NULL,
    last_failure_at BIGINT,
    locked_until    BIGINT,
    PRIMARY KEY (scope, key)
);

CREATE INDEX admin_login_failures_last_idx ON admin_login_failures (last_failure_at);

-- Audit log (spec 21.1), append-only. tenant_id is NULL for a global event
-- (setup, admin management, maintenance, key rotation). It is deliberately
-- not a foreign key: the events of a deleted tenant stay in the log, with
-- their tenant, until the 12-month purge; no delegated admin can read them
-- any more (attachments are deleted with the tenant), only the super admin.
-- details is a bounded JSON object.
CREATE TABLE audit_events (
    id          TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    at          BIGINT NOT NULL,
    tenant_id   TEXT   COLLATE "C",
    actor_kind  TEXT   NOT NULL,
    actor       TEXT   NOT NULL,
    ip          TEXT,
    action      TEXT   NOT NULL,
    object_kind TEXT   NOT NULL,
    object_id   TEXT   NOT NULL,
    details     TEXT
);

CREATE INDEX audit_events_tenant_at_idx ON audit_events (tenant_id, at, id);
CREATE INDEX audit_events_at_idx ON audit_events (at, id);

-- System tables: system scope only.
ALTER TABLE system_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY system_secrets_system ON system_secrets
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

ALTER TABLE admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE admins FORCE ROW LEVEL SECURITY;
CREATE POLICY admins_system ON admins
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

-- admin_tenants carries a tenant_id, but the attachments are administration
-- data: a tenant-scoped transaction must not see who administers it.
ALTER TABLE admin_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_tenants_system ON admin_tenants
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

ALTER TABLE admin_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_sessions_system ON admin_sessions
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

ALTER TABLE admin_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_recovery_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_recovery_codes_system ON admin_recovery_codes
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

ALTER TABLE admin_activations ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_activations FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_activations_system ON admin_activations
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

ALTER TABLE admin_login_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_login_failures FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_login_failures_system ON admin_login_failures
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

-- Audit log: a tenant-scoped transaction reads and appends its own tenant's
-- events only (never the global ones, whose tenant_id is NULL); it can
-- neither update nor delete any event, even its own (append-only). The
-- system scope sees everything and alone updates or deletes (the 12-month
-- purge). Permissive policies are OR-ed per command, so SELECT and INSERT
-- get both a tenant and a system policy, UPDATE and DELETE the system one
-- only.
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_system ON audit_events
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');
CREATE POLICY audit_events_tenant_select ON audit_events FOR SELECT
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY audit_events_tenant_insert ON audit_events FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

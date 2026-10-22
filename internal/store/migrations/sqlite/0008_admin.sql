-- 0008_admin (SQLite): administrator accounts, sessions, recovery codes,
-- activation links, login failure counters, system secrets and the audit
-- log (spec 6.5, 6.6, 16 and 21.1). Keep in sync with
-- migrations/postgres/0008_admin.sql. Timestamps are Unix milliseconds
-- (UTC).
--
-- Every table but admin_tenants and audit_events is a system table, without
-- tenant_id: an administrator is not owned by a tenant. The store reaches
-- them through system queries only.

-- Secrets sealed by the master key that belong to no tenant: the TOTP
-- secrets of the administrators (purpose 'admin-totp'). Same columns as
-- wrapped_keys minus tenant_id; the master key rotation rewraps them too.
-- Deleting a row is the cryptographic erasure of the secret.
CREATE TABLE system_secrets (
    id         TEXT    NOT NULL PRIMARY KEY,
    purpose    TEXT    NOT NULL CHECK (purpose IN ('admin-totp')),
    key_id     TEXT    NOT NULL,
    blob       BLOB    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- Rotation scans the secrets still sealed under the old master key.
CREATE INDEX system_secrets_key_id_idx ON system_secrets (key_id, id);

-- A retired master key never seals anything again (same rule and message
-- as wrapped_keys, migration 0002).
CREATE TRIGGER system_secrets_reject_retired_insert BEFORE INSERT ON system_secrets
WHEN EXISTS (SELECT 1 FROM master_keys WHERE id = NEW.key_id AND status = 'retired')
BEGIN
    SELECT RAISE(ABORT, 'transteira: master key is retired');
END;

CREATE TRIGGER system_secrets_reject_retired_update BEFORE UPDATE OF key_id ON system_secrets
WHEN EXISTS (SELECT 1 FROM master_keys WHERE id = NEW.key_id AND status = 'retired')
BEGIN
    SELECT RAISE(ABORT, 'transteira: master key is retired');
END;

-- Administrator accounts. username is stored normalized (lower case) by the
-- store, so the unique constraint is case-insensitive. password_hash (PHC
-- string) is NULL until the account is activated. The TOTP secrets are
-- system_secrets rows, deleted by the store with the account; the active
-- one is used once totp_enabled, the pending one during enrollment.
-- totp_last_counter is the last accepted TOTP time step (replay refusal,
-- T-60). role is extensible (V2 'auditor') with a migration of the check.
-- A super admin always requires TOTP.
CREATE TABLE admins (
    id                     TEXT    NOT NULL PRIMARY KEY,
    username               TEXT    NOT NULL UNIQUE,
    email                  TEXT    NOT NULL,
    role                   TEXT    NOT NULL CHECK (role IN ('super_admin', 'delegated_admin')),
    password_hash          TEXT,
    totp_secret_id         TEXT    REFERENCES system_secrets (id),
    totp_enabled           INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1)),
    totp_last_counter      INTEGER,
    pending_totp_secret_id TEXT    REFERENCES system_secrets (id),
    require_totp           INTEGER NOT NULL DEFAULT 1 CHECK (require_totp IN (0, 1)),
    disabled               INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    language               TEXT,
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    last_login_at          INTEGER,
    credentials_changed_at INTEGER,
    CHECK (totp_enabled = 0 OR totp_secret_id IS NOT NULL),
    CHECK (role <> 'super_admin' OR require_totp = 1)
) STRICT;

-- Super admin count (last super admin rule).
CREATE INDEX admins_role_idx ON admins (role, disabled);

-- Tenants a delegated admin is attached to. Deleting the admin or the
-- tenant removes the attachment.
CREATE TABLE admin_tenants (
    admin_id  TEXT NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    PRIMARY KEY (admin_id, tenant_id)
) STRICT;

CREATE INDEX admin_tenants_tenant_id_idx ON admin_tenants (tenant_id, admin_id);

-- Administrator sessions. Only the SHA-256 of the cookie token is stored.
-- A session is valid while expires_at (absolute end) and, for the
-- intermediate states, state_expires_at are in the future and its last use
-- (last_seen_at) is within the idle timeout given by the caller.
CREATE TABLE admin_sessions (
    id               TEXT    NOT NULL PRIMARY KEY,
    token_hash       BLOB    NOT NULL UNIQUE,
    admin_id         TEXT    NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    state            TEXT    NOT NULL CHECK (state IN ('totp_required', 'totp_enrollment_required', 'authenticated')),
    created_at       INTEGER NOT NULL,
    last_seen_at     INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    state_expires_at INTEGER,
    totp_failures    INTEGER NOT NULL DEFAULT 0 CHECK (totp_failures >= 0),
    client_ip        TEXT,
    CHECK (expires_at > created_at),
    CHECK ((state = 'authenticated') = (state_expires_at IS NULL))
) STRICT;

CREATE INDEX admin_sessions_admin_idx ON admin_sessions (admin_id);
-- Purge of the expired sessions.
CREATE INDEX admin_sessions_expires_idx ON admin_sessions (expires_at);

-- Single-use TOTP recovery codes, stored as HMAC-SHA256 values keyed by a
-- key derived from the TOTP secret of the administrator (purpose
-- admin-recovery, internal/crypto RecoveryCodeMAC): a stolen database alone
-- cannot test guesses offline. used_at is set when a code is consumed.
CREATE TABLE admin_recovery_codes (
    admin_id  TEXT    NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    code_hash BLOB    NOT NULL,
    used_at   INTEGER,
    PRIMARY KEY (admin_id, code_hash)
) STRICT;

-- Single-use activation links of new or reset accounts. Only the SHA-256 of
-- the link token is stored.
CREATE TABLE admin_activations (
    id         TEXT    NOT NULL PRIMARY KEY,
    admin_id   TEXT    NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    token_hash BLOB    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    CHECK (expires_at > created_at)
) STRICT;

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
    scope           TEXT    NOT NULL CHECK (scope IN ('user_ip', 'ip', 'admin_totp')),
    key             TEXT    NOT NULL CHECK (key <> ''),
    failures        TEXT    NOT NULL,
    last_failure_at INTEGER,
    locked_until    INTEGER,
    PRIMARY KEY (scope, key)
) STRICT;

CREATE INDEX admin_login_failures_last_idx ON admin_login_failures (last_failure_at);

-- Audit log (spec 21.1), append-only. tenant_id is NULL for a global event
-- (setup, admin management, maintenance, key rotation). It is deliberately
-- not a foreign key: the events of a deleted tenant stay in the log, with
-- their tenant, until the 12-month purge; no delegated admin can read them
-- any more (attachments are deleted with the tenant), only the super admin.
-- details is a bounded JSON object.
CREATE TABLE audit_events (
    id          TEXT    NOT NULL PRIMARY KEY,
    at          INTEGER NOT NULL,
    tenant_id   TEXT,
    actor_kind  TEXT    NOT NULL,
    actor       TEXT    NOT NULL,
    ip          TEXT,
    action      TEXT    NOT NULL,
    object_kind TEXT    NOT NULL,
    object_id   TEXT    NOT NULL,
    details     TEXT
) STRICT;

CREATE INDEX audit_events_tenant_at_idx ON audit_events (tenant_id, at, id);
CREATE INDEX audit_events_at_idx ON audit_events (at, id);

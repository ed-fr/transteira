-- 0026_auditor (SQLite): the read-only auditor role and the security events
-- kept in the database (V2, feature F1). Keep in sync with
-- migrations/postgres/0026_auditor.sql. Timestamps are Unix milliseconds
-- (UTC). See docs/architecture/data-model-v2.md, section 2.1.
--
-- admins.role gains 'auditor'. SQLite cannot change a check in place, so
-- admins is rebuilt (create, copy, drop, rename). admins is referenced by
-- admin_tenants, admin_sessions, admin_recovery_codes and
-- admin_activations: the migrator runs every SQLite migration with foreign
-- keys disabled (store/migrate.go, data-model-v1.1.md section 2.1), so that
-- dropping the old table neither cascades to the children nor fails, and
-- checks PRAGMA foreign_key_check before committing. The children keep
-- their "REFERENCES admins" clause, which resolves to the new table once
-- renamed. The only index of admins (admins_role_idx) is recreated; no
-- trigger or view references admins.
--
-- sso_only marks an account created without a local password (delivery
-- "none"): it can only sign in through single sign-on. Existing rows get 0.
-- The checks forbid a password on such an account and forbid it for a
-- super admin (whose local account with TOTP is the break-glass access).
--
-- An auditor is attached to tenants through admin_tenants, like a delegated
-- admin, and has require_totp = 1 by default (not forced: only a super
-- admin must always require TOTP).
CREATE TABLE admins_0026 (
    id                     TEXT    NOT NULL PRIMARY KEY,
    username               TEXT    NOT NULL UNIQUE,
    email                  TEXT    NOT NULL,
    role                   TEXT    NOT NULL CHECK (role IN ('super_admin', 'delegated_admin', 'auditor')),
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
    sso_only               INTEGER NOT NULL DEFAULT 0 CHECK (sso_only IN (0, 1)),
    CHECK (totp_enabled = 0 OR totp_secret_id IS NOT NULL),
    CHECK (role <> 'super_admin' OR require_totp = 1),
    CHECK (sso_only = 0 OR password_hash IS NULL),
    CHECK (sso_only = 0 OR role <> 'super_admin')
) STRICT;

INSERT INTO admins_0026 (id, username, email, role, password_hash, totp_secret_id, totp_enabled,
    totp_last_counter, pending_totp_secret_id, require_totp, disabled, language, created_at, updated_at,
    last_login_at, credentials_changed_at, sso_only)
SELECT id, username, email, role, password_hash, totp_secret_id, totp_enabled,
    totp_last_counter, pending_totp_secret_id, require_totp, disabled, language, created_at, updated_at,
    last_login_at, credentials_changed_at, 0
FROM admins;

DROP TABLE admins;
ALTER TABLE admins_0026 RENAME TO admins;

CREATE INDEX admins_role_idx ON admins (role, disabled);

-- Security events (spec 16.3), mirror of every line the security log
-- writer emits, so that a delegated admin or an auditor can read the
-- security log of a tenant without shell access. The file log and its
-- format (fail2ban, CrowdSec) are unchanged. id is "sev_" + ULID (cursor
-- pagination on (at, id), like audit_events). tenant_id is NULL for an
-- event bound to no tenant (unknown FQDN, admin host); like audit_events it
-- is not a foreign key, so the events of a deleted tenant stay until the
-- 12-month purge. event_type is the stable security log event type; the
-- set is owned by the code (internal/securitylog), so a new type needs no
-- migration. reason is the reason field of the line, when there is one;
-- details is a bounded JSON object of the other fields (scope, purpose,
-- host). ip is the real client IP, NULL when unknown. No e-mail address is
-- ever stored here (the file log never carries one either). Rows are
-- written by an asynchronous bounded queue that coalesces identical events
-- (same type, reason, IP and tenant within a window, brief amendment A3):
-- at is the first occurrence, last_seen_at the last one and occurrences
-- their number. The file log keeps one line per event.
CREATE TABLE security_events (
    id           TEXT    NOT NULL PRIMARY KEY,
    at           INTEGER NOT NULL,
    tenant_id    TEXT,
    event_type   TEXT    NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
    reason       TEXT    CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 64),
    ip           TEXT    CHECK (ip IS NULL OR length(ip) BETWEEN 2 AND 64),
    details      TEXT    CHECK (details IS NULL OR octet_length(details) <= 2048),
    occurrences  INTEGER NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
    last_seen_at INTEGER NOT NULL,
    CHECK (last_seen_at >= at)
) STRICT;

-- Tenant listing (delegated admin, auditor) and super admin listing, newest
-- first; the global index also drives the 12-month purge.
CREATE INDEX security_events_tenant_at_idx ON security_events (tenant_id, at, id);
CREATE INDEX security_events_at_idx ON security_events (at, id);

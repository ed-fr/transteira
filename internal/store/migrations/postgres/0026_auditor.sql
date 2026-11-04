-- 0026_auditor (PostgreSQL): the read-only auditor role and the security
-- events kept in the database (V2, feature F1). Keep in sync with
-- migrations/sqlite/0026_auditor.sql, which documents the columns.
-- Timestamps are Unix milliseconds (UTC). Conventions of 0001_init: "C"
-- collation on identifiers, row-level security ENABLE + FORCE. See
-- docs/architecture/data-model-v2.md, section 2.1.
--
-- admins is altered in place: its row-level security and its policy
-- admins_system (0008) are kept. The role check is the column check of
-- 0008, named admins_role_check by PostgreSQL.
ALTER TABLE admins
    DROP CONSTRAINT admins_role_check,
    ADD CONSTRAINT admins_role_check CHECK (role IN ('super_admin', 'delegated_admin', 'auditor'));

-- sso_only marks an account created without a local password (delivery
-- "none"): it can only sign in through single sign-on. Existing rows get
-- false. Same checks as the SQLite migration.
ALTER TABLE admins
    ADD COLUMN sso_only BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT admins_sso_only_no_password_check CHECK (NOT sso_only OR password_hash IS NULL),
    ADD CONSTRAINT admins_sso_only_not_super_check CHECK (NOT sso_only OR role <> 'super_admin');

CREATE TABLE security_events (
    id           TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    at           BIGINT NOT NULL,
    tenant_id    TEXT   COLLATE "C",
    event_type   TEXT   COLLATE "C" NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
    reason       TEXT   COLLATE "C" CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 64),
    ip           TEXT   CHECK (ip IS NULL OR length(ip) BETWEEN 2 AND 64),
    details      TEXT    CHECK (details IS NULL OR octet_length(details) <= 2048),
    occurrences  INTEGER NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
    last_seen_at BIGINT  NOT NULL,
    CHECK (last_seen_at >= at)
);

CREATE INDEX security_events_tenant_at_idx ON security_events (tenant_id, at, id);
CREATE INDEX security_events_at_idx ON security_events (at, id);

-- A tenant-scoped transaction reads its own tenant's events only (never the
-- tenant-less ones). Events are written by the security log writer in the
-- system scope (most of them happen before or outside any tenant scope),
-- and only the system scope updates or deletes them (the 12-month purge):
-- unlike audit_events, there is no tenant INSERT policy.
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events FORCE ROW LEVEL SECURITY;
CREATE POLICY security_events_system ON security_events
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');
CREATE POLICY security_events_tenant_select ON security_events FOR SELECT
    USING (tenant_id = current_setting('app.tenant_id', true));

-- 0001_init (PostgreSQL): tenants, internal network rules and blocklist.
-- Keep in sync with migrations/sqlite/0001_init.sql (same tables, columns
-- and constraints). Timestamps are Unix milliseconds (UTC). Every
-- tenant-scoped table carries tenant_id and an index starting with it.
--
-- Row-level security is the second isolation layer (spec 5 and 17). The
-- application sets, local to each transaction:
--   app.tenant_id    = the tenant of a scoped transaction;
--   app.system_scope = 'on' for a system transaction (tenant administration,
--                      host resolution, maintenance tasks).
-- Identifier columns use the "C" collation: byte order, like SQLite, so that
-- cursor pagination ("id > ?" ... ORDER BY id) behaves the same on both
-- engines.
--
-- Two roles (TT_DB_MIGRATE_DSN and TT_DB_DSN): these migrations run as the
-- owner role, which owns every object. The application connects as a
-- separate runtime role that owns nothing and receives, after each
-- migration run, USAGE on the schema and SELECT/INSERT/UPDATE/DELETE on the
-- tables (SELECT only on schema_migrations), so it can neither alter nor
-- drop the policies; the application refuses to start otherwise. FORCE
-- additionally makes the policies apply to the owner role.

CREATE TABLE tenants (
    id                  TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    name                TEXT   NOT NULL,
    fqdn                TEXT   NOT NULL UNIQUE,
    default_language    TEXT   NOT NULL,
    max_transfer_bytes  BIGINT NOT NULL CHECK (max_transfer_bytes > 0),
    storage_quota_bytes BIGINT NOT NULL CHECK (storage_quota_bytes > 0),
    created_at          BIGINT NOT NULL,
    updated_at          BIGINT NOT NULL
);

-- Internal IP ranges (kind 'cidr') and internal mail domains (kind 'domain')
-- of a tenant (spec 6.2). The primary key doubles as the tenant_id index.
CREATE TABLE tenant_network_rules (
    tenant_id TEXT COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind      TEXT NOT NULL CHECK (kind IN ('cidr', 'domain')),
    value     TEXT NOT NULL,
    PRIMARY KEY (tenant_id, kind, value)
);

-- Blocked addresses, domains and file fingerprints of a tenant (spec 15.2).
CREATE TABLE blocklist_entries (
    id         TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id  TEXT   COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind       TEXT   NOT NULL CHECK (kind IN ('email', 'domain', 'sha256')),
    value      TEXT   NOT NULL,
    comment    TEXT   NOT NULL DEFAULT '',
    created_by TEXT   NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    UNIQUE (tenant_id, kind, value)
);

-- Cursor pagination of a tenant's entries (ordered by id).
CREATE INDEX blocklist_entries_tenant_id_idx ON blocklist_entries (tenant_id, id);

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
-- A tenant-scoped transaction may only read its own tenant row; creating,
-- modifying and deleting tenants is reserved to the system scope.
CREATE POLICY tenants_read_own ON tenants FOR SELECT
    USING (id = current_setting('app.tenant_id', true));
CREATE POLICY tenants_system ON tenants
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

ALTER TABLE tenant_network_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_network_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_network_rules_isolation ON tenant_network_rules
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

ALTER TABLE blocklist_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE blocklist_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY blocklist_entries_isolation ON blocklist_entries
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

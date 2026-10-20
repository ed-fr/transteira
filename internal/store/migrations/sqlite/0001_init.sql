-- 0001_init (SQLite): tenants, internal network rules and blocklist.
-- Keep in sync with migrations/postgres/0001_init.sql (same tables, columns
-- and constraints). Timestamps are Unix milliseconds (UTC). Every
-- tenant-scoped table carries tenant_id and an index starting with it.

CREATE TABLE tenants (
    id                  TEXT    NOT NULL PRIMARY KEY,
    name                TEXT    NOT NULL,
    fqdn                TEXT    NOT NULL UNIQUE,
    default_language    TEXT    NOT NULL,
    max_transfer_bytes  INTEGER NOT NULL CHECK (max_transfer_bytes > 0),
    storage_quota_bytes INTEGER NOT NULL CHECK (storage_quota_bytes > 0),
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
) STRICT;

-- Internal IP ranges (kind 'cidr') and internal mail domains (kind 'domain')
-- of a tenant (spec 6.2). The primary key doubles as the tenant_id index.
CREATE TABLE tenant_network_rules (
    tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind      TEXT NOT NULL CHECK (kind IN ('cidr', 'domain')),
    value     TEXT NOT NULL,
    PRIMARY KEY (tenant_id, kind, value)
) STRICT, WITHOUT ROWID;

-- Blocked addresses, domains and file fingerprints of a tenant (spec 15.2).
CREATE TABLE blocklist_entries (
    id         TEXT    NOT NULL PRIMARY KEY,
    tenant_id  TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('email', 'domain', 'sha256')),
    value      TEXT    NOT NULL,
    comment    TEXT    NOT NULL DEFAULT '',
    created_by TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE (tenant_id, kind, value)
) STRICT;

-- Cursor pagination of a tenant's entries (ordered by id).
CREATE INDEX blocklist_entries_tenant_id_idx ON blocklist_entries (tenant_id, id);

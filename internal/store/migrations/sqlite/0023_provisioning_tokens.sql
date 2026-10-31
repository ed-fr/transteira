-- 0023_provisioning_tokens (SQLite): provisioning tokens of the MSP API and
-- the tenants they created (V1.2, feature F6). Keep in sync with
-- migrations/postgres/0023_provisioning_tokens.sql. Timestamps are Unix
-- milliseconds (UTC). See docs/architecture/data-model-v1.2.md, section 2.2.

-- Provisioning tokens. An instance-level table without tenant_id, like
-- admins: it is reached through system queries only, and a tenant API token
-- never authenticates here (nor the reverse). id is "prv_" + ULID; the
-- secret itself ("ttp_" + 43 base62 characters) is shown once at creation
-- and never stored: token_hash is its SHA-256 (32 bytes), and prefix its
-- first characters, shown to the super admin to recognize it.
-- allowed_cidrs is the JSON array of the IP ranges the token may be used
-- from (at least one, never 0.0.0.0/0 nor ::/0, enforced by the store) and
-- allowed_fqdn_suffixes the JSON array of the suffixes the FQDN of a
-- created tenant must end with (at least one). max_storage_quota_bytes caps
-- the storage quota of each tenant created, max_transfer_bytes (optional)
-- the limit per transfer, max_tenants (required, threat model P48) the number of live tenants
-- created by the token. created_by is the ID of the super admin who created
-- it, kept as plain text without a foreign key so that deleting an admin
-- never depends on its tokens (the audit log keeps the history). A token is
-- never deleted: it is revoked (revoked_at set), so that the tenants keep
-- their reference.
CREATE TABLE provisioning_tokens (
    id                      TEXT    NOT NULL PRIMARY KEY,
    name                    TEXT    NOT NULL CHECK (name <> ''),
    prefix                  TEXT    NOT NULL CHECK (prefix <> ''),
    token_hash              BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    allowed_cidrs           TEXT    NOT NULL,
    allowed_fqdn_suffixes   TEXT    NOT NULL,
    max_storage_quota_bytes INTEGER NOT NULL CHECK (max_storage_quota_bytes > 0),
    max_transfer_bytes      INTEGER CHECK (max_transfer_bytes > 0),
    max_tenants             INTEGER NOT NULL CHECK (max_tenants > 0),
    created_by              TEXT    NOT NULL CHECK (created_by <> ''),
    created_at              INTEGER NOT NULL,
    last_used_at            INTEGER,
    expires_at              INTEGER,
    revoked_at              INTEGER,
    CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;

-- Super admin list of the tokens, newest first.
CREATE INDEX provisioning_tokens_created_idx ON provisioning_tokens (created_at, id);

-- provisioned_by is the token that created the tenant, NULL for a tenant
-- created by a super admin. The foreign key has no ON DELETE action: a
-- token that created tenants cannot be deleted (it is only revoked).
ALTER TABLE tenants ADD COLUMN provisioned_by TEXT REFERENCES provisioning_tokens (id);

-- Lists the tenants of a token, counts its live tenants (maxTenants cap),
-- and counts its recent creations (rate limit of 30 per hour).
CREATE INDEX tenants_provisioned_by_idx ON tenants (provisioned_by, created_at)
    WHERE provisioned_by IS NOT NULL;

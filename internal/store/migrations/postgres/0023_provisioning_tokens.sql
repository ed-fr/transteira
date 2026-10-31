-- 0023_provisioning_tokens (PostgreSQL): provisioning tokens of the MSP API
-- and the tenants they created (V1.2, feature F6). Keep in sync with
-- migrations/sqlite/0023_provisioning_tokens.sql, which documents the
-- columns. Timestamps are Unix milliseconds (UTC). Conventions of
-- 0001_init: "C" collation on identifiers, row-level security ENABLE +
-- FORCE. See docs/architecture/data-model-v1.2.md, section 2.2.
CREATE TABLE provisioning_tokens (
    id                      TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    name                    TEXT   NOT NULL CHECK (name <> ''),
    prefix                  TEXT   COLLATE "C" NOT NULL CHECK (prefix <> ''),
    token_hash              BYTEA  NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    allowed_cidrs           TEXT   NOT NULL,
    allowed_fqdn_suffixes   TEXT   NOT NULL,
    max_storage_quota_bytes BIGINT NOT NULL CHECK (max_storage_quota_bytes > 0),
    max_transfer_bytes      BIGINT CHECK (max_transfer_bytes > 0),
    max_tenants             INTEGER NOT NULL CHECK (max_tenants > 0),
    created_by              TEXT   NOT NULL CHECK (created_by <> ''),
    created_at              BIGINT NOT NULL,
    last_used_at            BIGINT,
    expires_at              BIGINT,
    revoked_at              BIGINT,
    CHECK (expires_at IS NULL OR expires_at > created_at)
);

-- Super admin list of the tokens, newest first.
CREATE INDEX provisioning_tokens_created_idx ON provisioning_tokens (created_at, id);

ALTER TABLE tenants ADD COLUMN provisioned_by TEXT COLLATE "C" REFERENCES provisioning_tokens (id);

CREATE INDEX tenants_provisioned_by_idx ON tenants (provisioned_by, created_at)
    WHERE provisioned_by IS NOT NULL;

-- Instance table: system scope only, like admins. A tenant-scoped
-- transaction must not see the tokens, their scope or their hashes.
ALTER TABLE provisioning_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE provisioning_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY provisioning_tokens_system ON provisioning_tokens
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

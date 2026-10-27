-- 0019_my_transfers (PostgreSQL): "my transfers" access links and
-- sessions (spec 8.7). Keep in sync with
-- migrations/sqlite/0019_my_transfers.sql, which documents the columns.
-- Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v1.1.md, section 2.7.

CREATE TABLE access_link_requests (
    tenant_id   TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    id          TEXT    COLLATE "C" NOT NULL,
    address_mac BYTEA   NOT NULL CHECK (length(address_mac) = 32),
    client_ip   TEXT    NOT NULL,
    created_at  BIGINT  NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX access_link_requests_mac_idx ON access_link_requests (tenant_id, address_mac, created_at);
CREATE INDEX access_link_requests_ip_idx ON access_link_requests (tenant_id, client_ip, created_at);

CREATE TABLE sender_access_links (
    id          TEXT    COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id   TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash  BYTEA   NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    email       TEXT    NOT NULL,
    created_at  BIGINT  NOT NULL,
    expires_at  BIGINT  NOT NULL,
    consumed_at BIGINT,
    CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX sender_access_links_token_idx ON sender_access_links (tenant_id, token_hash);
CREATE INDEX sender_access_links_email_idx ON sender_access_links (tenant_id, email);

CREATE TABLE sender_sessions (
    id         TEXT    COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id  TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash BYTEA   NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    email      TEXT    NOT NULL,
    created_at BIGINT  NOT NULL,
    expires_at BIGINT  NOT NULL,
    ended_at   BIGINT,
    CHECK (expires_at > created_at)
);

CREATE INDEX sender_sessions_email_idx ON sender_sessions (tenant_id, email);
CREATE INDEX sender_sessions_expires_idx ON sender_sessions (tenant_id, expires_at);

ALTER TABLE access_link_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_link_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY access_link_requests_isolation ON access_link_requests
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

ALTER TABLE sender_access_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE sender_access_links FORCE ROW LEVEL SECURITY;
CREATE POLICY sender_access_links_isolation ON sender_access_links
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

ALTER TABLE sender_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sender_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sender_sessions_isolation ON sender_sessions
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

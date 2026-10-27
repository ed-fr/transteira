-- 0019_my_transfers (SQLite): "my transfers" access links and sessions
-- (spec 8.7). Keep in sync with migrations/postgres/0019_my_transfers.sql.
-- Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v1.1.md, section 2.7.

-- Rate limit of the access link requests, for known and unknown addresses
-- alike (D12): 5 per hour per address, 20 per hour per IP. id is a ULID;
-- address_mac is the HMAC-SHA256 of the normalized address (dedicated key
-- derived from the master key), never the address itself. Purged 1 hour
-- after created_at.
CREATE TABLE access_link_requests (
    tenant_id   TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    id          TEXT    NOT NULL,
    address_mac BLOB    NOT NULL CHECK (length(address_mac) = 32),
    client_ip   TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, id)
) STRICT, WITHOUT ROWID;

CREATE INDEX access_link_requests_mac_idx ON access_link_requests (tenant_id, address_mac, created_at);
CREATE INDEX access_link_requests_ip_idx ON access_link_requests (tenant_id, client_ip, created_at);

-- One-time "my transfers" links ("mta_" token), mailed to a verified
-- address only. id is "sal_" + ULID; token_hash the SHA-256 of the token,
-- never kept sealed. Valid 15 minutes, purged once expired or consumed.
CREATE TABLE sender_access_links (
    id          TEXT    NOT NULL PRIMARY KEY,
    tenant_id   TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash  BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    email       TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    consumed_at INTEGER,
    CHECK (expires_at > created_at)
) STRICT;

CREATE UNIQUE INDEX sender_access_links_token_idx ON sender_access_links (tenant_id, token_hash);
CREATE INDEX sender_access_links_email_idx ON sender_access_links (tenant_id, email);

-- Cookie sessions of "my transfers" (1 hour), opened by an access link.
-- Only the SHA-256 of the cookie token is stored.
CREATE TABLE sender_sessions (
    id         TEXT    NOT NULL PRIMARY KEY,
    tenant_id  TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    email      TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ended_at   INTEGER,
    CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX sender_sessions_email_idx ON sender_sessions (tenant_id, email);
CREATE INDEX sender_sessions_expires_idx ON sender_sessions (tenant_id, expires_at);

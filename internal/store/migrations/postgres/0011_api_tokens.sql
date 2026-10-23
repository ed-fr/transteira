-- 0011_api_tokens (PostgreSQL): API tokens of a tenant (spec 16.4) and the
-- transfers they create. Keep in sync with
-- migrations/sqlite/0011_api_tokens.sql. Timestamps are Unix milliseconds
-- (UTC). Conventions of 0001_init: "C" collation on identifiers, row-level
-- security ENABLE + FORCE. The transfers policy of 0004 covers the new
-- transfer column.

-- API tokens. id is "tok_" + ULID; the secret itself ("tt_" + 43 base62
-- characters) is shown once at creation and never stored: token_hash is
-- its SHA-256 (32 bytes), unique across tenants, and prefix its first
-- characters, shown to the admins to recognize it. The lookup by hash runs
-- in the scope of the tenant resolved from the Host header, so that a
-- token of another tenant is unknown (threat model T-69), here enforced by
-- row-level security too. allowed_cidrs is the JSON array of the IP ranges
-- the token may be used from (1 to 100, masked, canonical text form), and
-- allowed_senders the JSON array of the sender addresses and mail domains
-- it may deposit as (0 to 100, normalized; empty: any address of an
-- internal domain of the tenant). created_by is the username of the admin
-- who created it. A token is never deleted with its tenant alive: it is
-- revoked (revoked_at set), so that the transfers keep their reference.
CREATE TABLE api_tokens (
    id              TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id       TEXT   COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name            TEXT   NOT NULL CHECK (name <> ''),
    prefix          TEXT   COLLATE "C" NOT NULL CHECK (prefix <> ''),
    token_hash      BYTEA  NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    allowed_cidrs   TEXT   NOT NULL,
    allowed_senders TEXT   NOT NULL DEFAULT '[]',
    created_by      TEXT   NOT NULL,
    created_at      BIGINT NOT NULL,
    last_used_at    BIGINT,
    expires_at      BIGINT,
    revoked_at      BIGINT,
    UNIQUE (tenant_id, id)
);

-- Administrator list of the tokens, newest first.
CREATE INDEX api_tokens_tenant_created_idx ON api_tokens (tenant_id, created_at, id);

-- api_token_id is the token that created the transfer, NULL for a transfer
-- created by a deposit session. Such a transfer keeps sender_kind
-- 'internal' (its sender address is in an internal domain of the tenant);
-- its origin "api" derives from this column. The single-column foreign key
-- (as on SQLite, which cannot add a composite one to an existing table)
-- proves that the token exists, the store checks that it belongs to the
-- same tenant. Tokens are only revoked, never deleted while their tenant
-- lives.
ALTER TABLE transfers ADD COLUMN api_token_id TEXT COLLATE "C" REFERENCES api_tokens (id);

-- The idempotency key is unique per sender address for the transfers of a
-- deposit session, and per token for the transfers of an API token: a
-- session and a token never share a key, even with the same address.
DROP INDEX transfers_idempotency_idx;
CREATE UNIQUE INDEX transfers_idempotency_idx ON transfers (tenant_id, sender_email, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND api_token_id IS NULL;
CREATE UNIQUE INDEX transfers_token_idempotency_idx ON transfers (tenant_id, api_token_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND api_token_id IS NOT NULL;
-- Counts and lists the recent open (uploading) transfers of a token
-- (per-token cap).
CREATE INDEX transfers_token_status_idx ON transfers (tenant_id, api_token_id, status, created_at);

ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY api_tokens_isolation ON api_tokens
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

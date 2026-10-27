-- 0018_webhooks (PostgreSQL): alert webhooks of the tenants and of the
-- instance (spec 12.4). Keep in sync with migrations/sqlite/0018_webhooks.sql,
-- which documents the columns. Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v1.1.md, section 2.6.

ALTER TABLE system_secrets
    DROP CONSTRAINT system_secrets_purpose_check,
    ADD CONSTRAINT system_secrets_purpose_check CHECK (purpose IN ('admin-totp', 'webhook'));

ALTER TABLE tenants ADD COLUMN webhook_include_addresses BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE webhooks (
    id                   TEXT    COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id            TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name                 TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind                 TEXT    NOT NULL CHECK (kind IN ('teams', 'slack', 'generic')),
    url_key_id           TEXT    COLLATE "C" REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    url_hint             TEXT    NOT NULL CHECK (length(url_hint) <= 300),
    secret_key_id        TEXT    COLLATE "C" REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    events               TEXT    NOT NULL,
    enabled              BOOLEAN NOT NULL DEFAULT true,
    created_at           BIGINT  NOT NULL,
    created_by           TEXT    NOT NULL CHECK (length(created_by) <= 64),
    updated_at           BIGINT  NOT NULL,
    last_delivery_at     BIGINT,
    last_status          TEXT    CHECK (last_status IN ('success', 'failure')),
    last_http_status     INTEGER CHECK (last_http_status BETWEEN 100 AND 599),
    last_duration_ms     INTEGER CHECK (last_duration_ms >= 0),
    last_error           TEXT    CHECK (length(last_error) <= 300),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    circuit_open_until   BIGINT,
    UNIQUE (tenant_id, id),
    CHECK (kind = 'generic' OR secret_key_id IS NULL)
);

CREATE INDEX webhooks_tenant_idx ON webhooks (tenant_id, created_at, id);
CREATE UNIQUE INDEX webhooks_url_key_idx ON webhooks (url_key_id);
CREATE UNIQUE INDEX webhooks_secret_key_idx ON webhooks (secret_key_id);

CREATE TABLE system_webhooks (
    id                   TEXT    COLLATE "C" NOT NULL PRIMARY KEY,
    name                 TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind                 TEXT    NOT NULL CHECK (kind IN ('teams', 'slack', 'generic')),
    url_secret_id        TEXT    COLLATE "C" REFERENCES system_secrets (id) ON DELETE SET NULL,
    url_hint             TEXT    NOT NULL CHECK (length(url_hint) <= 300),
    hmac_secret_id       TEXT    COLLATE "C" REFERENCES system_secrets (id) ON DELETE SET NULL,
    events               TEXT    NOT NULL,
    enabled              BOOLEAN NOT NULL DEFAULT true,
    created_at           BIGINT  NOT NULL,
    created_by           TEXT    NOT NULL CHECK (length(created_by) <= 64),
    updated_at           BIGINT  NOT NULL,
    last_delivery_at     BIGINT,
    last_status          TEXT    CHECK (last_status IN ('success', 'failure')),
    last_http_status     INTEGER CHECK (last_http_status BETWEEN 100 AND 599),
    last_duration_ms     INTEGER CHECK (last_duration_ms >= 0),
    last_error           TEXT    CHECK (length(last_error) <= 300),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    circuit_open_until   BIGINT,
    CHECK (kind = 'generic' OR hmac_secret_id IS NULL)
);

CREATE INDEX system_webhooks_created_idx ON system_webhooks (created_at, id);
CREATE UNIQUE INDEX system_webhooks_url_secret_idx ON system_webhooks (url_secret_id);
CREATE UNIQUE INDEX system_webhooks_hmac_secret_idx ON system_webhooks (hmac_secret_id);

ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks FORCE ROW LEVEL SECURITY;
CREATE POLICY webhooks_isolation ON webhooks
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

-- System table: open to the system scope only, like system_settings.
ALTER TABLE system_webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_webhooks FORCE ROW LEVEL SECURITY;
CREATE POLICY system_webhooks_system ON system_webhooks
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

-- 0018_webhooks (SQLite): alert webhooks of the tenants and of the
-- instance (spec 12.4). Keep in sync with migrations/postgres/0018_webhooks.sql.
-- Timestamps are Unix milliseconds (UTC); booleans are INTEGER 0/1. See
-- docs/architecture/data-model-v1.1.md, section 2.6.

-- system_secrets.purpose gains 'webhook' (sealed URL and HMAC secret of an
-- instance webhook). admins references system_secrets: like transfers in
-- 0014, the rebuild relies on the migrator disabling foreign keys
-- (store/migrate.go), so that dropping the old table neither fails nor
-- touches admins, whose "REFERENCES system_secrets" resolves to the new
-- table once renamed. The index and the retired-key triggers of 0008 are
-- dropped with the old table and recreated.
CREATE TABLE system_secrets_0018 (
    id         TEXT    NOT NULL PRIMARY KEY,
    purpose    TEXT    NOT NULL CHECK (purpose IN ('admin-totp', 'webhook')),
    key_id     TEXT    NOT NULL,
    blob       BLOB    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

INSERT INTO system_secrets_0018 (id, purpose, key_id, blob, created_at)
SELECT id, purpose, key_id, blob, created_at FROM system_secrets;

DROP TABLE system_secrets;
ALTER TABLE system_secrets_0018 RENAME TO system_secrets;

CREATE INDEX system_secrets_key_id_idx ON system_secrets (key_id, id);

CREATE TRIGGER system_secrets_reject_retired_insert BEFORE INSERT ON system_secrets
WHEN EXISTS (SELECT 1 FROM master_keys WHERE id = NEW.key_id AND status = 'retired')
BEGIN
    SELECT RAISE(ABORT, 'transteira: master key is retired');
END;

CREATE TRIGGER system_secrets_reject_retired_update BEFORE UPDATE OF key_id ON system_secrets
WHEN EXISTS (SELECT 1 FROM master_keys WHERE id = NEW.key_id AND status = 'retired')
BEGIN
    SELECT RAISE(ABORT, 'transteira: master key is retired');
END;

-- Payload privacy (D4): without this flag, the webhook payloads of the
-- tenant carry no e-mail address.
ALTER TABLE tenants ADD COLUMN webhook_include_addresses INTEGER NOT NULL DEFAULT 0
    CHECK (webhook_include_addresses IN (0, 1));

-- Webhooks of a tenant. id is "whk_" + ULID. The URL is sealed
-- (url_key_id, wrapped key of purpose 'secret'; url_hint is
-- "scheme://host/..." for display) and so is the HMAC secret of a generic
-- webhook (secret_key_id). Both keys are ON DELETE SET NULL: the store
-- destroys them before the row and refuses to delete a row whose keys
-- still exist (D23), and checks their tenant. events is the non-empty JSON
-- array of tenant event types (validated by the store). The last_* columns
-- and the circuit breaker are updated once per delivery attempt; last_error
-- is a coarse category, never the URL.
CREATE TABLE webhooks (
    id                   TEXT    NOT NULL PRIMARY KEY,
    tenant_id            TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name                 TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind                 TEXT    NOT NULL CHECK (kind IN ('teams', 'slack', 'generic')),
    url_key_id           TEXT    REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    url_hint             TEXT    NOT NULL CHECK (length(url_hint) <= 300),
    secret_key_id        TEXT    REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    events               TEXT    NOT NULL,
    enabled              INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at           INTEGER NOT NULL,
    created_by           TEXT    NOT NULL CHECK (length(created_by) <= 64),
    updated_at           INTEGER NOT NULL,
    last_delivery_at     INTEGER,
    last_status          TEXT    CHECK (last_status IN ('success', 'failure')),
    last_http_status     INTEGER CHECK (last_http_status BETWEEN 100 AND 599),
    last_duration_ms     INTEGER CHECK (last_duration_ms >= 0),
    last_error           TEXT    CHECK (length(last_error) <= 300),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    circuit_open_until   INTEGER,
    UNIQUE (tenant_id, id),
    CHECK (kind = 'generic' OR secret_key_id IS NULL)
) STRICT;

CREATE INDEX webhooks_tenant_idx ON webhooks (tenant_id, created_at, id);
CREATE UNIQUE INDEX webhooks_url_key_idx ON webhooks (url_key_id);
CREATE UNIQUE INDEX webhooks_secret_key_idx ON webhooks (secret_key_id);

-- Webhooks of the instance (super admin): same columns without tenant_id,
-- the URL and HMAC secret being system_secrets rows (purpose 'webhook').
-- They receive instance event types only (D4). System table: the store
-- reaches it through system queries only.
CREATE TABLE system_webhooks (
    id                   TEXT    NOT NULL PRIMARY KEY,
    name                 TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind                 TEXT    NOT NULL CHECK (kind IN ('teams', 'slack', 'generic')),
    url_secret_id        TEXT    REFERENCES system_secrets (id) ON DELETE SET NULL,
    url_hint             TEXT    NOT NULL CHECK (length(url_hint) <= 300),
    hmac_secret_id       TEXT    REFERENCES system_secrets (id) ON DELETE SET NULL,
    events               TEXT    NOT NULL,
    enabled              INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at           INTEGER NOT NULL,
    created_by           TEXT    NOT NULL CHECK (length(created_by) <= 64),
    updated_at           INTEGER NOT NULL,
    last_delivery_at     INTEGER,
    last_status          TEXT    CHECK (last_status IN ('success', 'failure')),
    last_http_status     INTEGER CHECK (last_http_status BETWEEN 100 AND 599),
    last_duration_ms     INTEGER CHECK (last_duration_ms >= 0),
    last_error           TEXT    CHECK (length(last_error) <= 300),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    circuit_open_until   INTEGER,
    CHECK (kind = 'generic' OR hmac_secret_id IS NULL)
) STRICT;

CREATE INDEX system_webhooks_created_idx ON system_webhooks (created_at, id);
CREATE UNIQUE INDEX system_webhooks_url_secret_idx ON system_webhooks (url_secret_id);
CREATE UNIQUE INDEX system_webhooks_hmac_secret_idx ON system_webhooks (hmac_secret_id);

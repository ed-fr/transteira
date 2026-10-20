-- 0002_encryption (SQLite): master keys, key rotations and wrapped keys
-- (spec 16.1). Keep in sync with migrations/postgres/0002_encryption.sql.
-- Timestamps are Unix milliseconds (UTC).

-- Master keys known to the installation. The id is derived from the key
-- itself ("mk_" + 16 hex), never the key. System table: no tenant_id.
CREATE TABLE master_keys (
    id         TEXT    NOT NULL PRIMARY KEY,
    status     TEXT    NOT NULL CHECK (status IN ('active', 'retired')),
    created_at INTEGER NOT NULL,
    retired_at INTEGER
) STRICT;

-- At most one active master key.
CREATE UNIQUE INDEX master_keys_one_active_idx ON master_keys (status) WHERE status = 'active';

-- Master key rotation runs (resumable). System table: no tenant_id. The
-- key ids are not foreign keys: the new key is only recorded in master_keys
-- when the rotation completes.
CREATE TABLE key_rotations (
    id             TEXT    NOT NULL PRIMARY KEY,
    from_key_id    TEXT    NOT NULL,
    to_key_id      TEXT    NOT NULL,
    status         TEXT    NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    total_keys     INTEGER NOT NULL CHECK (total_keys >= 0),
    rewrapped_keys INTEGER NOT NULL CHECK (rewrapped_keys >= 0),
    started_at     INTEGER NOT NULL,
    completed_at   INTEGER,
    error          TEXT,
    CHECK (from_key_id <> to_key_id)
) STRICT;

-- At most one running rotation.
CREATE UNIQUE INDEX key_rotations_one_running_idx ON key_rotations (status) WHERE status = 'running';

-- Data keys (purpose 'dek') and secrets (purpose 'secret') of a tenant,
-- encrypted under the master key key_id: the only table holding wrapped
-- keys. Deleting a row is the cryptographic erasure of what it protects
-- (secure_delete overwrites the freed content). key_id is not a foreign
-- key: during a rotation, new keys are wrapped under the new master key
-- before it is recorded in master_keys. Deleting the tenant erases its keys.
CREATE TABLE wrapped_keys (
    id         TEXT    NOT NULL PRIMARY KEY,
    tenant_id  TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    purpose    TEXT    NOT NULL CHECK (purpose IN ('dek', 'secret')),
    key_id     TEXT    NOT NULL,
    blob       BLOB    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX wrapped_keys_tenant_id_idx ON wrapped_keys (tenant_id, id);
-- Rotation scans the keys still wrapped under the old master key.
CREATE INDEX wrapped_keys_key_id_idx ON wrapped_keys (key_id, id);

-- A retired master key never wraps anything again (rotation target, new
-- key or rewrap). A key_id absent from master_keys is allowed: during a
-- rotation the new key is only registered when the rotation completes. The
-- message is matched by the store (retiredKeyMessage).
CREATE TRIGGER wrapped_keys_reject_retired_insert BEFORE INSERT ON wrapped_keys
WHEN EXISTS (SELECT 1 FROM master_keys WHERE id = NEW.key_id AND status = 'retired')
BEGIN
    SELECT RAISE(ABORT, 'transteira: master key is retired');
END;

CREATE TRIGGER wrapped_keys_reject_retired_update BEFORE UPDATE OF key_id ON wrapped_keys
WHEN EXISTS (SELECT 1 FROM master_keys WHERE id = NEW.key_id AND status = 'retired')
BEGIN
    SELECT RAISE(ABORT, 'transteira: master key is retired');
END;

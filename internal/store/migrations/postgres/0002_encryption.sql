-- 0002_encryption (PostgreSQL): master keys, key rotations and wrapped keys
-- (spec 16.1). Keep in sync with migrations/sqlite/0002_encryption.sql.
-- Timestamps are Unix milliseconds (UTC). Conventions of 0001_init: "C"
-- collation on identifiers, row-level security ENABLE + FORCE.

-- Master keys known to the installation. The id is derived from the key
-- itself ("mk_" + 16 hex), never the key. System table: no tenant_id.
CREATE TABLE master_keys (
    id         TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    status     TEXT   NOT NULL CHECK (status IN ('active', 'retired')),
    created_at BIGINT NOT NULL,
    retired_at BIGINT
);

-- At most one active master key.
CREATE UNIQUE INDEX master_keys_one_active_idx ON master_keys (status) WHERE status = 'active';

-- Master key rotation runs (resumable). System table: no tenant_id. The
-- key ids are not foreign keys: the new key is only recorded in master_keys
-- when the rotation completes.
CREATE TABLE key_rotations (
    id             TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    from_key_id    TEXT   COLLATE "C" NOT NULL,
    to_key_id      TEXT   COLLATE "C" NOT NULL,
    status         TEXT   NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    total_keys     BIGINT NOT NULL CHECK (total_keys >= 0),
    rewrapped_keys BIGINT NOT NULL CHECK (rewrapped_keys >= 0),
    started_at     BIGINT NOT NULL,
    completed_at   BIGINT,
    error          TEXT,
    CHECK (from_key_id <> to_key_id)
);

-- At most one running rotation.
CREATE UNIQUE INDEX key_rotations_one_running_idx ON key_rotations (status) WHERE status = 'running';

-- Data keys (purpose 'dek') and secrets (purpose 'secret') of a tenant,
-- encrypted under the master key key_id: the only table holding wrapped
-- keys. Deleting a row is the cryptographic erasure of what it protects;
-- dead tuples remain on disk until VACUUM (threat model T-109). key_id is
-- not a foreign key: during a rotation, new keys are wrapped under the new
-- master key before it is recorded in master_keys. Deleting the tenant
-- erases its keys.
CREATE TABLE wrapped_keys (
    id         TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id  TEXT   COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    purpose    TEXT   NOT NULL CHECK (purpose IN ('dek', 'secret')),
    key_id     TEXT   COLLATE "C" NOT NULL,
    blob       BYTEA  NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX wrapped_keys_tenant_id_idx ON wrapped_keys (tenant_id, id);
-- Rotation scans the keys still wrapped under the old master key.
CREATE INDEX wrapped_keys_key_id_idx ON wrapped_keys (key_id, id);

-- The key tables are written by the system scope only (startup key check,
-- rotation); a tenant-scoped transaction cannot see the rotations.
ALTER TABLE master_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE master_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY master_keys_system ON master_keys
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');
-- Master key identifiers are not secret: every scope may read them, which
-- the wrapped_keys trigger below needs in tenant scope. Writes stay reserved
-- to the system scope.
CREATE POLICY master_keys_read ON master_keys FOR SELECT USING (true);

ALTER TABLE key_rotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_rotations FORCE ROW LEVEL SECURITY;
CREATE POLICY key_rotations_system ON key_rotations
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

ALTER TABLE wrapped_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE wrapped_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY wrapped_keys_isolation ON wrapped_keys
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

-- A retired master key never wraps anything again (rotation target, new
-- key or rewrap). A key_id absent from master_keys is allowed: during a
-- rotation the new key is only registered when the rotation completes. The
-- function runs with the caller's rights (no SECURITY DEFINER), reading
-- master_keys through its read policy; its search_path is pinned to the
-- schema of the migration. SQLSTATE TTK01 is matched by the store
-- (pgKeyRetired).
CREATE FUNCTION wrapped_keys_reject_retired() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path FROM CURRENT
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM master_keys WHERE id = NEW.key_id AND status = 'retired') THEN
        RAISE EXCEPTION 'transteira: master key is retired' USING ERRCODE = 'TTK01';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER wrapped_keys_reject_retired BEFORE INSERT OR UPDATE OF key_id ON wrapped_keys
    FOR EACH ROW EXECUTE FUNCTION wrapped_keys_reject_retired();

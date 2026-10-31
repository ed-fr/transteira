-- 0025_system_state (SQLite): instance key/value state written by the
-- application itself, starting with the cache of the update check (V1.2,
-- feature F1). Keep in sync with migrations/postgres/0025_system_state.sql.
-- Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v1.2.md, section 2.4.
--
-- A system table without tenant_id, reached through system queries only.
-- Unlike system_settings (settings edited by the super admin, one row), it
-- holds state the application computes. key is a fixed identifier defined
-- by the code (V1.2: 'update_check'); value is a JSON document validated by
-- the store, never a secret.
CREATE TABLE system_state (
    key        TEXT    NOT NULL PRIMARY KEY CHECK (key <> ''),
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

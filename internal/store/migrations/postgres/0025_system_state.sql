-- 0025_system_state (PostgreSQL): instance key/value state written by the
-- application itself, starting with the cache of the update check (V1.2,
-- feature F1). Keep in sync with migrations/sqlite/0025_system_state.sql,
-- which documents the columns. See docs/architecture/data-model-v1.2.md,
-- section 2.4.
CREATE TABLE system_state (
    key        TEXT   COLLATE "C" NOT NULL PRIMARY KEY CHECK (key <> ''),
    value      TEXT   NOT NULL,
    updated_at BIGINT NOT NULL
);

-- System table: system scope only.
ALTER TABLE system_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_state FORCE ROW LEVEL SECURITY;
CREATE POLICY system_state_system ON system_state
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

-- 0012_system (PostgreSQL): instance settings editable at runtime by the
-- super admin (spec 4, 12.2 and 19): disk alert threshold and address,
-- maintenance mode, and the persisted disk alert level. Keep in sync with
-- migrations/sqlite/0012_system.sql. Timestamps are Unix milliseconds
-- (UTC). Conventions of 0001_init: row-level security ENABLE + FORCE.
--
-- A system table without tenant_id, holding exactly one row (id = 1),
-- created here. The store reaches it through system queries only; its
-- policy admits the system scope only, like the administration tables.
--
-- disk_alert_threshold_bp is the disk usage ratio raising the alert, in
-- basis points (8500 = 85 %). alert_email is the optional extra recipient of
-- the disk alert and alert_email_language the language it is written in
-- (both NULL when none). maintenance_message is the JSON object of the
-- maintenance messages by language ('{}' when none); maintenance_since is
-- the start of the maintenance enabled by the super admin. disk_alert_level
-- is 1 while the disk alert is raised, so that a restart never mails it
-- again; disk_alert_changed_at is its last change. disk_alert_mailed_at is
-- the last time the disk alert was mailed: the alert mails are at least an
-- hour apart, whatever the number of crossings. updated_at is the last
-- change of the settings (0: never changed).
CREATE TABLE system_settings (
    id                      INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    disk_alert_threshold_bp INTEGER NOT NULL DEFAULT 8500
                            CHECK (disk_alert_threshold_bp BETWEEN 5000 AND 9900),
    alert_email             TEXT,
    alert_email_language    TEXT,
    maintenance_enabled     BOOLEAN NOT NULL DEFAULT false,
    maintenance_since       BIGINT,
    maintenance_message     TEXT    NOT NULL DEFAULT '{}',
    disk_alert_level        INTEGER NOT NULL DEFAULT 0 CHECK (disk_alert_level IN (0, 1)),
    disk_alert_changed_at   BIGINT,
    disk_alert_mailed_at    BIGINT,
    updated_at              BIGINT  NOT NULL
);

INSERT INTO system_settings (id, updated_at) VALUES (1, 0);

-- System table: system scope only.
ALTER TABLE system_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY system_settings_system ON system_settings
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

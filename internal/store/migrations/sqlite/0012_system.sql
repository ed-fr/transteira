-- 0012_system (SQLite): instance settings editable at runtime by the super
-- admin (spec 4, 12.2 and 19): disk alert threshold and address,
-- maintenance mode, and the persisted disk alert level. Keep in sync with
-- migrations/postgres/0012_system.sql. Timestamps are Unix milliseconds
-- (UTC); booleans are INTEGER 0/1.
--
-- A system table without tenant_id, holding exactly one row (id = 1),
-- created here. The store reaches it through system queries only.
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
                            CHECK (disk_alert_threshold_bp >= 5000 AND disk_alert_threshold_bp <= 9900),
    alert_email             TEXT,
    alert_email_language    TEXT,
    maintenance_enabled     INTEGER NOT NULL DEFAULT 0 CHECK (maintenance_enabled IN (0, 1)),
    maintenance_since       INTEGER,
    maintenance_message     TEXT    NOT NULL DEFAULT '{}',
    disk_alert_level        INTEGER NOT NULL DEFAULT 0 CHECK (disk_alert_level IN (0, 1)),
    disk_alert_changed_at   INTEGER,
    disk_alert_mailed_at    INTEGER,
    updated_at              INTEGER NOT NULL
) STRICT;

INSERT INTO system_settings (id, updated_at) VALUES (1, 0);

-- 0017_abuse (PostgreSQL): abuse detection thresholds, alert deduplication
-- and abuse reports (spec 10 and 15). Keep in sync with
-- migrations/sqlite/0017_abuse.sql, which documents the columns.
-- Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v1.1.md, section 2.5.

CREATE TABLE tenant_abuse_settings (
    tenant_id                      TEXT    COLLATE "C" NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    max_daily_bytes_per_sender     BIGINT  CHECK (max_daily_bytes_per_sender > 0),
    max_daily_transfers_per_sender INTEGER CHECK (max_daily_transfers_per_sender > 0),
    max_recipients_per_transfer    INTEGER CHECK (max_recipients_per_transfer > 0),
    block_on_exceed                BOOLEAN NOT NULL DEFAULT false,
    unusual_volume_pct             INTEGER CHECK (unusual_volume_pct BETWEEN 150 AND 10000),
    unusual_min_history_days       INTEGER NOT NULL DEFAULT 7 CHECK (unusual_min_history_days BETWEEN 1 AND 30),
    large_external_transfer_bytes  BIGINT  CHECK (large_external_transfer_bytes > 0),
    office_start_minute            INTEGER CHECK (office_start_minute BETWEEN 0 AND 1439),
    office_end_minute              INTEGER CHECK (office_end_minute BETWEEN 1 AND 1440),
    office_weekdays                INTEGER NOT NULL DEFAULT 31 CHECK (office_weekdays BETWEEN 0 AND 127),
    time_zone                      TEXT    NOT NULL DEFAULT 'UTC' CHECK (length(time_zone) BETWEEN 1 AND 64),
    max_invitations_per_inviter    INTEGER NOT NULL DEFAULT 20 CHECK (max_invitations_per_inviter BETWEEN 1 AND 1000),
    external_max_daily_bytes       BIGINT  CHECK (external_max_daily_bytes > 0),
    external_max_daily_deposits    INTEGER CHECK (external_max_daily_deposits > 0),
    updated_at                     BIGINT  NOT NULL,
    updated_by                     TEXT    NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64),
    CHECK ((office_start_minute IS NULL) = (office_end_minute IS NULL)),
    CHECK (office_start_minute IS NULL OR office_start_minute < office_end_minute)
);

-- Seed data: one row per existing tenant (see the SQLite migration).
INSERT INTO tenant_abuse_settings (tenant_id, updated_at) SELECT id, 0 FROM tenants;

CREATE TABLE abuse_alerts (
    tenant_id    TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    sender_email TEXT    NOT NULL,
    rule         TEXT    NOT NULL CHECK (rule IN ('daily_bytes', 'daily_transfers', 'recipients', 'unusual_volume', 'large_external', 'off_hours', 'invitations', 'external_quota')),
    day          TEXT    NOT NULL CHECK (length(day) = 10),
    created_at   BIGINT  NOT NULL,
    PRIMARY KEY (tenant_id, sender_email, rule, day)
);

CREATE INDEX abuse_alerts_created_idx ON abuse_alerts (tenant_id, created_at);

CREATE TABLE abuse_reports (
    id                 TEXT    COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id          TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    transfer_id        TEXT    COLLATE "C" NOT NULL,
    recipient_link_id  TEXT    COLLATE "C",
    sender_email       TEXT    NOT NULL,
    recipient_position INTEGER CHECK (recipient_position >= 0),
    reporter_email     TEXT,
    reporter_verified  BOOLEAN NOT NULL DEFAULT false,
    reporter_ip        TEXT    NOT NULL,
    category           TEXT    NOT NULL CHECK (category IN ('malware', 'phishing', 'illegal_content', 'spam', 'unknown_sender', 'other')),
    message            TEXT    NOT NULL DEFAULT '' CHECK (length(message) <= 1000),
    status             TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    closed_at          BIGINT,
    closed_by          TEXT    CHECK (length(closed_by) <= 64),
    note               TEXT    NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
    created_at         BIGINT  NOT NULL,
    UNIQUE (tenant_id, id),
    CHECK ((recipient_link_id IS NULL) = (recipient_position IS NULL)),
    CHECK ((reporter_email IS NOT NULL) = reporter_verified),
    CHECK (NOT reporter_verified OR recipient_link_id IS NOT NULL),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CHECK ((closed_at IS NULL) = (closed_by IS NULL))
);

CREATE INDEX abuse_reports_list_idx ON abuse_reports (tenant_id, status, created_at, id);
CREATE INDEX abuse_reports_link_rate_idx ON abuse_reports (tenant_id, recipient_link_id, created_at)
    WHERE recipient_link_id IS NOT NULL;
CREATE INDEX abuse_reports_shared_rate_idx ON abuse_reports (tenant_id, transfer_id, created_at)
    WHERE recipient_link_id IS NULL;
CREATE INDEX abuse_reports_ip_rate_idx ON abuse_reports (tenant_id, reporter_ip, created_at);
CREATE INDEX abuse_reports_sender_idx ON abuse_reports (tenant_id, sender_email);
CREATE INDEX abuse_reports_reporter_idx ON abuse_reports (tenant_id, reporter_email) WHERE reporter_email IS NOT NULL;

ALTER TABLE tenant_abuse_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_abuse_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_abuse_settings_isolation ON tenant_abuse_settings
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

ALTER TABLE abuse_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE abuse_alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY abuse_alerts_isolation ON abuse_alerts
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

ALTER TABLE abuse_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE abuse_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY abuse_reports_isolation ON abuse_reports
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

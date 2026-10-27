-- 0017_abuse (SQLite): abuse detection thresholds, alert deduplication and
-- abuse reports (spec 10 and 15). Keep in sync with
-- migrations/postgres/0017_abuse.sql. Timestamps are Unix milliseconds
-- (UTC); booleans are INTEGER 0/1. See
-- docs/architecture/data-model-v1.1.md, section 2.5.

-- Abuse thresholds of a tenant, one row per tenant; a NULL threshold
-- disables its rule. unusual_volume_pct is the API unusualVolumeFactor x
-- 100. "Per day" is the calendar day in time_zone (IANA). Office hours are
-- minutes of the day (end 1440 = 24:00, start < end: no span across
-- midnight) on office_weekdays (bit 0 = Monday). max_invitations_per_inviter
-- is counted per rolling hour (D29). The counters themselves are computed
-- from transfers: there is no counter table.
CREATE TABLE tenant_abuse_settings (
    tenant_id                      TEXT    NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    max_daily_bytes_per_sender     INTEGER CHECK (max_daily_bytes_per_sender > 0),
    max_daily_transfers_per_sender INTEGER CHECK (max_daily_transfers_per_sender > 0),
    max_recipients_per_transfer    INTEGER CHECK (max_recipients_per_transfer > 0),
    block_on_exceed                INTEGER NOT NULL DEFAULT 0 CHECK (block_on_exceed IN (0, 1)),
    unusual_volume_pct             INTEGER CHECK (unusual_volume_pct BETWEEN 150 AND 10000),
    unusual_min_history_days       INTEGER NOT NULL DEFAULT 7 CHECK (unusual_min_history_days BETWEEN 1 AND 30),
    large_external_transfer_bytes  INTEGER CHECK (large_external_transfer_bytes > 0),
    office_start_minute            INTEGER CHECK (office_start_minute BETWEEN 0 AND 1439),
    office_end_minute              INTEGER CHECK (office_end_minute BETWEEN 1 AND 1440),
    office_weekdays                INTEGER NOT NULL DEFAULT 31 CHECK (office_weekdays BETWEEN 0 AND 127),
    time_zone                      TEXT    NOT NULL DEFAULT 'UTC' CHECK (length(time_zone) BETWEEN 1 AND 64),
    max_invitations_per_inviter    INTEGER NOT NULL DEFAULT 20 CHECK (max_invitations_per_inviter BETWEEN 1 AND 1000),
    external_max_daily_bytes       INTEGER CHECK (external_max_daily_bytes > 0),
    external_max_daily_deposits    INTEGER CHECK (external_max_daily_deposits > 0),
    updated_at                     INTEGER NOT NULL,
    updated_by                     TEXT    NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64),
    CHECK ((office_start_minute IS NULL) = (office_end_minute IS NULL)),
    CHECK (office_start_minute IS NULL OR office_start_minute < office_end_minute)
) STRICT;

-- Seed data: one row per existing tenant, every threshold disabled and the
-- V1 invitation limit (20 per hour), so that V1 behaviour is unchanged.
-- Tenants.Create inserts the same row for the new tenants.
INSERT INTO tenant_abuse_settings (tenant_id, updated_at) SELECT id, 0 FROM tenants;

-- Deduplication of the abuse alerts: one per sender, rule and day (day in
-- the tenant time zone, 'YYYY-MM-DD'). The alerts themselves are audit
-- events; rows are purged 2 days after created_at.
CREATE TABLE abuse_alerts (
    tenant_id    TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    sender_email TEXT    NOT NULL,
    rule         TEXT    NOT NULL CHECK (rule IN ('daily_bytes', 'daily_transfers', 'recipients', 'unusual_volume', 'large_external', 'off_hours', 'invitations', 'external_quota')),
    day          TEXT    NOT NULL CHECK (length(day) = 10),
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, sender_email, rule, day)
) STRICT, WITHOUT ROWID;

CREATE INDEX abuse_alerts_created_idx ON abuse_alerts (tenant_id, created_at);

-- Abuse reports from the download page (spec 10). id is "abr_" + ULID.
-- transfer_id, recipient_link_id and sender_email are snapshots without
-- foreign key: a report outlives its transfer. reporter_email is set only
-- when a valid __Host-tt_rv entry proves it (reporter_verified = 1);
-- otherwise recipient_position tells through which recipient link the
-- report came (NULL for a V1 shared link). Purged 12 months after
-- created_at.
CREATE TABLE abuse_reports (
    id                 TEXT    NOT NULL PRIMARY KEY,
    tenant_id          TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    transfer_id        TEXT    NOT NULL,
    recipient_link_id  TEXT,
    sender_email       TEXT    NOT NULL,
    recipient_position INTEGER CHECK (recipient_position >= 0),
    reporter_email     TEXT,
    reporter_verified  INTEGER NOT NULL DEFAULT 0 CHECK (reporter_verified IN (0, 1)),
    reporter_ip        TEXT    NOT NULL,
    category           TEXT    NOT NULL CHECK (category IN ('malware', 'phishing', 'illegal_content', 'spam', 'unknown_sender', 'other')),
    message            TEXT    NOT NULL DEFAULT '' CHECK (length(message) <= 1000),
    status             TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    closed_at          INTEGER,
    closed_by          TEXT    CHECK (length(closed_by) <= 64),
    note               TEXT    NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
    created_at         INTEGER NOT NULL,
    UNIQUE (tenant_id, id),
    CHECK ((recipient_link_id IS NULL) = (recipient_position IS NULL)),
    CHECK ((reporter_email IS NOT NULL) = (reporter_verified = 1)),
    CHECK (reporter_verified = 0 OR recipient_link_id IS NOT NULL),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CHECK ((closed_at IS NULL) = (closed_by IS NULL))
) STRICT;

CREATE INDEX abuse_reports_list_idx ON abuse_reports (tenant_id, status, created_at, id);
-- Rate limits (D13): 3 per recipient link (or shared link) per day, 5 per
-- IP per hour.
CREATE INDEX abuse_reports_link_rate_idx ON abuse_reports (tenant_id, recipient_link_id, created_at)
    WHERE recipient_link_id IS NOT NULL;
CREATE INDEX abuse_reports_shared_rate_idx ON abuse_reports (tenant_id, transfer_id, created_at)
    WHERE recipient_link_id IS NULL;
CREATE INDEX abuse_reports_ip_rate_idx ON abuse_reports (tenant_id, reporter_ip, created_at);
-- GDPR searches by address.
CREATE INDEX abuse_reports_sender_idx ON abuse_reports (tenant_id, sender_email);
CREATE INDEX abuse_reports_reporter_idx ON abuse_reports (tenant_id, reporter_email) WHERE reporter_email IS NOT NULL;

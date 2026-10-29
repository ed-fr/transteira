-- 0021_abuse_alerts_blocked (SQLite): an alert-only finding and a refusal
-- are deduplicated separately, and the refusals of the day are counted
-- (spec 15, decision D28 revised). Keep in sync with
-- migrations/postgres/0021_abuse_alerts_blocked.sql. Timestamps are Unix
-- milliseconds (UTC); booleans are INTEGER 0/1. See
-- docs/architecture/data-model-v1.1.md, section 2.5.
--
-- abuse_alerts gains blocked (part of the primary key: an alert-only alert
-- earlier in the day never masks a refusal) and attempts (the occurrences
-- of the day, incremented on every deduplicated one). No table references
-- abuse_alerts: plain rebuild, as in 0020. The existing rows were alerts
-- whose kind is unknown: they become alert-only rows of one attempt.
CREATE TABLE abuse_alerts_0021 (
    tenant_id    TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    sender_email TEXT    NOT NULL,
    rule         TEXT    NOT NULL CHECK (rule IN ('daily_bytes', 'daily_transfers', 'recipients', 'unusual_volume', 'large_external', 'off_hours', 'invitations', 'external_quota')),
    day          TEXT    NOT NULL CHECK (length(day) = 10),
    created_at   INTEGER NOT NULL,
    blocked      INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1)),
    attempts     INTEGER NOT NULL DEFAULT 1 CHECK (attempts >= 1),
    PRIMARY KEY (tenant_id, sender_email, rule, day, blocked)
) STRICT, WITHOUT ROWID;

INSERT INTO abuse_alerts_0021 (tenant_id, sender_email, rule, day, created_at)
SELECT tenant_id, sender_email, rule, day, created_at FROM abuse_alerts;

DROP TABLE abuse_alerts;
ALTER TABLE abuse_alerts_0021 RENAME TO abuse_alerts;

CREATE INDEX abuse_alerts_created_idx ON abuse_alerts (tenant_id, created_at);

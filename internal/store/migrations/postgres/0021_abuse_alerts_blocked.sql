-- 0021_abuse_alerts_blocked (PostgreSQL): an alert-only finding and a
-- refusal are deduplicated separately, and the refusals of the day are
-- counted (spec 15, decision D28 revised). Keep in sync with
-- migrations/sqlite/0021_abuse_alerts_blocked.sql, which documents the
-- columns. See docs/architecture/data-model-v1.1.md, section 2.5.
--
-- The table is altered in place: its row-level security and its policy
-- abuse_alerts_isolation (0017) are kept.
ALTER TABLE abuse_alerts
    ADD COLUMN blocked  BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN attempts INTEGER NOT NULL DEFAULT 1 CHECK (attempts >= 1),
    DROP CONSTRAINT abuse_alerts_pkey,
    ADD CONSTRAINT abuse_alerts_pkey PRIMARY KEY (tenant_id, sender_email, rule, day, blocked);

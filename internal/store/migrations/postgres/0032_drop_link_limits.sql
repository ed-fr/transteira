-- 0032_drop_link_limits (PostgreSQL): limits of a permanent drop link (V2,
-- feature F5, threat model P63). Keep in sync with
-- migrations/sqlite/0032_drop_link_limits.sql, which documents the
-- columns. Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v2.md, section 2.7.
--
-- The tables are altered in place: their row-level security and their
-- policies are kept.
ALTER TABLE drop_links
    ADD COLUMN expires_at BIGINT,
    ADD COLUMN max_deposits_per_hour INTEGER NOT NULL DEFAULT 20
        CONSTRAINT drop_links_max_deposits_per_hour_check CHECK (max_deposits_per_hour BETWEEN 1 AND 1000);

ALTER TABLE deposit_sessions ADD COLUMN used_at BIGINT;
CREATE INDEX deposit_sessions_drop_link_used_idx ON deposit_sessions (tenant_id, drop_link_id, used_at)
    WHERE used_at IS NOT NULL;

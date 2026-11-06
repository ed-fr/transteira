-- 0032_drop_link_limits (SQLite): limits of a permanent drop link (V2,
-- feature F5, threat model P63, T-310 and T-314). Keep in sync with
-- migrations/postgres/0032_drop_link_limits.sql. Timestamps are Unix
-- milliseconds (UTC). See docs/architecture/data-model-v2.md, section 2.7.
--
-- expires_at is the optional end of a link (NULL: no end). From then on
-- the link answers exactly like a revoked or disabled one, and the
-- lifecycle task purges it 12 months later, like a revoked link, once no
-- transfer references it.
--
-- max_deposits_per_hour caps the transfers created through the link in the
-- sliding last hour, all depositors together, on top of the external
-- quotas: beyond it, no verification code is sent and no transfer is
-- created (429 rate-limited). The existing links get the default, 20.
--
-- deposit_sessions.used_at is when a drop link session created its one
-- transfer, set in the creation transaction (NULL: not used yet). It makes
-- both rules independent of the transfer rows, which cancelling a transfer
-- deletes (threat model T-310): the single use of a session is "used_at IS
-- NULL", and the hourly cap counts the sessions of the link used in the
-- last hour. The cleanup task keeps a used session for one hour after its
-- use, even ended or expired, so that it still counts.
--
-- ADD COLUMN keeps the table, its foreign keys and its indexes (no
-- rebuild): a constant default and a check on the new column only are
-- allowed by SQLite.
ALTER TABLE drop_links ADD COLUMN expires_at INTEGER;
ALTER TABLE drop_links ADD COLUMN max_deposits_per_hour INTEGER NOT NULL DEFAULT 20
    CHECK (max_deposits_per_hour BETWEEN 1 AND 1000);
ALTER TABLE deposit_sessions ADD COLUMN used_at INTEGER;
CREATE INDEX deposit_sessions_drop_link_used_idx ON deposit_sessions (tenant_id, drop_link_id, used_at)
    WHERE used_at IS NOT NULL;

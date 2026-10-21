-- 0007_cleanup (PostgreSQL): periodic cleanup task (spec 20). Keep in sync
-- with migrations/sqlite/0007_cleanup.sql. Timestamps are Unix
-- milliseconds (UTC). The row-level security policy of 0004 covers the new
-- transfer column; no table is added.

-- ended_at is when the transfer reached a terminal status (rejected,
-- expired or deleted), set once by the store on that transition and never
-- moved afterwards. The cleanup task deletes the rows of a terminal
-- transfer 30 days after ended_at (its link answers "gone" until then).
ALTER TABLE transfers
    ADD COLUMN ended_at BIGINT,
    ADD CONSTRAINT transfers_ended_at_check
        CHECK (ended_at IS NULL OR status IN ('rejected', 'expired', 'deleted'));

-- Backfill: the transfers already terminal get the migration time, the
-- only time known for all of them (no column records when a transfer was
-- rejected or deleted). It is conservative: their rows are kept 30 days
-- after the upgrade, never less than after their real end.
UPDATE transfers SET ended_at = CAST(extract(epoch FROM clock_timestamp()) * 1000 AS BIGINT)
WHERE status IN ('rejected', 'expired', 'deleted');

-- Purge of the terminal transfers of a tenant, oldest end first.
CREATE INDEX transfers_ended_idx ON transfers (tenant_id, ended_at, id) WHERE ended_at IS NOT NULL;
-- Expiry sweep across tenants (system query, keyset pagination): available
-- transfers by expiry (the scanning ones use transfers_scanning_idx of 0005).
CREATE INDEX transfers_expiry_idx ON transfers (expires_at, tenant_id, id) WHERE status = 'available';
-- Rejected transfers that may still hold file keys, across tenants.
CREATE INDEX transfers_rejected_idx ON transfers (ended_at, id) WHERE status = 'rejected';
-- Abandoned uploads across tenants, oldest creation first.
CREATE INDEX transfers_uploading_idx ON transfers (created_at, tenant_id, id) WHERE status = 'uploading';

-- Purges of the deposit tables, per tenant.
CREATE INDEX verification_challenges_created_idx ON verification_challenges (tenant_id, created_at);
CREATE INDEX deposit_sessions_expires_idx ON deposit_sessions (tenant_id, expires_at);
CREATE INDEX verified_addresses_last_used_idx ON verified_addresses (tenant_id, last_used_at);

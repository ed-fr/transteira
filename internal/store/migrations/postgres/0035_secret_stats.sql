-- 0035_secret_stats (PostgreSQL): the daily usage counters of a tenant also
-- count the one-time secrets created (statistics, spec 21.2, field
-- secretsCreated). Keep in sync with migrations/sqlite/0035_secret_stats.sql.
-- The RLS policies of the table are kept.
--
-- Additive only: one new column with a constant default. A secret is
-- counted on the day of its creation, like the secret.created audit event,
-- whatever happened to it afterwards. No backfill: the secrets created
-- before this migration (2.1 development builds only) are not counted.
ALTER TABLE tenant_daily_stats ADD COLUMN secrets_created BIGINT NOT NULL DEFAULT 0
    CHECK (secrets_created >= 0);

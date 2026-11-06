-- 0031_drop_link_challenges (PostgreSQL): verification codes sent for a
-- permanent drop link (V2, feature F5). Keep in sync with
-- migrations/sqlite/0031_drop_link_challenges.sql, which documents the
-- column. Timestamps are Unix milliseconds (UTC). Conventions of 0001_init:
-- "C" collation on identifiers. See docs/architecture/data-model-v2.md,
-- section 2.6.
--
-- The table is altered in place: its row-level security and its policy
-- (verification_challenges_isolation) are kept.
ALTER TABLE verification_challenges
    ADD COLUMN drop_link_id TEXT COLLATE "C",
    ADD CONSTRAINT verification_challenges_drop_link_fkey
        FOREIGN KEY (tenant_id, drop_link_id) REFERENCES drop_links (tenant_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT verification_challenges_drop_link_check
        CHECK (invitation_id IS NULL OR drop_link_id IS NULL),
    ADD CONSTRAINT verification_challenges_drop_link_purpose_check
        CHECK (purpose = 'deposit' OR drop_link_id IS NULL);

CREATE INDEX verification_challenges_drop_link_idx ON verification_challenges (tenant_id, drop_link_id)
    WHERE drop_link_id IS NOT NULL;

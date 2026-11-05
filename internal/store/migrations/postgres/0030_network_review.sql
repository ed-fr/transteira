-- 0030_network_review (PostgreSQL): confirmation of the internal network
-- rules of a tenant (V2, configuration import, threat model T-307). Keep in
-- sync with migrations/sqlite/0030_network_review.sql, which documents the
-- column. Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v2.md, section 2.5.
--
-- The tenants table is altered in place: its row-level security and its
-- policies (0001) are kept; the new column needs no policy of its own (the
-- tenants rows are written in the system scope only).
ALTER TABLE tenants ADD COLUMN network_reviewed_at BIGINT;

-- The migration runs in the system scope: the tenants and
-- tenant_network_rules policies let it read and update every row.
UPDATE tenants SET network_reviewed_at = updated_at
    WHERE EXISTS (SELECT 1 FROM tenant_network_rules r WHERE r.tenant_id = tenants.id);

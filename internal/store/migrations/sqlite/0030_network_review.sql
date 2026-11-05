-- 0030_network_review (SQLite): confirmation of the internal network rules
-- of a tenant (V2, configuration import, threat model T-307). Keep in sync
-- with migrations/postgres/0030_network_review.sql. Timestamps are Unix
-- milliseconds (UTC). See docs/architecture/data-model-v2.md, section 2.5.
--
-- network_reviewed_at is the time an administrator last saved the internal
-- IP ranges and mail domains of the tenant (administration or setup
-- wizard, even without a change), NULL when never. A configuration import
-- writes the rules of the source tenant without it: the "internal_networks"
-- and "internal_domains" items of the setup checklist, and the completion
-- of the setup that is not forced, wait for this confirmation.
ALTER TABLE tenants ADD COLUMN network_reviewed_at INTEGER;

-- Backfill: the rules of the existing tenants were entered by hand, so
-- they count as reviewed (at the last modification of the tenant); a
-- tenant without any rule stays NULL, its items being undone anyway.
UPDATE tenants SET network_reviewed_at = updated_at
    WHERE EXISTS (SELECT 1 FROM tenant_network_rules r WHERE r.tenant_id = tenants.id);

-- 0024_admin_activation_delivery (PostgreSQL): how an activation link of an
-- administrator was delivered and in which language (V1.2, feature F4).
-- Keep in sync with migrations/sqlite/0024_admin_activation_delivery.sql,
-- which documents the columns. See docs/architecture/data-model-v1.2.md,
-- section 2.3.
--
-- The table is altered in place: its row-level security and its policy
-- admin_activations_system (0008) are kept.
ALTER TABLE admin_activations
    ADD COLUMN delivery TEXT NOT NULL DEFAULT 'copy'
        CHECK (delivery IN ('copy', 'mail')),
    ADD COLUMN language TEXT
        CHECK (language IS NULL OR length(language) BETWEEN 2 AND 16);

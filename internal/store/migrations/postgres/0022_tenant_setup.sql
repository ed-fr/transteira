-- 0022_tenant_setup (PostgreSQL): setup state of a tenant, background
-- preset, last successful SMTP test and mail templates review mark (V1.2,
-- features F3 and F5). Keep in sync with
-- migrations/sqlite/0022_tenant_setup.sql, which documents the columns.
-- See docs/architecture/data-model-v1.2.md, section 2.1.
--
-- The tenants table is altered in place: its row-level security and its
-- policies (0001) are kept; the new columns need no policy of their own.
ALTER TABLE tenants
    ADD COLUMN setup_state TEXT NOT NULL DEFAULT 'active'
        CHECK (setup_state IN ('setup', 'active')),
    ADD COLUMN background_preset TEXT
        CHECK (background_preset IS NULL OR length(background_preset) BETWEEN 1 AND 32),
    ADD COLUMN smtp_tested_at BIGINT,
    ADD COLUMN mail_templates_reviewed_at BIGINT;

-- The default only backfills the existing tenants as active. It is dropped
-- at once (fail closed, threat model T-261): every insert must name the
-- setup state explicitly, a forgotten one fails instead of opening the
-- tenant. SQLite cannot drop a column default: there, the Go type of the
-- creation (an explicit state, no zero value accepted) is the guard.
ALTER TABLE tenants ALTER COLUMN setup_state DROP DEFAULT;

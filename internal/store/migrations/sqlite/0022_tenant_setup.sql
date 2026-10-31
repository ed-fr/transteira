-- 0022_tenant_setup (SQLite): setup state of a tenant, background preset,
-- last successful SMTP test and mail templates review mark (V1.2, features
-- F3 and F5). Keep in sync with migrations/postgres/0022_tenant_setup.sql.
-- Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v1.2.md, section 2.1.
--
-- setup_state is 'setup' while the tenant is being configured (the public
-- deposit paths answer 503 tenant-in-setup) and 'active' once the wizard is
-- completed. The default is 'active', so that every existing tenant stays
-- usable; the store writes the value explicitly on every insert (new
-- tenants: 'setup' unless the super admin asks for 'active').
--
-- background_preset is the id (stable slug) of the generated background
-- chosen for the tenant, NULL meaning the default one. The set of valid ids
-- is defined by the code (internal/branding), not by the database, so that
-- adding a preset needs no migration; the store validates the id.
--
-- smtp_tested_at is the time of the last successful test send with the
-- current SMTP configuration: set by the test, cleared (NULL) by the store
-- whenever the SMTP configuration changes. mail_templates_reviewed_at is
-- the time the admin marked the mail templates as reviewed in the wizard.
ALTER TABLE tenants ADD COLUMN setup_state TEXT NOT NULL DEFAULT 'active'
    CHECK (setup_state IN ('setup', 'active'));
ALTER TABLE tenants ADD COLUMN background_preset TEXT
    CHECK (background_preset IS NULL OR length(background_preset) BETWEEN 1 AND 32);
ALTER TABLE tenants ADD COLUMN smtp_tested_at INTEGER;
ALTER TABLE tenants ADD COLUMN mail_templates_reviewed_at INTEGER;

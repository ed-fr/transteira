-- 0009_tenant_config (PostgreSQL): tenant configuration from the
-- administration (spec 5, 6.5, 12.3 and 13). Keep in sync with
-- migrations/sqlite/0009_tenant_config.sql. Timestamps are Unix
-- milliseconds (UTC). Conventions of 0001_init: "C" collation on
-- identifiers, row-level security ENABLE + FORCE. The tenants policies of
-- 0001 cover the new tenant columns.

-- max_transfer_ceiling is the ceiling of max_transfer_bytes set by the
-- super admin (at most 20 GiB, spec 8.5): a delegated admin may only lower
-- the limit under it. The existing tenants get their current limit as
-- ceiling. status 'deleting' marks a tenant whose deletion has started:
-- it no longer resolves from its FQDN, and the deletion resumes after an
-- interruption. The colors are "#RRGGBB" (OpenAPI HexColor); the defaults
-- reach the WCAG AA contrast on white and with white text. has_logo and
-- has_background tell whether the tenant uploaded its own images, stored
-- in its folder.
ALTER TABLE tenants
    ADD COLUMN max_transfer_ceiling BIGINT NOT NULL DEFAULT 21474836480
        CHECK (max_transfer_ceiling >= max_transfer_bytes AND max_transfer_ceiling <= 21474836480),
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'deleting')),
    ADD COLUMN primary_color TEXT NOT NULL DEFAULT '#1F4E79'
        CHECK (primary_color ~ '^#[0-9A-Fa-f]{6}$'),
    ADD COLUMN accent_color TEXT NOT NULL DEFAULT '#C2410C'
        CHECK (accent_color ~ '^#[0-9A-Fa-f]{6}$'),
    ADD COLUMN has_logo BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN has_background BOOLEAN NOT NULL DEFAULT false;

-- The migration runs in the system scope: the tenants policies let it
-- update every row.
UPDATE tenants SET max_transfer_ceiling = max_transfer_bytes;

-- Resumption of the interrupted deletions.
CREATE INDEX tenants_status_idx ON tenants (status, id);

-- Mail templates customized by a tenant (spec 12.3), one per template and
-- language; without a row, the default template applies. updated_by is the
-- administrator who saved it ('' when unknown); it is not a foreign key,
-- like the audit log actors. The bodies use the {{name}} variable syntax of
-- internal/mail and the HTML one is sanitized before being stored.
CREATE TABLE tenant_email_templates (
    tenant_id    TEXT   COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    template_key TEXT   COLLATE "C" NOT NULL CHECK (template_key IN ('verification-code', 'transfer-notification', 'transfer-confirmation', 'first-download', 'file-problems', 'file-not-scanned', 'invitation', 'quota-warning', 'quota-reached', 'disk-alert', 'antivirus-unavailable')),
    language     TEXT   COLLATE "C" NOT NULL CHECK (language IN ('fr', 'en')),
    subject      TEXT   NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    body_html    TEXT   NOT NULL CHECK (length(body_html) <= 100000),
    body_text    TEXT   NOT NULL CHECK (length(body_text) <= 100000),
    updated_at   BIGINT NOT NULL,
    updated_by   TEXT   COLLATE "C" NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64),
    PRIMARY KEY (tenant_id, template_key, language)
);

-- Legal notice and privacy policy of a tenant (spec 13), in limited
-- Markdown, one per document and language.
CREATE TABLE tenant_legal_documents (
    tenant_id  TEXT   COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    document   TEXT   COLLATE "C" NOT NULL CHECK (document IN ('legal-notice', 'privacy-policy')),
    language   TEXT   COLLATE "C" NOT NULL CHECK (language IN ('fr', 'en')),
    content    TEXT   NOT NULL CHECK (length(content) <= 100000),
    updated_at BIGINT NOT NULL,
    updated_by TEXT   COLLATE "C" NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64),
    PRIMARY KEY (tenant_id, document, language)
);

ALTER TABLE tenant_email_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_email_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_email_templates_isolation ON tenant_email_templates
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

ALTER TABLE tenant_legal_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_legal_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_legal_documents_isolation ON tenant_legal_documents
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

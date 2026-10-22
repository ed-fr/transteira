-- 0009_tenant_config (SQLite): tenant configuration from the
-- administration (spec 5, 6.5, 12.3 and 13). Keep in sync with
-- migrations/postgres/0009_tenant_config.sql. Timestamps are Unix
-- milliseconds (UTC).

-- max_transfer_ceiling is the ceiling of max_transfer_bytes set by the
-- super admin (at most 20 GiB, spec 8.5): a delegated admin may only lower
-- the limit under it. The existing tenants get their current limit as
-- ceiling. status 'deleting' marks a tenant whose deletion has started:
-- it no longer resolves from its FQDN, and the deletion resumes after an
-- interruption. The colors are "#RRGGBB" (OpenAPI HexColor); the defaults
-- reach the WCAG AA contrast on white and with white text. has_logo and
-- has_background tell whether the tenant uploaded its own images, stored
-- in its folder.
ALTER TABLE tenants ADD COLUMN max_transfer_ceiling INTEGER NOT NULL DEFAULT 21474836480
    CHECK (max_transfer_ceiling >= max_transfer_bytes AND max_transfer_ceiling <= 21474836480);
ALTER TABLE tenants ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'deleting'));
ALTER TABLE tenants ADD COLUMN primary_color TEXT NOT NULL DEFAULT '#1F4E79'
    CHECK (length(primary_color) = 7 AND primary_color GLOB '#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]');
ALTER TABLE tenants ADD COLUMN accent_color TEXT NOT NULL DEFAULT '#C2410C'
    CHECK (length(accent_color) = 7 AND accent_color GLOB '#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]');
ALTER TABLE tenants ADD COLUMN has_logo INTEGER NOT NULL DEFAULT 0 CHECK (has_logo IN (0, 1));
ALTER TABLE tenants ADD COLUMN has_background INTEGER NOT NULL DEFAULT 0 CHECK (has_background IN (0, 1));

UPDATE tenants SET max_transfer_ceiling = max_transfer_bytes;

-- Resumption of the interrupted deletions.
CREATE INDEX tenants_status_idx ON tenants (status, id);

-- Mail templates customized by a tenant (spec 12.3), one per template and
-- language; without a row, the default template applies. updated_by is the
-- administrator who saved it ('' when unknown); it is not a foreign key,
-- like the audit log actors. The bodies use the {{name}} variable syntax of
-- internal/mail and the HTML one is sanitized before being stored.
CREATE TABLE tenant_email_templates (
    tenant_id    TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    template_key TEXT    NOT NULL CHECK (template_key IN ('verification-code', 'transfer-notification', 'transfer-confirmation', 'first-download', 'file-problems', 'file-not-scanned', 'invitation', 'quota-warning', 'quota-reached', 'disk-alert', 'antivirus-unavailable')),
    language     TEXT    NOT NULL CHECK (language IN ('fr', 'en')),
    subject      TEXT    NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    body_html    TEXT    NOT NULL CHECK (length(body_html) <= 100000),
    body_text    TEXT    NOT NULL CHECK (length(body_text) <= 100000),
    updated_at   INTEGER NOT NULL,
    updated_by   TEXT    NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64),
    PRIMARY KEY (tenant_id, template_key, language)
) STRICT, WITHOUT ROWID;

-- Legal notice and privacy policy of a tenant (spec 13), in limited
-- Markdown, one per document and language.
CREATE TABLE tenant_legal_documents (
    tenant_id  TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    document   TEXT    NOT NULL CHECK (document IN ('legal-notice', 'privacy-policy')),
    language   TEXT    NOT NULL CHECK (language IN ('fr', 'en')),
    content    TEXT    NOT NULL CHECK (length(content) <= 100000),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64),
    PRIMARY KEY (tenant_id, document, language)
) STRICT, WITHOUT ROWID;

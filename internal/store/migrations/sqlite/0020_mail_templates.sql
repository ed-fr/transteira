-- 0020_mail_templates (SQLite): the V1.1 mails can be customized per
-- tenant (spec 12.2 and 12.3). Keep in sync with
-- migrations/postgres/0020_mail_templates.sql. Timestamps are Unix
-- milliseconds (UTC). See docs/architecture/data-model-v1.1.md, section 2.8.
--
-- tenant_email_templates.template_key gains expiry-reminder, abuse-alert,
-- abuse-report, my-transfers-link and recipient-verification-code. No
-- table references tenant_email_templates: plain rebuild, as in 0005.
-- Without a row, the default template applies: no backfill.
CREATE TABLE tenant_email_templates_0020 (
    tenant_id    TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    template_key TEXT    NOT NULL CHECK (template_key IN ('verification-code', 'transfer-notification', 'transfer-confirmation', 'first-download', 'file-problems', 'file-not-scanned', 'invitation', 'quota-warning', 'quota-reached', 'disk-alert', 'antivirus-unavailable', 'expiry-reminder', 'abuse-alert', 'abuse-report', 'my-transfers-link', 'recipient-verification-code')),
    language     TEXT    NOT NULL CHECK (language IN ('fr', 'en')),
    subject      TEXT    NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    body_html    TEXT    NOT NULL CHECK (length(body_html) <= 100000),
    body_text    TEXT    NOT NULL CHECK (length(body_text) <= 100000),
    updated_at   INTEGER NOT NULL,
    updated_by   TEXT    NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64),
    PRIMARY KEY (tenant_id, template_key, language)
) STRICT, WITHOUT ROWID;

INSERT INTO tenant_email_templates_0020 (tenant_id, template_key, language, subject, body_html, body_text,
    updated_at, updated_by)
SELECT tenant_id, template_key, language, subject, body_html, body_text, updated_at, updated_by
FROM tenant_email_templates;

DROP TABLE tenant_email_templates;
ALTER TABLE tenant_email_templates_0020 RENAME TO tenant_email_templates;

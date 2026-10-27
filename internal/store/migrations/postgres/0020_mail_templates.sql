-- 0020_mail_templates (PostgreSQL): the V1.1 mails can be customized per
-- tenant (spec 12.2 and 12.3). Keep in sync with
-- migrations/sqlite/0020_mail_templates.sql. See
-- docs/architecture/data-model-v1.1.md, section 2.8.
ALTER TABLE tenant_email_templates
    DROP CONSTRAINT tenant_email_templates_template_key_check,
    ADD CONSTRAINT tenant_email_templates_template_key_check
        CHECK (template_key IN ('verification-code', 'transfer-notification', 'transfer-confirmation', 'first-download',
                                'file-problems', 'file-not-scanned', 'invitation', 'quota-warning', 'quota-reached',
                                'disk-alert', 'antivirus-unavailable', 'expiry-reminder', 'abuse-alert', 'abuse-report',
                                'my-transfers-link', 'recipient-verification-code'));

-- 0016_confidentiality (PostgreSQL): confidentiality levels and recipient
-- domain rules of a tenant (spec 8.3 and 8.4). Keep in sync with
-- migrations/sqlite/0016_confidentiality.sql, which documents the columns.
-- Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v1.1.md, section 2.4.

CREATE TABLE confidentiality_levels (
    tenant_id                      TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    key                            TEXT    COLLATE "C" NOT NULL CHECK (length(key) BETWEEN 1 AND 32),
    position                       INTEGER NOT NULL CHECK (position BETWEEN 0 AND 9),
    labels                         TEXT    NOT NULL,
    descriptions                   TEXT    NOT NULL DEFAULT '{}',
    is_default                     BOOLEAN NOT NULL DEFAULT false,
    require_recipient_verification BOOLEAN NOT NULL DEFAULT false,
    require_password               BOOLEAN NOT NULL DEFAULT false,
    allowed_validity_days          INTEGER NOT NULL DEFAULT 7 CHECK (allowed_validity_days BETWEEN 1 AND 7),
    internal_recipients_only       BOOLEAN NOT NULL DEFAULT false,
    force_delete_after_download    BOOLEAN NOT NULL DEFAULT false,
    max_downloads_cap              INTEGER CHECK (max_downloads_cap BETWEEN 1 AND 1000),
    updated_at                     BIGINT  NOT NULL,
    updated_by                     TEXT    NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64),
    PRIMARY KEY (tenant_id, key),
    UNIQUE (tenant_id, position)
);

CREATE UNIQUE INDEX confidentiality_levels_default_idx ON confidentiality_levels (tenant_id) WHERE is_default;

-- Seed data for every existing tenant (see the SQLite migration).
INSERT INTO confidentiality_levels (tenant_id, key, position, labels, is_default, require_recipient_verification,
    require_password, allowed_validity_days, internal_recipients_only, updated_at)
SELECT id, 'public', 0, '{"fr":"Public","en":"Public"}', false, false, false, 7, false, 0 FROM tenants;
INSERT INTO confidentiality_levels (tenant_id, key, position, labels, is_default, require_recipient_verification,
    require_password, allowed_validity_days, internal_recipients_only, updated_at)
SELECT id, 'internal', 1, '{"fr":"Interne","en":"Internal"}', true, false, false, 7, false, 0 FROM tenants;
INSERT INTO confidentiality_levels (tenant_id, key, position, labels, is_default, require_recipient_verification,
    require_password, allowed_validity_days, internal_recipients_only, updated_at)
SELECT id, 'confidential', 2, '{"fr":"Confidentiel","en":"Confidential"}', false, true, true, 3, true, 0 FROM tenants;

CREATE TABLE recipient_domain_rules (
    tenant_id  TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('allow', 'deny')),
    domain     TEXT    COLLATE "C" NOT NULL CHECK (length(domain) BETWEEN 1 AND 253),
    created_at BIGINT  NOT NULL,
    PRIMARY KEY (tenant_id, kind, domain)
);

ALTER TABLE confidentiality_levels ENABLE ROW LEVEL SECURITY;
ALTER TABLE confidentiality_levels FORCE ROW LEVEL SECURITY;
CREATE POLICY confidentiality_levels_isolation ON confidentiality_levels
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

ALTER TABLE recipient_domain_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE recipient_domain_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY recipient_domain_rules_isolation ON recipient_domain_rules
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

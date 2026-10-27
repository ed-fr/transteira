-- 0016_confidentiality (SQLite): confidentiality levels and recipient
-- domain rules of a tenant (spec 8.3 and 8.4). Keep in sync with
-- migrations/postgres/0016_confidentiality.sql. Timestamps are Unix
-- milliseconds (UTC); booleans are INTEGER 0/1. See
-- docs/architecture/data-model-v1.1.md, section 2.4.

-- Confidentiality levels: 1 to 10 per tenant with exactly one default
-- (store; the partial unique index allows at most one). key matches
-- ^[a-z][a-z0-9_-]{0,31}$ (store). labels and descriptions are JSON
-- objects by language. allowed_validity_days is a bit mask of the
-- durations (1 = 1 day, 2 = 7 days, 4 = 30 days); max_downloads_cap NULL is
-- no cap. Transfers keep a snapshot of their level (no foreign key).
CREATE TABLE confidentiality_levels (
    tenant_id                      TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    key                            TEXT    NOT NULL CHECK (length(key) BETWEEN 1 AND 32),
    position                       INTEGER NOT NULL CHECK (position BETWEEN 0 AND 9),
    labels                         TEXT    NOT NULL,
    descriptions                   TEXT    NOT NULL DEFAULT '{}',
    is_default                     INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    require_recipient_verification INTEGER NOT NULL DEFAULT 0 CHECK (require_recipient_verification IN (0, 1)),
    require_password               INTEGER NOT NULL DEFAULT 0 CHECK (require_password IN (0, 1)),
    allowed_validity_days          INTEGER NOT NULL DEFAULT 7 CHECK (allowed_validity_days BETWEEN 1 AND 7),
    internal_recipients_only       INTEGER NOT NULL DEFAULT 0 CHECK (internal_recipients_only IN (0, 1)),
    force_delete_after_download    INTEGER NOT NULL DEFAULT 0 CHECK (force_delete_after_download IN (0, 1)),
    max_downloads_cap              INTEGER CHECK (max_downloads_cap BETWEEN 1 AND 1000),
    updated_at                     INTEGER NOT NULL,
    updated_by                     TEXT    NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64),
    PRIMARY KEY (tenant_id, key),
    UNIQUE (tenant_id, position)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX confidentiality_levels_default_idx ON confidentiality_levels (tenant_id) WHERE is_default = 1;

-- Seed data for every existing tenant (Tenants.Create seeds the same rows
-- for the new ones): the default level is 'internal' without any rule, so
-- that the upgrade changes nothing for the users.
INSERT INTO confidentiality_levels (tenant_id, key, position, labels, is_default, require_recipient_verification,
    require_password, allowed_validity_days, internal_recipients_only, updated_at)
SELECT id, 'public', 0, '{"fr":"Public","en":"Public"}', 0, 0, 0, 7, 0, 0 FROM tenants;
INSERT INTO confidentiality_levels (tenant_id, key, position, labels, is_default, require_recipient_verification,
    require_password, allowed_validity_days, internal_recipients_only, updated_at)
SELECT id, 'internal', 1, '{"fr":"Interne","en":"Internal"}', 1, 0, 0, 7, 0, 0 FROM tenants;
INSERT INTO confidentiality_levels (tenant_id, key, position, labels, is_default, require_recipient_verification,
    require_password, allowed_validity_days, internal_recipients_only, updated_at)
SELECT id, 'confidential', 2, '{"fr":"Confidentiel","en":"Confidential"}', 0, 1, 1, 3, 1, 0 FROM tenants;

-- Recipient domain rules: a rule for a domain also matches its subdomains,
-- deny wins over allow, a non-empty allow list accepts only its domains.
-- domain is a lower-case A-label without leading dot. At most 500 entries
-- per kind (store). No personal data.
CREATE TABLE recipient_domain_rules (
    tenant_id  TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('allow', 'deny')),
    domain     TEXT    NOT NULL CHECK (length(domain) BETWEEN 1 AND 253),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, kind, domain)
) STRICT, WITHOUT ROWID;

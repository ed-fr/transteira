-- 0029_transfer_options_v2 (PostgreSQL): permanent drop links, link-only
-- transfers and end-to-end encrypted transfers (V2, features F5, F6 and
-- F7). Keep in sync with migrations/sqlite/0029_transfer_options_v2.sql,
-- which documents the columns. Timestamps are Unix milliseconds (UTC).
-- Conventions of 0001_init: "C" collation on identifiers, row-level
-- security ENABLE + FORCE. See docs/architecture/data-model-v2.md,
-- section 2.4.
--
-- No rebuild is needed: the altered tables (tenants,
-- confidentiality_levels, transfers, transfer_files, deposit_sessions)
-- keep their row-level security and policies. Check constraints are
-- replaced under their existing names.
ALTER TABLE tenants
    ADD COLUMN link_only_allowed BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN e2e_policy TEXT NOT NULL DEFAULT 'forbidden'
        CHECK (e2e_policy IN ('forbidden', 'allowed', 'required'));

ALTER TABLE confidentiality_levels
    ADD COLUMN link_only_allowed BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN e2e_policy TEXT
        CHECK (e2e_policy IS NULL OR e2e_policy IN ('forbidden', 'allowed', 'required'));

-- recipients is JSONB here (TEXT in SQLite, checked by json_valid): the
-- type guarantees valid JSON, the check that it is an array.
CREATE TABLE drop_links (
    id                    TEXT    COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id             TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash            BYTEA   NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    label                 TEXT    NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
    recipients            JSONB   NOT NULL CHECK (octet_length(recipients::text) BETWEEN 2 AND 65536
                                  AND jsonb_typeof(recipients) = 'array'),
    validity_days         INTEGER NOT NULL CHECK (validity_days IN (1, 7, 30)),
    confidentiality_level TEXT    COLLATE "C" CHECK (confidentiality_level IS NULL OR length(confidentiality_level) BETWEEN 1 AND 32),
    enabled               BOOLEAN NOT NULL DEFAULT true,
    created_by            TEXT    COLLATE "C" NOT NULL CHECK (length(created_by) BETWEEN 1 AND 64),
    created_at            BIGINT  NOT NULL,
    updated_at            BIGINT  NOT NULL,
    last_used_at          BIGINT,
    revoked_at            BIGINT,
    UNIQUE (tenant_id, id)
);

CREATE INDEX drop_links_tenant_created_idx ON drop_links (tenant_id, created_at, id);

-- Lifecycle purge of links revoked for 12 months (data model, section 4).
CREATE INDEX drop_links_revoked_idx ON drop_links (revoked_at, id) WHERE revoked_at IS NOT NULL;

ALTER TABLE drop_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE drop_links FORCE ROW LEVEL SECURITY;
CREATE POLICY drop_links_isolation ON drop_links
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

ALTER TABLE transfers
    ADD COLUMN link_only BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN e2e BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN drop_link_id TEXT COLLATE "C",
    ADD COLUMN e2e_message TEXT CHECK (e2e_message IS NULL OR octet_length(e2e_message) BETWEEN 1 AND 32768),
    DROP CONSTRAINT transfers_sender_kind_check,
    ADD CONSTRAINT transfers_sender_kind_check
        CHECK (sender_kind IN ('internal', 'external', 'internal_remote', 'reply', 'drop_link')),
    ADD CONSTRAINT transfers_drop_link_check CHECK ((sender_kind = 'drop_link') = (drop_link_id IS NOT NULL)),
    ADD CONSTRAINT transfers_link_only_check CHECK (NOT link_only OR link_mode = 'shared'),
    ADD CONSTRAINT transfers_e2e_only_message_check CHECK (e2e OR e2e_message IS NULL),
    ADD CONSTRAINT transfers_e2e_plain_message_check CHECK (NOT e2e OR message = ''),
    ADD CONSTRAINT transfers_e2e_drop_link_check CHECK (NOT e2e OR sender_kind <> 'drop_link'),
    ADD CONSTRAINT transfers_drop_link_fkey
        FOREIGN KEY (tenant_id, drop_link_id) REFERENCES drop_links (tenant_id, id);

CREATE INDEX transfers_drop_link_idx ON transfers (tenant_id, drop_link_id, created_at)
    WHERE drop_link_id IS NOT NULL;

ALTER TABLE transfer_files
    ADD COLUMN e2e_metadata TEXT
        CHECK (e2e_metadata IS NULL OR octet_length(e2e_metadata) BETWEEN 1 AND 5462),
    DROP CONSTRAINT transfer_files_scan_status_check,
    ADD CONSTRAINT transfer_files_scan_status_check
        CHECK (scan_status IN ('pending', 'scanning', 'clean', 'infected', 'not_scanned_too_large',
            'not_scanned_encrypted', 'not_scanned_disabled', 'scan_error', 'not_scanned_e2e')),
    ADD CONSTRAINT transfer_files_e2e_check CHECK (scan_status <> 'not_scanned_e2e' OR e2e_metadata IS NOT NULL);

ALTER TABLE deposit_sessions
    ADD COLUMN drop_link_id TEXT COLLATE "C",
    DROP CONSTRAINT deposit_sessions_kind_check,
    ADD CONSTRAINT deposit_sessions_kind_check
        CHECK (kind IN ('internal', 'external', 'internal_remote', 'reply', 'drop_link')),
    ADD CONSTRAINT deposit_sessions_drop_link_check CHECK ((kind = 'drop_link') = (drop_link_id IS NOT NULL)),
    ADD CONSTRAINT deposit_sessions_drop_link_fkey
        FOREIGN KEY (tenant_id, drop_link_id) REFERENCES drop_links (tenant_id, id) ON DELETE CASCADE;

CREATE INDEX deposit_sessions_drop_link_idx ON deposit_sessions (tenant_id, drop_link_id)
    WHERE drop_link_id IS NOT NULL;

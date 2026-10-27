-- 0015_recipient_links (PostgreSQL): per-recipient links, their
-- verification and tracking, and the reply sessions (spec 6.4 and 10).
-- Keep in sync with migrations/sqlite/0015_recipient_links.sql, which
-- documents the columns. Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v1.1.md, section 2.3.

CREATE TABLE recipient_links (
    id                  TEXT    COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id           TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    transfer_id         TEXT    COLLATE "C" NOT NULL,
    position            INTEGER NOT NULL CHECK (position >= 0),
    token_hash          BYTEA   NOT NULL CHECK (length(token_hash) = 32),
    token_key_id        TEXT    COLLATE "C" REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    verified_at         BIGINT,
    first_downloaded_at BIGINT,
    last_downloaded_at  BIGINT,
    completed_at        BIGINT,
    download_count      INTEGER NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    reminder_sent_at    BIGINT,
    created_at          BIGINT  NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, transfer_id, position),
    CHECK ((first_downloaded_at IS NULL) = (last_downloaded_at IS NULL)),
    CHECK (completed_at IS NULL OR first_downloaded_at IS NOT NULL),
    FOREIGN KEY (tenant_id, transfer_id, position) REFERENCES transfer_recipients (tenant_id, transfer_id, position) ON DELETE CASCADE
);

CREATE UNIQUE INDEX recipient_links_token_global_idx ON recipient_links (token_hash);
CREATE UNIQUE INDEX recipient_links_token_idx ON recipient_links (tenant_id, token_hash);
CREATE UNIQUE INDEX recipient_links_token_key_idx ON recipient_links (token_key_id);

CREATE TABLE recipient_downloads (
    tenant_id         TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    recipient_link_id TEXT    COLLATE "C" NOT NULL,
    item              TEXT    COLLATE "C" NOT NULL CHECK (item = 'archive' OR item LIKE 'fil\_%'),
    first_at          BIGINT  NOT NULL,
    last_at           BIGINT  NOT NULL,
    count             INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
    completed_at      BIGINT,
    PRIMARY KEY (tenant_id, recipient_link_id, item),
    FOREIGN KEY (tenant_id, recipient_link_id) REFERENCES recipient_links (tenant_id, id) ON DELETE CASCADE
);

-- Same rules as the SQLite table checks, as named table constraints.
ALTER TABLE verification_challenges
    ADD COLUMN purpose TEXT NOT NULL DEFAULT 'deposit' CHECK (purpose IN ('deposit', 'recipient')),
    ADD COLUMN recipient_link_id TEXT COLLATE "C",
    ADD COLUMN recipient_intent TEXT CHECK (recipient_intent IN ('download', 'reply')),
    ADD CONSTRAINT verification_challenges_recipient_link_fkey
        FOREIGN KEY (tenant_id, recipient_link_id) REFERENCES recipient_links (tenant_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT verification_challenges_invitation_purpose_check
        CHECK (purpose = 'deposit' OR invitation_id IS NULL),
    ADD CONSTRAINT verification_challenges_link_check
        CHECK ((recipient_link_id IS NOT NULL) = (purpose = 'recipient')),
    ADD CONSTRAINT verification_challenges_intent_check
        CHECK ((recipient_intent IS NULL) = (purpose = 'deposit'));

CREATE INDEX verification_challenges_link_idx ON verification_challenges (tenant_id, recipient_link_id, created_at)
    WHERE recipient_link_id IS NOT NULL;

ALTER TABLE deposit_sessions
    ADD COLUMN reply_to_transfer_id TEXT COLLATE "C",
    ADD COLUMN recipient_link_id TEXT COLLATE "C",
    DROP CONSTRAINT deposit_sessions_kind_check,
    ADD CONSTRAINT deposit_sessions_kind_check
        CHECK (kind IN ('internal', 'external', 'internal_remote', 'reply')),
    ADD CONSTRAINT deposit_sessions_reply_check
        CHECK ((kind = 'reply') = (reply_to_transfer_id IS NOT NULL)),
    ADD CONSTRAINT deposit_sessions_reply_link_check
        CHECK ((kind = 'reply') = (recipient_link_id IS NOT NULL)),
    ADD CONSTRAINT deposit_sessions_reply_transfer_fkey
        FOREIGN KEY (tenant_id, reply_to_transfer_id) REFERENCES transfers (tenant_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT deposit_sessions_recipient_link_fkey
        FOREIGN KEY (tenant_id, recipient_link_id) REFERENCES recipient_links (tenant_id, id) ON DELETE CASCADE;

CREATE INDEX deposit_sessions_reply_idx ON deposit_sessions (tenant_id, reply_to_transfer_id)
    WHERE reply_to_transfer_id IS NOT NULL;

ALTER TABLE recipient_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE recipient_links FORCE ROW LEVEL SECURITY;
CREATE POLICY recipient_links_isolation ON recipient_links
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

ALTER TABLE recipient_downloads ENABLE ROW LEVEL SECURITY;
ALTER TABLE recipient_downloads FORCE ROW LEVEL SECURITY;
CREATE POLICY recipient_downloads_isolation ON recipient_downloads
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

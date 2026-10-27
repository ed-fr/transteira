-- 0015_recipient_links (SQLite): per-recipient links, their verification
-- and tracking, and the reply sessions (spec 6.4 and 10). Keep in sync with
-- migrations/postgres/0015_recipient_links.sql. Timestamps are Unix
-- milliseconds (UTC); booleans are INTEGER 0/1. See
-- docs/architecture/data-model-v1.1.md, section 2.3.

-- One link per recipient of a per_recipient transfer, created when the
-- transfer becomes available. id is "rcl_" + ULID. token_hash is the
-- SHA-256 of the "dl_" link token, unique across tenants; token_key_id its
-- sealed copy (wrapped key of purpose 'secret'), used only to mail the link
-- again to its own recipient: ON DELETE SET NULL, the store destroys it
-- first and checks the tenant. The recipient address is read from
-- transfer_recipients through the composite foreign key. verified_at is for
-- display only (the proof is the __Host-tt_rv cookie). completed_at is the
-- first complete download through the link (D2). reminder_sent_at marks the
-- expiry reminder of the current expiry date.
CREATE TABLE recipient_links (
    id                  TEXT    NOT NULL PRIMARY KEY,
    tenant_id           TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    transfer_id         TEXT    NOT NULL,
    position            INTEGER NOT NULL CHECK (position >= 0),
    token_hash          BLOB    NOT NULL CHECK (length(token_hash) = 32),
    token_key_id        TEXT    REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    verified_at         INTEGER,
    first_downloaded_at INTEGER,
    last_downloaded_at  INTEGER,
    completed_at        INTEGER,
    download_count      INTEGER NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    reminder_sent_at    INTEGER,
    created_at          INTEGER NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, transfer_id, position),
    CHECK ((first_downloaded_at IS NULL) = (last_downloaded_at IS NULL)),
    CHECK (completed_at IS NULL OR first_downloaded_at IS NOT NULL),
    FOREIGN KEY (tenant_id, transfer_id, position) REFERENCES transfer_recipients (tenant_id, transfer_id, position) ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX recipient_links_token_global_idx ON recipient_links (token_hash);
CREATE UNIQUE INDEX recipient_links_token_idx ON recipient_links (tenant_id, token_hash);
CREATE UNIQUE INDEX recipient_links_token_key_idx ON recipient_links (token_key_id);

-- Per-recipient tracking (spec 10): one row per link and item, item being
-- a file id or 'archive' (the ZIP). Written once per download start and
-- once at completion, never per range.
CREATE TABLE recipient_downloads (
    tenant_id         TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    recipient_link_id TEXT    NOT NULL,
    item              TEXT    NOT NULL CHECK (item = 'archive' OR item GLOB 'fil_*'),
    first_at          INTEGER NOT NULL,
    last_at           INTEGER NOT NULL,
    count             INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
    completed_at      INTEGER,
    PRIMARY KEY (tenant_id, recipient_link_id, item),
    FOREIGN KEY (tenant_id, recipient_link_id) REFERENCES recipient_links (tenant_id, id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- Verification codes: purpose 'deposit' (V1) or 'recipient' (a recipient
-- link, for a download or a reply: recipient_intent). Rebuilt to add the
-- composite foreign key to the link (SQLite cannot add one with ALTER
-- TABLE); no table references verification_challenges, and the indexes of
-- 0003 and 0007 are recreated.
CREATE TABLE verification_challenges_0015 (
    id                 TEXT    NOT NULL PRIMARY KEY,
    tenant_id          TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email              TEXT    NOT NULL,
    code_mac           BLOB    NOT NULL,
    attempts_remaining INTEGER NOT NULL CHECK (attempts_remaining BETWEEN 0 AND 2),
    invitation_id      TEXT,
    client_ip          TEXT    NOT NULL,
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    consumed_at        INTEGER,
    purpose            TEXT    NOT NULL DEFAULT 'deposit' CHECK (purpose IN ('deposit', 'recipient')),
    recipient_link_id  TEXT,
    recipient_intent   TEXT    CHECK (recipient_intent IN ('download', 'reply')),
    CHECK (purpose = 'deposit' OR invitation_id IS NULL),
    CHECK ((recipient_link_id IS NOT NULL) = (purpose = 'recipient')),
    CHECK ((recipient_intent IS NULL) = (purpose = 'deposit')),
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, recipient_link_id) REFERENCES recipient_links (tenant_id, id) ON DELETE CASCADE
) STRICT;

INSERT INTO verification_challenges_0015 (id, tenant_id, email, code_mac, attempts_remaining, invitation_id, client_ip,
    created_at, expires_at, consumed_at)
SELECT id, tenant_id, email, code_mac, attempts_remaining, invitation_id, client_ip, created_at, expires_at, consumed_at
FROM verification_challenges;

DROP TABLE verification_challenges;
ALTER TABLE verification_challenges_0015 RENAME TO verification_challenges;

CREATE INDEX verification_challenges_email_idx ON verification_challenges (tenant_id, email, created_at);
CREATE INDEX verification_challenges_ip_idx ON verification_challenges (tenant_id, client_ip, created_at);
CREATE INDEX verification_challenges_created_idx ON verification_challenges (tenant_id, created_at);
-- Recipient code budget (D22) and cascade lookups.
CREATE INDEX verification_challenges_link_idx ON verification_challenges (tenant_id, recipient_link_id, created_at)
    WHERE recipient_link_id IS NOT NULL;

-- Deposit sessions: kinds 'internal_remote' (spec 6.4) and 'reply' (spec
-- 10). A reply session belongs to the recipient link that verified it and
-- dies with the source transfer or the link. No table references
-- deposit_sessions: plain rebuild, as in 0005.
CREATE TABLE deposit_sessions_0015 (
    id                   TEXT    NOT NULL PRIMARY KEY,
    tenant_id            TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash           BLOB    NOT NULL UNIQUE,
    email                TEXT    NOT NULL,
    kind                 TEXT    NOT NULL CHECK (kind IN ('internal', 'external', 'internal_remote', 'reply')),
    invitation_id        TEXT,
    created_at           INTEGER NOT NULL,
    expires_at           INTEGER NOT NULL,
    ended_at             INTEGER,
    reply_to_transfer_id TEXT,
    recipient_link_id    TEXT,
    CHECK ((kind = 'reply') = (reply_to_transfer_id IS NOT NULL)),
    CHECK ((kind = 'reply') = (recipient_link_id IS NOT NULL)),
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, reply_to_transfer_id) REFERENCES transfers (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, recipient_link_id) REFERENCES recipient_links (tenant_id, id) ON DELETE CASCADE
) STRICT;

INSERT INTO deposit_sessions_0015 (id, tenant_id, token_hash, email, kind, invitation_id, created_at, expires_at, ended_at)
SELECT id, tenant_id, token_hash, email, kind, invitation_id, created_at, expires_at, ended_at
FROM deposit_sessions;

DROP TABLE deposit_sessions;
ALTER TABLE deposit_sessions_0015 RENAME TO deposit_sessions;

CREATE INDEX deposit_sessions_tenant_id_idx ON deposit_sessions (tenant_id, id);
CREATE INDEX deposit_sessions_expires_idx ON deposit_sessions (tenant_id, expires_at);
CREATE INDEX deposit_sessions_email_idx ON deposit_sessions (tenant_id, email);
CREATE INDEX deposit_sessions_reply_idx ON deposit_sessions (tenant_id, reply_to_transfer_id)
    WHERE reply_to_transfer_id IS NOT NULL;

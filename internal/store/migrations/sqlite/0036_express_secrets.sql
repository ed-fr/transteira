-- 0036_express_secrets (SQLite): express secrets (V2.3, CLAUDE.md section
-- 22.2), anonymous one-time text secrets stored as rows of the 2.1 secrets
-- table. Keep in sync with migrations/postgres/0036_express_secrets.sql.
-- Timestamps are Unix milliseconds (UTC); booleans are INTEGER 0/1. See
-- docs/architecture/data-model-v2.3.md, section 2.
--
-- tenants and api_tokens gain columns (ADD COLUMN with a constant default
-- and a check on the new column: no rebuild). secrets and abuse_reports
-- lose a NOT NULL and gain checks, which SQLite cannot alter in place: both
-- are rebuilt (create, copy, drop, rename), as in 0015, 0031 and 0034. No
-- table, trigger or view references either of them; the migrator disables
-- foreign keys for every SQLite migration and runs PRAGMA foreign_key_check
-- before committing, which proves that the copied rows still reference
-- existing tenants, keys, invitations and tokens. Dropping a table drops
-- its indexes: every one is recreated. No existing row changes: express is
-- 0 everywhere, every secret keeps its address and every report its
-- transfer.

-- Tenant settings of the express secrets (delegated admin, super admin).
-- The anonymous mode is off by default, for the existing tenants too
-- (threat model T-389); the limits are 10 anonymous creations per client
-- and hour, 100 creations per API token and hour, and 1 000 live express
-- secrets per tenant (anonymous creations refused beyond). The instance
-- kill switch TT_EXPRESS_SECRETS_DISABLED is not a column.
ALTER TABLE tenants ADD COLUMN express_enabled INTEGER NOT NULL DEFAULT 0
    CHECK (express_enabled IN (0, 1));
ALTER TABLE tenants ADD COLUMN express_per_hour_ip INTEGER NOT NULL DEFAULT 10
    CHECK (express_per_hour_ip BETWEEN 1 AND 1000);
ALTER TABLE tenants ADD COLUMN express_per_hour_token INTEGER NOT NULL DEFAULT 100
    CHECK (express_per_hour_token BETWEEN 1 AND 10000);
ALTER TABLE tenants ADD COLUMN express_max_pending INTEGER NOT NULL DEFAULT 1000
    CHECK (express_max_pending BETWEEN 1 AND 100000);

-- The explicit opt-in of an API token for the express secrets (threat model
-- P91): off for the new and the existing tokens.
ALTER TABLE api_tokens ADD COLUMN express_allowed INTEGER NOT NULL DEFAULT 0
    CHECK (express_allowed IN (0, 1));

-- secrets: every column and check of 0033, with
--   * creator_kind widened with 'anonymous' (no session, no invitation, no
--     token);
--   * sender_email nullable: NULL exactly for the express secrets
--     (anonymous ones and those created with an API token: the token is
--     the accountable identity, decision E2);
--   * express, the last column, 1 for an express secret, whose profile is
--     enforced by the six new checks: an anonymous creator only for an
--     express secret, an express creator anonymous or an API token, link
--     delivery without receipt, passphrase or file, durations 1h, 1d or
--     7d, created active (never pending, activated at its creation).
CREATE TABLE secrets_0036 (
    id                    TEXT    NOT NULL PRIMARY KEY,
    tenant_id             TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash            BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    state                 TEXT    NOT NULL CHECK (state IN ('pending', 'active', 'read', 'expired', 'deleted', 'locked')),
    creator_kind          TEXT    NOT NULL CHECK (creator_kind IN ('internal', 'internal_remote', 'external', 'api_token', 'anonymous')),
    sender_email          TEXT    CHECK (sender_email IS NULL OR length(sender_email) BETWEEN 3 AND 320),
    api_token_id          TEXT,
    invitation_id         TEXT,
    delivery              TEXT    NOT NULL CHECK (delivery IN ('link', 'email')),
    recipient_email       TEXT    CHECK (recipient_email IS NULL OR length(recipient_email) BETWEEN 3 AND 320),
    read_receipt          INTEGER NOT NULL DEFAULT 0 CHECK (read_receipt IN (0, 1)),
    receipt_sent_at       INTEGER,
    verifier              BLOB    CHECK (verifier IS NULL OR length(verifier) = 32),
    key_verifier          BLOB    CHECK (key_verifier IS NULL OR length(key_verifier) = 32),
    kdf_salt              BLOB    CHECK (kdf_salt IS NULL OR length(kdf_salt) = 16),
    kdf_iterations        INTEGER CHECK (kdf_iterations IS NULL OR kdf_iterations = 600000),
    text_sealed           BLOB    CHECK (text_sealed IS NULL OR length(text_sealed) BETWEEN 1 AND 65536),
    text_key_id           TEXT    UNIQUE REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    duration_code         TEXT    NOT NULL CHECK (duration_code IN ('1h', '12h', '1d', '3d', '7d', '30d')),
    created_at            INTEGER NOT NULL,
    activated_at          INTEGER,
    expires_at            INTEGER,
    read_at               INTEGER,
    ended_at              INTEGER,
    end_reason            TEXT    CHECK (end_reason IS NULL
                                         OR end_reason IN ('read', 'expired', 'locked', 'deleted_by_creator', 'deleted_by_admin')),
    failed_proofs         INTEGER NOT NULL DEFAULT 0 CHECK (failed_proofs BETWEEN 0 AND 5),
    file_size             INTEGER CHECK (file_size IS NULL OR file_size BETWEEN 1 AND 26214400),
    file_metadata         TEXT    CHECK (file_metadata IS NULL OR octet_length(file_metadata) BETWEEN 1 AND 5462),
    file_storage_name     TEXT    CHECK (file_storage_name IS NULL OR length(file_storage_name) = 32),
    file_key_id           TEXT    UNIQUE REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    file_uploaded_at      INTEGER,
    file_grant_hash       BLOB    CHECK (file_grant_hash IS NULL OR length(file_grant_hash) = 32),
    file_grant_expires_at INTEGER,
    file_downloaded_at    INTEGER,
    express               INTEGER NOT NULL DEFAULT 0 CHECK (express IN (0, 1)),
    UNIQUE (tenant_id, id),
    -- Origin.
    CHECK ((creator_kind = 'external') = (invitation_id IS NOT NULL)),
    CHECK ((creator_kind = 'api_token') = (api_token_id IS NOT NULL)),
    CHECK (creator_kind <> 'external' OR delivery = 'email'),
    -- Delivery and receipt (sent on read, expiry unread or lock).
    CHECK ((delivery = 'email') = (recipient_email IS NOT NULL)),
    CHECK (read_receipt = 1 OR receipt_sent_at IS NULL),
    CHECK (receipt_sent_at IS NULL OR state IN ('read', 'expired', 'locked')),
    -- Passphrase parameters: both or neither.
    CHECK ((kdf_salt IS NULL) = (kdf_iterations IS NULL)),
    -- Content and secret material exist in pending and active only.
    CHECK ((state IN ('pending', 'active')) = (text_sealed IS NOT NULL)),
    CHECK ((state IN ('pending', 'active')) = (verifier IS NOT NULL)),
    CHECK ((state IN ('pending', 'active')) = (key_verifier IS NOT NULL)),
    CHECK (state IN ('pending', 'active') OR kdf_salt IS NULL),
    CHECK ((state IN ('pending', 'active')) = (text_key_id IS NOT NULL)),
    CHECK (state IN ('pending', 'active') OR file_metadata IS NULL),
    CHECK (state IN ('pending', 'active') OR (state = 'read' AND file_grant_hash IS NOT NULL)
           OR (file_storage_name IS NULL AND file_key_id IS NULL)),
    -- File: declared size, metadata and storage name together while live;
    -- uploaded before activation.
    CHECK (state NOT IN ('pending', 'active')
           OR ((file_size IS NULL) = (file_metadata IS NULL) AND (file_size IS NULL) = (file_storage_name IS NULL))),
    CHECK (file_size IS NOT NULL OR (file_storage_name IS NULL AND file_uploaded_at IS NULL AND file_grant_hash IS NULL
                                     AND file_downloaded_at IS NULL)),
    CHECK (file_uploaded_at IS NULL OR file_storage_name IS NOT NULL OR state NOT IN ('pending', 'active')),
    CHECK (state <> 'active' OR file_size IS NULL OR file_uploaded_at IS NOT NULL),
    CHECK (state NOT IN ('pending', 'active') OR file_uploaded_at IS NULL OR file_key_id IS NOT NULL),
    -- One-time file grant: created by the reveal, with its expiry.
    CHECK ((file_grant_hash IS NULL) = (file_grant_expires_at IS NULL)),
    CHECK (file_grant_hash IS NULL OR (state = 'read' AND file_storage_name IS NOT NULL)),
    CHECK (file_downloaded_at IS NULL OR state = 'read'),
    -- Lifecycle.
    CHECK ((activated_at IS NULL) = (expires_at IS NULL)),
    CHECK (expires_at IS NULL OR expires_at > activated_at),
    CHECK (state <> 'pending' OR activated_at IS NULL),
    CHECK (state IN ('pending', 'deleted') OR activated_at IS NOT NULL),
    CHECK ((state = 'read') = (read_at IS NOT NULL)),
    CHECK ((state IN ('pending', 'active')) = (ended_at IS NULL)),
    CHECK ((ended_at IS NULL) = (end_reason IS NULL)),
    CHECK (end_reason IS NULL OR end_reason = state
           OR (state = 'deleted' AND end_reason IN ('deleted_by_creator', 'deleted_by_admin'))),
    -- Proof failures: 5 in 'locked'; 5 in 'active' only for the slot a
    -- reveal claims inside its transaction (released or locked before the
    -- commit); a tombstone other than 'locked' keeps at most 4.
    CHECK (state <> 'locked' OR failed_proofs = 5),
    CHECK (failed_proofs < 5 OR state IN ('active', 'locked')),
    -- Express secrets (0036). Creator address: absent exactly for them.
    CHECK ((sender_email IS NULL) = (express = 1)),
    -- Anonymous creators exist only for express secrets; express creators
    -- are anonymous or an API token (never a session, an invitation or a
    -- drop link).
    CHECK (creator_kind <> 'anonymous' OR express = 1),
    CHECK (express = 0 OR creator_kind IN ('anonymous', 'api_token')),
    -- Express profile: link, no receipt, no passphrase, no file, fixed
    -- durations, created active.
    CHECK (express = 0 OR (delivery = 'link' AND read_receipt = 0 AND kdf_salt IS NULL AND file_size IS NULL)),
    CHECK (express = 0 OR duration_code IN ('1h', '1d', '7d')),
    CHECK (express = 0 OR (state <> 'pending' AND activated_at = created_at)),
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id),
    FOREIGN KEY (tenant_id, api_token_id) REFERENCES api_tokens (tenant_id, id)
) STRICT;

INSERT INTO secrets_0036 (id, tenant_id, token_hash, state, creator_kind, sender_email, api_token_id, invitation_id,
    delivery, recipient_email, read_receipt, receipt_sent_at, verifier, key_verifier, kdf_salt, kdf_iterations,
    text_sealed, text_key_id, duration_code, created_at, activated_at, expires_at, read_at, ended_at, end_reason,
    failed_proofs, file_size, file_metadata, file_storage_name, file_key_id, file_uploaded_at, file_grant_hash,
    file_grant_expires_at, file_downloaded_at)
SELECT id, tenant_id, token_hash, state, creator_kind, sender_email, api_token_id, invitation_id,
    delivery, recipient_email, read_receipt, receipt_sent_at, verifier, key_verifier, kdf_salt, kdf_iterations,
    text_sealed, text_key_id, duration_code, created_at, activated_at, expires_at, read_at, ended_at, end_reason,
    failed_proofs, file_size, file_metadata, file_storage_name, file_key_id, file_uploaded_at, file_grant_hash,
    file_grant_expires_at, file_downloaded_at
FROM secrets;

DROP TABLE secrets;
ALTER TABLE secrets_0036 RENAME TO secrets;

-- Indexes of secrets (state after 0033), then the new one.
CREATE INDEX secrets_tenant_created_idx ON secrets (tenant_id, created_at, id);
CREATE INDEX secrets_sender_created_idx ON secrets (tenant_id, sender_email, created_at, id);
CREATE INDEX secrets_token_created_idx ON secrets (tenant_id, api_token_id, created_at)
    WHERE api_token_id IS NOT NULL;
CREATE INDEX secrets_recipient_idx ON secrets (tenant_id, recipient_email)
    WHERE recipient_email IS NOT NULL;
CREATE INDEX secrets_invitation_idx ON secrets (tenant_id, invitation_id)
    WHERE invitation_id IS NOT NULL;
CREATE INDEX secrets_pending_idx ON secrets (created_at, tenant_id, id) WHERE state = 'pending';
CREATE INDEX secrets_expiry_idx ON secrets (expires_at, tenant_id, id) WHERE state = 'active';
CREATE INDEX secrets_grant_idx ON secrets (file_grant_expires_at, tenant_id, id) WHERE file_grant_hash IS NOT NULL;
CREATE INDEX secrets_ended_idx ON secrets (tenant_id, ended_at, id) WHERE ended_at IS NOT NULL;
CREATE UNIQUE INDEX secrets_file_storage_idx ON secrets (tenant_id, file_storage_name)
    WHERE file_storage_name IS NOT NULL;
-- Live express secrets of a tenant: the tenant cap, counted in the creation
-- transaction (active and not expired), and the purge of the anonymous
-- ones. The condition is written "express AND ..." as on PostgreSQL, and as
-- in the store queries: SQLite matches the terms of a partial index
-- literally, so that "express = 1" here would not serve "express" there.
CREATE INDEX secrets_express_live_idx ON secrets (tenant_id, expires_at) WHERE express AND state = 'active';

-- abuse_reports: every column and check of 0017, with transfer_id and
-- sender_email nullable and secret_id, the last column: a report on an
-- express secret (reportSecretAbuse) names the secret ("sec_" ID, a
-- snapshot without foreign key, like transfer_id: a report outlives the
-- secret and its tombstone for its 12-month retention) instead of a
-- transfer, has no sender address (an express secret has none) and an
-- unverified reporter without recipient link. Rate limit: 3 reports per
-- secret per day (abuse_reports_secret_rate_idx), 5 per IP per hour shared
-- with the transfer reports (abuse_reports_ip_rate_idx).
CREATE TABLE abuse_reports_0036 (
    id                 TEXT    NOT NULL PRIMARY KEY,
    tenant_id          TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    transfer_id        TEXT,
    recipient_link_id  TEXT,
    sender_email       TEXT,
    recipient_position INTEGER CHECK (recipient_position >= 0),
    reporter_email     TEXT,
    reporter_verified  INTEGER NOT NULL DEFAULT 0 CHECK (reporter_verified IN (0, 1)),
    reporter_ip        TEXT    NOT NULL,
    category           TEXT    NOT NULL CHECK (category IN ('malware', 'phishing', 'illegal_content', 'spam', 'unknown_sender', 'other')),
    message            TEXT    NOT NULL DEFAULT '' CHECK (length(message) <= 1000),
    status             TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    closed_at          INTEGER,
    closed_by          TEXT    CHECK (length(closed_by) <= 64),
    note               TEXT    NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
    created_at         INTEGER NOT NULL,
    secret_id          TEXT,
    UNIQUE (tenant_id, id),
    CHECK ((recipient_link_id IS NULL) = (recipient_position IS NULL)),
    CHECK ((reporter_email IS NOT NULL) = (reporter_verified = 1)),
    CHECK (reporter_verified = 0 OR recipient_link_id IS NOT NULL),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CHECK ((closed_at IS NULL) = (closed_by IS NULL)),
    -- Reports on secrets (0036): one target, no sender address for a
    -- secret, neither recipient link nor verified reporter.
    CHECK ((transfer_id IS NULL) <> (secret_id IS NULL)),
    CHECK ((sender_email IS NULL) = (secret_id IS NOT NULL)),
    CHECK (secret_id IS NULL OR (recipient_link_id IS NULL AND reporter_verified = 0))
) STRICT;

INSERT INTO abuse_reports_0036 (id, tenant_id, transfer_id, recipient_link_id, sender_email, recipient_position,
    reporter_email, reporter_verified, reporter_ip, category, message, status, closed_at, closed_by, note, created_at)
SELECT id, tenant_id, transfer_id, recipient_link_id, sender_email, recipient_position,
    reporter_email, reporter_verified, reporter_ip, category, message, status, closed_at, closed_by, note, created_at
FROM abuse_reports;

DROP TABLE abuse_reports;
ALTER TABLE abuse_reports_0036 RENAME TO abuse_reports;

-- Indexes of abuse_reports (state after 0017), then the new one.
CREATE INDEX abuse_reports_list_idx ON abuse_reports (tenant_id, status, created_at, id);
CREATE INDEX abuse_reports_link_rate_idx ON abuse_reports (tenant_id, recipient_link_id, created_at)
    WHERE recipient_link_id IS NOT NULL;
CREATE INDEX abuse_reports_shared_rate_idx ON abuse_reports (tenant_id, transfer_id, created_at)
    WHERE recipient_link_id IS NULL;
CREATE INDEX abuse_reports_ip_rate_idx ON abuse_reports (tenant_id, reporter_ip, created_at);
CREATE INDEX abuse_reports_sender_idx ON abuse_reports (tenant_id, sender_email);
CREATE INDEX abuse_reports_reporter_idx ON abuse_reports (tenant_id, reporter_email) WHERE reporter_email IS NOT NULL;
CREATE INDEX abuse_reports_secret_rate_idx ON abuse_reports (tenant_id, secret_id, created_at)
    WHERE secret_id IS NOT NULL;

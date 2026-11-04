-- 0029_transfer_options_v2 (SQLite): permanent drop links, link-only
-- transfers and end-to-end encrypted transfers (V2, features F5, F6 and
-- F7). Keep in sync with migrations/postgres/0029_transfer_options_v2.sql.
-- Timestamps are Unix milliseconds (UTC); booleans are INTEGER 0/1. See
-- docs/architecture/data-model-v2.md, section 2.4.
--
-- Every transfer-level change goes into this one migration, so that the
-- large transfers table is rebuilt once (as in 0014). transfers,
-- transfer_files and deposit_sessions get new check values, which SQLite
-- cannot change in place: they are rebuilt (create, copy, drop, rename).
-- transfers is referenced by transfer_recipients, transfer_files,
-- recipient_links (through transfer_recipients), deposit_sessions and
-- others: the migrator runs every SQLite migration with foreign keys
-- disabled (store/migrate.go), so that dropping the old table neither
-- cascades nor fails, and checks PRAGMA foreign_key_check before
-- committing. Dropping a table drops its indexes: every one is recreated.
-- No trigger or view references these tables.

-- Tenant policies (defaults reproduce 1.2: no link-only, no end-to-end
-- encryption). link_only_allowed: the sender may ask for a link-only
-- transfer (F6). e2e_policy: 'forbidden', 'allowed' or 'required' (F7).
-- Both are written by the super admin only (store rule, like
-- antivirus_enabled: 'required' means no antivirus for the tenant).
ALTER TABLE tenants ADD COLUMN link_only_allowed INTEGER NOT NULL DEFAULT 0
    CHECK (link_only_allowed IN (0, 1));
ALTER TABLE tenants ADD COLUMN e2e_policy TEXT NOT NULL DEFAULT 'forbidden'
    CHECK (e2e_policy IN ('forbidden', 'allowed', 'required'));

-- Level rules. link_only_allowed = 0 forbids link-only transfers at this
-- level (default 1: the tenant flag decides). e2e_policy NULL follows the
-- tenant; a value only tightens it ('required' forces end-to-end
-- encryption at this level). A level never loosens the tenant: a tenant
-- 'forbidden' stays forbidden and a tenant 'required' stays required (a
-- floor). The store computes the effective policy, the database only
-- bounds the values (the tenant policy can change after the levels).
ALTER TABLE confidentiality_levels ADD COLUMN link_only_allowed INTEGER NOT NULL DEFAULT 1
    CHECK (link_only_allowed IN (0, 1));
ALTER TABLE confidentiality_levels ADD COLUMN e2e_policy TEXT
    CHECK (e2e_policy IS NULL OR e2e_policy IN ('forbidden', 'allowed', 'required'));

-- Permanent drop links of a tenant (F5). id is "drl_" + ULID; the link
-- carries a separate bearer token ("ttd_" + random), shown at creation and
-- at rotation only, stored as its SHA-256 (token_hash). recipients is the
-- non-empty JSON array of the internal addresses that receive the
-- deposits (each in an internal domain of the tenant, checked by the
-- store; the database checks that it is valid JSON and an array). validity_days is the validity of the transfers deposited
-- through the link. confidentiality_level is the key of a level of the
-- tenant (confidentiality_levels.key, referenced by key and not by row ID),
-- NULL for the default rules; it is not a foreign key (a level can
-- be deleted; the store then falls back to the tenant default, see the
-- data model). created_by is the admin ID, without foreign key, like
-- provisioning_tokens.created_by. A link is revoked (revoked_at), never
-- deleted, so that the transfers keep their reference; deleting the tenant
-- deletes its links. At most 100 links per tenant (store rule).
-- UNIQUE (tenant_id, id) doubles as the tenant_id index and is the target
-- of the composite foreign keys below.
CREATE TABLE drop_links (
    id                    TEXT    NOT NULL PRIMARY KEY,
    tenant_id             TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash            BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    label                 TEXT    NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
    recipients            TEXT    NOT NULL CHECK (octet_length(recipients) BETWEEN 2 AND 65536
                                  AND json_valid(recipients) AND json_type(recipients) = 'array'),
    validity_days         INTEGER NOT NULL CHECK (validity_days IN (1, 7, 30)),
    confidentiality_level TEXT    CHECK (confidentiality_level IS NULL OR length(confidentiality_level) BETWEEN 1 AND 32),
    enabled               INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_by            TEXT    NOT NULL CHECK (length(created_by) BETWEEN 1 AND 64),
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    last_used_at          INTEGER,
    revoked_at            INTEGER,
    UNIQUE (tenant_id, id)
) STRICT;

-- Administration list, newest first.
CREATE INDEX drop_links_tenant_created_idx ON drop_links (tenant_id, created_at, id);

-- Lifecycle purge of links revoked for 12 months (data model, section 4).
CREATE INDEX drop_links_revoked_idx ON drop_links (revoked_at, id) WHERE revoked_at IS NOT NULL;

-- Transfers, with the V2 columns:
-- - sender_kind adds 'drop_link'; drop_link_id is the link used (composite
--   foreign key within the tenant, no action: links are never deleted but
--   with their tenant).
-- - link_only: the download link is returned once to the sender and never
--   mailed (F6). A link-only transfer requires link_mode 'shared' (one
--   shared link, check below), hence no recipient verification.
-- - e2e: the files were encrypted in the browser (F7); the server stores
--   ciphertext only and knows no key. The free-text message of such a
--   transfer is encrypted too (e2e_message, base64url, brief amendment A7):
--   the plaintext message stays ''. Drop links refuse end-to-end
--   encryption in 2.0 (A7).
-- - A link-only transfer whose finalize answer was lost gets a new link
--   by replacing download_token_hash (A9): no column.
CREATE TABLE transfers_0029 (
    id                          TEXT    NOT NULL PRIMARY KEY,
    tenant_id                   TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    status                      TEXT    NOT NULL CHECK (status IN ('uploading', 'scanning', 'available', 'rejected', 'expired', 'deleted')),
    sender_email                TEXT    NOT NULL,
    sender_kind                 TEXT    NOT NULL CHECK (sender_kind IN ('internal', 'external', 'internal_remote', 'reply', 'drop_link')),
    invitation_id               TEXT,
    message                     TEXT    NOT NULL DEFAULT '',
    language                    TEXT    NOT NULL DEFAULT '',
    expiry_days                 INTEGER NOT NULL CHECK (expiry_days IN (1, 7, 30)),
    password_hash               TEXT,
    delete_after_first_download INTEGER NOT NULL CHECK (delete_after_first_download IN (0, 1)),
    total_bytes                 INTEGER NOT NULL CHECK (total_bytes >= 0),
    idempotency_key             TEXT,
    request_fingerprint         TEXT    CHECK (length(request_fingerprint) = 64),
    created_at                  INTEGER NOT NULL,
    finalized_at                INTEGER,
    expires_at                  INTEGER,
    download_token_hash         BLOB    CHECK (length(download_token_hash) = 32),
    download_token_key_id       TEXT    REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    available_at                INTEGER,
    first_downloaded_at         INTEGER,
    delete_after                INTEGER,
    ended_at                    INTEGER,
    sender_ip                   TEXT,
    download_count              INTEGER NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    api_token_id                TEXT    REFERENCES api_tokens (id),
    reply_to_transfer_id        TEXT,
    link_mode                   TEXT    NOT NULL DEFAULT 'per_recipient' CHECK (link_mode IN ('shared', 'per_recipient')),
    recipient_verification      INTEGER NOT NULL DEFAULT 0 CHECK (recipient_verification IN (0, 1)),
    max_downloads               INTEGER CHECK (max_downloads BETWEEN 1 AND 1000),
    confidentiality_level       TEXT    CHECK (length(confidentiality_level) BETWEEN 1 AND 32),
    confidentiality_label       TEXT,
    rule_expiry_days_mask       INTEGER CHECK (rule_expiry_days_mask BETWEEN 1 AND 7),
    rule_max_downloads_cap      INTEGER CHECK (rule_max_downloads_cap BETWEEN 1 AND 1000),
    rule_require_password       INTEGER CHECK (rule_require_password IN (0, 1)),
    rule_require_recipient_verification INTEGER CHECK (rule_require_recipient_verification IN (0, 1)),
    rule_internal_recipients_only INTEGER CHECK (rule_internal_recipients_only IN (0, 1)),
    rule_force_delete_after_first_download INTEGER CHECK (rule_force_delete_after_first_download IN (0, 1)),
    expiry_reminder_at          INTEGER,
    extension_count             INTEGER NOT NULL DEFAULT 0 CHECK (extension_count >= 0),
    extended_at                 INTEGER,
    link_only                   INTEGER NOT NULL DEFAULT 0 CHECK (link_only IN (0, 1)),
    e2e                         INTEGER NOT NULL DEFAULT 0 CHECK (e2e IN (0, 1)),
    drop_link_id                TEXT,
    e2e_message                 TEXT    CHECK (e2e_message IS NULL OR octet_length(e2e_message) BETWEEN 1 AND 32768),
    UNIQUE (tenant_id, id),
    CHECK ((sender_kind = 'external') = (invitation_id IS NOT NULL)),
    CHECK ((sender_kind = 'reply') = (reply_to_transfer_id IS NOT NULL)),
    CHECK ((sender_kind = 'drop_link') = (drop_link_id IS NOT NULL)),
    CHECK (sender_kind IN ('internal', 'internal_remote') OR api_token_id IS NULL),
    CHECK ((finalized_at IS NULL) = (expires_at IS NULL)),
    CHECK (status <> 'uploading' OR finalized_at IS NULL),
    CHECK (status NOT IN ('scanning', 'available', 'rejected') OR finalized_at IS NOT NULL),
    CHECK (status <> 'available' OR (available_at IS NOT NULL AND (link_mode = 'per_recipient' OR download_token_hash IS NOT NULL))),
    CHECK (link_mode = 'shared' OR download_token_hash IS NULL),
    CHECK (delete_after IS NULL OR (first_downloaded_at IS NOT NULL AND delete_after_first_download = 1) OR (max_downloads IS NOT NULL AND download_count >= max_downloads)),
    CHECK (ended_at IS NULL OR status IN ('rejected', 'expired', 'deleted')),
    CHECK (recipient_verification = 0 OR link_mode = 'per_recipient'),
    CHECK (link_only = 0 OR link_mode = 'shared'),
    CHECK (e2e = 1 OR e2e_message IS NULL),
    CHECK (e2e = 0 OR message = ''),
    CHECK (e2e = 0 OR sender_kind <> 'drop_link'),
    CHECK ((confidentiality_level IS NULL) = (confidentiality_label IS NULL)),
    CHECK (((confidentiality_level IS NULL) = (rule_expiry_days_mask IS NULL)) AND ((confidentiality_level IS NULL) = (rule_require_password IS NULL)) AND ((confidentiality_level IS NULL) = (rule_require_recipient_verification IS NULL)) AND ((confidentiality_level IS NULL) = (rule_internal_recipients_only IS NULL)) AND ((confidentiality_level IS NULL) = (rule_force_delete_after_first_download IS NULL)) AND (confidentiality_level IS NOT NULL OR rule_max_downloads_cap IS NULL)),
    CHECK ((extension_count = 0) = (extended_at IS NULL)),
    CHECK (extension_count = 0 OR expires_at <= created_at + 7776000000),
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id),
    FOREIGN KEY (tenant_id, drop_link_id) REFERENCES drop_links (tenant_id, id)
) STRICT;

INSERT INTO transfers_0029 (id, tenant_id, status, sender_email, sender_kind, invitation_id, message, language,
    expiry_days, password_hash, delete_after_first_download, total_bytes, idempotency_key, request_fingerprint,
    created_at, finalized_at, expires_at, download_token_hash, download_token_key_id, available_at,
    first_downloaded_at, delete_after, ended_at, sender_ip, download_count, api_token_id, reply_to_transfer_id,
    link_mode, recipient_verification, max_downloads, confidentiality_level, confidentiality_label,
    rule_expiry_days_mask, rule_max_downloads_cap, rule_require_password, rule_require_recipient_verification,
    rule_internal_recipients_only, rule_force_delete_after_first_download, expiry_reminder_at, extension_count,
    extended_at)
SELECT id, tenant_id, status, sender_email, sender_kind, invitation_id, message, language,
    expiry_days, password_hash, delete_after_first_download, total_bytes, idempotency_key, request_fingerprint,
    created_at, finalized_at, expires_at, download_token_hash, download_token_key_id, available_at,
    first_downloaded_at, delete_after, ended_at, sender_ip, download_count, api_token_id, reply_to_transfer_id,
    link_mode, recipient_verification, max_downloads, confidentiality_level, confidentiality_label,
    rule_expiry_days_mask, rule_max_downloads_cap, rule_require_password, rule_require_recipient_verification,
    rule_internal_recipients_only, rule_force_delete_after_first_download, expiry_reminder_at, extension_count,
    extended_at
FROM transfers;

DROP TABLE transfers;
ALTER TABLE transfers_0029 RENAME TO transfers;

-- Indexes of transfers (state after 0025), then the V2 one.
CREATE UNIQUE INDEX transfers_idempotency_idx ON transfers (tenant_id, sender_email, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND api_token_id IS NULL;
CREATE UNIQUE INDEX transfers_token_idempotency_idx ON transfers (tenant_id, api_token_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND api_token_id IS NOT NULL;
CREATE INDEX transfers_status_idx ON transfers (tenant_id, status);
CREATE INDEX transfers_sender_status_idx ON transfers (tenant_id, sender_email, status, created_at);
CREATE INDEX transfers_invitation_idx ON transfers (tenant_id, invitation_id);
CREATE UNIQUE INDEX transfers_download_token_idx ON transfers (tenant_id, download_token_hash);
CREATE UNIQUE INDEX transfers_download_token_global_idx ON transfers (download_token_hash);
CREATE UNIQUE INDEX transfers_download_token_key_idx ON transfers (download_token_key_id);
CREATE INDEX transfers_scanning_idx ON transfers (finalized_at, id) WHERE status = 'scanning';
CREATE INDEX transfers_delete_after_idx ON transfers (delete_after, id) WHERE delete_after IS NOT NULL;
CREATE INDEX transfers_ended_idx ON transfers (tenant_id, ended_at, id) WHERE ended_at IS NOT NULL;
CREATE INDEX transfers_expiry_idx ON transfers (expires_at, tenant_id, id) WHERE status = 'available';
CREATE INDEX transfers_rejected_idx ON transfers (ended_at, id) WHERE status = 'rejected';
CREATE INDEX transfers_uploading_idx ON transfers (created_at, tenant_id, id) WHERE status = 'uploading';
CREATE INDEX transfers_tenant_created_idx ON transfers (tenant_id, created_at, id);
CREATE INDEX transfers_token_status_idx ON transfers (tenant_id, api_token_id, status, created_at);
CREATE INDEX transfers_sender_created_idx ON transfers (tenant_id, sender_email, created_at, id);
CREATE INDEX transfers_reminder_idx ON transfers (expires_at, tenant_id, id)
    WHERE status = 'available' AND link_mode = 'per_recipient' AND expiry_reminder_at IS NULL;
-- Transfers deposited through a drop link (administration detail, usage).
CREATE INDEX transfers_drop_link_idx ON transfers (tenant_id, drop_link_id, created_at)
    WHERE drop_link_id IS NOT NULL;

-- Files, with the V2 columns:
-- - scan_status adds 'not_scanned_e2e': an end-to-end encrypted file,
--   which no antivirus can read, delivered unscanned and flagged.
-- - e2e_metadata: the encrypted metadata blob of an end-to-end encrypted
--   file (base64url text sent by the browser: name, media type and
--   plaintext SHA-256, encrypted with the transfer key). NULL for any other
--   file. For such a file, name is the generic "file-<n>.tte2", media_type
--   is '' and sha256 is the SHA-256 of the ciphertext.
CREATE TABLE transfer_files_0029 (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    transfer_id     TEXT    NOT NULL,
    position        INTEGER NOT NULL CHECK (position >= 0),
    name            TEXT    NOT NULL CHECK (name <> ''),
    size            INTEGER NOT NULL CHECK (size >= 0),
    media_type      TEXT    NOT NULL DEFAULT '',
    expected_sha256 TEXT    CHECK (length(expected_sha256) = 64),
    sha256          TEXT    CHECK (length(sha256) = 64),
    dek_key_id      TEXT    UNIQUE REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    storage_name    TEXT    NOT NULL CHECK (length(storage_name) = 32),
    upload_id       TEXT    NOT NULL UNIQUE,
    ciphertext_size INTEGER CHECK (ciphertext_size >= 0),
    uploaded_at     INTEGER,
    scan_status     TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (scan_status IN ('pending', 'scanning', 'clean', 'infected', 'not_scanned_too_large', 'not_scanned_encrypted', 'not_scanned_disabled', 'scan_error', 'not_scanned_e2e')),
    scanned_at      INTEGER,
    scan_signature  TEXT    CHECK (octet_length(scan_signature) <= 200),
    scan_attempts   INTEGER NOT NULL DEFAULT 0 CHECK (scan_attempts >= 0),
    path            TEXT    NOT NULL DEFAULT '' CHECK (octet_length(path) <= 1024),
    e2e_metadata    TEXT    CHECK (e2e_metadata IS NULL OR octet_length(e2e_metadata) BETWEEN 1 AND 5462),
    UNIQUE (tenant_id, storage_name),
    UNIQUE (tenant_id, transfer_id, position),
    CHECK ((uploaded_at IS NULL) = (sha256 IS NULL)),
    CHECK ((uploaded_at IS NULL) = (ciphertext_size IS NULL)),
    CHECK ((scanned_at IS NULL) = (scan_status IN ('pending', 'scanning'))),
    CHECK (scan_status <> 'not_scanned_e2e' OR e2e_metadata IS NOT NULL),
    FOREIGN KEY (tenant_id, transfer_id) REFERENCES transfers (tenant_id, id) ON DELETE CASCADE
) STRICT;

INSERT INTO transfer_files_0029 (id, tenant_id, transfer_id, position, name, size, media_type, expected_sha256,
    sha256, dek_key_id, storage_name, upload_id, ciphertext_size, uploaded_at, scan_status, scanned_at,
    scan_signature, scan_attempts, path)
SELECT id, tenant_id, transfer_id, position, name, size, media_type, expected_sha256,
    sha256, dek_key_id, storage_name, upload_id, ciphertext_size, uploaded_at, scan_status, scanned_at,
    scan_signature, scan_attempts, path
FROM transfer_files;

DROP TABLE transfer_files;
ALTER TABLE transfer_files_0029 RENAME TO transfer_files;

CREATE INDEX transfer_files_tenant_id_idx ON transfer_files (tenant_id, id);

-- Deposit sessions: kind adds 'drop_link', bound to its link
-- (drop_link_id, composite foreign key within the tenant; the session goes
-- with the link, like an invitation session). The e-mail code is required
-- at every use of a drop link: a session of this kind is never reused for
-- another deposit (store rule).
CREATE TABLE deposit_sessions_0029 (
    id                   TEXT    NOT NULL PRIMARY KEY,
    tenant_id            TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash           BLOB    NOT NULL UNIQUE,
    email                TEXT    NOT NULL,
    kind                 TEXT    NOT NULL CHECK (kind IN ('internal', 'external', 'internal_remote', 'reply', 'drop_link')),
    invitation_id        TEXT,
    created_at           INTEGER NOT NULL,
    expires_at           INTEGER NOT NULL,
    ended_at             INTEGER,
    reply_to_transfer_id TEXT,
    recipient_link_id    TEXT,
    drop_link_id         TEXT,
    CHECK ((kind = 'reply') = (reply_to_transfer_id IS NOT NULL)),
    CHECK ((kind = 'reply') = (recipient_link_id IS NOT NULL)),
    CHECK ((kind = 'drop_link') = (drop_link_id IS NOT NULL)),
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, reply_to_transfer_id) REFERENCES transfers (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, recipient_link_id) REFERENCES recipient_links (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, drop_link_id) REFERENCES drop_links (tenant_id, id) ON DELETE CASCADE
) STRICT;

INSERT INTO deposit_sessions_0029 (id, tenant_id, token_hash, email, kind, invitation_id, created_at,
    expires_at, ended_at, reply_to_transfer_id, recipient_link_id)
SELECT id, tenant_id, token_hash, email, kind, invitation_id, created_at,
    expires_at, ended_at, reply_to_transfer_id, recipient_link_id
FROM deposit_sessions;

DROP TABLE deposit_sessions;
ALTER TABLE deposit_sessions_0029 RENAME TO deposit_sessions;

CREATE INDEX deposit_sessions_tenant_id_idx ON deposit_sessions (tenant_id, id);
CREATE INDEX deposit_sessions_email_idx ON deposit_sessions (tenant_id, email);
CREATE INDEX deposit_sessions_expires_idx ON deposit_sessions (tenant_id, expires_at);
CREATE INDEX deposit_sessions_reply_idx ON deposit_sessions (tenant_id, reply_to_transfer_id)
    WHERE reply_to_transfer_id IS NOT NULL;
CREATE INDEX deposit_sessions_drop_link_idx ON deposit_sessions (tenant_id, drop_link_id)
    WHERE drop_link_id IS NOT NULL;

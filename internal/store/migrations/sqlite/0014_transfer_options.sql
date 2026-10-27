-- 0014_transfer_options (SQLite): V1.1 transfer options (spec 6.4, 8.2,
-- 8.3, 8.6, 8.7, 10 and 11.1). Keep in sync with
-- migrations/postgres/0014_transfer_options.sql. Timestamps are Unix
-- milliseconds (UTC); booleans are INTEGER 0/1. See
-- docs/architecture/data-model-v1.1.md, section 2.2.
--
-- SQLite cannot change a check in place, so transfers and transfer_files
-- are rebuilt (create the new table, copy, drop, rename). transfers is
-- referenced by transfer_recipients and transfer_files: the migrator runs
-- every SQLite migration with foreign keys disabled (store/migrate.go), so
-- that dropping the old table neither cascades to its children nor fails,
-- and checks PRAGMA foreign_key_check before committing. The children keep
-- their "REFERENCES transfers" clause, which resolves to the new table once
-- renamed. Dropping a table drops its indexes: every one is recreated.

-- Tenant flags: deposit from outside by verified internal users (spec
-- 6.4), reply to a transfer (spec 10) and antivirus switch (spec 11.1,
-- changed by the super admin only).
ALTER TABLE tenants ADD COLUMN allow_remote_internal_deposit INTEGER NOT NULL DEFAULT 0
    CHECK (allow_remote_internal_deposit IN (0, 1));
ALTER TABLE tenants ADD COLUMN allow_transfer_reply INTEGER NOT NULL DEFAULT 0
    CHECK (allow_transfer_reply IN (0, 1));
ALTER TABLE tenants ADD COLUMN antivirus_enabled INTEGER NOT NULL DEFAULT 1
    CHECK (antivirus_enabled IN (0, 1));

-- Transfers, with the V1.1 columns:
-- - sender_kind adds 'internal_remote' (spec 6.4) and 'reply' (spec 10);
--   reply_to_transfer_id is the source of a reply, without foreign key (a
--   reply outlives the purge of its source, the store checks the tenant).
-- - link_mode: 'shared' is the single V1 "dl_" link (download_token_hash),
--   'per_recipient' one recipient_links row per recipient (default of the
--   new transfers, never a transfer-level token).
-- - recipient_verification, max_downloads (NULL: unlimited).
-- - confidentiality_level/_label and the rule_* columns: snapshot of the
--   level and of its rules at creation (D11), all NULL without a level
--   (rule_max_downloads_cap may stay NULL with a level: no cap).
-- - expiry_reminder_at: reminder pass done (or skipped) for the current
--   expiry; extension_count/extended_at: extensions through "my
--   transfers", the lifetime staying within 90 days of created_at (D3).
CREATE TABLE transfers_0014 (
    id                          TEXT    NOT NULL PRIMARY KEY,
    tenant_id                   TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    status                      TEXT    NOT NULL CHECK (status IN ('uploading', 'scanning', 'available', 'rejected', 'expired', 'deleted')),
    sender_email                TEXT    NOT NULL,
    sender_kind                 TEXT    NOT NULL CHECK (sender_kind IN ('internal', 'external', 'internal_remote', 'reply')),
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
    UNIQUE (tenant_id, id),
    CHECK ((sender_kind = 'external') = (invitation_id IS NOT NULL)),
    CHECK ((sender_kind = 'reply') = (reply_to_transfer_id IS NOT NULL)),
    CHECK (sender_kind IN ('internal', 'internal_remote') OR api_token_id IS NULL),
    CHECK ((finalized_at IS NULL) = (expires_at IS NULL)),
    CHECK (status <> 'uploading' OR finalized_at IS NULL),
    CHECK (status NOT IN ('scanning', 'available', 'rejected') OR finalized_at IS NOT NULL),
    CHECK (status <> 'available' OR (available_at IS NOT NULL AND (link_mode = 'per_recipient' OR download_token_hash IS NOT NULL))),
    CHECK (link_mode = 'shared' OR download_token_hash IS NULL),
    CHECK (delete_after IS NULL OR (first_downloaded_at IS NOT NULL AND delete_after_first_download = 1) OR (max_downloads IS NOT NULL AND download_count >= max_downloads)),
    CHECK (ended_at IS NULL OR status IN ('rejected', 'expired', 'deleted')),
    CHECK (recipient_verification = 0 OR link_mode = 'per_recipient'),
    CHECK ((confidentiality_level IS NULL) = (confidentiality_label IS NULL)),
    CHECK (((confidentiality_level IS NULL) = (rule_expiry_days_mask IS NULL)) AND ((confidentiality_level IS NULL) = (rule_require_password IS NULL)) AND ((confidentiality_level IS NULL) = (rule_require_recipient_verification IS NULL)) AND ((confidentiality_level IS NULL) = (rule_internal_recipients_only IS NULL)) AND ((confidentiality_level IS NULL) = (rule_force_delete_after_first_download IS NULL)) AND (confidentiality_level IS NOT NULL OR rule_max_downloads_cap IS NULL)),
    CHECK ((extension_count = 0) = (extended_at IS NULL)),
    CHECK (extension_count = 0 OR expires_at <= created_at + 7776000000),
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id)
) STRICT;

-- Backfill: the V1 transfers keep their single shared link.
INSERT INTO transfers_0014 (id, tenant_id, status, sender_email, sender_kind, invitation_id, message, language,
    expiry_days, password_hash, delete_after_first_download, total_bytes, idempotency_key, request_fingerprint,
    created_at, finalized_at, expires_at, download_token_hash, download_token_key_id, available_at,
    first_downloaded_at, delete_after, ended_at, sender_ip, download_count, api_token_id, link_mode)
SELECT id, tenant_id, status, sender_email, sender_kind, invitation_id, message, language,
    expiry_days, password_hash, delete_after_first_download, total_bytes, idempotency_key, request_fingerprint,
    created_at, finalized_at, expires_at, download_token_hash, download_token_key_id, available_at,
    first_downloaded_at, delete_after, ended_at, sender_ip, download_count, api_token_id, 'shared'
FROM transfers;

DROP TABLE transfers;
ALTER TABLE transfers_0014 RENAME TO transfers;

-- Indexes of transfers (state after 0013), then the V1.1 ones.
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
-- Abuse counters per sender and day, and the "my transfers" list.
CREATE INDEX transfers_sender_created_idx ON transfers (tenant_id, sender_email, created_at, id);
-- Expiry reminder sweep across tenants (system query).
CREATE INDEX transfers_reminder_idx ON transfers (expires_at, tenant_id, id)
    WHERE status = 'available' AND link_mode = 'per_recipient' AND expiry_reminder_at IS NULL;

-- Files: path is the relative folder of the file ('' for the root, at most
-- 16 segments separated by '/', validated by the store), and the final
-- scan status not_scanned_disabled marks a file released without analysis
-- because the antivirus was disabled at finalization (D8). No table
-- references transfer_files: plain rebuild, as in 0005.
CREATE TABLE transfer_files_0014 (
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
                    CHECK (scan_status IN ('pending', 'scanning', 'clean', 'infected', 'not_scanned_too_large', 'not_scanned_encrypted', 'not_scanned_disabled', 'scan_error')),
    scanned_at      INTEGER,
    scan_signature  TEXT    CHECK (octet_length(scan_signature) <= 200),
    scan_attempts   INTEGER NOT NULL DEFAULT 0 CHECK (scan_attempts >= 0),
    path            TEXT    NOT NULL DEFAULT '' CHECK (octet_length(path) <= 1024),
    UNIQUE (tenant_id, storage_name),
    UNIQUE (tenant_id, transfer_id, position),
    CHECK ((uploaded_at IS NULL) = (sha256 IS NULL)),
    CHECK ((uploaded_at IS NULL) = (ciphertext_size IS NULL)),
    CHECK ((scanned_at IS NULL) = (scan_status IN ('pending', 'scanning'))),
    FOREIGN KEY (tenant_id, transfer_id) REFERENCES transfers (tenant_id, id) ON DELETE CASCADE
) STRICT;

INSERT INTO transfer_files_0014 (id, tenant_id, transfer_id, position, name, size, media_type, expected_sha256,
    sha256, dek_key_id, storage_name, upload_id, ciphertext_size, uploaded_at, scan_status, scanned_at,
    scan_signature, scan_attempts)
SELECT id, tenant_id, transfer_id, position, name, size, media_type, expected_sha256,
    sha256, dek_key_id, storage_name, upload_id, ciphertext_size, uploaded_at, scan_status, scanned_at,
    scan_signature, scan_attempts
FROM transfer_files;

DROP TABLE transfer_files;
ALTER TABLE transfer_files_0014 RENAME TO transfer_files;
CREATE INDEX transfer_files_tenant_id_idx ON transfer_files (tenant_id, id);

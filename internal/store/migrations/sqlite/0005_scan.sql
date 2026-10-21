-- 0005_scan (SQLite): antivirus results and download links (spec 10, 11
-- and 16.1). Keep in sync with migrations/postgres/0005_scan.sql.
-- Timestamps are Unix milliseconds (UTC). SQLite cannot add a table
-- constraint to an existing table: the checks added to transfers are column
-- checks (which may reference other columns), uniqueness is given by unique
-- indexes, and transfer_files is rebuilt.

-- Download link of a transfer, set when it becomes available.
-- download_token_hash is the SHA-256 (32 bytes) of the "dl_" link token,
-- looked up at download time (step 8); it is unique across tenants, and
-- the (tenant_id, download_token_hash) index serves the tenant-scoped
-- lookup. download_token_key_id is a copy of the raw token sealed by the
-- key vault (wrapped key of purpose 'secret'), so that the link can be
-- shown to the sender and mailed again; like dek_key_id, its foreign key is
-- ON DELETE SET NULL (cryptographic erasure destroys the key first) and the
-- store checks that the key belongs to the same tenant. available_at is
-- when the analysis made the transfer available. An available transfer
-- always has its token hash and available_at.
ALTER TABLE transfers ADD COLUMN download_token_hash BLOB
    CHECK (length(download_token_hash) = 32);
ALTER TABLE transfers ADD COLUMN download_token_key_id TEXT
    REFERENCES wrapped_keys (id) ON DELETE SET NULL;
ALTER TABLE transfers ADD COLUMN available_at INTEGER
    CHECK (status <> 'available' OR (download_token_hash IS NOT NULL AND available_at IS NOT NULL));

CREATE UNIQUE INDEX transfers_download_token_idx ON transfers (tenant_id, download_token_hash);
CREATE UNIQUE INDEX transfers_download_token_global_idx ON transfers (download_token_hash);
CREATE UNIQUE INDEX transfers_download_token_key_idx ON transfers (download_token_key_id);
-- Start-up sweep of the transfers waiting for the antivirus, across
-- tenants (system query), oldest finalization first.
CREATE INDEX transfers_scanning_idx ON transfers (finalized_at, id) WHERE status = 'scanning';

-- Antivirus result of a file (spec 11). SQLite cannot change the
-- scan_status check of 0004 in place, so transfer_files is rebuilt with the
-- new columns and the extended status list: not_scanned_encrypted is a file
-- clamd could not look inside (encrypted archive), delivered and flagged
-- like not_scanned_too_large. No table references transfer_files, so the
-- rebuild needs no foreign key juggling.
--
-- scanned_at is set with the final status (clean, infected,
-- not_scanned_too_large, not_scanned_encrypted or scan_error) and only
-- then. scan_signature is the name of the detected signature (at most 200
-- bytes, escaped at display, shown to the sender only), NULL when none.
-- scan_attempts counts the file-specific analysis failures (3 give
-- scan_error).
CREATE TABLE transfer_files_0005 (
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
                    CHECK (scan_status IN ('pending', 'scanning', 'clean', 'infected', 'not_scanned_too_large', 'not_scanned_encrypted', 'scan_error')),
    scanned_at      INTEGER,
    scan_signature  TEXT    CHECK (octet_length(scan_signature) <= 200),
    scan_attempts   INTEGER NOT NULL DEFAULT 0 CHECK (scan_attempts >= 0),
    UNIQUE (tenant_id, storage_name),
    UNIQUE (tenant_id, transfer_id, position),
    CHECK ((uploaded_at IS NULL) = (sha256 IS NULL)),
    CHECK ((uploaded_at IS NULL) = (ciphertext_size IS NULL)),
    CHECK ((scanned_at IS NULL) = (scan_status IN ('pending', 'scanning'))),
    FOREIGN KEY (tenant_id, transfer_id) REFERENCES transfers (tenant_id, id) ON DELETE CASCADE
) STRICT;

INSERT INTO transfer_files_0005 (id, tenant_id, transfer_id, position, name, size, media_type, expected_sha256,
    sha256, dek_key_id, storage_name, upload_id, ciphertext_size, uploaded_at, scan_status)
SELECT id, tenant_id, transfer_id, position, name, size, media_type, expected_sha256,
    sha256, dek_key_id, storage_name, upload_id, ciphertext_size, uploaded_at, scan_status
FROM transfer_files;

DROP TABLE transfer_files;
ALTER TABLE transfer_files_0005 RENAME TO transfer_files;
CREATE INDEX transfer_files_tenant_id_idx ON transfer_files (tenant_id, id);

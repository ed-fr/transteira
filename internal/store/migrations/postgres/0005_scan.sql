-- 0005_scan (PostgreSQL): antivirus results and download links (spec 10,
-- 11 and 16.1). Keep in sync with migrations/sqlite/0005_scan.sql.
-- Timestamps are Unix milliseconds (UTC). The row-level security policies
-- of 0004 cover the new columns.

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
ALTER TABLE transfers
    ADD COLUMN download_token_hash BYTEA
        CHECK (length(download_token_hash) = 32),
    ADD COLUMN download_token_key_id TEXT COLLATE "C"
        REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    ADD COLUMN available_at BIGINT,
    ADD CONSTRAINT transfers_available_check
        CHECK (status <> 'available' OR (download_token_hash IS NOT NULL AND available_at IS NOT NULL));

CREATE UNIQUE INDEX transfers_download_token_idx ON transfers (tenant_id, download_token_hash);
CREATE UNIQUE INDEX transfers_download_token_global_idx ON transfers (download_token_hash);
CREATE UNIQUE INDEX transfers_download_token_key_idx ON transfers (download_token_key_id);
-- Start-up sweep of the transfers waiting for the antivirus, across
-- tenants (system query), oldest finalization first.
CREATE INDEX transfers_scanning_idx ON transfers (finalized_at, id) WHERE status = 'scanning';

-- Antivirus result of a file (spec 11). The scan_status check of 0004 is
-- replaced to add not_scanned_encrypted: a file clamd could not look inside
-- (encrypted archive), delivered and flagged like not_scanned_too_large.
-- scanned_at is set with the final status (clean, infected,
-- not_scanned_too_large, not_scanned_encrypted or scan_error) and only
-- then. scan_signature is the name of the detected signature (at most 200
-- bytes, escaped at display, shown to the sender only), NULL when none.
-- scan_attempts counts the file-specific analysis failures (3 give
-- scan_error).
ALTER TABLE transfer_files
    ADD COLUMN scanned_at BIGINT,
    ADD COLUMN scan_signature TEXT
        CHECK (octet_length(scan_signature) <= 200),
    ADD COLUMN scan_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (scan_attempts >= 0),
    ADD CONSTRAINT transfer_files_scanned_check
        CHECK ((scanned_at IS NULL) = (scan_status IN ('pending', 'scanning'))),
    DROP CONSTRAINT transfer_files_scan_status_check,
    ADD CONSTRAINT transfer_files_scan_status_check
        CHECK (scan_status IN ('pending', 'scanning', 'clean', 'infected', 'not_scanned_too_large',
                               'not_scanned_encrypted', 'scan_error'));

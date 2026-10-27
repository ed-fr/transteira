-- 0014_transfer_options (PostgreSQL): V1.1 transfer options (spec 6.4,
-- 8.2, 8.3, 8.6, 8.7, 10 and 11.1). Keep in sync with
-- migrations/sqlite/0014_transfer_options.sql, which documents the columns.
-- Timestamps are Unix milliseconds (UTC). See
-- docs/architecture/data-model-v1.1.md, section 2.2. The existing policies
-- of tenants, transfers and transfer_files cover the new columns.

ALTER TABLE tenants
    ADD COLUMN allow_remote_internal_deposit BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN allow_transfer_reply BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN antivirus_enabled BOOLEAN NOT NULL DEFAULT true;

-- link_mode is added with the default 'shared', which backfills the V1
-- transfers (they keep their single shared link), then the default
-- becomes 'per_recipient' for the new transfers.
ALTER TABLE transfers
    ADD COLUMN reply_to_transfer_id TEXT COLLATE "C",
    ADD COLUMN link_mode TEXT NOT NULL DEFAULT 'shared' CHECK (link_mode IN ('shared', 'per_recipient')),
    ADD COLUMN recipient_verification BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN max_downloads INTEGER CHECK (max_downloads BETWEEN 1 AND 1000),
    ADD COLUMN confidentiality_level TEXT CHECK (length(confidentiality_level) BETWEEN 1 AND 32),
    ADD COLUMN confidentiality_label TEXT,
    ADD COLUMN rule_expiry_days_mask INTEGER CHECK (rule_expiry_days_mask BETWEEN 1 AND 7),
    ADD COLUMN rule_max_downloads_cap INTEGER CHECK (rule_max_downloads_cap BETWEEN 1 AND 1000),
    ADD COLUMN rule_require_password BOOLEAN,
    ADD COLUMN rule_require_recipient_verification BOOLEAN,
    ADD COLUMN rule_internal_recipients_only BOOLEAN,
    ADD COLUMN rule_force_delete_after_first_download BOOLEAN,
    ADD COLUMN expiry_reminder_at BIGINT,
    ADD COLUMN extension_count INTEGER NOT NULL DEFAULT 0 CHECK (extension_count >= 0),
    ADD COLUMN extended_at BIGINT;
ALTER TABLE transfers ALTER COLUMN link_mode SET DEFAULT 'per_recipient';

-- The invitation check of 0004 ((sender_kind = 'external') = (invitation_id
-- IS NOT NULL)) is unchanged and kept as is. The column check on link_mode
-- is auto-named transfers_link_mode_check, hence transfers_link_token_check
-- for the transfer-level token rule.
ALTER TABLE transfers
    DROP CONSTRAINT transfers_sender_kind_check,
    ADD CONSTRAINT transfers_sender_kind_check
        CHECK (sender_kind IN ('internal', 'external', 'internal_remote', 'reply')),
    ADD CONSTRAINT transfers_reply_check
        CHECK ((sender_kind = 'reply') = (reply_to_transfer_id IS NOT NULL)),
    ADD CONSTRAINT transfers_api_token_kind_check
        CHECK (sender_kind IN ('internal', 'internal_remote') OR api_token_id IS NULL),
    ADD CONSTRAINT transfers_recipient_verification_check
        CHECK (NOT recipient_verification OR link_mode = 'per_recipient'),
    ADD CONSTRAINT transfers_confidentiality_check
        CHECK ((confidentiality_level IS NULL) = (confidentiality_label IS NULL)),
    ADD CONSTRAINT transfers_link_token_check
        CHECK (link_mode = 'shared' OR download_token_hash IS NULL),
    ADD CONSTRAINT transfers_rules_check
        CHECK (((confidentiality_level IS NULL) = (rule_expiry_days_mask IS NULL))
           AND ((confidentiality_level IS NULL) = (rule_require_password IS NULL))
           AND ((confidentiality_level IS NULL) = (rule_require_recipient_verification IS NULL))
           AND ((confidentiality_level IS NULL) = (rule_internal_recipients_only IS NULL))
           AND ((confidentiality_level IS NULL) = (rule_force_delete_after_first_download IS NULL))
           AND (confidentiality_level IS NOT NULL OR rule_max_downloads_cap IS NULL)),
    ADD CONSTRAINT transfers_extension_check
        CHECK ((extension_count = 0) = (extended_at IS NULL)),
    ADD CONSTRAINT transfers_lifetime_check
        CHECK (extension_count = 0 OR expires_at <= created_at + 7776000000),
    DROP CONSTRAINT transfers_available_check,
    ADD CONSTRAINT transfers_available_check
        CHECK (status <> 'available' OR (available_at IS NOT NULL
               AND (link_mode = 'per_recipient' OR download_token_hash IS NOT NULL))),
    DROP CONSTRAINT transfers_delete_after_check,
    ADD CONSTRAINT transfers_delete_after_check
        CHECK (delete_after IS NULL
               OR (first_downloaded_at IS NOT NULL AND delete_after_first_download)
               OR (max_downloads IS NOT NULL AND download_count >= max_downloads));

CREATE INDEX transfers_sender_created_idx ON transfers (tenant_id, sender_email, created_at, id);
CREATE INDEX transfers_reminder_idx ON transfers (expires_at, tenant_id, id)
    WHERE status = 'available' AND link_mode = 'per_recipient' AND expiry_reminder_at IS NULL;

ALTER TABLE transfer_files
    ADD COLUMN path TEXT NOT NULL DEFAULT '' CHECK (octet_length(path) <= 1024),
    DROP CONSTRAINT transfer_files_scan_status_check,
    ADD CONSTRAINT transfer_files_scan_status_check
        CHECK (scan_status IN ('pending', 'scanning', 'clean', 'infected', 'not_scanned_too_large',
                               'not_scanned_encrypted', 'not_scanned_disabled', 'scan_error'));

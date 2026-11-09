-- 0033_secrets (PostgreSQL): one-time secrets (V2.1, CLAUDE.md section
-- 22.1). Keep in sync with migrations/sqlite/0033_secrets.sql, which
-- documents the columns. Timestamps are Unix milliseconds (UTC).
-- Conventions of 0001_init: "C" collation on identifiers, row-level
-- security ENABLE + FORCE. See docs/architecture/data-model-v2.1.md.
--
-- The tenants table is altered in place: its row-level security and its
-- policies (0001) are kept; the new columns are written in the system
-- scope (tenants_system), like the other tenant settings.
ALTER TABLE tenants
    ADD COLUMN secrets_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN secret_durations TEXT NOT NULL DEFAULT '1h,1d,7d'
        CONSTRAINT tenants_secret_durations_check
        CHECK (length(secret_durations) BETWEEN 2 AND 19
               AND replace(replace(replace(replace(replace(replace(',' || secret_durations || ',',
                   ',1h,', ','), ',12h,', ','), ',1d,', ','), ',3d,', ','), ',7d,', ','), ',30d,', ',') = ','),
    ADD COLUMN secret_default_duration TEXT
        CONSTRAINT tenants_secret_default_duration_check
        CHECK (secret_default_duration IS NULL
               OR (secret_default_duration IN ('1h', '12h', '1d', '3d', '7d', '30d')
                   AND strpos(',' || secret_durations || ',', ',' || secret_default_duration || ',') > 0)),
    ADD COLUMN secret_file_allowed BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN secret_file_max_bytes BIGINT NOT NULL DEFAULT 10485760
        CONSTRAINT tenants_secret_file_max_bytes_check
        CHECK (secret_file_max_bytes BETWEEN 1048576 AND 26214400),
    ADD COLUMN secret_email_allowed BOOLEAN NOT NULL DEFAULT true;

CREATE TABLE secrets (
    id                    TEXT    COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id             TEXT    COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash            BYTEA   NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    state                 TEXT    NOT NULL CHECK (state IN ('pending', 'active', 'read', 'expired', 'deleted', 'locked')),
    creator_kind          TEXT    NOT NULL CHECK (creator_kind IN ('internal', 'internal_remote', 'external', 'api_token')),
    sender_email          TEXT    NOT NULL CHECK (length(sender_email) BETWEEN 3 AND 320),
    api_token_id          TEXT    COLLATE "C",
    invitation_id         TEXT    COLLATE "C",
    delivery              TEXT    NOT NULL CHECK (delivery IN ('link', 'email')),
    recipient_email       TEXT    CHECK (recipient_email IS NULL OR length(recipient_email) BETWEEN 3 AND 320),
    read_receipt          BOOLEAN NOT NULL DEFAULT false,
    receipt_sent_at       BIGINT,
    verifier              BYTEA   CHECK (verifier IS NULL OR octet_length(verifier) = 32),
    key_verifier          BYTEA   CHECK (key_verifier IS NULL OR octet_length(key_verifier) = 32),
    kdf_salt              BYTEA   CHECK (kdf_salt IS NULL OR octet_length(kdf_salt) = 16),
    kdf_iterations        INTEGER CHECK (kdf_iterations IS NULL OR kdf_iterations = 600000),
    text_sealed           BYTEA   CHECK (text_sealed IS NULL OR octet_length(text_sealed) BETWEEN 1 AND 65536),
    text_key_id           TEXT    COLLATE "C" UNIQUE REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    duration_code         TEXT    NOT NULL CHECK (duration_code IN ('1h', '12h', '1d', '3d', '7d', '30d')),
    created_at            BIGINT  NOT NULL,
    activated_at          BIGINT,
    expires_at            BIGINT,
    read_at               BIGINT,
    ended_at              BIGINT,
    end_reason            TEXT    CHECK (end_reason IS NULL
                                         OR end_reason IN ('read', 'expired', 'locked', 'deleted_by_creator', 'deleted_by_admin')),
    failed_proofs         INTEGER NOT NULL DEFAULT 0 CHECK (failed_proofs BETWEEN 0 AND 5),
    file_size             BIGINT  CHECK (file_size IS NULL OR file_size BETWEEN 1 AND 26214400),
    file_metadata         TEXT    CHECK (file_metadata IS NULL OR octet_length(file_metadata) BETWEEN 1 AND 5462),
    file_storage_name     TEXT    COLLATE "C" CHECK (file_storage_name IS NULL OR length(file_storage_name) = 32),
    file_key_id           TEXT    COLLATE "C" UNIQUE REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    file_uploaded_at      BIGINT,
    file_grant_hash       BYTEA   CHECK (file_grant_hash IS NULL OR octet_length(file_grant_hash) = 32),
    file_grant_expires_at BIGINT,
    file_downloaded_at    BIGINT,
    UNIQUE (tenant_id, id),
    -- Origin.
    CONSTRAINT secrets_external_check CHECK ((creator_kind = 'external') = (invitation_id IS NOT NULL)),
    CONSTRAINT secrets_api_token_check CHECK ((creator_kind = 'api_token') = (api_token_id IS NOT NULL)),
    CONSTRAINT secrets_external_delivery_check CHECK (creator_kind <> 'external' OR delivery = 'email'),
    -- Delivery and receipt.
    CONSTRAINT secrets_recipient_check CHECK ((delivery = 'email') = (recipient_email IS NOT NULL)),
    CONSTRAINT secrets_receipt_check CHECK (read_receipt OR receipt_sent_at IS NULL),
    CONSTRAINT secrets_receipt_state_check CHECK (receipt_sent_at IS NULL OR state IN ('read', 'expired', 'locked')),
    -- Passphrase parameters: both or neither.
    CONSTRAINT secrets_kdf_check CHECK ((kdf_salt IS NULL) = (kdf_iterations IS NULL)),
    -- Content and secret material exist in pending and active only.
    CONSTRAINT secrets_text_check CHECK ((state IN ('pending', 'active')) = (text_sealed IS NOT NULL)),
    CONSTRAINT secrets_verifier_live_check CHECK ((state IN ('pending', 'active')) = (verifier IS NOT NULL)),
    CONSTRAINT secrets_key_verifier_live_check CHECK ((state IN ('pending', 'active')) = (key_verifier IS NOT NULL)),
    CONSTRAINT secrets_kdf_live_check CHECK (state IN ('pending', 'active') OR kdf_salt IS NULL),
    CONSTRAINT secrets_text_key_check CHECK ((state IN ('pending', 'active')) = (text_key_id IS NOT NULL)),
    CONSTRAINT secrets_file_metadata_live_check CHECK (state IN ('pending', 'active') OR file_metadata IS NULL),
    CONSTRAINT secrets_file_content_check
        CHECK (state IN ('pending', 'active') OR (state = 'read' AND file_grant_hash IS NOT NULL)
               OR (file_storage_name IS NULL AND file_key_id IS NULL)),
    -- File.
    CONSTRAINT secrets_file_live_check
        CHECK (state NOT IN ('pending', 'active')
               OR ((file_size IS NULL) = (file_metadata IS NULL) AND (file_size IS NULL) = (file_storage_name IS NULL))),
    CONSTRAINT secrets_no_file_check
        CHECK (file_size IS NOT NULL OR (file_storage_name IS NULL AND file_uploaded_at IS NULL AND file_grant_hash IS NULL
                                         AND file_downloaded_at IS NULL)),
    CONSTRAINT secrets_file_uploaded_check
        CHECK (file_uploaded_at IS NULL OR file_storage_name IS NOT NULL OR state NOT IN ('pending', 'active')),
    CONSTRAINT secrets_file_active_check CHECK (state <> 'active' OR file_size IS NULL OR file_uploaded_at IS NOT NULL),
    CONSTRAINT secrets_file_key_live_check
        CHECK (state NOT IN ('pending', 'active') OR file_uploaded_at IS NULL OR file_key_id IS NOT NULL),
    -- One-time file grant.
    CONSTRAINT secrets_grant_check CHECK ((file_grant_hash IS NULL) = (file_grant_expires_at IS NULL)),
    CONSTRAINT secrets_grant_state_check CHECK (file_grant_hash IS NULL OR (state = 'read' AND file_storage_name IS NOT NULL)),
    CONSTRAINT secrets_downloaded_check CHECK (file_downloaded_at IS NULL OR state = 'read'),
    -- Lifecycle.
    CONSTRAINT secrets_activation_check CHECK ((activated_at IS NULL) = (expires_at IS NULL)),
    CONSTRAINT secrets_expiry_check CHECK (expires_at IS NULL OR expires_at > activated_at),
    CONSTRAINT secrets_pending_check CHECK (state <> 'pending' OR activated_at IS NULL),
    CONSTRAINT secrets_activated_check CHECK (state IN ('pending', 'deleted') OR activated_at IS NOT NULL),
    CONSTRAINT secrets_read_check CHECK ((state = 'read') = (read_at IS NOT NULL)),
    CONSTRAINT secrets_ended_check CHECK ((state IN ('pending', 'active')) = (ended_at IS NULL)),
    CONSTRAINT secrets_end_reason_set_check CHECK ((ended_at IS NULL) = (end_reason IS NULL)),
    CONSTRAINT secrets_end_reason_state_check
        CHECK (end_reason IS NULL OR end_reason = state
               OR (state = 'deleted' AND end_reason IN ('deleted_by_creator', 'deleted_by_admin'))),
    CONSTRAINT secrets_locked_check CHECK (state <> 'locked' OR failed_proofs = 5),
    CONSTRAINT secrets_failed_proofs_slot_check CHECK (failed_proofs < 5 OR state IN ('active', 'locked')),
    CONSTRAINT secrets_invitation_fkey FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id),
    CONSTRAINT secrets_api_token_fkey FOREIGN KEY (tenant_id, api_token_id) REFERENCES api_tokens (tenant_id, id)
);

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

ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY secrets_isolation ON secrets
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

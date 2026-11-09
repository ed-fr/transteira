-- 0033_secrets (SQLite): one-time secrets (V2.1, CLAUDE.md section 22.1).
-- Keep in sync with migrations/postgres/0033_secrets.sql. Timestamps are
-- Unix milliseconds (UTC); booleans are INTEGER 0/1. See
-- docs/architecture/data-model-v2.1.md.
--
-- Additive only: one new table and new tenant columns (ADD COLUMN with a
-- constant default and a check on the new column, or on an earlier one:
-- no rebuild). No existing check is widened.

-- Tenant settings of the module (delegated admin, super admin). The module
-- is on by default, existing tenants included (V2.1 decision): no
-- instance resource beyond the storage quota, and each tenant can turn it
-- off. secret_durations is the comma-separated list of the duration codes
-- the creators may pick ('1h', '12h', '1d', '3d', '7d', '30d'), non-empty,
-- each code at most once (the check removes every known code from the
-- list and expects nothing but one comma left; the store writes the codes
-- in ascending order). secret_default_duration is the code preselected in
-- the web app (NULL: the shortest offered one), one of the offered codes.
-- secret_file_max_bytes bounds the ciphertext size of the optional file,
-- from 1 MiB to 25 MiB (default 10 MiB).
ALTER TABLE tenants ADD COLUMN secrets_enabled INTEGER NOT NULL DEFAULT 1
    CHECK (secrets_enabled IN (0, 1));
ALTER TABLE tenants ADD COLUMN secret_durations TEXT NOT NULL DEFAULT '1h,1d,7d'
    CHECK (length(secret_durations) BETWEEN 2 AND 19
           AND replace(replace(replace(replace(replace(replace(',' || secret_durations || ',',
               ',1h,', ','), ',12h,', ','), ',1d,', ','), ',3d,', ','), ',7d,', ','), ',30d,', ',') = ',');
ALTER TABLE tenants ADD COLUMN secret_default_duration TEXT
    CHECK (secret_default_duration IS NULL
           OR (secret_default_duration IN ('1h', '12h', '1d', '3d', '7d', '30d')
               AND instr(',' || secret_durations || ',', ',' || secret_default_duration || ',') > 0));
ALTER TABLE tenants ADD COLUMN secret_file_allowed INTEGER NOT NULL DEFAULT 1
    CHECK (secret_file_allowed IN (0, 1));
ALTER TABLE tenants ADD COLUMN secret_file_max_bytes INTEGER NOT NULL DEFAULT 10485760
    CHECK (secret_file_max_bytes BETWEEN 1048576 AND 26214400);
ALTER TABLE tenants ADD COLUMN secret_email_allowed INTEGER NOT NULL DEFAULT 1
    CHECK (secret_email_allowed IN (0, 1));

-- One-time secrets of a tenant. id is "sec_" + ULID (management: creator,
-- admin, audit); the recipient link carries a separate bearer token
-- ("tts_" + 43 base62 characters), stored as its SHA-256 only
-- (token_hash, unique on the whole instance). The decryption key K stays
-- in the fragment of the link and never reaches the database.
--
-- States: 'pending' (created, waiting for the file and/or the send call),
-- 'active' (readable; the expiry clock starts at activated_at), then one
-- of the tombstones 'read', 'expired', 'deleted' (creator or admin, see
-- end_reason) and 'locked' (5 wrong proofs). A tombstone holds no content:
-- text_sealed, text_key_id, verifier, key_verifier, kdf_salt,
-- kdf_iterations and file_metadata are NULL, and so are
-- file_storage_name and file_key_id, except while the one-time file grant
-- created by the reveal is pending (state 'read', file_grant_hash set).
-- Tombstones are purged 30 days after ended_at; a pending secret is deleted
-- outright one hour after created_at (nothing was delivered).
--
-- creator_kind: 'internal' (internal depositor), 'internal_remote'
-- (internal from outside, V1.1 6.4), 'external' (invited, invitation_id
-- set, delivery by e-mail to the inviter, forced by the store) or
-- 'api_token' (api_token_id set; sender_email is the declared sender).
-- The composite foreign keys keep the invitation and the token in the
-- tenant; neither has an ON DELETE action, like transfers: tokens are only
-- revoked, and the store deletes the secrets of an address before its
-- invitations (data-subject erasure).
--
-- delivery 'email': recipient_email is the one recipient address, and the
-- server receives K once, in the send call, to compose the mail (never
-- stored). delivery 'link': the creator hands the link out; no recipient.
--
-- verifier is SHA-256 of the proof derived from the secret root key K'
-- (K and the passphrase); key_verifier is SHA-256 of the key proof derived
-- from K alone (docs/architecture/e2e-format.md, section 3.3.4). The
-- reveal compares both in constant time: a wrong key proof is refused and
-- not counted (a wrong or truncated link), a right key proof with a wrong
-- proof is a wrong passphrase and counts in failed_proofs (lock at 5).
-- kdf_salt and kdf_iterations describe the optional passphrase
-- (PBKDF2-HMAC-SHA-256, 600 000 iterations exactly, a constant of the
-- format): both NULL without passphrase. The salt is public (returned by
-- the status call). Both verifiers and the passphrase parameters are
-- NULLed in a tombstone: with an old link, a later leak of the database
-- would otherwise give an offline passphrase oracle.
--
-- failed_proofs counts the wrong passphrase proofs (a wrong key proof is
-- never counted). The reveal claims a slot before comparing the proof:
-- UPDATE ... SET failed_proofs = failed_proofs + 1 WHERE id = ? AND
-- state = 'active' AND failed_proofs < 5, then compares inside the same
-- transaction; a success releases the slot as part of the reveal
-- (failed_proofs - 1, state 'read'), a failure keeps it and the fifth
-- locks in the same transaction. Concurrent reveals therefore evaluate at
-- most 5 proofs in all. The value 5 is allowed in 'active' only for that
-- claimed slot (never committed by the store) and is required in
-- 'locked'.
--
-- text_sealed is the sealed text sent by the browser (base64url, at most
-- 53 372 characters), encrypted again at rest with a per-secret data key
-- wrapped by the master key (text_key_id, a wrapped_keys row of purpose
-- 'dek'), set whenever the secret is live. The reveal returns it, then
-- destroys the key and NULLs both columns in the same transaction:
-- cryptographic erasure of the server layer. A database backup taken
-- while the secret was live still holds text_sealed, its wrapped key, the
-- verifiers and the salt; the erasure does not reach it, and the text in
-- it stays protected by K (and the passphrase), not by the server layer.
-- Because a live row must reference its keys, a wrapped key of a live
-- secret cannot be destroyed (ON DELETE SET NULL would break the check):
-- a deletion path removes the row first, then destroys its keys.
-- file_key_id does the same for the stored file, a TTE2
-- ciphertext of at most 25 MiB (file_size, declared at creation and kept
-- in the tombstone for the statistics) under <tenant dir>/secrets/
-- <file_storage_name> (32 random hex characters, chosen at creation,
-- never derived from the token); file_uploaded_at is set when the upload
-- completed (file_key_id is then set while the secret is live).
-- file_metadata is the sealed metadata of the file (base64url, at most
-- 4 KiB decoded); it is sealed under K', so it is returned by the reveal
-- only (never by the status call) and NULLed in the same transaction.
--
-- file_grant_hash is the SHA-256 of the one-time download grant created by
-- the reveal (valid until file_grant_expires_at, 10 minutes); the file and
-- its key are destroyed at the first complete download
-- (file_downloaded_at) or when the grant expires.
--
-- No column holds the token, K, the proof, the passphrase or a plaintext.
CREATE TABLE secrets (
    id                    TEXT    NOT NULL PRIMARY KEY,
    tenant_id             TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash            BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    state                 TEXT    NOT NULL CHECK (state IN ('pending', 'active', 'read', 'expired', 'deleted', 'locked')),
    creator_kind          TEXT    NOT NULL CHECK (creator_kind IN ('internal', 'internal_remote', 'external', 'api_token')),
    sender_email          TEXT    NOT NULL CHECK (length(sender_email) BETWEEN 3 AND 320),
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
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id),
    FOREIGN KEY (tenant_id, api_token_id) REFERENCES api_tokens (tenant_id, id)
) STRICT;

-- Administration list, newest first (UNIQUE (tenant_id, id) is the plain
-- tenant_id index).
CREATE INDEX secrets_tenant_created_idx ON secrets (tenant_id, created_at, id);
-- Creator side: "My transfers" list, open secrets and creations in the
-- last 24 hours per address, data-subject search by sender.
CREATE INDEX secrets_sender_created_idx ON secrets (tenant_id, sender_email, created_at, id);
-- The same limits per API token.
CREATE INDEX secrets_token_created_idx ON secrets (tenant_id, api_token_id, created_at)
    WHERE api_token_id IS NOT NULL;
-- Data-subject search by recipient.
CREATE INDEX secrets_recipient_idx ON secrets (tenant_id, recipient_email)
    WHERE recipient_email IS NOT NULL;
-- Cascade checks from an invitation.
CREATE INDEX secrets_invitation_idx ON secrets (tenant_id, invitation_id)
    WHERE invitation_id IS NOT NULL;
-- Lifecycle sweeps across tenants: abandoned pending secrets (1 hour),
-- expiry of the active ones, expired file grants.
CREATE INDEX secrets_pending_idx ON secrets (created_at, tenant_id, id) WHERE state = 'pending';
CREATE INDEX secrets_expiry_idx ON secrets (expires_at, tenant_id, id) WHERE state = 'active';
CREATE INDEX secrets_grant_idx ON secrets (file_grant_expires_at, tenant_id, id) WHERE file_grant_hash IS NOT NULL;
-- Purge of the tombstones (30 days after ended_at), per tenant.
CREATE INDEX secrets_ended_idx ON secrets (tenant_id, ended_at, id) WHERE ended_at IS NOT NULL;
-- Stored files: unique name per tenant, quota sum and orphan file sweep.
CREATE UNIQUE INDEX secrets_file_storage_idx ON secrets (tenant_id, file_storage_name)
    WHERE file_storage_name IS NOT NULL;

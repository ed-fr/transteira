-- 0028_proofs (SQLite): signed proofs of deposit and delivery and the
-- instance keys that sign them (V2, feature F3). Keep in sync with
-- migrations/postgres/0028_proofs.sql. Timestamps are Unix milliseconds
-- (UTC). See docs/architecture/data-model-v2.md, section 2.3.
--
-- system_secrets.purpose gains 'proof-signing' (sealed Ed25519 private key
-- of a proof signing key). As in 0018, system_secrets is referenced by
-- admins and system_webhooks: the rebuild relies on the migrator disabling
-- foreign keys (store/migrate.go), so that dropping the old table neither
-- fails nor touches the children, whose "REFERENCES system_secrets"
-- resolves to the new table once renamed. The index and the retired-key
-- triggers are dropped with the old table and recreated.
CREATE TABLE system_secrets_0028 (
    id         TEXT    NOT NULL PRIMARY KEY,
    purpose    TEXT    NOT NULL CHECK (purpose IN ('admin-totp', 'webhook', 'proof-signing')),
    key_id     TEXT    NOT NULL,
    blob       BLOB    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

INSERT INTO system_secrets_0028 (id, purpose, key_id, blob, created_at)
SELECT id, purpose, key_id, blob, created_at FROM system_secrets;

DROP TABLE system_secrets;
ALTER TABLE system_secrets_0028 RENAME TO system_secrets;

CREATE INDEX system_secrets_key_id_idx ON system_secrets (key_id, id);

CREATE TRIGGER system_secrets_reject_retired_insert BEFORE INSERT ON system_secrets
WHEN EXISTS (SELECT 1 FROM master_keys WHERE id = NEW.key_id AND status = 'retired')
BEGIN
    SELECT RAISE(ABORT, 'transteira: master key is retired');
END;

CREATE TRIGGER system_secrets_reject_retired_update BEFORE UPDATE OF key_id ON system_secrets
WHEN EXISTS (SELECT 1 FROM master_keys WHERE id = NEW.key_id AND status = 'retired')
BEGIN
    SELECT RAISE(ABORT, 'transteira: master key is retired');
END;

-- Proof signing keys of the instance. id is the key id published in
-- /proof-keys and written in every statement ("psk_" + ULID). public_key
-- is the raw Ed25519 public key (32 bytes), kept for ever so that old
-- proofs stay verifiable. The private key is a system secret (purpose
-- 'proof-signing'), sealed by the master key and rewrapped by its
-- rotation; it may be erased once the key is retired (ON DELETE SET NULL),
-- never while it is active (the check then fails the delete). At most one
-- key is active (retired_at NULL); it is created on first use. A key row is
-- never deleted: transfer_proofs references it.
CREATE TABLE proof_signing_keys (
    id                    TEXT    NOT NULL PRIMARY KEY,
    public_key            BLOB    NOT NULL UNIQUE CHECK (length(public_key) = 32),
    private_key_secret_id TEXT    UNIQUE REFERENCES system_secrets (id) ON DELETE SET NULL,
    created_at            INTEGER NOT NULL,
    retired_at            INTEGER,
    CHECK (retired_at IS NOT NULL OR private_key_secret_id IS NOT NULL),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
) STRICT;

-- At most one active key.
CREATE UNIQUE INDEX proof_signing_keys_one_active_idx ON proof_signing_keys ((retired_at IS NULL))
    WHERE retired_at IS NULL;

-- Signed statements of a transfer, written when the fact happens and kept
-- 12 months after creation (expires_at), even after the transfer is gone:
-- transfer_id is therefore not a foreign key. id is "prf_" + ULID. kind is
-- 'deposit' (written at finalization, after the antivirus verdict) or
-- 'delivery' (written at the first download: one row for the transfer,
-- recipient_link_id NULL, and one per recipient link at that recipient's
-- first download when the transfer has per-recipient links; the link id is
-- not a foreign key either). statement is the canonical JSON (RFC 8785) of
-- the ProofStatement and signature its Ed25519 signature (64 bytes) by
-- key_id. A proof is immutable (brief amendment A8): it is inserted once
-- and never updated (trigger below); the unique indexes make the insert of
-- a fact idempotent. Statements name e-mail addresses: the data-subject erasure
-- deletes the rows whose statement names the address (section 4 of the
-- data model). Deleting the tenant deletes its proofs.
CREATE TABLE transfer_proofs (
    id                TEXT    NOT NULL PRIMARY KEY,
    tenant_id         TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    transfer_id       TEXT    NOT NULL,
    kind              TEXT    NOT NULL CHECK (kind IN ('deposit', 'delivery')),
    recipient_link_id TEXT,
    statement         TEXT    NOT NULL CHECK (octet_length(statement) BETWEEN 2 AND 4194304),
    signature         BLOB    NOT NULL CHECK (length(signature) = 64),
    key_id            TEXT    NOT NULL REFERENCES proof_signing_keys (id),
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    CHECK (kind = 'delivery' OR recipient_link_id IS NULL),
    CHECK (expires_at > created_at)
) STRICT;

-- One deposit proof and one overall delivery proof per transfer, one
-- delivery proof per recipient link.
CREATE UNIQUE INDEX transfer_proofs_transfer_idx ON transfer_proofs (tenant_id, transfer_id, kind)
    WHERE recipient_link_id IS NULL;
CREATE UNIQUE INDEX transfer_proofs_recipient_idx ON transfer_proofs (tenant_id, transfer_id, recipient_link_id)
    WHERE recipient_link_id IS NOT NULL;
-- 12-month purge.
CREATE INDEX transfer_proofs_expires_idx ON transfer_proofs (expires_at, id);
-- Statements signed by a key (key retirement checks).
CREATE INDEX transfer_proofs_key_idx ON transfer_proofs (key_id);

-- Proofs are immutable: any UPDATE is refused (deletion by the purge, the
-- data-subject erasure or the tenant deletion stays possible). The message
-- is matched by the store.
CREATE TRIGGER transfer_proofs_immutable BEFORE UPDATE ON transfer_proofs
BEGIN
    SELECT RAISE(ABORT, 'transteira: proofs are immutable');
END;

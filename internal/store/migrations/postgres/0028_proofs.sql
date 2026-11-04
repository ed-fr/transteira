-- 0028_proofs (PostgreSQL): signed proofs of deposit and delivery and the
-- instance keys that sign them (V2, feature F3). Keep in sync with
-- migrations/sqlite/0028_proofs.sql, which documents the columns.
-- Timestamps are Unix milliseconds (UTC). Conventions of 0001_init: "C"
-- collation on identifiers, row-level security ENABLE + FORCE. See
-- docs/architecture/data-model-v2.md, section 2.3.
--
-- system_secrets is altered in place: its row-level security, its policy
-- (0008) and its retired-key trigger are kept.
ALTER TABLE system_secrets
    DROP CONSTRAINT system_secrets_purpose_check,
    ADD CONSTRAINT system_secrets_purpose_check CHECK (purpose IN ('admin-totp', 'webhook', 'proof-signing'));

CREATE TABLE proof_signing_keys (
    id                    TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    public_key            BYTEA  NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    private_key_secret_id TEXT   COLLATE "C" UNIQUE REFERENCES system_secrets (id) ON DELETE SET NULL,
    created_at            BIGINT NOT NULL,
    retired_at            BIGINT,
    CHECK (retired_at IS NOT NULL OR private_key_secret_id IS NOT NULL),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE UNIQUE INDEX proof_signing_keys_one_active_idx ON proof_signing_keys ((retired_at IS NULL))
    WHERE retired_at IS NULL;

CREATE TABLE transfer_proofs (
    id                TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    tenant_id         TEXT   COLLATE "C" NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    transfer_id       TEXT   COLLATE "C" NOT NULL,
    kind              TEXT   NOT NULL CHECK (kind IN ('deposit', 'delivery')),
    recipient_link_id TEXT   COLLATE "C",
    statement         TEXT   NOT NULL CHECK (octet_length(statement) BETWEEN 2 AND 4194304),
    signature         BYTEA  NOT NULL CHECK (octet_length(signature) = 64),
    key_id            TEXT   COLLATE "C" NOT NULL REFERENCES proof_signing_keys (id),
    created_at        BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL,
    CHECK (kind = 'delivery' OR recipient_link_id IS NULL),
    CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX transfer_proofs_transfer_idx ON transfer_proofs (tenant_id, transfer_id, kind)
    WHERE recipient_link_id IS NULL;
CREATE UNIQUE INDEX transfer_proofs_recipient_idx ON transfer_proofs (tenant_id, transfer_id, recipient_link_id)
    WHERE recipient_link_id IS NOT NULL;
CREATE INDEX transfer_proofs_expires_idx ON transfer_proofs (expires_at, id);
CREATE INDEX transfer_proofs_key_idx ON transfer_proofs (key_id);

-- Instance table: system scope only. The signing itself (private key) is a
-- system operation; the tenant-scoped insert of a proof references the key
-- by id, and PostgreSQL referential integrity checks are not filtered by
-- row-level security.
ALTER TABLE proof_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE proof_signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY proof_signing_keys_system ON proof_signing_keys
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

-- Tenant table: a tenant-scoped transaction reads and writes its own
-- proofs only.
ALTER TABLE transfer_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE transfer_proofs FORCE ROW LEVEL SECURITY;
CREATE POLICY transfer_proofs_isolation ON transfer_proofs
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

-- Proofs are immutable (brief amendment A8): any UPDATE is refused, in
-- every scope. SQLSTATE TTP01 is matched by the store.
CREATE FUNCTION transfer_proofs_reject_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path FROM CURRENT
AS $$
BEGIN
    RAISE EXCEPTION 'transteira: proofs are immutable' USING ERRCODE = 'TTP01';
END
$$;

CREATE TRIGGER transfer_proofs_immutable BEFORE UPDATE ON transfer_proofs
    FOR EACH ROW EXECUTE FUNCTION transfer_proofs_reject_update();

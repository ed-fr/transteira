-- 0004_transfers (SQLite): transfers, their recipients and their files
-- (spec 8, 10 and 16.1). Keep in sync with
-- migrations/postgres/0004_transfers.sql. Timestamps are Unix milliseconds
-- (UTC); booleans are INTEGER 0/1. Every table carries tenant_id and an
-- index starting with it; references between these tables are composite
-- (tenant_id, id) foreign keys, which keep them within one tenant.

-- Transfers (spec 8.2). id is "trf_" + ULID. sender_kind and invitation_id
-- go together: an external sender deposits through an invitation of the
-- same tenant. message and language are '' when unset ('' = tenant default
-- language). password_hash is an opaque PHC string (argon2id), NULL without
-- password. total_bytes is the sum of the declared sizes of the files of
-- the transfer, kept up to date by the store: the storage quota sums it
-- over the transfers being uploaded, scanned or available. finalized_at and
-- expires_at are set together at finalization (uploading -> scanning).
--
-- The invitation foreign key has no ON DELETE action (NO ACTION, checked at
-- the end of the statement): SET NULL is impossible on a composite key
-- whose tenant_id is NOT NULL, and CASCADE would silently delete transfers
-- and leave their wrapped keys behind. Deleting an invitation still
-- referenced by a transfer therefore fails; deleting the tenant removes
-- both in the same statement and succeeds.
--
-- The idempotency key (Idempotency-Key header, at most 64 characters) is
-- unique per tenant and sender while it is set; the store releases a key
-- older than its 24-hour retention before reusing it. request_fingerprint
-- is the SHA-256 (64 lowercase hex characters) of the canonical creation
-- request, kept with the key so that a replay with a different body is
-- refused; NULL when no fingerprint was recorded.
CREATE TABLE transfers (
    id                          TEXT    NOT NULL PRIMARY KEY,
    tenant_id                   TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    status                      TEXT    NOT NULL CHECK (status IN ('uploading', 'scanning', 'available', 'rejected', 'expired', 'deleted')),
    sender_email                TEXT    NOT NULL,
    sender_kind                 TEXT    NOT NULL CHECK (sender_kind IN ('internal', 'external')),
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
    UNIQUE (tenant_id, id),
    CHECK ((sender_kind = 'external') = (invitation_id IS NOT NULL)),
    CHECK ((finalized_at IS NULL) = (expires_at IS NULL)),
    CHECK (status <> 'uploading' OR finalized_at IS NULL),
    CHECK (status NOT IN ('scanning', 'available', 'rejected') OR finalized_at IS NOT NULL),
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id)
) STRICT;

CREATE UNIQUE INDEX transfers_idempotency_idx ON transfers (tenant_id, sender_email, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX transfers_status_idx ON transfers (tenant_id, status);
-- Counts and lists the recent open (uploading) transfers of a sender
-- (per-sender cap).
CREATE INDEX transfers_sender_status_idx ON transfers (tenant_id, sender_email, status, created_at);
CREATE INDEX transfers_invitation_idx ON transfers (tenant_id, invitation_id);

-- Recipients of a transfer, in the order given by the sender (position
-- from 0). One row per recipient prepares the V1.1 per-recipient links and
-- tracking. The primary key doubles as the tenant_id index.
CREATE TABLE transfer_recipients (
    tenant_id   TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    transfer_id TEXT    NOT NULL,
    position    INTEGER NOT NULL CHECK (position >= 0),
    email       TEXT    NOT NULL,
    PRIMARY KEY (tenant_id, transfer_id, position),
    UNIQUE (tenant_id, transfer_id, email),
    FOREIGN KEY (tenant_id, transfer_id) REFERENCES transfers (tenant_id, id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- Files of a transfer (spec 8.6 and 16.1). id is "fil_" + ULID; name is
-- the original name, kept in the database only (never on disk);
-- media_type is informational ('' when unknown). On disk, the encrypted
-- file is named after storage_name (128 random bits in lowercase hex) in
-- the tenant's directory. upload_id ("upl_" + base62, at least 128 bits)
-- appears in the tus URL and is looked up by value, hence unique across
-- tenants. sha256, ciphertext_size and uploaded_at are set together when
-- the upload completes. Hashes are 64 lowercase hex characters.
--
-- dek_key_id is the wrapped data key of the file, one per file. Its
-- foreign key is ON DELETE SET NULL, never CASCADE: the cryptographic
-- erasure (T-110) destroys the key first, which leaves a file row without
-- key (unreadable), then deletes the row. The store refuses to delete a
-- file row whose key still exists, so that no key is ever left behind.
-- The store checks that the key belongs to the same tenant (a composite
-- foreign key could not be SET NULL).
CREATE TABLE transfer_files (
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
                    CHECK (scan_status IN ('pending', 'scanning', 'clean', 'infected', 'not_scanned_too_large', 'scan_error')),
    UNIQUE (tenant_id, storage_name),
    UNIQUE (tenant_id, transfer_id, position),
    CHECK ((uploaded_at IS NULL) = (sha256 IS NULL)),
    CHECK ((uploaded_at IS NULL) = (ciphertext_size IS NULL)),
    FOREIGN KEY (tenant_id, transfer_id) REFERENCES transfers (tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX transfer_files_tenant_id_idx ON transfer_files (tenant_id, id);

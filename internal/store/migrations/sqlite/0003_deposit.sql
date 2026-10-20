-- 0003_deposit (SQLite): SMTP settings of a tenant, address verification,
-- deposit sessions and external invitations (spec 6 to 9 and 12.1).
-- Keep in sync with migrations/postgres/0003_deposit.sql. Timestamps are
-- Unix milliseconds (UTC); booleans are INTEGER 0/1. Every table carries
-- tenant_id and an index starting with it. The store never sees a raw code
-- or token: only their HMAC (codes) or SHA-256 (tokens), computed by the
-- caller.

-- SMTP configuration of a tenant (spec 12.1), one row per tenant. The
-- password, when there is one, is a wrapped secret (purpose 'secret');
-- password_key_id references it. The store checks that the key belongs to
-- the same tenant; deleting the key leaves the settings without password.
-- username and from_name are '' when unset.
CREATE TABLE tenant_smtp_settings (
    tenant_id       TEXT    NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    host            TEXT    NOT NULL,
    port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    security        TEXT    NOT NULL CHECK (security IN ('none', 'starttls', 'tls')),
    username        TEXT    NOT NULL DEFAULT '',
    password_key_id TEXT    REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    from_address    TEXT    NOT NULL,
    from_name       TEXT    NOT NULL DEFAULT '',
    updated_at      INTEGER NOT NULL
) STRICT;

-- External invitations (spec 9). id is the administration identifier
-- ("inv_" + ULID); the link carries a separate bearer token whose SHA-256
-- is token_hash. An invitation expires 12 months after its creation or its
-- last use, whichever is later (expires_at is moved forward on each use).
-- language is '' when the tenant default applies. UNIQUE (tenant_id, id)
-- doubles as the tenant_id index and is the target of the composite
-- foreign keys below, which keep references within one tenant.
CREATE TABLE invitations (
    id           TEXT    NOT NULL PRIMARY KEY,
    tenant_id    TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash   BLOB    NOT NULL UNIQUE,
    email        TEXT    NOT NULL,
    invited_by   TEXT    NOT NULL,
    message      TEXT    NOT NULL DEFAULT '',
    language     TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER,
    UNIQUE (tenant_id, id)
) STRICT;

-- Per-inviter rate limit: invitations issued per address over an hour.
CREATE INDEX invitations_inviter_idx ON invitations (tenant_id, invited_by, created_at);

-- Verification codes sent by mail (spec 7). id ("vch_" + base62, at least
-- 128 bits) appears in the URL; the code itself is never stored, only its
-- HMAC (code_mac). attempts_remaining counts the wrong codes still allowed.
CREATE TABLE verification_challenges (
    id                 TEXT    NOT NULL PRIMARY KEY,
    tenant_id          TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email              TEXT    NOT NULL,
    code_mac           BLOB    NOT NULL,
    attempts_remaining INTEGER NOT NULL CHECK (attempts_remaining BETWEEN 0 AND 2),
    invitation_id      TEXT,
    client_ip          TEXT    NOT NULL,
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    consumed_at        INTEGER,
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id) ON DELETE CASCADE
) STRICT;

-- Sliding-hour rate limits: codes sent per address and per client IP (per
-- tenant). Rows must be kept at least one hour after created_at.
CREATE INDEX verification_challenges_email_idx ON verification_challenges (tenant_id, email, created_at);
CREATE INDEX verification_challenges_ip_idx ON verification_challenges (tenant_id, client_ip, created_at);

-- Addresses verified once (spec 7). internal_verified_at/_ip record the
-- first verification done through the internal rule (code confirmed by an
-- internal depositor), NULL until then: the V1.1 deposit from outside
-- (spec 6.4) requires one. recognition_salt (16 random bytes) is part of
-- the MAC of the browser recognition cookie entries of the address:
-- replacing it revokes them all. A verification of an address unused for 12
-- months overwrites every first-verification column and the salt. The
-- primary key doubles as the tenant_id index.
CREATE TABLE verified_addresses (
    tenant_id               TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email                   TEXT    NOT NULL,
    first_verified_at       INTEGER NOT NULL,
    first_verified_ip       TEXT    NOT NULL,
    internal_verified_at    INTEGER,
    internal_verified_ip    TEXT,
    recognition_salt        BLOB    NOT NULL CHECK (length(recognition_salt) = 16),
    last_used_at            INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, email),
    CHECK ((internal_verified_at IS NULL) = (internal_verified_ip IS NULL))
) STRICT, WITHOUT ROWID;

-- Deposit sessions opened after verification (cookie). Only the SHA-256 of
-- the cookie token is stored (token_hash). expires_at is absolute.
CREATE TABLE deposit_sessions (
    id            TEXT    NOT NULL PRIMARY KEY,
    tenant_id     TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash    BLOB    NOT NULL UNIQUE,
    email         TEXT    NOT NULL,
    kind          TEXT    NOT NULL CHECK (kind IN ('internal', 'external')),
    invitation_id TEXT,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    ended_at      INTEGER,
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX deposit_sessions_tenant_id_idx ON deposit_sessions (tenant_id, id);

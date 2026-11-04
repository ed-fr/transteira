-- 0027_sso (SQLite): OpenID Connect sign-in of delegated admins and
-- auditors (V2, feature F2). Keep in sync with
-- migrations/postgres/0027_sso.sql. Timestamps are Unix milliseconds (UTC);
-- booleans are INTEGER 0/1. See docs/architecture/data-model-v2.md,
-- section 2.2.

-- SSO configuration of a tenant, one row per tenant. issuer is the OpenID
-- Connect issuer URL (https, tenant-specific for Entra ID: the store
-- refuses /common, /organizations and /consumers). The client secret is a
-- wrapped secret of the tenant (purpose 'secret'), exactly like the SMTP
-- password (0003): client_secret_key_id references it, the store checks
-- that the key belongs to the same tenant, and the master key rotation
-- rewraps it with every wrapped key. Deleting the key leaves the
-- configuration without secret (the store refuses to enable it then).
-- enforced: local password login refused for the delegated admins and
-- auditors attached to the tenant. require_mfa: the ID token amr claim
-- must contain "mfa". The e-mail domains routed to this configuration are
-- rows of sso_email_domains. updated_by is the admin ID ('' if unknown),
-- without foreign key, like confidentiality_levels.updated_by.
CREATE TABLE tenant_sso_settings (
    tenant_id            TEXT    NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    enabled              INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    issuer               TEXT    NOT NULL CHECK (length(issuer) BETWEEN 9 AND 512 AND issuer LIKE 'https://%'),
    client_id            TEXT    NOT NULL CHECK (length(client_id) BETWEEN 1 AND 255),
    client_secret_key_id TEXT    REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    enforced             INTEGER NOT NULL DEFAULT 0 CHECK (enforced IN (0, 1)),
    require_mfa          INTEGER NOT NULL DEFAULT 1 CHECK (require_mfa IN (0, 1)),
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    updated_by           TEXT    NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64)
) STRICT;

-- One secret serves one configuration only.
CREATE UNIQUE INDEX tenant_sso_settings_secret_idx ON tenant_sso_settings (client_secret_key_id)
    WHERE client_secret_key_id IS NOT NULL;

-- E-mail domains routed to the SSO configuration of a tenant. The primary
-- key on domain alone makes the routing unique across the instance: a
-- domain leads to one tenant configuration at most (conflict:
-- sso-domain-conflict). domain is stored normalized (lower case, IDNA
-- A-label) by the store. The rows go with the configuration.
CREATE TABLE sso_email_domains (
    domain    TEXT NOT NULL PRIMARY KEY CHECK (length(domain) BETWEEN 1 AND 253 AND domain = lower(domain)),
    tenant_id TEXT NOT NULL REFERENCES tenant_sso_settings (tenant_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX sso_email_domains_tenant_idx ON sso_email_domains (tenant_id, domain);

-- Identities pinned to an administrator account at its first SSO login.
-- id is "aid_" + ULID. issuer and subject are the iss and sub claims of the
-- ID token, client_id the application (audience) the login went through:
-- Entra ID subjects are pairwise per application, so an identity is keyed
-- by (issuer, client_id, subject) and the account is afterwards matched by
-- that triple only. An identity belongs to one account and an account has
-- at most one identity per (issuer, client_id). Instance table, like
-- admins: no tenant_id (the
-- tenant whose configuration was used is recorded in the audit event
-- admin.identity_linked). Deleting the account removes its identities.
CREATE TABLE admin_identities (
    id           TEXT    NOT NULL PRIMARY KEY,
    admin_id     TEXT    NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    issuer       TEXT    NOT NULL CHECK (length(issuer) BETWEEN 9 AND 512),
    client_id    TEXT    NOT NULL CHECK (length(client_id) BETWEEN 1 AND 255),
    subject      TEXT    NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    UNIQUE (issuer, client_id, subject),
    UNIQUE (admin_id, issuer, client_id)
) STRICT;

-- Sessions record how they were opened (brief amendment A1): 'password'
-- (local password, then TOTP; every existing session) or 'oidc' (SSO, opened
-- directly authenticated). sso_issuer and sso_client_id are the issuer and
-- the client ID of an SSO login, sso_mfa whether its ID token proved
-- multi-factor authentication (amr contains "mfa"); all three are set for
-- an 'oidc' session only. Such a session only reaches the tenants whose SSO
-- configuration is enabled, has this issuer and this client ID, and whose
-- require_mfa is satisfied by sso_mfa (checked by the access layer on every
-- request, against the current configuration).
ALTER TABLE admin_sessions ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'password'
    CHECK (auth_method IN ('password', 'oidc') AND (auth_method = 'password' OR state = 'authenticated'));
ALTER TABLE admin_sessions ADD COLUMN sso_issuer TEXT
    CHECK ((auth_method = 'oidc') = (sso_issuer IS NOT NULL) AND (sso_issuer IS NULL OR length(sso_issuer) BETWEEN 9 AND 512));
ALTER TABLE admin_sessions ADD COLUMN sso_client_id TEXT
    CHECK ((auth_method = 'oidc') = (sso_client_id IS NOT NULL) AND (sso_client_id IS NULL OR length(sso_client_id) BETWEEN 1 AND 255));
ALTER TABLE admin_sessions ADD COLUMN sso_mfa INTEGER
    CHECK ((auth_method = 'oidc') = (sso_mfa IS NOT NULL) AND (sso_mfa IS NULL OR sso_mfa IN (0, 1)));

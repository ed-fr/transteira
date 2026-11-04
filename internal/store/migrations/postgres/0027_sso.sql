-- 0027_sso (PostgreSQL): OpenID Connect sign-in of delegated admins and
-- auditors (V2, feature F2). Keep in sync with
-- migrations/sqlite/0027_sso.sql, which documents the columns. Timestamps
-- are Unix milliseconds (UTC). Conventions of 0001_init: "C" collation on
-- identifiers, row-level security ENABLE + FORCE. See
-- docs/architecture/data-model-v2.md, section 2.2.
CREATE TABLE tenant_sso_settings (
    tenant_id            TEXT    COLLATE "C" NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    enabled              BOOLEAN NOT NULL DEFAULT false,
    issuer               TEXT    COLLATE "C" NOT NULL CHECK (length(issuer) BETWEEN 9 AND 512 AND issuer LIKE 'https://%'),
    client_id            TEXT    COLLATE "C" NOT NULL CHECK (length(client_id) BETWEEN 1 AND 255),
    client_secret_key_id TEXT    COLLATE "C" REFERENCES wrapped_keys (id) ON DELETE SET NULL,
    enforced             BOOLEAN NOT NULL DEFAULT false,
    require_mfa          BOOLEAN NOT NULL DEFAULT true,
    created_at           BIGINT  NOT NULL,
    updated_at           BIGINT  NOT NULL,
    updated_by           TEXT    NOT NULL DEFAULT '' CHECK (length(updated_by) <= 64)
);

CREATE UNIQUE INDEX tenant_sso_settings_secret_idx ON tenant_sso_settings (client_secret_key_id)
    WHERE client_secret_key_id IS NOT NULL;

CREATE TABLE sso_email_domains (
    domain    TEXT COLLATE "C" NOT NULL PRIMARY KEY CHECK (length(domain) BETWEEN 1 AND 253 AND domain = lower(domain)),
    tenant_id TEXT COLLATE "C" NOT NULL REFERENCES tenant_sso_settings (tenant_id) ON DELETE CASCADE
);

CREATE INDEX sso_email_domains_tenant_idx ON sso_email_domains (tenant_id, domain);

CREATE TABLE admin_identities (
    id           TEXT   COLLATE "C" NOT NULL PRIMARY KEY,
    admin_id     TEXT   COLLATE "C" NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    issuer       TEXT   COLLATE "C" NOT NULL CHECK (length(issuer) BETWEEN 9 AND 512),
    client_id    TEXT   COLLATE "C" NOT NULL CHECK (length(client_id) BETWEEN 1 AND 255),
    subject      TEXT   COLLATE "C" NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    created_at   BIGINT NOT NULL,
    last_used_at BIGINT,
    UNIQUE (issuer, client_id, subject),
    UNIQUE (admin_id, issuer, client_id)
);

-- Tenant tables: a tenant-scoped transaction reads and writes its own
-- configuration and domains only. The login, on an admin host, resolves
-- the domain of an e-mail address in the system scope (no tenant is known
-- yet); the primary key of sso_email_domains enforces the instance-wide
-- uniqueness whatever the scope (constraints are not filtered by RLS).
ALTER TABLE tenant_sso_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_sso_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_sso_settings_isolation ON tenant_sso_settings
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

ALTER TABLE sso_email_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_email_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY sso_email_domains_isolation ON sso_email_domains
    USING (tenant_id = current_setting('app.tenant_id', true)
           OR current_setting('app.system_scope', true) = 'on')
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.system_scope', true) = 'on');

-- Instance table: system scope only, like admins.
ALTER TABLE admin_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_identities_system ON admin_identities
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');

-- Sessions record how they were opened (brief amendment A1), see the
-- SQLite migration. admin_sessions keeps its policy admin_sessions_system.
ALTER TABLE admin_sessions
    ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'password' CHECK (auth_method IN ('password', 'oidc')),
    ADD COLUMN sso_issuer TEXT COLLATE "C" CHECK (sso_issuer IS NULL OR length(sso_issuer) BETWEEN 9 AND 512),
    ADD COLUMN sso_client_id TEXT COLLATE "C" CHECK (sso_client_id IS NULL OR length(sso_client_id) BETWEEN 1 AND 255),
    ADD COLUMN sso_mfa BOOLEAN,
    ADD CONSTRAINT admin_sessions_sso_check CHECK ((auth_method = 'oidc') = (sso_issuer IS NOT NULL)
        AND (auth_method = 'oidc') = (sso_client_id IS NOT NULL)
        AND (auth_method = 'oidc') = (sso_mfa IS NOT NULL)),
    ADD CONSTRAINT admin_sessions_oidc_state_check CHECK (auth_method = 'password' OR state = 'authenticated');

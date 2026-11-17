-- 0036_express_secrets (PostgreSQL): express secrets (V2.3, CLAUDE.md
-- section 22.2), anonymous one-time text secrets stored as rows of the 2.1
-- secrets table. Keep in sync with migrations/sqlite/0036_express_secrets.sql.
-- See docs/architecture/data-model-v2.3.md, section 2.
--
-- Every table is altered in place; no existing row changes (express is
-- false everywhere, every secret keeps its address and every report its
-- transfer), and the new checks are validated against the existing rows.
-- The row-level security policies are unchanged: tenants_read_own and
-- tenants_system cover the new tenant columns, written in the system
-- scope; secrets_isolation, api_tokens_isolation and
-- abuse_reports_isolation (ENABLE and FORCE) cover the new columns and the
-- express rows.

-- Tenant settings of the express secrets (delegated admin, super admin).
-- The anonymous mode is off by default, for the existing tenants too
-- (threat model T-389); the limits are 10 anonymous creations per client
-- and hour, 100 creations per API token and hour, and 1 000 live express
-- secrets per tenant (anonymous creations refused beyond). The instance
-- kill switch TT_EXPRESS_SECRETS_DISABLED is not a column.
ALTER TABLE tenants
    ADD COLUMN express_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN express_per_hour_ip INTEGER NOT NULL DEFAULT 10
        CONSTRAINT tenants_express_per_hour_ip_check CHECK (express_per_hour_ip BETWEEN 1 AND 1000),
    ADD COLUMN express_per_hour_token INTEGER NOT NULL DEFAULT 100
        CONSTRAINT tenants_express_per_hour_token_check CHECK (express_per_hour_token BETWEEN 1 AND 10000),
    ADD COLUMN express_max_pending INTEGER NOT NULL DEFAULT 1000
        CONSTRAINT tenants_express_max_pending_check CHECK (express_max_pending BETWEEN 1 AND 100000);

-- The explicit opt-in of an API token for the express secrets (threat model
-- P91): off for the new and the existing tokens.
ALTER TABLE api_tokens ADD COLUMN express_allowed BOOLEAN NOT NULL DEFAULT false;

-- secrets: express, the last column, true for an express secret;
-- creator_kind widened with 'anonymous'; sender_email nullable, NULL exactly
-- for the express secrets (anonymous ones and those created with an API
-- token: the token is the accountable identity, decision E2). The two
-- column checks of 0033 were declared inline without a name, so PostgreSQL
-- named them secrets_creator_kind_check and secrets_sender_email_check: they
-- are replaced under the same names, so that later migrations and the
-- schema comparison of the tests see stable names.
ALTER TABLE secrets ADD COLUMN express BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE secrets DROP CONSTRAINT secrets_creator_kind_check,
    ADD CONSTRAINT secrets_creator_kind_check
        CHECK (creator_kind IN ('internal', 'internal_remote', 'external', 'api_token', 'anonymous'));
ALTER TABLE secrets ALTER COLUMN sender_email DROP NOT NULL;
ALTER TABLE secrets DROP CONSTRAINT secrets_sender_email_check,
    ADD CONSTRAINT secrets_sender_email_check
        CHECK (sender_email IS NULL OR length(sender_email) BETWEEN 3 AND 320);
-- The express profile: an anonymous creator only for an express secret, an
-- express creator anonymous or an API token, link delivery without receipt,
-- passphrase or file, durations 1h, 1d or 7d, created active (never
-- pending, activated at its creation).
ALTER TABLE secrets
    ADD CONSTRAINT secrets_express_sender_check CHECK ((sender_email IS NULL) = express),
    ADD CONSTRAINT secrets_anonymous_check CHECK (creator_kind <> 'anonymous' OR express),
    ADD CONSTRAINT secrets_express_kind_check CHECK (NOT express OR creator_kind IN ('anonymous', 'api_token')),
    ADD CONSTRAINT secrets_express_profile_check
        CHECK (NOT express OR (delivery = 'link' AND NOT read_receipt AND kdf_salt IS NULL AND file_size IS NULL)),
    ADD CONSTRAINT secrets_express_duration_check CHECK (NOT express OR duration_code IN ('1h', '1d', '7d')),
    ADD CONSTRAINT secrets_express_active_check
        CHECK (NOT express OR (state <> 'pending' AND activated_at = created_at));
-- Live express secrets of a tenant: the tenant cap, counted in the creation
-- transaction (active and not expired), and the purge of the anonymous
-- ones.
CREATE INDEX secrets_express_live_idx ON secrets (tenant_id, expires_at) WHERE express AND state = 'active';

-- abuse_reports: transfer_id and sender_email nullable and secret_id, the
-- last column: a report on an express secret (reportSecretAbuse) names the
-- secret ("sec_" ID, a snapshot without foreign key, like transfer_id: a
-- report outlives the secret and its tombstone for its 12-month retention)
-- instead of a transfer, has no sender address (an express secret has
-- none) and an unverified reporter without recipient link. Rate limit: 3
-- reports per secret per day (abuse_reports_secret_rate_idx), 5 per IP per
-- hour shared with the transfer reports (abuse_reports_ip_rate_idx).
ALTER TABLE abuse_reports
    ALTER COLUMN transfer_id DROP NOT NULL,
    ALTER COLUMN sender_email DROP NOT NULL,
    ADD COLUMN secret_id TEXT COLLATE "C",
    ADD CONSTRAINT abuse_reports_target_check CHECK ((transfer_id IS NULL) <> (secret_id IS NULL)),
    ADD CONSTRAINT abuse_reports_sender_check CHECK ((sender_email IS NULL) = (secret_id IS NOT NULL)),
    ADD CONSTRAINT abuse_reports_secret_check
        CHECK (secret_id IS NULL OR (recipient_link_id IS NULL AND NOT reporter_verified));
CREATE INDEX abuse_reports_secret_rate_idx ON abuse_reports (tenant_id, secret_id, created_at)
    WHERE secret_id IS NOT NULL;

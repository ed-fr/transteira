# TransTeira V1.2: data model

> V1.2, step 1, data part. Status: **proposal, to be validated before any code**.
> Sources: CLAUDE.md (V1.2 row of section 2), the V1.2 design brief (features F1 to F7),
> `docs/architecture/data-model-v1.1.md`, migrations
> `internal/store/migrations/{sqlite,postgres}/0001..0021`, package `internal/store`.
> The migrations 0022 to 0025 are written alongside this document (they apply on both
> engines and pass the store tests); the Go store code that uses them comes with the
> implementation steps.

## 1. Principles

All V1 and V1.1 conventions still apply (see `data-model-v1.1.md`, section 1). V1.2 is small and
purely additive: no table is rebuilt, no existing column changes, so SQLite needs no
foreign-key-off rebuild.

| Topic | Rule |
|---|---|
| Additive only | Every change is an `ALTER TABLE ... ADD COLUMN` or a new table. Existing rows keep working: each new column is nullable or has a default that reproduces the V1.1 behaviour. |
| Tenant scoping | No new tenant table. The two new tables (`provisioning_tokens`, `system_state`) are **instance-level**, without `tenant_id`, like `admins` and `system_settings`. They are reached through `systemQuery` only. |
| PostgreSQL RLS | Instance tables get `ENABLE` + `FORCE ROW LEVEL SECURITY` and a policy open to the system scope only (template in section 3). The `tenants` policies (0001) and the `admin_activations` policy (0008) are unchanged: altered tables keep them. `DB.Verify` already requires RLS on every table, so the new tables are covered. |
| Types | SQLite tables are `STRICT`. Timestamps are Unix **milliseconds** UTC (`INTEGER` / `BIGINT`). Identifiers are `TEXT` (PostgreSQL adds `COLLATE "C"`). Hashes are `BLOB` / `BYTEA` of 32 bytes. JSON is `TEXT` validated by the store. No GRANT is written in migrations: the application role is granted by the install procedure, as in V1. |
| Secrets | A provisioning token is stored as SHA-256 only, shown once, never re-mailed, so it gets no sealed copy. |
| Enums owned by the code | `background_preset` is not constrained to a list in the database: the presets are defined in code (`internal/branding`), the store validates the slug. Adding a preset needs no migration. `setup_state` and `delivery` are closed two-value sets and are constrained. |
| Parity | Each migration exists for both engines with the same columns and constraints. The migration tests pin the schema on both engines. |
| Files, not columns | Favicons (F2) are files generated next to the logo through `internal/storage`. No column. |
| Names | Problem codes are kebab-case. Enum values stored in the database equal the OpenAPI values. |

## 2. Migration plan

| # | Name | Content |
|---|---|---|
| 0022 | `tenant_setup` | `tenants`: `setup_state`, `background_preset`, `smtp_tested_at`, `mail_templates_reviewed_at`. |
| 0023 | `provisioning_tokens` | New table `provisioning_tokens` (instance level, RLS system scope), `tenants.provisioned_by` and its index. |
| 0024 | `admin_activation_delivery` | `admin_activations`: `delivery`, `language`. |
| 0025 | `system_state` | New table `system_state` (instance level, RLS system scope). |

### 2.1 Migration 0022 `tenant_setup` (F3, F5)

```sql
setup_state                TEXT NOT NULL DEFAULT 'active' CHECK (setup_state IN ('setup', 'active'))  -- PG: default dropped after the backfill
background_preset          TEXT CHECK (background_preset IS NULL OR length(background_preset) BETWEEN 1 AND 32)
smtp_tested_at             INTEGER   -- PG: BIGINT, NULL = never tested with the current configuration
mail_templates_reviewed_at INTEGER   -- PG: BIGINT, NULL = not reviewed
```

- **Existing tenants end up `active`**: the column default is `'active'`, so the `ALTER` backfills every existing row without an `UPDATE`. Both engines are checked by the migration tests.
- **New tenants**: the store writes `setup_state` explicitly on every insert; the Go creation function requires an explicit state. API 1.2 stays backward compatible (user decision): `createTenant` without `setupState` creates an `active` tenant, the API handler mapping the absent member to `active` explicitly; the administration interface and its wizard send `'setup'`; tenants provisioned through the API are always `'setup'`. The database default exists only for the backfill of existing tenants (SQLite needs a default to add a `NOT NULL` column). On PostgreSQL, 0022 drops it right after the backfill (fail closed: an insert without a state fails); SQLite cannot drop a column default, so there the Go type is the guard. It is never a fallback: the store refuses an insert whose state is empty (threat model T-261 and P51), a test checks it, and `updateTenant` never writes `setup_state` (only `completeTenantSetup` does).
- `setup_state` has two values and a `CHECK` (x-extensible-enum in the API only affects clients). A third state would be a `CHECK` migration (PostgreSQL `DROP`/`ADD CONSTRAINT`, SQLite rebuild of `tenants`, which is referenced by many tables and needs the foreign-keys-off procedure of V1.1 section 2.1).
- `background_preset` NULL means the default preset. The upload of a custom background still wins; deleting it falls back to the preset (a store/branding rule, no column). Unknown slug: the store returns the error mapped to `unknown-background-preset`.
- `smtp_tested_at` is set by a successful test send to the **version of the SMTP configuration that was tested**: its `tenant_smtp_settings.updated_at`, read before sending. As implemented (step 5), the SMTP settings are written in a tenant-scoped transaction, which the `tenants` policies forbid to update its tenant row on PostgreSQL, so the column cannot be cleared in that transaction. Instead every write of the SMTP settings moves `updated_at` strictly forward under the tenant lock (at least 1 ms after the stored value, whatever the clock), so that **the statement that changes the SMTP configuration invalidates the stamp atomically** (server, port, encryption, authentication, password, sender, even rewritten to the same values). The wizard item `smtp` is done when SMTP is configured and `smtp_tested_at = tenant_smtp_settings.updated_at`; the non-forced completion checks this equality in its own `UPDATE` (subquery on `tenant_smtp_settings`, system scope), together with `EXISTS` guards for one internal CIDR, one internal domain and non-blank legal notice and privacy policy in the default language (the "to complete" marker check stays in Go, just before). A test of a configuration replaced during the send records a stamp that never matches (fail closed). Known gap: erasing the password secret (`ON DELETE SET NULL` of `password_key_id`, only on tenant deletion) does not move the version.
- `mail_templates_reviewed_at` backs the optional `mail_templates` wizard item ("reviewed" flag). The brief did not list it; without it the item could not be persisted (see open point 1).
- Other wizard items are derived, with no column: `branding_logo` (a logo exists in storage), `branding_colors` (colours differ from the defaults), `internal_networks` and `internal_domains` (`tenant_network_rules`), `legal_notice` and `privacy_policy` (`tenant_legal_documents` for the default language).
- RLS: the `tenants` policies are unchanged (a tenant-scoped transaction reads its own row, writes are system scope). A tenant-scoped read can now see its own `setup_state`, which the public tenant endpoint needs.

### 2.2 Migration 0023 `provisioning_tokens` (F6)

```sql
CREATE TABLE provisioning_tokens (
    id                      TEXT    NOT NULL PRIMARY KEY,                  -- "prv_" + ULID
    name                    TEXT    NOT NULL CHECK (name <> ''),
    prefix                  TEXT    NOT NULL CHECK (prefix <> ''),         -- first characters of "ttp_..."
    token_hash              BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    allowed_cidrs           TEXT    NOT NULL,                              -- JSON array, >= 1, no /0
    allowed_fqdn_suffixes   TEXT    NOT NULL,                              -- JSON array, >= 1
    max_storage_quota_bytes INTEGER NOT NULL CHECK (max_storage_quota_bytes > 0),
    max_transfer_bytes      INTEGER CHECK (max_transfer_bytes > 0),
    max_tenants             INTEGER NOT NULL CHECK (max_tenants > 0),
    created_by              TEXT    NOT NULL CHECK (created_by <> ''),     -- super admin ID, no FK
    created_at              INTEGER NOT NULL,
    last_used_at            INTEGER,
    expires_at              INTEGER,
    revoked_at              INTEGER,
    CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;
ALTER TABLE tenants ADD COLUMN provisioned_by TEXT REFERENCES provisioning_tokens (id);
CREATE INDEX tenants_provisioned_by_idx ON tenants (provisioned_by, created_at) WHERE provisioned_by IS NOT NULL;
```

- **Separate from `api_tokens`**: different table, different prefix (`ttp_` against `tt_`), different lookup (global, by hash, on admin hosts only). A tenant token can never match here and the reverse (threat T-69 style isolation). The lookup is by `token_hash` (unique), then CIDR, expiry and revocation are checked in code; a CIDR mismatch answers like an unknown token (no oracle).
- **Scope in the token**: `allowed_cidrs` and `allowed_fqdn_suffixes` are mandatory and non-empty, enforced by the store (JSON content cannot be checked portably in `CHECK`). The store also refuses `0.0.0.0/0` and `::/0`. The caps `max_storage_quota_bytes`, `max_transfer_bytes`, `max_tenants` are checked at creation of a tenant.
- **`created_by`** is the admin ID as plain text, not a foreign key: deleting an admin must not depend on, or be blocked by, tokens they created (the audit log `provisioning_token.created` keeps the history). Open point 2.
- **Revoke, never delete**: `revoked_at` is set; there is no delete path. The `tenants.provisioned_by` foreign key has no `ON DELETE` action, so a token that created tenants cannot be deleted even by mistake. Deleting a tenant removes its row, so the token simply counts one tenant less.
- **Counters are computed**, no counter columns and no per-request writes: `tenantsCreated` is `count(*) FROM tenants WHERE provisioned_by = ?` (live tenants, which is also the `max_tenants` check), the creation rate limit (30 per hour per token) counts `tenants.created_at` over the last hour through `tenants_provisioned_by_idx`. The `last_used_at` column is updated at most once per minute per token (store rule), as for API tokens.
- **Failure lockout** (10 failures per IP, security log `provisioning_token_invalid`) uses the same mechanism as API token failures. No new table is expected (open point 3).
- **Order**: the table is created before `tenants.provisioned_by` because SQLite `ADD COLUMN ... REFERENCES` needs an existing target. The column is nullable with default NULL, which SQLite allows for `ADD COLUMN`.
- **PostgreSQL RLS**: instance table, policy `provisioning_tokens_system`, system scope only, like `admins_system` (0008). A tenant-scoped transaction sees no token and no scope. `tenants.provisioned_by` is visible to a tenant reading its own row; it is an opaque ID and no secret.
- **Provisioning reads**: `GET /provisioning/tenants[/{id}]` read `tenants` in the system scope with `provisioned_by = <token id>` in every query, never a bare `id` lookup (other tokens' tenants answer 404). Only `id, name, fqdn, setup_state, created_at` and whether the delegated admin is activated (join on `admin_tenants`/`admins`, boolean only) are returned.

### 2.3 Migration 0024 `admin_activation_delivery` (F4)

```sql
delivery TEXT NOT NULL DEFAULT 'copy' CHECK (delivery IN ('copy', 'mail'))
language TEXT CHECK (language IS NULL OR length(language) BETWEEN 2 AND 16)
```

- Existing activations are `copy` (they were shown to the super admin), language NULL.
- `delivery = 'mail'`: the link is sent through the system SMTP after the commit and never returned by the API; `copy`: returned once as `activationLink`. In both cases only the SHA-256 of the token is stored and the token travels in the URL fragment.
- `language` is the mail language chosen by the super admin (`invitation.language`, defaulting to the admin's language); the length check accepts any future language code without a migration.
- **Re-issue** (`POST /admin/admins/{id}/invite`): the previous activations of the account are deleted in the same transaction, as a credentials reset already does (implementation choice of step 4: the per-account limit of 5 re-issues per hour is kept in memory, so the rows are not needed to count them); a new row is inserted (TTL 72 h). `admin-already-active` when the admin already has a password.
- RLS: unchanged, the table is altered in place and keeps `admin_activations_system` (0008).

### 2.4 Migration 0025 `system_state` (F1)

```sql
CREATE TABLE system_state (
    key        TEXT    NOT NULL PRIMARY KEY CHECK (key <> ''),
    value      TEXT    NOT NULL,                    -- JSON document, validated by the store
    updated_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
```

- One row per state key defined by the code. V1.2 uses `update_check`, whose JSON is `{latestVersion, releaseUrl, checkedAt, lastError}`; the response fields `updateAvailable` and `enabled` are computed on read from the running version and `TT_UPDATE_CHECK`, not stored.
- Why a new table rather than columns on `system_settings`: `system_settings` is the settings row edited by the super admin (migration-per-column). `system_state` holds values the application computes; adding a cache needs no migration. The value is never a secret and never personal data.
- Written at most once per check (24 h, plus manual checks limited to one per minute). Not written when the check is disabled.
- **PostgreSQL RLS**: instance table, policy `system_state_system`, system scope only, like `system_settings_system` (0012).

## 3. PostgreSQL RLS summary

Template for an instance table (identical to `admins_system` and `system_settings_system`):

```sql
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <t> FORCE ROW LEVEL SECURITY;
CREATE POLICY <t>_system ON <t>
    USING (current_setting('app.system_scope', true) = 'on')
    WITH CHECK (current_setting('app.system_scope', true) = 'on');
```

| Table | Change | RLS |
|---|---|---|
| `tenants` | 5 columns | Unchanged (`tenants_read_own` for SELECT in tenant scope, `tenants_system` for everything else). |
| `provisioning_tokens` | New | Template above (`provisioning_tokens_system`). |
| `admin_activations` | 2 columns | Unchanged (`admin_activations_system`). |
| `system_state` | New | Template above (`system_state_system`). |

## 4. Purge and retention (spec 20)

| Data | Rule |
|---|---|
| `tenants.setup_state`, `background_preset`, `smtp_tested_at`, `mail_templates_reviewed_at`, `provisioned_by` | Configuration, kept for the tenant's lifetime. |
| `provisioning_tokens` | Configuration (system). Kept after revocation or expiry as long as any tenant references them; otherwise kept too (the token is listed with `revokedAt`). No automatic purge in V1.2. A token holds no personal data (the name is chosen by the super admin). |
| `admin_activations` | Existing rule (purged once expired or used). `delivery` and `language` follow the row. |
| `system_state` | Overwritten in place, one row per key, no purge. |
| Favicon files | Stored with the logo; removed when the logo is removed and with the tenant folder on deletion. |

No new table holds personal data. Data-subject erasure (`internal/datasubject`) is unaffected: it targets addresses in tenant tables, none of which changes. The `delegatedAdmin.email` given to the provisioning API lands in `admins`, covered by the existing admin rules.

**Tenant deletion.** `Tenants.Delete` is unchanged. Deleting a tenant created by a token reduces its `tenantsCreated`; the token row stays.

## 5. Impact on existing behaviour

- **Public paths in `setup`**: as implemented (step 5, user decision), refusal by default: every operation of the tenant API router reads `tenants.setup_state` from the tenant already loaded for the request (no extra query) and answers `503 tenant-in-setup`, consistent with the maintenance answer, except a closed allowlist (`getPublicTenant`, `getTenantAsset`, `getTenantLegalDocument`, and the instance `getVersion`). Downloads and "my transfers" are refused too, although a tenant in setup holds no transfer (there is no transition back to `setup`). `/healthz`, the other instance routes and the admin API are unaffected.
- **Tenant creation**: `INSERT INTO tenants` gains `setup_state`, `background_preset`, `provisioned_by`. The store already writes `setup_state = 'active'` explicitly since step 1 (the PostgreSQL default is dropped). Raw SQL inserts of tests must name `setup_state` on PostgreSQL at 0022 and later; inserts on an older schema (upgrade tests) are backfilled by 0022.
- **SMTP configuration update**: moves `tenant_smtp_settings.updated_at` strictly forward, which invalidates `smtp_tested_at` (see section 2.1; the design said "sets `smtp_tested_at = NULL` in the same statement", impossible from the tenant-scoped transaction under the `tenants` policies).
- **Schema parity test**: the live comparison of named indexes between engines now includes `tenants_provisioned_by_idx` and `provisioning_tokens_created_idx`. The store tests that count applied migrations expect 12 from a V1 database (0014 to 0025).

## 6. ER summary

```mermaid
erDiagram
    tenants ||--o{ admin_tenants : "delegated admins"
    admins ||--o{ admin_tenants : "attached to"
    admins ||--o{ admin_activations : "activation links (delivery, language)"
    provisioning_tokens |o--o{ tenants : "provisioned_by, no ON DELETE"
    admins }o..o{ provisioning_tokens : "created_by, no FK"
    system_state : "instance key/value (update_check)"
```

## 7. Decisions and open points

| Topic | Decision | Where |
|---|---|---|
| Existing tenants | Backfilled to `active` by the column default | §2.1 |
| Presets | Slug validated in code, not by a database list | §1, §2.1 |
| Provisioning token | Separate table, SHA-256 only, revoke never delete, counters computed | §2.2 |
| Instance tables | System-scope-only RLS, same as `admins` | §3 |
| Update check cache | Generic `system_state` key/value | §2.4 |

Open points for review:

1. **`mail_templates_reviewed_at`** is an addition to the brief's data model, needed to persist the optional "reviewed" flag of the wizard item `mail_templates`. Alternative: drop it and make the item always `done` (no persistence).
2. **`created_by` without a foreign key**: chosen so that deleting an admin is never blocked by a token. Alternative: `REFERENCES admins (id)` with `ON DELETE RESTRICT`, which forbids deleting an admin who created tokens.
3. **Failure lockout for provisioning tokens**: assumed to reuse the API token mechanism (to be confirmed against `internal/store` when implementing step 6; a new `scope` value on `admin_login_failures` or an in-memory limiter, which would be a CHECK migration).
4. **`setup_state` stays two-valued.** A later state such as `suspended` costs a rebuild of `tenants`; accept it, or widen the check now at no cost on PostgreSQL (SQLite would still need a rebuild).
5. **`provisioning_tokens` purge**: none in V1.2. Revoked and expired tokens stay listed; confirm that is acceptable or add a purge of tokens revoked for over 12 months without tenants.

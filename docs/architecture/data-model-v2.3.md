# TransTeira V2.3: data model (express secrets)

> V2.3, express secret, data part. Status: **proposal, to be validated before any code**.
> Sources: CLAUDE.md (sections 2 and 22.2), `api/openapi.yaml` (`createExpressSecret`,
> `SecretSettings`, `AdminSecret`), `docs/architecture/data-model-v2.1.md` (the `secrets` table,
> migrations 0033 to 0035), `docs/architecture/e2e-format.md` (section 3.3.9), migrations
> `internal/store/migrations/{sqlite,postgres}/0001..0035`. The migration 0036 described here is
> written with the implementation step, on both engines.

## 1. Principles

All V1 to V2.1 conventions still apply (see `data-model-v2.1.md`, section 1). An express secret
is **a row of the existing `secrets` table**, not a new table: it is a 2.1 secret restricted to
one profile (e2e-format.md §3.3.9), read by the same recipient operations (`GET
/secret-links/{token}`, `POST .../reveal`, page `/s/<token>`), swept by the same lifecycle
tasks, listed and deleted by the same admin operations.

| Topic | Rule |
|---|---|
| One table | New column `secrets.express` (0/1). The express profile is enforced by checks: link delivery, no passphrase, no file, no read receipt, created `active`, durations `1h`, `1d`, `7d`. |
| No creator address | `secrets.sender_email` becomes nullable: NULL **exactly** for express rows (anonymous ones and those created with an API token). A new creator kind `anonymous` (no token, no invitation). |
| Defaults | The anonymous mode is **off by default**, for new and existing tenants (`tenants.express_enabled = 0`); limits 10 per hour per IP, 100 per hour per token, 1 000 live express secrets per tenant. No existing row changes (`express = 0` everywhere after the migration). |
| Zero knowledge | Unchanged: the database never holds the token (SHA-256 only), `K`, a proof or the plaintext. An express row holds **no personal data**: no address, no IP (the per-IP limiter is in memory, section 2.3). |
| Tenant scoping | Unchanged: `secrets_isolation` (PostgreSQL RLS) covers express rows; the new tenant settings are `tenants` columns written in the system scope. |
| Parity | Same columns, constraints and named indexes on both engines (`TestLiveSchemaMatches`). `express` is the **last** column of `secrets` on both engines (PostgreSQL `ADD COLUMN` appends it; the SQLite rebuild puts it last). |

## 2. Migration 0036 `express_secrets`

| # | Name | Content |
|---|---|---|
| 0036 | `express_secrets` | `tenants`: `express_enabled`, `express_per_hour_ip`, `express_per_hour_token`, `express_max_pending`. `api_tokens`: `express_allowed`. `secrets`: column `express`, `creator_kind` widened with `anonymous`, `sender_email` nullable, express profile checks, index `secrets_express_live_idx`. `abuse_reports`: column `secret_id`, `transfer_id` and `sender_email` nullable, report target checks, index `abuse_reports_secret_rate_idx`. SQLite rebuilds `secrets` and `abuse_reports`; PostgreSQL alters both in place. |

### 2.1 Tenant settings

```sql
-- tenants (ADD COLUMN on both engines, no rebuild)
express_enabled        INTEGER NOT NULL DEFAULT 0    CHECK (express_enabled IN (0, 1))                 -- PG BOOLEAN DEFAULT false
express_per_hour_ip    INTEGER NOT NULL DEFAULT 10   CHECK (express_per_hour_ip BETWEEN 1 AND 1000)    -- PG tenants_express_per_hour_ip_check
express_per_hour_token INTEGER NOT NULL DEFAULT 100  CHECK (express_per_hour_token BETWEEN 1 AND 10000) -- PG tenants_express_per_hour_token_check
express_max_pending    INTEGER NOT NULL DEFAULT 1000 CHECK (express_max_pending BETWEEN 1 AND 100000)  -- PG tenants_express_max_pending_check
```

- **API mapping.** `SecretSettings.expressEnabled`, `expressPerHourPerIp`,
  `expressPerHourPerToken`, `expressMaxPending` (`GET|PUT
  /admin/tenants/{tenantId}/secret-settings`, delegated admin and super admin, audited
  `secret.settings_updated`). They are optional in the `PUT`: an absent member keeps the stored
  value (the service reads the row and overwrites only the members present), so a 2.1 client
  never resets them. Exported and imported with the tenant configuration
  (`TenantConfigExport.secretSettings`); an import without them takes the column defaults.
- **Import.** `importTenant` always writes `express_enabled = 0`, whatever the document says
  (threat model P92: opening an anonymous service on a new FQDN is a deliberate admin
  action); the limits are imported as given or take the defaults.
- **Kill switch.** `TT_EXPRESS_SECRETS_DISABLED=true` (environment, instance-wide) is **not** a
  column: it overrides `express_enabled` at request time without changing it, refuses token
  creations too, and makes `features.expressSecrets.enabled` false.
- **Independence from the 2.1 module.** `secrets_enabled` governs `POST /secrets` only;
  `express_enabled` governs anonymous `POST /express-secrets` only. The recipient operations
  ignore both, as in 2.1.
- `SQLite`: `ALTER TABLE tenants ADD COLUMN` with a constant default and a check on the new
  column (no rebuild of `tenants`). `PostgreSQL`: `ALTER TABLE tenants ADD COLUMN ...` with
  named checks; its policies (`tenants_read_own`, `tenants_system`) are unchanged.

### 2.2 `secrets`: new column, widened origin, express profile

**Column changes** (relative to 0033):

```sql
creator_kind  TEXT NOT NULL CHECK (creator_kind IN ('internal', 'internal_remote', 'external', 'api_token', 'anonymous')),
sender_email  TEXT          CHECK (sender_email IS NULL OR length(sender_email) BETWEEN 3 AND 320),  -- was NOT NULL
...
express       INTEGER NOT NULL DEFAULT 0 CHECK (express IN (0, 1))                                    -- PG BOOLEAN DEFAULT false, last column
```

**New table checks** (PostgreSQL names in comments):

```sql
-- Creator address: absent exactly for express secrets.
CHECK ((sender_email IS NULL) = (express = 1)),                                 -- PG secrets_express_sender_check
-- Anonymous creators exist only for express secrets; express creators are
-- anonymous or an API token (never a session, an invitation or a drop link).
CHECK (creator_kind <> 'anonymous' OR express = 1),                             -- PG secrets_anonymous_check
CHECK (express = 0 OR creator_kind IN ('anonymous', 'api_token')),              -- PG secrets_express_kind_check
-- Express profile: link, no receipt, no passphrase, no file, fixed durations.
CHECK (express = 0 OR (delivery = 'link' AND read_receipt = 0 AND kdf_salt IS NULL
                       AND file_size IS NULL)),                                 -- PG secrets_express_profile_check
CHECK (express = 0 OR duration_code IN ('1h', '1d', '7d')),                     -- PG secrets_express_duration_check
-- Created active: never pending, activated at its creation.
CHECK (express = 0 OR (state <> 'pending' AND activated_at = created_at)),      -- PG secrets_express_active_check
```

Consequences, together with the unchanged 0033 checks:

- **anonymous** ⇒ `express = 1`, `sender_email` NULL, `api_token_id` NULL
  (`secrets_api_token_check`: `(creator_kind = 'api_token') = (api_token_id IS NOT NULL)`) and
  `invitation_id` NULL (`secrets_external_check`). Conversely an express row with NULL
  `api_token_id` is anonymous. This is the "anonymous ⇔ no address and no token" rule; a
  non-express row always has an address.
- **express with a token**: `creator_kind = 'api_token'`, `api_token_id` set (composite foreign
  key, same tenant), `sender_email` NULL. Decision: **no declared sender** for an express
  secret, even with a token (section 22.2: no address; the token is the accountable identity in
  the audit, `api_token.used` has the token as actor). A 2.1 `api_token` row keeps its
  mandatory `sender_email` (`secrets_express_sender_check`).
- **no passphrase**: `kdf_salt` NULL, hence `kdf_iterations` NULL (`secrets_kdf_check`), in every
  state. **no file**: `file_size` NULL, hence no storage name, upload, grant or download
  (`secrets_no_file_check`), and `file_metadata` NULL (`secrets_file_live_check` while live,
  `secrets_file_metadata_live_check` after). **no receipt**: `read_receipt = 0`, hence
  `receipt_sent_at` NULL (`secrets_receipt_check`). **link**: `recipient_email` NULL
  (`secrets_recipient_check`).
- **created active**: the creation inserts the row `active` with `activated_at = created_at`
  (the store uses one timestamp for both) and `expires_at = created_at + duration`. Every
  tombstone of an express row therefore has its activation, `deleted` included.
- The external and invitation rules (`secrets_external_check`,
  `secrets_external_delivery_check`) and every lifecycle, content and key check of 0033 are
  unchanged and apply to express rows as to any other.

**New index** (the tenant cap, section 2.3):

```sql
CREATE INDEX secrets_express_live_idx ON secrets (tenant_id, expires_at)
    WHERE express AND state = 'active';           -- the same text on both engines
```

The condition is written `express AND ...` on SQLite too, as in the store queries: SQLite
matches the terms of a partial index literally, so an index on `express = 1` would not serve a
query on `express` (the portable form, since PostgreSQL refuses `boolean = integer`).

#### SQLite: rebuild of `secrets`

SQLite cannot drop `NOT NULL` or alter a check, so `secrets` is rebuilt as in 0015, 0031 and
0034 (create, copy, drop, rename), in the single transaction of the migration:

1. `CREATE TABLE secrets_0036 (...) STRICT` with **every** column of 0033 in the same order and
   with the same definitions (types, defaults, `UNIQUE` on `token_hash`, `text_key_id`,
   `file_key_id`, `UNIQUE (tenant_id, id)`, `REFERENCES tenants (id) ON DELETE CASCADE`,
   `REFERENCES wrapped_keys (id) ON DELETE SET NULL` on both key columns, the composite foreign
   keys to `invitations` and `api_tokens` without action), the two changed column definitions
   above, `express` as the last column, all 0033 table checks verbatim and the six new ones.
2. `INSERT INTO secrets_0036 (<every 0033 column>) SELECT <every 0033 column> FROM secrets;`
   (`express` takes its default 0; every existing row has a `sender_email` and a 2.1 creator
   kind, so every new check holds).
3. `DROP TABLE secrets;` then `ALTER TABLE secrets_0036 RENAME TO secrets;`
4. Recreate **every** index of 0033 (dropping the table dropped them): the ten named indexes
   `secrets_tenant_created_idx`, `secrets_sender_created_idx`, `secrets_token_created_idx`,
   `secrets_recipient_idx`, `secrets_invitation_idx`, `secrets_pending_idx`,
   `secrets_expiry_idx`, `secrets_grant_idx`, `secrets_ended_idx`,
   `secrets_file_storage_idx` (unique), with their exact columns and partial `WHERE` clauses,
   plus the new `secrets_express_live_idx`. The automatic indexes of the `UNIQUE` constraints
   come back with the table definition.

Why it is safe:

- **No table references `secrets`** (no `REFERENCES secrets` in any migration), so dropping and
  renaming it breaks no foreign key; its own references (to `tenants`, `wrapped_keys`,
  `invitations`, `api_tokens`) are carried by the new definition.
- The migrator runs every SQLite migration on a reserved connection with **foreign keys off**
  (`PRAGMA foreign_keys = OFF` before the transaction, checked by `checkForeignKeysOff`), so
  `DROP TABLE secrets` cascades nowhere and the `ON DELETE SET NULL` of the key columns does not
  fire; before committing it runs `pragma_foreign_key_check` (`checkForeignKeys`), which proves
  that the copied rows still reference existing tenants, keys, invitations and tokens, then
  restores enforcement.
- **No trigger or view** references `secrets` (the `wrapped_keys` triggers are on
  `wrapped_keys`), so the rename rewrites nothing else.
- The wrapped keys of live secrets are untouched (same IDs copied), so the hardening checks
  (`secrets_text_key_check`, `secrets_file_key_live_check`) hold in the copy.

#### PostgreSQL: in place

```sql
ALTER TABLE secrets ADD COLUMN express BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE secrets DROP CONSTRAINT secrets_creator_kind_check,
    ADD CONSTRAINT secrets_creator_kind_check
        CHECK (creator_kind IN ('internal', 'internal_remote', 'external', 'api_token', 'anonymous'));
ALTER TABLE secrets ALTER COLUMN sender_email DROP NOT NULL;
ALTER TABLE secrets DROP CONSTRAINT secrets_sender_email_check,
    ADD CONSTRAINT secrets_sender_email_check
        CHECK (sender_email IS NULL OR length(sender_email) BETWEEN 3 AND 320);
ALTER TABLE secrets
    ADD CONSTRAINT secrets_express_sender_check CHECK ((sender_email IS NULL) = express),
    ADD CONSTRAINT secrets_anonymous_check CHECK (creator_kind <> 'anonymous' OR express),
    ADD CONSTRAINT secrets_express_kind_check CHECK (NOT express OR creator_kind IN ('anonymous', 'api_token')),
    ADD CONSTRAINT secrets_express_profile_check
        CHECK (NOT express OR (delivery = 'link' AND NOT read_receipt AND kdf_salt IS NULL AND file_size IS NULL)),
    ADD CONSTRAINT secrets_express_duration_check CHECK (NOT express OR duration_code IN ('1h', '1d', '7d')),
    ADD CONSTRAINT secrets_express_active_check
        CHECK (NOT express OR (state <> 'pending' AND activated_at = created_at));
CREATE INDEX secrets_express_live_idx ON secrets (tenant_id, expires_at) WHERE express AND state = 'active';
```

- The column checks of 0033 were declared inline without a name, so PostgreSQL named them
  `secrets_creator_kind_check` and `secrets_sender_email_check` (`<table>_<column>_check`); the
  migration drops and re-adds them **under the same names**, so that later migrations and
  `TestLiveSchemaMatches` see stable names. The implementation checks these names against a
  migrated database before writing the migration.
- `ADD COLUMN ... DEFAULT false` is a metadata-only change; the new checks are validated against
  the existing rows (all `express = false` with an address: they pass).
- **RLS unchanged**: `secrets_isolation` (ENABLE + FORCE) applies to the new column and rows; no
  policy is created or altered. `verifyRLS` and `TestRLSRoleCannotBypass` need no change.

### 2.2a `api_tokens.express_allowed`

```sql
-- api_tokens (ADD COLUMN on both engines, no rebuild)
express_allowed INTEGER NOT NULL DEFAULT 0 CHECK (express_allowed IN (0, 1))   -- PG BOOLEAN DEFAULT false
```

The explicit opt-in of a token for `createExpressSecret` (`ApiToken.expressAllowed`, set by
`createApiToken` / `updateApiToken`, audited in `api_token.created` / `api_token.updated`).
Existing tokens get 0: no integration starts creating express secrets without an admin
decision. `api_tokens` is a tenant table (`api_tokens_isolation` on PostgreSQL, unchanged);
SQLite accepts the `ADD COLUMN` with a constant default and a check on the new column.

### 2.2b `abuse_reports`: reports on express secrets

`reportSecretAbuse` stores its reports in the existing `abuse_reports` table (same list, same
closing workflow, same alerts, same 12-month retention as the transfer reports, V1.1 0017),
with the secret instead of the transfer:

```sql
transfer_id   TEXT,               -- was NOT NULL; NULL for a report on a secret
sender_email  TEXT,               -- was NOT NULL; NULL for a report on a secret (no creator address)
...
secret_id     TEXT,               -- new, last column: the reported "sec_" ID (snapshot, no foreign key)
CHECK ((transfer_id IS NULL) <> (secret_id IS NULL)),                 -- PG abuse_reports_target_check
CHECK ((sender_email IS NULL) = (secret_id IS NOT NULL)),             -- PG abuse_reports_sender_check
CHECK (secret_id IS NULL OR (recipient_link_id IS NULL AND reporter_verified = 0)),
                                                                      -- PG abuse_reports_secret_check
CREATE INDEX abuse_reports_secret_rate_idx ON abuse_reports (tenant_id, secret_id, created_at)
    WHERE secret_id IS NOT NULL;
```

- `secret_id` is a **snapshot without foreign key**, like `transfer_id`: a report outlives the
  secret and its tombstone (30 days) for its 12-month retention. A report on a secret never
  holds an address (no sender, unverified reporter), only the reporter IP (`reporter_ip`, as
  for transfers, purged with the report).
- Rate limits: 3 reports per secret per day through `abuse_reports_secret_rate_idx`, 5 per IP
  per hour through the existing `abuse_reports_ip_rate_idx` (shared with transfer reports), and,
  in memory, 5 per hour per tenant and client key (IPv4 address or IPv6 /64), since anyone can
  create express secrets to report: rotating addresses within a /64 does not multiply the alerts.
  `abuse_reports_shared_rate_idx` (`WHERE recipient_link_id IS NULL`) also indexes the secret
  rows with a NULL `transfer_id`; harmless, kept unchanged for parity.
- **SQLite**: `transfer_id` and `sender_email` lose `NOT NULL`, so the table is rebuilt exactly
  as `secrets` (section 2.2): `abuse_reports_0036` with every 0017 column in order, the two
  relaxed columns, `secret_id` last, the 0017 checks verbatim plus the three new ones; rows
  copied; old table dropped; copy renamed; the six 0017 indexes recreated
  (`abuse_reports_list_idx`, `abuse_reports_link_rate_idx`, `abuse_reports_shared_rate_idx`,
  `abuse_reports_ip_rate_idx`, `abuse_reports_sender_idx`, `abuse_reports_reporter_idx`) plus
  the new one. No table, trigger or view references `abuse_reports`.
- **PostgreSQL**: `ALTER COLUMN transfer_id DROP NOT NULL`, `ALTER COLUMN sender_email DROP
  NOT NULL`, `ADD COLUMN secret_id TEXT COLLATE "C"`, the three named checks and the index;
  `abuse_reports_isolation` unchanged.
- The data-subject erasure and search by address (`abuse_reports_sender_idx`,
  `abuse_reports_reporter_idx`) never match a report on a secret (NULL addresses).

### 2.3 Store rules (creation of an express secret)

`Secrets.CreateExpress` (name indicative) inserts one row in a single write transaction, under
the tenant lock already used by the 2.1 creation limits:

1. **Tenant cap** (`express_max_pending`). In the creation transaction:

   ```sql
   SELECT count(*) FROM secrets
   WHERE tenant_id = ? AND express AND state = 'active' AND expires_at > ?   -- now
   ```

   served by `secrets_express_live_idx` (a range scan on `(tenant_id, expires_at)`
   restricted to live express rows; at most `express_max_pending` entries per tenant plus those
   not yet swept). An active row past `expires_at` is not counted: it is already answered as
   expired. The count covers **all** express secrets of the tenant (anonymous and token), but
   only an **anonymous** creation is refused when `count >= express_max_pending`
   (`429 express-secret-limit-reached`); a token creation is inserted anyway, so the count may
   exceed the cap through tokens. Lowering the setting deletes nothing.
2. **Per-token hourly limit** (`express_per_hour_token`), in the same transaction:
   `SELECT count(*) ... WHERE tenant_id = ? AND api_token_id = ? AND express = 1 AND created_at
   > ?` (now minus one hour), through `secrets_token_created_idx`. Exact and restart-proof:
   express rows are never deleted within an hour (tombstones live 30 days; only the data-subject
   erasure, which never matches them, and the tenant deletion remove rows). `Retry-After` is
   the time until the oldest counted row leaves the window.
3. **Per-IP hourly limit** (`express_per_hour_ip`): **in memory**, a sliding one-hour window
   per (tenant, client key), the client key being the IPv4 address or the IPv6 /64, as the
   other limiters. Not in the database: storing client IPs on secret rows would be personal
   data kept 30 days for a one-hour limit (minimization). Reset at a restart (single instance;
   at worst one extra hour of quota, accepted). Charged after the body checks (a malformed call
   counts against no limit). One table per tenant, at most 100 000 clients each: a new client
   replaces a client without event in the window, else the least recently seen client below the
   limit; a client at its limit is never forgotten, so a tenant whose least recently seen
   clients are all at their limit refuses a new client (`429 express-secret-limit-reached`,
   `express_refused` reason `limit`, never `express_ip` against that client) without effect on
   the other tenants.
4. Insert: `express = 1`, `creator_kind` `anonymous` (`api_token_id` NULL) or `api_token`
   (`api_token_id` set), `sender_email` NULL, `delivery = 'link'`, `read_receipt = 0`,
   `kdf_*` NULL, `file_*` NULL, `state = 'active'`, `activated_at = created_at = now`,
   `expires_at = now + duration`, `token_hash`, both verifiers, `text_sealed` and its new `dek`
   key (`Vault.NewDEKTx`), exactly as a 2.1 link secret without file.

The token opt-in (`api_tokens.express_allowed = 1`) is checked by the service before the
transaction, with the token already authenticated (`403 express-token-not-allowed`), and again
in the transaction with the token row: a token revoked or expired since its authentication is
`401 invalid-credentials` (`api_token_invalid`), as the token middleware answers it.

The 2.1 per-creator limits (50 open, 200 per 24 hours, `secrets_sender_created_idx` /
`secrets_token_created_idx`) are not checked for express secrets, and the 2.1 counts exclude
them (`AND express = 0`), so that express use with a token never consumes the 2.1 quota of that
token.

### 2.4 Read block, lookup and purge (no schema change)

- **Read block of a closed service.** `GET /secret-links/{token}` and `POST .../reveal` look
  the token up first (unknown: `404`, `secret_invalid`, as before), then, for a row with
  `express = 1`, refuse with `403 express-secrets-disabled` when the kill switch is on, or when
  `tenants.express_enabled = 0` and `creator_kind = 'anonymous'`. The check reads the row only:
  no update, no `failed_proofs` slot, no failure counted, whatever the state; nothing in the
  schema changes. `expires_at` keeps running (no suspension).
- **Status members.** `SecretStatus.express` and `anonymous` come from `secrets.express` and
  `creator_kind = 'anonymous'`.
- **Lookup by link** (`lookupTenantSecret`). The service extracts the `tts_` token, drops the
  fragment, computes its SHA-256 and reads `secrets` by `token_hash` in the tenant scope (the
  unique index on `token_hash`), any state. Nothing is written but the audit entry
  `secret.looked_up` (the `sec_` ID).
- **Purge** (`purgeExpressSecrets`). Selects the live anonymous express rows of the tenant
  (`express = 1 AND creator_kind = 'anonymous' AND state = 'active'`, through
  `secrets_express_live_idx`) and ends each one exactly as `deleteTenantSecret` does
  (`state = 'deleted'`, `end_reason = 'deleted_by_admin'`, `ended_at`, content columns NULLed,
  then its text key destroyed with `Vault.DestroyTx`: cryptographic erasure, threat model
  T-369), in batches of at most 500 rows per write transaction so that the SQLite writer is
  never held long; the total is returned and audited once (`secret.express_purged`,
  `details.count`). A listed row ended meanwhile by a reveal, the expiry task or a deletion (the
  list takes no row lock; PostgreSQL reads at READ COMMITTED) is skipped, its key left to that
  operation, and not counted. A failure midway leaves the already ended batches ended: calling
  again finishes the work.

## 3. PostgreSQL RLS summary

| Table | Change | RLS |
|---|---|---|
| `tenants` | 4 columns, 3 named checks | Unchanged (`tenants_read_own`, `tenants_system`); written in the system scope. |
| `secrets` | 1 column, 2 checks replaced, 6 checks added, 1 index | Unchanged (`secrets_isolation`). |
| `api_tokens` | 1 column with its check | Unchanged (`api_tokens_isolation`). |
| `abuse_reports` | 1 column, 2 `NOT NULL` dropped, 3 checks, 1 index | Unchanged (`abuse_reports_isolation`). |

## 4. Purge, lifecycle and statistics

Unchanged; express rows follow the 2.1 rules of `data-model-v2.1.md`, section 4:

| Data | Rule |
|---|---|
| Live express secret | At `expires_at` (1 hour, 1 day or 7 days after the creation) the `expire` task makes it `expired` and destroys its text and key (`secrets_expiry_idx`). The reveal makes it `read` (text returned once, key destroyed). |
| Pending purge | Not applicable (never `pending`). |
| Tombstones | Deleted 30 days after `ended_at` (`secrets_ended_idx`). An express tombstone holds no address and no IP: only the dates, the state and the token hash (for the `410 secret-gone` answer). |
| Data-subject erasure | Never matches an express row (no `sender_email`, no `recipient_email`); `DataSubjectSummary.secrets` and `secretsDeleted` are unchanged. |
| Tenant deletion | Unchanged (the secrets of the tenant are deleted before its key loop). |
| Admin deletion | `deleteTenantSecret` works on express rows (`end_reason = 'deleted_by_admin'`); `purgeExpressSecrets` does the same for every live anonymous express row (section 2.4). |
| Abuse reports on secrets | `abuse_reports` rows with `secret_id`, purged after 12 months like the transfer reports. |
| Statistics | `tenant_daily_stats.secrets_created` (0035) counts express creations too (`TenantStats.secretsCreated`); `/status` `secretsCreatedLast24h` / `secretsReadLast24h` and the Prometheus secret counters include them. No new counter. |
| Abuse detection | `Transfers.SenderActivity` counts secrets by address: express rows (no address) are never counted. |
| `tenants.express_*` | Configuration, tenant lifetime. |

The audit events (`secret.created` with `details.express: true`, `secret.revealed`,
`secret.expired`, `secret.deleted`) and the security events (`express_refused`,
`rate_limited` scopes `express_ip` and `express_token`) keep their 12-month retention and never
carry content, key, proof, verifier or token.

## 5. Impact on existing behaviour

- **`sender_email` nullable.** Every store read of `secrets.sender_email` must accept NULL
  (`sql.NullString` or a pointer); the admin list returns `senderEmail` absent and
  `express: true` for these rows. `/me/secrets` filters on `sender_email = ?` and never returns
  them. The creator-side operations of 2.1 (`uploadSecretFile`, `sendSecret`) never apply to an
  express row (it is `active` and has no file or e-mail delivery: `409 state-conflict`, or
  `404` for a session, whose address never matches NULL).
- **Admin list filter.** `listTenantSecrets?sender=` compares with `sender_email`, so it never
  matches an express row.
- **Upgrade tests.** The tests that count applied migrations gain one (from a V1 database:
  0014 to 0036; from scratch: 36). A `TestV23SchemaConstraints` checks, on both engines, the
  new checks (an anonymous non-express row, an express row with an address, a passphrase, a
  file, a receipt, an e-mail delivery, a `12h` duration, a `pending` state or
  `activated_at <> created_at` are refused; an anonymous and a token express row are
  accepted; an abuse report with both or neither of `transfer_id` / `secret_id`, or a secret
  report with an address, is refused) and that both SQLite rebuilds kept every index
  (`pragma_index_list`) and foreign key (`pragma_foreign_key_list`).
- **Abuse reports.** Every store read of `abuse_reports.transfer_id` and `sender_email` must
  accept NULL; `AbuseReport.transferId` / `senderEmail` are absent and `secretId` present for a
  report on a secret.
- **Inserts.** Unchanged for 2.1 rows (`express` defaults to 0, `sender_email` still given).
- **Master key rotation.** Unchanged (the text key is an ordinary `dek` row).

## 6. Decisions

| # | Topic | Choice | Where |
|---|---|---|---|
| E1 | Storage | A row of `secrets` with `express = 1`, no new table | §1 |
| E2 | `sender_email` of a token express secret | NULL, like an anonymous one: `sender_email IS NULL` ⇔ `express`; the token is the accountable identity | §2.2 |
| E3 | Creation activation | `activated_at = created_at` enforced by a check | §2.2 |
| E4 | Tenant cap | Counts every live express row (`state = 'active' AND expires_at > now`), refuses anonymous creations only; index `secrets_express_live_idx` | §2.3 |
| E5 | Hourly limits | Per token in the database (exact), per IP in memory (no IP stored) | §2.3 |
| E6 | 2.1 per-creator limits | Not applied to express secrets, which are excluded from the 2.1 counts | §2.3 |
| E7 | PostgreSQL constraint names | The two inline 0033 checks are replaced under their generated names | §2.2 |
| E8 | Token opt-in | `api_tokens.express_allowed`, default 0 for new and existing tokens; refusal `403 express-token-not-allowed`, security event `express_refused` `reason=token`, not counted by fail2ban/CrowdSec | §2.2a |
| E9 | Reports on secrets | Same `abuse_reports` table (one admin workflow), `secret_id` snapshot, `transfer_id`/`sender_email` nullable; SQLite rebuild | §2.2b |
| E10 | Read block | Service rule after the token lookup (unknown token still `404` first), no schema change, nothing counted | §2.4 |
| E11 | Purge | Batches of 500 ended like an admin deletion, one audit entry | §2.4 |
| E12 | Import | `express_enabled` forced to 0 | §2.1 |

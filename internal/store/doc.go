// Package store is the data access layer of TransTeira, on SQLite (default)
// or PostgreSQL (CLAUDE.md §17). It holds metadata only, never file
// contents.
//
// # Tenant isolation
//
// Isolation between tenants (CLAUDE.md §5) is enforced at the lowest level,
// in three layers:
//
//  1. Registered statements. Every SQL statement of the package is declared
//     at package level with tenantQuery, reviewedTenantQuery or
//     systemQuery, which panic at start-up on a statement breaking the
//     rules. All of them: one statement, bare "?" placeholders only (no
//     $n, ?NNN, :name, @name), no quoted identifier, no prefixed literal,
//     no nested comment, no set_config, current_setting, pg_* name or
//     'app.*' literal. tenantQuery also requires a single table (no join,
//     subquery or second table) and exactly one tenant slot: a
//     "tenant_id = ?" conjunct of the top-level WHERE clause, qualified
//     only by the target table or its alias, or, for a single-row INSERT,
//     the tenant_id column with a bare "?" value. No top-level OR, UNION,
//     CASE or BETWEEN may escape the predicate, and an UPDATE may not set
//     tenant_id. The slot position and the placeholder count are recorded.
//     reviewedTenantQuery lifts the single-table rule after a security
//     review; systemQuery requires a reason. Tests pin the exact set of
//     tenant, reviewed and system queries.
//  2. Typed executors. A [TenantQuery] only runs through a [ScopedTx],
//     obtained from [DB.Scoped] for a validated [tenant.ID]; the executor
//     binds the tenant at the recorded slot itself, so callers can neither
//     forget nor forge it, and checks the argument count. A [SystemQuery]
//     only runs through a [SystemTx], obtained from [DB.System] with a
//     reason logged at info level for every transaction (a proper audit
//     trail comes with the audit package). The two query types are
//     structurally distinct, so neither converts to the other, the
//     executors check the kind again at run time, and queries can only be
//     declared inside this package.
//  3. PostgreSQL row-level security with two roles. The migrations run as
//     an owner role (TT_DB_MIGRATE_DSN, used by [DB.Migrate] only); the
//     application connects as a runtime role (TT_DB_DSN) that owns nothing
//     and is granted DML on the tables, so it cannot disable the policies.
//     [Open] and [DB.Migrate] run [DB.Verify], which refuses to start when
//     the runtime role is a superuser, has BYPASSRLS, owns or may create
//     application objects, belongs to such a role, or when a tenant-scoped
//     table lacks ENABLE and FORCE row-level security and a policy. Each
//     scoped transaction sets app.tenant_id (transaction-local, never
//     session-level, so pooled connections cannot leak it) and the policies
//     only expose rows of that tenant (its own tenants row read-only);
//     system transactions set app.system_scope instead.
//
// Repository methods take the tenant ID as an explicit parameter. A row of
// another tenant is reported as [ErrNotFound], exactly like a missing row.
//
// # Portability
//
// Statements are written once with "?" placeholders, rewritten to "$n" for
// PostgreSQL. Identifiers are TEXT, timestamps BIGINT Unix milliseconds
// (UTC) and booleans BOOLEAN (PostgreSQL) or INTEGER 0/1 (SQLite), which
// database/sql converts to and from Go bool on both engines.
//
// # Schema migrations
//
// Versioned SQL files are embedded per engine (migrations/sqlite and
// migrations/postgres) and applied by [DB.Migrate], each in its own
// transaction. The binary refuses a database migrated by a newer version.
package store

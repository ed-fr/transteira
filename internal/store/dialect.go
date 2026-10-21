package store

import (
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ed-fr/transteira/internal/config"
)

// dialect captures the differences between the supported engines. Portable
// statements are written once, with "?" placeholders; the few
// engine-specific statements below are plumbing that never touches tenant
// data.
type dialect struct {
	// name is the engine name, config.DriverSQLite or config.DriverPostgres.
	name string
	// numbered is true when placeholders must be rewritten to "$n".
	numbered bool
	// scopeTenant, when set, is executed first in every tenant-scoped
	// transaction with the tenant ID as its only argument. It sets the
	// transaction-local settings read by the row-level security policies.
	scopeTenant string
	// scopeSystem, when set, is executed first in every system transaction.
	scopeSystem string
	// lockTenant, when set, takes a transaction-scoped lock on the tenant
	// given as its only argument, serializing read-modify-write operations
	// of the same tenant (such as replacing its network rules). SQLite needs
	// none: its write transactions are already serialized (BEGIN IMMEDIATE
	// on the single writer connection).
	lockTenant string
	// lockWrappedKeys, when set, blocks every concurrent write to wrapped_keys
	// until the end of the transaction, so that no key can be wrapped under
	// the old master key after a completing rotation counted the remaining
	// ones (PostgreSQL, READ COMMITTED). SQLite needs none: BEGIN IMMEDIATE
	// already excludes every other writer, in this process (single writer
	// connection) and in others (database lock).
	lockWrappedKeys string
	// isolation, when not sql.LevelDefault, is the isolation level every
	// transaction is opened with, whatever the server default
	// (default_transaction_isolation). The tenant lock followed by a count
	// (rate limits, upserts) relies on READ COMMITTED: each statement sees
	// the rows committed before it, including those committed while it
	// waited for the lock. SQLite has a single isolation level and needs
	// none.
	isolation sql.IsolationLevel
	// scrubDeleted, when set, is run by [DB.ScrubDeleted] on the write pool
	// and returns (busy, log frames, checkpointed frames).
	scrubDeleted string
	// backup, when set, is run by [DB.Backup] on the write pool, outside
	// any transaction, with the destination path as its only argument.
	backup string
	// migrationLock, when set, serializes concurrent migrators. It runs at
	// the start of each migration transaction and is released at its end.
	migrationLock string
	// migrationsTableExists counts the schema_migrations tables visible to
	// the connection (0 or 1) without creating anything.
	migrationsTableExists string

	// ownerMigrations is true when migrations run with a separate owner
	// role, the runtime role holding DML rights only (PostgreSQL).
	ownerMigrations bool
	// identity returns the connection's role and current schema (NULL when
	// no schema of the search path is usable).
	identity string
	// grants returns the statements giving role its runtime rights on
	// schema; both names are raw and quoted by the function.
	grants func(schema, role string) []string
	// verifyRole returns (is superuser, has BYPASSRLS) for the connection's
	// role. An empty value disables [DB.Verify].
	verifyRole string
	// verifyOwnership counts the schemas and relations of the search path
	// owned by the connection's role.
	verifyOwnership string
	// verifyMembership counts the roles, other than the connection's, that
	// it is a member of and that are superusers, have BYPASSRLS or own a
	// schema or relation of the search path.
	verifyMembership string
	// verifyCreate counts the (schema of the search path, role) pairs where
	// the connection's role, or any role it is a member of (inherited or
	// via SET ROLE), may create objects, plus one when it may create
	// schemas in the database.
	verifyCreate string
	// verifyTemp tells whether the connection's role may create temporary
	// tables (a warning only: pg_temp tables could shadow application
	// tables).
	verifyTemp string
	// verifyRLS lists the tenant-scoped tables of the current schema (with a
	// tenant_id column), plus the tenants registry and the system key tables,
	// lacking ENABLE and FORCE row-level security or a policy.
	verifyRLS string
}

// sqliteDialect describes SQLite. Isolation relies on the query registry
// and the scoped executor only. Each write transaction starts with BEGIN
// IMMEDIATE (DSN option), which already serializes migrators.
var sqliteDialect = &dialect{
	name:                  config.DriverSQLite,
	scrubDeleted:          `PRAGMA wal_checkpoint(TRUNCATE)`,
	backup:                `VACUUM INTO ?`,
	migrationsTableExists: `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
}

// postgresDialect describes PostgreSQL. set_config(..., true) is local to
// the current transaction: nothing leaks to the next user of a pooled
// connection, unlike a session-level SET.
var postgresDialect = &dialect{
	name:     config.DriverPostgres,
	numbered: true,
	scopeTenant: `SELECT set_config('app.tenant_id', $1, true), ` +
		`set_config('app.system_scope', 'off', true)`,
	scopeSystem: `SELECT set_config('app.tenant_id', '', true), ` +
		`set_config('app.system_scope', 'on', true)`,
	// Dialect plumbing, outside the query registry (whose token ban targets
	// statements written by repository code): the tenant ID is a bound
	// parameter and the lock is released at the end of the transaction. A
	// hash collision between two tenants only serializes them needlessly.
	// Row locks (SELECT ... FOR UPDATE on the tenant row) are not an option:
	// the tenants policies only let the system scope update that row.
	lockTenant:      `SELECT pg_advisory_xact_lock(hashtext('transteira.tenant.' || current_schema() || '.' || $1))`,
	lockWrappedKeys: `LOCK TABLE wrapped_keys IN SHARE ROW EXCLUSIVE MODE`,
	isolation:       sql.LevelReadCommitted,
	migrationLock:   `SELECT pg_advisory_xact_lock(hashtext('transteira.migrate.' || current_schema()))`,
	migrationsTableExists: `SELECT count(*) FROM pg_catalog.pg_tables ` +
		`WHERE schemaname = current_schema() AND tablename = 'schema_migrations'`,

	ownerMigrations: true,
	identity:        `SELECT current_user::text, current_schema()::text`,
	grants:          postgresGrants,
	verifyRole:      `SELECT rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user`,
	verifyOwnership: `SELECT (SELECT count(*) FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = ANY (current_schemas(false)) AND pg_catalog.pg_get_userbyid(c.relowner) = current_user)
		+ (SELECT count(*) FROM pg_catalog.pg_namespace
			WHERE nspname = ANY (current_schemas(false)) AND pg_catalog.pg_get_userbyid(nspowner) = current_user)`,
	verifyMembership: `SELECT count(*) FROM pg_catalog.pg_roles r
		WHERE r.rolname <> current_user AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')
		  AND (r.rolsuper OR r.rolbypassrls
		    OR r.oid IN (SELECT c.relowner FROM pg_catalog.pg_class c
		      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = ANY (current_schemas(false)))
		    OR r.oid IN (SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname = ANY (current_schemas(false))))`,
	verifyCreate: `SELECT (SELECT count(*) FROM unnest(current_schemas(false)) AS s(name), pg_catalog.pg_roles r
			WHERE pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')
			  AND pg_catalog.has_schema_privilege(r.oid, s.name, 'CREATE'))
		+ CASE WHEN pg_catalog.has_database_privilege(current_user, current_database(), 'CREATE') THEN 1 ELSE 0 END`,
	verifyTemp: `SELECT pg_catalog.has_database_privilege(current_user, current_database(), 'TEMP')`,
	verifyRLS: `SELECT c.relname::text FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')
		  AND (c.relname IN ('tenants', 'master_keys', 'key_rotations') OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
		        WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped))
		  AND NOT (c.relrowsecurity AND c.relforcerowsecurity
		        AND EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid))
		ORDER BY c.relname`,
}

// postgresGrants returns the statements giving the runtime role role its
// rights on schema, and nothing more: USAGE on the schema (any other schema
// privilege revoked), SELECT/INSERT/UPDATE/DELETE on every table (TRUNCATE,
// REFERENCES and TRIGGER revoked), SELECT only on schema_migrations, and
// USAGE and SELECT on the sequences.
// Revoking first makes the result independent of earlier grants, so the
// statements are idempotent.
func postgresGrants(schema, role string) []string {
	s, r := pgx.Identifier{schema}.Sanitize(), pgx.Identifier{role}.Sanitize()
	return []string{
		`REVOKE ALL ON SCHEMA ` + s + ` FROM ` + r,
		`GRANT USAGE ON SCHEMA ` + s + ` TO ` + r,
		`REVOKE ALL ON ALL TABLES IN SCHEMA ` + s + ` FROM ` + r,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ` + s + ` TO ` + r,
		`REVOKE INSERT, UPDATE, DELETE ON TABLE ` + s + `.schema_migrations FROM ` + r,
		`REVOKE ALL ON ALL SEQUENCES IN SCHEMA ` + s + ` FROM ` + r,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ` + s + ` TO ` + r,
	}
}

// toMillis converts t to the portable timestamp representation: Unix
// milliseconds, UTC.
func toMillis(t time.Time) int64 {
	return t.UnixMilli()
}

// fromMillis converts a portable timestamp back to a UTC time.
func fromMillis(ms int64) time.Time {
	return time.UnixMilli(ms).UTC()
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Errors of the PostgreSQL two-role set-up.
var (
	// ErrUnsafeDatabase reports a PostgreSQL configuration under which
	// row-level security would not isolate tenants: the runtime role is a
	// superuser, has BYPASSRLS or owns application objects, or a
	// tenant-scoped table lacks its policies.
	ErrUnsafeDatabase = errors.New("store: unsafe postgresql configuration")
	// errNoOwnerDSN reports a PostgreSQL migration without owner DSN.
	errNoOwnerDSN = errors.New("store: migrations on postgresql need TT_DB_MIGRATE_DSN (owner role)")
	// errRoles reports an inconsistent pair of runtime and owner roles.
	errRoles = errors.New("store: inconsistent migration and runtime roles")
)

// ownerPoolConns bounds the short-lived owner pool used by Migrate.
const ownerPoolConns = 2

// identity returns the role and current schema of a connection of pool.
func (db *DB) identity(ctx context.Context, pool *sql.DB) (role string, schema sql.NullString, err error) {
	err = db.runTx(ctx, pool, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, db.dialect.identity).Scan(&role, &schema)
	})
	if err != nil {
		return "", schema, wrap("read role", err)
	}
	return role, schema, nil
}

// migrateWithOwner applies the migrations with the owner role, then grants
// the runtime role USAGE on the schema and DML on the tables (SELECT only on
// schema_migrations), and finally verifies the runtime role. The grants are
// re-applied on every run.
func (db *DB) migrateWithOwner(ctx context.Context) (int, error) {
	if !db.ownerDSN.IsSet() {
		return 0, errNoOwnerDSN
	}
	runtimeRole, _, err := db.identity(ctx, db.read)
	if err != nil {
		return 0, err
	}
	pool, _ := sql.Open(db.driverName, db.ownerDSN.Reveal())
	pool.SetMaxOpenConns(ownerPoolConns)
	defer func() { _ = pool.Close() }()
	if err := pool.PingContext(ctx); err != nil {
		// pgx redacts the password from the connection strings it quotes.
		return 0, fmt.Errorf("store: connecting to postgresql with the migration role: %w", err)
	}
	owner := &DB{
		dialect: db.dialect, write: pool, read: pool,
		logger: db.logger, now: db.now, newID: db.newID, migrationsFS: db.migrationsFS,
	}
	ownerRole, schema, err := owner.identity(ctx, pool)
	switch {
	case err != nil:
		return 0, err
	case ownerRole == runtimeRole:
		return 0, fmt.Errorf("%w: TT_DB_MIGRATE_DSN and TT_DB_DSN use the same role %q", errRoles, runtimeRole)
	case !schema.Valid:
		return 0, fmt.Errorf("%w: the migration role has no usable schema in its search_path", errRoles)
	}
	n, err := owner.applyMigrations(ctx)
	if err != nil {
		return n, err
	}
	err = owner.runTx(ctx, pool, db.dialect.scopeSystem, nil, func(tx *sql.Tx) error {
		for _, stmt := range db.dialect.grants(schema.String, runtimeRole) {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return n, wrap("grant runtime role", err)
	}
	if _, rtSchema, err := db.identity(ctx, db.read); err != nil {
		return n, err
	} else if rtSchema != schema {
		return n, fmt.Errorf("%w: TT_DB_MIGRATE_DSN and TT_DB_DSN resolve to different schemas (check search_path)", errRoles)
	}
	return n, db.Verify(ctx)
}

// Verify refuses a PostgreSQL runtime role that would defeat row-level
// security: superuser, BYPASSRLS, owner of a schema or relation of its
// search path (an owner can disable the policies), member of a role that is
// any of these, allowed (itself or through a role it belongs to) to CREATE
// in a schema of its search path or in the database, or a
// tenant-scoped table of the current schema without ENABLE and FORCE
// row-level security and a policy. It logs a warning when the role may
// create temporary tables. It returns an error wrapping ErrUnsafeDatabase, and does nothing
// on SQLite. [Open] and [DB.Migrate] call it.
func (db *DB) Verify(ctx context.Context) error {
	d := db.dialect
	if d.verifyRole == "" {
		return nil
	}
	return db.runTx(ctx, db.read, d.scopeSystem, nil, func(tx *sql.Tx) error {
		var super, bypass bool
		if err := tx.QueryRowContext(ctx, d.verifyRole).Scan(&super, &bypass); err != nil {
			return wrap("verify role attributes", err)
		}
		if super || bypass {
			return fmt.Errorf("%w: the runtime role (TT_DB_DSN) is a superuser or has BYPASSRLS, "+
				"which disables row-level security", ErrUnsafeDatabase)
		}
		var owned int
		if err := tx.QueryRowContext(ctx, d.verifyOwnership).Scan(&owned); err != nil {
			return wrap("verify ownership", err)
		}
		if owned > 0 {
			return fmt.Errorf("%w: the runtime role (TT_DB_DSN) owns %d schema(s) or table(s) of the application "+
				"and could disable row-level security; objects must belong to the migration role (TT_DB_MIGRATE_DSN)",
				ErrUnsafeDatabase, owned)
		}
		var members int
		if err := tx.QueryRowContext(ctx, d.verifyMembership).Scan(&members); err != nil {
			return wrap("verify role membership", err)
		}
		if members > 0 {
			return fmt.Errorf("%w: the runtime role (TT_DB_DSN) is a member of %d role(s) that are superusers, "+
				"have BYPASSRLS or own application objects", ErrUnsafeDatabase, members)
		}
		var creatable int
		if err := tx.QueryRowContext(ctx, d.verifyCreate).Scan(&creatable); err != nil {
			return wrap("verify schema privileges", err)
		}
		if creatable > 0 {
			return fmt.Errorf("%w: the runtime role (TT_DB_DSN), directly or through a role it belongs to, "+
				"has CREATE on the database or on a schema of its search_path (%d grant(s)) and could shadow "+
				"application tables", ErrUnsafeDatabase, creatable)
		}
		var temp bool
		if err := tx.QueryRowContext(ctx, d.verifyTemp).Scan(&temp); err != nil {
			return wrap("verify temporary privilege", err)
		}
		if temp {
			db.logger.WarnContext(ctx, "store: the runtime role may create temporary tables, which could shadow "+
				"application tables; consider REVOKE TEMPORARY ON DATABASE")
		}
		rows, err := tx.QueryContext(ctx, d.verifyRLS)
		if err != nil {
			return wrap("verify row-level security", err)
		}
		bad, err := collect(rows, func(r *sql.Rows) (string, error) {
			var name string
			err := r.Scan(&name)
			return name, err
		})
		if err != nil {
			return wrap("verify row-level security", err)
		}
		if len(bad) > 0 {
			return fmt.Errorf("%w: tenant-scoped tables without ENABLE and FORCE row-level security and a policy: %s",
				ErrUnsafeDatabase, strings.Join(bad, ", "))
		}
		return nil
	})
}

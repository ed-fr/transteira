package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// migrationFiles holds the versioned schema migrations of both engines.
//
//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrationFiles embed.FS

// migrationName matches a migration file name: a four-digit version, an
// underscore and a lowercase snake_case name.
var migrationName = regexp.MustCompile(`^([0-9]{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`)

// errBadMigrations reports an invalid set of embedded migration files.
var errBadMigrations = errors.New("store: invalid migration files")

// Statements of the migrator. The schema_migrations table records the
// applied migrations; it holds no tenant data.
var (
	qCreateMigrationsTable = systemQuery(
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    BIGINT NOT NULL PRIMARY KEY,
			name       TEXT   NOT NULL,
			checksum   TEXT   NOT NULL,
			applied_at BIGINT NOT NULL
		)`,
		"schema migrations: create the bookkeeping table")
	qListMigrations = systemQuery(
		`SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version`,
		"schema migrations: read the applied versions")
	qInsertMigration = systemQuery(
		`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		"schema migrations: record an applied version")
)

// migration is one embedded schema migration.
type migration struct {
	version  int
	name     string
	body     string
	checksum string
}

// loadMigrations reads the migrations of directory dir in fsys. Versions
// must start at 1 and be contiguous. The checksum is computed on the body
// with CRLF line endings normalized to LF, so that a Git checkout converting
// line endings does not look like a modified migration.
func loadMigrations(fsys fs.FS, dir string) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBadMigrations, err)
	}
	var out []migration
	for _, e := range entries {
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil || e.IsDir() {
			return nil, fmt.Errorf("%w: unexpected entry %q in %s", errBadMigrations, e.Name(), dir)
		}
		version, _ := strconv.Atoi(m[1]) // four digits: always parses
		if version != len(out)+1 {
			return nil, fmt.Errorf("%w: %s: expected version %04d, found %q", errBadMigrations, dir, len(out)+1, e.Name())
		}
		raw, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errBadMigrations, err)
		}
		body := strings.ReplaceAll(string(raw), "\r\n", "\n")
		sum := sha256.Sum256([]byte(body))
		out = append(out, migration{version: version, name: m[2], body: body, checksum: hex.EncodeToString(sum[:])})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no migration in %s", errBadMigrations, dir)
	}
	return out, nil
}

// MigrationState describes a migration as seen by [DB.Status].
type MigrationState string

// Migration states.
const (
	// MigrationApplied means the migration is recorded with a matching checksum.
	MigrationApplied MigrationState = "applied"
	// MigrationPending means the migration is known but not applied yet.
	MigrationPending MigrationState = "pending"
	// MigrationModified means the migration is applied but its content
	// changed since.
	MigrationModified MigrationState = "modified"
	// MigrationUnknown means the database records a migration this binary
	// does not know: the database was migrated by a newer version.
	MigrationUnknown MigrationState = "unknown"
)

// MigrationStatus is the state of one schema migration.
type MigrationStatus struct {
	// Version is the migration number, starting at 1.
	Version int
	// Name is the migration name (file name without version and extension).
	Name string
	// State tells whether the migration is applied.
	State MigrationState
	// AppliedAt is the time the migration was applied (zero when pending).
	AppliedAt time.Time
}

// appliedMigration is a row of schema_migrations.
type appliedMigration struct {
	version   int
	name      string
	checksum  string
	appliedAt int64
}

// migrations returns the embedded migrations of the database engine.
func (db *DB) migrations() ([]migration, error) {
	return loadMigrations(db.migrationsFS, "migrations/"+db.dialect.name)
}

// migrationScope is the reason logged for migrator transactions.
const migrationScope = "schema migrations"

// Migrate applies the pending schema migrations, each in its own
// transaction, and returns how many it applied. With PostgreSQL it connects
// with the owner role (TT_DB_MIGRATE_DSN), then grants the runtime role the
// minimum it needs and verifies it (see migrateWithOwner and [DB.Verify]). Concurrent migrators are
// serialized (advisory lock with PostgreSQL, BEGIN IMMEDIATE with SQLite),
// and every step re-reads the applied versions under that lock, so running
// Migrate repeatedly or concurrently is safe. It refuses to run, returning
// ErrSchemaTooNew or ErrMigrationModified, when the database was migrated by
// a newer binary or an applied migration changed.
func (db *DB) Migrate(ctx context.Context) (int, error) {
	if db.dialect.ownerMigrations {
		return db.migrateWithOwner(ctx)
	}
	return db.applyMigrations(ctx)
}

// applyMigrations applies the pending migrations on db's write pool.
func (db *DB) applyMigrations(ctx context.Context) (int, error) {
	known, err := db.migrations()
	if err != nil {
		return 0, err
	}
	applied := 0
	for {
		done := false
		err := db.migrationTx(ctx, func(tx *SystemTx) error {
			if db.dialect.migrationLock != "" {
				if _, err := tx.tx.ExecContext(ctx, db.dialect.migrationLock); err != nil {
					return wrap("lock migrations", err)
				}
			}
			if _, err := tx.Exec(ctx, qCreateMigrationsTable); err != nil {
				return wrap("create schema_migrations", err)
			}
			rows, err := readApplied(ctx, tx)
			if err != nil {
				return err
			}
			if err := checkApplied(known, rows); err != nil {
				return err
			}
			if len(rows) == len(known) {
				done = true
				return nil
			}
			next := known[len(rows)]
			name := fmt.Sprintf("migration %04d_%s", next.version, next.name)
			if err := db.checkForeignKeysOff(ctx, tx); err != nil {
				return err
			}
			if _, err := tx.tx.ExecContext(ctx, next.body); err != nil {
				return wrap("apply "+name, err)
			}
			if err := db.checkForeignKeys(ctx, tx, name); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, qInsertMigration, next.version, next.name, next.checksum, toMillis(db.now())); err != nil {
				return wrap("record migration", err)
			}
			return nil
		})
		if err != nil {
			return applied, err
		}
		if done {
			return applied, nil
		}
		applied++
	}
}

// errForeignKeys reports a migration run with foreign keys enforced, or
// leaving foreign key violations behind.
var errForeignKeys = errors.New("store: migration foreign key check failed")

// migrationTx runs fn in a migration transaction on the write pool. When
// the dialect disables foreign keys for migrations (SQLite), the
// transaction runs on one reserved connection: enforcement is turned off
// before the transaction starts and turned back on after it ends, whether
// it committed or not. If it cannot be turned back on, the connection is
// discarded rather than returned to the pool, so that no later transaction
// ever runs without foreign keys. The SQLite dialect has no transaction
// scope statement to run.
func (db *DB) migrationTx(ctx context.Context, fn func(*SystemTx) error) (err error) {
	if db.dialect.migrationFKOff == "" {
		sys, _ := db.System(migrationScope) // constant, non-empty reason
		return sys.Tx(ctx, fn)
	}
	db.logger.InfoContext(ctx, "store: system scope", "reason", migrationScope)
	conn, err := db.write.Conn(ctx)
	if err != nil {
		return wrap("reserve the migration connection", err)
	}
	defer func() { _ = conn.Close() }()
	// The restore is registered before the statement turning enforcement
	// off: that statement may fail after taking effect, and the connection
	// must not return to the pool with foreign keys off.
	defer func() {
		if _, rerr := conn.ExecContext(context.WithoutCancel(ctx), db.dialect.migrationFKOn); rerr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, wrap("restore foreign keys after migration", rerr))
		}
	}()
	if _, err := conn.ExecContext(ctx, db.dialect.migrationFKOff); err != nil {
		return wrap("disable foreign keys for migrations", err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return wrap("begin transaction", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(&SystemTx{tx: tx, dialect: db.dialect}); err != nil {
		return err
	}
	committed = true
	if err := tx.Commit(); err != nil {
		return wrap("commit", err)
	}
	return nil
}

// checkForeignKeysOff verifies, inside a migration transaction, that the
// connection does not enforce foreign keys when the dialect requires it
// off: a connection reopened by the pool would enforce them again, and a
// table rebuild would then cascade to its children.
func (db *DB) checkForeignKeysOff(ctx context.Context, tx *SystemTx) error {
	if db.dialect.migrationFKState == "" {
		return nil
	}
	var on int
	if err := tx.tx.QueryRowContext(ctx, db.dialect.migrationFKState).Scan(&on); err != nil {
		return wrap("read the foreign key enforcement", err)
	}
	if on != 0 {
		return fmt.Errorf("%w: foreign keys are enforced on the migration connection", errForeignKeys)
	}
	return nil
}

// checkForeignKeys verifies, before a migration commits, that it left no
// foreign key violation behind (needed when foreign keys are off).
func (db *DB) checkForeignKeys(ctx context.Context, tx *SystemTx, name string) error {
	if db.dialect.migrationFKCheck == "" {
		return nil
	}
	var violations int
	if err := tx.tx.QueryRowContext(ctx, db.dialect.migrationFKCheck).Scan(&violations); err != nil {
		return wrap("check the foreign keys", err)
	}
	if violations != 0 {
		return fmt.Errorf("%w: %s leaves %d foreign key violation(s)", errForeignKeys, name, violations)
	}
	return nil
}

// checkApplied verifies the applied migrations against the known ones: they
// must be a prefix of the known list, with identical checksums.
func checkApplied(known []migration, rows []appliedMigration) error {
	for i, r := range rows {
		if i >= len(known) || r.version != known[i].version {
			return fmt.Errorf("%w: version %04d is not known by this binary (latest: %04d)",
				ErrSchemaTooNew, r.version, len(known))
		}
		if r.checksum != known[i].checksum {
			return fmt.Errorf("%w: %04d_%s", ErrMigrationModified, r.version, known[i].name)
		}
	}
	return nil
}

// readApplied returns the rows of schema_migrations, ordered by version.
func readApplied(ctx context.Context, tx *SystemTx) ([]appliedMigration, error) {
	rows, err := tx.Query(ctx, qListMigrations)
	if err != nil {
		return nil, wrap("read schema_migrations", err)
	}
	out, err := collect(rows, func(r *sql.Rows) (appliedMigration, error) {
		var a appliedMigration
		err := r.Scan(&a.version, &a.name, &a.checksum, &a.appliedAt)
		return a, err
	})
	if err != nil {
		return nil, wrap("read schema_migrations", err)
	}
	return out, nil
}

// Status reports the state of every known migration, followed by the
// migrations recorded in the database but unknown to this binary. It never
// modifies the database.
func (db *DB) Status(ctx context.Context) ([]MigrationStatus, error) {
	known, err := db.migrations()
	if err != nil {
		return nil, err
	}
	var rows []appliedMigration
	sys, _ := db.System(migrationScope)
	err = sys.ReadTx(ctx, func(tx *SystemTx) error {
		var n int
		if err := tx.tx.QueryRowContext(ctx, db.dialect.migrationsTableExists).Scan(&n); err != nil {
			return wrap("look up schema_migrations", err)
		}
		if n == 0 {
			return nil
		}
		rows, err = readApplied(ctx, tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	byVersion := make(map[int]appliedMigration, len(rows))
	for _, r := range rows {
		byVersion[r.version] = r
	}
	out := make([]MigrationStatus, 0, len(known)+len(rows))
	for _, m := range known {
		st := MigrationStatus{Version: m.version, Name: m.name, State: MigrationPending}
		if r, ok := byVersion[m.version]; ok {
			st.State = MigrationApplied
			st.AppliedAt = fromMillis(r.appliedAt)
			if r.checksum != m.checksum {
				st.State = MigrationModified
			}
			delete(byVersion, m.version)
		}
		out = append(out, st)
	}
	for _, r := range rows {
		if _, ok := byVersion[r.version]; ok {
			out = append(out, MigrationStatus{Version: r.version, Name: r.name, State: MigrationUnknown, AppliedAt: fromMillis(r.appliedAt)})
		}
	}
	return out, nil
}

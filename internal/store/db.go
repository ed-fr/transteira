package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"time"

	// Register the "pgx" database/sql driver.
	_ "github.com/jackc/pgx/v5/stdlib"
	// Register the "sqlite" database/sql driver (pure Go, no cgo).
	_ "modernc.org/sqlite"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/id"
)

// database/sql driver names.
const (
	sqliteDriverName   = "sqlite"
	postgresDriverName = "pgx"
)

// Connection pool settings.
const (
	// sqliteReaders is the size of the SQLite read-only pool. WAL mode lets
	// readers run concurrently with the single writer.
	sqliteReaders = 4
	// sqliteBusyTimeoutMS is how long a SQLite connection waits for a lock.
	sqliteBusyTimeoutMS = 10_000
	// postgresMaxConns bounds the PostgreSQL pool (low concurrency, §1).
	postgresMaxConns = 10
	// postgresMaxIdle is the number of idle PostgreSQL connections kept.
	postgresMaxIdle = 5
	// connMaxLifetime recycles connections periodically.
	connMaxLifetime = 30 * time.Minute
)

// sqliteCommonParams are the per-connection settings of every SQLite
// connection: WAL journal, foreign keys enforced, a busy timeout and
// synchronous=NORMAL (durable across application crashes; WAL keeps the
// database consistent across power loss).
var sqliteCommonParams = []string{
	fmt.Sprintf("_pragma=busy_timeout(%d)", sqliteBusyTimeoutMS),
	"_pragma=journal_mode(WAL)",
	"_pragma=foreign_keys(1)",
	"_pragma=synchronous(NORMAL)",
}

// errInMemory rejects in-memory SQLite databases: the read and write pools
// would each see a different, empty database.
var errInMemory = errors.New("store: in-memory SQLite databases are not supported")

// DB is the TransTeira database. It is safe for concurrent use.
//
// With SQLite, writes go through a pool holding a single connection, so that
// the application never competes with itself for SQLite's database-wide
// write lock (busy errors, deadlocks between deferred transactions upgrading
// to writers), while reads use a separate read-only pool and run
// concurrently thanks to WAL mode. With PostgreSQL both roles share one pool.
type DB struct {
	dialect *dialect
	write   *sql.DB
	read    *sql.DB
	logger  *slog.Logger
	now     func() time.Time
	newID   func(id.Prefix) (string, error)
	// migrationsFS holds the migrations, by engine directory.
	migrationsFS fs.FS
	// driverName and ownerDSN open the short-lived owner pool used by
	// Migrate on engines with a separate owner role (PostgreSQL).
	driverName string
	ownerDSN   config.Secret
}

// Option customizes [Open].
type Option func(*DB)

// WithLogger sets the logger receiving debug traces of system-scope
// operations. The default discards everything.
func WithLogger(l *slog.Logger) Option {
	return func(db *DB) { db.logger = l }
}

// WithClock replaces the time source used for creation and update
// timestamps, for tests.
func WithClock(now func() time.Time) Option {
	return func(db *DB) {
		db.now = now
		db.newID = id.NewGenerator(now, nil).New
	}
}

// Open connects to the database selected by cfg.DBDriver and cfg.DBDSN and
// checks that it is reachable. With PostgreSQL it also runs [DB.Verify] and
// refuses an unsafe runtime role; cfg.DBMigrateDSN (owner role) is kept,
// redacted, for [DB.Migrate] only, until [DB.DropMigrationCredentials]. It
// does not apply migrations.
func Open(ctx context.Context, cfg *config.Config, opts ...Option) (*DB, error) {
	switch cfg.DBDriver {
	case config.DriverSQLite:
		return openSQLite(ctx, sqliteDriverName, cfg.DBDSN.Reveal(), opts)
	case config.DriverPostgres:
		return openPostgres(ctx, postgresDriverName, cfg.DBDSN.Reveal(), cfg.DBMigrateDSN, postgresDialect, opts)
	}
	return nil, invalid("unsupported database driver %q", cfg.DBDriver)
}

// newDB builds a DB with default settings and applies opts.
func newDB(d *dialect, write, read *sql.DB, opts []Option) *DB {
	db := &DB{
		dialect: d,
		write:   write,
		read:    read,
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:     time.Now,
		newID:   id.NewGenerator(nil, nil).New,

		migrationsFS: migrationFiles,
	}
	for _, o := range opts {
		o(db)
	}
	return db
}

// sqliteParams returns the common SQLite parameters followed by extra, in a
// new slice.
func sqliteParams(extra ...string) []string {
	return append(slices.Clone(sqliteCommonParams), extra...)
}

// sqliteDSN appends params to the SQLite DSN dsn.
func sqliteDSN(dsn string, params []string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + strings.Join(params, "&")
}

// isInMemory reports whether dsn designates an in-memory SQLite database.
func isInMemory(dsn string) bool {
	return dsn == "" || strings.Contains(dsn, ":memory:") || strings.Contains(dsn, "mode=memory")
}

// openSQLite opens the SQLite write and read pools on dsn with the given
// driver (overridable for fault-injection tests).
func openSQLite(ctx context.Context, driver, dsn string, opts []Option) (*DB, error) {
	if isInMemory(dsn) {
		return nil, errInMemory
	}
	// sql.Open only fails for an unknown driver name, a programming error
	// caught by the tests: the driver names are constants.
	write, _ := sql.Open(driver, sqliteDSN(dsn, sqliteParams("_txlock=immediate")))
	write.SetMaxOpenConns(1)
	write.SetMaxIdleConns(1)
	write.SetConnMaxLifetime(0)
	// Open the writer first: it switches a new database to WAL mode.
	if err := write.PingContext(ctx); err != nil {
		_ = write.Close()
		return nil, fmt.Errorf("store: opening sqlite database: %w", err)
	}
	read, _ := sql.Open(driver, sqliteDSN(dsn, sqliteParams("_query_only=1")))
	read.SetMaxOpenConns(sqliteReaders)
	read.SetMaxIdleConns(sqliteReaders)
	read.SetConnMaxLifetime(connMaxLifetime)
	if err := read.PingContext(ctx); err != nil {
		_ = write.Close()
		_ = read.Close()
		return nil, fmt.Errorf("store: opening sqlite database: %w", err)
	}
	return newDB(sqliteDialect, write, read, opts), nil
}

// openPostgres opens the PostgreSQL runtime pool on dsn with the given
// driver and dialect, remembers ownerDSN for the migrations, and verifies
// the runtime role.
func openPostgres(ctx context.Context, driver, dsn string, ownerDSN config.Secret, d *dialect, opts []Option) (*DB, error) {
	pool, _ := sql.Open(driver, dsn)
	pool.SetMaxOpenConns(postgresMaxConns)
	pool.SetMaxIdleConns(postgresMaxIdle)
	pool.SetConnMaxLifetime(connMaxLifetime)
	if err := pool.PingContext(ctx); err != nil {
		_ = pool.Close()
		// pgx redacts the password from the connection strings it quotes.
		return nil, fmt.Errorf("store: connecting to postgresql: %w", err)
	}
	db := newDB(d, pool, pool, opts)
	db.driverName = driver
	db.ownerDSN = ownerDSN
	if err := db.Verify(ctx); err != nil {
		_ = pool.Close()
		return nil, err
	}
	return db, nil
}

// Driver returns the engine name: config.DriverSQLite or
// config.DriverPostgres.
func (db *DB) Driver() string { return db.dialect.name }

// Ping checks that the database answers, for the health check.
func (db *DB) Ping(ctx context.Context) error {
	if err := db.write.PingContext(ctx); err != nil {
		return wrap("ping", err)
	}
	return nil
}

// DropMigrationCredentials forgets the owner-role DSN kept for
// [DB.Migrate]. Call it once the start-up migration is done, before serving
// requests, and zero cfg.DBMigrateDSN as well; a later Migrate then fails.
// It must not run concurrently with Migrate.
func (db *DB) DropMigrationCredentials() { db.ownerDSN = config.Secret{} }

// Close releases every connection.
func (db *DB) Close() error {
	err := db.write.Close()
	if db.read != db.write {
		err = errors.Join(err, db.read.Close())
	}
	return err
}

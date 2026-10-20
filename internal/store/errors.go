package store

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Errors returned by the store. Callers test them with errors.Is.
var (
	// ErrNotFound reports a missing row. A row belonging to another tenant
	// is reported exactly the same way, so that callers cannot tell the two
	// cases apart.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict reports a uniqueness violation (duplicate FQDN, duplicate
	// blocklist entry...).
	ErrConflict = errors.New("store: conflict")
	// ErrInvalid reports an argument rejected before reaching the database
	// (malformed value, unknown kind, bad cursor...).
	ErrInvalid = errors.New("store: invalid argument")
	// ErrSchemaTooNew reports a database migrated by a newer TransTeira
	// version than the running binary. Running would risk losing data, so
	// the binary refuses to start.
	ErrSchemaTooNew = errors.New("store: database schema is newer than this binary")
	// ErrMigrationModified reports an applied migration whose content
	// changed since it was applied.
	ErrMigrationModified = errors.New("store: an applied migration was modified")
)

// PostgreSQL SQLSTATE codes mapped to store errors.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

// classify maps a driver error to a store sentinel error when it is a
// uniqueness violation (ErrConflict) or a foreign key violation (ErrNotFound:
// the referenced row, such as the tenant, does not exist). It returns nil for
// any other error.
func classify(err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return ErrConflict
		case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
			return ErrNotFound
		}
		return nil
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case pgUniqueViolation:
			return ErrConflict
		case pgForeignKeyViolation:
			return ErrNotFound
		}
	}
	return nil
}

// wrap annotates err with the failed operation. Constraint violations are
// replaced by the matching sentinel, dropping the driver message, which may
// quote the offending values. Store sentinels pass through unchanged.
func wrap(op string, err error) error {
	for _, s := range []error{ErrNotFound, ErrConflict, ErrInvalid} {
		if errors.Is(err, s) {
			return err
		}
	}
	if s := classify(err); s != nil {
		return fmt.Errorf("store: %s: %w", op, s)
	}
	return fmt.Errorf("store: %s: %w", op, err)
}

// invalid returns an ErrInvalid error describing the rejected argument. The
// description must never contain the value itself.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

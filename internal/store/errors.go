package store

import (
	"errors"
	"fmt"
	"strings"

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
	// ErrRotationRunning reports an attempt to start a master key rotation
	// while another one is running.
	ErrRotationRunning = errors.New("store: a master key rotation is already running")
	// ErrRotationNotRunning reports an operation on a master key rotation
	// that is completed or failed, or whose keys differ from the ones given.
	ErrRotationNotRunning = errors.New("store: the master key rotation is not running")
	// ErrRotationIncomplete reports an attempt to complete a master key
	// rotation while keys are still wrapped under the old master key.
	ErrRotationIncomplete = errors.New("store: keys are still wrapped under the old master key")
	// ErrKeyRetired reports a master key recorded as retired used as the
	// target of a rotation or to wrap a key: a retired key must never wrap
	// anything again.
	ErrKeyRetired = errors.New("store: the master key is retired")
	// ErrUnregisteredKeys reports, on first registration, wrapped keys under
	// master keys other than the one being registered: the keyring holds the
	// wrong key, and nothing is recorded.
	ErrUnregisteredKeys = errors.New("store: wrapped keys reference unregistered master keys")
	// ErrRotationKeys reports a rotation between keys that fit neither a
	// regular rotation (from the active key to an unregistered key) nor a
	// clean-up rotation (from a retired key to the active key).
	ErrRotationKeys = errors.New("store: a rotation must go from the active master key to a new one, " +
		"or from a retired master key to the active one")
	// ErrRotationInUse reports a rotation that cannot be abandoned: wrapped
	// keys already use its target, which is not a registered active key.
	ErrRotationInUse = errors.New("store: wrapped keys already use the target key of the rotation")
	// ErrScrubBusy reports a WAL checkpoint that could not complete because
	// readers were active: deleted data may remain in the SQLite WAL until
	// the next [DB.ScrubDeleted]. It is not fatal.
	ErrScrubBusy = errors.New("store: wal checkpoint incomplete, deleted data may remain in the wal")
)

// retiredKeyMessage is the message of the SQLite trigger rejecting a
// retired master key (migration 0002).
const retiredKeyMessage = "transteira: master key is retired"

// PostgreSQL SQLSTATE codes mapped to store errors.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
	// pgKeyRetired is raised by the wrapped_keys trigger rejecting a retired
	// master key (migration 0002).
	pgKeyRetired = "TTK01"
)

// classify maps a driver error to a store sentinel error when it is a
// uniqueness violation (ErrConflict), a foreign key violation (ErrNotFound:
// the referenced row, such as the tenant, does not exist) or the rejection of
// a retired master key by the wrapped_keys triggers (ErrKeyRetired). It
// returns nil for any other error.
func classify(err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return ErrConflict
		case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
			return ErrNotFound
		case sqlite3.SQLITE_CONSTRAINT_TRIGGER:
			if strings.Contains(se.Error(), retiredKeyMessage) {
				return ErrKeyRetired
			}
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
		case pgKeyRetired:
			return ErrKeyRetired
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

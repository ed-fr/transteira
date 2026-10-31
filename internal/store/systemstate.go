package store

import (
	"context"
	"encoding/json"
	"time"
)

// reasonSystemState is the reason of the system state queries.
const reasonSystemState = "instance state computed by the application: cache of the update check"

// Keys of the system state. A key is a fixed identifier defined by the
// code, never a value supplied by a user.
const (
	// SystemStateUpdateCheck holds the outcome of the last check for a
	// newer release (internal/updatecheck), a JSON document
	// {latestVersion, releaseUrl, checkedAt, lastError}.
	SystemStateUpdateCheck = "update_check"
)

// MaxSystemStateValueBytes bounds the JSON document of a system state key.
const MaxSystemStateValueBytes = 4 << 10

// Statements of the SystemState repository. The upsert keeps a single row
// per key without a read-then-write race between engines.
var (
	qSystemStateGet = systemQuery(
		`SELECT value, updated_at FROM system_state WHERE key = ?`,
		reasonSystemState)
	qSystemStatePut = systemQuery(
		`INSERT INTO system_state (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		reasonSystemState)
)

// SystemStateValue is the value of a system state key.
type SystemStateValue struct {
	// Value is the JSON document, as written by [SystemState.Put]. The
	// store only checks that it is well-formed JSON: the owner of the key
	// revalidates its content on every read.
	Value []byte
	// UpdatedAt is the time of the last write.
	UpdatedAt time.Time
}

// SystemState is the repository of the instance state computed by the
// application (table system_state, never a secret nor personal data). Its
// operations are system-scoped. Obtain it with [DB.SystemState].
type SystemState struct {
	db *DB
}

// SystemState returns the system state repository.
func (db *DB) SystemState() *SystemState { return &SystemState{db: db} }

// validSystemStateKey reports whether key is a key defined by the code.
func validSystemStateKey(key string) bool {
	return key == SystemStateUpdateCheck
}

// Get returns the value of key. It returns ErrInvalid for an unknown key
// and ErrNotFound when the key was never written.
func (r *SystemState) Get(ctx context.Context, key string) (SystemStateValue, error) {
	if !validSystemStateKey(key) {
		return SystemStateValue{}, invalid("unknown system state key")
	}
	var (
		value   string
		updated int64
	)
	err := r.db.systemScope(reasonSystemState).ReadTx(ctx, func(tx *SystemTx) error {
		return tx.QueryRow(ctx, qSystemStateGet, key).Scan(&value, &updated)
	})
	if err != nil {
		return SystemStateValue{}, wrap("get system state", err)
	}
	return SystemStateValue{Value: []byte(value), UpdatedAt: fromMillis(updated)}, nil
}

// Put writes value under key, replacing the previous value, and dates it
// with the store's clock. It returns ErrInvalid for an unknown key, or a
// value that is not well-formed JSON or longer than
// [MaxSystemStateValueBytes].
func (r *SystemState) Put(ctx context.Context, key string, value []byte) error {
	switch {
	case !validSystemStateKey(key):
		return invalid("unknown system state key")
	case len(value) == 0 || len(value) > MaxSystemStateValueBytes:
		return invalid("system state value must hold 1 to %d bytes", MaxSystemStateValueBytes)
	case !json.Valid(value):
		return invalid("system state value must be JSON")
	}
	err := r.db.systemScope(reasonSystemState).Tx(ctx, func(tx *SystemTx) error {
		_, err := tx.Exec(ctx, qSystemStatePut, key, string(value), toMillis(r.db.now()))
		return err
	})
	if err != nil {
		return wrap("put system state", err)
	}
	return nil
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// MasterKeyStatus is the state of a master key in master_keys.
type MasterKeyStatus string

// Master key states.
const (
	// MasterKeyActive marks the master key that wraps new keys. At most one
	// key is active.
	MasterKeyActive MasterKeyStatus = "active"
	// MasterKeyRetired marks a master key replaced by a completed rotation.
	MasterKeyRetired MasterKeyStatus = "retired"
)

// RotationStatus is the state of a master key rotation.
type RotationStatus string

// Rotation states.
const (
	// RotationRunning marks the rotation in progress (at most one).
	RotationRunning RotationStatus = "running"
	// RotationCompleted marks a rotation that rewrapped every key.
	RotationCompleted RotationStatus = "completed"
	// RotationFailed marks an abandoned rotation.
	RotationFailed RotationStatus = "failed"
)

// maxRotationErrorLen bounds the stored error message of a failed rotation,
// in bytes.
const maxRotationErrorLen = 1000

// rotationColumns is the column list read by the rotation queries.
const rotationColumns = `id, from_key_id, to_key_id, status, total_keys, rewrapped_keys, started_at, completed_at, error`

// Statements of the MasterKeys and KeyRotations repositories. Both tables
// are system tables: they hold no tenant data.
var (
	qMasterKeyList = systemQuery(
		`SELECT id, status, created_at, retired_at FROM master_keys ORDER BY created_at, id`,
		reasonKeyCheck)
	qMasterKeyActive = systemQuery(
		`SELECT id FROM master_keys WHERE status = 'active'`,
		reasonKeyCheck)
	qMasterKeyCount = systemQuery(
		`SELECT count(*) FROM master_keys`,
		reasonKeyCheck)
	qMasterKeyRegister = systemQuery(
		`INSERT INTO master_keys (id, status, created_at, retired_at) VALUES (?, 'active', ?, NULL)`,
		reasonKeyCheck)
	qMasterKeyRetire = systemQuery(
		`UPDATE master_keys SET status = 'retired', retired_at = ? WHERE status = 'active' AND id <> ?`,
		reasonKeyRotation)
	qMasterKeyStatus = systemQuery(
		`SELECT status FROM master_keys WHERE id = ?`,
		reasonKeyRotation)
	qMasterKeyAdd = systemQuery(
		`INSERT INTO master_keys (id, status, created_at) VALUES (?, 'active', ?)`,
		reasonKeyRotation)

	qRotationInsert = systemQuery(
		`INSERT INTO key_rotations (id, from_key_id, to_key_id, status, total_keys, rewrapped_keys, started_at)
		VALUES (?, ?, ?, 'running', ?, 0, ?)`,
		reasonKeyRotation)
	qRotationGet = systemQuery(
		`SELECT `+rotationColumns+` FROM key_rotations WHERE id = ?`,
		reasonKeyRotation)
	qRotationRunning = systemQuery(
		`SELECT `+rotationColumns+` FROM key_rotations WHERE status = 'running'`,
		reasonKeyRotation)
	qRotationLatest = systemQuery(
		`SELECT `+rotationColumns+` FROM key_rotations ORDER BY started_at DESC, id DESC LIMIT 1`,
		reasonKeyRotation)
	qRotationProgress = systemQuery(
		`UPDATE key_rotations SET rewrapped_keys = rewrapped_keys + ?
		WHERE id = ? AND status = 'running' AND from_key_id = ? AND to_key_id = ?`,
		reasonKeyRotation)
	qRotationFinish = systemQuery(
		`UPDATE key_rotations SET status = ?, completed_at = ?, error = ? WHERE id = ? AND status = 'running'`,
		reasonKeyRotation)
)

// MasterKeyRecord is a master key known to the installation: its
// identifier and state, never the key.
type MasterKeyRecord struct {
	// ID is the identifier derived from the key ("mk_" + 16 hex).
	ID string
	// Status is MasterKeyActive or MasterKeyRetired.
	Status MasterKeyStatus
	// CreatedAt is when the key was registered.
	CreatedAt time.Time
	// RetiredAt is when the key was retired (zero while active).
	RetiredAt time.Time
}

// MasterKeys is the registry of master keys. Its operations are
// system-scoped. Obtain it with [DB.MasterKeys].
type MasterKeys struct {
	db *DB
}

// MasterKeys returns the master key registry.
func (db *DB) MasterKeys() *MasterKeys { return &MasterKeys{db: db} }

// List returns every known master key, oldest first.
func (r *MasterKeys) List(ctx context.Context) ([]MasterKeyRecord, error) {
	var keys []MasterKeyRecord
	err := r.db.systemScope(reasonKeyCheck).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qMasterKeyList)
		if err != nil {
			return err
		}
		keys, err = collect(rows, func(r *sql.Rows) (MasterKeyRecord, error) {
			var (
				k       MasterKeyRecord
				status  string
				created int64
				retired sql.NullInt64
			)
			if err := r.Scan(&k.ID, &status, &created, &retired); err != nil {
				return MasterKeyRecord{}, err
			}
			k.Status = MasterKeyStatus(status)
			k.CreatedAt = fromMillis(created)
			if retired.Valid {
				k.RetiredAt = fromMillis(retired.Int64)
			}
			return k, nil
		})
		return err
	})
	if err != nil {
		return nil, wrap("list master keys", err)
	}
	return keys, nil
}

// Active returns the identifier of the active master key, or ErrNotFound
// when none is registered.
func (r *MasterKeys) Active(ctx context.Context) (string, error) {
	var keyID string
	err := r.db.systemScope(reasonKeyCheck).ReadTx(ctx, func(tx *SystemTx) error {
		return tx.QueryRow(ctx, qMasterKeyActive).Scan(&keyID)
	})
	if err != nil {
		return "", wrap("get active master key", err)
	}
	return keyID, nil
}

// EnsureActive registers keyID as the active master key, created at now, on
// first start, and reports whether it did. In one transaction, it registers
// keyID only when no master key is registered at all and every wrapped key
// is wrapped under keyID (or there is none). When master keys are already
// registered it changes nothing: the caller compares [MasterKeys.Active]
// with its keyring. When no master key is registered but wrapped keys
// reference other master keys, it records nothing and returns an error
// wrapping ErrUnregisteredKeys that lists those identifiers (the keyring
// holds the wrong key: a wrong key is never recorded). It returns
// ErrInvalid for a malformed identifier.
func (r *MasterKeys) EnsureActive(ctx context.Context, keyID string, now time.Time) (registered bool, err error) {
	if !validMasterKeyID(keyID) {
		return false, invalid("malformed master key id")
	}
	err = r.db.systemScope(reasonKeyCheck).Tx(ctx, func(tx *SystemTx) error {
		var n int64
		if err := tx.QueryRow(ctx, qMasterKeyCount).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		inUse, err := keyIDsInUse(ctx, tx)
		if err != nil {
			return err
		}
		if others := slices.DeleteFunc(inUse, func(s string) bool { return s == keyID }); len(others) > 0 {
			return fmt.Errorf("%w: %s", ErrUnregisteredKeys, strings.Join(others, ", "))
		}
		if _, err := tx.Exec(ctx, qMasterKeyRegister, keyID, toMillis(now)); err != nil {
			return err
		}
		registered = true
		return nil
	})
	if err != nil {
		return false, wrap("register master key", err)
	}
	return registered, nil
}

// Rotation is a master key rotation run: every wrapped key is rewrapped
// from FromKeyID to ToKeyID, in batches, resumably.
type Rotation struct {
	// ID is the rotation identifier ("rot_" + ULID), assigned by the caller.
	ID string
	// FromKeyID is the master key being replaced.
	FromKeyID string
	// ToKeyID is the new master key.
	ToKeyID string
	// Status is the state of the rotation (RotationRunning on Start).
	Status RotationStatus
	// TotalKeys is the number of keys to rewrap, counted by the caller at
	// start. Keys wrapped under the old key afterwards are rewrapped too, so
	// RewrappedKeys can exceed it.
	TotalKeys int64
	// RewrappedKeys is the number of keys rewrapped so far (0 on Start).
	RewrappedKeys int64
	// StartedAt is the start time; the store's clock is used when it is
	// zero on Start.
	StartedAt time.Time
	// CompletedAt is when the rotation completed or failed (zero while
	// running).
	CompletedAt time.Time
	// Error is the failure message of a failed rotation.
	Error string
}

// KeyRotations is the repository of master key rotations. Its operations
// are system-scoped. Obtain it with [DB.KeyRotations].
type KeyRotations struct {
	db *DB
}

// KeyRotations returns the rotation repository.
func (db *DB) KeyRotations() *KeyRotations { return &KeyRotations{db: db} }

// scanRotation reads one row of rotationColumns.
func scanRotation(sc interface{ Scan(...any) error }) (Rotation, error) {
	var (
		r         Rotation
		status    string
		started   int64
		completed sql.NullInt64
		msg       sql.NullString
	)
	if err := sc.Scan(&r.ID, &r.FromKeyID, &r.ToKeyID, &status, &r.TotalKeys, &r.RewrappedKeys,
		&started, &completed, &msg); err != nil {
		return Rotation{}, err
	}
	r.Status = RotationStatus(status)
	r.StartedAt = fromMillis(started)
	if completed.Valid {
		r.CompletedAt = fromMillis(completed.Int64)
	}
	r.Error = msg.String
	return r, nil
}

// Start records rot as the running rotation (Status, RewrappedKeys,
// CompletedAt and Error are ignored). Only two kinds of rotation are
// accepted: a regular rotation, from the active key to a key that is not
// registered yet, and a clean-up rotation of keys wrapped late under a
// retired key, from that retired key to the active key. It returns
// ErrRotationRunning when a rotation is already running, ErrKeyRetired when
// ToKeyID is a retired master key, ErrRotationKeys for any other pair of
// keys, ErrInvalid for malformed or identical key identifiers, a malformed
// ID or a negative TotalKeys, and ErrConflict when the ID is already used
// (or, on PostgreSQL, when another rotation started concurrently).
func (r *KeyRotations) Start(ctx context.Context, rot Rotation) error {
	switch {
	case !id.Valid(id.Rotation, rot.ID):
		return invalid("malformed rotation id")
	case !validMasterKeyID(rot.FromKeyID) || !validMasterKeyID(rot.ToKeyID):
		return invalid("malformed master key id")
	case rot.FromKeyID == rot.ToKeyID:
		return invalid("the new master key must differ from the current one")
	case rot.TotalKeys < 0:
		return invalid("negative key count")
	}
	started := rot.StartedAt
	if started.IsZero() {
		started = r.db.now()
	}
	err := r.db.systemScope(reasonKeyRotation).Tx(ctx, func(tx *SystemTx) error {
		_, err := scanRotation(tx.QueryRow(ctx, qRotationRunning))
		switch {
		case err == nil:
			return ErrRotationRunning
		case !errors.Is(err, ErrNotFound):
			return err
		}
		to, err := masterKeyStatus(ctx, tx, rot.ToKeyID)
		if err != nil {
			return err
		}
		from, err := masterKeyStatus(ctx, tx, rot.FromKeyID)
		if err != nil {
			return err
		}
		switch {
		case to == MasterKeyRetired:
			return ErrKeyRetired
		case from == MasterKeyActive && to == "", from == MasterKeyRetired && to == MasterKeyActive:
		default:
			return ErrRotationKeys
		}
		_, err = tx.Exec(ctx, qRotationInsert, rot.ID, rot.FromKeyID, rot.ToKeyID, rot.TotalKeys, toMillis(started))
		return err
	})
	if err != nil {
		return wrap("start key rotation", err)
	}
	return nil
}

// Get returns the rotation rotID, or ErrNotFound.
func (r *KeyRotations) Get(ctx context.Context, rotID string) (Rotation, error) {
	return r.read(ctx, "get key rotation", qRotationGet, rotID)
}

// Running returns the running rotation, or ErrNotFound when none is.
func (r *KeyRotations) Running(ctx context.Context) (Rotation, error) {
	return r.read(ctx, "get running key rotation", qRotationRunning)
}

// Latest returns the most recently started rotation, or ErrNotFound when
// none was ever started.
func (r *KeyRotations) Latest(ctx context.Context) (Rotation, error) {
	return r.read(ctx, "get latest key rotation", qRotationLatest)
}

// read runs a single-row rotation query.
func (r *KeyRotations) read(ctx context.Context, op string, q SystemQuery, args ...any) (Rotation, error) {
	var rot Rotation
	err := r.db.systemScope(reasonKeyRotation).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		rot, err = scanRotation(tx.QueryRow(ctx, q, args...))
		return err
	})
	if err != nil {
		return Rotation{}, wrap(op, err)
	}
	return rot, nil
}

// runningRotation returns the rotation rotID inside tx: ErrNotFound when it
// does not exist, ErrRotationNotRunning when it is not running.
func runningRotation(ctx context.Context, tx *SystemTx, rotID string) (Rotation, error) {
	rot, err := scanRotation(tx.QueryRow(ctx, qRotationGet, rotID))
	if err != nil {
		return Rotation{}, err
	}
	if rot.Status != RotationRunning {
		return Rotation{}, ErrRotationNotRunning
	}
	return rot, nil
}

// affected returns ErrRotationNotRunning unless res reports an affected
// row: the conditional update found no running rotation.
func affected(res sql.Result) error {
	if err := expectOne(res); errors.Is(err, ErrNotFound) {
		return ErrRotationNotRunning
	} else if err != nil {
		return err
	}
	return nil
}

// RewrapBatch rewraps, in one short transaction, up to limit keys still
// wrapped under fromKeyID (in ID order): rewrap receives each key and its
// tenant (both bound by the wrapping) and returns the key wrapped under
// toKeyID. Each row is updated only if it is still wrapped under fromKeyID,
// so a key deleted meanwhile is skipped, and the rotation progress grows by
// the number of rows updated, which RewrapBatch returns (0 when no key is
// left). An error from rewrap, or an invalid blob, rolls the whole batch
// back and is returned. It returns ErrNotFound for an unknown rotation and
// ErrRotationNotRunning when the rotation is not running or its keys differ
// from fromKeyID and toKeyID.
func (r *KeyRotations) RewrapBatch(ctx context.Context, rotID, fromKeyID, toKeyID string, limit int,
	rewrap func(k WrappedKey, tid tenant.ID) ([]byte, error),
) (int, error) {
	if limit <= 0 || rewrap == nil {
		return 0, invalid("rewrap batch needs a positive limit and a function")
	}
	n := 0
	err := r.db.systemScope(reasonKeyRotation).Tx(ctx, func(tx *SystemTx) error {
		rot, err := runningRotation(ctx, tx, rotID)
		if err != nil {
			return err
		}
		if rot.FromKeyID != fromKeyID || rot.ToKeyID != toKeyID {
			return ErrRotationNotRunning
		}
		type item struct {
			tid tenant.ID
			key WrappedKey
		}
		// Read the whole batch first: the connection cannot run updates
		// while a result set is open.
		rows, err := tx.Query(ctx, qWrappedKeyBatch, fromKeyID, limit)
		if err != nil {
			return err
		}
		items, err := collect(rows, func(r *sql.Rows) (item, error) {
			var (
				it      item
				tid     string
				created int64
			)
			err := r.Scan(&tid, &it.key.ID, &it.key.Purpose, &it.key.KeyID, &it.key.Blob, &created)
			it.tid = tenant.ID(tid)
			it.key.CreatedAt = fromMillis(created)
			return it, err
		})
		if err != nil {
			return err
		}
		for _, it := range items {
			blob, err := rewrap(it.key, it.tid)
			if err != nil {
				return err
			}
			if !validBlob(blob) {
				return invalid("rewrapped key must hold 1 to %d bytes", MaxWrappedKeyBytes)
			}
			res, err := tx.Exec(ctx, qWrappedKeyRewrap, blob, toKeyID, it.key.ID, fromKeyID)
			if err != nil {
				return err
			}
			m, err := res.RowsAffected()
			if err != nil {
				return err
			}
			n += int(m)
		}
		res, err := tx.Exec(ctx, qRotationProgress, n, rotID, fromKeyID, toKeyID)
		if err != nil {
			return err
		}
		return affected(res)
	})
	if err != nil {
		return 0, wrap("rewrap keys", err)
	}
	return n, nil
}

// Complete ends the running rotation rotID at now, in one transaction: the
// new master key becomes the active one (registered if needed), any other
// active key is retired, and the rotation is marked completed. For a
// clean-up rotation (retired source, active target) only the rotation
// changes. The target key is never retired. On PostgreSQL, writes to
// wrapped_keys are blocked from the count of the remaining keys to the
// commit, so that no key wrapped under the old master key can slip in. It
// returns ErrRotationIncomplete while keys are still wrapped under the old
// master key, ErrKeyRetired when the target key was retired meanwhile,
// ErrNotFound for an unknown rotation and ErrRotationNotRunning when it is
// not running.
func (r *KeyRotations) Complete(ctx context.Context, rotID string, now time.Time) error {
	ms := toMillis(now)
	err := r.db.systemScope(reasonKeyRotation).Tx(ctx, func(tx *SystemTx) error {
		rot, err := runningRotation(ctx, tx, rotID)
		if err != nil {
			return err
		}
		if err := lockWrappedKeys(ctx, tx); err != nil {
			return err
		}
		var left int64
		if err := tx.QueryRow(ctx, qWrappedKeyCountByKey, rot.FromKeyID).Scan(&left); err != nil {
			return err
		}
		if left > 0 {
			return ErrRotationIncomplete
		}
		status, err := masterKeyStatus(ctx, tx, rot.ToKeyID)
		switch {
		case err != nil:
			return err
		case status == MasterKeyRetired:
			return ErrKeyRetired
		}
		// Retire first: at most one key may be active. The target is
		// excluded, so a clean-up rotation retires nothing.
		if _, err := tx.Exec(ctx, qMasterKeyRetire, ms, rot.ToKeyID); err != nil {
			return err
		}
		if status == "" {
			if _, err := tx.Exec(ctx, qMasterKeyAdd, rot.ToKeyID, ms); err != nil {
				return err
			}
		}
		res, err := tx.Exec(ctx, qRotationFinish, string(RotationCompleted), ms, nil, rotID)
		if err != nil {
			return err
		}
		return affected(res)
	})
	if err != nil {
		return wrap("complete key rotation", err)
	}
	return nil
}

// masterKeyStatus returns the status of the master key keyID inside tx, or
// "" when it is not registered.
func masterKeyStatus(ctx context.Context, tx *SystemTx, keyID string) (MasterKeyStatus, error) {
	var status string
	err := tx.QueryRow(ctx, qMasterKeyStatus, keyID).Scan(&status)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	return MasterKeyStatus(status), err
}

// lockWrappedKeys blocks concurrent writes to wrapped_keys until the end of
// tx, on engines that need it (see dialect.lockWrappedKeys).
func lockWrappedKeys(ctx context.Context, tx *SystemTx) error {
	if tx.dialect.lockWrappedKeys == "" {
		return nil
	}
	_, err := tx.tx.ExecContext(ctx, tx.dialect.lockWrappedKeys)
	return err
}

// Fail marks the running rotation rotID as failed at now, with message msg
// (truncated to 1000 bytes; it must never contain key material). The master
// keys are unchanged: every key stays readable with one of the two keys,
// and a new rotation may start. It returns ErrNotFound for an unknown
// rotation and ErrRotationNotRunning when it is not running.
func (r *KeyRotations) Fail(ctx context.Context, rotID, msg string, now time.Time) error {
	if len(msg) > maxRotationErrorLen {
		msg = strings.ToValidUTF8(msg[:maxRotationErrorLen], "")
	}
	err := r.db.systemScope(reasonKeyRotation).Tx(ctx, func(tx *SystemTx) error {
		if _, err := runningRotation(ctx, tx, rotID); err != nil {
			return err
		}
		res, err := tx.Exec(ctx, qRotationFinish, string(RotationFailed), toMillis(now), msg, rotID)
		if err != nil {
			return err
		}
		return affected(res)
	})
	if err != nil {
		return wrap("fail key rotation", err)
	}
	return nil
}

// Abandon marks the running rotation rotID as failed at now, with message
// msg, unless giving it up would strand wrapped keys: it returns an error
// wrapping ErrRotationInUse (with the number of keys) when keys are wrapped
// under its target and the target is not the registered active key. A
// clean-up rotation, whose target is the active key, can always be
// abandoned. The count and the update happen in one transaction that, on
// PostgreSQL, blocks writes to wrapped_keys (SQLite transactions are
// already exclusive), so no key can be wrapped under the target in between.
// It returns ErrNotFound for an unknown rotation and ErrRotationNotRunning
// when it is not running.
func (r *KeyRotations) Abandon(ctx context.Context, rotID, msg string, now time.Time) error {
	if len(msg) > maxRotationErrorLen {
		msg = strings.ToValidUTF8(msg[:maxRotationErrorLen], "")
	}
	err := r.db.systemScope(reasonKeyRotation).Tx(ctx, func(tx *SystemTx) error {
		rot, err := runningRotation(ctx, tx, rotID)
		if err != nil {
			return err
		}
		if err := lockWrappedKeys(ctx, tx); err != nil {
			return err
		}
		status, err := masterKeyStatus(ctx, tx, rot.ToKeyID)
		if err != nil {
			return err
		}
		if status != MasterKeyActive {
			var n int64
			if err := tx.QueryRow(ctx, qWrappedKeyCountByKey, rot.ToKeyID).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return fmt.Errorf("%w: %d key(s) wrapped under %s", ErrRotationInUse, n, rot.ToKeyID)
			}
		}
		res, err := tx.Exec(ctx, qRotationFinish, string(RotationFailed), toMillis(now), msg, rotID)
		if err != nil {
			return err
		}
		return affected(res)
	})
	if err != nil {
		return wrap("abandon key rotation", err)
	}
	return nil
}

package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Reasons of the key system queries.
const (
	reasonKeyRotation = "master key rotation"
	reasonKeyCheck    = "startup key check"
)

// Purposes of a wrapped key, as stored in wrapped_keys.purpose. Each purpose
// is wrapped with its own key derived from the master key.
const (
	// KeyPurposeDEK marks the data encryption key of a file.
	KeyPurposeDEK = "dek"
	// KeyPurposeSecret marks a configuration secret (SMTP password...).
	KeyPurposeSecret = "secret"
)

// MaxWrappedKeyBytes bounds the size of a wrapped key blob. A wrapped
// 32-byte key takes 61 bytes; secrets are short too.
const MaxWrappedKeyBytes = 4096

// Master key identifiers: "mk_" followed by 16 lowercase hexadecimal
// characters (64 bits of an HMAC of the key). They must match the format
// produced by crypto.MasterKey.ID (keyIDPrefix and keyIDBytes in
// internal/crypto); a cross-package test in internal/masterkey checks it.
const (
	masterKeyIDPrefix = "mk_"
	masterKeyIDHexLen = 16
)

// wrappedKeyColumns is the column list read by the wrapped key queries.
const wrappedKeyColumns = `id, purpose, key_id, blob, created_at`

// Statements of the WrappedKeys repository: tenant queries for the
// operations of one tenant, system queries for the master key operations,
// which span every tenant.
var (
	qWrappedKeyInsert = tenantQuery(
		`INSERT INTO wrapped_keys (tenant_id, id, purpose, key_id, blob, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
	qWrappedKeyGet = tenantQuery(
		`SELECT ` + wrappedKeyColumns + ` FROM wrapped_keys WHERE tenant_id = ? AND id = ?`)
	qWrappedKeyDelete = tenantQuery(
		`DELETE FROM wrapped_keys WHERE tenant_id = ? AND id = ?`)
	qWrappedKeyListIDs = tenantQuery(
		`SELECT id FROM wrapped_keys WHERE tenant_id = ? AND id > ? ORDER BY id LIMIT ?`)
	qWrappedKeyIDsInUse = systemQuery(
		`SELECT key_id FROM wrapped_keys UNION SELECT key_id FROM system_secrets ORDER BY key_id`,
		reasonKeyCheck)
	qWrappedKeyCountByKey = systemQuery(
		`SELECT (SELECT count(*) FROM wrapped_keys WHERE key_id = ?) + (SELECT count(*) FROM system_secrets WHERE key_id = ?)`,
		reasonKeyRotation)
	qWrappedKeyBatch = systemQuery(
		`SELECT tenant_id, `+wrappedKeyColumns+` FROM wrapped_keys WHERE key_id = ? ORDER BY id LIMIT ?`,
		reasonKeyRotation)
	// qWrappedKeyRewrap only updates a row still wrapped under the old key,
	// so that a concurrent change (deletion) is never overwritten.
	qWrappedKeyRewrap = systemQuery(
		`UPDATE wrapped_keys SET blob = ?, key_id = ? WHERE id = ? AND key_id = ?`,
		reasonKeyRotation)
)

// WrappedKey is a data key or secret of a tenant, encrypted (wrapped) under
// a master key. The store never sees the clear key: Blob is opaque here.
type WrappedKey struct {
	// ID is the row identifier ("wk_" + ULID). The caller assigns it,
	// because the wrapping authenticates it (and the tenant).
	ID string
	// Purpose is KeyPurposeDEK or KeyPurposeSecret.
	Purpose string
	// KeyID identifies the master key Blob is wrapped under.
	KeyID string
	// Blob is the wrapped key (1 to MaxWrappedKeyBytes bytes).
	Blob []byte
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
}

// WrappedKeys is the repository of wrapped keys, the only table holding
// encrypted keys. Obtain it with [DB.WrappedKeys]. Create, Get and Delete
// are tenant-scoped; KeyIDsInUse and CountByKey span every tenant for the
// master key operations.
type WrappedKeys struct {
	db *DB
}

// WrappedKeys returns the wrapped key repository.
func (db *DB) WrappedKeys() *WrappedKeys { return &WrappedKeys{db: db} }

// validMasterKeyID reports whether s has the shape of a master key
// identifier.
func validMasterKeyID(s string) bool {
	h, ok := strings.CutPrefix(s, masterKeyIDPrefix)
	return ok && len(h) == masterKeyIDHexLen && strings.Trim(h, "0123456789abcdef") == ""
}

// validBlob reports whether b is an acceptable wrapped key.
func validBlob(b []byte) bool {
	return len(b) > 0 && len(b) <= MaxWrappedKeyBytes
}

// validateWrappedKey checks the fields of k set by the caller.
func validateWrappedKey(k WrappedKey) error {
	switch {
	case !id.Valid(id.WrappedKey, k.ID):
		return invalid("malformed wrapped key id")
	case k.Purpose != KeyPurposeDEK && k.Purpose != KeyPurposeSecret:
		return invalid("unknown wrapped key purpose")
	case !validMasterKeyID(k.KeyID):
		return invalid("malformed master key id")
	case !validBlob(k.Blob):
		return invalid("wrapped key must hold 1 to %d bytes", MaxWrappedKeyBytes)
	}
	return nil
}

// scanWrappedKey reads one row of wrappedKeyColumns.
func scanWrappedKey(sc interface{ Scan(...any) error }) (WrappedKey, error) {
	var (
		k       WrappedKey
		created int64
	)
	if err := sc.Scan(&k.ID, &k.Purpose, &k.KeyID, &k.Blob, &created); err != nil {
		return WrappedKey{}, err
	}
	k.CreatedAt = fromMillis(created)
	return k, nil
}

// Create stores k for tenant tid in its own transaction (see
// [WrappedKeys.CreateTx]).
func (r *WrappedKeys) Create(ctx context.Context, tid tenant.ID, k WrappedKey) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if err := s.Tx(ctx, func(tx *ScopedTx) error { return r.create(ctx, tx, k) }); err != nil {
		return wrap("create wrapped key", err)
	}
	return nil
}

// CreateTx stores k for the tenant tx is bound to, inside tx, so that the
// key and the row it protects (a file...) are created atomically. It
// returns ErrInvalid for a malformed field, ErrNotFound when the tenant
// does not exist, ErrConflict when the ID is already used and ErrKeyRetired
// when k.KeyID names a retired master key. After an error, the caller must
// abort the transaction (return the error from the transaction function).
func (r *WrappedKeys) CreateTx(ctx context.Context, tx *ScopedTx, k WrappedKey) error {
	if err := r.create(ctx, tx, k); err != nil {
		return wrap("create wrapped key", err)
	}
	return nil
}

// create validates and inserts k in tx, returning raw errors.
func (r *WrappedKeys) create(ctx context.Context, tx *ScopedTx, k WrappedKey) error {
	if err := validateWrappedKey(k); err != nil {
		return err
	}
	created := k.CreatedAt
	if created.IsZero() {
		created = r.db.now()
	}
	_, err := tx.Exec(ctx, qWrappedKeyInsert, k.ID, k.Purpose, k.KeyID, k.Blob, toMillis(created))
	return err
}

// Get returns the wrapped key wkID of tenant tid, or ErrNotFound when it
// does not exist or belongs to another tenant.
func (r *WrappedKeys) Get(ctx context.Context, tid tenant.ID, wkID string) (WrappedKey, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return WrappedKey{}, err
	}
	var k WrappedKey
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		var err error
		k, err = scanWrappedKey(tx.QueryRow(ctx, qWrappedKeyGet, wkID))
		return err
	})
	if err != nil {
		return WrappedKey{}, wrap("get wrapped key", err)
	}
	return k, nil
}

// Delete destroys the wrapped key wkID of tenant tid in its own
// transaction (see [WrappedKeys.DeleteTx]).
func (r *WrappedKeys) Delete(ctx context.Context, tid tenant.ID, wkID string) error {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	if err := s.Tx(ctx, func(tx *ScopedTx) error { return deleteWrappedKey(ctx, tx, wkID) }); err != nil {
		return wrap("delete wrapped key", err)
	}
	return nil
}

// DeleteTx destroys the wrapped key wkID of the tenant tx is bound to,
// inside tx: the cryptographic erasure of what it protects (spec 16.1). It
// returns ErrNotFound when the key does not exist or belongs to another
// tenant. Callers delete the key before the file it protects, and call
// [DB.ScrubDeleted] afterwards to purge the SQLite WAL.
func (r *WrappedKeys) DeleteTx(ctx context.Context, tx *ScopedTx, wkID string) error {
	if err := deleteWrappedKey(ctx, tx, wkID); err != nil {
		return wrap("delete wrapped key", err)
	}
	return nil
}

// deleteWrappedKey deletes wkID in tx, returning raw errors.
func deleteWrappedKey(ctx context.Context, tx *ScopedTx, wkID string) error {
	res, err := tx.Exec(ctx, qWrappedKeyDelete, wkID)
	if err != nil {
		return err
	}
	return expectOne(res)
}

// ListIDs returns the IDs (never the keys) of up to limit wrapped keys of
// tenant tid that sort after after ("" for the first page), in ID order
// (DefaultPageSize when limit <= 0, at most MaxPageSize). The deletion of a
// tenant walks them to destroy every key left (SMTP password, sealed
// tokens, keys of files without transfer) before [Tenants.Delete]. A
// malformed after yields ErrInvalid.
func (r *WrappedKeys) ListIDs(ctx context.Context, tid tenant.ID, after string, limit int) ([]string, error) {
	if after != "" && !id.Valid(id.WrappedKey, after) {
		return nil, invalid("malformed cursor")
	}
	s, err := r.db.Scoped(tid)
	if err != nil {
		return nil, err
	}
	var ids []string
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		rows, err := tx.Query(ctx, qWrappedKeyListIDs, after, pageLimit(limit))
		if err != nil {
			return err
		}
		ids, err = collect(rows, func(r *sql.Rows) (string, error) {
			var s string
			err := r.Scan(&s)
			return s, err
		})
		return err
	})
	if err != nil {
		return nil, wrap("list wrapped key ids", err)
	}
	return ids, nil
}

// KeyIDsInUse returns the distinct master key identifiers that wrapped keys
// of any tenant or system secrets reference, sorted. The start-up check
// refuses to run when one of them is missing from the keyring.
func (r *WrappedKeys) KeyIDsInUse(ctx context.Context) ([]string, error) {
	var ids []string
	err := r.db.systemScope(reasonKeyCheck).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		ids, err = keyIDsInUse(ctx, tx)
		return err
	})
	if err != nil {
		return nil, wrap("list master keys in use", err)
	}
	return ids, nil
}

// CountByKey returns the number of keys wrapped under the master key
// keyID: wrapped keys across every tenant plus system secrets. The master
// key rotation counts both, and [KeyRotations.Complete] refuses to
// complete while either remains under the old key.
func (r *WrappedKeys) CountByKey(ctx context.Context, keyID string) (int64, error) {
	if !validMasterKeyID(keyID) {
		return 0, invalid("malformed master key id")
	}
	var n int64
	err := r.db.systemScope(reasonKeyRotation).ReadTx(ctx, func(tx *SystemTx) error {
		return tx.QueryRow(ctx, qWrappedKeyCountByKey, keyID, keyID).Scan(&n)
	})
	if err != nil {
		return 0, wrap("count wrapped keys", err)
	}
	return n, nil
}

// keyIDsInUse returns the distinct master key identifiers referenced by
// wrapped keys and system secrets, sorted, inside tx.
func keyIDsInUse(ctx context.Context, tx *SystemTx) ([]string, error) {
	rows, err := tx.Query(ctx, qWrappedKeyIDsInUse)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r *sql.Rows) (string, error) {
		var s string
		err := r.Scan(&s)
		return s, err
	})
}

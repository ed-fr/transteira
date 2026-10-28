package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/ed-fr/transteira/internal/id"
)

// reasonSystemSecrets is the reason of the system secret queries.
const reasonSystemSecrets = "secrets sealed by the master key that belong to no tenant (administrator TOTP secrets)"

// SecretPurposeAdminTOTP is the purpose of a system secret holding the
// TOTP secret of an administrator. It matches crypto.PurposeAdminTOTP,
// the wrapping purpose.
const SecretPurposeAdminTOTP = "admin-totp"

// SecretPurposeWebhook is the purpose of a system secret holding the URL
// or the signing secret of an instance-wide webhook. It matches
// crypto.PurposeWebhook, the wrapping purpose.
const SecretPurposeWebhook = "webhook"

// sealedRowColumns is the column list read by the system secret queries.
const sealedRowColumns = `id, purpose, key_id, blob, created_at`

// Statements of the SystemSecrets repository and of the master key
// rotation of system secrets.
var (
	qSystemSecretInsert = systemQuery(
		`INSERT INTO system_secrets (`+sealedRowColumns+`) VALUES (?, ?, ?, ?, ?)`,
		reasonSystemSecrets)
	qSystemSecretGet = systemQuery(
		`SELECT `+sealedRowColumns+` FROM system_secrets WHERE id = ?`,
		reasonSystemSecrets)
	qSystemSecretDelete = systemQuery(
		`DELETE FROM system_secrets WHERE id = ?`,
		reasonSystemSecrets)
	qSystemSecretBatch = systemQuery(
		`SELECT `+sealedRowColumns+` FROM system_secrets WHERE key_id = ? ORDER BY id LIMIT ?`,
		reasonKeyRotation)
	// qSystemSecretRewrap only updates a row still sealed under the old
	// key, so that a concurrent change (deletion) is never overwritten.
	qSystemSecretRewrap = systemQuery(
		`UPDATE system_secrets SET blob = ?, key_id = ? WHERE id = ? AND key_id = ?`,
		reasonKeyRotation)
)

// SystemSecret is a secret sealed (wrapped) under a master key that belongs
// to no tenant, such as the TOTP secret of an administrator. The store
// never sees the clear secret: Blob is opaque here.
type SystemSecret struct {
	// ID is the row identifier ("ss_" + ULID). The caller assigns it,
	// because the sealing authenticates it.
	ID string
	// Purpose is SecretPurposeAdminTOTP or SecretPurposeWebhook.
	Purpose string
	// KeyID identifies the master key Blob is sealed under.
	KeyID string
	// Blob is the sealed secret (1 to MaxWrappedKeyBytes bytes).
	Blob []byte
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
}

// SystemSecrets is the repository of system secrets. Its operations are
// system-scoped. Obtain it with [DB.SystemSecrets]. The master key
// operations cover the table: [WrappedKeys.KeyIDsInUse] and
// [WrappedKeys.CountByKey] include its rows, and
// [KeyRotations.RewrapSystemSecretsBatch] rewraps them.
type SystemSecrets struct {
	db *DB
}

// SystemSecrets returns the system secret repository.
func (db *DB) SystemSecrets() *SystemSecrets { return &SystemSecrets{db: db} }

// validateSystemSecret checks the fields of s set by the caller.
func validateSystemSecret(s SystemSecret) error {
	switch {
	case !id.Valid(id.SystemSecret, s.ID):
		return invalid("malformed system secret id")
	case s.Purpose != SecretPurposeAdminTOTP && s.Purpose != SecretPurposeWebhook:
		return invalid("unknown system secret purpose")
	case !validMasterKeyID(s.KeyID):
		return invalid("malformed master key id")
	case !validBlob(s.Blob):
		return invalid("sealed secret must hold 1 to %d bytes", MaxWrappedKeyBytes)
	}
	return nil
}

// scanSystemSecret reads one row of sealedRowColumns.
func scanSystemSecret(sc interface{ Scan(...any) error }) (SystemSecret, error) {
	var (
		s       SystemSecret
		created int64
	)
	if err := sc.Scan(&s.ID, &s.Purpose, &s.KeyID, &s.Blob, &created); err != nil {
		return SystemSecret{}, err
	}
	s.CreatedAt = fromMillis(created)
	return s, nil
}

// Create stores s in its own transaction (see [SystemSecrets.CreateTx]).
func (r *SystemSecrets) Create(ctx context.Context, s SystemSecret) error {
	err := r.db.systemScope(reasonSystemSecrets).Tx(ctx, func(tx *SystemTx) error { return r.create(ctx, tx, s) })
	if err != nil {
		return wrap("create system secret", err)
	}
	return nil
}

// CreateTx stores s inside tx. It returns ErrInvalid for a malformed
// field, ErrConflict when the ID is already used and ErrKeyRetired when
// s.KeyID names a retired master key. TOTP secrets are normally created
// through [Admins.SetPendingTOTPTx].
func (r *SystemSecrets) CreateTx(ctx context.Context, tx *SystemTx, s SystemSecret) error {
	if err := r.create(ctx, tx, s); err != nil {
		return wrap("create system secret", err)
	}
	return nil
}

// create validates and inserts s in tx, returning raw errors.
func (r *SystemSecrets) create(ctx context.Context, tx *SystemTx, s SystemSecret) error {
	if err := validateSystemSecret(s); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, qSystemSecretInsert, s.ID, s.Purpose, s.KeyID, s.Blob, toMillis(r.db.orNow(s.CreatedAt)))
	return err
}

// Get returns the system secret ssID, or ErrNotFound.
func (r *SystemSecrets) Get(ctx context.Context, ssID string) (SystemSecret, error) {
	var s SystemSecret
	err := r.db.systemScope(reasonSystemSecrets).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		s, err = scanSystemSecret(tx.QueryRow(ctx, qSystemSecretGet, ssID))
		return err
	})
	if err != nil {
		return SystemSecret{}, wrap("get system secret", err)
	}
	return s, nil
}

// GetTx is Get inside tx.
func (r *SystemSecrets) GetTx(ctx context.Context, tx *SystemTx, ssID string) (SystemSecret, error) {
	s, err := scanSystemSecret(tx.QueryRow(ctx, qSystemSecretGet, ssID))
	if err != nil {
		return SystemSecret{}, wrap("get system secret", err)
	}
	return s, nil
}

// Delete destroys the system secret ssID (cryptographic erasure). It
// returns ErrNotFound when it does not exist, and an error wrapping
// ErrNotFound too when an administrator still references it (clear the
// reference first: [Admins.ClearTOTP] does both). Callers run
// [DB.ScrubDeleted] afterwards to purge the SQLite WAL.
func (r *SystemSecrets) Delete(ctx context.Context, ssID string) error {
	err := r.db.systemScope(reasonSystemSecrets).Tx(ctx, func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qSystemSecretDelete, ssID)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("delete system secret", err)
	}
	return nil
}

// DeleteTx is Delete inside tx, so that a secret and the row referencing
// it can be destroyed together (an instance-wide webhook,
// [SystemWebhooks.DeleteTx]). It returns ErrNotFound when the secret does
// not exist. Callers run [DB.ScrubDeleted] once tx is committed.
func (r *SystemSecrets) DeleteTx(ctx context.Context, tx *SystemTx, ssID string) error {
	res, err := tx.Exec(ctx, qSystemSecretDelete, ssID)
	if err == nil {
		err = expectOne(res)
	}
	if err != nil {
		return wrap("delete system secret", err)
	}
	return nil
}

// deleteSecrets destroys, inside tx, the system secrets of ids that are
// not "", ignoring the missing ones.
func deleteSecrets(ctx context.Context, tx *SystemTx, ids ...string) error {
	for _, ssID := range ids {
		if ssID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, qSystemSecretDelete, ssID); err != nil {
			return err
		}
	}
	return nil
}

// RewrapSystemSecretsBatch is the counterpart of [KeyRotations.RewrapBatch]
// for the system secrets: in one short transaction, it rewraps up to limit
// secrets still sealed under fromKeyID (in ID order) with rewrap, which
// receives each secret and returns it sealed under toKeyID (a system
// secret has no tenant; its ID and purpose are bound by the sealing). Each
// row is updated only if it is still sealed under fromKeyID, and the
// rotation progress grows by the number of rows updated, which it returns
// (0 when no secret is left). An error from rewrap, or an invalid blob,
// rolls the whole batch back and is returned. It returns ErrNotFound for an
// unknown rotation and ErrRotationNotRunning when the rotation is not
// running or its keys differ from fromKeyID and toKeyID. A rotation is
// complete ([KeyRotations.Complete]) only once both RewrapBatch and
// RewrapSystemSecretsBatch return 0.
func (r *KeyRotations) RewrapSystemSecretsBatch(ctx context.Context, rotID, fromKeyID, toKeyID string, limit int,
	rewrap func(s SystemSecret) ([]byte, error),
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
		// Read the whole batch first: the connection cannot run updates
		// while a result set is open.
		rows, err := tx.Query(ctx, qSystemSecretBatch, fromKeyID, limit)
		if err != nil {
			return err
		}
		items, err := collect(rows, func(r *sql.Rows) (SystemSecret, error) { return scanSystemSecret(r) })
		if err != nil {
			return err
		}
		for _, s := range items {
			blob, err := rewrap(s)
			if err != nil {
				return err
			}
			if !validBlob(blob) {
				return invalid("rewrapped secret must hold 1 to %d bytes", MaxWrappedKeyBytes)
			}
			res, err := tx.Exec(ctx, qSystemSecretRewrap, blob, toKeyID, s.ID, fromKeyID)
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
		return 0, wrap("rewrap system secrets", err)
	}
	return n, nil
}

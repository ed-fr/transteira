package masterkey

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

var (
	// ErrUnknownKey is returned by Vault.Open and Vault.OpenSystem when a
	// row is wrapped with a master key the keyring does not hold. The
	// message names that key ID.
	ErrUnknownKey = errors.New("masterkey: wrapped with a master key that is not provided")
	// ErrPurposeMismatch is returned by Vault.Open and Vault.OpenSystem when
	// the stored purpose of a row is not the requested one, and by
	// Vault.WrapSystem for a purpose that is not a system secret purpose.
	ErrPurposeMismatch = errors.New("masterkey: wrapped key purpose mismatch")
)

// systemBinding is the tenant binding of the system secrets (table
// system_secrets), which belong to no tenant. The envelope binds every blob
// to a tenant identifier and a row identifier; a system secret is bound to
// this reserved value and to its own "ss_" ID, exactly as a tenant key is
// bound to its tenant and its "wk_" ID. A tenant ID is always "ten_"
// followed by a ULID (tenant.ID.Validate), so it can never equal this
// value: a system secret never unwraps as a tenant key and conversely, even
// for the same row ID and purpose. It is never empty, which the envelope
// refuses.
const systemBinding = "system"

// systemPurposes lists the purposes a system secret may be wrapped for.
var systemPurposes = map[crypto.Purpose]bool{crypto.PurposeAdminTOTP: true}

// generateDEK creates data encryption keys; replaced in tests to cover a
// failure of the random source.
var generateDEK = crypto.GenerateDEK

// Vault seals, opens and destroys the wrapped keys of tenants (table
// wrapped_keys), and wraps and opens the system secrets (table
// system_secrets, WrapSystem and OpenSystem). Every tenant key operation is
// scoped to a tenant: a row of another tenant is not found, and a blob copied
// to another row or tenant does not unwrap. A system secret is bound to its
// row and to the reserved system binding (systemBinding). It is safe for
// concurrent use.
//
// Rows are referenced by the objects they protect (files, tenant settings)
// through their ID. A row whose owner disappeared without calling Destroy
// (a crash between two transactions) is harmless but useless. Data keys and
// download token keys are created in the same transaction as the rows that
// reference them, so such orphans are not expected; the cleanup task does
// not reconcile wrapped_keys.
type Vault struct {
	keys    *store.WrappedKeys
	secrets *store.SystemSecrets
	kr      *Keyring
	logger  *slog.Logger
	// scrub purges deleted data from the database files (db.ScrubDeleted).
	scrub func(context.Context) error
}

// NewVault returns the vault storing wrapped keys in db with the keys of kr.
// logger receives the warnings of the post-deletion scrub (nil discards
// them).
func NewVault(db *store.DB, kr *Keyring, logger *slog.Logger) *Vault {
	return &Vault{keys: db.WrappedKeys(), secrets: db.SystemSecrets(), kr: kr, logger: orDiscard(logger), scrub: db.ScrubDeleted}
}

// orDiscard returns logger, or a logger discarding everything when nil.
func orDiscard(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return logger
}

// wrap wraps plaintext for tid with the wrapping key of the keyring (the new
// master key during a rotation), bound to a new row ID.
func (v *Vault) wrap(tid tenant.ID, p crypto.Purpose, plaintext []byte) (store.WrappedKey, error) {
	mk := v.kr.wrapKey()
	wkID := id.New(id.WrappedKey)
	blob, err := mk.Wrap(p, string(tid), wkID, plaintext)
	if err != nil {
		return store.WrappedKey{}, fmt.Errorf("masterkey: seal: %w", err)
	}
	return store.WrappedKey{ID: wkID, Purpose: string(p), KeyID: mk.ID(), Blob: blob}, nil
}

// sealError labels an error of the store when storing a wrapped key, and
// explains a retired wrapping key (refused by the database).
func (v *Vault) sealError(err error) error {
	if errors.Is(err, store.ErrKeyRetired) {
		return fmt.Errorf("masterkey: seal: the wrapping master key %s is recorded as retired and must never wrap "+
			"again; configure the active key; see %s: %w", v.kr.WrapID(), DocLink, err)
	}
	return fmt.Errorf("masterkey: seal: %w", err)
}

// Seal wraps plaintext for purpose p with the wrapping key of the keyring
// (the new master key during a rotation), bound to tid and to a new row ID,
// stores it in its own transaction and returns the row ID ("wk_..."). The
// caller keeps ownership of plaintext. A retired wrapping key is refused by
// the database (store.ErrKeyRetired).
func (v *Vault) Seal(ctx context.Context, tid tenant.ID, p crypto.Purpose, plaintext []byte) (string, error) {
	k, err := v.wrap(tid, p, plaintext)
	if err != nil {
		return "", err
	}
	if err := v.keys.Create(ctx, tid, k); err != nil {
		return "", v.sealError(err)
	}
	return k.ID, nil
}

// SealTx is Seal inside tx, so that the wrapped key and the row it protects
// are created atomically. The key is sealed for the tenant tx is bound to.
// After an error the caller must abort tx.
func (v *Vault) SealTx(ctx context.Context, tx *store.ScopedTx, p crypto.Purpose, plaintext []byte) (string, error) {
	k, err := v.wrap(tx.Tenant(), p, plaintext)
	if err != nil {
		return "", err
	}
	if err := v.keys.CreateTx(ctx, tx, k); err != nil {
		return "", v.sealError(err)
	}
	return k.ID, nil
}

// NewDEK generates a data encryption key, seals it for tid and returns its
// row ID and the plaintext key. The caller should clear the key once used.
func (v *Vault) NewDEK(ctx context.Context, tid tenant.ID) (wkID string, dek []byte, err error) {
	return newDEK(func(dek []byte) (string, error) { return v.Seal(ctx, tid, crypto.PurposeDEK, dek) })
}

// NewDEKTx is NewDEK inside tx, for the tenant tx is bound to, so that an
// upload row and its data key are created in one transaction (threat model
// P6). After an error the caller must abort tx.
func (v *Vault) NewDEKTx(ctx context.Context, tx *store.ScopedTx) (wkID string, dek []byte, err error) {
	return newDEK(func(dek []byte) (string, error) { return v.SealTx(ctx, tx, crypto.PurposeDEK, dek) })
}

// newDEK generates a data encryption key and seals it with seal.
func newDEK(seal func([]byte) (string, error)) (string, []byte, error) {
	dek, err := generateDEK()
	if err != nil {
		return "", nil, fmt.Errorf("masterkey: new data key: %w", err)
	}
	wkID, err := seal(dek)
	if err != nil {
		clear(dek)
		return "", nil, err
	}
	return wkID, dek, nil
}

// Open reads the row wkID of tid and unwraps it with the master key recorded
// on the row. It fails with store.ErrNotFound for an unknown row (or a row of
// another tenant), ErrPurposeMismatch when the row holds another purpose,
// ErrUnknownKey when the row's master key is not provided, and
// crypto.ErrUnwrap when the blob does not authenticate.
func (v *Vault) Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error) {
	row, err := v.keys.Get(ctx, tid, wkID)
	if err != nil {
		return nil, fmt.Errorf("masterkey: open: %w", err)
	}
	if row.Purpose != string(p) {
		return nil, fmt.Errorf("%w: wrapped key %s is not a %q key", ErrPurposeMismatch, wkID, p)
	}
	mk, ok := v.kr.key(row.KeyID)
	if !ok {
		return nil, fmt.Errorf("%w: wrapped key %s uses master key %s (%s); see %s",
			ErrUnknownKey, wkID, row.KeyID, v.kr.describe(), DocLink)
	}
	plaintext, err := mk.Unwrap(p, string(tid), wkID, row.Blob)
	if err != nil {
		return nil, fmt.Errorf("masterkey: open wrapped key %s: %w", wkID, err)
	}
	return plaintext, nil
}

// WrapSystem wraps plaintext, a secret that belongs to no tenant (the TOTP
// secret of an administrator), for purpose p with the wrapping key of the
// keyring (the new master key during a rotation). It assigns a new
// system secret ID ("ss_...") and binds the blob to it and to the reserved
// system binding (see the package documentation), then returns the row
// without storing it: the caller inserts it in its own transaction (for
// instance store.Admins.SetPendingTOTPTx), and gets store.ErrKeyRetired
// from the database if the wrapping key is retired. It returns an error
// matching ErrPurposeMismatch when p is not a system secret purpose
// (crypto.PurposeAdminTOTP). The caller keeps ownership of plaintext.
func (v *Vault) WrapSystem(p crypto.Purpose, plaintext []byte) (store.SystemSecret, error) {
	if !systemPurposes[p] {
		return store.SystemSecret{}, fmt.Errorf("%w: %q is not a system secret purpose", ErrPurposeMismatch, p)
	}
	mk := v.kr.wrapKey()
	ssID := id.New(id.SystemSecret)
	blob, err := mk.Wrap(p, systemBinding, ssID, plaintext)
	if err != nil {
		return store.SystemSecret{}, fmt.Errorf("masterkey: seal system secret: %w", err)
	}
	return store.SystemSecret{ID: ssID, Purpose: string(p), KeyID: mk.ID(), Blob: blob}, nil
}

// OpenSystem reads the system secret secretID and unwraps it with the
// master key recorded on its row (the old or the new key during a
// rotation). It fails with store.ErrNotFound for an unknown secret,
// ErrPurposeMismatch when the secret holds another purpose, ErrUnknownKey
// when its master key is not provided, and crypto.ErrUnwrap when the blob
// does not authenticate (tampered, or copied from another row).
func (v *Vault) OpenSystem(ctx context.Context, p crypto.Purpose, secretID string) ([]byte, error) {
	row, err := v.secrets.Get(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("masterkey: open system secret: %w", err)
	}
	if row.Purpose != string(p) {
		return nil, fmt.Errorf("%w: system secret %s is not a %q secret", ErrPurposeMismatch, secretID, p)
	}
	mk, ok := v.kr.key(row.KeyID)
	if !ok {
		return nil, fmt.Errorf("%w: system secret %s uses master key %s (%s); see %s",
			ErrUnknownKey, secretID, row.KeyID, v.kr.describe(), DocLink)
	}
	plaintext, err := mk.Unwrap(p, systemBinding, secretID, row.Blob)
	if err != nil {
		return nil, fmt.Errorf("masterkey: open system secret %s: %w", secretID, err)
	}
	return plaintext, nil
}

// Destroy deletes the row wkID of tid (crypto-erase): whatever it protected
// can no longer be decrypted from the live system. It then scrubs the
// database files (Scrub). It fails with store.ErrNotFound when the row does
// not exist for tid. Batch jobs (expiry, cleanup) should use DestroyTx for
// each key and call Scrub once per batch instead.
func (v *Vault) Destroy(ctx context.Context, tid tenant.ID, wkID string) error {
	if err := v.keys.Delete(ctx, tid, wkID); err != nil {
		return fmt.Errorf("masterkey: destroy: %w", err)
	}
	return v.Scrub(ctx)
}

// DestroyTx deletes the row wkID inside tx, the transaction that also
// deletes the object it protects (the file row is deleted after the key,
// the file on disk after the commit). The caller must call Scrub once tx is
// committed.
func (v *Vault) DestroyTx(ctx context.Context, tx *store.ScopedTx, wkID string) error {
	if err := v.keys.DeleteTx(ctx, tx, wkID); err != nil {
		return fmt.Errorf("masterkey: destroy: %w", err)
	}
	return nil
}

// Scrub purges deleted wrapped keys from the database files (on SQLite, a
// WAL checkpoint after secure_delete; nothing on PostgreSQL, see
// store.DB.ScrubDeleted). A checkpoint left incomplete by active readers is
// logged as a warning and is not an error: the next scrub completes it.
func (v *Vault) Scrub(ctx context.Context) error {
	return scrubDeleted(ctx, v.scrub, v.logger)
}

// scrubDeleted runs scrub, logging store.ErrScrubBusy as a warning.
func scrubDeleted(ctx context.Context, scrub func(context.Context) error, logger *slog.Logger) error {
	err := scrub(ctx)
	if errors.Is(err, store.ErrScrubBusy) {
		logger.WarnContext(ctx, "deleted keys may remain in the database WAL until the next checkpoint",
			slog.String("error", err.Error()))
		return nil
	}
	if err != nil {
		return fmt.Errorf("masterkey: scrub deleted keys: %w", err)
	}
	return nil
}

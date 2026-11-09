package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// The optional file of a one-time secret, its delivery by e-mail and its
// read receipt (since 2.1, data-model-v2.1.md section 2.1 "File",
// "One-time file grant" and "Receipt"; e2e-format.md 3.3.5 and 4.1).

// SecretFiles stores the files of the secrets under
// <tenant dir>/secrets/<storage name>. *storage.Store implements it.
type SecretFiles interface {
	// CreateSecretFile creates (or truncates) the file name of tenant tid
	// for writing.
	CreateSecretFile(tid tenant.ID, name string) (*os.File, error)
	// OpenSecretFile opens the file name of tenant tid for reading.
	OpenSecretFile(tid tenant.ID, name string) (*os.File, int64, error)
	// RemoveSecretFile removes the file name of tenant tid (idempotent).
	RemoveSecretFile(tid tenant.ID, name string) error
}

// secretFileBufSize is the size of the reads of an uploaded file body.
const secretFileBufSize = 64 << 10

// Statements of the files, the send call and the receipts.
var (
	// qSecretFileBytes sums the declared sizes of the stored secret files
	// of a tenant, counted in its storage quota (see usedBytesTx).
	qSecretFileBytes = tenantQuery(
		`SELECT CAST(COALESCE(sum(file_size), 0) AS BIGINT) FROM secrets
		WHERE tenant_id = ? AND file_storage_name IS NOT NULL`)
	// qSecretFileBytesAll is qSecretFileBytes for every tenant at once.
	qSecretFileBytesAll = systemQuery(
		`SELECT tenant_id, CAST(COALESCE(sum(file_size), 0) AS BIGINT) FROM secrets
		WHERE file_storage_name IS NOT NULL GROUP BY tenant_id ORDER BY tenant_id`,
		reasonUsedBytesAll)
	// qSecretFileBegin attaches the new file key and the fresh storage
	// name of an upload attempt: a pending secret with a declared file,
	// neither uploaded nor receiving it.
	qSecretFileBegin = tenantQuery(
		`UPDATE secrets SET file_key_id = ?, file_storage_name = ? WHERE tenant_id = ? AND id = ? AND state = 'pending'
		AND file_size IS NOT NULL AND file_key_id IS NULL AND file_uploaded_at IS NULL`)
	// qSecretFileAbort detaches the file key of a failed upload, unless
	// the row changed meanwhile (which then destroyed the key itself).
	qSecretFileAbort = tenantQuery(
		`UPDATE secrets SET file_key_id = NULL WHERE tenant_id = ? AND id = ? AND file_key_id = ?
		AND file_uploaded_at IS NULL`)
	// qSecretFileDoneLink completes the upload of a link secret, which
	// becomes active.
	qSecretFileDoneLink = tenantQuery(
		`UPDATE secrets SET file_uploaded_at = ?, state = 'active', activated_at = ?, expires_at = ?
		WHERE tenant_id = ? AND id = ? AND state = 'pending' AND delivery = 'link' AND file_key_id = ?
		AND file_uploaded_at IS NULL`)
	// qSecretFileDoneEmail completes the upload of an e-mail secret, which
	// stays pending until the send call.
	qSecretFileDoneEmail = tenantQuery(
		`UPDATE secrets SET file_uploaded_at = ?
		WHERE tenant_id = ? AND id = ? AND state = 'pending' AND delivery = 'email' AND file_key_id = ?
		AND file_uploaded_at IS NULL`)
	// qSecretActivate activates a pending e-mail secret whose file, if
	// any, is uploaded (the send call).
	qSecretActivate = tenantQuery(
		`UPDATE secrets SET state = 'active', activated_at = ?, expires_at = ?
		WHERE tenant_id = ? AND id = ? AND state = 'pending' AND delivery = 'email'
		AND (file_size IS NULL OR file_uploaded_at IS NOT NULL)`)
	// qSecretTokenHash reads the token hash of a secret (the send call
	// checks the token the creator presents).
	qSecretTokenHash = tenantQuery(`SELECT token_hash FROM secrets WHERE tenant_id = ? AND id = ?`)
	// qSecretGrantByHash reads what a file download checks.
	qSecretGrantByHash = tenantQuery(
		`SELECT id, state, file_size, file_storage_name, file_key_id, file_grant_hash, file_grant_expires_at
		FROM secrets WHERE tenant_id = ? AND token_hash = ?`)
	// qSecretGrantConsume ends the one-time grant at the first complete
	// download: the file and its key go.
	qSecretGrantConsume = tenantQuery(
		`UPDATE secrets SET file_downloaded_at = ?, file_grant_hash = NULL, file_grant_expires_at = NULL, ` + secretFileNull + `
		WHERE tenant_id = ? AND id = ? AND state = 'read' AND file_grant_hash = ?`)
	// qSecretGrantExpire ends an expired grant without download.
	qSecretGrantExpire = tenantQuery(
		`UPDATE secrets SET file_grant_hash = NULL, file_grant_expires_at = NULL, ` + secretFileNull + `
		WHERE tenant_id = ? AND id = ? AND file_grant_hash IS NOT NULL AND file_grant_expires_at <= ?`)
	// qSecretMarkReceipt marks the receipt of an ended secret as sent,
	// once.
	qSecretMarkReceipt = tenantQuery(
		`UPDATE secrets SET receipt_sent_at = ? WHERE tenant_id = ? AND id = ? AND receipt_sent_at IS NULL
		AND read_receipt = ? AND state IN ('read', 'expired', 'locked')`)
	// qSecretFileRefs lists the storage names of the secret files of a
	// tenant, with their key (orphan file sweep).
	qSecretFileRefs = tenantQuery(
		`SELECT file_storage_name, file_key_id FROM secrets WHERE tenant_id = ? AND file_storage_name IS NOT NULL
		ORDER BY file_storage_name LIMIT ?`)

	qSecretDueGrant = systemQuery(
		`SELECT tenant_id, id, file_grant_expires_at FROM secrets WHERE file_grant_hash IS NOT NULL
		AND file_grant_expires_at <= ? AND (file_grant_expires_at, tenant_id, id) > (?, ?, ?)
		ORDER BY file_grant_expires_at, tenant_id, id LIMIT ?`,
		reasonSecretSweep)
)

// secretFileBinding is the file identifier the at-rest encryption of the
// file of secret secID is bound to (distinct from the sealed text's).
func secretFileBinding(secID string) string { return secID + ".file" }

// UploadFile stores the declared file of the pending secret secID of
// tenant tid for its creator actor ([SecretActor.Owns]), reading body
// (e2e-format.md 4.1, data-model-v2.1.md 2.1 "File"), in three steps:
//
//  1. a transaction checks the secret and attaches a new file data key
//     (SecretKeys.NewDEKTx) and a fresh storage name (storage.NewName) to
//     its row, which marks the upload in progress: each attempt writes a
//     file of its own, so that the orphan sweep, which may remove the
//     file of an earlier failed attempt, never removes the file of a new
//     one (threat model T-360);
//  2. the body is streamed, outside any transaction, through the keyless
//     tte2.Validator of the declared size, encrypted at rest with that
//     key (the TTEF format of the transfer files, bound to the tenant and
//     the secret) into files at <tenant dir>/secrets/<storage name>, and
//     synced;
//  3. a transaction marks the file uploaded: a link secret becomes active
//     (its expiry starts at clock()), an e-mail secret stays pending until
//     [Secrets.ActivateForSend].
//
// It returns ErrNotFound for an unknown secret, another tenant's or
// another creator's; ErrSecretState for a secret that is not pending, has
// no declared file, has it already or is receiving it (a concurrent
// upload); ErrSecretFileFormat for a body that is not exactly a TTE2
// stream of the declared size. After a failure of step 2 or 3 the partial
// file is removed and the key detached and destroyed (the secret stays
// pending for a new attempt): the error then also matches
// ErrSecretUploadAborted and the caller scrubs the database. clock nil is
// the store clock.
func (r *Secrets) UploadFile(ctx context.Context, tid tenant.ID, secID string, actor SecretActor, files SecretFiles,
	body io.Reader, clock func() time.Time,
) (Secret, error) {
	if r.keys == nil {
		return Secret{}, errSecretNoKeys
	}
	if !id.Valid(id.Secret, secID) {
		return Secret{}, fmt.Errorf("store: upload secret file: %w", ErrNotFound)
	}
	if clock == nil {
		clock = r.db.now
	}
	var (
		row secretRow
		wk  string
		dek []byte
	)
	err := writeScoped(ctx, r.db, tid, "upload secret file", func(tx *ScopedTx) error {
		var err error
		row, wk, dek, err = r.beginUploadTx(ctx, tx, secID, actor)
		return err
	})
	if err != nil {
		return Secret{}, err
	}
	err = writeSecretFile(tid, secID, row.FileStorageName, row.FileSize, dek, files, body)
	clear(dek)
	if err == nil {
		var out Secret
		out, err = writeScopedValue(ctx, r.db, tid, "upload secret file", func(tx *ScopedTx) (Secret, error) {
			return r.completeUploadTx(ctx, tx, row, wk, clock().UTC().Truncate(time.Millisecond))
		})
		if err == nil {
			return out, nil
		}
	}
	return Secret{}, errors.Join(err, ErrSecretUploadAborted,
		r.abortUpload(context.WithoutCancel(ctx), tid, secID, row.FileStorageName, wk, files))
}

// beginUploadTx is step 1 of UploadFile: it returns the row (with the new
// storage name), the new key and its plaintext.
func (r *Secrets) beginUploadTx(ctx context.Context, tx *ScopedTx, secID string, actor SecretActor) (secretRow, string, []byte, error) {
	row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
	if err != nil {
		return secretRow{}, "", nil, err
	}
	if !actor.Owns(row.Secret) {
		return secretRow{}, "", nil, ErrNotFound
	}
	if row.State != SecretPending || row.FileSize == 0 || !row.FileUploadedAt.IsZero() || row.fileKeyID != "" {
		return secretRow{}, "", nil, ErrSecretState
	}
	wk, dek, err := r.keys.NewDEKTx(ctx, tx)
	if err != nil {
		return secretRow{}, "", nil, err
	}
	row.FileStorageName = storage.NewName()
	if err := execOne(ctx, tx, qSecretFileBegin, wk, row.FileStorageName, secID); err != nil {
		clear(dek)
		return secretRow{}, "", nil, err
	}
	return row, wk, dek, nil
}

// writeSecretFile is step 2 of UploadFile.
func writeSecretFile(tid tenant.ID, secID, name string, size int64, dek []byte, files SecretFiles, body io.Reader) error {
	v, err := tte2.NewValidator(size)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSecretFileFormat, err)
	}
	f, err := files.CreateSecretFile(tid, name)
	if err != nil {
		return err
	}
	w, err := crypto.NewWriter(f, dek, string(tid), secretFileBinding(secID))
	if err == nil {
		err = copySecretFile(w, body, v)
	}
	if err == nil {
		err = w.Close()
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(withoutPath(err), withoutPath(f.Close()))
}

// withoutPath replaces err, when its chain holds an *fs.PathError, by the
// cause of that error, so that no error of the store names a path of the
// data directory. err must be a single chain (not joined).
func withoutPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("store: secret file: %w", pe.Err)
	}
	return err
}

// copySecretFile copies body to dst through the validator v, which
// refuses a byte beyond the declared size; the body must end exactly at
// the declared size.
func copySecretFile(dst io.Writer, body io.Reader, v *tte2.Validator) error {
	buf := make([]byte, secretFileBufSize)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if err := v.Check(buf[:n]); err != nil {
				return fmt.Errorf("%w: %w", ErrSecretFileFormat, err)
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return err
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if !v.Complete() {
		return fmt.Errorf("%w: %d bytes received, %d declared", ErrSecretFileFormat, v.Offset(), v.DeclaredSize())
	}
	return nil
}

// completeUploadTx is step 3 of UploadFile.
func (r *Secrets) completeUploadTx(ctx context.Context, tx *ScopedTx, row secretRow, wk string, now time.Time) (Secret, error) {
	var err error
	if row.Delivery == SecretDeliveryLink {
		err = execOne(ctx, tx, qSecretFileDoneLink, toMillis(now), toMillis(now),
			toMillis(now.Add(row.Duration.Duration())), row.ID, wk)
	} else {
		err = execOne(ctx, tx, qSecretFileDoneEmail, toMillis(now), row.ID, wk)
	}
	if errors.Is(err, ErrNotFound) {
		// Deleted, purged or ended meanwhile.
		err = ErrSecretState
	}
	if err != nil {
		return Secret{}, err
	}
	after, err := scanSecret(tx.QueryRow(ctx, qSecretGet, row.ID), tx.Tenant())
	return after.Secret, err
}

// abortUpload removes the partial file of a failed upload, then detaches
// and destroys its key wk unless the row changed meanwhile.
func (r *Secrets) abortUpload(ctx context.Context, tid tenant.ID, secID, name, wk string, files SecretFiles) error {
	ferr := files.RemoveSecretFile(tid, name)
	err := writeScoped(ctx, r.db, tid, "abort secret file upload", func(tx *ScopedTx) error {
		n, err := execCount(ctx, tx, qSecretFileAbort, secID, wk)
		if err != nil || n == 0 {
			return err
		}
		return r.keys.DestroyTx(ctx, tx, wk)
	})
	return errors.Join(ferr, err)
}

// ActivateForSend activates, for its creator actor holding the secret
// token, the pending e-mail secret secID of tenant tid whose declared file,
// if any, is uploaded (the send call): activated at now (truncated to the
// millisecond), its expiry follows its duration. The SHA-256 of token is
// compared in constant time with the stored token hash; the token itself is
// neither stored nor logged. It returns ErrNotFound for an unknown secret,
// another tenant's, another creator's or a token that is not the secret's
// (checked in that order), and ErrSecretState for a link secret, a secret
// that is not pending or whose file is missing.
func (r *Secrets) ActivateForSend(ctx context.Context, tid tenant.ID, secID string, actor SecretActor, token string,
	now time.Time,
) (Secret, error) {
	if !id.Valid(id.Secret, secID) {
		return Secret{}, fmt.Errorf("store: activate secret: %w", ErrNotFound)
	}
	now = r.db.orNow(now).UTC().Truncate(time.Millisecond)
	return writeScopedValue(ctx, r.db, tid, "activate secret", func(tx *ScopedTx) (Secret, error) {
		row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
		if err != nil {
			return Secret{}, err
		}
		if !actor.Owns(row.Secret) {
			return Secret{}, ErrNotFound
		}
		var hash []byte
		if err := tx.QueryRow(ctx, qSecretTokenHash, secID).Scan(&hash); err != nil {
			return Secret{}, err
		}
		if subtle.ConstantTimeCompare(hash, id.HashToken(token)) != 1 {
			return Secret{}, ErrNotFound
		}
		err = execOne(ctx, tx, qSecretActivate, toMillis(now), toMillis(now.Add(row.Duration.Duration())), secID)
		if errors.Is(err, ErrNotFound) {
			err = ErrSecretState
		}
		if err != nil {
			return Secret{}, err
		}
		after, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
		return after.Secret, err
	})
}

// SecretFileDownload streams the file of a revealed secret: the TTE2
// ciphertext sent by the creator, decrypted from its at-rest layer. Close
// it once done.
type SecretFileDownload struct {
	// ID is the identifier of the secret.
	ID string
	// Size is the size of the stream (the declared ciphertext size).
	Size int64
	// Reader yields the stream; an error reports a damaged stored file.
	io.Reader
	file *os.File
}

// Close closes the stored file.
func (d *SecretFileDownload) Close() error { return d.file.Close() }

// OpenFile opens, for the holder of the one-time grant, the file of the
// read secret of tenant tid whose link carries token, at now. It returns
// ErrNotFound for a malformed or unknown token (or another tenant's),
// ErrSecretPending for a pending secret, and ErrSecretGrant (which wraps
// ErrNotFound) for a secret without grant (no file, already downloaded or
// swept) or a malformed, wrong or expired grant; the grant is compared in
// constant time. It consumes nothing: [Secrets.CompleteFileDownload] ends
// the grant once the stream was delivered completely.
func (r *Secrets) OpenFile(ctx context.Context, tid tenant.ID, token, grant string, files SecretFiles, now time.Time) (*SecretFileDownload, error) {
	if r.keys == nil {
		return nil, errSecretNoKeys
	}
	if !id.SecretTokenValid(token) {
		return nil, fmt.Errorf("store: open secret file: %w", ErrNotFound)
	}
	type opened struct {
		secID, name string
		size        int64
		dek         []byte
	}
	o, err := readScoped(ctx, r.db, tid, "open secret file", func(tx *ScopedTx) (opened, error) {
		var (
			o             opened
			state         string
			size, expires sql.NullInt64
			name, keyID   sql.NullString
			hash          []byte
		)
		err := tx.QueryRow(ctx, qSecretGrantByHash, id.HashToken(token)).Scan(&o.secID, &state, &size, &name, &keyID,
			&hash, &expires)
		switch {
		case err != nil:
			return o, err
		case SecretState(state) == SecretPending:
			return o, ErrSecretPending
		case hash == nil || !id.SecretGrantValid(grant) ||
			subtle.ConstantTimeCompare(hash, id.HashToken(grant)) != 1 || !nullMillis(expires).After(now):
			return o, ErrSecretGrant
		}
		o.name, o.size = name.String, size.Int64
		o.dek, err = r.keys.OpenTx(ctx, tx, crypto.PurposeDEK, keyID.String)
		return o, err
	})
	if err != nil {
		return nil, err
	}
	defer clear(o.dek)
	f, _, err := files.OpenSecretFile(tid, o.name)
	if err != nil {
		return nil, fmt.Errorf("store: open secret file: %w", err)
	}
	rd, err := crypto.NewReader(f, o.dek, string(tid), secretFileBinding(o.secID))
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("store: open secret file: %w", err)
	}
	return &SecretFileDownload{ID: o.secID, Size: o.size, Reader: rd, file: f}, nil
}

// CompleteFileDownload ends the one-time grant of the read secret secID
// of tenant tid after the first complete download of its file with grant:
// in one transaction, file_downloaded_at is set to now and the grant, the
// storage name and the file key are cleared, then the key is destroyed. It
// returns the tombstone with the file to remove, and false when the grant
// was already ended (a concurrent download completed first, or the sweep
// ran): nothing is changed then. The caller removes the file and scrubs
// the database.
func (r *Secrets) CompleteFileDownload(ctx context.Context, tid tenant.ID, secID, grant string, now time.Time) (EndedSecret, bool, error) {
	if r.keys == nil {
		return EndedSecret{}, false, errSecretNoKeys
	}
	var (
		out EndedSecret
		ok  bool
	)
	err := writeScoped(ctx, r.db, tid, "complete secret file download", func(tx *ScopedTx) error {
		row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
		if err != nil {
			return ignoreNotFound(err)
		}
		out, err = r.endTx(ctx, tx, row, qSecretGrantConsume, toMillis(now), secID, id.HashToken(grant))
		ok = err == nil
		return ignoreNotFound(err)
	})
	if err != nil || !ok {
		return EndedSecret{}, false, err
	}
	return out, true, nil
}

// ExpireGrants ends up to limit (1 to SecretSweepLimit) file grants of
// every tenant expired at or before now, without download, each in its own
// tenant transaction: the grant, the storage name and the file key are
// cleared, then the key is destroyed (secrets_grant_idx). It returns the
// tombstones with the files to remove and whether more may be due. A grant
// used meanwhile is skipped. The caller removes the files and scrubs the
// database.
func (r *Secrets) ExpireGrants(ctx context.Context, now time.Time, limit int) ([]EndedSecret, bool, error) {
	at := toMillis(now)
	return r.sweep(ctx, "expire secret file grants", qSecretDueGrant, limit, func(tx *ScopedTx, secID string) (EndedSecret, bool, error) {
		return r.sweepGrantTx(ctx, tx, secID, at)
	}, at)
}

// sweepGrantTx ends the grant of secID inside tx if it expired at or before
// at (milliseconds), reporting false when the row changed meanwhile.
func (r *Secrets) sweepGrantTx(ctx context.Context, tx *ScopedTx, secID string, at int64) (EndedSecret, bool, error) {
	row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
	if err != nil {
		return EndedSecret{}, false, ignoreNotFound(err)
	}
	e, err := r.endTx(ctx, tx, row, qSecretGrantExpire, secID, at)
	if err != nil {
		return EndedSecret{}, false, ignoreNotFound(err)
	}
	return e, true, nil
}

// MarkReceiptSent marks, at now, the read receipt of the secret secID of
// tenant tid as sent, atomically: only a secret asked with a receipt,
// ended as read, expired or locked, and whose receipt is not marked yet.
// It reports whether this call marked it, so that of concurrent callers
// exactly one sends the mail (T-366). A deleted secret is never marked.
func (r *Secrets) MarkReceiptSent(ctx context.Context, tid tenant.ID, secID string, now time.Time) (bool, error) {
	var n int64
	err := writeScoped(ctx, r.db, tid, "mark secret receipt", func(tx *ScopedTx) error {
		var err error
		n, err = execCount(ctx, tx, qSecretMarkReceipt, toMillis(r.db.orNow(now)), secID, true)
		return err
	})
	return n == 1, err
}

// SecretFileRefs returns the storage names of the secret files of tenant
// tid, each with whether its row still has the file key: a name absent
// from the map, or mapped to false, is an orphan file (unreadable). It
// reads at most MaxReconcileRows names and returns [ErrTooManyRows]
// beyond.
func (r *Secrets) SecretFileRefs(ctx context.Context, tid tenant.ID) (map[string]bool, error) {
	return readScoped(ctx, r.db, tid, "list secret storage names", func(tx *ScopedTx) (map[string]bool, error) {
		rows, err := tx.Query(ctx, qSecretFileRefs, r.db.reconcileRows+1)
		if err != nil {
			return nil, err
		}
		refs := make(map[string]bool)
		_, err = collect(rows, func(rs *sql.Rows) (struct{}, error) {
			var (
				name string
				key  sql.NullString
			)
			err := rs.Scan(&name, &key)
			refs[name] = key.Valid
			return struct{}{}, err
		})
		if err != nil {
			return nil, err
		}
		if len(refs) > r.db.reconcileRows {
			return nil, ErrTooManyRows
		}
		return refs, nil
	})
}

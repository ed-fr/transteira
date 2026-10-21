package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// reasonAntivirusSweep is the reason of the system query listing the
// transfers waiting for the antivirus across tenants.
const reasonAntivirusSweep = "antivirus sweep"

// MaxScanSignatureBytes bounds the name of a detected signature, in bytes.
const MaxScanSignatureBytes = 200

// ScanSweepLimit bounds the transfers returned by one
// [Transfers.ScanningSweep]. A transfer stays scanning until its analysis
// ends, so a caller that got ScanSweepLimit transfers sweeps again once it
// processed them.
const ScanSweepLimit = 1000

// Statements of the antivirus analysis and the download link. The sweep is
// the only system query: everything else stays tenant-scoped.
var (
	// qTransferMarkAvailable records the download link of a scanning
	// transfer, makes it available and restarts its expiry from now (the
	// CAST avoids an INTEGER overflow on PostgreSQL, as at finalization).
	qTransferMarkAvailable = tenantQuery(
		`UPDATE transfers SET status = 'available', download_token_hash = ?, download_token_key_id = ?, available_at = ?,
		expires_at = ? + expiry_days * CAST(86400000 AS BIGINT)
		WHERE tenant_id = ? AND id = ? AND status = 'scanning'`)
	qTransferGetByToken = tenantQuery(
		`SELECT ` + transferColumns + ` FROM transfers WHERE tenant_id = ? AND download_token_hash = ?`)
	// qTransferScanningSweep returns identifiers only, oldest finalization
	// first, bounded by ScanSweepLimit.
	qTransferScanningSweep = systemQuery(
		`SELECT tenant_id, id FROM transfers WHERE status = 'scanning' ORDER BY finalized_at, id LIMIT ?`,
		reasonAntivirusSweep)

	qFileSetScanning = tenantQuery(
		`UPDATE transfer_files SET scan_status = 'scanning'
		WHERE tenant_id = ? AND id = ? AND uploaded_at IS NOT NULL AND scan_status IN ('pending', 'scanning')`)
	qFileSetScanResult = tenantQuery(
		`UPDATE transfer_files SET scan_status = ?, scan_signature = ?, scanned_at = ?
		WHERE tenant_id = ? AND id = ? AND uploaded_at IS NOT NULL AND scan_status IN ('pending', 'scanning')`)
	qFileScanAttempt = tenantQuery(
		`UPDATE transfer_files SET scan_attempts = scan_attempts + 1
		WHERE tenant_id = ? AND id = ? AND scan_status IN ('pending', 'scanning') RETURNING scan_attempts`)
)

// TenantTransfer identifies a transfer and its tenant, as returned by the
// cross-tenant sweeps ([Transfers.ScanningSweep] and the cleanup sweeps):
// the caller reads the transfer in the scope of its tenant.
type TenantTransfer struct {
	// TenantID is the tenant of the transfer.
	TenantID tenant.ID
	// TransferID is the transfer ("trf_" + ULID).
	TransferID string
	// SortKey is the time the keyset-paginated sweeps order by (see
	// [SweepPage]), zero for the other listings.
	SortKey time.Time
}

// final reports whether s is a final scan status, recorded by
// [TransferFiles.SetScanResultTx].
func (s ScanStatus) final() bool {
	return s == ScanInfected || s == ScanError || s.Deliverable()
}

// Deliverable reports whether a file with the scan status s may be
// downloaded: ScanClean, ScanNotScannedTooLarge or ScanNotScannedEncrypted
// (the last two flagged as not scanned). Every other status is withheld:
// pending or scanning (not analyzed yet), infected (erased) and scan_error.
// It is the single rule shared by the antivirus worker, the mails and the
// download endpoints.
func (s ScanStatus) Deliverable() bool {
	switch s {
	case ScanClean, ScanNotScannedTooLarge, ScanNotScannedEncrypted:
		return true
	}
	return false
}

// MarkAvailableTx makes the scanning transfer trfID of the tenant tx is
// bound to available at now, inside tx, and records its download link. Its
// expiry restarts from now: ExpiresAt becomes now + ExpiryDays, replacing
// the provisional value set at finalization, so that the recipients get
// the whole chosen duration however long the analysis took. The link is:
// tokenHash is the SHA-256 (TokenHashSize bytes) of the "dl_" token, and
// tokenKeyID the wrapped key ("wk_" + ULID, purpose KeyPurposeSecret, same
// tenant) sealing the raw token, created in the same transaction.
//
// It returns ErrInvalid for a malformed value or a key that is not a
// secret, ErrNotFound when the transfer or the key does not exist (or
// belongs to another tenant), and ErrConflict when the transfer is not
// scanning or the token hash or the key is already used. After an error,
// the caller must abort the transaction.
func (r *Transfers) MarkAvailableTx(ctx context.Context, tx *ScopedTx, trfID string, tokenHash []byte, tokenKeyID string, now time.Time) error {
	if err := markAvailable(ctx, tx, trfID, tokenHash, tokenKeyID, now); err != nil {
		return wrap("mark transfer available", err)
	}
	return nil
}

// markAvailable implements MarkAvailableTx, returning raw errors.
func markAvailable(ctx context.Context, tx *ScopedTx, trfID string, tokenHash []byte, tokenKeyID string, now time.Time) error {
	if !validTokenHash(tokenHash) {
		return invalid("token hash must hold %d bytes", TokenHashSize)
	}
	if !id.Valid(id.WrappedKey, tokenKeyID) {
		return invalid("malformed token key id")
	}
	if err := checkKey(ctx, tx, tokenKeyID, KeyPurposeSecret, "token key is not a secret"); err != nil {
		return err
	}
	ms := toMillis(now)
	res, err := tx.Exec(ctx, qTransferMarkAvailable, tokenHash, tokenKeyID, ms, ms, trfID)
	if err == nil {
		err = expectOne(res)
	}
	if errors.Is(err, ErrNotFound) {
		return probe(ctx, tx, qTransferCount, trfID, ErrConflict)
	}
	return err
}

// MarkRejectedTx moves the scanning transfer trfID of the tenant tx is
// bound to to rejected, inside tx: every file was infected or could not be
// analyzed. EndedAt is set from the store's clock. It returns ErrNotFound when the transfer does not exist or
// belongs to another tenant, and ErrConflict when it is not scanning. After
// an error, the caller must abort the transaction.
func (r *Transfers) MarkRejectedTx(ctx context.Context, tx *ScopedTx, trfID string) error {
	if err := setStatus(ctx, tx, trfID, TransferScanning, TransferRejected, r.db.now()); err != nil {
		return wrap("mark transfer rejected", err)
	}
	return nil
}

// ScanningSweep returns the transfers of every tenant waiting for the
// antivirus (status scanning), oldest finalization first, at most
// ScanSweepLimit of them: the analysis worker resumes them at start-up. It
// is a system query (reason "antivirus sweep") and returns identifiers
// only; the caller reads each transfer in the scope of its tenant.
func (r *Transfers) ScanningSweep(ctx context.Context) ([]TenantTransfer, error) {
	var out []TenantTransfer
	err := r.db.systemScope(reasonAntivirusSweep).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qTransferScanningSweep, ScanSweepLimit)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (TenantTransfer, error) {
			var t TenantTransfer
			err := r.Scan(&t.TenantID, &t.TransferID)
			return t, err
		})
		return err
	})
	if err != nil {
		return nil, wrap("sweep scanning transfers", err)
	}
	return out, nil
}

// GetByDownloadTokenHash returns the transfer of tenant tid whose download
// token has the SHA-256 hash, with its recipients and files, in whatever
// state it is. It returns ErrNotFound when there is none, including for a
// transfer of another tenant, and ErrInvalid for a hash of the wrong size.
//
// The store applies no download rule: the caller must require Status
// TransferAvailable and now before ExpiresAt, serve only the files whose
// ScanStatus is Deliverable (an infected file has no data key left: its
// DEKKeyID reads ""), and never expose ScanSignature to recipients (it is
// shown to the sender only).
func (r *Transfers) GetByDownloadTokenHash(ctx context.Context, tid tenant.ID, hash []byte) (TransferDetails, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return TransferDetails{}, err
	}
	if !validTokenHash(hash) {
		return TransferDetails{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	return readScoped(ctx, r.db, tid, "get transfer by download token", func(tx *ScopedTx) (TransferDetails, error) {
		return details(ctx, tx, tx.QueryRow(ctx, qTransferGetByToken, hash))
	})
}

// SetScanningTx marks the file fileID of the tenant tx is bound to as being
// analyzed, inside tx. The upload of the file must be complete; a file
// already scanning stays so (resumption after a restart). It returns
// ErrNotFound when the file does not exist or belongs to another tenant,
// and ErrConflict when its upload is incomplete or its scan status is
// final. After an error, the caller must abort the transaction.
func (r *TransferFiles) SetScanningTx(ctx context.Context, tx *ScopedTx, fileID string) error {
	res, err := tx.Exec(ctx, qFileSetScanning, fileID)
	if err := conditional(ctx, tx, res, err, fileID); err != nil {
		return wrap("set file scanning", err)
	}
	return nil
}

// SetScanResultTx records, inside tx, the final scan status of the file
// fileID of the tenant tx is bound to at now: ScanClean, ScanInfected,
// ScanNotScannedTooLarge, ScanNotScannedEncrypted or ScanError. signature
// is the name of the detected signature, allowed for ScanInfected only (at
// most MaxScanSignatureBytes bytes of single-line text, "" when unknown).
// The file must be complete and pending or scanning.
//
// It returns ErrInvalid for a malformed value, ErrNotFound when the file
// does not exist or belongs to another tenant, and ErrConflict when its
// upload is incomplete or its scan status is already final. After an
// error, the caller must abort the transaction.
func (r *TransferFiles) SetScanResultTx(ctx context.Context, tx *ScopedTx, fileID string, status ScanStatus, signature string, now time.Time) error {
	if err := setScanResult(ctx, tx, fileID, status, signature, now); err != nil {
		return wrap("set scan result", err)
	}
	return nil
}

// setScanResult implements SetScanResultTx, returning raw errors.
func setScanResult(ctx context.Context, tx *ScopedTx, fileID string, status ScanStatus, signature string, now time.Time) error {
	switch {
	case !status.final():
		return invalid("scan result must be a final scan status")
	case signature != "" && status != ScanInfected:
		return invalid("only an infected file has a signature")
	case len(signature) > MaxScanSignatureBytes || !validText(signature, MaxScanSignatureBytes, true):
		return invalid("signature must be a line of at most %d bytes", MaxScanSignatureBytes)
	}
	res, err := tx.Exec(ctx, qFileSetScanResult, string(status), nullText(signature), toMillis(now), fileID)
	return conditional(ctx, tx, res, err, fileID)
}

// IncrementScanAttempt counts, in its own transaction, a file-specific
// analysis failure of the file fileID of tenant tid (inconsistent answer,
// decryption failure) and returns the new count: the worker gives up with
// ScanError after a few attempts. It returns ErrNotFound when the file
// does not exist or belongs to another tenant, and ErrConflict when its
// scan status is already final.
func (r *TransferFiles) IncrementScanAttempt(ctx context.Context, tid tenant.ID, fileID string) (int, error) {
	var n int
	err := writeScoped(ctx, r.db, tid, "count scan attempt", func(tx *ScopedTx) error {
		err := tx.QueryRow(ctx, qFileScanAttempt, fileID).Scan(&n)
		if errors.Is(err, ErrNotFound) {
			return probe(ctx, tx, qFileCount, fileID, ErrConflict)
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TransferStatus is the life-cycle state of a transfer (OpenAPI
// TransferStatus).
type TransferStatus string

// Transfer statuses: uploading -> scanning -> available -> expired |
// deleted; rejected when every file was infected or blocklisted. An
// available transfer deleted after its first download goes through
// [Transfers.MarkDeletedTx].
const (
	// TransferUploading is a declared transfer whose files are being sent.
	TransferUploading TransferStatus = "uploading"
	// TransferScanning is a finalized transfer waiting for the antivirus.
	TransferScanning TransferStatus = "scanning"
	// TransferAvailable is a transfer its recipients can download.
	TransferAvailable TransferStatus = "available"
	// TransferRejected is a transfer whose files were all rejected.
	TransferRejected TransferStatus = "rejected"
	// TransferExpired is a transfer past its expiry.
	TransferExpired TransferStatus = "expired"
	// TransferDeleted is a transfer deleted before its expiry.
	TransferDeleted TransferStatus = "deleted"
)

// valid reports whether s is a known transfer status.
func (s TransferStatus) valid() bool {
	switch s {
	case TransferUploading, TransferScanning, TransferAvailable, TransferRejected, TransferExpired, TransferDeleted:
		return true
	}
	return false
}

// ScanStatus is the antivirus state of a file (OpenAPI ScanStatus).
type ScanStatus string

// Scan statuses.
const (
	// ScanPending is a file not analyzed yet (the initial state).
	ScanPending ScanStatus = "pending"
	// ScanScanning is a file being analyzed.
	ScanScanning ScanStatus = "scanning"
	// ScanClean is a file found clean.
	ScanClean ScanStatus = "clean"
	// ScanInfected is a file found infected (deleted).
	ScanInfected ScanStatus = "infected"
	// ScanNotScannedTooLarge is a file above the antivirus limits,
	// accepted and flagged.
	ScanNotScannedTooLarge ScanStatus = "not_scanned_too_large"
	// ScanNotScannedEncrypted is a file the antivirus could not look
	// inside (encrypted archive), accepted and flagged.
	ScanNotScannedEncrypted ScanStatus = "not_scanned_encrypted"
	// ScanError is a file that could not be analyzed (withheld).
	ScanError ScanStatus = "scan_error"
)

// Limits of the transfer fields, as the OpenAPI specification declares
// them (TransferCreate, FileDeclaration and the Idempotency-Key header).
const (
	// MaxTransferMessageLen bounds the message of a transfer, in
	// characters.
	MaxTransferMessageLen = 5000
	// MaxTransferRecipients bounds the recipients of a transfer.
	MaxTransferRecipients = 100
	// MaxTransferFiles bounds the files of a transfer.
	MaxTransferFiles = 1000
	// MaxFileNameBytes bounds the original name of a file, in bytes.
	MaxFileNameBytes = 255
	// MaxMediaTypeLen bounds the informational media type of a file, in
	// characters.
	MaxMediaTypeLen = 255
	// MaxIdempotencyKeyLen bounds an idempotency key, in bytes.
	MaxIdempotencyKeyLen = 64
	// MaxPasswordHashLen bounds the PHC string of a transfer password.
	MaxPasswordHashLen = 512
	// StorageNameLen is the length of a storage name: 128 random bits in
	// lowercase hexadecimal.
	StorageNameLen = 32
)

// IdempotencyRetention is how long an idempotency key identifies the
// transfer created with it (24 hours). [Transfers.CreateTx] releases an
// older key of the same sender before reusing it.
const IdempotencyRetention = 24 * time.Hour

// transferColumns is the column list read by the transfer queries.
const transferColumns = `id, status, sender_email, sender_kind, invitation_id, message, language, expiry_days, ` +
	`password_hash, delete_after_first_download, total_bytes, idempotency_key, request_fingerprint, created_at, ` +
	`finalized_at, download_token_hash, download_token_key_id, available_at, expires_at, first_downloaded_at, delete_after, ` +
	`ended_at, sender_ip, download_count`

// reasonTransferTenantActive is the review of qTransferTenantActive: the
// tenant slot filters transfers, and the join reads the tenants row of the
// same tenant only (n.id = t.tenant_id); on PostgreSQL the tenants policy
// also restricts a tenant scope to its own row.
const reasonTransferTenantActive = "transfer creation: refuse a tenant whose deletion started (same tenant row only)"

// fileColumns is the column list read by the file queries.
const fileColumns = `id, transfer_id, position, name, size, media_type, expected_sha256, sha256, dek_key_id, ` +
	`storage_name, upload_id, ciphertext_size, uploaded_at, scanned_at, scan_signature, scan_attempts, scan_status`

// Statements of the Transfers and TransferFiles repositories. All of them
// are single-table tenant queries: a transfer and its files are read with
// separate statements of the same transaction.
var (
	qTransferInsert = tenantQuery(
		`INSERT INTO transfers (tenant_id, id, status, sender_email, sender_kind, invitation_id, message, language,
		expiry_days, password_hash, delete_after_first_download, total_bytes, idempotency_key, request_fingerprint,
		created_at, sender_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	// qTransferReleaseKey clears an idempotency key of the sender older
	// than the retention, so that the key can be reused.
	qTransferReleaseKey = tenantQuery(
		`UPDATE transfers SET idempotency_key = NULL
		WHERE tenant_id = ? AND sender_email = ? AND idempotency_key = ? AND created_at < ?`)
	qTransferGet = tenantQuery(
		`SELECT ` + transferColumns + ` FROM transfers WHERE tenant_id = ? AND id = ?`)
	qTransferGetByKey = tenantQuery(
		`SELECT ` + transferColumns + ` FROM transfers
		WHERE tenant_id = ? AND sender_email = ? AND idempotency_key = ? AND created_at >= ?`)
	qTransferCount = tenantQuery(
		`SELECT count(*) FROM transfers WHERE tenant_id = ? AND id = ?`)
	// qTransferCountUploading counts the open transfers of a sender created
	// since a time.
	qTransferCountUploading = tenantQuery(
		`SELECT count(*) FROM transfers
		WHERE tenant_id = ? AND sender_email = ? AND status = 'uploading' AND created_at >= ?`)
	// qTransferListUploading lists them, newest first, up to a limit.
	qTransferListUploading = tenantQuery(
		`SELECT ` + transferColumns + ` FROM transfers
		WHERE tenant_id = ? AND sender_email = ? AND status = 'uploading' AND created_at >= ?
		ORDER BY created_at DESC, id DESC LIMIT ?`)
	// qTransferUsedBytes sums the declared sizes held against the quota.
	// The CAST keeps an integer result on PostgreSQL (sum of BIGINT is
	// NUMERIC).
	qTransferUsedBytes = tenantQuery(
		`SELECT CAST(COALESCE(sum(total_bytes), 0) AS BIGINT) FROM transfers
		WHERE tenant_id = ? AND status IN ('uploading', 'scanning', 'available')`)
	// qTransferSetStatus moves a transfer to a terminal status (every
	// target but the finalization's) and records when it first ended. The
	// sealed download token must be destroyed first (T-110); the store
	// checks the file keys beforehand.
	qTransferSetStatus = tenantQuery(
		`UPDATE transfers SET status = ?, ended_at = COALESCE(ended_at, ?)
		WHERE tenant_id = ? AND id = ? AND status = ? AND download_token_key_id IS NULL`)
	// qTransferFinalize moves an uploading transfer to scanning and sets
	// its finalization and expiry times (the CAST avoids an INTEGER
	// overflow of expiry_days * milliseconds on PostgreSQL).
	qTransferFinalize = tenantQuery(
		`UPDATE transfers SET status = 'scanning', finalized_at = ?, expires_at = ? + expiry_days * CAST(86400000 AS BIGINT)
		WHERE tenant_id = ? AND id = ? AND status = 'uploading'`)
	qTransferShrink = tenantQuery(
		`UPDATE transfers SET total_bytes = total_bytes - ? WHERE tenant_id = ? AND id = ?`)
	// qTransferDelete only deletes a transfer whose sealed download token
	// was destroyed first (T-110).
	qTransferDelete = tenantQuery(
		`DELETE FROM transfers WHERE tenant_id = ? AND id = ? AND download_token_key_id IS NULL`)
	// qTransferTenantActive counts the transfer just inserted when its
	// tenant is still active: a creation that resolved the tenant before
	// its deletion started finds 0 and is rolled back, so that no row (and
	// no file) appears in a tenant being erased.
	qTransferTenantActive = reviewedTenantQuery(
		`SELECT count(*) FROM transfers t JOIN tenants n ON n.id = t.tenant_id
		WHERE t.tenant_id = ? AND t.id = ? AND n.status = 'active'`,
		reasonTransferTenantActive)

	qRecipientInsert = tenantQuery(
		`INSERT INTO transfer_recipients (tenant_id, transfer_id, position, email) VALUES (?, ?, ?, ?)`)
	qRecipientList = tenantQuery(
		`SELECT email FROM transfer_recipients WHERE tenant_id = ? AND transfer_id = ? ORDER BY position`)

	qFileInsert = tenantQuery(
		`INSERT INTO transfer_files (tenant_id, id, transfer_id, position, name, size, media_type, expected_sha256,
		sha256, dek_key_id, storage_name, upload_id, ciphertext_size, uploaded_at, scan_status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	qFileList = tenantQuery(
		`SELECT ` + fileColumns + ` FROM transfer_files WHERE tenant_id = ? AND transfer_id = ? ORDER BY position`)
	qFileGetByUpload = tenantQuery(
		`SELECT ` + fileColumns + ` FROM transfer_files WHERE tenant_id = ? AND upload_id = ?`)
	qFileCount = tenantQuery(
		`SELECT count(*) FROM transfer_files WHERE tenant_id = ? AND id = ?`)
	qFileCountKeyed = tenantQuery(
		`SELECT count(*) FROM transfer_files WHERE tenant_id = ? AND transfer_id = ? AND dek_key_id IS NOT NULL`)
	qFileComplete = tenantQuery(
		`UPDATE transfer_files SET sha256 = ?, ciphertext_size = ?, uploaded_at = ?
		WHERE tenant_id = ? AND id = ? AND uploaded_at IS NULL`)
	qFileReplaceDEK = tenantQuery(
		`UPDATE transfer_files SET dek_key_id = ?, storage_name = ?
		WHERE tenant_id = ? AND id = ? AND uploaded_at IS NULL`)
	// qFileDelete only deletes a file whose data key was destroyed first
	// (T-110), and returns what the transfer total must lose.
	qFileDelete = tenantQuery(
		`DELETE FROM transfer_files WHERE tenant_id = ? AND id = ? AND dek_key_id IS NULL RETURNING transfer_id, size`)
)

// Transfer is a deposit: a sender, recipients and files (spec 8.2). The
// store keeps its metadata only; the files are on disk, encrypted.
type Transfer struct {
	// ID is the identifier ("trf_" + ULID), assigned by the caller.
	ID string
	// Status is the life-cycle state; a new transfer is TransferUploading
	// (the zero value is accepted at creation).
	Status TransferStatus
	// SenderEmail is the verified address of the sender, normalized by the
	// store.
	SenderEmail string
	// SenderKind tells how the sender was allowed to deposit.
	SenderKind DepositorKind
	// InvitationID is the invitation of an external sender ("inv_" + ULID,
	// same tenant), "" for an internal one.
	InvitationID string
	// Message is the optional plain-text message (at most
	// MaxTransferMessageLen characters), sanitized by the caller.
	Message string
	// Language is the language of the mails, "" for the tenant default.
	Language string
	// ExpiryDays is the validity chosen by the sender: 1, 7 or 30 days,
	// counted from the finalization.
	ExpiryDays int
	// PasswordHash is the PHC string of the transfer password (argon2id),
	// "" without password. It is opaque to the store.
	PasswordHash string
	// DeleteAfterFirstDownload deletes the transfer after its first
	// download.
	DeleteAfterFirstDownload bool
	// TotalBytes is the sum of the declared sizes of the files. The store
	// computes it at creation (a non-zero value must match) and keeps it up
	// to date when a file is deleted.
	TotalBytes int64
	// IdempotencyKey is the Idempotency-Key of the creation request, ""
	// when none was given. It identifies the transfer for
	// IdempotencyRetention.
	IdempotencyKey string
	// RequestFingerprint is the SHA-256 (64 lowercase hex characters) of
	// the canonical creation request, computed by the caller and kept with
	// the idempotency key so that a replay with another body is refused; ""
	// when none.
	RequestFingerprint string
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// FinalizedAt is the finalization time, zero before.
	FinalizedAt time.Time
	// ExpiresAt is the expiry, zero before the finalization. The
	// finalization sets a provisional value (FinalizedAt + ExpiryDays);
	// [Transfers.MarkAvailableTx] replaces it with AvailableAt +
	// ExpiryDays, so that the recipients get the whole chosen duration. The
	// provisional value of a transfer still scanning is never enforced: the
	// validity starts when the transfer becomes available, and the expiry
	// sweep ([Transfers.DueExpirations]) bounds a stuck analysis on
	// FinalizedAt instead (ScanningMaxAge).
	ExpiresAt time.Time
	// DownloadTokenHash is the SHA-256 (TokenHashSize bytes) of the
	// download link token, set by [Transfers.MarkAvailableTx]; nil before.
	DownloadTokenHash []byte
	// DownloadTokenKeyID is the wrapped key ("wk_" + ULID, purpose
	// KeyPurposeSecret, same tenant) holding the raw download token sealed by
	// the key vault, set by [Transfers.MarkAvailableTx]. It reads "" before,
	// and once the key was destroyed (cryptographic erasure).
	DownloadTokenKeyID string
	// AvailableAt is when the analysis made the transfer available, zero
	// before.
	AvailableAt time.Time
	// FirstDownloadedAt is when the transfer was downloaded completely for
	// the first time ([Transfers.MarkFirstDownloadTx]), zero before.
	FirstDownloadedAt time.Time
	// DeleteAfter is when a transfer with DeleteAfterFirstDownload becomes
	// due for deletion ([Transfers.DueDeletions]), set with
	// FirstDownloadedAt; zero otherwise.
	DeleteAfter time.Time
	// EndedAt is when the transfer first reached a terminal status
	// (rejected, expired or deleted), zero before. The cleanup task deletes
	// its rows EndedAt + 30 days ([Transfers.ListEnded]).
	EndedAt time.Time
	// SenderIP is the client IP of the sender when the transfer was
	// created (an IPv4-mapped address is stored as IPv4), set at creation;
	// the zero Addr when unknown (transfers created before the column
	// existed, or created without one).
	SenderIP netip.Addr
	// DownloadCount counts the download starts of a file or of the archive
	// ([Transfers.IncrementDownloadsTx]); 0 for a new transfer.
	DownloadCount int64
}

// PasswordProtected reports whether the transfer has a password.
func (t Transfer) PasswordProtected() bool { return t.PasswordHash != "" }

// TransferFile is a file of a transfer.
type TransferFile struct {
	// ID is the identifier ("fil_" + ULID), assigned by the caller.
	ID string
	// TransferID is the transfer of the file; [Transfers.CreateTx] sets it
	// (a non-empty value must match the transfer).
	TransferID string
	// Position is the rank of the file in the transfer, from 0;
	// [Transfers.CreateTx] assigns it from the order of the files.
	Position int
	// Name is the original name (1 to MaxFileNameBytes bytes of UTF-8,
	// without control characters), sanitized by the caller. It is never
	// used on disk.
	Name string
	// Size is the declared size of the clear file, in bytes.
	Size int64
	// MediaType is the informational media type, "" when unknown.
	MediaType string
	// ExpectedSHA256 is the SHA-256 announced by the sender (64 lowercase
	// hex characters), "" when none was given.
	ExpectedSHA256 string
	// SHA256 is the SHA-256 of the clear file, computed during the upload;
	// "" until the upload completes.
	SHA256 string
	// DEKKeyID is the wrapped data key of the file ("wk_" + ULID, purpose
	// KeyPurposeDEK, same tenant). It reads "" once the key was destroyed
	// (cryptographic erasure).
	DEKKeyID string
	// StorageName is the random name of the encrypted file on disk
	// (StorageNameLen lowercase hex characters).
	StorageName string
	// UploadID is the tus upload identifier ("upl_" + base62, see
	// id.NewUploadToken).
	UploadID string
	// CiphertextSize is the size of the encrypted file once the upload
	// completed, 0 before.
	CiphertextSize int64
	// UploadedAt is when the upload completed, zero before.
	UploadedAt time.Time
	// ScanStatus is the antivirus state; a new file is ScanPending (the
	// zero value is accepted at creation).
	ScanStatus ScanStatus
	// ScannedAt is when the final scan status was recorded
	// ([TransferFiles.SetScanResultTx]), zero while pending or scanning.
	ScannedAt time.Time
	// ScanSignature is the name of the signature detected in an infected
	// file (at most MaxScanSignatureBytes bytes), "" otherwise. It is shown
	// to the sender only, escaped.
	ScanSignature string
	// ScanAttempts counts the file-specific analysis failures
	// ([TransferFiles.IncrementScanAttempt]); 0 for a new file.
	ScanAttempts int
}

// Completed reports whether the upload of the file is complete.
func (f TransferFile) Completed() bool { return !f.UploadedAt.IsZero() }

// TransferDetails is a transfer with its recipients (in the sender's
// order) and its files (by position).
type TransferDetails struct {
	Transfer
	// Recipients are the normalized recipient addresses.
	Recipients []string
	// Files are the files, by position.
	Files []TransferFile
}

// FileUpload is a file looked up by its upload identifier, with the
// transfer it belongs to (the upload endpoints check the sender, the
// invitation and the status of the transfer).
type FileUpload struct {
	// File is the file.
	File TransferFile
	// Transfer is its transfer (without recipients or files).
	Transfer Transfer
}

// Transfers is the tenant-scoped repository of transfers and their
// recipients. Obtain it with [DB.Transfers].
//
// Every row deletion follows the cryptographic erasure rule (spec 16.1,
// T-110): the caller destroys the data key of each file first
// ([WrappedKeys.DeleteTx], which leaves the file without key), then
// deletes the rows; the store refuses to delete a file whose key still
// exists ([ErrKeysRemain]).
type Transfers struct {
	db *DB
}

// Transfers returns the transfer repository.
func (db *DB) Transfers() *Transfers { return &Transfers{db: db} }

// TransferFiles is the tenant-scoped repository of the files of transfers.
// Obtain it with [DB.TransferFiles].
type TransferFiles struct {
	db *DB
}

// TransferFiles returns the transfer file repository.
func (db *DB) TransferFiles() *TransferFiles { return &TransferFiles{db: db} }

// isLowerHex reports whether s holds exactly n lowercase hexadecimal
// characters.
func isLowerHex(s string, n int) bool {
	return len(s) == n && strings.Trim(s, "0123456789abcdef") == ""
}

// isPrintableASCII reports whether s holds 1 to maxLen visible ASCII
// characters (no space or control character).
func isPrintableASCII(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// validIdempotencyKey reports whether k is an acceptable idempotency key.
func validIdempotencyKey(k string) bool {
	return isPrintableASCII(k, MaxIdempotencyKeyLen)
}

// validFileName is the store's cheap guard on a file name: the caller
// sanitizes names (normalization, bidirectional and invisible characters,
// path separators, reserved names).
func validFileName(s string) bool {
	return s != "" && len(s) <= MaxFileNameBytes && utf8.ValidString(s) && !strings.ContainsFunc(s, isLineBreakOrControl)
}

// validExpiryDays reports whether d is an allowed validity (spec 8.2).
func validExpiryDays(d int) bool {
	return d == 1 || d == 7 || d == 30
}

// normalizeTransfer validates t for creation and returns it normalized,
// with its status and total.
func normalizeTransfer(t Transfer, total int64) (Transfer, error) {
	email, err := NormalizeEmail(t.SenderEmail)
	if err != nil {
		return Transfer{}, err
	}
	t.SenderEmail = email
	switch {
	case !id.Valid(id.Transfer, t.ID):
		return Transfer{}, invalid("malformed transfer id")
	case t.Status != "" && t.Status != TransferUploading:
		return Transfer{}, invalid("a new transfer must be uploading")
	case t.SenderKind != DepositorInternal && t.SenderKind != DepositorExternal:
		return Transfer{}, invalid("unknown sender kind")
	case (t.SenderKind == DepositorExternal) != (t.InvitationID != ""):
		return Transfer{}, invalid("an external sender needs an invitation, an internal one none")
	case t.InvitationID != "" && !id.Valid(id.Invitation, t.InvitationID):
		return Transfer{}, invalid("malformed invitation id")
	case !validText(t.Message, MaxTransferMessageLen, false):
		return Transfer{}, invalid("message must be text of at most %d characters", MaxTransferMessageLen)
	case t.Language != "" && !tenant.IsLanguage(t.Language):
		return Transfer{}, invalid("unsupported language")
	case !validExpiryDays(t.ExpiryDays):
		return Transfer{}, invalid("expiry must be 1, 7 or 30 days")
	case t.PasswordHash != "" && (t.PasswordHash[0] != '$' || !isPrintableASCII(t.PasswordHash, MaxPasswordHashLen)):
		return Transfer{}, invalid("password hash must be a PHC string")
	case t.TotalBytes != 0 && t.TotalBytes != total:
		return Transfer{}, invalid("total bytes must be the sum of the file sizes")
	case t.IdempotencyKey != "" && !validIdempotencyKey(t.IdempotencyKey):
		return Transfer{}, invalid("idempotency key must hold 1 to %d visible ASCII characters", MaxIdempotencyKeyLen)
	case t.RequestFingerprint != "" && !isLowerHex(t.RequestFingerprint, sha256HexLen):
		return Transfer{}, invalid("malformed request fingerprint")
	case !t.FinalizedAt.IsZero() || !t.ExpiresAt.IsZero():
		return Transfer{}, invalid("a new transfer cannot be finalized")
	case t.DownloadTokenHash != nil || t.DownloadTokenKeyID != "" || !t.AvailableAt.IsZero():
		return Transfer{}, invalid("a new transfer cannot be available")
	case !t.FirstDownloadedAt.IsZero() || !t.DeleteAfter.IsZero():
		return Transfer{}, invalid("a new transfer cannot be downloaded")
	case !t.EndedAt.IsZero():
		return Transfer{}, invalid("a new transfer cannot be ended")
	case t.DownloadCount != 0:
		return Transfer{}, invalid("a new transfer cannot be downloaded")
	}
	t.Status, t.TotalBytes = TransferUploading, total
	if t.SenderIP.IsValid() {
		t.SenderIP = t.SenderIP.Unmap().WithZone("")
	}
	return t, nil
}

// normalizeRecipients validates and normalizes the recipient addresses.
func normalizeRecipients(recipients []string) ([]string, error) {
	if len(recipients) == 0 || len(recipients) > MaxTransferRecipients {
		return nil, invalid("a transfer needs 1 to %d recipients", MaxTransferRecipients)
	}
	out := make([]string, len(recipients))
	seen := make(map[string]bool, len(recipients))
	for i, r := range recipients {
		email, err := NormalizeEmail(r)
		if err != nil {
			return nil, err
		}
		if seen[email] {
			return nil, invalid("duplicate recipient")
		}
		seen[email] = true
		out[i] = email
	}
	return out, nil
}

// normalizeFile validates f, the file at position pos of the transfer
// trfID, and returns it with its transfer, position and scan status set.
func normalizeFile(f TransferFile, trfID string, pos int) (TransferFile, error) {
	switch {
	case !id.Valid(id.File, f.ID):
		return TransferFile{}, invalid("malformed file id")
	case f.TransferID != "" && f.TransferID != trfID:
		return TransferFile{}, invalid("file belongs to another transfer")
	case !validFileName(f.Name):
		return TransferFile{}, invalid("file name must hold 1 to %d bytes of text without control characters", MaxFileNameBytes)
	case f.Size < 0:
		return TransferFile{}, invalid("file size must not be negative")
	case !validText(f.MediaType, MaxMediaTypeLen, true):
		return TransferFile{}, invalid("media type must be a line of at most %d characters", MaxMediaTypeLen)
	case f.ExpectedSHA256 != "" && !isLowerHex(f.ExpectedSHA256, sha256HexLen):
		return TransferFile{}, invalid("malformed expected sha256")
	case !id.Valid(id.WrappedKey, f.DEKKeyID):
		return TransferFile{}, invalid("malformed data key id")
	case !isLowerHex(f.StorageName, StorageNameLen):
		return TransferFile{}, invalid("malformed storage name")
	case !id.UploadTokenValid(f.UploadID):
		return TransferFile{}, invalid("malformed upload id")
	case f.ScanStatus != "" && f.ScanStatus != ScanPending:
		return TransferFile{}, invalid("a new file must be pending analysis")
	case !f.ScannedAt.IsZero() || f.ScanSignature != "" || f.ScanAttempts != 0:
		return TransferFile{}, invalid("a new file has no scan result")
	case f.Completed() && (!isLowerHex(f.SHA256, sha256HexLen) || f.CiphertextSize < 0):
		return TransferFile{}, invalid("a completed file needs its sha256 and ciphertext size")
	case !f.Completed() && (f.SHA256 != "" || f.CiphertextSize != 0):
		return TransferFile{}, invalid("an incomplete file has no sha256 or ciphertext size")
	}
	f.TransferID, f.Position, f.ScanStatus = trfID, pos, ScanPending
	return f, nil
}

// checkDEK verifies, inside tx, that keyID is a data key of the tenant tx
// is bound to: the foreign key only proves that the key exists, the
// tenant-scoped read proves it belongs to this tenant.
func checkDEK(ctx context.Context, tx *ScopedTx, keyID string) error {
	return checkKey(ctx, tx, keyID, KeyPurposeDEK, "file key is not a data key")
}

// checkKey verifies, inside tx, that keyID is a wrapped key of purpose
// purpose of the tenant tx is bound to; msg describes a purpose mismatch.
func checkKey(ctx context.Context, tx *ScopedTx, keyID, purpose, msg string) error {
	k, err := scanWrappedKey(tx.QueryRow(ctx, qWrappedKeyGet, keyID))
	if err != nil {
		return err
	}
	if k.Purpose != purpose {
		return invalid("%s", msg)
	}
	return nil
}

// CreateTx stores the new transfer t, its recipients (in order) and its
// files (positions assigned from their order) for the tenant tx is bound
// to, inside tx: the creation transaction also checks the quota
// ([Transfers.UsedBytesTx]) and creates the data key of each file
// ([WrappedKeys.CreateTx]) beforehand. Addresses are normalized.
//
// It returns ErrInvalid for a malformed field (1 to MaxTransferRecipients
// distinct recipients and 1 to MaxTransferFiles files are required; a file
// may be created completed, such as an empty file), ErrNotFound when the
// tenant is not active (its deletion started: checked under the tenant
// lock, in the same transaction as the inserts), or when the invitation or
// a data key does not exist (or belongs to another tenant), and ErrConflict when an identifier, an upload
// identifier, a storage name or a data key is already used, or when the
// sender used the idempotency key for another transfer within
// IdempotencyRetention of t.CreatedAt (a key older than that is released
// first). After an error, the caller must abort the transaction.
func (r *Transfers) CreateTx(ctx context.Context, tx *ScopedTx, t Transfer, recipients []string, files []TransferFile) error {
	if err := r.create(ctx, tx, t, recipients, files); err != nil {
		return wrap("create transfer", err)
	}
	return nil
}

// create validates and inserts a transfer in tx, returning raw errors.
func (r *Transfers) create(ctx context.Context, tx *ScopedTx, t Transfer, recipients []string, files []TransferFile) error {
	if len(files) == 0 || len(files) > MaxTransferFiles {
		return invalid("a transfer needs 1 to %d files", MaxTransferFiles)
	}
	fs := make([]TransferFile, len(files))
	var total int64
	for i, f := range files {
		var err error
		if fs[i], err = normalizeFile(f, t.ID, i); err != nil {
			return err
		}
		if f.Size > math.MaxInt64-total {
			return invalid("total size overflows")
		}
		total += f.Size
	}
	t, err := normalizeTransfer(t, total)
	if err != nil {
		return err
	}
	rcpts, err := normalizeRecipients(recipients)
	if err != nil {
		return err
	}
	// The tenant lock orders the creation with the start of a deletion
	// (Tenants.SetStatus takes it too), so that the status read below is
	// final until the commit.
	if err := tx.lock(ctx); err != nil {
		return err
	}
	created := r.db.orNow(t.CreatedAt)
	if t.IdempotencyKey != "" {
		_, err := tx.Exec(ctx, qTransferReleaseKey, t.SenderEmail, t.IdempotencyKey,
			toMillis(created.Add(-IdempotencyRetention)))
		if err != nil {
			return err
		}
	}
	var senderIP any
	if t.SenderIP.IsValid() {
		senderIP = t.SenderIP.String()
	}
	_, err = tx.Exec(ctx, qTransferInsert, t.ID, string(t.Status), t.SenderEmail, string(t.SenderKind),
		nullText(t.InvitationID), t.Message, t.Language, t.ExpiryDays, nullText(t.PasswordHash),
		t.DeleteAfterFirstDownload, t.TotalBytes, nullText(t.IdempotencyKey), nullText(t.RequestFingerprint),
		toMillis(created), senderIP)
	if err != nil {
		return err
	}
	var active int
	if err := tx.QueryRow(ctx, qTransferTenantActive, t.ID).Scan(&active); err != nil {
		return err
	}
	if active == 0 {
		return ErrNotFound
	}
	for i, email := range rcpts {
		if _, err := tx.Exec(ctx, qRecipientInsert, t.ID, i, email); err != nil {
			return err
		}
	}
	for _, f := range fs {
		if err := checkDEK(ctx, tx, f.DEKKeyID); err != nil {
			return err
		}
		var uploaded, ctSize any
		if f.Completed() {
			uploaded, ctSize = toMillis(f.UploadedAt), f.CiphertextSize
		}
		_, err := tx.Exec(ctx, qFileInsert, f.ID, f.TransferID, f.Position, f.Name, f.Size, f.MediaType,
			nullText(f.ExpectedSHA256), nullText(f.SHA256), f.DEKKeyID, f.StorageName, f.UploadID, ctSize,
			uploaded, string(f.ScanStatus))
		if err != nil {
			return err
		}
	}
	return nil
}

// scanTransfer reads one row of transferColumns.
func scanTransfer(row interface{ Scan(...any) error }) (Transfer, error) {
	var (
		t                                Transfer
		status, kind                     string
		inv, pwd, key, fp, tokenKey, ip  sql.NullString
		created                          int64
		finalized, available, expiration sql.NullInt64
		downloaded, deleteAfter, ended   sql.NullInt64
	)
	err := row.Scan(&t.ID, &status, &t.SenderEmail, &kind, &inv, &t.Message, &t.Language, &t.ExpiryDays,
		&pwd, &t.DeleteAfterFirstDownload, &t.TotalBytes, &key, &fp, &created, &finalized, &t.DownloadTokenHash,
		&tokenKey, &available, &expiration, &downloaded, &deleteAfter, &ended, &ip, &t.DownloadCount)
	if err != nil {
		return Transfer{}, err
	}
	t.Status, t.SenderKind = TransferStatus(status), DepositorKind(kind)
	t.InvitationID, t.PasswordHash, t.IdempotencyKey, t.RequestFingerprint = inv.String, pwd.String, key.String, fp.String
	t.CreatedAt, t.FinalizedAt, t.ExpiresAt = fromMillis(created), nullMillis(finalized), nullMillis(expiration)
	t.DownloadTokenKeyID, t.AvailableAt = tokenKey.String, nullMillis(available)
	t.FirstDownloadedAt, t.DeleteAfter, t.EndedAt = nullMillis(downloaded), nullMillis(deleteAfter), nullMillis(ended)
	t.SenderIP = parseIP(ip.String)
	return t, nil
}

// scanFile reads one row of fileColumns.
func scanFile(row interface{ Scan(...any) error }) (TransferFile, error) {
	var (
		f                               TransferFile
		expected, sum, keyID, signature sql.NullString
		ctSize, uploaded, scanned       sql.NullInt64
		scan                            string
	)
	err := row.Scan(&f.ID, &f.TransferID, &f.Position, &f.Name, &f.Size, &f.MediaType, &expected, &sum, &keyID,
		&f.StorageName, &f.UploadID, &ctSize, &uploaded, &scanned, &signature, &f.ScanAttempts, &scan)
	if err != nil {
		return TransferFile{}, err
	}
	f.ExpectedSHA256, f.SHA256, f.DEKKeyID = expected.String, sum.String, keyID.String
	f.CiphertextSize, f.UploadedAt, f.ScanStatus = ctSize.Int64, nullMillis(uploaded), ScanStatus(scan)
	f.ScannedAt, f.ScanSignature = nullMillis(scanned), signature.String
	return f, nil
}

// listFiles returns the files of the transfer trfID by position, inside tx.
func listFiles(ctx context.Context, tx *ScopedTx, trfID string) ([]TransferFile, error) {
	rows, err := tx.Query(ctx, qFileList, trfID)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r *sql.Rows) (TransferFile, error) { return scanFile(r) })
}

// details reads the transfer of row and loads its recipients and files,
// inside tx.
func details(ctx context.Context, tx *ScopedTx, row *Row) (TransferDetails, error) {
	t, err := scanTransfer(row)
	if err != nil {
		return TransferDetails{}, err
	}
	rows, err := tx.Query(ctx, qRecipientList, t.ID)
	if err != nil {
		return TransferDetails{}, err
	}
	rcpts, err := collect(rows, func(r *sql.Rows) (string, error) {
		var s string
		err := r.Scan(&s)
		return s, err
	})
	if err != nil {
		return TransferDetails{}, err
	}
	files, err := listFiles(ctx, tx, t.ID)
	if err != nil {
		return TransferDetails{}, err
	}
	return TransferDetails{Transfer: t, Recipients: rcpts, Files: files}, nil
}

// readScoped runs fn in a read transaction of tenant tid and wraps its
// error with op.
func readScoped[T any](ctx context.Context, db *DB, tid tenant.ID, op string, fn func(*ScopedTx) (T, error)) (T, error) {
	var zero T
	s, err := db.Scoped(tid)
	if err != nil {
		return zero, err
	}
	var v T
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		var err error
		v, err = fn(tx)
		return err
	})
	if err != nil {
		return zero, wrap(op, err)
	}
	return v, nil
}

// writeScoped runs fn in a write transaction of tenant tid and wraps its
// error with op.
func writeScoped(ctx context.Context, db *DB, tid tenant.ID, op string, fn func(*ScopedTx) error) error {
	s, err := db.Scoped(tid)
	if err != nil {
		return err
	}
	if err := s.Tx(ctx, fn); err != nil {
		return wrap(op, err)
	}
	return nil
}

// Get returns the transfer trfID of tenant tid with its recipients and
// files, in whatever state it is, or ErrNotFound when it does not exist or
// belongs to another tenant.
func (r *Transfers) Get(ctx context.Context, tid tenant.ID, trfID string) (TransferDetails, error) {
	return readScoped(ctx, r.db, tid, "get transfer", func(tx *ScopedTx) (TransferDetails, error) {
		return details(ctx, tx, tx.QueryRow(ctx, qTransferGet, trfID))
	})
}

// GetTx is [Transfers.Get] inside tx, for the tenant tx is bound to (for
// example to check the files before [Transfers.FinalizeTx]). After an
// error, the caller must abort the transaction.
func (r *Transfers) GetTx(ctx context.Context, tx *ScopedTx, trfID string) (TransferDetails, error) {
	d, err := details(ctx, tx, tx.QueryRow(ctx, qTransferGet, trfID))
	if err != nil {
		return TransferDetails{}, wrap("get transfer", err)
	}
	return d, nil
}

// GetByIdempotencyKey returns the transfer of tenant tid that the sender
// created with the idempotency key at or after since (callers pass now -
// IdempotencyRetention), with its recipients and files. It returns
// ErrNotFound when there is none (an older key is ignored), including for a
// transfer of another tenant, and ErrInvalid for a malformed address or
// key.
func (r *Transfers) GetByIdempotencyKey(ctx context.Context, tid tenant.ID, sender, key string, since time.Time) (TransferDetails, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return TransferDetails{}, err
	}
	sender, err := NormalizeEmail(sender)
	if err != nil {
		return TransferDetails{}, err
	}
	if !validIdempotencyKey(key) {
		return TransferDetails{}, invalid("idempotency key must hold 1 to %d visible ASCII characters", MaxIdempotencyKeyLen)
	}
	return readScoped(ctx, r.db, tid, "get transfer by idempotency key", func(tx *ScopedTx) (TransferDetails, error) {
		return details(ctx, tx, tx.QueryRow(ctx, qTransferGetByKey, sender, key, toMillis(since)))
	})
}

// UsedBytesTx returns the storage used by the tenant tx is bound to: the
// sum of the declared sizes of the files of its transfers that are
// uploading, scanning or available (the quota of spec 8.5 reserves the
// declared size at creation). It first takes the tenant lock, so that the
// check followed by [Transfers.CreateTx] in the same transaction is atomic
// against concurrent creations of the tenant. After an error, the caller
// must abort the transaction.
func (r *Transfers) UsedBytesTx(ctx context.Context, tx *ScopedTx) (int64, error) {
	if err := tx.lock(ctx); err != nil {
		return 0, err
	}
	var n int64
	if err := tx.QueryRow(ctx, qTransferUsedBytes).Scan(&n); err != nil {
		return 0, wrap("sum used bytes", err)
	}
	return n, nil
}

// CountUploadingTx returns the number of transfers of the tenant tx is
// bound to that sender (normalized) created at or after since and has not
// finalized yet (status uploading), inside tx. Called after
// [Transfers.UsedBytesTx] in the creation transaction, it runs under the
// tenant lock, so that a per-sender cap on open transfers cannot be
// exceeded by concurrent creations. It returns ErrInvalid for a malformed
// address. After an error, the caller must abort the transaction.
func (r *Transfers) CountUploadingTx(ctx context.Context, tx *ScopedTx, sender string, since time.Time) (int, error) {
	sender, err := NormalizeEmail(sender)
	if err != nil {
		return 0, err
	}
	var n int
	if err := tx.QueryRow(ctx, qTransferCountUploading, sender, toMillis(since)).Scan(&n); err != nil {
		return 0, wrap("count open transfers", err)
	}
	return n, nil
}

// ListUploadingTx returns, inside tx, the transfers counted by
// [Transfers.CountUploadingTx] (without recipients or files), newest
// first, at most limit of them (1 to MaxTransferFiles). It returns
// ErrInvalid for a malformed address or limit. After an error, the caller
// must abort the transaction.
func (r *Transfers) ListUploadingTx(ctx context.Context, tx *ScopedTx, sender string, since time.Time, limit int) ([]Transfer, error) {
	sender, err := NormalizeEmail(sender)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > MaxTransferFiles {
		return nil, invalid("limit must be between 1 and %d", MaxTransferFiles)
	}
	var out []Transfer
	rows, err := tx.Query(ctx, qTransferListUploading, sender, toMillis(since), limit)
	if err == nil {
		out, err = collect(rows, func(r *sql.Rows) (Transfer, error) { return scanTransfer(r) })
	}
	if err != nil {
		return nil, wrap("list open transfers", err)
	}
	return out, nil
}

// probe distinguishes, after a conditional statement affected no row, a
// missing row (ErrNotFound) from a row in another state (conflict). count
// is a "SELECT count(*) ... WHERE tenant_id = ? AND id = ?" statement.
func probe(ctx context.Context, tx *ScopedTx, count TenantQuery, rowID string, conflict error) error {
	var n int
	if err := tx.QueryRow(ctx, count, rowID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return conflict
}

// SetStatusTx moves the transfer trfID of the tenant tx is bound to from
// status from to status to, inside tx. Moving from TransferUploading to
// TransferScanning is the finalization: it also sets FinalizedAt to now
// and ExpiresAt to now + ExpiryDays. Every other allowed target is
// terminal: EndedAt is set to now (the store's clock when now is zero),
// unless the transfer had already ended. A transfer
// reaches scanning only through the finalization, rejected only from
// scanning, and never returns to uploading; it becomes available only
// through [Transfers.MarkAvailableTx], which records its download link.
// Any other status may move to expired or deleted, once the data key of
// every file and the sealed download token (DownloadTokenKeyID) are
// destroyed (T-110), like [Transfers.MarkExpiredTx]; a rejected transfer
// keeps its file keys until the expiry sweep erases them.
//
// It returns ErrInvalid for an unknown or disallowed transition,
// ErrNotFound when the transfer does not exist or belongs to another
// tenant, ErrConflict when its status is not from, and [ErrKeysRemain]
// when a key remains (a file key for expired or deleted, the token key for
// any terminal target). After an error, the caller must abort the
// transaction.
func (r *Transfers) SetStatusTx(ctx context.Context, tx *ScopedTx, trfID string, from, to TransferStatus, now time.Time) error {
	if err := setStatus(ctx, tx, trfID, from, to, r.db.orNow(now)); err != nil {
		return wrap("set transfer status", err)
	}
	return nil
}

// setStatus implements SetStatusTx, returning raw errors.
func setStatus(ctx context.Context, tx *ScopedTx, trfID string, from, to TransferStatus, now time.Time) error {
	finalize := from == TransferUploading && to == TransferScanning
	switch {
	case !from.valid() || !to.valid() || from == to:
		return invalid("unknown or empty status transition")
	case to == TransferUploading:
		return invalid("a transfer never returns to uploading")
	case to == TransferAvailable:
		return invalid("a transfer becomes available only with its download link")
	case to == TransferScanning && !finalize:
		return invalid("only the finalization leads to scanning")
	case to == TransferRejected && from != TransferScanning:
		return invalid("only a scanning transfer can be rejected")
	}
	if finalize {
		ms := toMillis(now)
		res, err := tx.Exec(ctx, qTransferFinalize, ms, ms, trfID)
		if err == nil {
			err = expectOne(res)
		}
		if errors.Is(err, ErrNotFound) {
			return probe(ctx, tx, qTransferCount, trfID, ErrConflict)
		}
		return err
	}
	return endTransfer(ctx, tx, trfID, from, to, now)
}

// endTransfer moves the transfer trfID from from to the terminal status to
// at now, refusing while a key remains (see [Transfers.SetStatusTx]).
func endTransfer(ctx context.Context, tx *ScopedTx, trfID string, from, to TransferStatus, now time.Time) error {
	keyed := 0
	if to != TransferRejected {
		if err := tx.QueryRow(ctx, qFileCountKeyed, trfID).Scan(&keyed); err != nil {
			return err
		}
	}
	if keyed == 0 {
		res, err := tx.Exec(ctx, qTransferSetStatus, string(to), toMillis(now), trfID, string(from))
		if err == nil {
			err = expectOne(res)
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	t, err := scanTransfer(tx.QueryRow(ctx, qTransferGet, trfID))
	switch {
	case err != nil:
		return err
	case t.Status != from:
		return ErrConflict
	default:
		return ErrKeysRemain
	}
}

// FinalizeTx finalizes the transfer trfID inside tx at now: it moves from
// uploading to scanning (see [Transfers.SetStatusTx]). The caller checks
// beforehand that every file is complete and matches its expected SHA-256.
func (r *Transfers) FinalizeTx(ctx context.Context, tx *ScopedTx, trfID string, now time.Time) error {
	if err := setStatus(ctx, tx, trfID, TransferUploading, TransferScanning, now); err != nil {
		return wrap("finalize transfer", err)
	}
	return nil
}

// DeleteTx deletes the transfer trfID of the tenant tx is bound to, with
// (by cascade) its recipients and files, inside tx. The data key of every
// file, and the sealed download token of an available transfer
// (DownloadTokenKeyID), must have been destroyed first in the same
// transaction ([WrappedKeys.DeleteTx]); otherwise it returns
// [ErrKeysRemain] and deletes nothing. It returns ErrNotFound when the transfer does not exist
// or belongs to another tenant. Callers delete the files on disk once the
// transaction is committed, then call [DB.ScrubDeleted]. After an error,
// the caller must abort the transaction.
func (r *Transfers) DeleteTx(ctx context.Context, tx *ScopedTx, trfID string) error {
	if err := deleteTransfer(ctx, tx, trfID); err != nil {
		return wrap("delete transfer", err)
	}
	return nil
}

// deleteTransfer implements DeleteTx, returning raw errors.
func deleteTransfer(ctx context.Context, tx *ScopedTx, trfID string) error {
	var keyed int
	if err := tx.QueryRow(ctx, qFileCountKeyed, trfID).Scan(&keyed); err != nil {
		return err
	}
	if keyed > 0 {
		return ErrKeysRemain
	}
	res, err := tx.Exec(ctx, qTransferDelete, trfID)
	if err == nil {
		err = expectOne(res)
	}
	if errors.Is(err, ErrNotFound) {
		return probe(ctx, tx, qTransferCount, trfID, ErrKeysRemain)
	}
	return err
}

// getByUploadID implements GetByUploadID inside tx, returning raw errors.
func getByUploadID(ctx context.Context, tx *ScopedTx, uploadID string) (FileUpload, error) {
	f, err := scanFile(tx.QueryRow(ctx, qFileGetByUpload, uploadID))
	if err != nil {
		return FileUpload{}, err
	}
	t, err := scanTransfer(tx.QueryRow(ctx, qTransferGet, f.TransferID))
	if err != nil {
		return FileUpload{}, err
	}
	return FileUpload{File: f, Transfer: t}, nil
}

// GetByUploadID returns the file of tenant tid whose upload identifier is
// uploadID, with its transfer. It returns ErrNotFound when there is none,
// including for an upload of another tenant (the lookup runs in the tenant
// scope, under row-level security on PostgreSQL), and ErrInvalid for a
// malformed upload identifier.
func (r *TransferFiles) GetByUploadID(ctx context.Context, tid tenant.ID, uploadID string) (FileUpload, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return FileUpload{}, err
	}
	if !id.UploadTokenValid(uploadID) {
		return FileUpload{}, invalid("malformed upload id")
	}
	return readScoped(ctx, r.db, tid, "get file by upload id", func(tx *ScopedTx) (FileUpload, error) {
		return getByUploadID(ctx, tx, uploadID)
	})
}

// GetByUploadIDTx is [TransferFiles.GetByUploadID] inside tx, for the
// tenant tx is bound to (for example before [TransferFiles.ReplaceDEKTx]).
// After an error, the caller must abort the transaction.
func (r *TransferFiles) GetByUploadIDTx(ctx context.Context, tx *ScopedTx, uploadID string) (FileUpload, error) {
	if !id.UploadTokenValid(uploadID) {
		return FileUpload{}, invalid("malformed upload id")
	}
	u, err := getByUploadID(ctx, tx, uploadID)
	if err != nil {
		return FileUpload{}, wrap("get file by upload id", err)
	}
	return u, nil
}

// ListByTransfer returns the files of the transfer trfID of tenant tid, by
// position. The list is empty when the transfer has no file, does not exist
// or belongs to another tenant.
func (r *TransferFiles) ListByTransfer(ctx context.Context, tid tenant.ID, trfID string) ([]TransferFile, error) {
	return readScoped(ctx, r.db, tid, "list files", func(tx *ScopedTx) ([]TransferFile, error) {
		return listFiles(ctx, tx, trfID)
	})
}

// ListByTransferTx is [TransferFiles.ListByTransfer] inside tx, for the
// tenant tx is bound to. After an error, the caller must abort the
// transaction.
func (r *TransferFiles) ListByTransferTx(ctx context.Context, tx *ScopedTx, trfID string) ([]TransferFile, error) {
	files, err := listFiles(ctx, tx, trfID)
	if err != nil {
		return nil, wrap("list files", err)
	}
	return files, nil
}

// CompleteUpload records the end of the upload of the file fileID of
// tenant tid at now, in its own transaction (see
// [TransferFiles.CompleteUploadTx]).
func (r *TransferFiles) CompleteUpload(ctx context.Context, tid tenant.ID, fileID, sha256 string, ciphertextSize int64, now time.Time) error {
	return writeScoped(ctx, r.db, tid, "complete upload", func(tx *ScopedTx) error {
		return completeUpload(ctx, tx, fileID, sha256, ciphertextSize, now)
	})
}

// CompleteUploadTx records, inside tx, the end of the upload of the file
// fileID at now: the SHA-256 of the clear file (64 lowercase hex
// characters) and the size of the encrypted file. This is the only write of
// an upload besides the creation (spec 17). It returns ErrInvalid for a
// malformed value, ErrNotFound when the file does not exist or belongs to
// another tenant, and ErrConflict when its upload is already complete.
// After an error, the caller must abort the transaction.
func (r *TransferFiles) CompleteUploadTx(ctx context.Context, tx *ScopedTx, fileID, sha256 string, ciphertextSize int64, now time.Time) error {
	if err := completeUpload(ctx, tx, fileID, sha256, ciphertextSize, now); err != nil {
		return wrap("complete upload", err)
	}
	return nil
}

// completeUpload implements CompleteUploadTx, returning raw errors.
func completeUpload(ctx context.Context, tx *ScopedTx, fileID, sha256 string, ciphertextSize int64, now time.Time) error {
	if !isLowerHex(sha256, sha256HexLen) {
		return invalid("malformed sha256")
	}
	if ciphertextSize < 0 {
		return invalid("ciphertext size must not be negative")
	}
	res, err := tx.Exec(ctx, qFileComplete, sha256, ciphertextSize, toMillis(now), fileID)
	return conditional(ctx, tx, res, err, fileID)
}

// conditional checks the result of a conditional update of the file
// fileID: ErrNotFound for a missing file, ErrConflict for a completed one.
func conditional(ctx context.Context, tx *ScopedTx, res sql.Result, err error, fileID string) error {
	if err == nil {
		err = expectOne(res)
	}
	if errors.Is(err, ErrNotFound) {
		return probe(ctx, tx, qFileCount, fileID, ErrConflict)
	}
	return err
}

// ReplaceDEKTx gives the file fileID a new data key and a new storage
// name, inside tx: the reset of an upload after a stale checkpoint, which
// never reuses a key on rewritten data. newKeyID must be a data key of the
// tenant tx is bound to, created in the same transaction. The caller reads
// the previous key ([TransferFiles.GetByUploadIDTx]) and destroys it in the
// same transaction, then removes the previous file on disk.
//
// It returns ErrInvalid for a malformed value or a key that is not a data
// key, ErrNotFound when the file or the key does not exist (or belongs to
// another tenant), and ErrConflict when the upload is already complete or
// the key or the storage name is already used. After an error, the caller
// must abort the transaction.
func (r *TransferFiles) ReplaceDEKTx(ctx context.Context, tx *ScopedTx, fileID, newKeyID, newStorageName string) error {
	if err := replaceDEK(ctx, tx, fileID, newKeyID, newStorageName); err != nil {
		return wrap("replace data key", err)
	}
	return nil
}

// replaceDEK implements ReplaceDEKTx, returning raw errors.
func replaceDEK(ctx context.Context, tx *ScopedTx, fileID, newKeyID, newStorageName string) error {
	if !id.Valid(id.WrappedKey, newKeyID) {
		return invalid("malformed data key id")
	}
	if !isLowerHex(newStorageName, StorageNameLen) {
		return invalid("malformed storage name")
	}
	if err := checkDEK(ctx, tx, newKeyID); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, qFileReplaceDEK, newKeyID, newStorageName, fileID)
	return conditional(ctx, tx, res, err, fileID)
}

// DeleteTx deletes the file fileID of the tenant tx is bound to, inside tx
// (tus termination), and subtracts its declared size from the total of its
// transfer, which releases it from the quota. Its data key must have been
// destroyed first in the same transaction ([WrappedKeys.DeleteTx]);
// otherwise it returns [ErrKeysRemain] and deletes nothing. It returns
// ErrNotFound when the file does not exist or belongs to another tenant.
// The caller checks that the transfer is still uploading. After an error,
// the caller must abort the transaction.
func (r *TransferFiles) DeleteTx(ctx context.Context, tx *ScopedTx, fileID string) error {
	if err := deleteFile(ctx, tx, fileID); err != nil {
		return wrap("delete file", err)
	}
	return nil
}

// deleteFile implements DeleteTx, returning raw errors.
func deleteFile(ctx context.Context, tx *ScopedTx, fileID string) error {
	var (
		trfID string
		size  int64
	)
	err := tx.QueryRow(ctx, qFileDelete, fileID).Scan(&trfID, &size)
	if errors.Is(err, ErrNotFound) {
		return probe(ctx, tx, qFileCount, fileID, ErrKeysRemain)
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, qTransferShrink, size, trfID)
	return err
}

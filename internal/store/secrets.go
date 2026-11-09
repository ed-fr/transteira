package store

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// One-time secrets (since 2.1, CLAUDE.md section 22.1). The data model is
// docs/architecture/data-model-v2.1.md, section 2.1; the proofs and the
// attempt slots are docs/architecture/e2e-format.md, section 3.3.4.
//
// Key rule of every path: a live secret (pending or active) references its
// text key, and its file key once the file is uploaded (hardening checks of
// migration 0033). Every path that ends or removes a secret therefore
// changes or deletes the row first, then destroys its keys with
// SecretKeys.DestroyTx in the same transaction, so that no unreferenced
// "dek" row is ever left behind. The methods that destroy keys do not scrub
// the database: the caller calls [DB.ScrubDeleted] (or the vault's Scrub)
// once they return, as after any [WrappedKeys.DeleteTx].

// SecretKeys creates, opens and destroys the server data keys of the
// secrets inside the caller's transaction. *masterkey.Vault implements it.
type SecretKeys interface {
	// NewDEKTx creates a data key sealed for the tenant tx is bound to and
	// returns its wrapped key ID and the plaintext key.
	NewDEKTx(ctx context.Context, tx *ScopedTx) (wkID string, dek []byte, err error)
	// OpenTx unwraps the wrapped key wkID of purpose p of the tenant tx is
	// bound to.
	OpenTx(ctx context.Context, tx *ScopedTx, p crypto.Purpose, wkID string) ([]byte, error)
	// DestroyTx deletes the wrapped key wkID (cryptographic erasure).
	DestroyTx(ctx context.Context, tx *ScopedTx, wkID string) error
}

// SecretState is the state of a one-time secret (secrets.state).
type SecretState string

// Secret states. Pending and active are live; the others are tombstones,
// which hold no content and are purged SecretTombstoneRetention after
// their end.
const (
	// SecretPending waits for its file and/or the send call.
	SecretPending SecretState = "pending"
	// SecretActive is readable until its expiry.
	SecretActive SecretState = "active"
	// SecretRead was revealed once.
	SecretRead SecretState = "read"
	// SecretExpired reached its expiry unread.
	SecretExpired SecretState = "expired"
	// SecretDeleted was deleted by its creator or an admin.
	SecretDeleted SecretState = "deleted"
	// SecretLocked received SecretMaxFailedProofs wrong passphrase proofs.
	SecretLocked SecretState = "locked"
)

// Live reports whether s is pending or active.
func (s SecretState) Live() bool { return s == SecretPending || s == SecretActive }

// SecretCreatorKind tells who created a secret (secrets.creator_kind).
type SecretCreatorKind string

// Creator kinds: the depositor kinds of the deposit sessions, and the API
// tokens.
const (
	// SecretCreatorInternal is an internal depositor.
	SecretCreatorInternal SecretCreatorKind = "internal"
	// SecretCreatorInternalRemote is an internal depositor from outside the
	// tenant's IP ranges (spec 6.4).
	SecretCreatorInternalRemote SecretCreatorKind = "internal_remote"
	// SecretCreatorExternal is an invited external; it must use the e-mail
	// delivery, to its inviter.
	SecretCreatorExternal SecretCreatorKind = "external"
	// SecretCreatorAPIToken is an API token.
	SecretCreatorAPIToken SecretCreatorKind = "api_token"
)

// valid reports whether k is a known creator kind.
func (k SecretCreatorKind) valid() bool {
	switch k {
	case SecretCreatorInternal, SecretCreatorInternalRemote, SecretCreatorExternal, SecretCreatorAPIToken:
		return true
	}
	return false
}

// SecretDelivery is the delivery of a secret (secrets.delivery).
type SecretDelivery string

// Deliveries.
const (
	// SecretDeliveryLink: the creator hands the link out.
	SecretDeliveryLink SecretDelivery = "link"
	// SecretDeliveryEmail: the server mails the link to one recipient.
	SecretDeliveryEmail SecretDelivery = "email"
)

// SecretEndReason tells why a secret ended (secrets.end_reason). The API
// maps both deleted_by_* values to "deleted" (decision D5).
type SecretEndReason string

// End reasons.
const (
	SecretEndRead             SecretEndReason = "read"
	SecretEndExpired          SecretEndReason = "expired"
	SecretEndLocked           SecretEndReason = "locked"
	SecretEndDeletedByCreator SecretEndReason = "deleted_by_creator" //nolint:gosec // G101: an end reason, not a credential
	SecretEndDeletedByAdmin   SecretEndReason = "deleted_by_admin"
)

// Limits of the one-time secrets.
const (
	// SecretMaxFailedProofs is the number of wrong passphrase proofs that
	// locks a secret.
	SecretMaxFailedProofs = 5
	// SecretMaxOpen is the number of pending and active secrets a creator
	// (address or API token) may have at once.
	SecretMaxOpen = 50
	// SecretMaxDaily is the number of secrets a creator may create in the
	// rolling SecretDailyWindow.
	SecretMaxDaily = 200
	// SecretDailyWindow is the window of SecretMaxDaily.
	SecretDailyWindow = 24 * time.Hour
	// SecretPendingRetention is how long a pending secret may wait before
	// [Secrets.PurgePending] deletes it.
	SecretPendingRetention = time.Hour
	// SecretTombstoneRetention is how long a tombstone is kept after its
	// end ([Secrets.PurgeTombstones]).
	SecretTombstoneRetention = 30 * 24 * time.Hour
	// MinSecretSealedTextLen and MaxSecretSealedTextLen bound the sealed
	// text string (e2e-format.md 3.3.3).
	MinSecretSealedTextLen = 39
	MaxSecretSealedTextLen = 53372
	// MaxSecretFileMetadataLen bounds the sealed file metadata string, as
	// MaxE2EMetadataLen for transfer files.
	MaxSecretFileMetadataLen = MaxE2EMetadataLen
	// SecretKDFIterations is the only PBKDF2 iteration count of the format.
	SecretKDFIterations = 600000
	// SecretKDFSaltLen is the length of the passphrase salt.
	SecretKDFSaltLen = 16
	// secretVerifierLen is the length of a verifier (SHA-256).
	secretVerifierLen = sha256.Size
	// secretStorageNameLen is the length of a file storage name.
	secretStorageNameLen = 32
	// SecretFileGrantLifetime is how long the one-time file grant drawn
	// by a reveal stays valid.
	SecretFileGrantLifetime = 10 * time.Minute
)

// Errors of the one-time secrets. Policy refusals wrap ErrSecretPolicy and
// the creation limits wrap ErrLimitReached.
var (
	// ErrSecretPolicy is wrapped by every refusal of a tenant setting.
	ErrSecretPolicy = errors.New("store: refused by the secret settings of the tenant")
	// ErrSecretsDisabled reports a creation while the module is off.
	ErrSecretsDisabled = fmt.Errorf("%w: secrets are disabled", ErrSecretPolicy)
	// ErrSecretDurationNotOffered reports a duration the tenant does not
	// offer.
	ErrSecretDurationNotOffered = fmt.Errorf("%w: duration not offered", ErrSecretPolicy)
	// ErrSecretFileNotAllowed reports a file while the tenant forbids them.
	ErrSecretFileNotAllowed = fmt.Errorf("%w: files are not allowed", ErrSecretPolicy)
	// ErrSecretFileTooLarge reports a file above the tenant limit.
	ErrSecretFileTooLarge = fmt.Errorf("%w: file too large", ErrSecretPolicy)
	// ErrSecretEmailNotAllowed reports an e-mail delivery while the tenant
	// forbids it (which also closes the module to invited externals).
	ErrSecretEmailNotAllowed = fmt.Errorf("%w: e-mail delivery is not allowed", ErrSecretPolicy)
	// ErrSecretPassphraseRequired reports an e-mail secret without
	// passphrase while the tenant requires one (P83).
	ErrSecretPassphraseRequired = fmt.Errorf("%w: a passphrase is required for the e-mail delivery", ErrSecretPolicy)
	// ErrSecretOpenLimit reports a creator with SecretMaxOpen open secrets.
	ErrSecretOpenLimit = fmt.Errorf("%w: too many open secrets", ErrLimitReached)
	// ErrSecretDailyLimit reports a creator with SecretMaxDaily creations
	// in the last SecretDailyWindow.
	ErrSecretDailyLimit = fmt.Errorf("%w: too many secrets created today", ErrLimitReached)
	// ErrSecretPending reports the token of a secret still pending (never
	// delivered) on a recipient operation. It wraps ErrNotFound: the
	// recipient side answers it like an unknown token, without the security
	// event of an unknown one.
	ErrSecretPending = fmt.Errorf("%w: secret pending", ErrNotFound)
	// ErrSecretGone is matched by a [*SecretGoneError].
	ErrSecretGone = errors.New("store: secret gone")
	// ErrSecretKeyProof reports a wrong key proof at the reveal: the caller
	// does not hold the link key. Nothing is counted nor written.
	ErrSecretKeyProof = errors.New("store: wrong secret key proof")
	// ErrSecretProof is matched by a [*SecretProofError].
	ErrSecretProof = errors.New("store: wrong secret proof")
	// ErrSecretQuotaExceeded reports a secret whose file does not fit in
	// the storage quota of the tenant (spec 8.5, the same rule as a
	// transfer).
	ErrSecretQuotaExceeded = errors.New("store: storage quota exceeded")
	// ErrSecretState reports a creator operation the state of the secret
	// does not allow (the upload of a secret that is not pending, has no
	// file, has it already or is receiving it; the send call of a secret
	// that is not a pending e-mail secret, or whose file is missing). It
	// wraps ErrConflict.
	ErrSecretState = fmt.Errorf("%w: secret state", ErrConflict)
	// ErrSecretUploadAborted is joined to the error of a secret file
	// upload that failed after its file key was created: the key was
	// destroyed (or is left to the orphan sweep) and the caller scrubs the
	// database.
	ErrSecretUploadAborted = errors.New("store: secret file upload aborted")
	// ErrSecretFileFormat reports an uploaded file body that is not a
	// TTE2 stream of exactly the declared size (keyless validator).
	ErrSecretFileFormat = errors.New("store: malformed secret file")
	// ErrSecretGrant reports a file download whose one-time grant is
	// missing, malformed, wrong, used or expired, or a secret without file
	// grant. It wraps ErrNotFound: answered like an unknown secret, but
	// without the security event of an unknown token.
	ErrSecretGrant = fmt.Errorf("%w: secret file grant", ErrNotFound)
	// errSecretNoKeys reports a repository built without SecretKeys used
	// for an operation that needs them.
	errSecretNoKeys = errors.New("store: the secrets repository has no key vault")
)

// SecretGoneError reports a secret that is no longer readable: a tombstone,
// or an active secret past its expiry. It matches ErrSecretGone.
type SecretGoneError struct {
	// Reason is why the secret ended (SecretEndExpired for an active
	// secret past its expiry).
	Reason SecretEndReason
}

// Error implements error.
func (e *SecretGoneError) Error() string { return "store: secret gone (" + string(e.Reason) + ")" }

// Is matches ErrSecretGone.
func (e *SecretGoneError) Is(target error) bool { return target == ErrSecretGone }

// SecretProofError reports a wrong passphrase proof with a right key proof:
// a counted failure. It matches ErrSecretProof.
type SecretProofError struct {
	// ID is the identifier of the secret ("sec_" + ULID), for the audit
	// of a lock.
	ID string
	// Remaining is the number of attempts left; 0 means the secret is now
	// locked and its content destroyed.
	Remaining int
	// RemovedFile is, when Remaining is 0, the storage name of the file
	// the caller must remove ("" when the secret had no stored file).
	RemovedFile string
}

// Error implements error.
func (e *SecretProofError) Error() string {
	return fmt.Sprintf("store: wrong secret proof (%d attempts left)", e.Remaining)
}

// Is matches ErrSecretProof.
func (e *SecretProofError) Is(target error) bool { return target == ErrSecretProof }

// Secret describes a one-time secret without its content: no token, no
// sealed text, no verifier, no key.
type Secret struct {
	// ID is "sec_" + ULID.
	ID string
	// TenantID is the owning tenant.
	TenantID tenant.ID
	// State is the stored state (see [Secrets.StatusByToken] for the
	// expiry checked on read).
	State SecretState
	// CreatorKind, SenderEmail, APITokenID ("" unless an API token) and
	// InvitationID ("" unless external) describe the creator.
	CreatorKind  SecretCreatorKind
	SenderEmail  string
	APITokenID   string
	InvitationID string
	// Delivery and RecipientEmail ("" for the link delivery).
	Delivery       SecretDelivery
	RecipientEmail string
	// ReadReceipt is the creator's choice; ReceiptSentAt is set once the
	// receipt left (zero otherwise).
	ReadReceipt   bool
	ReceiptSentAt time.Time
	// KDFSalt and KDFIterations describe the passphrase (nil and 0
	// without passphrase, and in every tombstone). The salt is public
	// while the secret is live.
	KDFSalt       []byte
	KDFIterations int
	// Duration is the duration code chosen at creation.
	Duration tenant.SecretDuration
	// CreatedAt, ActivatedAt and ExpiresAt (zero while pending), ReadAt
	// (state read), EndedAt (tombstones).
	CreatedAt   time.Time
	ActivatedAt time.Time
	ExpiresAt   time.Time
	ReadAt      time.Time
	EndedAt     time.Time
	// EndReason is set in the tombstones.
	EndReason SecretEndReason
	// FailedProofs counts the wrong passphrase proofs.
	FailedProofs int
	// FileSize is the declared ciphertext size of the file, 0 without
	// file (kept in the tombstone).
	FileSize int64
	// FileStorageName is the name of the stored file under
	// <tenant dir>/secrets/, "" when no file is stored.
	FileStorageName string
	// FileUploadedAt and FileDownloadedAt mark the upload and the first
	// complete download.
	FileUploadedAt   time.Time
	FileDownloadedAt time.Time
}

// HasPassphrase reports whether s is protected by a passphrase (known
// while it is live only).
func (s Secret) HasPassphrase() bool { return s.KDFSalt != nil }

// SecretActor identifies who acts on a secret on the creator side
// (data-model-v2.1.md, "Creator identity").
type SecretActor struct {
	// APITokenID identifies an API token: it acts on the secrets it
	// created only. Email and Kind are then ignored.
	APITokenID string
	// Email is the verified address of a deposit session or of a "my
	// transfers" session (normalized by the store).
	Email string
	// Kind is the creator kind of a deposit session (internal,
	// internal_remote or external): it acts on the secrets of the same
	// address and kind. "" stands for the "my transfers" session, which
	// acts on every secret of the address created by a deposit session.
	Kind SecretCreatorKind
}

// Owns reports whether a is the creator of s.
func (a SecretActor) Owns(s Secret) bool {
	if a.APITokenID != "" {
		return s.APITokenID == a.APITokenID
	}
	if s.CreatorKind == SecretCreatorAPIToken || a.Email == "" {
		return false
	}
	email, err := NormalizeEmail(a.Email)
	if err != nil || email != s.SenderEmail {
		return false
	}
	return a.Kind == "" || a.Kind == s.CreatorKind
}

// CreateSecret is the input of [Secrets.Create].
type CreateSecret struct {
	// CreatorKind is the creator; SecretCreatorAPIToken needs APITokenID,
	// SecretCreatorExternal needs InvitationID.
	CreatorKind  SecretCreatorKind
	APITokenID   string
	InvitationID string
	// SenderEmail is the verified address of the session, or the declared
	// sender of an API token.
	SenderEmail string
	// Delivery and, for the e-mail delivery, RecipientEmail. For an
	// external creator the store forces the e-mail delivery to the inviter
	// (RecipientEmail is ignored).
	Delivery       SecretDelivery
	RecipientEmail string
	// ReadReceipt asks for the receipt mail.
	ReadReceipt bool
	// Verifier is SHA-256(proof) and KeyVerifier SHA-256(keyProof), 32
	// bytes each.
	Verifier    []byte
	KeyVerifier []byte
	// KDFSalt is the passphrase salt (SecretKDFSaltLen bytes), nil without
	// passphrase; the iteration count is always SecretKDFIterations.
	KDFSalt []byte
	// SealedText is the sealed text string from the browser,
	// MinSecretSealedTextLen to MaxSecretSealedTextLen base64url
	// characters.
	SealedText string
	// Duration must be offered by the tenant.
	Duration tenant.SecretDuration
	// FileSize (ciphertext bytes, 0 without file), FileMetadata (the sealed
	// metadata, required with a file) and FileStorageName (32 lowercase
	// hexadecimal characters, storage.NewName, required with a file)
	// declare the optional file. A secret with a file starts pending.
	FileSize        int64
	FileMetadata    string
	FileStorageName string
	// Now is the creation time; zero means the store clock.
	Now time.Time
}

// CreatedSecret is the result of [Secrets.Create].
type CreatedSecret struct {
	// Secret is the stored secret.
	Secret Secret
	// Token is the bearer token of the link ("tts_..."), returned once:
	// only its SHA-256 is stored.
	Token string
}

// RevealedSecret is the result of a successful [Secrets.Reveal].
type RevealedSecret struct {
	// Secret is the tombstone after the reveal (state read).
	Secret Secret
	// SealedText is the sealed text, as sent at creation.
	SealedText string
	// FileMetadata is the sealed file metadata ("" without file).
	FileMetadata string
	// FileGrant is the one-time file grant ("ttg_...", "" without file),
	// returned once: only its SHA-256 is stored.
	FileGrant string
	// FileGrantExpiresAt is the end of validity of FileGrant
	// (SecretFileGrantLifetime after the reveal).
	FileGrantExpiresAt time.Time
}

// EndedSecret describes a secret ended or removed by a deletion or a
// sweep.
type EndedSecret struct {
	// Secret is the row after the change (the tombstone), or as it was
	// before its deletion when the row is gone.
	Secret Secret
	// RemovedFile is the storage name of the file the caller must remove
	// from <tenant dir>/secrets/ ("" when none was stored).
	RemovedFile string
}

// SecretErasure is the result of a data-subject erasure of the secrets of
// an address.
type SecretErasure struct {
	// Deleted counts the secrets deleted (rows and keys).
	Deleted int
	// RemovedFiles are the storage names the caller must remove.
	RemovedFiles []string
}

// SecretListOptions selects a page of secrets, newest first.
type SecretListOptions struct {
	// Cursor is the NextCursor of the previous page, or "" for the first.
	Cursor string
	// Limit is the page size (DefaultPageSize when <= 0, at most
	// MaxPageSize).
	Limit int
}

// secretColumns is the column list of a [Secret], content excluded, then
// the key IDs (read by the store only).
const secretColumns = `id, state, creator_kind, sender_email, api_token_id, invitation_id, delivery, recipient_email, ` +
	`read_receipt, receipt_sent_at, kdf_salt, kdf_iterations, duration_code, created_at, activated_at, expires_at, ` +
	`read_at, ended_at, end_reason, failed_proofs, file_size, file_storage_name, file_uploaded_at, file_downloaded_at, ` +
	`text_key_id, file_key_id`

// secretContentNull clears the content of a secret that ends: every
// column a tombstone must not hold (checks of migration 0033).
const secretContentNull = `text_sealed = NULL, text_key_id = NULL, verifier = NULL, key_verifier = NULL, ` +
	`kdf_salt = NULL, kdf_iterations = NULL, file_metadata = NULL`

// secretFileNull also clears the stored file of a secret that ends
// without a file grant.
const secretFileNull = `file_storage_name = NULL, file_key_id = NULL`

// Reasons of the system and reviewed queries of the secrets.
const (
	reasonSecretSweep = "one-time secrets lifecycle: list the due secrets of every tenant, each handled in its own scope"
	// reasonSecretSettings is the review of qSecretSettings: the tenant
	// slot filters secrets, and the join reads the tenants row of the
	// same tenant only (n.id = s.tenant_id); on PostgreSQL the tenants
	// policy also restricts a tenant scope to its own row.
	reasonSecretSettings = "secret creation: check the secret settings of the same tenant row only"
)

// Statements of the Secrets repository.
var (
	qSecretInsert = tenantQuery(
		`INSERT INTO secrets (id, tenant_id, token_hash, state, creator_kind, sender_email, api_token_id, invitation_id,
		delivery, recipient_email, read_receipt, verifier, key_verifier, kdf_salt, kdf_iterations, text_sealed,
		text_key_id, duration_code, created_at, activated_at, expires_at, file_size, file_metadata, file_storage_name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	// qSecretSettings reads, after the insertion, the status and the
	// secret settings of the tenant of the new secret.
	qSecretSettings = reviewedTenantQuery(
		`SELECT n.status, n.secrets_enabled, n.secret_durations, n.secret_file_allowed, n.secret_file_max_bytes,
		n.secret_email_allowed, n.secret_email_requires_passphrase, n.storage_quota_bytes
		FROM secrets s JOIN tenants n ON n.id = s.tenant_id WHERE s.tenant_id = ? AND s.id = ?`,
		reasonSecretSettings)
	qSecretCountOpenBySender = tenantQuery(
		`SELECT count(*) FROM secrets WHERE tenant_id = ? AND sender_email = ? AND api_token_id IS NULL
		AND state IN ('pending', 'active')`)
	qSecretCountRecentBySender = tenantQuery(
		`SELECT count(*) FROM secrets WHERE tenant_id = ? AND sender_email = ? AND api_token_id IS NULL
		AND created_at > ?`)
	qSecretCountOpenByToken = tenantQuery(
		`SELECT count(*) FROM secrets WHERE tenant_id = ? AND api_token_id = ? AND state IN ('pending', 'active')`)
	qSecretCountRecentByToken = tenantQuery(
		`SELECT count(*) FROM secrets WHERE tenant_id = ? AND api_token_id = ? AND created_at > ?`)
	qSecretGet = tenantQuery(
		`SELECT ` + secretColumns + ` FROM secrets WHERE tenant_id = ? AND id = ?`)
	qSecretGetByHash = tenantQuery(
		`SELECT ` + secretColumns + ` FROM secrets WHERE tenant_id = ? AND token_hash = ?`)
	qSecretKeyVerifierByHash = tenantQuery(
		`SELECT id, state, expires_at, end_reason, key_verifier FROM secrets WHERE tenant_id = ? AND token_hash = ?`)
	// qSecretClaim claims an attempt slot (e2e-format.md 3.3.4): it holds
	// the row until the end of the transaction.
	qSecretClaim = tenantQuery(
		`UPDATE secrets SET failed_proofs = failed_proofs + 1
		WHERE tenant_id = ? AND id = ? AND state = 'active' AND expires_at > ? AND failed_proofs < 5`)
	qSecretContent = tenantQuery(
		`SELECT failed_proofs, verifier, text_sealed, text_key_id, file_metadata, file_size
		FROM secrets WHERE tenant_id = ? AND id = ?`)
	qSecretMarkRead = tenantQuery(
		`UPDATE secrets SET state = 'read', failed_proofs = failed_proofs - 1, read_at = ?, ended_at = ?,
		end_reason = 'read', ` + secretContentNull + `
		WHERE tenant_id = ? AND id = ? AND state = 'active' AND file_size IS NULL`)
	// qSecretMarkReadGrant is qSecretMarkRead for a secret with a file:
	// the stored file and its key stay, behind the one-time grant.
	qSecretMarkReadGrant = tenantQuery(
		`UPDATE secrets SET state = 'read', failed_proofs = failed_proofs - 1, read_at = ?, ended_at = ?,
		end_reason = 'read', ` + secretContentNull + `, file_grant_hash = ?, file_grant_expires_at = ?
		WHERE tenant_id = ? AND id = ? AND state = 'active' AND file_size IS NOT NULL`)
	qSecretLock = tenantQuery(
		`UPDATE secrets SET state = 'locked', ended_at = ?, end_reason = 'locked', ` + secretContentNull + `, ` + secretFileNull + `
		WHERE tenant_id = ? AND id = ? AND state = 'active' AND failed_proofs = 5`)
	qSecretExpire = tenantQuery(
		`UPDATE secrets SET state = 'expired', ended_at = ?, end_reason = 'expired', ` + secretContentNull + `, ` + secretFileNull + `
		WHERE tenant_id = ? AND id = ? AND state = 'active' AND expires_at <= ?`)
	qSecretMarkDeleted = tenantQuery(
		`UPDATE secrets SET state = 'deleted', ended_at = ?, end_reason = ?, ` + secretContentNull + `, ` + secretFileNull + `
		WHERE tenant_id = ? AND id = ? AND state IN ('pending', 'active')`)
	qSecretDeletePending = tenantQuery(
		`DELETE FROM secrets WHERE tenant_id = ? AND id = ? AND state = 'pending' AND created_at <= ?`)
	qSecretDeleteRow = tenantQuery(
		`DELETE FROM secrets WHERE tenant_id = ? AND id = ?`)
	qSecretListTenant = tenantQuery(
		`SELECT ` + secretColumns + ` FROM secrets WHERE tenant_id = ? AND (created_at, id) < (?, ?)
		ORDER BY created_at DESC, id DESC LIMIT ?`)
	qSecretListSender = tenantQuery(
		`SELECT ` + secretColumns + ` FROM secrets WHERE tenant_id = ? AND sender_email = ? AND api_token_id IS NULL
		AND (created_at, id) < (?, ?) ORDER BY created_at DESC, id DESC LIMIT ?`)
	// The empty filters match everything (administration).
	qSecretListAdmin = tenantQuery(
		`SELECT ` + secretColumns + ` FROM secrets WHERE tenant_id = ? AND (? = '' OR state = ?)
		AND (? = '' OR sender_email = ?) AND (created_at, id) < (?, ?)
		ORDER BY created_at DESC, id DESC LIMIT ?`)
	qSecretAll = tenantQuery(
		`SELECT ` + secretColumns + ` FROM secrets WHERE tenant_id = ? ORDER BY id LIMIT ?`)
	qSecretBySender = tenantQuery(
		`SELECT ` + secretColumns + ` FROM secrets WHERE tenant_id = ? AND sender_email = ? ORDER BY id`)
	qSecretByRecipient = tenantQuery(
		`SELECT ` + secretColumns + ` FROM secrets WHERE tenant_id = ? AND recipient_email = ? ORDER BY id`)
	qSecretCountByAddress = tenantQuery(
		`SELECT count(*) FROM secrets WHERE tenant_id = ? AND (sender_email = ? OR recipient_email = ?)`)
	qSecretTombstonePurgeList = tenantQuery(
		`SELECT id FROM secrets WHERE tenant_id = ? AND ended_at <= ? AND file_key_id IS NULL AND id > ?
		ORDER BY id LIMIT ?`)
	qSecretTombstonePurge = tenantQuery(
		`DELETE FROM secrets WHERE tenant_id = ? AND id = ? AND ended_at <= ? AND file_key_id IS NULL
		AND text_key_id IS NULL`)

	qSecretDuePending = systemQuery(
		`SELECT tenant_id, id, created_at FROM secrets WHERE state = 'pending' AND created_at <= ?
		AND (created_at, tenant_id, id) > (?, ?, ?)
		ORDER BY created_at, tenant_id, id LIMIT ?`,
		reasonSecretSweep)
	qSecretDueExpiry = systemQuery(
		`SELECT tenant_id, id, expires_at FROM secrets WHERE state = 'active' AND expires_at <= ?
		AND (expires_at, tenant_id, id) > (?, ?, ?)
		ORDER BY expires_at, tenant_id, id LIMIT ?`,
		reasonSecretSweep)
)

// secretRow is a scanned secret with its key IDs.
type secretRow struct {
	Secret
	textKeyID string
	fileKeyID string
}

// keyIDs returns the key IDs the row references.
func (r secretRow) keyIDs() []string {
	var out []string
	for _, k := range []string{r.textKeyID, r.fileKeyID} {
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

// scanSecret reads one row of secretColumns for tenant tid.
func scanSecret(sc interface{ Scan(...any) error }, tid tenant.ID) (secretRow, error) {
	var (
		r                                       secretRow
		state, kind, delivery, duration         string
		apiTok, inv, recipient, reason, storage sql.NullString
		textKey, fileKey                        sql.NullString
		iterations                              sql.NullInt64
		fileSize                                sql.NullInt64
		receipt, activated, expires, read       sql.NullInt64
		ended, uploaded, downloaded             sql.NullInt64
		created                                 int64
	)
	err := sc.Scan(&r.ID, &state, &kind, &r.SenderEmail, &apiTok, &inv, &delivery, &recipient,
		&r.ReadReceipt, &receipt, &r.KDFSalt, &iterations, &duration, &created, &activated, &expires,
		&read, &ended, &reason, &r.FailedProofs, &fileSize, &storage, &uploaded, &downloaded,
		&textKey, &fileKey)
	if err != nil {
		return secretRow{}, err
	}
	r.TenantID = tid
	r.State, r.CreatorKind, r.Delivery = SecretState(state), SecretCreatorKind(kind), SecretDelivery(delivery)
	r.Duration = tenant.SecretDuration(duration)
	r.APITokenID, r.InvitationID, r.RecipientEmail = apiTok.String, inv.String, recipient.String
	r.EndReason = SecretEndReason(reason.String)
	r.KDFIterations = int(iterations.Int64)
	if len(r.KDFSalt) == 0 {
		r.KDFSalt = nil
	}
	r.FileSize, r.FileStorageName = fileSize.Int64, storage.String
	r.CreatedAt = fromMillis(created)
	r.ReceiptSentAt, r.ActivatedAt, r.ExpiresAt = nullMillis(receipt), nullMillis(activated), nullMillis(expires)
	r.ReadAt, r.EndedAt = nullMillis(read), nullMillis(ended)
	r.FileUploadedAt, r.FileDownloadedAt = nullMillis(uploaded), nullMillis(downloaded)
	r.textKeyID, r.fileKeyID = textKey.String, fileKey.String
	return r, nil
}

// Secrets is the repository of the one-time secrets of the tenants.
// Obtain it with [DB.Secrets].
type Secrets struct {
	db       *DB
	keys     SecretKeys
	newToken func() (string, error) // id.NewSecretToken; replaced in tests
	newGrant func() (string, error) // id.NewSecretGrant; replaced in tests
}

// Secrets returns the secret repository using keys for the server data
// keys of the secrets. keys may be nil for the operations that touch no
// key (Get, StatusByToken, lists, counts, PurgeTombstones); the others then
// fail.
func (db *DB) Secrets(keys SecretKeys) *Secrets {
	return &Secrets{db: db, keys: keys, newToken: id.NewSecretToken, newGrant: id.NewSecretGrant}
}

// Stages of a reveal reported to secretRevealHook.
const (
	// revealStageClaim: the key proof is right, the write transaction is
	// about to start.
	revealStageClaim = "claim"
	// revealStageCompare: a slot is claimed, the proof is about to be
	// compared (counted by the concurrency test).
	revealStageCompare = "compare"
)

// secretRevealHook, when set by a test (before any test runs), is called
// with the stage and the secret ID at each stage of a reveal.
var secretRevealHook func(stage, secID string)

// normalizeCreateSecret checks the input of Create, independent of the
// database, and normalizes the addresses.
func normalizeCreateSecret(c CreateSecret) (CreateSecret, error) {
	if !c.CreatorKind.valid() {
		return c, invalid("unknown creator kind")
	}
	if (c.CreatorKind == SecretCreatorAPIToken) != (c.APITokenID != "") {
		return c, invalid("an API token creator needs its token, and only it")
	}
	if (c.CreatorKind == SecretCreatorExternal) != (c.InvitationID != "") {
		return c, invalid("an external creator needs its invitation, and only it")
	}
	email, err := NormalizeEmail(c.SenderEmail)
	if err != nil {
		return c, err
	}
	c.SenderEmail = email
	if c.CreatorKind == SecretCreatorExternal {
		c.Delivery, c.RecipientEmail = SecretDeliveryEmail, "" // the inviter, read by Create
	}
	switch c.Delivery {
	case SecretDeliveryLink:
		if c.RecipientEmail != "" {
			return c, invalid("a link secret has no recipient")
		}
	case SecretDeliveryEmail:
		if c.CreatorKind != SecretCreatorExternal {
			if c.RecipientEmail, err = NormalizeEmail(c.RecipientEmail); err != nil {
				return c, err
			}
		}
	default:
		return c, invalid("unknown delivery")
	}
	if len(c.Verifier) != secretVerifierLen || len(c.KeyVerifier) != secretVerifierLen {
		return c, invalid("verifiers must be %d bytes", secretVerifierLen)
	}
	if c.KDFSalt != nil && len(c.KDFSalt) != SecretKDFSaltLen {
		return c, invalid("the passphrase salt must be %d bytes", SecretKDFSaltLen)
	}
	if len(c.SealedText) < MinSecretSealedTextLen || !isBase64URL(c.SealedText, MaxSecretSealedTextLen) {
		return c, invalid("malformed sealed text")
	}
	if !c.Duration.Valid() {
		return c, invalid("unknown duration")
	}
	switch {
	case c.FileSize < 0 || c.FileSize > tenant.MaxSecretFileBytes:
		return c, invalid("file size out of range")
	case c.FileSize == 0 && (c.FileMetadata != "" || c.FileStorageName != ""):
		return c, invalid("file metadata and storage name need a file")
	case c.FileSize > 0 && !isBase64URL(c.FileMetadata, MaxSecretFileMetadataLen):
		return c, invalid("malformed file metadata")
	case c.FileSize > 0 && !isLowerHex(c.FileStorageName, secretStorageNameLen):
		return c, invalid("malformed file storage name")
	}
	return c, nil
}

// Create stores a new secret of tenant tid, in one transaction under the
// tenant lock: the creator limits (SecretMaxOpen pending and active
// secrets, SecretMaxDaily creations in SecretDailyWindow, per address for
// the sessions and per API token for the tokens), a new text data key
// (SecretKeys.NewDEKTx) encrypting the sealed text at rest (the TTEF
// stream format of internal/crypto, bound to the tenant and the secret
// ID), the row, then the tenant settings (module on, duration offered,
// file allowed and within the limit, e-mail delivery allowed, passphrase
// when required). The secret is active at once (expiry from Now) for the
// link delivery without file, pending otherwise (the upload of the file
// or the send call activates it). An external creator's secret goes by
// e-mail to the inviter of its invitation, whose address must be
// SenderEmail.
//
// It returns the secret with its token, shown once. Errors: ErrInvalid
// for a malformed input; ErrNotFound for an unknown or unusable API token,
// an unknown invitation or a tenant being deleted; ErrSecretOpenLimit and
// ErrSecretDailyLimit (ErrLimitReached); the ErrSecretPolicy errors.
func (r *Secrets) Create(ctx context.Context, tid tenant.ID, c CreateSecret) (CreatedSecret, error) {
	if r.keys == nil {
		return CreatedSecret{}, errSecretNoKeys
	}
	c, err := normalizeCreateSecret(c)
	if err != nil {
		return CreatedSecret{}, err
	}
	secID, err := r.db.newID(id.Secret)
	if err != nil {
		return CreatedSecret{}, wrap("create secret", err)
	}
	token, err := r.newToken()
	if err != nil {
		return CreatedSecret{}, wrap("create secret", err)
	}
	now := r.db.orNow(c.Now).UTC().Truncate(time.Millisecond)
	out, err := writeScopedValue(ctx, r.db, tid, "create secret", func(tx *ScopedTx) (Secret, error) {
		return r.createTx(ctx, tx, secID, id.HashToken(token), c, now)
	})
	if err != nil {
		return CreatedSecret{}, err
	}
	return CreatedSecret{Secret: out, Token: token}, nil
}

// createTx implements Create inside tx.
func (r *Secrets) createTx(ctx context.Context, tx *ScopedTx, secID string, tokenHash []byte, c CreateSecret, now time.Time) (Secret, error) {
	if err := tx.lock(ctx); err != nil {
		return Secret{}, err
	}
	if err := r.checkCreator(ctx, tx, &c, now); err != nil {
		return Secret{}, err
	}
	var used int64
	if c.FileSize > 0 {
		// Under the tenant lock, before the row is counted: the same rule
		// as a transfer deposit (spec 8.5).
		var err error
		if used, err = usedBytesTx(ctx, tx); err != nil {
			return Secret{}, err
		}
	}
	wkID, dek, err := r.keys.NewDEKTx(ctx, tx)
	if err != nil {
		return Secret{}, err
	}
	sealed, err := sealSecretText(dek, tx.Tenant(), secID, c.SealedText)
	clear(dek)
	if err != nil {
		return Secret{}, err
	}
	state := SecretPending
	var activated, expires any
	if c.Delivery == SecretDeliveryLink && c.FileSize == 0 {
		state = SecretActive
		activated, expires = toMillis(now), toMillis(now.Add(c.Duration.Duration()))
	}
	var iterations any
	if c.KDFSalt != nil {
		iterations = SecretKDFIterations
	}
	var fileSize any
	if c.FileSize > 0 {
		fileSize = c.FileSize
	}
	_, err = tx.Exec(ctx, qSecretInsert, secID, tokenHash, string(state), string(c.CreatorKind), c.SenderEmail,
		nullText(c.APITokenID), nullText(c.InvitationID), string(c.Delivery), nullText(c.RecipientEmail),
		c.ReadReceipt, c.Verifier, c.KeyVerifier, c.KDFSalt, iterations, sealed, wkID, string(c.Duration),
		toMillis(now), activated, expires, fileSize, nullText(c.FileMetadata), nullText(c.FileStorageName))
	if err != nil {
		return Secret{}, err
	}
	if err := checkSecretSettings(ctx, tx, secID, c, used); err != nil {
		return Secret{}, err
	}
	row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
	return row.Secret, err
}

// checkCreator checks the API token or the invitation of the creator (an
// external's recipient becomes its inviter) and the creator limits.
func (r *Secrets) checkCreator(ctx context.Context, tx *ScopedTx, c *CreateSecret, now time.Time) error {
	openQ, recentQ, owner := qSecretCountOpenBySender, qSecretCountRecentBySender, c.SenderEmail
	switch c.CreatorKind {
	case SecretCreatorAPIToken:
		if err := checkAPIToken(ctx, tx, c.APITokenID, now); err != nil {
			return err
		}
		openQ, recentQ, owner = qSecretCountOpenByToken, qSecretCountRecentByToken, c.APITokenID
	case SecretCreatorExternal:
		inv, err := scanInvitation(tx.QueryRow(ctx, qInvitationGet, c.InvitationID))
		if err != nil {
			return err
		}
		if inv.Email != c.SenderEmail {
			return invalid("the invitation belongs to another address")
		}
		c.RecipientEmail = inv.InvitedBy
	}
	var open, recent int
	if err := tx.QueryRow(ctx, openQ, owner).Scan(&open); err != nil {
		return err
	}
	if open >= SecretMaxOpen {
		return ErrSecretOpenLimit
	}
	if err := tx.QueryRow(ctx, recentQ, owner, toMillis(now.Add(-SecretDailyWindow))).Scan(&recent); err != nil {
		return err
	}
	if recent >= SecretMaxDaily {
		return ErrSecretDailyLimit
	}
	return nil
}

// checkSecretSettings checks the new secret secID against the status, the
// secret settings and the storage quota of its tenant, read in the creation
// transaction; used is the storage the tenant used before the secret.
func checkSecretSettings(ctx context.Context, tx *ScopedTx, secID string, c CreateSecret, used int64) error {
	var (
		status, durations                                      string
		enabled, fileAllowed, emailAllowed, passphraseRequired bool
		fileMax, quota                                         int64
	)
	err := tx.QueryRow(ctx, qSecretSettings, secID).Scan(&status, &enabled, &durations, &fileAllowed, &fileMax,
		&emailAllowed, &passphraseRequired, &quota)
	if err != nil {
		return err
	}
	// The column check makes a parse error impossible; an empty set would
	// offer nothing.
	set, _ := tenant.ParseSecretDurationSet(durations)
	switch {
	case tenant.Status(status) != tenant.StatusActive:
		return ErrNotFound
	case !enabled:
		return ErrSecretsDisabled
	case !set.Has(c.Duration):
		return ErrSecretDurationNotOffered
	case c.FileSize > 0 && !fileAllowed:
		return ErrSecretFileNotAllowed
	case c.FileSize > fileMax:
		return ErrSecretFileTooLarge
	case c.FileSize > 0 && c.FileSize > quota-used:
		return ErrSecretQuotaExceeded
	case c.Delivery == SecretDeliveryEmail && !emailAllowed:
		return ErrSecretEmailNotAllowed
	case c.Delivery == SecretDeliveryEmail && passphraseRequired && c.KDFSalt == nil:
		return ErrSecretPassphraseRequired
	}
	return nil
}

// sealSecretText encrypts the sealed text at rest with dek, bound to the
// tenant and the secret (crypto.NewWriter, the TTEF format of the transfer
// files).
func sealSecretText(dek []byte, tid tenant.ID, secID, text string) ([]byte, error) {
	var buf bytes.Buffer
	w, err := crypto.NewWriter(&buf, dek, string(tid), secID)
	if err != nil {
		return nil, err
	}
	// Writing to a bytes.Buffer cannot fail, and Close only emits the
	// final chunk: no error can happen past NewWriter.
	_, _ = io.WriteString(w, text)
	_ = w.Close()
	return buf.Bytes(), nil
}

// openSecretText decrypts a text sealed by sealSecretText.
func openSecretText(dek []byte, tid tenant.ID, secID string, sealed []byte) (string, error) {
	rd, err := crypto.NewReader(bytes.NewReader(sealed), dek, string(tid), secID)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(rd)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Get returns the secret secID of tenant tid, whatever its state, or
// ErrNotFound (also for another tenant's secret). The creator side checks
// the caller with [SecretActor.Owns].
func (r *Secrets) Get(ctx context.Context, tid tenant.ID, secID string) (Secret, error) {
	if !id.Valid(id.Secret, secID) {
		return Secret{}, fmt.Errorf("store: get secret: %w", ErrNotFound)
	}
	return readScoped(ctx, r.db, tid, "get secret", func(tx *ScopedTx) (Secret, error) {
		row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tid)
		return row.Secret, err
	})
}

// goneReason returns the reason a secret is no longer readable at now
// ("" when it is active and not expired).
func goneReason(state SecretState, reason SecretEndReason, expires time.Time, now time.Time) SecretEndReason {
	switch {
	case state != SecretActive:
		return reason
	case !expires.After(now):
		return SecretEndExpired
	}
	return ""
}

// StatusByToken returns the secret of tenant tid whose link carries
// token, as seen at now: an active secret past its expiry is reported as
// SecretExpired (end reason expired, EndedAt its expiry, no salt) before
// the lifecycle sweep changed it. It returns ErrNotFound for a malformed
// or unknown token, a token of another tenant and a pending secret (never
// delivered; ErrSecretPending, which wraps ErrNotFound). The caller answers
// a tombstone with its end reason.
func (r *Secrets) StatusByToken(ctx context.Context, tid tenant.ID, token string, now time.Time) (Secret, error) {
	if !id.SecretTokenValid(token) {
		return Secret{}, fmt.Errorf("store: secret status: %w", ErrNotFound)
	}
	s, err := readScoped(ctx, r.db, tid, "secret status", func(tx *ScopedTx) (Secret, error) {
		row, err := scanSecret(tx.QueryRow(ctx, qSecretGetByHash, id.HashToken(token)), tid)
		return row.Secret, err
	})
	if err != nil {
		return Secret{}, err
	}
	if s.State == SecretPending {
		return Secret{}, fmt.Errorf("store: secret status: %w", ErrSecretPending)
	}
	if s.State == SecretActive && !s.ExpiresAt.After(now) {
		s.State, s.EndReason, s.EndedAt = SecretExpired, SecretEndExpired, s.ExpiresAt
		s.KDFSalt, s.KDFIterations = nil, 0
	}
	return s, nil
}

// Reveal reveals the secret of tenant tid whose link carries token, with
// the key proof and the proof of the recipient (e2e-format.md 3.3.4,
// data-model-v2.1.md 2.1 "Proofs"):
//
//  1. read: an unknown secret is ErrNotFound, a pending one
//     ErrSecretPending (wrapping ErrNotFound), a tombstone or an
//     active secret past its expiry a [*SecretGoneError]; SHA-256(keyProof)
//     is compared with the key verifier in constant time, and a mismatch
//     is ErrSecretKeyProof, neither counted nor written;
//  2. in one write transaction (BEGIN IMMEDIATE on SQLite, a row lock on
//     PostgreSQL): an attempt slot is claimed (failed_proofs + 1 while
//     below SecretMaxFailedProofs, active and not expired; none: a
//     [*SecretGoneError] with the reason of the row), then the proof is
//     compared in constant time (the key verifier of a live secret never
//     changes);
//  3. both right: the secret becomes read (the slot released), its content
//     and verifiers cleared, its text key destroyed after the row change,
//     and the sealed text decrypted and returned;
//  4. wrong proof: the slot stays counted and a [*SecretProofError] is
//     returned with the attempts left; the fifth locks the secret (content
//     cleared, keys destroyed) in the same transaction, Remaining 0 and
//     RemovedFile the stored file the caller removes at once.
//
// Concurrent reveals of one secret therefore compare at most
// SecretMaxFailedProofs proofs in all, and exactly one can succeed. For a
// secret with a file, the success also draws the one-time file grant
// (data-model-v2.1.md 2.1): its SHA-256 is stored, valid
// SecretFileGrantLifetime, and the grant returned once with the sealed
// file metadata; the stored file and its key stay until
// [Secrets.CompleteFileDownload] or [Secrets.ExpireGrants]. The caller
// scrubs the database after a success or a lock (keys destroyed).
func (r *Secrets) Reveal(ctx context.Context, tid tenant.ID, token string, keyProof, proof [32]byte, now time.Time) (RevealedSecret, error) {
	if r.keys == nil {
		return RevealedSecret{}, errSecretNoKeys
	}
	if !id.SecretTokenValid(token) {
		return RevealedSecret{}, fmt.Errorf("store: reveal secret: %w", ErrNotFound)
	}
	hash := id.HashToken(token)
	secID, err := readScoped(ctx, r.db, tid, "reveal secret", func(tx *ScopedTx) (string, error) {
		return checkKeyProof(ctx, tx, hash, keyProof, now)
	})
	if err != nil {
		return RevealedSecret{}, err
	}
	if secretRevealHook != nil {
		secretRevealHook(revealStageClaim, secID)
	}
	var (
		out     RevealedSecret
		outcome error
	)
	err = writeScoped(ctx, r.db, tid, "reveal secret", func(tx *ScopedTx) error {
		var err error
		out, outcome, err = r.revealTx(ctx, tx, secID, proof, now)
		return err
	})
	if err != nil {
		return RevealedSecret{}, err
	}
	if outcome != nil {
		return RevealedSecret{}, outcome
	}
	return out, nil
}

// checkKeyProof reads the secret of token hash hash and checks the key
// proof, returning the secret ID (step 1 of Reveal).
func checkKeyProof(ctx context.Context, tx *ScopedTx, hash []byte, keyProof [32]byte, now time.Time) (string, error) {
	var (
		secID, state string
		reason       sql.NullString
		expires      sql.NullInt64
		keyVerifier  []byte
	)
	err := tx.QueryRow(ctx, qSecretKeyVerifierByHash, hash).Scan(&secID, &state, &expires, &reason, &keyVerifier)
	if err != nil {
		return "", err
	}
	if SecretState(state) == SecretPending {
		return "", ErrSecretPending
	}
	if gone := goneReason(SecretState(state), SecretEndReason(reason.String), nullMillis(expires), now); gone != "" {
		return "", &SecretGoneError{Reason: gone}
	}
	if !tte2.VerifierMatches(keyVerifier, keyProof[:]) {
		return "", ErrSecretKeyProof
	}
	return secID, nil
}

// revealTx runs steps 2 to 4 of Reveal inside tx. It returns the revealed
// secret, or the outcome to return once tx committed (a counted wrong
// proof), or an error that rolls tx back.
func (r *Secrets) revealTx(ctx context.Context, tx *ScopedTx, secID string, proof [32]byte,
	now time.Time,
) (RevealedSecret, error, error) {
	n, err := execCount(ctx, tx, qSecretClaim, secID, toMillis(now))
	if err != nil {
		return RevealedSecret{}, nil, err
	}
	if n == 0 {
		row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
		if err != nil {
			return RevealedSecret{}, nil, err
		}
		// Active, not expired, all slots taken is only possible inside a
		// transaction, so never observed: it would be answered as locked.
		reason := cmp.Or(goneReason(row.State, row.EndReason, row.ExpiresAt, now), SecretEndLocked)
		return RevealedSecret{}, nil, &SecretGoneError{Reason: reason}
	}
	var (
		failed           int
		verifier, sealed []byte
		textKey          sql.NullString
		metadata         sql.NullString
		fileSize         sql.NullInt64
	)
	err = tx.QueryRow(ctx, qSecretContent, secID).Scan(&failed, &verifier, &sealed, &textKey, &metadata, &fileSize)
	if err != nil {
		return RevealedSecret{}, nil, err
	}
	if secretRevealHook != nil {
		secretRevealHook(revealStageCompare, secID)
	}
	// The key proof was checked in step 1: the key verifier of a live
	// secret never changes.
	proofOK := tte2.VerifierMatches(verifier, proof[:])
	switch {
	case !proofOK && failed < SecretMaxFailedProofs:
		return RevealedSecret{}, &SecretProofError{ID: secID, Remaining: SecretMaxFailedProofs - failed}, nil
	case !proofOK:
		file, err := r.lockTx(ctx, tx, secID, now)
		if err != nil {
			return RevealedSecret{}, nil, err
		}
		return RevealedSecret{}, &SecretProofError{ID: secID, Remaining: 0, RemovedFile: file}, nil
	}
	dek, err := r.keys.OpenTx(ctx, tx, crypto.PurposeDEK, textKey.String)
	if err != nil {
		return RevealedSecret{}, nil, err
	}
	text, err := openSecretText(dek, tx.Tenant(), secID, sealed)
	clear(dek)
	if err != nil {
		return RevealedSecret{}, nil, err
	}
	out := RevealedSecret{SealedText: text, FileMetadata: metadata.String}
	if fileSize.Valid {
		if out.FileGrant, err = r.newGrant(); err != nil {
			return RevealedSecret{}, nil, err
		}
		out.FileGrantExpiresAt = now.Add(SecretFileGrantLifetime)
		err = execOne(ctx, tx, qSecretMarkReadGrant, toMillis(now), toMillis(now), id.HashToken(out.FileGrant),
			toMillis(out.FileGrantExpiresAt), secID)
	} else {
		err = execOne(ctx, tx, qSecretMarkRead, toMillis(now), toMillis(now), secID)
	}
	if err != nil {
		return RevealedSecret{}, nil, err
	}
	if err := r.keys.DestroyTx(ctx, tx, textKey.String); err != nil {
		return RevealedSecret{}, nil, err
	}
	row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
	if err != nil {
		return RevealedSecret{}, nil, err
	}
	out.Secret = row.Secret
	return out, nil, nil
}

// lockTx locks the active secret secID whose fifth slot is claimed:
// content cleared, then its keys destroyed. It returns the storage name of
// the file the caller must remove ("" without stored file).
func (r *Secrets) lockTx(ctx context.Context, tx *ScopedTx, secID string, now time.Time) (string, error) {
	row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
	if err != nil {
		return "", err
	}
	if err := execOne(ctx, tx, qSecretLock, toMillis(now), secID); err != nil {
		return "", err
	}
	return row.FileStorageName, r.destroyKeys(ctx, tx, row.keyIDs())
}

// execOne runs q and returns ErrNotFound when it affected no row.
func execOne(ctx context.Context, tx *ScopedTx, q TenantQuery, args ...any) error {
	n, err := execCount(ctx, tx, q, args...)
	if err == nil && n == 0 {
		err = ErrNotFound
	}
	return err
}

// destroyKeys destroys the wrapped keys wkIDs inside tx, after the row that
// referenced them changed or went.
func (r *Secrets) destroyKeys(ctx context.Context, tx *ScopedTx, wkIDs []string) error {
	for _, k := range wkIDs {
		if err := r.keys.DestroyTx(ctx, tx, k); err != nil {
			return err
		}
	}
	return nil
}

// DeleteByCreator deletes the live secret secID of tenant tid for its
// creator actor ([SecretActor.Owns]): the row becomes a deleted tombstone
// (end reason deleted_by_creator, content and file columns cleared), then
// its keys are destroyed, in one transaction. It returns ErrNotFound for
// an unknown secret, another tenant's or another creator's, and a
// [*SecretGoneError] for a tombstone. The caller removes RemovedFile and
// scrubs the database.
func (r *Secrets) DeleteByCreator(ctx context.Context, tid tenant.ID, secID string, actor SecretActor, now time.Time) (EndedSecret, error) {
	return r.deleteLive(ctx, tid, secID, SecretEndDeletedByCreator, actor.Owns, now)
}

// DeleteByAdmin is [Secrets.DeleteByCreator] for an administrator of the
// tenant (end reason deleted_by_admin), whoever created the secret.
func (r *Secrets) DeleteByAdmin(ctx context.Context, tid tenant.ID, secID string, now time.Time) (EndedSecret, error) {
	return r.deleteLive(ctx, tid, secID, SecretEndDeletedByAdmin, func(Secret) bool { return true }, now)
}

// deleteLive implements DeleteByCreator and DeleteByAdmin.
func (r *Secrets) deleteLive(ctx context.Context, tid tenant.ID, secID string, reason SecretEndReason,
	allowed func(Secret) bool, now time.Time,
) (EndedSecret, error) {
	if r.keys == nil {
		return EndedSecret{}, errSecretNoKeys
	}
	if !id.Valid(id.Secret, secID) {
		return EndedSecret{}, fmt.Errorf("store: delete secret: %w", ErrNotFound)
	}
	return writeScopedValue(ctx, r.db, tid, "delete secret", func(tx *ScopedTx) (EndedSecret, error) {
		row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tid)
		if err != nil {
			return EndedSecret{}, err
		}
		if !allowed(row.Secret) {
			return EndedSecret{}, ErrNotFound
		}
		if !row.State.Live() {
			return EndedSecret{}, &SecretGoneError{Reason: row.EndReason}
		}
		return r.endTx(ctx, tx, row, qSecretMarkDeleted, toMillis(now), string(reason), secID)
	})
}

// endTx ends the live secret row with the guarded update q (args), then
// destroys its keys, and returns the tombstone.
func (r *Secrets) endTx(ctx context.Context, tx *ScopedTx, row secretRow, q TenantQuery, args ...any) (EndedSecret, error) {
	if err := execOne(ctx, tx, q, args...); err != nil {
		return EndedSecret{}, err
	}
	if err := r.destroyKeys(ctx, tx, row.keyIDs()); err != nil {
		return EndedSecret{}, err
	}
	after, err := scanSecret(tx.QueryRow(ctx, qSecretGet, row.ID), tx.Tenant())
	if err != nil {
		return EndedSecret{}, err
	}
	return EndedSecret{Secret: after.Secret, RemovedFile: row.FileStorageName}, nil
}

// deleteRowTx deletes the row of secret row (guarded by q and args, which
// must name the secret), then destroys its keys.
func (r *Secrets) deleteRowTx(ctx context.Context, tx *ScopedTx, row secretRow, q TenantQuery, args ...any) error {
	if err := execOne(ctx, tx, q, args...); err != nil {
		return err
	}
	return r.destroyKeys(ctx, tx, row.keyIDs())
}

// list returns a page of secrets with the list query q, run with args then
// the cursor and the limit.
func (r *Secrets) list(ctx context.Context, tid tenant.ID, op string, q TenantQuery, opts SecretListOptions, args ...any) (Page[Secret], error) {
	at, after, err := parseTimeCursor(opts.Cursor, id.Secret)
	if err != nil {
		return Page[Secret]{}, err
	}
	limit := pageLimit(opts.Limit)
	items, err := readScoped(ctx, r.db, tid, op, func(tx *ScopedTx) ([]Secret, error) {
		rows, err := tx.Query(ctx, q, append(args, at, after, limit+1)...)
		if err != nil {
			return nil, err
		}
		return collect(rows, func(rs *sql.Rows) (Secret, error) {
			row, err := scanSecret(rs, tid)
			return row.Secret, err
		})
	})
	if err != nil {
		return Page[Secret]{}, err
	}
	return paginate(items, limit, func(s Secret) string { return timeCursor(s.CreatedAt, s.ID) }), nil
}

// ListByTenant returns a page of the secrets of tenant tid, in every
// state, newest first, without content (administration). A malformed
// cursor yields ErrInvalid.
func (r *Secrets) ListByTenant(ctx context.Context, tid tenant.ID, opts SecretListOptions) (Page[Secret], error) {
	return r.list(ctx, tid, "list secrets", qSecretListTenant, opts)
}

// SecretFilter narrows the administration listing of the secrets; the zero
// value selects every secret.
type SecretFilter struct {
	// State selects one state; "" every state. An unknown state selects
	// nothing.
	State SecretState
	// Sender selects the secrets created by this address (exact match once
	// normalized, any creator kind); "" every creator. A malformed address
	// is ErrInvalid.
	Sender string
}

// ListFiltered returns a page of the secrets of tenant tid selected by f,
// in every creator kind, newest first, without content (administration). A
// malformed address or cursor yields ErrInvalid.
func (r *Secrets) ListFiltered(ctx context.Context, tid tenant.ID, f SecretFilter, opts SecretListOptions) (Page[Secret], error) {
	if f.Sender != "" {
		var err error
		if f.Sender, err = NormalizeEmail(f.Sender); err != nil {
			return Page[Secret]{}, err
		}
	}
	st := string(f.State)
	return r.list(ctx, tid, "list secrets", qSecretListAdmin, opts, st, st, f.Sender, f.Sender)
}

// ListBySender returns a page of the secrets of tenant tid created by a
// deposit session of the address email (any creator kind but the API
// tokens), newest first ("my transfers"). It returns ErrInvalid for a
// malformed address or cursor.
func (r *Secrets) ListBySender(ctx context.Context, tid tenant.ID, email string, opts SecretListOptions) (Page[Secret], error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return Page[Secret]{}, err
	}
	return r.list(ctx, tid, "list sender secrets", qSecretListSender, opts, email)
}

// SecretSweepLimit is the largest page of [Secrets.PurgePending] and
// [Secrets.ExpireDue].
const SecretSweepLimit = maxSweepPage

// sweep lists one page of due secrets with q (after its arguments args)
// and handles each of them in its own tenant transaction with fn, which
// returns false for a secret that changed meanwhile (skipped). It returns
// the handled secrets and whether the page was full (call again).
func (r *Secrets) sweep(ctx context.Context, op string, q SystemQuery, limit int,
	fn func(tx *ScopedTx, secID string) (EndedSecret, bool, error), args ...any,
) ([]EndedSecret, bool, error) {
	if r.keys == nil {
		return nil, false, errSecretNoKeys
	}
	due, err := r.db.sweepPage(ctx, reasonSecretSweep, op, q, SweepPage{Limit: limit}, args...)
	if err != nil {
		return nil, false, err
	}
	out := make([]EndedSecret, 0, len(due))
	for _, d := range due {
		var (
			e  EndedSecret
			ok bool
		)
		err := writeScoped(ctx, r.db, d.TenantID, op, func(tx *ScopedTx) error {
			var err error
			e, ok, err = fn(tx, d.TransferID)
			return err
		})
		if err != nil {
			return out, false, err
		}
		if ok {
			out = append(out, e)
		}
	}
	return out, len(due) == limit, nil
}

// PurgePending deletes up to limit (1 to SecretSweepLimit) pending secrets
// of every tenant created SecretPendingRetention or more before now
// (nothing was delivered: no tombstone), each in its own tenant
// transaction: the row, then its keys. It returns the deleted secrets (as
// they were, with the file to remove) and whether more may be due (call
// again). A secret activated meanwhile is skipped. The caller removes the
// files and scrubs the database.
func (r *Secrets) PurgePending(ctx context.Context, now time.Time, limit int) ([]EndedSecret, bool, error) {
	before := toMillis(now.Add(-SecretPendingRetention))
	return r.sweep(ctx, "purge pending secrets", qSecretDuePending, limit, func(tx *ScopedTx, secID string) (EndedSecret, bool, error) {
		row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
		if err != nil || row.State != SecretPending {
			return EndedSecret{}, false, ignoreNotFound(err)
		}
		if err := r.deleteRowTx(ctx, tx, row, qSecretDeletePending, secID, before); err != nil {
			return EndedSecret{}, false, ignoreNotFound(err)
		}
		return EndedSecret{Secret: row.Secret, RemovedFile: row.FileStorageName}, true, nil
	}, before)
}

// ExpireDue expires up to limit (1 to SecretSweepLimit) active secrets of
// every tenant whose expiry is at or before now, each in its own tenant
// transaction: the row becomes an expired tombstone (content and file
// cleared), then its keys are destroyed. It returns the tombstones (with
// the sender, recipient and receipt choice for the receipt mail of step
// 3, and the file to remove) and whether more may be due. A secret read or
// deleted meanwhile is skipped. The caller removes the files and scrubs
// the database.
func (r *Secrets) ExpireDue(ctx context.Context, now time.Time, limit int) ([]EndedSecret, bool, error) {
	at := toMillis(now)
	return r.sweep(ctx, "expire secrets", qSecretDueExpiry, limit, func(tx *ScopedTx, secID string) (EndedSecret, bool, error) {
		row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, secID), tx.Tenant())
		if err != nil || row.State != SecretActive {
			return EndedSecret{}, false, ignoreNotFound(err)
		}
		e, err := r.endTx(ctx, tx, row, qSecretExpire, at, secID, at)
		if err != nil {
			return EndedSecret{}, false, ignoreNotFound(err)
		}
		return e, true, nil
	}, at)
}

// ignoreNotFound maps ErrNotFound to nil.
func ignoreNotFound(err error) error {
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// PurgeTombstones deletes the tombstones of tenant tid ended
// SecretTombstoneRetention or more before now and holding no key (a read
// secret whose file grant is pending is cleaned by [Secrets.ExpireGrants]
// first), in batches of PurgeBatchSize, and returns how many it deleted.
// No key is destroyed: a tombstone references none.
func (r *Secrets) PurgeTombstones(ctx context.Context, tid tenant.ID, now time.Time) (int64, error) {
	before := toMillis(now.Add(-SecretTombstoneRetention))
	return r.db.purge(ctx, tid, "purge secret tombstones", false, func(ctx context.Context, tx *ScopedTx, after string, size int) (int64, string, bool, error) {
		return deleteEach(ctx, tx, qSecretTombstonePurgeList, []any{before}, after, size, qSecretTombstonePurge,
			func(k string) []any { return []any{k, before} })
	})
}

// DeleteTenant deletes every secret of tenant tid, in batches of
// PurgeBatchSize: the rows, then their keys, in each transaction. The
// erasure of a tenant calls it before it destroys the remaining wrapped
// keys of the tenant (a live secret's key cannot be destroyed first, see
// [Tenants.Delete]). It returns the storage names of the files to remove
// (the tenant directory goes anyway); the caller scrubs the database.
func (r *Secrets) DeleteTenant(ctx context.Context, tid tenant.ID) ([]string, error) {
	if r.keys == nil {
		return nil, errSecretNoKeys
	}
	var files []string
	for {
		var n int
		err := writeScoped(ctx, r.db, tid, "delete tenant secrets", func(tx *ScopedTx) error {
			rows, err := r.queryRows(ctx, tx, qSecretAll, r.db.purgeBatch)
			if err != nil {
				return err
			}
			n = len(rows)
			for _, row := range rows {
				if err := r.deleteRowTx(ctx, tx, row, qSecretDeleteRow, row.ID); err != nil {
					return err
				}
				if row.FileStorageName != "" {
					files = append(files, row.FileStorageName)
				}
			}
			return nil
		})
		if err != nil {
			return files, err
		}
		if n < r.db.purgeBatch {
			return files, nil
		}
	}
}

// queryRows runs q in tx and scans every secret row.
func (r *Secrets) queryRows(ctx context.Context, tx *ScopedTx, q TenantQuery, args ...any) ([]secretRow, error) {
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(rs *sql.Rows) (secretRow, error) { return scanSecret(rs, tx.Tenant()) })
}

// CountByAddress counts the secrets of tenant tid whose sender or
// recipient is the address email, in every state (data-subject summary).
// It returns ErrInvalid for a malformed address.
func (r *Secrets) CountByAddress(ctx context.Context, tid tenant.ID, email string) (int, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	return readScoped(ctx, r.db, tid, "count secrets by address", func(tx *ScopedTx) (int, error) {
		var n int
		err := tx.QueryRow(ctx, qSecretCountByAddress, email, email).Scan(&n)
		return n, err
	})
}

// DeleteByAddressTx deletes, inside tx, every secret of the tenant tx is
// bound to whose sender or recipient is the address email, in every state
// (data-subject erasure, spec 20): the rows, then their keys. It runs
// before the invitations of the address are deleted (the secrets of an
// invited external reference its invitation). It returns ErrInvalid for a
// malformed address; the caller removes the files and scrubs the database.
// After an error the caller must abort tx.
func (r *Secrets) DeleteByAddressTx(ctx context.Context, tx *ScopedTx, email string) (SecretErasure, error) {
	if r.keys == nil {
		return SecretErasure{}, errSecretNoKeys
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return SecretErasure{}, err
	}
	var out SecretErasure
	for _, q := range []TenantQuery{qSecretBySender, qSecretByRecipient} {
		rows, err := r.queryRows(ctx, tx, q, email)
		if err != nil {
			return SecretErasure{}, wrap("erase secrets", err)
		}
		for _, row := range rows {
			if err := r.deleteRowTx(ctx, tx, row, qSecretDeleteRow, row.ID); err != nil {
				return SecretErasure{}, wrap("erase secrets", err)
			}
			out.Deleted++
			if row.FileStorageName != "" {
				out.RemovedFiles = append(out.RemovedFiles, row.FileStorageName)
			}
		}
	}
	return out, nil
}

// DeleteByAddress is [Secrets.DeleteByAddressTx] in its own transaction of
// tenant tid.
func (r *Secrets) DeleteByAddress(ctx context.Context, tid tenant.ID, email string) (SecretErasure, error) {
	return writeScopedValue(ctx, r.db, tid, "erase secrets", func(tx *ScopedTx) (SecretErasure, error) {
		return r.DeleteByAddressTx(ctx, tx, email)
	})
}

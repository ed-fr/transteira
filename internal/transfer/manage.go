package transfer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Details is a transfer as its sender sees it (OpenAPI SenderTransfer).
type Details struct {
	// ID is the transfer identifier ("trf_" + ULID).
	ID string
	// Status is the life-cycle state.
	Status store.TransferStatus
	// SenderEmail is the normalized sender address.
	SenderEmail string
	// Recipients are the normalized recipient addresses, in order.
	Recipients []string
	// Message is the sanitized message, "" when none.
	Message string
	// ExpiryDays is the validity chosen by the sender.
	ExpiryDays int
	// ExpiresAt is the expiry of the download link, known once the transfer
	// became available (the chosen duration starts then): zero while it is
	// uploading or scanning, and for a rejected transfer.
	ExpiresAt time.Time
	// PasswordProtected reports whether the transfer has a password.
	PasswordProtected bool
	// DeleteAfterFirstDownload deletes the transfer after its first
	// download.
	DeleteAfterFirstDownload bool
	// TotalBytes is the sum of the declared sizes of the files.
	TotalBytes int64
	// CreatedAt is the creation time.
	CreatedAt time.Time
	// UploadExpiresAt is, while the transfer is uploading, when its
	// unfinished uploads expire, as the upload engine computes it from the
	// last upload activity of the transfer (TT_UPLOAD_TTL after it). Zero
	// once finalized.
	UploadExpiresAt time.Time
	// FinalizedAt is the finalization time (zero before).
	FinalizedAt time.Time
	// DownloadURL is the public download page of an available transfer
	// with a single shared link (created before 1.1), built from the FQDN
	// stored for the tenant and the unsealed download token ("" otherwise).
	// It carries a bearer token: never log it. A transfer with one link
	// per recipient never has one: those links are mailed to each
	// recipient only (P27, T-199).
	DownloadURL string
	// RecipientVerification reports whether each recipient must prove
	// their address by code before downloading.
	RecipientVerification bool
	// RecipientTracking is, once a transfer with one link per recipient is
	// available, the download tracking of each recipient, by position. It
	// never carries a link or a token. Nil otherwise.
	RecipientTracking []store.RecipientTracking
	// Files are the files, by position.
	Files []File
	// MaxDownloads is the limit on the download starts, nil for none.
	MaxDownloads *int
	// ConfidentialityLevel is the key of the level snapshotted at creation,
	// "" for a transfer without level.
	ConfidentialityLevel string
	// ConfidentialityLabel is the label of that level in the language of
	// the transfer (the tenant default when it has none), "" without level.
	ConfidentialityLabel string
	// Rules are the rules of the level as snapshotted at creation, nil
	// without level. Later changes of the level never affect them.
	Rules *store.ConfidentialityRules
}

// File is a file of a transfer as its sender sees it (OpenAPI SenderFile).
type File struct {
	// ID is the file identifier ("fil_" + ULID).
	ID string
	// Name is the original name (NFC).
	Name string
	// Size is the declared size, in bytes.
	Size int64
	// MediaType is the informational media type, "" when unknown.
	MediaType string
	// SHA256 is the SHA-256 computed during the upload, "" until the
	// upload completes.
	SHA256 string
	// ScanStatus is the antivirus state.
	ScanStatus store.ScanStatus
	// ScanSignature is the name of the signature detected in an infected
	// file, "" otherwise. It comes from clamd: escape it when displaying.
	ScanSignature string
	// UploadID is the tus upload identifier ("upl_" + base62), only while
	// the transfer is uploading ("" otherwise): the HTTP layer builds the
	// uploadUrl from it.
	UploadID string
	// UploadOffset is the durable upload offset (Size once complete); it is
	// meaningful only when UploadID is set.
	UploadOffset int64
}

// details converts d, a transfer of tenant t. While d is uploading, the
// upload engine gives the last activity of the transfer and its upload
// expiry, and every file carries its upload identifier and offset (Size
// for a completed file). Once d is available, a transfer with one link per
// recipient gets the tracking of its recipients (never their links), and a
// shared transfer gets its download token
// unsealed to build the download link (id.DownloadURL); a token that cannot
// be unsealed is logged and the transfer is returned without link, rather
// than failing the whole view.
func (s *Service) details(ctx context.Context, t *tenant.Tenant, d store.TransferDetails) (Details, error) {
	tid := t.ID
	out := Details{
		ID: d.ID, Status: d.Status, SenderEmail: d.SenderEmail, Recipients: d.Recipients, Message: d.Message,
		ExpiryDays: d.ExpiryDays, PasswordProtected: d.PasswordProtected(),
		DeleteAfterFirstDownload: d.DeleteAfterFirstDownload, TotalBytes: d.TotalBytes,
		CreatedAt: d.CreatedAt, FinalizedAt: d.FinalizedAt, Files: make([]File, len(d.Files)),
		MaxDownloads: d.MaxDownloads, ConfidentialityLevel: d.ConfidentialityLevel, Rules: d.Rules,
		RecipientVerification: d.RecipientVerification,
	}
	if d.ConfidentialityLevel != "" {
		out.ConfidentialityLabel = store.LevelLabel(d.ConfidentialityLabel, d.Language, t.DefaultLanguage, "en")
	}
	// The expires_at written at finalization is provisional: it becomes
	// the expiry when the antivirus makes the transfer available.
	if !d.AvailableAt.IsZero() {
		out.ExpiresAt = d.ExpiresAt
	}
	uploading := d.Status == store.TransferUploading
	var activity time.Time
	if uploading {
		var err error
		if activity, out.UploadExpiresAt, err = s.uploads.TransferActivity(ctx, tid, d.Files, d.CreatedAt); err != nil {
			return Details{}, fmt.Errorf("transfer: read upload activity: %w", err)
		}
	}
	for i, f := range d.Files {
		file := File{
			ID: f.ID, Name: f.Name, Size: f.Size, MediaType: f.MediaType, SHA256: f.SHA256, ScanStatus: f.ScanStatus,
			ScanSignature: f.ScanSignature,
		}
		if uploading {
			file.UploadID, file.UploadOffset = f.UploadID, f.Size
			if !f.Completed() {
				off, _, err := s.uploads.Offset(ctx, tid, f, d.CreatedAt, activity)
				if err != nil {
					return Details{}, fmt.Errorf("transfer: read upload offset: %w", err)
				}
				file.UploadOffset = off
			}
		}
		out.Files[i] = file
	}
	if d.LinkMode == store.LinkModePerRecipient {
		if !d.AvailableAt.IsZero() {
			tracking, err := s.repo.tracking(ctx, tid, d.ID)
			if err != nil {
				return Details{}, fmt.Errorf("transfer: read recipient tracking: %w", err)
			}
			out.RecipientTracking = tracking
		}
		return out, nil
	}
	if d.Status == store.TransferAvailable && d.DownloadTokenKeyID != "" {
		token, err := s.repo.downloadToken(ctx, tid, d.DownloadTokenKeyID)
		if err != nil {
			s.logger.ErrorContext(ctx, "transfer: cannot open the download token: download link omitted",
				slog.String("tenant", tid.String()), slog.String("transfer", d.ID), slog.String("error", err.Error()))
		} else {
			out.DownloadURL = id.DownloadURL(t.FQDN, string(token))
			clear(token)
		}
	}
	return out, nil
}

// Get returns the transfer trfID of tenant t as its sender sees it (OpenAPI
// getTransfer). Only the sender who created it, or the API token that
// created it, may read it ([store.Depositor.Owns]: same address and, for an
// external sender, same invitation; same token for a token transfer);
// anyone else gets ErrNotFound, as for an unknown transfer or a transfer of
// another tenant. The offsets of the incomplete files come
// from the upload engine while the transfer is uploading.
func (s *Service) Get(ctx context.Context, t *tenant.Tenant, sender Sender, trfID string) (Details, error) {
	if _, err := normalize(sender); err != nil {
		return Details{}, err
	}
	d, err := s.load(ctx, t.ID, sender, trfID)
	if err != nil {
		return Details{}, err
	}
	return s.details(ctx, t, d)
}

// Cancel deletes the transfer trfID of tenant t on behalf of its sender
// (OpenAPI cancelTransfer), with the cryptographic erasure of its files.
//
// In V1 a sender may only cancel a transfer that is still uploading:
// ErrConflict otherwise. The specification allows canceling any transfer
// that is not yet available, but a scanning transfer belongs to the
// antivirus worker (step 7), which reads its files: canceling it would
// race with the scan. Admins (and the V1.1 "My transfers") delete the
// others. ErrBusy reports an upload in progress on one of the files, and
// ErrNotFound a transfer the sender did not create.
//
// Order, under the upload lock of every file: the upload engine destroys
// the data keys of the files in one transaction, then their files on disk
// (T-110), then scrubs the deleted data from the SQLite WAL once; then the
// rows are deleted, which releases the quota. If the files cannot all be
// removed, the error is returned and the transfer remains, with its keys
// already destroyed: Finalize then refuses it (ErrConflict) and canceling
// again finishes the job.
func (s *Service) Cancel(ctx context.Context, t *tenant.Tenant, sender Sender, trfID string) error {
	email, err := normalize(sender)
	if err != nil {
		return err
	}
	d, unlock, err := s.lockUploading(ctx, t.ID, sender, trfID)
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.uploads.RemoveFiles(ctx, t.ID, d.Files); err != nil {
		return fmt.Errorf("transfer: remove files: %w", err)
	}
	err = s.repo.tx(ctx, t.ID, func(tx txRepo) error { return tx.deleteTransfer(ctx, trfID) })
	if err != nil {
		return storeError("delete transfer", err)
	}
	s.record(ctx, t, sender, email, audit.ActionTransferDeleted, trfID, map[string]any{"by": deletedBySender})
	return nil
}

// Finalize closes the uploads of the transfer trfID of tenant t on behalf
// of its sender (OpenAPI finalizeTransfer) and hands it to the antivirus:
// the transfer moves to scanning, with its finalization and expiry times
// set. Checks, in order:
//
//  1. eligibility, checked again (T-25): ErrForbidden;
//  2. the transfer exists and belongs to the sender: ErrNotFound (for an
//     API token sender, this check comes first, and the eligibility of
//     step 1 applies to the sender address stored on the transfer);
//  3. it is uploading and has at least one file (tus terminations may
//     have removed them all; that is a state of the transfer rather than
//     an incomplete upload, hence state-conflict): ErrConflict; ErrBusy when
//     an upload is in progress (the files stay locked until the end, so
//     that no PATCH races with the checks);
//  4. every file still has its data key: ErrConflict otherwise (a
//     cancellation that failed after destroying the keys; the sender
//     cancels again);
//  5. every file is completely uploaded: *FilesError ErrIncomplete;
//  6. every computed SHA-256 equals the declared expectedSha256:
//     *FilesError ErrChecksumMismatch;
//  7. no computed SHA-256 is on the tenant blocklist (T-27):
//     ErrBlockedFile, logged as deposit_refused with reason blocklist. The
//     transfer stays uploading and is never made available; the sender may
//     cancel it, and the cleanup purges it after the upload TTL.
//
// After the commit, Options.OnFinalized and Options.Usage are called and
// the transfer.finalized audit event is recorded (best effort).
func (s *Service) Finalize(ctx context.Context, t *tenant.Tenant, sender Sender, trfID string) (Details, error) {
	var email string
	if sender.APITokenID == "" {
		var err error
		if email, _, err = s.checkEligible(ctx, t, sender); err != nil {
			return Details{}, err
		}
	} else if _, err := normalize(sender); err != nil {
		return Details{}, err
	}
	d, unlock, err := s.lockUploading(ctx, t.ID, sender, trfID)
	if err != nil {
		return Details{}, err
	}
	defer unlock()
	if sender.APITokenID != "" {
		sender.Email = d.SenderEmail
		if email, _, err = s.checkEligible(ctx, t, sender); err != nil {
			return Details{}, err
		}
	}
	if len(d.Files) == 0 {
		return Details{}, ErrConflict
	}
	var incomplete, mismatch []string
	var total int64
	for _, f := range d.Files {
		total += f.Size
		switch {
		case f.DEKKeyID == "":
			return Details{}, ErrConflict
		case !f.Completed():
			incomplete = append(incomplete, f.ID)
		case f.ExpectedSHA256 != "" && f.ExpectedSHA256 != f.SHA256:
			mismatch = append(mismatch, f.ID)
		}
	}
	if len(incomplete) > 0 {
		return Details{}, &FilesError{Kind: ErrIncomplete, FileIDs: incomplete}
	}
	if len(mismatch) > 0 {
		return Details{}, &FilesError{Kind: ErrChecksumMismatch, FileIDs: mismatch}
	}
	if err := s.checkBlockedFiles(ctx, t, sender, d.Files); err != nil {
		return Details{}, err
	}
	now := s.now()
	err = s.repo.tx(ctx, t.ID, func(tx txRepo) error { return tx.finalize(ctx, trfID, now) })
	if err != nil {
		return Details{}, storeError("finalize transfer", err)
	}
	s.onFinalized(t.ID, trfID)
	if s.usage != nil {
		s.usage.TransferFinalized(t.ID, total, now)
	}
	s.record(ctx, t, sender, email, audit.ActionTransferFinalized, trfID,
		map[string]any{"fileCount": len(d.Files), "totalBytes": total})
	if d, err = s.load(ctx, t.ID, sender, trfID); err != nil {
		return Details{}, err
	}
	return s.details(ctx, t, d)
}

// checkBlockedFiles refuses files whose SHA-256 is on the blocklist of t.
func (s *Service) checkBlockedFiles(ctx context.Context, t *tenant.Tenant, sender Sender, files []store.TransferFile) error {
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		if seen[f.SHA256] {
			continue
		}
		seen[f.SHA256] = true
		blocked, err := s.repo.blocked(ctx, t.ID, "", f.SHA256)
		if err != nil {
			return fmt.Errorf("transfer: check file blocklist: %w", err)
		}
		if blocked {
			s.logEvent(ctx, t, sender.ClientIP, securitylog.DepositRefused,
				securitylog.Field{Key: securitylog.KeyReason, Value: securitylog.ReasonBlocklist})
			return ErrBlockedFile
		}
	}
	return nil
}

// storeError maps an error of a store write on an existing transfer: a
// transfer deleted meanwhile (ErrNotFound) or no longer in the expected
// state (ErrConflict), any other error being internal.
func storeError(op string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, store.ErrConflict):
		return ErrConflict
	}
	return fmt.Errorf("transfer: %s: %w", op, err)
}

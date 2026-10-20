package transfer

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	// ExpiresAt is the expiry, set at finalization (zero before).
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
	// Files are the files, by position.
	Files []File
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
	// UploadID is the tus upload identifier ("upl_" + base62), only while
	// the transfer is uploading ("" otherwise): the HTTP layer builds the
	// uploadUrl from it.
	UploadID string
	// UploadOffset is the durable upload offset (Size once complete); it is
	// meaningful only when UploadID is set.
	UploadOffset int64
}

// details converts d. While d is uploading, the upload engine gives the
// last activity of the transfer and its upload expiry, and every file
// carries its upload identifier and offset (Size for a completed file).
func (s *Service) details(ctx context.Context, tid tenant.ID, d store.TransferDetails) (Details, error) {
	out := Details{
		ID: d.ID, Status: d.Status, SenderEmail: d.SenderEmail, Recipients: d.Recipients, Message: d.Message,
		ExpiryDays: d.ExpiryDays, ExpiresAt: d.ExpiresAt, PasswordProtected: d.PasswordProtected(),
		DeleteAfterFirstDownload: d.DeleteAfterFirstDownload, TotalBytes: d.TotalBytes,
		CreatedAt: d.CreatedAt, FinalizedAt: d.FinalizedAt, Files: make([]File, len(d.Files)),
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
	return out, nil
}

// Get returns the transfer trfID of tenant t as its sender sees it (OpenAPI
// getTransfer). Only the sender who created it may read it
// ([store.Depositor.Owns]: same address and, for an external sender, same
// invitation); anyone else gets ErrNotFound, as for an unknown transfer or
// a transfer of another tenant. The offsets of the incomplete files come
// from the upload engine while the transfer is uploading.
func (s *Service) Get(ctx context.Context, t *tenant.Tenant, sender Sender, trfID string) (Details, error) {
	if _, err := normalize(sender); err != nil {
		return Details{}, err
	}
	d, err := s.load(ctx, t.ID, sender, trfID)
	if err != nil {
		return Details{}, err
	}
	return s.details(ctx, t.ID, d)
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
	if _, err := normalize(sender); err != nil {
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
	return nil
}

// Finalize closes the uploads of the transfer trfID of tenant t on behalf
// of its sender (OpenAPI finalizeTransfer) and hands it to the antivirus:
// the transfer moves to scanning, with its finalization and expiry times
// set. Checks, in order:
//
//  1. eligibility, checked again (T-25): ErrForbidden;
//  2. the transfer exists and belongs to the sender: ErrNotFound;
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
// After the commit, Options.OnFinalized is called (best effort).
func (s *Service) Finalize(ctx context.Context, t *tenant.Tenant, sender Sender, trfID string) (Details, error) {
	if _, _, err := s.checkEligible(ctx, t, sender); err != nil {
		return Details{}, err
	}
	d, unlock, err := s.lockUploading(ctx, t.ID, sender, trfID)
	if err != nil {
		return Details{}, err
	}
	defer unlock()
	if len(d.Files) == 0 {
		return Details{}, ErrConflict
	}
	var incomplete, mismatch []string
	for _, f := range d.Files {
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
	err = s.repo.tx(ctx, t.ID, func(tx txRepo) error { return tx.finalize(ctx, trfID, s.now()) })
	if err != nil {
		return Details{}, storeError("finalize transfer", err)
	}
	s.onFinalized(t.ID, trfID)
	if d, err = s.load(ctx, t.ID, sender, trfID); err != nil {
		return Details{}, err
	}
	return s.details(ctx, t.ID, d)
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

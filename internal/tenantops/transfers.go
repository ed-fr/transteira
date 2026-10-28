package tenantops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// MaxReasonLen is the maximum length, in characters, of the reason of a
// transfer deletion, as given and as recorded once redacted (OpenAPI
// AdminReason).
const MaxReasonLen = 500

// Origin tells how the sender of a transfer was allowed to deposit
// (OpenAPI TransferOrigin).
type Origin string

// Transfer origins.
const (
	// OriginInternal is an internal depositor (deposit session).
	OriginInternal Origin = "internal"
	// OriginExternal is an invited external depositor.
	OriginExternal Origin = "external"
	// OriginAPI is an API token.
	OriginAPI Origin = "api"
)

// Transfer is a transfer as the administration lists it (OpenAPI
// AdminTransfer): metadata only, never a link or a file content.
type Transfer struct {
	ID     string
	Status store.TransferStatus
	// Origin tells how the sender was allowed to deposit.
	Origin       Origin
	SenderEmail  string
	Recipients   []string
	InvitationID string
	// APITokenID is the API token that created the transfer ("tok_" +
	// ULID), "" for a deposit session transfer.
	APITokenID               string
	FileCount                int
	TotalBytes               int64
	PasswordProtected        bool
	DeleteAfterFirstDownload bool
	CreatedAt                time.Time
	// ExpiresAt is the expiry, zero (null) until the transfer became
	// available: the value written at finalization is provisional.
	ExpiresAt time.Time
	// FirstDownloadedAt is zero (null) before the first complete download.
	FirstDownloadedAt time.Time
	DownloadCount     int64
	// MaxDownloads is the limit on the download starts, nil for none.
	MaxDownloads *int
	// ConfidentialityLevel is the key of the level snapshotted at creation,
	// "" for a transfer without level.
	ConfidentialityLevel string
	// ConfidentialityLabel is the label of that level in the language of
	// the transfer (the tenant default when it has none), "" without level.
	ConfidentialityLabel string
	// Rules are the rules of the level as snapshotted at creation, nil
	// without level.
	Rules *store.ConfidentialityRules
}

// TransferDetail is a transfer with its files (OpenAPI
// AdminTransferDetail).
type TransferDetail struct {
	Transfer
	// SenderIP is the client IP of the sender at creation, the zero Addr
	// (null) when unknown.
	SenderIP netip.Addr
	Files    []File
}

// File is a file of a transfer: metadata, fingerprint and antivirus
// result.
type File struct {
	ID         string
	Name       string
	Size       int64
	MediaType  string
	SHA256     string
	ScanStatus store.ScanStatus
}

// TransferFilter selects a page of transfers (OpenAPI listTenantTransfers).
type TransferFilter struct {
	// Status keeps the transfers of this status ("" for all).
	Status string
	// Email keeps the transfers whose sender or one of whose recipients is
	// this address ("" for all).
	Email string
	// CreatedAfter keeps the transfers created after this time (zero: no
	// bound).
	CreatedAfter time.Time
	// Cursor is the nextCursor of the previous page, "" for the first.
	Cursor string
	// Limit is the page size, 0 for store.DefaultPageSize.
	Limit int
}

// transferStatuses are the statuses accepted by the status filter.
var transferStatuses = map[store.TransferStatus]bool{
	store.TransferUploading: true, store.TransferScanning: true, store.TransferAvailable: true,
	store.TransferRejected: true, store.TransferExpired: true, store.TransferDeleted: true,
}

// originOf returns the origin of a stored transfer.
func originOf(t store.Transfer) Origin {
	switch {
	case t.APITokenID != "":
		return OriginAPI
	case t.SenderKind == store.DepositorExternal:
		return OriginExternal
	}
	return OriginInternal
}

// transferOf converts a stored transfer; lang is the default language of
// its tenant, for the label of its confidentiality level.
func transferOf(t store.Transfer, recipients []string, fileCount int, lang string) Transfer {
	out := Transfer{
		ID: t.ID, Status: t.Status, Origin: originOf(t), SenderEmail: t.SenderEmail,
		Recipients: append([]string{}, recipients...), InvitationID: t.InvitationID, APITokenID: t.APITokenID,
		FileCount: fileCount, TotalBytes: t.TotalBytes, PasswordProtected: t.PasswordProtected(),
		DeleteAfterFirstDownload: t.DeleteAfterFirstDownload, CreatedAt: t.CreatedAt,
		FirstDownloadedAt: t.FirstDownloadedAt, DownloadCount: t.DownloadCount,
		MaxDownloads: t.MaxDownloads, ConfidentialityLevel: t.ConfidentialityLevel, Rules: t.Rules,
	}
	if t.ConfidentialityLevel != "" {
		out.ConfidentialityLabel = store.LevelLabel(t.ConfidentialityLabel, t.Language, lang, "en")
	}
	if !t.AvailableAt.IsZero() {
		out.ExpiresAt = t.ExpiresAt
	}
	return out
}

// ListTransfers returns a page of the transfers of tenant tid, most recent
// first, in every status, with their recipients and number of files.
func (s *Service) ListTransfers(ctx context.Context, p adminauth.Principal, tid tenant.ID, f TransferFilter) (store.Page[Transfer], error) {
	tn, err := s.readableTenant(ctx, p, tid)
	if err != nil {
		return store.Page[Transfer]{}, err
	}
	sf := store.AdminTransferFilter{
		Status: store.TransferStatus(f.Status), CreatedAfter: f.CreatedAfter, Cursor: f.Cursor, Limit: f.Limit,
	}
	if f.Status != "" && !transferStatuses[sf.Status] {
		return store.Page[Transfer]{}, invalid(FieldStatus, "unknown transfer status")
	}
	if f.Email != "" {
		var ok bool
		if sf.Email, ok = normalizeAddress(f.Email); !ok {
			return store.Page[Transfer]{}, invalidAddress(FieldEmail)
		}
	}
	if err := checkLimit(f.Limit); err != nil {
		return store.Page[Transfer]{}, err
	}
	page, err := s.repo.listTransfers(ctx, tid, sf)
	if err != nil {
		return store.Page[Transfer]{}, listError("list transfers", err)
	}
	out := store.Page[Transfer]{Items: make([]Transfer, len(page.Items)), NextCursor: page.NextCursor}
	for i, t := range page.Items {
		out.Items[i] = transferOf(t.Transfer, t.Recipients, t.FileCount, tn.DefaultLanguage)
	}
	return out, nil
}

// transfer reads the transfer trfID of tenant tid; a malformed ID and a
// transfer of another tenant are ErrNotFound.
func (s *Service) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	if !id.Valid(id.Transfer, trfID) {
		return store.TransferDetails{}, ErrNotFound
	}
	d, err := s.repo.getTransfer(ctx, tid, trfID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.TransferDetails{}, ErrNotFound
	case err != nil:
		return store.TransferDetails{}, fmt.Errorf("tenantops: get transfer: %w", err)
	}
	return d, nil
}

// GetTransfer returns the transfer trfID of tenant tid with its files,
// their fingerprints and antivirus results: never a file content nor the
// download link.
func (s *Service) GetTransfer(ctx context.Context, p adminauth.Principal, tid tenant.ID, trfID string) (TransferDetail, error) {
	tn, err := s.readableTenant(ctx, p, tid)
	if err != nil {
		return TransferDetail{}, err
	}
	d, err := s.transfer(ctx, tid, trfID)
	if err != nil {
		return TransferDetail{}, err
	}
	out := TransferDetail{
		Transfer: transferOf(d.Transfer, d.Recipients, len(d.Files), tn.DefaultLanguage), SenderIP: d.SenderIP,
		Files: make([]File, len(d.Files)),
	}
	for i, f := range d.Files {
		out.Files[i] = File{
			ID: f.ID, Name: f.Name, Size: f.Size, MediaType: f.MediaType, SHA256: f.SHA256, ScanStatus: f.ScanStatus,
		}
	}
	return out, nil
}

// DeleteTransfer erases the transfer trfID of tenant tid before its expiry
// (crypto-erase through the Eraser, which withdraws it from the antivirus
// first) and marks it deleted. The optional reason, at most MaxReasonLen
// characters, is recorded in the transfer.deleted audit event once its
// mail addresses are replaced by "[address]" and it is cut to MaxReasonLen
// characters.
//
// A transfer already expired or deleted is left as it is, without audit
// (nil error). While an upload request holds a file of the transfer, the
// deletion is retried a few times, then refused with a *[BusyError]. The
// erasure itself is not interrupted by the cancellation of ctx: a
// half-done erasure would leave the transfer listed with its keys gone.
func (s *Service) DeleteTransfer(ctx context.Context, p adminauth.Principal, tid tenant.ID, trfID, reason string, ip netip.Addr) error {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return err
	}
	if !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > MaxReasonLen {
		return invalid(FieldReason, "must be text of at most %d characters", MaxReasonLen)
	}
	if !id.Valid(id.Transfer, trfID) {
		return ErrNotFound
	}
	res, err := s.erase(ctx, tid, trfID)
	switch {
	case errors.Is(err, lifecycle.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, lifecycle.ErrBusy):
		return &BusyError{RetryAfter: s.busyRetryAfter}
	case err != nil:
		return fmt.Errorf("tenantops: delete transfer: %w", err)
	case res == lifecycle.AlreadyEnded:
		return nil
	}
	var details map[string]any
	if reason != "" {
		details = map[string]any{"reason": redactReason(reason)}
	}
	s.record(ctx, p, ip, tid, audit.ActionTransferDeleted, audit.ObjectTransfer, trfID, details)
	return nil
}

// erase runs the Eraser, retrying while an upload holds the transfer. The
// waits between the attempts stop when ctx is done; the erasure itself
// runs without cancellation.
func (s *Service) erase(ctx context.Context, tid tenant.ID, trfID string) (lifecycle.EraseResult, error) {
	for attempt := 0; ; attempt++ {
		res, err := s.eraser.EraseTransfer(context.WithoutCancel(ctx), tid, trfID, lifecycle.MarkDeleted)
		if !errors.Is(err, lifecycle.ErrBusy) || attempt >= s.busyRetries {
			return res, err
		}
		timer := time.NewTimer(s.busyDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-timer.C:
		}
	}
}

// redactReason replaces the mail addresses of reason and cuts it to
// MaxReasonLen characters.
func redactReason(reason string) string {
	r := []rune(audit.RedactAddresses(reason))
	if len(r) > MaxReasonLen {
		r = r[:MaxReasonLen]
	}
	return string(r)
}

// ResendNotification queues the notification mail of the transfer trfID
// of tenant tid again, through the SMTP settings of the tenant, to the
// given recipients, or to all of them when the list is empty. The transfer
// must be available (ErrNotAvailable) and every listed address must be an
// original recipient (*InvalidError on "/recipients/<index>").
//
// The mail carries the existing link: the download token is unsealed for
// the build, wiped after it, never rotated, returned or logged. A tenant
// without SMTP settings is ErrMailUnavailable, with nothing queued. At most
// ResendLimit resends per transfer and window are queued
// (*RateLimitError), checked before the token is unsealed; a resend
// refused or failed before queuing does not count. It records
// transfer.notification_resent with the number of recipients only.
func (s *Service) ResendNotification(ctx context.Context, p adminauth.Principal, tid tenant.ID, trfID string, recipients []string, ip netip.Addr) error {
	t, err := s.writable(ctx, p, tid)
	if err != nil {
		return err
	}
	if len(recipients) > store.MaxTransferRecipients {
		return invalid(FieldRecipients, "at most %d recipients", store.MaxTransferRecipients)
	}
	d, err := s.transfer(ctx, tid, trfID)
	if err != nil {
		return err
	}
	if d.Status != store.TransferAvailable || d.DownloadTokenKeyID == "" {
		return ErrNotAvailable
	}
	subset, err := selectRecipients(d.Recipients, recipients)
	if err != nil {
		return err
	}
	// The slot is reserved before the download token is unsealed, so that a
	// rate-limited caller never gets it decrypted; it is refunded when the
	// resend fails before anything is queued.
	key := string(tid) + "|" + trfID
	if ok, retry := s.resends.Allow(key); !ok {
		return &RateLimitError{RetryAfter: max(retry, time.Second)}
	}
	jobs, err := s.resendJobs(ctx, t, d, subset)
	if err != nil {
		s.resends.Refund(key)
		return err
	}
	s.mailer.Send(ctx, jobs, slog.String("tenant", string(tid)), slog.String("transfer", trfID))
	s.record(ctx, p, ip, tid, audit.ActionTransferNotificationResent, audit.ObjectTransfer, trfID,
		map[string]any{"recipientCount": len(subset)})
	return nil
}

// resendJobs unseals the download token of d, builds the notification
// mails of the recipients subset with it and wipes it.
func (s *Service) resendJobs(ctx context.Context, t *tenant.Tenant, d store.TransferDetails, subset []string) ([]mail.Job, error) {
	token, err := s.repo.openSecret(ctx, t.ID, d.DownloadTokenKeyID)
	if err != nil {
		return nil, fmt.Errorf("tenantops: open the download token: %w", err)
	}
	view := notify.ViewOf(d)
	view.Recipients = subset
	jobs, err := s.notifier.RecipientJobs(ctx, t, view, id.DownloadURL(t.FQDN, string(token)))
	clear(token)
	switch {
	case errors.Is(err, notify.ErrNoSMTP):
		return nil, ErrMailUnavailable
	case err != nil:
		return nil, fmt.Errorf("tenantops: build the notification mails: %w", err)
	}
	return jobs, nil
}

// selectRecipients returns the recipients of the resend: original (the
// normalized recipients of the transfer) when requested is empty, else
// the normalized requested addresses without duplicates, each of which
// must be an original recipient.
func selectRecipients(original, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return original, nil
	}
	known := make(map[string]bool, len(original))
	for _, r := range original {
		known[r] = true
	}
	seen := make(map[string]bool, len(requested))
	out := make([]string, 0, len(requested))
	for i, raw := range requested {
		field := FieldRecipients + "/" + strconv.Itoa(i)
		r, ok := normalizeAddress(raw)
		if !ok {
			return nil, invalidAddress(field)
		}
		if !known[r] {
			return nil, invalid(field, "must be a recipient of the transfer")
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// normalizeAddress validates a mail address given by the caller with the
// restricted syntax of mail.ParseAddress (a bare address, no display name),
// then normalizes it like the store.
func normalizeAddress(raw string) (string, bool) {
	mailbox, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	addr, err := store.NormalizeEmail(mailbox)
	return addr, err == nil
}

package mytransfers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Transfer is a transfer as "my transfers" lists it (OpenAPI MyTransfer).
type Transfer struct {
	store.SenderTransfer
	// LevelLabel is the label of the confidentiality level snapshotted on
	// the transfer, in its language (then the tenant default, then
	// English); "" without level.
	LevelLabel string
	// DropLinkLabel is, for a transfer deposited through a permanent drop
	// link, the label of the link ("" when it is gone), shown instead of
	// the recipients: those are never disclosed to the depositor (threat
	// model T-311), so Recipients is nil and DownloadedBy 0 for such a
	// transfer. "" otherwise.
	DropLinkLabel string
}

// TransferDetail is a transfer as "my transfers" shows it (OpenAPI
// MyTransferDetail): files and per-recipient tracking, never a link or a
// token.
type TransferDetail struct {
	store.SenderTransferDetail
	// LevelLabel is as in [Transfer].
	LevelLabel string
	// DropLinkLabel is as in [Transfer]; Recipients and Tracking are nil
	// and DownloadedBy 0 for a drop link transfer.
	DropLinkLabel string
	// ExtendableTo is the latest expiry [Service.Extend] could set now,
	// zero when the transfer cannot be extended (see [ExtendableTo]).
	ExtendableTo time.Time
}

// AllowedExpiryDays returns the durations, in days, an extension of t may
// choose: those of the confidentiality rules snapshotted on t, or 1, 7 and
// 30 days without level. The slice is shortest first and never shared.
func AllowedExpiryDays(t store.Transfer) []int {
	if t.Rules != nil {
		return t.Rules.AllowedExpiryDays()
	}
	return slices.Clone(expiryDays)
}

// ExtendableTo returns the latest expiry an extension of t could set at
// now: now plus the longest allowed duration, but never more than
// store.MaxTransferLifetime after the creation of t. It returns the zero
// time when t cannot be extended: not available, past its expiry, due for
// deletion after its downloads, its maximum number of downloads reached,
// no allowed duration, or no later expiry possible.
func ExtendableTo(t store.Transfer, now time.Time) time.Time {
	days := AllowedExpiryDays(t)
	switch {
	case t.Status != store.TransferAvailable, !t.ExpiresAt.After(now), !t.DeleteAfter.IsZero(),
		t.MaxDownloads != nil && t.DownloadCount >= int64(*t.MaxDownloads), len(days) == 0:
		return time.Time{}
	}
	to := now.Add(time.Duration(days[len(days)-1]) * 24 * time.Hour)
	if limit := t.CreatedAt.Add(store.MaxTransferLifetime); to.After(limit) {
		to = limit
	}
	if !to.After(t.ExpiresAt) {
		return time.Time{}
	}
	return to
}

// levelLabel returns the label of the level snapshotted on t in its
// language, then the default language of tn, then English.
func levelLabel(tn *tenant.Tenant, t store.Transfer) string {
	if t.ConfidentialityLevel == "" {
		return ""
	}
	return store.LevelLabel(t.ConfidentialityLabel, t.Language, tn.DefaultLanguage, "en")
}

// detail renders d for the session, hiding the recipients of a drop link
// transfer.
func (s *Service) detail(ctx context.Context, t *tenant.Tenant, d store.SenderTransferDetail) (TransferDetail, error) {
	out := TransferDetail{
		SenderTransferDetail: d, LevelLabel: levelLabel(t, d.Transfer), ExtendableTo: ExtendableTo(d.Transfer, s.now()),
	}
	if d.DropLinkID == "" {
		return out, nil
	}
	labels, err := s.repo.dropLinkLabels(ctx, t.ID)
	if err != nil {
		return TransferDetail{}, fmt.Errorf("mytransfers: read drop links: %w", err)
	}
	out.DropLinkLabel = labels[d.DropLinkID]
	out.Recipients, out.Tracking, out.DownloadedBy = nil, nil, 0
	return out, nil
}

// List returns a page of the transfers in progress (scanning or
// available) of tenant t sent by the session address with a deposit
// session, newest first. cursor is the NextCursor of the previous page
// ("" for the first) and limit the page size (the store default when
// <= 0, at most store.MaxPageSize). A malformed cursor is an *InvalidError
// on FieldCursor.
func (s *Service) List(ctx context.Context, t *tenant.Tenant, sess SessionInfo, cursor string, limit int) (store.Page[Transfer], error) {
	page, err := s.repo.list(ctx, t.ID, sess.Email, cursor, limit)
	switch {
	case errors.Is(err, store.ErrInvalid):
		return store.Page[Transfer]{}, invalid(FieldCursor)
	case err != nil:
		return store.Page[Transfer]{}, fmt.Errorf("mytransfers: list transfers: %w", err)
	}
	out := store.Page[Transfer]{Items: make([]Transfer, len(page.Items)), NextCursor: page.NextCursor}
	var labels map[string]string
	for i, it := range page.Items {
		out.Items[i] = Transfer{SenderTransfer: it, LevelLabel: levelLabel(t, it.Transfer)}
		if it.DropLinkID == "" {
			continue
		}
		// The recipients of a drop link stay hidden from its depositor.
		if labels == nil {
			if labels, err = s.repo.dropLinkLabels(ctx, t.ID); err != nil {
				return store.Page[Transfer]{}, fmt.Errorf("mytransfers: read drop links: %w", err)
			}
		}
		out.Items[i].DropLinkLabel = labels[it.DropLinkID]
		out.Items[i].Recipients, out.Items[i].DownloadedBy = nil, 0
	}
	return out, nil
}

// Get returns the transfer trfID of tenant t sent by the session address,
// in progress, with its files and per-recipient tracking. Any other
// transfer (unknown, of another tenant or sender, of an API token, ended)
// is ErrNotFound (T-209).
func (s *Service) Get(ctx context.Context, t *tenant.Tenant, sess SessionInfo, trfID string) (TransferDetail, error) {
	d, err := s.repo.get(ctx, t.ID, trfID, sess.Email)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return TransferDetail{}, ErrNotFound
	case err != nil:
		return TransferDetail{}, fmt.Errorf("mytransfers: read transfer: %w", err)
	}
	return s.detail(ctx, t, d)
}

// Delete deletes the transfer trfID of tenant t sent by the session
// address, exactly as an administrator does: the lifecycle erasure
// (antivirus held, keys destroyed, files removed, transfer marked
// deleted), retried while an upload holds one of its files, then audited
// as transfer.deleted with the sender as actor.
//
// A transfer of the sender that already ended (expired, deleted,
// rejected) is a no-op returning nil. A transfer that is not one of the
// sender in progress or ended (unknown, of another tenant or sender, of an
// API token, still uploading) is ErrNotFound. A transfer still held after
// the retries is a *BusyError.
func (s *Service) Delete(ctx context.Context, t *tenant.Tenant, sess SessionInfo, ip netip.Addr, trfID string) error {
	st, err := s.repo.status(ctx, t.ID, trfID, sess.Email)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("mytransfers: read transfer status: %w", err)
	}
	switch st {
	case store.TransferScanning, store.TransferAvailable:
	case store.TransferUploading:
		return ErrNotFound
	default:
		return nil // already ended
	}
	res, err := lifecycle.EraseRetrying(ctx, s.eraser, t.ID, trfID, s.busyRetries, s.busyDelay)
	switch {
	case errors.Is(err, lifecycle.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, lifecycle.ErrBusy):
		return &BusyError{RetryAfter: s.busyRetryAfter}
	case err != nil:
		return fmt.Errorf("mytransfers: delete transfer: %w", err)
	case res == lifecycle.AlreadyEnded:
		return nil
	}
	s.record(ctx, t, ip, sess.Email, audit.ActionTransferDeleted, audit.ObjectTransfer, trfID, nil)
	return nil
}

// Extend sets the expiry of the available transfer trfID of tenant t sent
// by the session address to now plus days (spec 8.7, P34, T-210), and
// returns the transfer extended. days must be one of AllowedExpiryDays of
// the transfer, and the new expiry must be after the current one
// (*NotAllowedError otherwise); a transfer that is not available, whose
// downloads are over or that is due for deletion after its downloads is
// ErrNotExtendable; an expiry more than 90 days after the creation is
// ErrExtensionLimit; a transfer that is not one of the sender in progress
// is ErrNotFound. The extension re-arms the expiry reminder and is
// audited as transfer.extended with the old and new expiry and the number
// of extensions. Once committed, the abuse notifier (when set) evaluates
// the daily rules of the sender, which may alert but never fails the call.
func (s *Service) Extend(ctx context.Context, t *tenant.Tenant, sess SessionInfo, ip netip.Addr, trfID string, days int) (TransferDetail, error) {
	now := s.now()
	var allowed []int
	x, d, err := s.repo.extend(ctx, t.ID, trfID, sess.Email, now, func(d store.SenderTransferDetail) (time.Time, error) {
		allowed = AllowedExpiryDays(d.Transfer)
		if !slices.Contains(allowed, days) {
			return time.Time{}, &NotAllowedError{Allowed: allowed}
		}
		return now.Add(time.Duration(days) * 24 * time.Hour), nil
	})
	var notAllowed *NotAllowedError
	switch {
	case errors.As(err, &notAllowed):
		return TransferDetail{}, notAllowed
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return TransferDetail{}, ErrNotFound
	case errors.Is(err, store.ErrNotExtendable):
		return TransferDetail{}, ErrNotExtendable
	case errors.Is(err, store.ErrExtensionShortens):
		return TransferDetail{}, &NotAllowedError{Allowed: allowed}
	case errors.Is(err, store.ErrExtensionLimit):
		return TransferDetail{}, ErrExtensionLimit
	case err != nil:
		return TransferDetail{}, fmt.Errorf("mytransfers: extend transfer: %w", err)
	}
	s.record(ctx, t, ip, sess.Email, audit.ActionTransferExtended, audit.ObjectTransfer, trfID, map[string]any{
		"previousExpiresAt": x.PreviousExpiresAt.UTC().Format(time.RFC3339Nano),
		"expiresAt":         x.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"extensionCount":    x.Count,
	})
	if s.abuse != nil {
		s.abuse.AfterExtend(context.WithoutCancel(ctx), t, AbuseFacts{
			TransferID: trfID, SenderEmail: d.SenderEmail, Kind: d.SenderKind, Bytes: d.TotalBytes,
			Recipients: slices.Clone(d.Recipients), At: now, ClientIP: ip,
		})
	}
	return s.detail(ctx, t, d)
}

// ReissueLink issues a new download link for the link-only transfer trfID
// of tenant t sent by the session address (since 2.0, OpenAPI
// reissueMyTransferLink), whose link was lost: a new token is drawn, only
// its SHA-256 replaces the previous one (which stops working at once), and
// the link is returned once, built from the registered FQDN of t. A
// transfer that is not one of the sender in progress is ErrNotFound; one
// that is not link-only, neither scanning nor available, or available past
// its expiry is ErrNotReissuable. A link reissued while the transfer is
// scanning works once it becomes available. It is audited as transfer.link_reissued, naming the
// transfer only (never the link).
func (s *Service) ReissueLink(ctx context.Context, t *tenant.Tenant, sess SessionInfo, ip netip.Addr, trfID string) (string, error) {
	token, err := s.newToken(id.DownloadTokenPrefix, id.DownloadTokenBytes)
	if err != nil {
		return "", fmt.Errorf("mytransfers: new download token: %w", err)
	}
	now := s.now()
	err = s.repo.reissue(ctx, t.ID, trfID, sess.Email, id.HashToken(token), func(d store.SenderTransferDetail) error {
		// While scanning, the expiry is only provisional: the new link
		// works once the transfer is available.
		if !d.LinkOnly || (d.Status != store.TransferAvailable && d.Status != store.TransferScanning) ||
			(d.Status == store.TransferAvailable && !d.ExpiresAt.After(now)) {
			return ErrNotReissuable
		}
		return nil
	})
	switch {
	case errors.Is(err, ErrNotReissuable), errors.Is(err, store.ErrConflict):
		// ErrConflict: the transfer stopped being available meanwhile.
		return "", ErrNotReissuable
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
		return "", ErrNotFound
	case err != nil:
		return "", fmt.Errorf("mytransfers: reissue link: %w", err)
	}
	s.record(ctx, t, ip, sess.Email, audit.ActionTransferLinkReissued, audit.ObjectTransfer, trfID, nil)
	return id.DownloadURL(t.FQDN, token), nil
}

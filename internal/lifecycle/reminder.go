package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DefaultReminderInterval is the default delay between two runs of
// TaskExpiryReminder.
const DefaultReminderInterval = 15 * time.Minute

// ReminderNotifier builds the expiry reminder mails. *notify.Notifier
// implements it.
type ReminderNotifier interface {
	ExpiryReminderJobs(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, links []notify.RecipientLink, verificationRequired bool) ([]mail.Job, error)
}

// MailQueue queues a mail without blocking. *mail.Queue implements it.
type MailQueue interface {
	Enqueue(job mail.Job) error
}

// Opener unseals a wrapped secret. *masterkey.Vault implements it.
type Opener interface {
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
}

// reminderBatch is what prepareReminder committed for one transfer: the
// transfer and the links to mail, whose reminder is marked sent.
type reminderBatch struct {
	details store.TransferDetails
	links   []store.RecipientLink
}

// prepareReminder is the committed part of the reminder of the transfer
// trfID of tid at now. In one transaction it checks the transfer is still
// due (errNotDue otherwise), marks the reminder sent for the links to mail,
// marks the transfer as reminded, even when no link is left, and audits
// the reminder when there is one. The links whose recipient address (or
// domain) is on the blocklist at that time, or whose sealed token is
// destroyed (erased recipient), are not mailed and left unmarked.
func (r storeRepo) prepareReminder(ctx context.Context, tid tenant.ID, trfID string, now time.Time) (reminderBatch, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return reminderBatch{}, err
	}
	var out reminderBatch
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		out = reminderBatch{}
		d, err := r.db.Transfers().GetTx(ctx, tx, trfID)
		if err != nil {
			return err
		}
		if d.Status != store.TransferAvailable || d.LinkMode != store.LinkModePerRecipient ||
			!d.ExpiryReminderAt.IsZero() || !d.ExpiresAt.After(now) {
			return errNotDue
		}
		targets, err := r.db.RecipientLinks().ReminderTargetsTx(ctx, tx, trfID)
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(targets))
		for _, l := range targets {
			if l.TokenKeyID == "" {
				continue
			}
			blocked, err := r.db.Blocklist().MatchTx(ctx, tx, l.Email, "")
			if err != nil {
				return err
			}
			if len(blocked) > 0 {
				continue
			}
			out.links = append(out.links, l)
			ids = append(ids, l.ID)
		}
		if len(ids) > 0 {
			if err := r.db.RecipientLinks().MarkReminderSentTx(ctx, tx, ids, now); err != nil {
				return err
			}
		}
		if err := r.db.Transfers().MarkExpiryReminderTx(ctx, tx, trfID, now); err != nil {
			return err
		}
		out.details = d
		if len(ids) == 0 {
			return nil
		}
		return audit.OrNew(r.writer, r.db).RecordScopedTx(ctx, tx, audit.Event{
			ActorKind: store.ActorSystem, Actor: SystemActor, Action: audit.ActionTransferReminderSent,
			ObjectKind: audit.ObjectTransfer, ObjectID: trfID, Details: map[string]any{"recipients": len(ids)},
		})
	})
	if err != nil {
		return reminderBatch{}, err
	}
	return out, nil
}

func (r storeRepo) dueReminders(ctx context.Context, now time.Time, page store.SweepPage) ([]store.TenantTransfer, error) {
	return r.db.RecipientLinks().DueReminders(ctx, now, page)
}

// resetReminder clears the reminder mark of the links linkIDs of the
// transfer trfID of tid, and the reminder pass of the transfer while it is
// still available at now, so that the next run mails these links again.
func (r storeRepo) resetReminder(ctx context.Context, tid tenant.ID, trfID string, linkIDs []string, now time.Time) error {
	return r.db.RecipientLinks().ResetReminderSent(ctx, tid, trfID, linkIDs, now)
}

// expiryReminders is the run function of TaskExpiryReminder: it mails the
// reminders due now, page after page. A transfer that failed is logged and
// counted; the run fails at the end if any did. Without Deps.Notifier,
// Deps.Mail or Deps.Opener it does nothing.
func (s *Sweeper) expiryReminders(ctx context.Context) error {
	if s.notifier == nil || s.mailer == nil || s.opener == nil {
		return nil
	}
	var after store.TenantTransfer
	failedN := 0
	for {
		now := s.now()
		page, err := s.repo.dueReminders(ctx, now, store.SweepPage{After: after, Limit: s.reminderPage})
		if err != nil {
			return fmt.Errorf("lifecycle: list the transfers of %s: %w", TaskExpiryReminder, err)
		}
		for _, tt := range page {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !s.remind(ctx, tt, now) {
				failedN++
			}
		}
		if len(page) < s.reminderPage {
			break
		}
		after = page[len(page)-1]
	}
	if failedN > 0 {
		return fmt.Errorf("lifecycle: %s: %d transfer(s) with a reminder not sent", TaskExpiryReminder, failedN)
	}
	return nil
}

// remind sends the reminder of the transfer tt and reports whether it went
// well (a transfer no longer due, or without recipient to mail, is fine).
func (s *Sweeper) remind(ctx context.Context, tt store.TenantTransfer, now time.Time) bool {
	t, err := s.repo.getTenant(ctx, tt.TenantID)
	if err != nil {
		return s.remindFailed(ctx, tt, "read tenant", err)
	}
	if t.Status == tenant.StatusDeleting {
		return true
	}
	b, err := s.repo.prepareReminder(ctx, tt.TenantID, tt.TransferID, now)
	switch {
	case errors.Is(err, errNotDue), errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrConflict):
		return true
	case err != nil:
		return s.remindFailed(ctx, tt, "mark reminder", err)
	case len(b.links) == 0:
		return true
	}
	// From here the reminder is marked: every link not mailed is reset,
	// with the reminder pass of the transfer, so that the next run retries
	// them (and them only).
	links := make([]notify.RecipientLink, 0, len(b.links))
	linkIDs := make(map[string]string, len(b.links))
	var failed []string
	ok := true
	for _, l := range b.links {
		token, err := s.opener.Open(ctx, tt.TenantID, crypto.PurposeSecret, l.TokenKeyID)
		if err != nil {
			failed = append(failed, l.ID)
			ok = s.remindFailed(ctx, tt, "open link token", err) && ok
			continue
		}
		links = append(links, notify.RecipientLink{Email: l.Email, Link: id.DownloadURL(t.FQDN, string(token))})
		clear(token)
		linkIDs[strings.ToLower(l.Email)] = l.ID
	}
	if len(links) > 0 {
		jobs, err := s.notifier.ExpiryReminderJobs(ctx, t, notify.ViewOf(b.details), links, b.details.RecipientVerification)
		if err != nil {
			for _, linkID := range linkIDs {
				failed = append(failed, linkID)
			}
			ok = s.remindFailed(ctx, tt, "build reminder mails", err)
		}
		for _, j := range jobs {
			if err := s.mailer.Enqueue(j); err != nil {
				for _, to := range j.Message.To {
					if linkID := linkIDs[strings.ToLower(to)]; linkID != "" {
						failed = append(failed, linkID)
					}
				}
				ok = s.remindFailed(ctx, tt, "enqueue reminder mail", err) && ok
			}
		}
	}
	s.resetLinks(ctx, tt, failed, now)
	return ok
}

// resetLinks clears the reminder mark of the links linkIDs of tt and the
// reminder pass of tt, best effort: a failure is logged.
func (s *Sweeper) resetLinks(ctx context.Context, tt store.TenantTransfer, linkIDs []string, now time.Time) {
	if len(linkIDs) == 0 {
		return
	}
	if err := s.repo.resetReminder(context.WithoutCancel(ctx), tt.TenantID, tt.TransferID, linkIDs, now); err != nil {
		s.logger.ErrorContext(ctx, "lifecycle: reminder mark not reset", slog.String("tenant", string(tt.TenantID)),
			slog.String("transfer", tt.TransferID), slog.Int("links", len(linkIDs)), slog.Any("error", err))
	}
}

// remindFailed logs a failed step of the reminder of tt and returns false.
func (s *Sweeper) remindFailed(ctx context.Context, tt store.TenantTransfer, step string, err error) bool {
	s.logger.ErrorContext(ctx, "lifecycle: expiry reminder failed", slog.String("tenant", string(tt.TenantID)),
		slog.String("transfer", tt.TransferID), slog.String("step", step), slog.Any("error", err))
	return false
}

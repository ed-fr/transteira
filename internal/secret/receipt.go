package secret

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Expired sends the read receipt of a secret that the lifecycle task
// expired unread (lifecycle.Options.SecretExpired): e is the tombstone,
// whose tenant is read again for the mail. A secret without read receipt is
// ignored. Like every receipt it is best effort: a failure is only logged.
// It never blocks on the mail delivery.
func (s *Service) Expired(ctx context.Context, e store.EndedSecret) {
	sec := e.Secret
	if !sec.ReadReceipt {
		return
	}
	t, err := s.dir.Tenant(ctx, sec.TenantID)
	if err != nil {
		s.logger.ErrorContext(ctx, "secret: no read receipt: reading the tenant failed",
			slog.String("tenant", sec.TenantID.String()), slog.String("secret", sec.ID), slog.String("error", err.Error()))
		return
	}
	s.receipt(ctx, t, sec, mail.SecretOutcomeExpired, sec.EndedAt)
}

// lockedReceipt sends the read receipt of the secret secID of tenant t,
// just locked by the fifth wrong passphrase: the tombstone is read for the
// creator and its choice. A failure is only logged.
func (s *Service) lockedReceipt(ctx context.Context, t *tenant.Tenant, secID string) {
	sec, err := s.repo.Get(context.WithoutCancel(ctx), t.ID, secID)
	if err != nil {
		s.logger.ErrorContext(ctx, "secret: no read receipt: reading the locked secret failed",
			slog.String("tenant", t.ID.String()), slog.String("secret", secID), slog.String("error", err.Error()))
		return
	}
	s.receipt(ctx, t, sec, mail.SecretOutcomeLocked, sec.EndedAt)
}

// receipt sends, at most once, the read receipt of the ended secret sec of
// tenant t to its creator (data-model-v2.1.md "Receipt", threat model
// T-366): outcome is mail.SecretOutcomeRead, Expired or Locked and at the
// time the secret ended. Nothing happens for a secret without read
// receipt. The mail is built first, in the language of the tenant (the
// creator's is not recorded); then [Repo.MarkReceiptSent] marks the
// receipt, and only the caller that marked it queues the mail, so that
// concurrent or repeated calls send one mail and a deleted secret none.
// The mail is queued without waiting for its delivery. Failures are only
// logged: the receipt is a courtesy, never the answer of a request.
func (s *Service) receipt(ctx context.Context, t *tenant.Tenant, sec store.Secret, outcome string, at time.Time) {
	if !sec.ReadReceipt {
		return
	}
	ctx = context.WithoutCancel(ctx)
	attrs := []slog.Attr{slog.String("tenant", t.ID.String()), slog.String("secret", sec.ID)}
	job, err := s.notifier.SecretReceipt(ctx, t, notify.SecretViewOf(sec), outcome, at)
	switch {
	case errors.Is(err, notify.ErrNoSMTP):
		s.logger.LogAttrs(ctx, slog.LevelError,
			"secret: no read receipt sent: the tenant has no SMTP settings, an administrator must configure them", attrs...)
		return
	case err != nil:
		s.logger.LogAttrs(ctx, slog.LevelError, "secret: read receipt not built", append(attrs, slog.String("error", err.Error()))...)
		return
	}
	marked, err := s.repo.MarkReceiptSent(ctx, t.ID, sec.ID, s.now())
	switch {
	case err != nil:
		s.logger.LogAttrs(ctx, slog.LevelError, "secret: marking the read receipt failed", append(attrs, slog.String("error", err.Error()))...)
		return
	case !marked:
		return
	}
	s.mailer.Send(ctx, []mail.Job{job}, attrs...)
}

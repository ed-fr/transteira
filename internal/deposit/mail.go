package deposit

import (
	"context"
	"errors"
	"fmt"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// prepareMail renders template name in lang for the mailbox to and loads
// the tenant SMTP settings with the password unsealed, ready to queue. It
// returns ErrMailUnavailable when the tenant has no SMTP settings.
func (s *Service) prepareMail(ctx context.Context, t *tenant.Tenant, name, lang, to string, data any) (mail.Job, error) {
	msg, err := s.render(name, lang, data)
	if err != nil {
		return mail.Job{}, fmt.Errorf("deposit: render %s mail: %w", name, err)
	}
	msg.To = []string{to}
	cfg, err := s.repo.smtp(ctx, t.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return mail.Job{}, fmt.Errorf("%w: the tenant has no smtp settings", ErrMailUnavailable)
	case err != nil:
		return mail.Job{}, fmt.Errorf("deposit: read smtp settings: %w", err)
	}
	settings := mail.Settings{
		Host: cfg.Host, Port: cfg.Port, Security: mail.Security(cfg.Security), Username: cfg.Username,
		FromAddress: cfg.FromAddress, FromName: cfg.FromName,
	}
	if cfg.PasswordKeyID != "" {
		pw, err := s.secrets.Open(ctx, t.ID, crypto.PurposeSecret, cfg.PasswordKeyID)
		if err != nil {
			return mail.Job{}, fmt.Errorf("deposit: unseal smtp password: %w", err)
		}
		settings.Password = string(pw)
		clear(pw)
	}
	return mail.Job{TenantID: t.ID.String(), Template: name, Settings: settings, Message: msg}, nil
}

// enqueue queues job, mapping a full queue to a *RateLimitError and a closed
// queue, unusable settings or an open SMTP circuit (the tenant's server keeps
// failing) to ErrMailUnavailable.
func (s *Service) enqueue(job mail.Job) error {
	err := s.queue.Enqueue(job)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, mail.ErrQueueFull):
		return &RateLimitError{RetryAfter: QueueFullRetryAfter}
	case errors.Is(err, mail.ErrQueueClosed), errors.Is(err, mail.ErrInvalidSettings), errors.Is(err, mail.ErrCircuitOpen):
		return fmt.Errorf("%w: %w", ErrMailUnavailable, err)
	}
	return fmt.Errorf("deposit: queue mail: %w", err)
}

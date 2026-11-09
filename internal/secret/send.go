package secret

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
	"github.com/ed-fr/transteira/internal/tte2"
)

// Send activates, for its creator sender, the pending e-mail secret secID
// of tenant t and mails its link to the recipient (e2e-format.md 3.3.6).
// secretToken is the "tts_" token returned by [Service.Create] and
// fragmentKey the key K of the link fragment: the server keeps only the
// SHA-256 of the token, so the creator sends both halves of the link once.
// They are used only to compose the link of the mail, on the registered
// FQDN of the tenant ([id.SecretURL]): never stored, logged nor audited
// (threat model T-363, T-365). In order:
//
//   - a reply or drop link sender: ErrNotFound;
//   - a malformed secretToken or fragmentKey: a *ValidationError (the key
//     is only checked to be 43 canonical base64url characters, nothing is
//     derived from it);
//   - an unknown secret, another tenant's or another creator's:
//     ErrNotFound; a link secret, one that is not pending or whose
//     declared file is not uploaded: ErrConflict;
//   - the blocklist and the recipient domain rules of the tenant are
//     applied again to the recipient, as at the creation, since they may
//     have changed meanwhile (ErrRecipientRefused, see checkRecipient;
//     the secret stays pending), except for an invited external, whose
//     recipient is its inviter;
//   - the mail is built before the activation: without SMTP settings for
//     the tenant, ErrMailUnavailable, and the secret stays pending;
//   - the activation checks the token in constant time (a token that is
//     not the secret's is ErrNotFound, without security event: the caller
//     is the authenticated creator and the token has 256 bits), and the
//     state again (ErrConflict when a concurrent call won).
//
// Once activated, the mail goes to the Mailer, which queues it in memory
// and retries while the queue is full; a mail dropped after that is only
// logged (the creator deletes the secret and creates another one). It
// audits secret.sent with the delivery and the domain of the recipient,
// and reports the activation to Options.Abuse (alert only).
func (s *Service) Send(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, secID, secretToken, fragmentKey string) (store.Secret, error) {
	actor, ok := actorOf(sender)
	if !ok {
		return store.Secret{}, ErrNotFound
	}
	if err := validateSend(secretToken, fragmentKey); err != nil {
		return store.Secret{}, err
	}
	sec, err := s.repo.Get(ctx, t.ID, secID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Secret{}, ErrNotFound
	case err != nil:
		return store.Secret{}, fmt.Errorf("secret: send: %w", err)
	case !actor.Owns(sec):
		return store.Secret{}, ErrNotFound
	case sec.Delivery != store.SecretDeliveryEmail || sec.State != store.SecretPending ||
		sec.FileSize > 0 && sec.FileUploadedAt.IsZero():
		return store.Secret{}, ErrConflict
	}
	// The rules may have changed since the creation (threat model T-364);
	// the recipient of an invited external is its inviter.
	if sec.CreatorKind != store.SecretCreatorExternal {
		if err := s.checkRecipient(ctx, t, sender, sec.SenderEmail, sec.RecipientEmail); err != nil {
			return store.Secret{}, err
		}
	}
	// The activation time is the one the store records (it keeps
	// milliseconds), so that the mail announces the stored expiry.
	now := s.now().UTC().Truncate(time.Millisecond)
	view := notify.SecretViewOf(sec)
	view.ExpiresAt = now.Add(sec.Duration.Duration())
	job, err := s.notifier.SecretNotification(ctx, t, view, id.SecretURL(t.FQDN, secretToken, fragmentKey))
	switch {
	case errors.Is(err, notify.ErrNoSMTP):
		return store.Secret{}, ErrMailUnavailable
	case err != nil:
		// The notifier never puts the link in its errors.
		return store.Secret{}, fmt.Errorf("secret: send: build the mail: %w", err)
	}
	act, err := s.repo.ActivateForSend(ctx, t.ID, secID, actor, secretToken, now)
	switch {
	case errors.Is(err, store.ErrSecretState):
		return store.Secret{}, ErrConflict
	case errors.Is(err, store.ErrNotFound):
		return store.Secret{}, ErrNotFound
	case err != nil:
		return store.Secret{}, fmt.Errorf("secret: send: %w", err)
	}
	s.mailer.Send(ctx, []mail.Job{job}, slog.String("tenant", t.ID.String()), slog.String("secret", secID))
	ev := audit.Event{
		ActorKind: store.ActorDepositor, Actor: act.SenderEmail, IP: sender.ClientIP,
		Action: audit.ActionSecretSent, ObjectID: secID,
		Details: map[string]any{"delivery": string(act.Delivery), "recipientDomain": domainOf(act.RecipientEmail)},
	}
	if sender.APITokenID != "" {
		ev.ActorKind, ev.Actor = store.ActorAPIToken, sender.APITokenID
	}
	s.record(ctx, t, ev)
	s.activated(ctx, t, sender, act)
	return act, nil
}

// validateSend checks the two halves of the link sent to [Service.Send].
func validateSend(secretToken, fragmentKey string) error {
	var v validator
	switch {
	case secretToken == "":
		v.add(FieldSecretToken, CodeRequired)
	case !id.SecretTokenValid(secretToken):
		v.add(FieldSecretToken, CodeInvalidFormat)
	}
	if fragmentKey == "" {
		v.add(FieldFragmentKey, CodeRequired)
	} else if _, err := tte2.DecodeKey(fragmentKey); err != nil {
		v.add(FieldFragmentKey, CodeInvalidFormat)
	}
	if len(v.errs) > 0 {
		return &ValidationError{Fields: v.errs}
	}
	return nil
}

// domainOf returns the domain of a normalized address.
func domainOf(email string) string {
	return email[strings.LastIndexByte(email, '@')+1:]
}

package notify

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// SecretView is what the one-time secret mails need to know about a secret.
// It never holds the content, the key or any free text of the creator.
type SecretView struct {
	// ID is the identifier of the secret (sec_...).
	ID string
	// SenderEmail is the verified address of the creator.
	SenderEmail string
	// RecipientEmail is the recipient of an e-mail delivery, "" for a link
	// delivery.
	RecipientEmail string
	// Delivery is the delivery mode of the secret.
	Delivery store.SecretDelivery
	// HasPassphrase tells that a passphrase protects the secret.
	HasPassphrase bool
	// HasFile tells that a file is attached to the secret.
	HasFile bool
	// FileSize is the declared size of the attached file, 0 without file.
	FileSize int64
	// CreatedAt and ExpiresAt are the creation and expiry times.
	CreatedAt time.Time
	ExpiresAt time.Time
	// Language is the language of the mails, "" (or an unsupported value)
	// for the tenant default.
	Language string
}

// SecretViewOf maps a stored secret to its [SecretView]. The language is
// left empty: the caller sets it when it knows the one of the creator.
func SecretViewOf(s store.Secret) SecretView {
	return SecretView{
		ID: s.ID, SenderEmail: s.SenderEmail, RecipientEmail: s.RecipientEmail, Delivery: s.Delivery,
		HasPassphrase: s.HasPassphrase(), HasFile: s.FileSize > 0 || s.FileStorageName != "",
		FileSize: s.FileSize, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
	}
}

// SecretNotification builds the secret_notification mail to the single
// recipient of an e-mail secret (V2.1, threat model T-362 to T-366). link is
// the absolute secret URL with its key in the fragment: it is treated as
// opaque, validated like a download link, put in the mail only and never
// logged. The mail holds no free text of the creator and no content; it says
// that the secret can be read once, that a passphrase comes through another
// channel and that an attached file was not analyzed by the antivirus. It
// fails with ErrInvalidTransfer for a view without valid sender and
// recipient, ErrInvalidLink for a bad link and ErrTransferExpired for an
// expired secret.
func (n *Notifier) SecretNotification(ctx context.Context, t *tenant.Tenant, v SecretView, link string) (mail.Job, error) {
	if err := checkLink(link); err != nil {
		return mail.Job{}, err
	}
	sender, err := mail.ParseAddress(v.SenderEmail)
	if err != nil {
		return mail.Job{}, fmt.Errorf("%w: sender: %w", ErrInvalidTransfer, err)
	}
	recipient, err := mail.ParseAddress(v.RecipientEmail)
	if err != nil {
		return mail.Job{}, fmt.Errorf("%w: recipient: %w", ErrInvalidTransfer, err)
	}
	if !v.ExpiresAt.After(n.now()) {
		return mail.Job{}, ErrTransferExpired
	}
	data := mail.SecretNotificationData{
		TenantName: t.Name, SenderEmail: sender, Link: link, ExpiresAt: v.ExpiresAt,
		PassphraseRequired: v.HasPassphrase, HasFile: v.HasFile,
	}
	return n.secretJob(ctx, t, v, mail.TemplateSecretNotification, recipient, data)
}

// SecretReceipt builds the secret_receipt mail to the creator: the secret
// ended at at with the given outcome (mail.SecretOutcomeRead,
// mail.SecretOutcomeExpired or mail.SecretOutcomeLocked). The mail names the
// secret identifier, its creation date and, for an e-mail delivery, the
// recipient; never the content, the reader IP or user agent. It fails with
// ErrInvalidTransfer for an invalid sender, an unknown outcome or a zero
// time.
func (n *Notifier) SecretReceipt(ctx context.Context, t *tenant.Tenant, v SecretView, outcome string, at time.Time) (mail.Job, error) {
	sender, err := mail.ParseAddress(v.SenderEmail)
	if err != nil {
		return mail.Job{}, fmt.Errorf("%w: sender: %w", ErrInvalidTransfer, err)
	}
	switch outcome {
	case mail.SecretOutcomeRead, mail.SecretOutcomeExpired, mail.SecretOutcomeLocked:
	default:
		return mail.Job{}, fmt.Errorf("%w: secret outcome %q", ErrInvalidTransfer, outcome)
	}
	if at.IsZero() || v.CreatedAt.IsZero() || v.ID == "" {
		return mail.Job{}, fmt.Errorf("%w: secret identifier or times", ErrInvalidTransfer)
	}
	data := mail.SecretReceiptData{
		TenantName: t.Name, SecretID: v.ID, Outcome: outcome, At: at, CreatedAt: v.CreatedAt,
	}
	if v.Delivery == store.SecretDeliveryEmail {
		data.RecipientEmail = v.RecipientEmail
	}
	return n.secretJob(ctx, t, v, mail.TemplateSecretReceipt, sender, data)
}

// secretJob renders the secret mail name for the address to, in the
// language of the secret when supported, else the default language of
// tenant t. An entity can customize both secret mails (template keys
// secret-notification and secret-receipt). Only the template and the
// secret identifier are logged, never the link nor the address.
func (n *Notifier) secretJob(ctx context.Context, t *tenant.Tenant, v SecretView, name, to string, data any) (mail.Job, error) {
	lang := t.DefaultLanguage
	if i18n.IsSupported(v.Language) {
		lang = v.Language
	}
	msg, err := n.templates.RenderFor(ctx, n.overrides, t.ID.String(), name, lang, data)
	if err != nil {
		return mail.Job{}, fmt.Errorf("notify: render %s: %w", name, err)
	}
	settings, err := n.settings(ctx, t)
	if err != nil {
		return mail.Job{}, err
	}
	msg.To = []string{to}
	n.logger.LogAttrs(ctx, slog.LevelDebug, "notification mails built",
		slog.String("tenant", t.ID.String()),
		slog.String("secret", v.ID),
		slog.String("template", name),
		slog.Int("count", 1))
	return n.job(t, name, settings, msg), nil
}

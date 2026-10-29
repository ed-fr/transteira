package notify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/vcode"
)

// RecipientLink is the personal download link of one recipient of a
// transfer sent with one link per recipient (CLAUDE.md section 10).
type RecipientLink struct {
	// Email is the recipient address.
	Email string
	// Link is the absolute download URL of that recipient, built from the
	// registered FQDN of the tenant.
	Link string
}

// normalizeLinks validates the recipient links (address and link) and drops
// the duplicate addresses, ignoring case; the first link of an address wins.
func normalizeLinks(in []RecipientLink) ([]RecipientLink, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("%w: no recipient", ErrInvalidTransfer)
	}
	if len(in) > MaxRecipients {
		return nil, fmt.Errorf("%w: more than %d recipients", ErrInvalidTransfer, MaxRecipients)
	}
	out := make([]RecipientLink, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, l := range in {
		addr, err := mail.ParseAddress(l.Email)
		if err != nil {
			return nil, fmt.Errorf("%w: recipient: %w", ErrInvalidTransfer, err)
		}
		if err := checkLink(l.Link); err != nil {
			return nil, err
		}
		key := strings.ToLower(addr)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, RecipientLink{Email: addr, Link: l.Link})
	}
	return out, nil
}

// PerRecipientJobs builds the transfer_notification mail of a transfer with
// one download link per recipient: one job per entry of links, each carrying
// the link of that recipient and the QR code of that link as an inline PNG.
// The other content is the one of [Notifier.RecipientJobs]; tr.Recipients is
// ignored (links is the list). Duplicate addresses (ignoring case) get a
// single mail, with their first link.
func (n *Notifier) PerRecipientJobs(ctx context.Context, t *tenant.Tenant, tr TransferView, links []RecipientLink) ([]mail.Job, error) {
	norm, err := normalizeLinks(links)
	if err != nil {
		return nil, err
	}
	v, err := n.prepareDownload(tr, norm[0].Link)
	if err != nil {
		return nil, err
	}
	settings, err := n.settings(ctx, t)
	if err != nil {
		return nil, err
	}
	label := n.levelLabel(t, tr)
	jobs := make([]mail.Job, 0, len(norm))
	for _, l := range norm {
		png, err := QRPNG(l.Link)
		if err != nil {
			return nil, err
		}
		data := mail.TransferNotificationData{
			TenantName: t.Name, SenderEmail: v.sender, Message: v.message, Link: l.Link,
			Files: v.files, ExpiresAt: tr.ExpiresAt, PasswordRequired: tr.PasswordProtected, QR: true,
			ConfidentialityLabel: label, ReplyToCreatedAt: tr.replyCreatedAt(),
		}
		m, err := n.render(ctx, t, tr, mail.TemplateTransferNotification, data)
		if err != nil {
			return nil, err
		}
		m.To = []string{l.Email}
		m.Inline = []mail.InlinePart{{ContentID: mail.QRContentID, ContentType: "image/png", Filename: qrFilename, Data: png}}
		jobs = append(jobs, n.job(t, mail.TemplateTransferNotification, settings, m))
	}
	n.logBuilt(ctx, t, tr, mail.TemplateTransferNotification, len(jobs))
	return jobs, nil
}

// ExpiryReminderJobs builds the expiry_reminder mail (CLAUDE.md section
// 12.2) of the recipients in links, who have not downloaded the transfer:
// one job per entry, each with the link of that recipient. The mail names
// the sender and the expiry, lists the delivered files with their size,
// shows the confidentiality level, tells that a password comes through
// another channel when the transfer is protected, and tells that a code will
// be asked when verificationRequired is set. It fails with
// ErrTransferExpired for an expired transfer.
func (n *Notifier) ExpiryReminderJobs(ctx context.Context, t *tenant.Tenant, tr TransferView, links []RecipientLink, verificationRequired bool) ([]mail.Job, error) {
	norm, err := normalizeLinks(links)
	if err != nil {
		return nil, err
	}
	v, err := n.prepareDownload(tr, norm[0].Link)
	if err != nil {
		return nil, err
	}
	settings, err := n.settings(ctx, t)
	if err != nil {
		return nil, err
	}
	label := n.levelLabel(t, tr)
	jobs := make([]mail.Job, 0, len(norm))
	for _, l := range norm {
		data := mail.ExpiryReminderData{
			TenantName: t.Name, SenderEmail: v.sender, Link: l.Link, Files: v.files, ExpiresAt: tr.ExpiresAt,
			PasswordRequired: tr.PasswordProtected, VerificationRequired: verificationRequired,
			ConfidentialityLabel: label,
		}
		m, err := n.render(ctx, t, tr, mail.TemplateExpiryReminder, data)
		if err != nil {
			return nil, err
		}
		m.To = []string{l.Email}
		jobs = append(jobs, n.job(t, mail.TemplateExpiryReminder, settings, m))
	}
	n.logBuilt(ctx, t, tr, mail.TemplateExpiryReminder, len(jobs))
	return jobs, nil
}

// RecipientVerificationCode builds the recipient_verification_code mail: the
// 6-digit code that the holder of a personal download link must enter before
// downloading, sent to the address of that link only (tr gives the language
// and the transfer ID for logs). The code is valid 15 minutes and is never
// logged. It fails with ErrInvalidTransfer for an invalid address or a code
// that is not 6 digits.
func (n *Notifier) RecipientVerificationCode(ctx context.Context, t *tenant.Tenant, tr TransferView, to, code string) (mail.Job, error) {
	addr, err := mail.ParseAddress(to)
	if err != nil {
		return mail.Job{}, fmt.Errorf("%w: recipient: %w", ErrInvalidTransfer, err)
	}
	if !vcode.Valid(code) {
		return mail.Job{}, fmt.Errorf("%w: verification code", ErrInvalidTransfer)
	}
	data := mail.RecipientVerificationCodeData{TenantName: t.Name, Code: code, ValidityMinutes: int(vcode.TTL.Minutes())}
	return n.senderJob(ctx, t, tr, addr, mail.TemplateRecipientVerificationCode, data)
}

// FirstDownloadBy is [Notifier.FirstDownload] for a transfer with one link
// per recipient: the mail also names recipient, the address that completed
// the download. An empty recipient gives the mail of FirstDownload.
func (n *Notifier) FirstDownloadBy(ctx context.Context, t *tenant.Tenant, tr TransferView, at, deleteAt time.Time, recipient string) (mail.Job, error) {
	if recipient != "" {
		addr, err := mail.ParseAddress(recipient)
		if err != nil {
			return mail.Job{}, fmt.Errorf("%w: recipient: %w", ErrInvalidTransfer, err)
		}
		recipient = addr
	}
	return n.firstDownload(ctx, t, tr, at, deleteAt, recipient)
}

// MyTransfersLinkJob builds the my_transfers_link mail: the one-time link
// that opens "My transfers", sent to the verified address to (the sender who
// asked for it). link is the absolute URL, https://<host>/me#mta_..., built
// by the caller from the registered FQDN of the tenant; it is a secret and
// is never logged. lang is the language of the mail ("" or an unsupported
// value for the tenant default). The link is valid for validity (shown in
// whole minutes). It fails with ErrInvalidTransfer for an invalid address or
// a non-positive validity, and with ErrInvalidLink for an invalid link.
func (n *Notifier) MyTransfersLinkJob(ctx context.Context, t *tenant.Tenant, lang, to, link string, validity time.Duration) (mail.Job, error) {
	addr, err := mail.ParseAddress(to)
	if err != nil {
		return mail.Job{}, fmt.Errorf("%w: recipient: %w", ErrInvalidTransfer, err)
	}
	if err := checkLink(link); err != nil {
		return mail.Job{}, err
	}
	if validity < time.Minute {
		return mail.Job{}, fmt.Errorf("%w: validity", ErrInvalidTransfer)
	}
	data := mail.MyTransfersLinkData{TenantName: t.Name, Link: link, ValidityMinutes: int(validity.Minutes())}
	return n.senderJob(ctx, t, TransferView{Language: lang}, addr, mail.TemplateMyTransfersLink, data)
}

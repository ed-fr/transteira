package scan

import (
	"context"
	"errors"
	"log/slog"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// builder builds one kind of mail.
type builder struct {
	template string
	build    func() ([]mail.Job, error)
}

// one adapts a single-job build to a builder.
func one(j mail.Job, err error) ([]mail.Job, error) {
	if err != nil {
		return nil, err
	}
	return []mail.Job{j}, nil
}

// notifyAvailable sends the mails of a transfer made available: one to each
// recipient, the confirmation to the sender, and the "file problems"
// (infected or withheld files) and "file not scanned" alerts when they apply.
// A shared transfer has a single link, sent to every recipient and shown in
// the confirmation. A transfer with one link per recipient has links (link
// is ""): each recipient gets their own link, and the confirmation carries
// none, since the sender never sees a recipient link (P27, T-199).
func (w *Worker) notifyAvailable(ctx context.Context, k key, t *tenant.Tenant, d store.TransferDetails, link string, links []notify.RecipientLink) {
	v := notify.ViewOf(d)
	recipients := func() ([]mail.Job, error) { return w.notifier.RecipientJobs(ctx, t, v, link) }
	if d.LinkMode == store.LinkModePerRecipient {
		recipients = func() ([]mail.Job, error) { return w.notifier.PerRecipientJobs(ctx, t, v, links) }
	}
	builders := []builder{
		{mail.TemplateTransferNotification, recipients},
		{mail.TemplateTransferConfirmation, func() ([]mail.Job, error) {
			return one(w.notifier.SenderConfirmation(ctx, t, v, link))
		}},
	}
	if count(v, notify.ScanInfected)+count(v, notify.ScanWithheld) > 0 {
		builders = append(builders, w.problemsBuilder(ctx, t, v))
	}
	if count(v, notify.ScanTooLarge)+count(v, notify.ScanEncrypted) > 0 {
		builders = append(builders, builder{mail.TemplateFileNotScanned, func() ([]mail.Job, error) {
			return one(w.notifier.FileNotScanned(ctx, t, v))
		}})
	}
	w.notify(ctx, k, builders)
}

// notifyRejected alerts the sender of a rejected transfer, whose files are
// all infected or withheld, with the file problems mail; the recipients are
// told nothing.
func (w *Worker) notifyRejected(ctx context.Context, k key, t *tenant.Tenant, d store.TransferDetails) {
	w.notify(ctx, k, []builder{w.problemsBuilder(ctx, t, notify.ViewOf(d))})
}

// problemsBuilder builds the file_problems mail.
func (w *Worker) problemsBuilder(ctx context.Context, t *tenant.Tenant, v notify.TransferView) builder {
	return builder{mail.TemplateFileProblems, func() ([]mail.Job, error) {
		return one(w.notifier.FileProblems(ctx, t, v))
	}}
}

// count returns the number of files of v with the scan result r.
func count(v notify.TransferView, r notify.ScanResult) int {
	n := 0
	for _, f := range v.Files {
		if f.Scan == r {
			n++
		}
	}
	return n
}

// notify builds the mails and enqueues them. A mail that cannot be built is
// logged and skipped; a tenant without SMTP settings stops everything, with
// one error line, since no mail can be sent for it. A held transfer gets no
// mail now (see [Worker.holdMailsLocked]): the hold is checked before the
// build, and again under the worker lock right before the mails are
// queued, so that a hold taken during the build is seen (the queue never
// blocks).
func (w *Worker) notify(ctx context.Context, k key, builders []builder) {
	if w.holdMails(ctx, k) {
		return
	}
	var jobs []mail.Job
	for _, b := range builders {
		js, err := b.build()
		switch {
		case errors.Is(err, notify.ErrNoSMTP):
			w.log(ctx, slog.LevelError, "no mail sent: the tenant has no SMTP settings, an administrator must configure them", k)
			return
		case err != nil:
			w.log(ctx, slog.LevelError, "notification mail not built", k,
				slog.String("template", b.template), slog.Any("error", err))
			continue
		}
		jobs = append(jobs, js...)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.holdMailsLocked(ctx, k) {
		return
	}
	w.mails.Send(ctx, jobs, slog.String("tenant", k.tid.String()), slog.String("transfer", k.id))
}

// holdMails is [Worker.holdMailsLocked] taking the worker lock.
func (w *Worker) holdMails(ctx context.Context, k key) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.holdMailsLocked(ctx, k)
}

// sendDeferred sends the mails deferred while the transfer d was held for
// an edit, rebuilt from its current state: to its remaining recipients,
// with the download link (or the link of each recipient) unsealed from the
// database, when it is available; the file problems mail when it is
// rejected. Any failure is logged.
func (w *Worker) sendDeferred(ctx context.Context, k key, d store.TransferDetails) {
	t, err := w.repo.tenant(ctx, k.tid)
	if err != nil {
		w.log(ctx, slog.LevelError, "deferred notification mails not sent: tenant not read", k, slog.Any("error", err))
		return
	}
	switch d.Status {
	case store.TransferRejected:
		w.notifyRejected(ctx, k, t, d)
	case store.TransferAvailable:
		if d.LinkMode == store.LinkModePerRecipient {
			links, err := w.openLinks(ctx, k, t)
			if err != nil {
				w.log(ctx, slog.LevelError, "deferred notification mails not sent: recipient links not opened", k,
					slog.Any("error", err))
				return
			}
			w.notifyAvailable(ctx, k, t, d, "", links)
			return
		}
		token, err := w.vault.Open(ctx, k.tid, crypto.PurposeSecret, d.DownloadTokenKeyID)
		if err != nil {
			w.log(ctx, slog.LevelError, "deferred notification mails not sent: download token not opened", k,
				slog.Any("error", err))
			return
		}
		link := id.DownloadURL(t.FQDN, string(token))
		clear(token)
		w.notifyAvailable(ctx, k, t, d, link, nil)
	default:
		w.log(ctx, slog.LevelInfo, "deferred notification mails dropped: the transfer is no longer available", k,
			slog.String("status", string(d.Status)))
	}
}

// openLinks unseals the token of each link of the transfer k, a transfer
// with one link per recipient, and returns the download URL of each
// recipient, built from the registered FQDN of tenant t. A link whose key
// was destroyed (its recipient erased) is skipped. The tokens are wiped
// once the URLs are built.
func (w *Worker) openLinks(ctx context.Context, k key, t *tenant.Tenant) ([]notify.RecipientLink, error) {
	links, err := w.repo.recipientLinks(ctx, k.tid, k.id)
	if err != nil {
		return nil, err
	}
	out := make([]notify.RecipientLink, 0, len(links))
	for _, l := range links {
		if l.TokenKeyID == "" {
			continue
		}
		token, err := w.vault.Open(ctx, k.tid, crypto.PurposeSecret, l.TokenKeyID)
		if err != nil {
			return nil, err
		}
		out = append(out, notify.RecipientLink{Email: l.Email, Link: id.DownloadURL(t.FQDN, string(token))})
		clear(token)
	}
	return out, nil
}

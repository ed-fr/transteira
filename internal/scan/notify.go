package scan

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

// mailBatch holds the mails of a transfer refused by the queue (full queue
// or open circuit), retried with backoff until deadline.
type mailBatch struct {
	k        key
	jobs     []mail.Job
	deadline time.Time
	attempt  int
}

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

// view returns what the mails show of the transfer d. A file in scan_error
// (or, defensively, in any status without a verdict) is withheld under
// fail-closed: never delivered, left out of the recipient mails and
// reported to the sender.
func view(d store.TransferDetails) notify.TransferView {
	v := notify.TransferView{
		ID: d.ID, Language: d.Language, SenderEmail: d.SenderEmail, Recipients: d.Recipients,
		Message: d.Message, ExpiresAt: d.ExpiresAt, PasswordProtected: d.PasswordProtected(),
	}
	for _, f := range d.Files {
		fv := notify.FileView{Name: f.Name, Size: f.Size, SHA256: f.SHA256}
		switch {
		case f.ScanStatus == store.ScanInfected:
			fv.Scan, fv.Signature = notify.ScanInfected, f.ScanSignature
		case !f.ScanStatus.Deliverable():
			fv.Scan = notify.ScanWithheld
		case f.ScanStatus == store.ScanNotScannedTooLarge:
			fv.Scan = notify.ScanTooLarge
		case f.ScanStatus == store.ScanNotScannedEncrypted:
			fv.Scan = notify.ScanEncrypted
		default:
			fv.Scan = notify.ScanClean
		}
		v.Files = append(v.Files, fv)
	}
	return v
}

// notifyAvailable sends the mails of a transfer made available: one to each
// recipient, the confirmation to the sender, and the "file problems"
// (infected or withheld files) and "file not scanned" alerts when they apply.
func (w *Worker) notifyAvailable(ctx context.Context, k key, t *tenant.Tenant, d store.TransferDetails, link string) {
	v := view(d)
	builders := []builder{
		{mail.TemplateTransferNotification, func() ([]mail.Job, error) {
			return w.notifier.RecipientJobs(ctx, t, v, link)
		}},
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
	w.notify(ctx, k, []builder{w.problemsBuilder(ctx, t, view(d))})
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
// one error line, since no mail can be sent for it.
func (w *Worker) notify(ctx context.Context, k key, builders []builder) {
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
	w.sendMails(ctx, &mailBatch{k: k, jobs: jobs, deadline: w.now().Add(w.opts.MailRetryFor)})
}

// sendMails enqueues the mails of b. Those refused because the queue is
// full or the tenant's circuit is open are retried with backoff until the
// deadline of b, then dropped with an error line; any other refusal is
// logged and the mail dropped.
func (w *Worker) sendMails(ctx context.Context, b *mailBatch) {
	var refused []mail.Job
	for _, j := range b.jobs {
		err := w.mail.Enqueue(j)
		switch {
		case err == nil:
		case errors.Is(err, mail.ErrQueueFull), errors.Is(err, mail.ErrCircuitOpen):
			refused = append(refused, j)
		default:
			w.log(ctx, slog.LevelError, "notification mail refused", b.k,
				slog.String("template", j.Template), slog.Any("error", err))
		}
	}
	if len(refused) == 0 {
		return
	}
	b.jobs = refused
	b.attempt++
	delay := w.backoff(b.attempt)
	if w.now().Add(delay).After(b.deadline) {
		w.log(ctx, slog.LevelError, "notification mails dropped: the mail queue kept refusing them", b.k,
			slog.Int("count", len(refused)))
		return
	}
	w.log(ctx, slog.LevelWarn, "notification mails refused by the queue, will retry", b.k,
		slog.Int("count", len(refused)), slog.Duration("retry_in", delay))
	w.schedule(ctx, task{mails: b}, delay)
}

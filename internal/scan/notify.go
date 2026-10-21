package scan

import (
	"context"
	"errors"
	"log/slog"

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
func (w *Worker) notifyAvailable(ctx context.Context, k key, t *tenant.Tenant, d store.TransferDetails, link string) {
	v := notify.ViewOf(d)
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
	w.mails.Send(ctx, jobs, slog.String("tenant", k.tid.String()), slog.String("transfer", k.id))
}

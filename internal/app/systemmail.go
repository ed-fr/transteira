package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/ed-fr/transteira/internal/avalert"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/diskalert"
	"github.com/ed-fr/transteira/internal/mail"
)

// systemQueueSize bounds the system mail queue: it only carries the disk
// and antivirus alerts, one mail per super admin and the alert address.
const systemQueueSize = 100

// systemMail is the mail channel of the instance mails (disk and antivirus
// alerts), separate from the tenant mail queue: its own queue, circuit
// breaker and drain, and its own SMTP sender.
//
// The sender is deliberately not guarded by TT_SMTP_DENY_NETWORKS: the
// system SMTP server is installation configuration (TT_SYSTEM_SMTP_*), set
// by the operator with the same trust as the database settings, and is
// typically a relay on localhost or on the Docker network, which the deny
// list refuses. The tenant SMTP settings, editable by delegated admins,
// stay guarded (threat model P21, T-154).
type systemMail struct {
	// settings are the SMTP settings of the system mails.
	settings mail.Settings
	// queue and retrier are nil when system mail is disabled.
	queue   *mail.Queue
	retrier *mail.Retrier
}

// systemSMTPSettings returns the mail settings of the system SMTP server s.
func systemSMTPSettings(s config.SystemSMTP) mail.Settings {
	return mail.Settings{
		Host: s.Host, Port: s.Port, Security: mail.Security(s.Security),
		Username: s.Username, Password: s.Password.Reveal(),
		FromAddress: s.From, FromName: s.FromName,
	}
}

// newSystemMail returns the system mail channel of cfg: disabled (no queue)
// without TT_SYSTEM_SMTP_HOST, otherwise a queue delivering through an
// unguarded SMTP sender (see systemMail). Invalid settings refuse the
// start.
func newSystemMail(cfg *config.Config, logger *slog.Logger) (*systemMail, error) {
	if !cfg.SystemSMTP.Enabled() {
		return &systemMail{}, nil
	}
	settings := systemSMTPSettings(cfg.SystemSMTP)
	if err := settings.Validate(); err != nil {
		return nil, fmt.Errorf("app: system SMTP settings (TT_SYSTEM_SMTP_*): %w", err)
	}
	sender := mail.NewSMTPSender(mail.SMTPOptions{Timeout: cfg.SMTPTimeout})
	// The queue owns the context of its deliveries, canceled by Close.
	queue := mail.NewQueue(sender, systemQueueSize, logger, mail.QueueOptions{Workers: 1})
	return &systemMail{
		settings: settings, queue: queue,
		retrier: mail.NewRetrier(queue, mail.RetryOptions{Logger: logger}),
	}, nil
}

// mailer returns the mailer of the disk and antivirus alerts, nil when
// system mail is disabled.
func (s *systemMail) mailer() diskalert.Mailer {
	if s.retrier == nil {
		return nil
	}
	return s.retrier
}

// Close stops the retrier of the system mails (closer of closeStages).
func (s *systemMail) Close(ctx context.Context) error {
	if s.retrier == nil {
		return nil
	}
	return s.retrier.Close(ctx)
}

// closeMailQueues drains the queues in parallel, each for at most
// MailDrainTimeout, so that the system queue fits in the same budget as the
// tenant queue. Nil queues are skipped.
func closeMailQueues(ctx context.Context, logger *slog.Logger, queues ...*mail.Queue) {
	var wg sync.WaitGroup
	for _, q := range queues {
		if q != nil {
			wg.Go(func() { closeMailQueue(ctx, q, logger) })
		}
	}
	wg.Wait()
}

// diskAlertOptions returns the options of the disk alert monitor: the data
// directory, the administration link and the system mail channel, edited
// by WithDiskAlertOptions when given.
func diskAlertOptions(cfg *config.Config, o *runOptions, sys *systemMail, logger *slog.Logger) diskalert.Options {
	opts := diskalert.Options{
		DataDir: cfg.DataDir, AdminLink: adminBaseURL(cfg) + "/admin", Mailer: sys.mailer(), SMTP: sys.settings,
		Logger: logger,
	}
	if o.diskAlertOpts != nil {
		o.diskAlertOpts(&opts)
	}
	return opts
}

// antivirusAlertOptions completes opts, the options of the antivirus alert
// monitor, with the administration link and the system mail channel, then
// lets WithAntivirusAlertOptions edit them when given.
func antivirusAlertOptions(cfg *config.Config, o *runOptions, sys *systemMail, opts avalert.Options) avalert.Options {
	opts.AdminLink, opts.SystemMailer, opts.SMTP = adminBaseURL(cfg)+"/admin", sys.mailer(), sys.settings
	if o.avAlertOpts != nil {
		o.avAlertOpts(&opts)
	}
	return opts
}

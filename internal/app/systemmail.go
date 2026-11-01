package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/avalert"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/diskalert"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenantadmin"
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

// invitationMailer sends the activation links of the administrators
// invited by mail through the system mail channel (adminauth.Mailer).
type invitationMailer struct {
	mailer    diskalert.Mailer
	settings  mail.Settings
	adminHost string
	logger    *slog.Logger
	// render renders a mail template (mail.Render; a field for the tests).
	render func(name, lang string, data any) (mail.Message, error)
}

// invitations returns the invitation mailer of the system mail channel,
// nil when system mail is disabled (the mail delivery is then refused).
func (s *systemMail) invitations(cfg *config.Config, logger *slog.Logger) adminauth.Mailer {
	if s.retrier == nil {
		return nil
	}
	return &invitationMailer{
		mailer: s.retrier, settings: s.settings, adminHost: cfg.AdminHosts[0], logger: logger, render: mail.Render,
	}
}

// SendInvitation renders the admin_invitation mail of m and queues it. A
// rendering failure is logged without the link; the delivery failures are
// logged by the queue.
func (im *invitationMailer) SendInvitation(ctx context.Context, m adminauth.InvitationMail) {
	msg, err := im.render(mail.TemplateAdminInvitation, m.Language, mail.AdminInvitationData{
		Username: m.Username, TenantNames: m.TenantNames, Link: m.Link, AdminHost: im.adminHost, ExpiresAt: m.ExpiresAt,
	})
	if err != nil {
		im.logger.ErrorContext(ctx, "admin invitation mail not sent: render failed", slog.Any("error", err))
		return
	}
	msg.To = []string{m.To}
	im.mailer.Send(ctx, []mail.Job{{TenantID: diskalert.MailTenantID, Template: mail.TemplateAdminInvitation, Settings: im.settings, Message: msg}},
		slog.String("template", mail.TemplateAdminInvitation))
}

// provisioningNotifier tells the super admins, through the system mail
// channel, that a tenant was created through the provisioning API, that
// such a tenant completed its setup (tenantadmin.ProvisioningNotifier,
// threat model P50) or that a provisioning token was created (T-275). Each super admin gets the mail in their language; the
// link of the mail is built from the configured admin host, never from a
// request Host.
type provisioningNotifier struct {
	mailer   diskalert.Mailer
	settings mail.Settings
	// contacts lists the super admins to notify
	// (store.Admins.SuperAdminContacts).
	contacts func(ctx context.Context) ([]store.AdminContact, error)
	// adminBase is the base URL of the administration (adminBaseURL).
	adminBase string
	logger    *slog.Logger
	// render renders a mail template (mail.Render; a field for the tests).
	render func(name, lang string, data any) (mail.Message, error)
}

// provisioning returns the provisioning notifier of the system mail
// channel, nil when system mail is disabled (no tenant can then be
// provisioned, and a setup completion is not mailed).
func (s *systemMail) provisioning(cfg *config.Config, contacts func(context.Context) ([]store.AdminContact, error),
	logger *slog.Logger,
) tenantadmin.ProvisioningNotifier {
	if s.retrier == nil {
		return nil
	}
	return &provisioningNotifier{
		mailer: s.retrier, settings: s.settings, contacts: contacts, adminBase: adminBaseURL(cfg), logger: logger,
		render: mail.Render,
	}
}

// TenantProvisioned mails the tenant_provisioned notice of n.
func (p *provisioningNotifier) TenantProvisioned(ctx context.Context, n tenantadmin.ProvisioningNotice) {
	p.send(ctx, mail.TemplateTenantProvisioned, tenantAttr(n), mail.TenantProvisionedData{
		TokenName: n.TokenName, TokenPrefix: n.TokenPrefix, TenantName: n.TenantName, FQDN: n.FQDN,
		AdminUsername: n.AdminUsername, ClientIP: ipText(n.ClientIP), At: n.At, AdminLink: p.adminLink(n),
	})
}

// TenantSetupCompleted mails the tenant_setup_completed notice of n.
func (p *provisioningNotifier) TenantSetupCompleted(ctx context.Context, n tenantadmin.ProvisioningNotice) {
	p.send(ctx, mail.TemplateTenantSetupCompleted, tenantAttr(n), mail.TenantSetupCompletedData{
		TenantName: n.TenantName, FQDN: n.FQDN, At: n.At, Forced: n.Forced, AdminLink: p.adminLink(n),
	})
}

// TokenCreated mails the provisioning_token_created notice of n (threat
// model T-275), with the link to the provisioning tokens page.
func (p *provisioningNotifier) TokenCreated(ctx context.Context, n tenantadmin.ProvisioningTokenNotice) {
	p.send(ctx, mail.TemplateProvisioningTokenCreated, slog.String("token", n.TokenID), mail.ProvisioningTokenCreatedData{
		TokenName: n.TokenName, TokenPrefix: n.TokenPrefix, CreatedBy: n.CreatedBy, ClientIP: ipText(n.ClientIP),
		At: n.At, CIDRCount: n.CIDRCount, SuffixCount: n.SuffixCount, MaxTenants: n.MaxTenants,
		MaxStorageQuotaBytes: n.MaxStorageQuotaBytes, ExpiresAt: n.ExpiresAt,
		AdminLink: p.adminBase + events.AdminPathProvisioningTokens,
	})
}

// tenantAttr is the log attribute naming the tenant of n.
func tenantAttr(n tenantadmin.ProvisioningNotice) slog.Attr {
	return slog.String("tenant", string(n.TenantID))
}

// ipText returns ip as text, "" when it is invalid.
func ipText(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

// adminLink returns the link to the page of the tenant of n in the
// administration.
func (p *provisioningNotifier) adminLink(n tenantadmin.ProvisioningNotice) string {
	return p.adminBase + tenantadmin.AdminPathTenant(n.TenantID)
}

// send renders template with data in the language of each super admin and
// queues one mail per super admin; subject is the log attribute naming the
// tenant or token concerned. The failures are logged, never returned: the
// tenant or token is already created or active.
func (p *provisioningNotifier) send(ctx context.Context, template string, subject slog.Attr, data any) {
	attrs := []any{slog.String("template", template), subject}
	contacts, err := p.contacts(ctx)
	if err != nil {
		p.logger.ErrorContext(ctx, "provisioning notice not mailed: list the super admins", append(attrs, slog.Any("error", err))...)
		return
	}
	// byLang holds the message of each language, nil when it failed to
	// render: its recipients are skipped, the others still mailed.
	byLang := make(map[string]*mail.Message, 2)
	jobs := make([]mail.Job, 0, len(contacts))
	for _, c := range contacts {
		lang := c.Language
		if !i18n.IsSupported(lang) {
			lang = i18n.Default
		}
		rendered, ok := byLang[lang]
		if !ok {
			msg, err := p.render(template, lang, data)
			if err != nil {
				p.logger.ErrorContext(ctx, "provisioning notice not mailed: render failed",
					append(attrs, slog.String("language", lang), slog.Any("error", err))...)
			} else {
				rendered = &msg
			}
			byLang[lang] = rendered
		}
		if rendered == nil {
			continue
		}
		msg := *rendered
		msg.To = []string{c.Email}
		jobs = append(jobs, mail.Job{TenantID: diskalert.MailTenantID, Template: template, Settings: p.settings, Message: msg})
	}
	if len(jobs) == 0 {
		p.logger.WarnContext(ctx, "provisioning notice not mailed: no recipient", attrs...)
		return
	}
	p.mailer.Send(ctx, jobs, slog.String("template", template))
}

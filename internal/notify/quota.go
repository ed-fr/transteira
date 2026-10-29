package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/tenant"
)

// MaxContacts is a backstop on the number of administrators notified by one
// alert.
const MaxContacts = 100

// ErrInvalidAlert is returned for an alert that cannot be built: unknown
// level, no recipient, too many recipients or an invalid address.
var ErrInvalidAlert = errors.New("notify: invalid alert")

// QuotaLevel is the storage quota threshold an alert reports, in percent of
// the quota (CLAUDE.md section 8.5).
type QuotaLevel int

// Quota alert levels.
const (
	// QuotaWarning is the preventive alert, at 80 % of the quota.
	QuotaWarning QuotaLevel = 80
	// QuotaReached is the alert sent when the quota is used up and new
	// deposits are refused.
	QuotaReached QuotaLevel = 100
)

// template returns the mail template of the level, "" for an unknown
// level.
func (l QuotaLevel) template() string {
	switch l {
	case QuotaWarning:
		return mail.TemplateQuotaWarning
	case QuotaReached:
		return mail.TemplateQuotaReached
	}
	return ""
}

// Contact is an administrator to notify.
type Contact struct {
	// Email is the mail address.
	Email string
	// Language is the preferred language, "" (or an unsupported value)
	// for the tenant default.
	Language string
}

// QuotaAlert builds the quota_warning (level [QuotaWarning]) or
// quota_reached (level [QuotaReached]) mail of every recipient: one job per
// recipient, in its language else the tenant default, rendered with the
// customized template of the tenant when there is one and sent through the
// SMTP settings of the tenant. Duplicate recipients (ignoring case) get a
// single mail. An empty data.TenantName is filled with the tenant name.
//
// It returns ErrInvalidAlert for an unknown level or an invalid recipient
// list, ErrInvalidLink when data.AdminLink is not an absolute http or https
// URL, and ErrNoSMTP when the tenant has no SMTP settings.
func (n *Notifier) QuotaAlert(ctx context.Context, t *tenant.Tenant, data mail.QuotaAlertData, level QuotaLevel, recipients []Contact) ([]mail.Job, error) {
	name := level.template()
	if name == "" {
		return nil, fmt.Errorf("%w: quota level %d", ErrInvalidAlert, level)
	}
	if data.TenantName == "" {
		data.TenantName = t.Name
	}
	return n.adminAlert(ctx, t, name, data.AdminLink, data, recipients)
}

// AntivirusUnavailable builds the antivirus_unavailable mail of every
// recipient (tenant template key "antivirus-unavailable", decision P10):
// one job per recipient, in its language else the tenant default, rendered
// with the customized template of the tenant when there is one and sent
// through the SMTP settings of the tenant. Duplicate recipients (ignoring
// case) get a single mail. An empty data.TenantName is filled with the
// tenant name.
//
// It returns ErrInvalidAlert for an invalid recipient list, ErrInvalidLink
// when data.AdminLink is not an absolute http or https URL, and ErrNoSMTP
// when the tenant has no SMTP settings.
func (n *Notifier) AntivirusUnavailable(ctx context.Context, t *tenant.Tenant, data mail.AntivirusUnavailableData, recipients []Contact) ([]mail.Job, error) {
	if data.TenantName == "" {
		data.TenantName = t.Name
	}
	return n.adminAlert(ctx, t, mail.TemplateAntivirusUnavailable, data.AdminLink, data, recipients)
}

// adminAlert builds the mails of template name, rendered with data, to the
// administrators recipients of tenant t; adminLink is the console link of
// data, checked first.
func (n *Notifier) adminAlert(ctx context.Context, t *tenant.Tenant, name, adminLink string, data any, recipients []Contact) ([]mail.Job, error) {
	if err := checkLink(adminLink); err != nil {
		return nil, err
	}
	contacts, err := normalizeContacts(recipients)
	if err != nil {
		return nil, err
	}
	settings, err := n.settings(ctx, t)
	if err != nil {
		return nil, err
	}
	// One rendering per language: the message only differs by recipient.
	byLang := make(map[string]mail.Message, 2)
	jobs := make([]mail.Job, 0, len(contacts))
	for _, c := range contacts {
		lang := t.DefaultLanguage
		if i18n.IsSupported(c.Language) {
			lang = c.Language
		}
		msg, ok := byLang[lang]
		if !ok {
			msg, err = n.templates.RenderFor(ctx, n.overrides, t.ID.String(), name, lang, data)
			if err != nil {
				return nil, fmt.Errorf("notify: render %s: %w", name, err)
			}
			byLang[lang] = msg
		}
		msg.To = []string{c.Email}
		jobs = append(jobs, n.job(t, name, settings, msg))
	}
	n.logger.LogAttrs(ctx, slog.LevelDebug, "alert mails built",
		slog.String("tenant", t.ID.String()),
		slog.String("template", name),
		slog.Int("count", len(jobs)))
	return jobs, nil
}

// normalizeContacts validates and normalizes the recipient addresses and
// drops duplicates, ignoring case; the first occurrence keeps its language.
func normalizeContacts(in []Contact) ([]Contact, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("%w: no recipient", ErrInvalidAlert)
	}
	if len(in) > MaxContacts {
		return nil, fmt.Errorf("%w: more than %d recipients", ErrInvalidAlert, MaxContacts)
	}
	out := make([]Contact, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, c := range in {
		addr, err := mail.ParseAddress(c.Email)
		if err != nil {
			return nil, fmt.Errorf("%w: recipient: %w", ErrInvalidAlert, err)
		}
		key := strings.ToLower(addr)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Contact{Email: addr, Language: c.Language})
	}
	return out, nil
}

// AbuseAlert builds the abuse_alert mail of every recipient (tenant template
// key "abuse-alert", CLAUDE.md section 15): one job per recipient, in its
// language else the tenant default, rendered with the customized template
// of the tenant when there is one and sent through the SMTP settings of the
// tenant. Duplicate recipients (ignoring case) get a single mail. An empty
// data.TenantName is filled with the tenant name.
//
// It returns ErrInvalidAlert for an invalid recipient list, ErrInvalidLink
// when data.AdminLink is not an absolute http or https URL, and ErrNoSMTP
// when the tenant has no SMTP settings.
func (n *Notifier) AbuseAlert(ctx context.Context, t *tenant.Tenant, data mail.AbuseAlertData, recipients []Contact) ([]mail.Job, error) {
	if data.TenantName == "" {
		data.TenantName = t.Name
	}
	return n.adminAlert(ctx, t, mail.TemplateAbuseAlert, data.AdminLink, data, recipients)
}

// AbuseReport builds the abuse_report mail of every recipient (tenant
// template key "abuse-report"), like [Notifier.AbuseAlert]. The free text of
// the reporter is quoted in the text body and escaped in the HTML body, never
// interpreted.
//
// It returns ErrInvalidAlert for an invalid recipient list, ErrInvalidLink
// when data.AdminLink is not an absolute http or https URL, and ErrNoSMTP
// when the tenant has no SMTP settings.
func (n *Notifier) AbuseReport(ctx context.Context, t *tenant.Tenant, data mail.AbuseReportData, recipients []Contact) ([]mail.Job, error) {
	if data.TenantName == "" {
		data.TenantName = t.Name
	}
	return n.adminAlert(ctx, t, mail.TemplateAbuseReport, data.AdminLink, data, recipients)
}

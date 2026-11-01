package app

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/diskalert"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

func TestSystemMailProvisioning(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{AdminHosts: []string{adminHost, "other-admin.example.com"}}
	contacts := func(context.Context) ([]store.AdminContact, error) { return nil, nil }
	off, err := newSystemMail(&config.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := off.provisioning(cfg, contacts, slog.New(slog.DiscardHandler)); n != nil {
		t.Fatalf("notifier without system mail = %v, want nil", n)
	}
	on, err := newSystemMail(&config.Config{SystemSMTP: config.SystemSMTP{
		Host: "smtp.example.com", Port: 25, Security: config.SMTPSecurityNone, From: "noreply@example.com",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = on.Close(context.Background()) })
	n, ok := on.provisioning(cfg, contacts, slog.New(slog.DiscardHandler)).(*provisioningNotifier)
	if !ok || n.adminBase != "https://"+adminHost || n.settings != on.settings || n.mailer == nil || n.render == nil ||
		n.contacts == nil {
		t.Fatalf("notifier = %+v", n)
	}
}

// provisioningNotice is the notice of a tenant provisioned by token "MSP".
func provisioningNotice() tenantadmin.ProvisioningNotice {
	return tenantadmin.ProvisioningNotice{
		TenantID: "ten_01JAB00000000000000ENT1TYC", TenantName: "Entity C", FQDN: "entity-c.transfer.example.com",
		TokenID: "prv_01JABCT1V2W3X4Y5Z6A7B8C9D0", TokenName: "MSP", TokenPrefix: "ttp_EXAM", AdminUsername: "admin.entity-c",
		ClientIP: netip.MustParseAddr("198.51.100.7"), At: time.Date(2026, 10, 31, 9, 12, 0, 0, time.UTC),
	}
}

// TestProvisioningNotifier renders the two notices with the real
// templates, to every super admin in their language (the default one for
// an unsupported language), with the link of the tenant on the configured
// admin host.
func TestProvisioningNotifier(t *testing.T) {
	t.Parallel()
	settings := mail.Settings{Host: "smtp.example.com", Port: 25, FromAddress: "noreply@example.com"}
	contacts := []store.AdminContact{
		{AdminID: "adm_1", Email: "root@example.com", Language: "fr"},
		{AdminID: "adm_2", Email: "ops@example.com", Language: "en"},
		{AdminID: "adm_3", Email: "other@example.com", Language: "xx"},
	}
	rec := &recordingMailer{}
	n := &provisioningNotifier{
		mailer: rec, settings: settings, adminBase: "https://" + adminHost, logger: slog.New(slog.DiscardHandler),
		render:   mail.Render,
		contacts: func(context.Context) ([]store.AdminContact, error) { return contacts, nil },
	}
	notice := provisioningNotice()
	link := "https://" + adminHost + "/admin/tenants/" + string(notice.TenantID)
	n.TenantProvisioned(context.Background(), notice)
	if len(rec.jobs) != 3 {
		t.Fatalf("jobs = %d", len(rec.jobs))
	}
	for i, j := range rec.jobs {
		if j.TenantID != diskalert.MailTenantID || j.Template != mail.TemplateTenantProvisioned || j.Settings != settings ||
			len(j.Message.To) != 1 || j.Message.To[0] != contacts[i].Email || j.Message.Subject == "" ||
			!strings.Contains(j.Message.Text, link) || !strings.Contains(j.Message.Text, "entity-c.transfer.example.com") ||
			!strings.Contains(j.Message.Text, "198.51.100.7") || !strings.Contains(j.Message.Text, "ttp_EXAM") {
			t.Errorf("job %d: %+v", i, j)
		}
	}
	if rec.jobs[0].Message.Subject == rec.jobs[1].Message.Subject || rec.jobs[1].Message.Subject != rec.jobs[2].Message.Subject {
		t.Errorf("subjects %q %q %q, want French then English twice", rec.jobs[0].Message.Subject,
			rec.jobs[1].Message.Subject, rec.jobs[2].Message.Subject)
	}

	rec.jobs = nil
	notice.Forced = true
	n.TenantSetupCompleted(context.Background(), notice)
	if len(rec.jobs) != 3 || rec.jobs[0].Template != mail.TemplateTenantSetupCompleted || !strings.Contains(rec.jobs[0].Message.Text, link) {
		t.Fatalf("setup completed jobs %+v", rec.jobs)
	}
}

// TestProvisioningNotifierFailures checks the failures: a contact list
// failure or no super admin sends nothing, a rendering failure skips the
// recipients of its language only, and an invalid client IP is rendered
// empty.
func TestProvisioningNotifierFailures(t *testing.T) {
	t.Parallel()
	var logs strings.Builder
	rec := &recordingMailer{}
	var contactsErr error
	var contacts []store.AdminContact
	var data []any
	n := &provisioningNotifier{
		mailer: rec, adminBase: "https://" + adminHost, logger: slog.New(slog.NewTextHandler(&logs, nil)),
		contacts: func(context.Context) ([]store.AdminContact, error) { return contacts, contactsErr },
		render: func(_, lang string, d any) (mail.Message, error) {
			data = append(data, d)
			if lang == "fr" {
				return mail.Message{}, errors.New("render failed")
			}
			return mail.Message{Subject: "s"}, nil
		},
	}
	notice := provisioningNotice()
	contactsErr = errors.New("database is locked")
	n.TenantProvisioned(context.Background(), notice)
	if len(rec.jobs) != 0 || !strings.Contains(logs.String(), "list the super admins") {
		t.Errorf("contacts failure: %d jobs, logs %s", len(rec.jobs), logs.String())
	}
	contactsErr = nil
	n.TenantProvisioned(context.Background(), notice)
	if len(rec.jobs) != 0 || !strings.Contains(logs.String(), "no recipient") {
		t.Errorf("no contact: %d jobs, logs %s", len(rec.jobs), logs.String())
	}
	contacts = []store.AdminContact{
		{Email: "a@example.com", Language: "fr"}, {Email: "b@example.com", Language: "fr"}, {Email: "c@example.com", Language: "en"},
	}
	notice.ClientIP = netip.Addr{}
	data = nil
	n.TenantProvisioned(context.Background(), notice)
	if len(rec.jobs) != 1 || rec.jobs[0].Message.To[0] != "c@example.com" || !strings.Contains(logs.String(), "render failed") {
		t.Errorf("render failure: jobs %+v, logs %s", rec.jobs, logs.String())
	}
	if len(data) != 2 { // one rendering per language
		t.Errorf("%d renderings", len(data))
	}
	if d, ok := data[0].(mail.TenantProvisionedData); !ok || d.ClientIP != "" || d.TokenName != "MSP" ||
		d.AdminUsername != "admin.entity-c" || d.AdminLink != "https://"+adminHost+"/admin/tenants/"+string(notice.TenantID) {
		t.Errorf("data %+v", data[0])
	}
	// Only French recipients, all failing: nothing sent.
	rec.jobs = nil
	contacts = contacts[:2]
	n.TenantSetupCompleted(context.Background(), notice)
	if len(rec.jobs) != 0 {
		t.Errorf("jobs %+v", rec.jobs)
	}
}

// TestProvisioningNotifierTokenCreated renders the notice of a new
// provisioning token with the real templates, to every super admin in their
// language, with the link of the provisioning tokens page on the configured
// admin host; the notice carries no secret, and an invalid client IP is
// rendered empty.
func TestProvisioningNotifierTokenCreated(t *testing.T) {
	t.Parallel()
	contacts := []store.AdminContact{
		{AdminID: "adm_1", Email: "root@example.com", Language: "fr"},
		{AdminID: "adm_2", Email: "ops@example.com", Language: "en"},
	}
	rec := &recordingMailer{}
	var data []any
	n := &provisioningNotifier{
		mailer: rec, adminBase: "https://" + adminHost, logger: slog.New(slog.DiscardHandler),
		render: func(name, lang string, d any) (mail.Message, error) {
			data = append(data, d)
			return mail.Render(name, lang, d)
		},
		contacts: func(context.Context) ([]store.AdminContact, error) { return contacts, nil },
	}
	notice := tenantadmin.ProvisioningTokenNotice{
		TokenID: "prv_01JABCT1V2W3X4Y5Z6A7B8C9D0", TokenName: "MSP", TokenPrefix: "ttp_EXAM", CreatedBy: "root",
		ClientIP: netip.MustParseAddr("198.51.100.7"), At: time.Date(2026, 10, 31, 9, 12, 0, 0, time.UTC),
		CIDRCount: 2, SuffixCount: 1, MaxTenants: 50, MaxStorageQuotaBytes: 1 << 40,
	}
	link := "https://" + adminHost + "/admin/system/provisioning-tokens"
	n.TokenCreated(context.Background(), notice)
	if len(rec.jobs) != 2 {
		t.Fatalf("jobs = %d", len(rec.jobs))
	}
	for i, j := range rec.jobs {
		if j.TenantID != diskalert.MailTenantID || j.Template != mail.TemplateProvisioningTokenCreated ||
			len(j.Message.To) != 1 || j.Message.To[0] != contacts[i].Email || j.Message.Subject == "" ||
			!strings.Contains(j.Message.Text, link) || !strings.Contains(j.Message.Text, "198.51.100.7") ||
			!strings.Contains(j.Message.Text, "ttp_EXAM") || !strings.Contains(j.Message.Text, "MSP") {
			t.Errorf("job %d: %+v", i, j)
		}
	}
	if rec.jobs[0].Message.Subject == rec.jobs[1].Message.Subject {
		t.Errorf("subjects %q %q, want French then English", rec.jobs[0].Message.Subject, rec.jobs[1].Message.Subject)
	}
	want := mail.ProvisioningTokenCreatedData{
		TokenName: "MSP", TokenPrefix: "ttp_EXAM", CreatedBy: "root", ClientIP: "198.51.100.7", At: notice.At,
		CIDRCount: 2, SuffixCount: 1, MaxTenants: 50, MaxStorageQuotaBytes: 1 << 40, AdminLink: link,
	}
	if len(data) != 2 || data[0] != want {
		t.Errorf("data %+v, want %+v", data, want)
	}
	rec.jobs, data = nil, nil
	notice.ClientIP = netip.Addr{}
	n.TokenCreated(context.Background(), notice)
	if d, ok := data[0].(mail.ProvisioningTokenCreatedData); !ok || d.ClientIP != "" || len(rec.jobs) != 2 {
		t.Errorf("invalid IP: data %+v, %d jobs", data[0], len(rec.jobs))
	}
}

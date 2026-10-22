package deposit

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// customMark marks the subject and the text of the customized templates.
const customMark = "[Custom]"

// customize stores for tn a customization of template key in every
// language: the default template with customMark added to the subject and
// the text.
func (ev *env) customize(t *testing.T, tn *tenant.Tenant, key string) {
	t.Helper()
	for _, lang := range []string{"en", "fr"} {
		src, err := mail.DefaultSource(key, lang)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ev.db.TenantEmailTemplates().Put(context.Background(), tn.ID, store.EmailTemplate{
			Key: key, Language: lang, Subject: customMark + " " + src.Subject, BodyHTML: src.HTML,
			BodyText: customMark + "\n" + src.Text,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// customized reports whether job was rendered from a customized template.
func customized(job mail.Job) bool {
	return strings.HasPrefix(job.Message.Subject, customMark) && strings.HasPrefix(job.Message.Text, customMark)
}

// TestCustomizedTemplates checks that the verification code and invitation
// mails of a tenant use its customized templates, and that the mails of
// another tenant keep the defaults.
func TestCustomizedTemplates(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)

		// No customization: the defaults.
		ev.mustChallenge(t, ev.a, internalIP, alice, "")
		if job := ev.queue.last(t); customized(job) || job.Template != mail.TemplateVerificationCode {
			t.Errorf("default verification mail customized: %q", job.Message.Subject)
		}

		ev.customize(t, ev.a, store.EmailTemplateVerificationCode)
		ev.customize(t, ev.a, store.EmailTemplateInvitation)

		ev.mustChallenge(t, ev.a, internalIP, alice, "")
		job := ev.queue.last(t)
		if !customized(job) || job.Template != mail.TemplateVerificationCode || job.TenantID != ev.a.ID.String() {
			t.Errorf("verification mail of A not customized: %q", job.Message.Subject)
		}
		_ = codeOf(t, job) // the mandatory code is still there
		ev.mustChallenge(t, ev.b, internalIP, alice, "")
		if job := ev.queue.last(t); customized(job) || job.TenantID != ev.b.ID.String() {
			t.Errorf("verification mail of B uses the template of A: %q", job.Message.Subject)
		}

		ev.mustInvite(t, bob)
		job = ev.queue.last(t)
		if !customized(job) || job.Template != mail.TemplateInvitation || job.TenantID != ev.a.ID.String() {
			t.Errorf("invitation mail of A not customized: %q", job.Message.Subject)
		}
		s := ev.mustSession(t, ev.b, internalIP, alice, "")
		if _, err := ev.svc.Invite(ctx, ev.b, s.SessionInfo, internalIP, "", bob, "", "fr"); err != nil {
			t.Fatalf("Invite(B): %v", err)
		}
		job = ev.queue.last(t)
		if customized(job) || job.Template != mail.TemplateInvitation || job.TenantID != ev.b.ID.String() {
			t.Errorf("invitation mail of B uses the template of A: %q", job.Message.Subject)
		}
		_, _ = linkOf(t, job)
	})
}

// TestCustomizedTemplateLookupFailure checks that a failure to read the
// customized template does not stop the mail: the default template is used
// and a warning names the tenant and the template, without any address.
func TestCustomizedTemplateLookupFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.customize(t, ev.a, store.EmailTemplateVerificationCode)
		ev.customize(t, ev.a, store.EmailTemplateInvitation)
		var logs syncBuffer
		ev.svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
		ev.svc.overrides = func(context.Context, string, string, string) (*mail.TemplateSource, error) {
			return nil, errFault
		}

		check := func(template string) {
			t.Helper()
			job := ev.queue.last(t)
			if customized(job) || job.Template != template {
				t.Errorf("%s: customized despite the lookup failure: %q", template, job.Message.Subject)
			}
			out := logs.String()
			for _, s := range []string{"level=WARN", "tenant=" + ev.a.ID.String(), "template=" + template, errFault.Error()} {
				if !strings.Contains(out, s) {
					t.Errorf("%s: log lacks %q: %s", template, s, out)
				}
			}
			if strings.Contains(out, "@") {
				t.Errorf("%s: log holds an address: %s", template, out)
			}
		}
		ev.mustChallenge(t, ev.a, internalIP, alice, "")
		check(mail.TemplateVerificationCode)
		ev.mustInvite(t, bob)
		check(mail.TemplateInvitation)
	})
}

// TestNoOverrides checks that a service without a customization source
// uses the default templates.
func TestNoOverrides(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.customize(t, ev.a, store.EmailTemplateVerificationCode)
		ev.svc.overrides = nil
		ev.mustChallenge(t, ev.a, internalIP, alice, "")
		if job := ev.queue.last(t); customized(job) {
			t.Errorf("customized without a customization source: %q", job.Message.Subject)
		}
	})
}

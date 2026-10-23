package tenantadmin

import (
	"context"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

const keyCode = store.EmailTemplateVerificationCode

// diskAlertKey is the API spelling of the instance disk alert mail, which
// has a built-in template but is no tenant template key.
const diskAlertKey = "disk-alert"

// goodTemplate is a valid customization of the verification code mail.
func goodTemplate() TemplateInput {
	return TemplateInput{
		Subject: "Your code for {{tenant_name}}",
		HTML: `<p>Code: <strong>{{code}}</strong></p><script>alert(1)</script>` +
			`<a href="javascript:alert(2)" onclick="steal()">x</a><img src="https://tracker.example.com/p.gif">`,
		Text: "Code: {{code}}\r\n",
	}
}

func TestTemplates(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		list, err := ev.svc.ListTemplates(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "list", err)
		if len(list) != 2*len(templateKeys()) || list[0].Customized {
			t.Fatalf("list: %+v", list)
		}
		// The disk alert has a built-in template, but it is an instance
		// mail: it must never be offered to an entity.
		if _, err := mail.Variables(diskAlertKey); err != nil {
			t.Fatalf("the disk alert has no built-in template: %v", err)
		}
		listed := map[string]bool{}
		for _, s := range list {
			if s.Key == diskAlertKey || s.Key == mail.TemplateDiskAlert {
				t.Fatal("the instance disk alert template is listed as a tenant template")
			}
			listed[s.Key] = true
		}
		if !listed[store.EmailTemplateQuotaWarning] || !listed[store.EmailTemplateQuotaReached] {
			t.Fatalf("quota alert templates not listed: %v", listed)
		}

		tpl, err := ev.svc.GetTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "fr")
		mustNoErr(t, "get default", err)
		if tpl.Customized || tpl.Subject == "" || !strings.Contains(tpl.HTML, "{{code}}") || len(tpl.Variables) == 0 {
			t.Fatalf("default: %+v", tpl)
		}

		tpl, err = ev.svc.UpdateTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", goodTemplate(), clientIP)
		mustNoErr(t, "update", err)
		for _, bad := range []string{"<script", "onclick", "javascript:", "tracker.example.com"} {
			if strings.Contains(tpl.HTML, bad) {
				t.Fatalf("stored HTML keeps %q: %s", bad, tpl.HTML)
			}
		}
		if !tpl.Customized || tpl.Text != "Code: {{code}}\n" || tpl.UpdatedAt.IsZero() {
			t.Fatalf("stored: %+v", tpl)
		}
		got, err := ev.svc.GetTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en")
		mustNoErr(t, "get custom", err)
		if !got.Customized || got.HTML != tpl.HTML {
			t.Fatalf("get: %+v", got)
		}
		list, _ = ev.svc.ListTemplates(ctx, ev.adminA, ev.a.ID)
		custom := 0
		for _, s := range list {
			if s.Customized {
				custom++
			}
		}
		if custom != 1 {
			t.Fatalf("%d customized", custom)
		}

		// Go template syntax and a missing required variable are refused.
		in := goodTemplate()
		in.HTML = `<p>{{.Code}}</p>{{template "x"}}`
		_, err = ev.svc.UpdateTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", in, clientIP)
		if ie := invalidOf(t, "go syntax", err, FieldTemplate); len(ie.Issues) == 0 {
			t.Fatal("no issues")
		}
		in = goodTemplate()
		in.Text = "No code here."
		_, err = ev.svc.UpdateTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", in, clientIP)
		if ie := invalidOf(t, "missing variable", err, FieldTemplate); len(ie.Issues) == 0 {
			t.Fatal("no issues")
		}

		// Preview: submitted, stored, default.
		p, err := ev.svc.PreviewTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", &TemplateInput{
			Subject: "Hi {{tenant_name}}", HTML: "<p>{{code}}</p>", Text: "{{code}}",
		})
		mustNoErr(t, "preview submitted", err)
		if !strings.Contains(p.Text, "123456") || !strings.HasPrefix(p.Subject, "Hi ") {
			t.Fatalf("preview: %+v", p)
		}
		p, err = ev.svc.PreviewTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", nil)
		mustNoErr(t, "preview stored", err)
		if !strings.HasPrefix(p.Subject, "Your code for") {
			t.Fatalf("stored preview: %+v", p)
		}
		p, err = ev.svc.PreviewTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "fr", nil)
		mustNoErr(t, "preview default", err)
		if p.HTML == "" {
			t.Fatal("empty preview")
		}
		_, err = ev.svc.PreviewTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", &TemplateInput{Subject: "x", HTML: "y", Text: "z"})
		wantInvalid(t, "preview invalid", err, FieldTemplate)

		// A stored customization that no longer validates: the default.
		_, err = ev.db.TenantEmailTemplates().Put(ctx, ev.a.ID, store.EmailTemplate{
			Key: keyCode, Language: "fr", Subject: "stale", BodyHTML: "no variable", BodyText: "no variable",
		})
		mustNoErr(t, "stale", err)
		p, err = ev.svc.PreviewTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "fr", nil)
		mustNoErr(t, "preview stale", err)
		if p.Subject == "stale" {
			t.Fatal("stale template previewed")
		}

		mustNoErr(t, "reset", ev.svc.ResetTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", clientIP))
		mustNoErr(t, "reset again", ev.svc.ResetTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", clientIP))
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantTemplateReset)); n != 1 {
			t.Fatalf("%d reset events", n)
		}
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantTemplateUpdated)); n != 1 {
			t.Fatalf("%d update events", n)
		}

		// Unknown keys and languages, and isolation.
		for _, k := range [][2]string{
			{diskAlertKey, "en"},
			{diskAlertKey, "fr"},
			{mail.TemplateDiskAlert, "en"},
			{"verification_code", "en"},
			{keyCode, "de"},
		} {
			_, err = ev.svc.GetTemplate(ctx, ev.adminA, ev.a.ID, k[0], k[1])
			wantErr(t, "get "+k[0]+"/"+k[1], err, ErrNotFound)
			_, err = ev.svc.UpdateTemplate(ctx, ev.adminA, ev.a.ID, k[0], k[1], goodTemplate(), clientIP)
			wantErr(t, "update "+k[0], err, ErrNotFound)
			err = ev.svc.ResetTemplate(ctx, ev.adminA, ev.a.ID, k[0], k[1], clientIP)
			wantErr(t, "reset "+k[0], err, ErrNotFound)
			_, err = ev.svc.PreviewTemplate(ctx, ev.adminA, ev.a.ID, k[0], k[1], nil)
			wantErr(t, "preview "+k[0], err, ErrNotFound)
		}
		_, err = ev.svc.ListTemplates(ctx, ev.adminB, ev.a.ID)
		wantErr(t, "other list", err, ErrNotFound)
		_, err = ev.svc.GetTemplate(ctx, ev.adminB, ev.a.ID, keyCode, "en")
		wantErr(t, "other get", err, ErrNotFound)
		_, err = ev.svc.UpdateTemplate(ctx, ev.adminB, ev.a.ID, keyCode, "en", goodTemplate(), clientIP)
		wantErr(t, "other update", err, ErrNotFound)
		err = ev.svc.ResetTemplate(ctx, ev.adminB, ev.a.ID, keyCode, "en", clientIP)
		wantErr(t, "other reset", err, ErrNotFound)
		_, err = ev.svc.PreviewTemplate(ctx, ev.adminB, ev.a.ID, keyCode, "en", nil)
		wantErr(t, "other preview", err, ErrNotFound)
	})
}

func TestTemplateFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	f := ev.faults("listTemplates", "template", "putTemplate", "deleteTemplate")
	_, err := ev.svc.ListTemplates(ctx, ev.adminA, ev.a.ID)
	wantErr(t, "list", err, errBoom)
	_, err = ev.svc.GetTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en")
	wantErr(t, "get", err, errBoom)
	_, err = ev.svc.PreviewTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", nil)
	wantErr(t, "preview", err, errBoom)
	_, err = ev.svc.UpdateTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", goodTemplate(), clientIP)
	wantErr(t, "put", err, errBoom)
	err = ev.svc.ResetTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", clientIP)
	wantErr(t, "delete", err, errBoom)
	f.errs["putTemplate"] = store.ErrInvalid
	_, err = ev.svc.UpdateTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", goodTemplate(), clientIP)
	wantInvalid(t, "store invalid", err, FieldTemplate)
	f.errs["putTemplate"] = store.ErrNotFound
	_, err = ev.svc.UpdateTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", goodTemplate(), clientIP)
	wantErr(t, "gone", err, ErrNotFound)
	delete(f.errs, "template")

	t.Cleanup(func() {
		defaultSource, normalizeTemplate = mail.DefaultSource, mail.NormalizeTemplate
	})
	defaultSource = func(string, string) (mail.TemplateSource, error) { return mail.TemplateSource{}, errBoom }
	_, err = ev.svc.GetTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en")
	wantErr(t, "default source", err, errBoom)
	normalizeTemplate = func(string, mail.TemplateSource) (mail.TemplateSource, error) { return mail.TemplateSource{}, errBoom }
	_, err = ev.svc.UpdateTemplate(ctx, ev.adminA, ev.a.ID, keyCode, "en", goodTemplate(), clientIP)
	wantErr(t, "normalize", err, errBoom)
}

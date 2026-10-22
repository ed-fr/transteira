package download

import (
	"context"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestCustomizedFirstDownloadTemplate checks that the first download mail
// of tenant A uses the customized template stored for A, and that the same
// mail of tenant B keeps the default.
func TestCustomizedFirstDownloadTemplate(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		const mark = "[Custom A]"
		for _, lang := range []string{"en", "fr"} {
			src, err := mail.DefaultSource(mail.TemplateFirstDownload, lang)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ev.db.TenantEmailTemplates().Put(context.Background(), ev.a.ID, store.EmailTemplate{
				Key: store.EmailTemplateFirstDownload, Language: lang,
				Subject: mark + " " + src.Subject, BodyHTML: src.HTML, BodyText: mark + "\n" + src.Text,
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		ev.complete(ev.publish(ev.a, spec{contents: [][]byte{random(100)}}))
		ev.complete(ev.publish(ev.b, spec{contents: [][]byte{random(100)}}))
		ev.waitUntil("first download mails", func() bool { return len(ev.firstDownloads()) == 2 })
		for _, j := range ev.firstDownloads() {
			custom := strings.HasPrefix(j.Message.Subject, mark) && strings.HasPrefix(j.Message.Text, mark)
			if want := j.TenantID == ev.a.ID.String(); custom != want {
				t.Errorf("first download mail of %s: customized %v, want %v (%q)", j.TenantID, custom, want, j.Message.Subject)
			}
		}
	})
}

package scan

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestCustomizedTemplates checks that the mails sent after the scan of a
// transfer of tenant A (notification, confirmation, file problems, file not
// scanned) use the customized templates stored for A, and that the same
// mails of tenant B keep the defaults.
func TestCustomizedTemplates(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		const mark = "[Custom A]"
		kinds := []string{
			mail.TemplateTransferNotification, mail.TemplateTransferConfirmation,
			mail.TemplateFileProblems, mail.TemplateFileNotScanned,
		}
		for _, name := range kinds {
			for _, lang := range []string{"en", "fr"} {
				src, err := mail.DefaultSource(name, lang)
				if err != nil {
					t.Fatal(err)
				}
				_, err = ev.db.TenantEmailTemplates().Put(context.Background(), ev.a.ID, store.EmailTemplate{
					Key: strings.ReplaceAll(name, "_", "-"), Language: lang,
					Subject: mark + " " + src.Subject, BodyHTML: src.HTML, BodyText: mark + "\n" + src.Text,
				})
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		ev.clamd.SetSizeLimit(1000)
		ev.scanning(ev.a, clean(10), antivirustest.EICAR(), clean(5000))
		ev.scanning(ev.b, clean(10), antivirustest.EICAR(), clean(5000))
		ev.start()
		jobs := ev.waitJobs(10)
		for _, j := range jobs {
			custom := strings.HasPrefix(j.Message.Subject, mark) && strings.HasPrefix(j.Message.Text, mark)
			if want := j.TenantID == ev.a.ID.String(); custom != want {
				t.Errorf("%s of %s: customized %v, want %v (%q)", j.Template, j.TenantID, custom, want, j.Message.Subject)
			}
		}
		want := append(slices.Clone(kinds), mail.TemplateTransferNotification)
		slices.Sort(want)
		for _, tn := range []string{ev.a.ID.String(), ev.b.ID.String()} {
			var mine []mail.Job
			for _, j := range jobs {
				if j.TenantID == tn {
					mine = append(mine, j)
				}
			}
			if got := templates(mine); !slices.Equal(got, want) {
				t.Errorf("templates of %s: %v, want %v", tn, got, want)
			}
		}
	})
}

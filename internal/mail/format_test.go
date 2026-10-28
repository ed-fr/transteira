package mail

import (
	"strings"
	"testing"
	"time"
)

func TestFormatSize(t *testing.T) {
	cases := []struct {
		lang string
		n    int64
		want string
	}{
		{"en", -5, "0 B"},
		{"en", 0, "0 B"},
		{"fr", 1023, "1023 o"},
		{"en", 1024, "1.0 KB"},
		{"fr", 1536, "1,5 Ko"},
		{"en", 10*1024 - 1, "10 KB"}, // 9.999 rounds up to 10, written without decimal
		{"en", 10 * 1024, "10 KB"},
		{"en", 1024*1024 - 1, "1.0 MB"}, // 1023.999 KB rounds up to the next unit
		{"fr", 1024*1024 - 1, "1,0 Mo"},
		{"en", 5 << 20, "5.0 MB"},
		{"fr", 20 << 30, "20 Go"},
		{"en", 3 << 40, "3.0 TB"},
		{"en", 1 << 62, "4096 PB"}, // the largest unit has no successor
		{"de", 2048, "2.0 KB"},     // unsupported language: English
	}
	for _, c := range cases {
		got := FormatSize(c.lang, c.n)
		if want := strings.ReplaceAll(c.want, " ", nbsp); got != want {
			t.Errorf("FormatSize(%q, %d) = %q, want %q", c.lang, c.n, got, want)
		}
	}
}

func TestFormatDateTime(t *testing.T) {
	ts := time.Date(2026, time.October, 21, 16, 5, 0, 0, time.FixedZone("CEST", 2*3600))
	for lang, want := range map[string]string{
		"fr": "21 octobre 2026 à 14:05 UTC",
		"en": "October 21, 2026 at 14:05 UTC",
		"de": "October 21, 2026 at 14:05 UTC",
	} {
		if got := FormatDateTime(lang, ts); got != want {
			t.Errorf("FormatDateTime(%q) = %q, want %q", lang, got, want)
		}
	}
}

// TestTransferTemplatesVariants covers the optional parts of the transfer
// templates that the golden files leave out.
func TestTransferTemplatesVariants(t *testing.T) {
	gd := goldenData()
	for _, lang := range []string{"fr", "en"} {
		n := gd[TemplateTransferNotification].(TransferNotificationData)
		n.Message, n.PasswordRequired, n.QR = "", false, false
		m, err := Render(TemplateTransferNotification, lang, n)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"blockquote", "cid:", "<img", "mot de passe", "password"} {
			if strings.Contains(m.HTML, bad) || strings.Contains(m.Text, bad) {
				t.Errorf("%s: notification without options contains %q", lang, bad)
			}
		}
		// The download link is the only link of the notification.
		if c := strings.Count(m.HTML, "<a "); c != 1 {
			t.Errorf("%s: %d links in the notification", lang, c)
		}

		c := gd[TemplateTransferConfirmation].(TransferConfirmationData)
		c.PasswordRequired = false
		m, err = Render(TemplateTransferConfirmation, lang, c)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(m.Text, "mot de passe") || strings.Contains(m.Text, "password") {
			t.Errorf("%s: confirmation without password mentions it", lang)
		}

		c.Withheld = nil
		m, err = Render(TemplateTransferConfirmation, lang, c)
		if err != nil || strings.Contains(m.Text, "<i>archive") || strings.Contains(m.HTML, "&lt;i&gt;archive") {
			t.Errorf("%s: confirmation without withheld file lists one: %v", lang, err)
		}

		rejected := map[string]string{"fr": "le transfert n'a pas été envoyé", "en": "the transfer was not sent"}[lang]
		withheldSubject := map[string]string{"fr": "Fichier retenu", "en": "File withheld"}[lang]
		infectedSubject := map[string]string{"fr": "Fichier infecté", "en": "Infected file"}[lang]
		v := gd[TemplateFileProblems].(FileProblemsData)
		m, err = Render(TemplateFileProblems, lang, v)
		if err != nil || !strings.HasPrefix(m.Subject, infectedSubject) || strings.Contains(m.Text, rejected) {
			t.Errorf("%s: mixed problems: %v %q", lang, err, m.Subject)
		}
		// Withheld files only, nothing delivered.
		v.Infected, v.Rejected = nil, true
		m, err = Render(TemplateFileProblems, lang, v)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(m.Subject, withheldSubject) || !strings.Contains(m.Text, rejected) ||
			!strings.Contains(m.HTML, rejected) ||
			strings.Contains(m.Text, "antivirus à jour") || strings.Contains(m.Text, "up-to-date antivirus") ||
			strings.Contains(m.HTML, "<code") {
			t.Errorf("%s: withheld only: %s\n%s", lang, m.Subject, m.Text)
		}
		// Infected files only.
		v = gd[TemplateFileProblems].(FileProblemsData)
		v.Withheld = nil
		m, err = Render(TemplateFileProblems, lang, v)
		if err != nil || strings.Contains(m.Text, "<i>archive") || strings.Contains(m.Text, "retenu") || strings.Contains(m.Text, "withheld") {
			t.Errorf("%s: infected only: %v\n%s", lang, err, m.Text)
		}
	}
}

// TestConfidentialityNotice covers the confidentiality level of the transfer
// mails: shown, escaped, and absent without a level.
func TestConfidentialityNotice(t *testing.T) {
	gd := goldenData()
	for lang, prefix := range map[string]string{"fr": "Niveau de confidentialité : ", "en": "Confidentiality level: "} {
		n := gd[TemplateTransferNotification].(TransferNotificationData)
		c := gd[TemplateTransferConfirmation].(TransferConfirmationData)
		n.ConfidentialityLabel, c.ConfidentialityLabel = "Secret <b>&", "Secret <b>&"
		for name, data := range map[string]any{TemplateTransferNotification: n, TemplateTransferConfirmation: c} {
			m, err := Render(name, lang, data)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(m.Text, prefix+"Secret <b>&") {
				t.Errorf("%s/%s: text lacks the level:\n%s", name, lang, m.Text)
			}
			if !strings.Contains(m.HTML, "<strong>"+prefix+"Secret &lt;b&gt;&amp;</strong>") {
				t.Errorf("%s/%s: html lacks the escaped level", name, lang)
			}
		}
		n.ConfidentialityLabel, c.ConfidentialityLabel = "", ""
		for name, data := range map[string]any{TemplateTransferNotification: n, TemplateTransferConfirmation: c} {
			m, err := Render(name, lang, data)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(m.Text, prefix) || strings.Contains(m.HTML, prefix) {
				t.Errorf("%s/%s: level shown without label", name, lang)
			}
		}
	}
}

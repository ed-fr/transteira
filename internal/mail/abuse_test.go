package mail

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/i18n"
)

// abuseAlert returns an alert of the given rule with plausible values.
func abuseAlert(rule string) AbuseAlertData {
	return AbuseAlertData{
		TenantName: "Entity A", Rule: rule, SenderEmail: "alice@entity-a.example.com",
		Value: 12, Threshold: 10, Blocked: true, Day: "2027-10-13", AdminLink: goldenAdminLink,
		At: time.Date(2027, time.October, 13, 23, 15, 0, 0, time.UTC),
	}
}

func TestAbuseAlertRules(t *testing.T) {
	for _, tc := range []struct {
		rule     string
		mutate   func(*AbuseAlertData)
		en, fr   string
		notInEn  string
		notInFre string
	}{
		{rule: AbuseRuleDailyBytes, mutate: func(d *AbuseAlertData) { d.Value, d.Threshold = 120<<30, 100<<30 }, en: "120" + nbsp + "GB sent, threshold 100" + nbsp + "GB", fr: "120" + nbsp + "Go envoyés, seuil 100" + nbsp + "Go"},
		{rule: AbuseRuleDailyTransfers, en: "12 transfers, threshold 10", fr: "12 transferts, seuil 10"}, //nolint:misspell // French text
		{rule: AbuseRuleRecipients, en: "12 recipients, threshold 10", fr: "12 destinataires, seuil 10"},
		{rule: AbuseRuleUnusualVolume, mutate: func(d *AbuseAlertData) { d.Value = 7.25 }, en: "about 7.3 times", fr: "environ 7,3 fois"},
		{rule: AbuseRuleLargeExternal, mutate: func(d *AbuseAlertData) { d.Value, d.Threshold = 3<<30, 1<<30 }, en: "3.0" + nbsp + "GB, threshold 1.0" + nbsp + "GB", fr: "3,0" + nbsp + "Go, seuil 1,0" + nbsp + "Go"},
		{rule: AbuseRuleOffHours, en: "at October 13, 2027 at 23:15 UTC", fr: "le 13 octobre 2027 à 23:15 UTC"},
		{rule: AbuseRuleInvitations, en: "12 invitations, limit 10", fr: "12 invitations, limite 10"},
		{rule: AbuseRuleExternalQuota, en: "12 deposits, limit 10", fr: "12 dépôts, limite 10"},
		{rule: AbuseRuleExternalQuota, mutate: func(d *AbuseAlertData) { d.Bytes, d.Value, d.Threshold = true, 2<<30, 1<<30 }, en: "2.0" + nbsp + "GB deposited, limit 1.0" + nbsp + "GB", fr: "2,0" + nbsp + "Go déposés, limite 1,0" + nbsp + "Go"},
		{rule: "no_such_rule", en: "An abuse detection threshold was reached.", fr: "Un seuil de détection des abus a été atteint."},
		{rule: "", en: "An abuse detection threshold was reached.", fr: "Un seuil de détection des abus a été atteint."},
	} {
		d := abuseAlert(tc.rule)
		if tc.mutate != nil {
			tc.mutate(&d)
		}
		for lang, want := range map[string]string{i18n.English: tc.en, i18n.French: tc.fr} {
			m, err := Render(TemplateAbuseAlert, lang, d)
			if err != nil {
				t.Fatalf("%s/%s: %v", tc.rule, lang, err)
			}
			for part, s := range map[string]string{"text": m.Text, "html": m.HTML} {
				if !strings.Contains(s, want) {
					t.Errorf("%s/%s %s lacks %q:\n%s", tc.rule, lang, part, want, s)
				}
				if !strings.Contains(s, goldenAdminLink) || !strings.Contains(s, "2027-10-13") {
					t.Errorf("%s/%s %s lacks link or day", tc.rule, lang, part)
				}
			}
			if !strings.Contains(m.Subject, "alice@entity-a.example.com") {
				t.Errorf("subject %q", m.Subject)
			}
		}
	}
}

func TestAbuseAlertBlockedAndOffHours(t *testing.T) {
	d := abuseAlert(AbuseRuleOffHours)
	d.At = time.Time{}
	m, err := Render(TemplateAbuseAlert, "en", d)
	if err != nil || !strings.Contains(m.Text, "Transfer sent outside office hours.") {
		t.Errorf("off hours without time: %v\n%s", err, m.Text)
	}
	for _, tc := range []struct {
		blocked bool
		lang    string
		want    string
	}{
		{true, "en", "The transfer was refused."},
		{false, "en", "not blocked"},
		{true, "fr", "refusé"},
		{false, "fr", "pas été bloqué"},
	} {
		d.Blocked = tc.blocked
		m, err := Render(TemplateAbuseAlert, tc.lang, d)
		if err != nil || !strings.Contains(m.Text, tc.want) || !strings.Contains(m.HTML, tc.want) {
			t.Errorf("blocked=%v %s: %v", tc.blocked, tc.lang, err)
		}
	}
}

func TestAbuseNumberFormats(t *testing.T) {
	if got := formatNumber("en", math.NaN()); got != "0" {
		t.Errorf("NaN = %q", got)
	}
	if got := formatNumber("fr", math.Inf(1)); got != "0" {
		t.Errorf("Inf = %q", got)
	}
	if got := formatNumber("fr", 1.5); got != "1,5" {
		t.Errorf("fr 1.5 = %q", got)
	}
	for _, v := range []float64{math.NaN(), -5, 0, math.Inf(1), 1e30} {
		if s := formatBytesFloat("en", v); s == "" {
			t.Errorf("formatBytesFloat(%v) empty", v)
		}
	}
	if got := formatBytesFloat("en", -1); got != "0"+nbsp+"B" {
		t.Errorf("negative = %q", got)
	}
	if abuseLabelsFor("xx") != allAbuseLabels[i18n.English] {
		t.Error("unsupported language does not use English")
	}
}

func TestAbuseReportCategories(t *testing.T) {
	for _, tc := range []struct{ cat, en, fr string }{
		{AbuseCategoryMalware, "Malware", "Logiciel malveillant"},
		{AbuseCategoryPhishing, "Phishing", "Hameçonnage"},
		{AbuseCategoryIllegalContent, "Illegal content", "Contenu illicite"},
		{AbuseCategorySpam, "Spam", "Courrier indésirable"},
		{AbuseCategoryUnknownSender, "Unknown sender", "Expéditeur inconnu"},
		{AbuseCategoryOther, "Other", "Autre"},
		{"made_up", "Other", "Autre"},
	} {
		d := AbuseReportData{TenantName: "Entity A", TransferID: "tr_1", SenderEmail: "a@example.com", Category: tc.cat, AdminLink: goldenAdminLink}
		for lang, want := range map[string]string{"en": tc.en, "fr": tc.fr} {
			m, err := Render(TemplateAbuseReport, lang, d)
			if err != nil || !strings.Contains(m.Subject, want) || !strings.Contains(m.Text, "Cat") || !strings.Contains(m.HTML, "<strong>"+want+"</strong>") {
				t.Errorf("%s/%s: %v subject %q", tc.cat, lang, err, m.Subject)
			}
			if strings.Contains(m.Text, "> ") || strings.Contains(m.HTML, "blockquote") {
				t.Errorf("%s/%s: quote block without message", tc.cat, lang)
			}
		}
	}
}

func TestAbuseReportReporter(t *testing.T) {
	d := AbuseReportData{TenantName: "Entity A", TransferID: "tr_1", SenderEmail: "a@example.com", Category: AbuseCategorySpam, AdminLink: goldenAdminLink}
	for _, tc := range []struct {
		email string
		index int
		lang  string
		want  string
	}{
		{"bob@example.com", 3, "en", "Reported by bob@example.com, whose address was verified"},
		{"", 3, "en", "link of recipient #3, unverified"},
		{"", 0, "en", "shared link of the transfer, unverified"},
		{"bob@example.com", 0, "fr", "Signalé par bob@example.com"},
		{"", 3, "fr", "destinataire n° 3, non vérifié"},
		{"", 0, "fr", "lien partagé du transfert, non vérifié"},
	} {
		d.ReporterEmail, d.RecipientIndex = tc.email, tc.index
		m, err := Render(TemplateAbuseReport, tc.lang, d)
		if err != nil || !strings.Contains(m.Text, tc.want) || !strings.Contains(m.HTML, tc.want) {
			t.Errorf("%+v: %v\n%s", tc, err, m.Text)
		}
	}
}

func TestAbuseReportMessageEscaped(t *testing.T) {
	msg := "<script>alert(1)</script>\n<img src=x onerror=alert(2)>\n{{admin_link}} &amp; \"q\" https://phishing.example.com"
	d := AbuseReportData{
		TenantName: "Entity A", TransferID: "tr_1", SenderEmail: "a@example.com", Category: AbuseCategoryPhishing,
		Message: msg, ReporterEmail: "<b>x</b>@example.com", AdminLink: goldenAdminLink,
	}
	for _, lang := range i18n.Supported() {
		m, err := Render(TemplateAbuseReport, lang, d)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"<script", "<img", "<b>x</b>", `onerror=alert(2)>`} {
			if strings.Contains(m.HTML, bad) {
				t.Errorf("%s: HTML contains %q:\n%s", lang, bad, m.HTML)
			}
		}
		if strings.Contains(m.Subject, "script") || strings.Contains(m.Subject, "\n") {
			t.Errorf("%s: subject %q", lang, m.Subject)
		}
		if !strings.Contains(m.HTML, "&lt;script&gt;alert(1)&lt;/script&gt;") || !strings.Contains(m.HTML, "&amp;amp;") ||
			!strings.Contains(m.HTML, "white-space:pre-wrap") || !strings.Contains(m.HTML, "{{admin_link}} ") {
			t.Errorf("%s: HTML not escaped or line breaks lost:\n%s", lang, m.HTML)
		}
		// The text part keeps the message as is, one quoted line each: it is
		// plain text, never interpreted.
		for _, line := range []string{"> <script>alert(1)</script>", "> <img src=x onerror=alert(2)>", "> {{admin_link}} &amp;"} {
			if !strings.Contains(m.Text, line) {
				t.Errorf("%s: text lacks %q:\n%s", lang, line, m.Text)
			}
		}
		// A placeholder written in the message is not expanded.
		if strings.Count(m.Text, goldenAdminLink) != 1 {
			t.Errorf("%s: placeholder of the message expanded:\n%s", lang, m.Text)
		}
	}
}

func TestAbuseVariablesAndSamples(t *testing.T) {
	for _, key := range []string{"abuse-alert", "abuse-report"} {
		vars, err := Variables(key)
		if err != nil || len(vars) == 0 {
			t.Fatalf("Variables(%s): %v", key, err)
		}
		for _, lang := range i18n.Supported() {
			def := keyDefs[keyName(key)]
			m, err := Render(keyName(key), lang, def.sample)
			if err != nil || m.Subject == "" {
				t.Errorf("sample %s/%s: %v", key, lang, err)
			}
		}
	}
	if _, ok := keyDefs[TemplateAbuseAlert].values(labelsFor("en"), "en", AbuseReportData{}); ok {
		t.Error("abuse_alert accepted the data of abuse_report")
	}
	if _, ok := keyDefs[TemplateAbuseReport].values(labelsFor("en"), "en", AbuseAlertData{}); ok {
		t.Error("abuse_report accepted the data of abuse_alert")
	}
}

func TestAbuseAlertInvitationsNotice(t *testing.T) {
	for _, blocked := range []bool{true, false} {
		d := abuseAlert(AbuseRuleInvitations)
		d.Blocked = blocked
		for lang, want := range map[string]string{"en": "Further invitations", "fr": "nouvelles invitations"} {
			m, err := Render(TemplateAbuseAlert, lang, d)
			if err != nil || !strings.Contains(m.Text, want) || !strings.Contains(m.HTML, want) {
				t.Errorf("blocked=%v %s: %v\n%s", blocked, lang, err, m.Text)
			}
			if strings.Contains(m.Text, "not blocked") || strings.Contains(m.Text, "pas été bloqué") {
				t.Errorf("blocked=%v %s: wrong notice\n%s", blocked, lang, m.Text)
			}
		}
	}
}

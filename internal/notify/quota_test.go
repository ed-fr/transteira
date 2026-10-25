package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
)

// testAdminLink is the administration console link of the quota alerts.
const testAdminLink = "https://admin.example.com/admin/"

func testQuotaData() mail.QuotaAlertData {
	return mail.QuotaAlertData{UsedBytes: 85 << 30, QuotaBytes: 100 << 30, AdminLink: testAdminLink}
}

func TestQuotaAlert(t *testing.T) {
	for _, tc := range []struct {
		level    QuotaLevel
		template string
		subject  map[string]string
	}{
		{QuotaWarning, mail.TemplateQuotaWarning, map[string]string{"en": "quota", "fr": "quota"}},
		{QuotaReached, mail.TemplateQuotaReached, map[string]string{"en": "reached", "fr": "atteint"}},
	} {
		e := newEnv(t)
		recipients := []Contact{
			{Email: "anna@entity-a.example.com", Language: "en"},
			{Email: "bruno@entity-a.example.com", Language: ""},
			{Email: "ANNA@entity-a.example.com", Language: "fr"},
			{Email: "chloe@entity-a.example.com", Language: "de"},
			{Email: "dan@entity-a.example.com", Language: "fr"},
		}
		jobs, err := e.n.QuotaAlert(context.Background(), e.t, testQuotaData(), tc.level, recipients)
		if err != nil {
			t.Fatal(err)
		}
		want := []struct{ to, lang string }{
			{"anna@entity-a.example.com", "en"},
			{"bruno@entity-a.example.com", "fr"},
			{"chloe@entity-a.example.com", "fr"},
			{"dan@entity-a.example.com", "fr"},
		}
		if len(jobs) != len(want) {
			t.Fatalf("level %d: %d jobs, want %d", tc.level, len(jobs), len(want))
		}
		for i, j := range jobs {
			if len(j.Message.To) != 1 || j.Message.To[0] != want[i].to || j.Message.Language != want[i].lang {
				t.Errorf("level %d job %d: To %v language %q, want %s %s", tc.level, i, j.Message.To, j.Message.Language, want[i].to, want[i].lang)
			}
			if j.TenantID != "ten_a" || j.Template != tc.template || j.Settings.Password != "s3cret-pass" {
				t.Errorf("level %d job %d: %+v", tc.level, i, j)
			}
			if !strings.Contains(strings.ToLower(j.Message.Subject), tc.subject[j.Message.Language]) {
				t.Errorf("level %d job %d: subject %q", tc.level, i, j.Message.Subject)
			}
			for _, s := range []string{"Entity A &amp; Co", testAdminLink} {
				if !strings.Contains(j.Message.HTML, s) {
					t.Errorf("level %d job %d: HTML lacks %q", tc.level, i, s)
				}
			}
			if !strings.Contains(j.Message.Text, "85") {
				t.Errorf("level %d job %d: text lacks the usage: %s", tc.level, i, j.Message.Text)
			}
			_ = build(t, j)
		}
		if e.vault.calls != 1 {
			t.Errorf("vault opened %d times", e.vault.calls)
		}
		logs := e.logs.String()
		if !strings.Contains(logs, "count=4") || strings.Contains(logs, "@") {
			t.Errorf("logs: %s", logs)
		}
	}
}

func TestQuotaAlertKeepsTenantName(t *testing.T) {
	e := newEnv(t)
	d := testQuotaData()
	d.TenantName = "Other name"
	jobs, err := e.n.QuotaAlert(context.Background(), e.t, d, QuotaWarning, []Contact{{Email: "a@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jobs[0].Message.Text, "Other name") {
		t.Errorf("text: %s", jobs[0].Message.Text)
	}
}

func TestQuotaAlertErrors(t *testing.T) {
	ctx := context.Background()
	one := []Contact{{Email: "admin@example.com"}}
	tooMany := make([]Contact, MaxContacts+1)
	for i := range tooMany {
		tooMany[i] = Contact{Email: "admin@example.com"}
	}
	for name, tc := range map[string]struct {
		mutate     func(*env)
		level      QuotaLevel
		link       string
		recipients []Contact
		want       error
	}{
		"level":      {level: 50, link: testAdminLink, recipients: one, want: ErrInvalidAlert},
		"link":       {level: QuotaWarning, link: "ftp://admin.example.com", recipients: one, want: ErrInvalidLink},
		"empty link": {level: QuotaWarning, recipients: one, want: ErrInvalidLink},
		"none":       {level: QuotaWarning, link: testAdminLink, want: ErrInvalidAlert},
		"too many":   {level: QuotaWarning, link: testAdminLink, recipients: tooMany, want: ErrInvalidAlert},
		"address": {
			level: QuotaWarning, link: testAdminLink, recipients: []Contact{{Email: "not an address"}},
			want: ErrInvalidAlert,
		},
		"no smtp": {
			mutate: func(e *env) { e.smtp.err = store.ErrNotFound },
			level:  QuotaReached, link: testAdminLink, recipients: one, want: ErrNoSMTP,
		},
		"render": {
			mutate: func(e *env) { e.n.templates = failRenderer{} },
			level:  QuotaReached, link: testAdminLink, recipients: one,
		},
	} {
		e := newEnv(t)
		if tc.mutate != nil {
			tc.mutate(e)
		}
		d := testQuotaData()
		d.AdminLink = tc.link
		jobs, err := e.n.QuotaAlert(ctx, e.t, d, tc.level, tc.recipients)
		if err == nil || jobs != nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: jobs %v, error %v; want %v", name, jobs, err, tc.want)
		}
	}
}

func testAntivirusData() mail.AntivirusUnavailableData {
	return mail.AntivirusUnavailableData{
		Since: time.Date(2027, time.October, 13, 9, 45, 0, 0, time.UTC), WaitingTransfers: 4, AdminLink: testAdminLink,
	}
}

func TestAntivirusUnavailable(t *testing.T) {
	e := newEnv(t)
	recipients := []Contact{
		{Email: "anna@entity-a.example.com", Language: "en"},
		{Email: "ANNA@entity-a.example.com", Language: "fr"},
		{Email: "bruno@entity-a.example.com"},
	}
	jobs, err := e.n.AntivirusUnavailable(context.Background(), e.t, testAntivirusData(), recipients)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ to, lang, subject, since string }{
		{"anna@entity-a.example.com", "en", "antivirus unavailable", "October 13, 2027 at 09:45 UTC"},
		{"bruno@entity-a.example.com", "fr", "antivirus indisponible", "13 octobre 2027 à 09:45 UTC"},
	}
	if len(jobs) != len(want) {
		t.Fatalf("%d jobs, want %d", len(jobs), len(want))
	}
	for i, j := range jobs {
		w := want[i]
		if len(j.Message.To) != 1 || j.Message.To[0] != w.to || j.Message.Language != w.lang {
			t.Errorf("job %d: To %v language %q, want %s %s", i, j.Message.To, j.Message.Language, w.to, w.lang)
		}
		if j.TenantID != "ten_a" || j.Template != mail.TemplateAntivirusUnavailable || j.Settings.Password != "s3cret-pass" {
			t.Errorf("job %d: %+v", i, j)
		}
		if s := strings.ToLower(j.Message.Subject); !strings.Contains(s, w.subject) || !strings.Contains(s, "entity a & co") {
			t.Errorf("job %d: subject %q", i, j.Message.Subject)
		}
		for _, s := range []string{w.since, "4", testAdminLink} {
			if !strings.Contains(j.Message.Text, s) {
				t.Errorf("job %d: text lacks %q: %s", i, s, j.Message.Text)
			}
		}
		_ = build(t, j)
	}
	if logs := e.logs.String(); !strings.Contains(logs, "count=2") || strings.Contains(logs, "@") {
		t.Errorf("logs: %s", logs)
	}

	// A tenant name given by the caller is kept.
	d := testAntivirusData()
	d.TenantName = "Other name"
	jobs, err = e.n.AntivirusUnavailable(context.Background(), e.t, d, recipients[:1])
	if err != nil || len(jobs) != 1 || !strings.Contains(jobs[0].Message.Text, "Other name") {
		t.Errorf("tenant name: %v %+v", err, jobs)
	}
}

func TestAntivirusUnavailableErrors(t *testing.T) {
	ctx := context.Background()
	one := []Contact{{Email: "admin@example.com"}}
	for name, tc := range map[string]struct {
		mutate     func(*env)
		link       string
		recipients []Contact
		want       error
	}{
		"link":    {link: "ftp://admin.example.com", recipients: one, want: ErrInvalidLink},
		"none":    {link: testAdminLink, want: ErrInvalidAlert},
		"address": {link: testAdminLink, recipients: []Contact{{Email: "not an address"}}, want: ErrInvalidAlert},
		"no smtp": {
			mutate: func(e *env) { e.smtp.err = store.ErrNotFound },
			link:   testAdminLink, recipients: one, want: ErrNoSMTP,
		},
		"render": {mutate: func(e *env) { e.n.templates = failRenderer{} }, link: testAdminLink, recipients: one},
	} {
		e := newEnv(t)
		if tc.mutate != nil {
			tc.mutate(e)
		}
		d := testAntivirusData()
		d.AdminLink = tc.link
		jobs, err := e.n.AntivirusUnavailable(ctx, e.t, d, tc.recipients)
		if err == nil || jobs != nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: jobs %v, error %v; want %v", name, jobs, err, tc.want)
		}
	}
}

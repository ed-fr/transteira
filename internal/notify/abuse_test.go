package notify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/mail"
)

func testAbuseAlertData() mail.AbuseAlertData {
	return mail.AbuseAlertData{
		Rule: mail.AbuseRuleDailyTransfers, SenderEmail: "alice@entity-a.example.com",
		Value: 12, Threshold: 10, Blocked: true, Day: "2027-10-13", AdminLink: testAdminLink,
	}
}

func testAbuseReportData() mail.AbuseReportData {
	return mail.AbuseReportData{
		TransferID: "tr_abc", SenderEmail: "alice@entity-a.example.com", Category: mail.AbuseCategoryPhishing,
		Message: "<script>alert(1)</script>", RecipientIndex: 2, AdminLink: testAdminLink,
	}
}

func TestAbuseAlert(t *testing.T) {
	e := newEnv(t)
	recipients := []Contact{
		{Email: "anna@entity-a.example.com", Language: "en"},
		{Email: "ANNA@entity-a.example.com", Language: "fr"},
		{Email: "bruno@entity-a.example.com"},
	}
	jobs, err := e.n.AbuseAlert(context.Background(), e.t, testAbuseAlertData(), recipients)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("%d jobs, want 2", len(jobs))
	}
	for i, want := range []struct{ lang, sentence string }{
		{"en", "12 transfers, threshold 10"}, {"fr", "12 transferts, seuil 10"}, //nolint:misspell // French mail text
	} {
		j := jobs[i]
		if j.Message.Language != want.lang || j.TenantID != "ten_a" || j.Template != mail.TemplateAbuseAlert || j.Settings.Password != "s3cret-pass" {
			t.Errorf("job %d: %+v", i, j)
		}
		for _, s := range []string{want.sentence, testAdminLink, "Entity A & Co"} {
			if !strings.Contains(j.Message.Text, s) && !strings.Contains(j.Message.Subject, s) {
				t.Errorf("job %d lacks %q: %s", i, s, j.Message.Text)
			}
		}
		_ = build(t, j)
	}

	// A tenant name given by the caller is kept.
	d := testAbuseAlertData()
	d.TenantName = "Other name"
	jobs, err = e.n.AbuseAlert(context.Background(), e.t, d, recipients[:1])
	if err != nil || len(jobs) != 1 || !strings.Contains(jobs[0].Message.Text, "Other name") {
		t.Errorf("tenant name: %v %+v", err, jobs)
	}
}

func TestAbuseReport(t *testing.T) {
	e := newEnv(t)
	jobs, err := e.n.AbuseReport(context.Background(), e.t, testAbuseReportData(), []Contact{{Email: "admin@entity-a.example.com", Language: "en"}})
	if err != nil || len(jobs) != 1 {
		t.Fatalf("%v %+v", err, jobs)
	}
	j := jobs[0]
	if j.Template != mail.TemplateAbuseReport || !strings.Contains(j.Message.Text, "link of recipient #2, unverified") ||
		!strings.Contains(j.Message.Text, "> <script>alert(1)</script>") || strings.Contains(j.Message.HTML, "<script>") ||
		!strings.Contains(j.Message.Text, "Entity A & Co") {
		t.Errorf("job: %+v", j)
	}
	_ = build(t, j)
}

func TestAbuseErrors(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	one := []Contact{{Email: "admin@example.com"}}
	d := testAbuseAlertData()
	d.AdminLink = "ftp://admin.example.com"
	if _, err := e.n.AbuseAlert(ctx, e.t, d, one); !errors.Is(err, ErrInvalidLink) {
		t.Errorf("link: %v", err)
	}
	if _, err := e.n.AbuseAlert(ctx, e.t, testAbuseAlertData(), nil); !errors.Is(err, ErrInvalidAlert) {
		t.Errorf("no recipient: %v", err)
	}
	r := testAbuseReportData()
	r.AdminLink = ""
	if _, err := e.n.AbuseReport(ctx, e.t, r, one); !errors.Is(err, ErrInvalidLink) {
		t.Errorf("report link: %v", err)
	}
	if _, err := e.n.AbuseReport(ctx, e.t, testAbuseReportData(), []Contact{{Email: "not an address"}}); !errors.Is(err, ErrInvalidAlert) {
		t.Errorf("report recipient: %v", err)
	}
}

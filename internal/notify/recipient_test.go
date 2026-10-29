package notify

import (
	"bytes"
	"context"
	"errors"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/mail"
)

// testLinks returns the personal links of the recipients of testTransfer
// (bob, carol, dave), one distinct link each.
func testLinks() []RecipientLink {
	return []RecipientLink{
		{Email: "bob@example.com", Link: "https://transfer.entity-a.example.com/d/dl_bob"},
		{Email: "carol@example.org", Link: "https://transfer.entity-a.example.com/d/dl_carol"},
		{Email: "dave@example.net", Link: "https://transfer.entity-a.example.com/d/dl_dave"},
	}
}

func TestPerRecipientJobs(t *testing.T) {
	e := newEnv(t)
	tr := testTransfer()
	tr.PasswordProtected = true
	links := append(testLinks(), RecipientLink{Email: "BOB@example.com", Link: "https://transfer.entity-a.example.com/d/dl_dup"})
	jobs, err := e.n.PerRecipientJobs(context.Background(), e.t, tr, links)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 3 {
		t.Fatalf("%d jobs, want 3 (duplicate merged)", len(jobs))
	}
	for i, j := range jobs {
		l := testLinks()[i]
		if len(j.Message.To) != 1 || j.Message.To[0] != l.Email || j.Template != mail.TemplateTransferNotification ||
			j.TenantID != "ten_a" || j.Message.Language != "fr" {
			t.Fatalf("job %d: %+v", i, j)
		}
		if !strings.Contains(j.Message.Text, l.Link) || !strings.Contains(j.Message.HTML, l.Link) {
			t.Errorf("job %d lacks its own link", i)
		}
		for k, other := range testLinks() {
			if k != i && (strings.Contains(j.Message.Text, other.Link) || strings.Contains(j.Message.HTML, other.Link)) {
				t.Errorf("job %d shows the link of %s", i, other.Email)
			}
			if k != i && strings.Contains(strings.ToLower(build(t, j)), other.Email) {
				t.Errorf("job %d names %s", i, other.Email)
			}
		}
		if strings.Contains(j.Message.Text, "dl_dup") {
			t.Errorf("job %d uses the duplicate link", i)
		}
		if !strings.Contains(j.Message.Text, "autre canal") || !strings.Contains(j.Message.Text, "report.pdf") ||
			strings.Contains(j.Message.Text, "eicar") {
			t.Errorf("job %d content:\n%s", i, j.Message.Text)
		}
		if len(j.Message.Inline) != 1 || j.Message.Inline[0].ContentID != mail.QRContentID {
			t.Fatalf("job %d inline parts %+v", i, j.Message.Inline)
		}
		if _, err := png.Decode(bytes.NewReader(j.Message.Inline[0].Data)); err != nil {
			t.Errorf("job %d QR: %v", i, err)
		}
	}
	// One QR per link: the images differ.
	if bytes.Equal(jobs[0].Message.Inline[0].Data, jobs[1].Message.Inline[0].Data) {
		t.Error("recipients share a QR code")
	}
	if e.vault.calls != 1 {
		t.Errorf("vault calls %d, want 1", e.vault.calls)
	}
}

func TestPerRecipientErrors(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	good := testLinks()
	many := make([]RecipientLink, MaxRecipients+1)
	for i := range many {
		many[i] = good[0]
	}
	expired := testTransfer()
	expired.ExpiresAt = testNow
	noFile := testTransfer()
	noFile.Files = nil
	cases := map[string]struct {
		tr    TransferView
		links []RecipientLink
		want  error
	}{
		"none":      {testTransfer(), nil, ErrInvalidTransfer},
		"too many":  {testTransfer(), many, ErrInvalidTransfer},
		"bad email": {testTransfer(), []RecipientLink{{Email: "nope", Link: good[0].Link}}, ErrInvalidTransfer},
		"bad link":  {testTransfer(), []RecipientLink{{Email: "bob@example.com", Link: "ftp://x"}}, ErrInvalidLink},
		"expired":   {expired, good, ErrTransferExpired},
		"no file":   {noFile, good, ErrInvalidTransfer},
	}
	for name, c := range cases {
		if _, err := e.n.PerRecipientJobs(ctx, e.t, c.tr, c.links); !errors.Is(err, c.want) {
			t.Errorf("PerRecipientJobs %s: %v, want %v", name, err, c.want)
		}
		if _, err := e.n.ExpiryReminderJobs(ctx, e.t, c.tr, c.links, false); !errors.Is(err, c.want) {
			t.Errorf("ExpiryReminderJobs %s: %v, want %v", name, err, c.want)
		}
	}
	// Settings and render failures.
	e.smtp.err = errors.New("db down")
	if _, err := e.n.PerRecipientJobs(ctx, e.t, testTransfer(), good); err == nil {
		t.Error("smtp failure ignored")
	}
	if _, err := e.n.ExpiryReminderJobs(ctx, e.t, testTransfer(), good, false); err == nil {
		t.Error("smtp failure ignored (reminder)")
	}
	e.smtp.err = nil
	// A valid link too long for a QR code.
	long := []RecipientLink{{Email: "bob@example.com", Link: testLink + "?" + strings.Repeat("q", maxQRText)}}
	if _, err := e.n.PerRecipientJobs(ctx, e.t, testTransfer(), long); !errors.Is(err, ErrQRText) {
		t.Errorf("PerRecipientJobs(long link) = %v, want ErrQRText", err)
	}
	e.n.templates = failRenderer{}
	if _, err := e.n.PerRecipientJobs(ctx, e.t, testTransfer(), good); err == nil {
		t.Error("render failure ignored")
	}
	if _, err := e.n.ExpiryReminderJobs(ctx, e.t, testTransfer(), good, false); err == nil {
		t.Error("render failure ignored (reminder)")
	}
}

func TestExpiryReminderJobs(t *testing.T) {
	e := newEnv(t)
	tr := testTransfer()
	tr.PasswordProtected = true
	tr.ConfidentialityLabels = map[string]string{"fr": "Confidentiel"} //nolint:misspell // French label
	jobs, err := e.n.ExpiryReminderJobs(context.Background(), e.t, tr, testLinks(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 3 {
		t.Fatalf("%d jobs, want 3", len(jobs))
	}
	for i, j := range jobs {
		l := testLinks()[i]
		if len(j.Message.To) != 1 || j.Message.To[0] != l.Email || j.Template != mail.TemplateExpiryReminder ||
			len(j.Message.Inline) != 0 {
			t.Fatalf("job %d: %+v", i, j)
		}
		for _, s := range []string{
			l.Link, "alice@entity-a.example.com", "28 octobre 2026", "- report.pdf (2,0\u00a0Mo)", "vault.7z",
			"Niveau de confidentialité : Confidentiel", "autre canal", "confirmer votre adresse", //nolint:misspell // French label
		} {
			if !strings.Contains(j.Message.Text, s) {
				t.Errorf("job %d lacks %q:\n%s", i, s, j.Message.Text)
			}
		}
		for _, s := range []string{"eicar", "locked.zip", "See you", "SHA-256"} {
			if strings.Contains(j.Message.Text, s) || strings.Contains(j.Message.HTML, s) {
				t.Errorf("job %d contains %q", i, s)
			}
		}
		build(t, j)
	}
	// Without password, verification or level, the notices are absent.
	tr.PasswordProtected, tr.ConfidentialityLabels = false, nil
	jobs, err = e.n.ExpiryReminderJobs(context.Background(), e.t, tr, testLinks()[:1], false)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"autre canal", "confirmer votre adresse", "confidentialité"} {
		if strings.Contains(jobs[0].Message.Text, s) {
			t.Errorf("notice %q shown without its option", s)
		}
	}
}

func TestRecipientVerificationCode(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tr := testTransfer()
	j, err := e.n.RecipientVerificationCode(ctx, e.t, tr, "Bob@Example.com", "042917")
	if err != nil {
		t.Fatal(err)
	}
	if j.Template != mail.TemplateRecipientVerificationCode || len(j.Message.To) != 1 || j.Message.To[0] != "Bob@example.com" ||
		j.TenantID != "ten_a" || j.Message.Language != "fr" {
		t.Errorf("job %+v", j)
	}
	for _, s := range []string{"042917", "15 minutes"} {
		if !strings.Contains(j.Message.Text, s) || !strings.Contains(j.Message.HTML, s) {
			t.Errorf("mail lacks %q:\n%s", s, j.Message.Text)
		}
	}
	build(t, j)
	if strings.Contains(e.logs.String(), "042917") {
		t.Error("the code is logged")
	}
	tr.Language = "en"
	if j, err = e.n.RecipientVerificationCode(ctx, e.t, tr, "bob@example.com", "042917"); err != nil ||
		j.Message.Language != "en" || !strings.Contains(j.Message.Text, "valid for 15 minutes") {
		t.Errorf("english: %v\n%s", err, j.Message.Text)
	}
	for _, c := range []struct{ to, code string }{
		{"nope", "123456"},
		{"bob@example.com", "12345"},
		{"bob@example.com", "1234567"},
		{"bob@example.com", "12345a"},
		{"bob@example.com", ""},
	} {
		if _, err := e.n.RecipientVerificationCode(ctx, e.t, tr, c.to, c.code); !errors.Is(err, ErrInvalidTransfer) {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

func TestFirstDownloadBy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tr := testTransfer()
	at := testNow.Add(time.Hour)
	j, err := e.n.FirstDownloadBy(ctx, e.t, tr, at, time.Time{}, "carol@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if j.Message.To[0] != "alice@entity-a.example.com" || !strings.Contains(j.Message.Text, "Téléchargé par : carol@example.org") ||
		strings.Contains(j.Message.Text, "bob@") {
		t.Errorf("named mail:\n%s", j.Message.Text)
	}
	// Without recipient it is the shared-link mail.
	shared, err := e.n.FirstDownloadBy(ctx, e.t, tr, at, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	old, err := e.n.FirstDownload(ctx, e.t, tr, at, time.Time{})
	if err != nil || shared.Message.Text != old.Message.Text || shared.Message.HTML != old.Message.HTML ||
		strings.Contains(old.Message.Text, "Téléchargé par") {
		t.Errorf("shared path changed: %v", err)
	}
	if _, err := e.n.FirstDownloadBy(ctx, e.t, tr, at, time.Time{}, "not an address"); !errors.Is(err, ErrInvalidTransfer) {
		t.Errorf("bad recipient: %v", err)
	}
}

func TestMyTransfersLinkJob(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const link = "https://transfer.entity-a.example.com/me#mta_secretvalue"
	j, err := e.n.MyTransfersLinkJob(ctx, e.t, "en", "Alice@Entity-A.example.com", link, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if j.Template != mail.TemplateMyTransfersLink || len(j.Message.To) != 1 || j.Message.To[0] != "Alice@entity-a.example.com" ||
		j.TenantID != "ten_a" || j.Message.Language != "en" {
		t.Errorf("job %+v", j)
	}
	for _, s := range []string{link, "15 minutes"} {
		if !strings.Contains(j.Message.Text, s) || !strings.Contains(j.Message.HTML, s) {
			t.Errorf("mail lacks %q:\n%s", s, j.Message.Text)
		}
	}
	build(t, j)
	if strings.Contains(e.logs.String(), "secretvalue") {
		t.Error("the link is logged")
	}
	if j, err = e.n.MyTransfersLinkJob(ctx, e.t, "", "alice@entity-a.example.com", link, 15*time.Minute); err != nil || j.Message.Language != "fr" {
		t.Errorf("tenant default language: %v %q", err, j.Message.Language)
	}
	if _, err := e.n.MyTransfersLinkJob(ctx, e.t, "en", "nope", link, 15*time.Minute); !errors.Is(err, ErrInvalidTransfer) {
		t.Errorf("address: %v", err)
	}
	if _, err := e.n.MyTransfersLinkJob(ctx, e.t, "en", "alice@entity-a.example.com", link, 0); !errors.Is(err, ErrInvalidTransfer) {
		t.Errorf("validity: %v", err)
	}
	if _, err := e.n.MyTransfersLinkJob(ctx, e.t, "en", "alice@entity-a.example.com", "javascript:x", time.Hour); !errors.Is(err, ErrInvalidLink) {
		t.Errorf("link: %v", err)
	}
}

package notify

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
)

const secretLink = "https://transfer.entity-a.example.com/s/sec_01J#k=TOPSECRETKEY"

func testSecret() SecretView {
	return SecretView{
		ID: "sec_01J00000000000000000000000", SenderEmail: "alice@entity-a.example.com",
		RecipientEmail: "bob@example.com", Delivery: store.SecretDeliveryEmail,
		HasPassphrase: true, HasFile: true, FileSize: 10,
		CreatedAt: testNow.Add(-time.Hour), ExpiresAt: testNow.Add(24 * time.Hour),
	}
}

func TestSecretNotification(t *testing.T) {
	for _, lang := range []string{"fr", "en"} {
		e := newEnv(t)
		v := testSecret()
		v.Language = lang
		job, err := e.n.SecretNotification(t.Context(), e.t, v, secretLink)
		if err != nil {
			t.Fatal(err)
		}
		m := job.Message
		if job.Template != mail.TemplateSecretNotification || len(m.To) != 1 || m.To[0] != "bob@example.com" {
			t.Fatalf("%s: job %+v", lang, job)
		}
		if !strings.Contains(m.Text, secretLink) || !strings.Contains(m.HTML, "TOPSECRETKEY") || strings.Contains(m.Subject, "TOPSECRETKEY") {
			t.Errorf("%s: link not (only) in the bodies", lang)
		}
		if !strings.Contains(m.Text, "alice@entity-a.example.com") {
			t.Errorf("%s: sender missing", lang)
		}
		if strings.Contains(e.logs.String(), "TOPSECRETKEY") || strings.Contains(e.logs.String(), "bob@example.com") {
			t.Errorf("%s: link or recipient logged: %s", lang, e.logs)
		}
		if !strings.Contains(e.logs.String(), v.ID) {
			t.Errorf("%s: secret id not logged", lang)
		}
		wantNotice := map[string]string{"fr": "phrase secrète", "en": "passphrase"}[lang]
		wantFile := map[string]string{"fr": "antivirus", "en": "antivirus"}[lang]
		if !strings.Contains(m.Text, wantNotice) || !strings.Contains(m.Text, wantFile) {
			t.Errorf("%s: notices missing:\n%s", lang, m.Text)
		}
		// Without passphrase and file the notices disappear.
		v.HasPassphrase, v.HasFile = false, false
		job, err = e.n.SecretNotification(t.Context(), e.t, v, secretLink)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(job.Message.Text, wantNotice) || strings.Contains(job.Message.Text, wantFile) {
			t.Errorf("%s: unexpected notices", lang)
		}
	}
}

func TestSecretNotificationErrors(t *testing.T) {
	e := newEnv(t)
	cases := map[string]struct {
		edit func(*SecretView)
		link string
		want error
	}{
		"bad link":      {func(*SecretView) {}, "javascript:alert(1)", ErrInvalidLink},
		"link space":    {func(*SecretView) {}, "https://a.example.com/s x#k=1", ErrInvalidLink},
		"bad sender":    {func(v *SecretView) { v.SenderEmail = "x" }, secretLink, ErrInvalidTransfer},
		"bad recipient": {func(v *SecretView) { v.RecipientEmail = "" }, secretLink, ErrInvalidTransfer},
		"expired":       {func(v *SecretView) { v.ExpiresAt = testNow }, secretLink, ErrTransferExpired},
	}
	for name, c := range cases {
		v := testSecret()
		c.edit(&v)
		if _, err := e.n.SecretNotification(t.Context(), e.t, v, c.link); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	e.smtp.cfg = store.SMTPConfig{}
	e.n.templates = failRenderer{}
	if _, err := e.n.SecretNotification(t.Context(), e.t, testSecret(), secretLink); err == nil {
		t.Error("render failure not reported")
	}
	e = newEnv(t)
	e.smtp.err = store.ErrNotFound
	if _, err := e.n.SecretNotification(t.Context(), e.t, testSecret(), secretLink); !errors.Is(err, ErrNoSMTP) {
		t.Errorf("no smtp: %v", err)
	}
}

func TestSecretReceipt(t *testing.T) {
	want := map[string]map[string]string{
		"fr": {mail.SecretOutcomeRead: "a été lu", mail.SecretOutcomeExpired: "expiré", mail.SecretOutcomeLocked: "verrouillé"},
		"en": {mail.SecretOutcomeRead: "was read", mail.SecretOutcomeExpired: "expired", mail.SecretOutcomeLocked: "locked"},
	}
	for lang, outcomes := range want {
		for outcome, frag := range outcomes {
			e := newEnv(t)
			v := testSecret()
			v.Language = lang
			job, err := e.n.SecretReceipt(t.Context(), e.t, v, outcome, testNow)
			if err != nil {
				t.Fatal(err)
			}
			m := job.Message
			if job.Template != mail.TemplateSecretReceipt || len(m.To) != 1 || m.To[0] != v.SenderEmail {
				t.Fatalf("job %+v", job)
			}
			if !strings.Contains(m.Subject+m.Text, frag) || !strings.Contains(m.Text, v.ID) || !strings.Contains(m.Text, "bob@example.com") {
				t.Errorf("%s/%s: content:\n%s\n%s", lang, outcome, m.Subject, m.Text)
			}
			if strings.Contains(e.logs.String(), "bob@example.com") {
				t.Errorf("recipient logged")
			}
		}
	}
	// Link delivery: no recipient line.
	e := newEnv(t)
	v := testSecret()
	v.Delivery, v.RecipientEmail = store.SecretDeliveryLink, "bob@example.com"
	job, err := e.n.SecretReceipt(t.Context(), e.t, v, mail.SecretOutcomeRead, testNow)
	if err != nil || strings.Contains(job.Message.Text, "bob@example.com") {
		t.Errorf("link delivery: %v\n%s", err, job.Message.Text)
	}
}

func TestSecretReceiptErrors(t *testing.T) {
	e := newEnv(t)
	cases := map[string]func(*SecretView, *string, *time.Time){
		"bad sender":  func(v *SecretView, _ *string, _ *time.Time) { v.SenderEmail = "x" },
		"bad outcome": func(_ *SecretView, o *string, _ *time.Time) { *o = "deleted" },
		"zero at":     func(_ *SecretView, _ *string, at *time.Time) { *at = time.Time{} },
		"no created":  func(v *SecretView, _ *string, _ *time.Time) { v.CreatedAt = time.Time{} },
		"no id":       func(v *SecretView, _ *string, _ *time.Time) { v.ID = "" },
	}
	for name, edit := range cases {
		v, outcome, at := testSecret(), mail.SecretOutcomeRead, testNow
		edit(&v, &outcome, &at)
		if _, err := e.n.SecretReceipt(t.Context(), e.t, v, outcome, at); !errors.Is(err, ErrInvalidTransfer) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	e.n.templates = failRenderer{}
	if _, err := e.n.SecretReceipt(t.Context(), e.t, testSecret(), mail.SecretOutcomeRead, testNow); err == nil {
		t.Error("render failure not reported")
	}
}

func TestSecretViewOf(t *testing.T) {
	s := store.Secret{
		ID: "sec_x", SenderEmail: "a@example.com", RecipientEmail: "b@example.com", Delivery: store.SecretDeliveryEmail,
		KDFSalt: []byte{1}, FileSize: 5, CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
	}
	v := SecretViewOf(s)
	if v.ID != "sec_x" || !v.HasPassphrase || !v.HasFile || v.FileSize != 5 || v.RecipientEmail != "b@example.com" || v.Language != "" {
		t.Errorf("view %+v", v)
	}
	if v := SecretViewOf(store.Secret{FileStorageName: "f"}); !v.HasFile || v.HasPassphrase {
		t.Errorf("view %+v", v)
	}
	if v := SecretViewOf(store.Secret{}); v.HasFile {
		t.Errorf("view %+v", v)
	}
}

package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/png"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

var testNow = time.Date(2026, time.October, 21, 10, 0, 0, 0, time.UTC)

// fakeVault returns a fresh password buffer per call and keeps them, so
// that tests can check they were wiped.
type fakeVault struct {
	err     error
	calls   int
	tid     tenant.ID
	purpose crypto.Purpose
	wkID    string
	issued  [][]byte
}

func (v *fakeVault) Open(_ context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error) {
	v.calls++
	v.tid, v.purpose, v.wkID = tid, p, wkID
	if v.err != nil {
		return nil, v.err
	}
	b := []byte("s3cret-pass")
	v.issued = append(v.issued, b)
	return b, nil
}

// fakeSMTP returns a fixed configuration, or an error.
type fakeSMTP struct {
	cfg store.SMTPConfig
	err error
	tid tenant.ID
}

func (s *fakeSMTP) Get(_ context.Context, tid tenant.ID) (store.SMTPConfig, error) {
	s.tid = tid
	return s.cfg, s.err
}

// failRenderer fails every render.
type failRenderer struct{}

func (failRenderer) RenderFor(context.Context, mail.OverrideLookup, string, string, string, any) (mail.Message, error) {
	return mail.Message{}, errors.New("render boom")
}

type env struct {
	n     *Notifier
	vault *fakeVault
	smtp  *fakeSMTP
	t     *tenant.Tenant
	logs  *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		vault: &fakeVault{},
		smtp: &fakeSMTP{cfg: store.SMTPConfig{
			Host: "smtp.entity-a.example.com", Port: 587, Security: store.SMTPSecuritySTARTTLS,
			Username: "mailer", PasswordKeyID: "wk_01", FromAddress: "transfer@entity-a.example.com",
			FromName: "Entity A",
		}},
		t:    &tenant.Tenant{ID: "ten_a", Name: "Entity A & Co", DefaultLanguage: "fr"},
		logs: &bytes.Buffer{},
	}
	logger := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.n = New(e.vault, e.smtp, nil, Options{Now: func() time.Time { return testNow }, Logger: logger})
	return e
}

func testTransfer() TransferView {
	return TransferView{
		ID:          "tr_01",
		SenderEmail: "alice@entity-a.example.com",
		Recipients:  []string{"bob@example.com", "carol@example.org", "BOB@EXAMPLE.COM", "dave@example.net"},
		Message:     "See you <b>soon</b>",
		ExpiresAt:   testNow.Add(7 * 24 * time.Hour),
		Files: []FileView{
			{Name: "report.pdf", Size: 2 << 20, SHA256: strings.Repeat("AB", 32), Scan: ScanClean},
			{Name: "big.iso", Size: 3 << 30, SHA256: strings.Repeat("cd", 32), Scan: ScanTooLarge},
			{Name: "eicar.com", Size: 68, Scan: ScanInfected, Signature: "Win.Test.EICAR_HDB-1"},
			{Name: "locked.zip", Size: 5 << 20, Scan: ScanWithheld},
			{Name: "vault.7z", Size: 1 << 20, SHA256: strings.Repeat("ef", 32), Scan: ScanEncrypted},
		},
	}
}

// build checks that a job is sendable and returns its MIME form.
func build(t *testing.T, j mail.Job) string {
	t.Helper()
	raw, err := mail.Build(j.Settings, j.Message)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return string(raw)
}

func TestRecipientJobs(t *testing.T) {
	e := newEnv(t)
	tr := testTransfer()
	jobs, err := e.n.RecipientJobs(context.Background(), e.t, tr, testLink)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bob@example.com", "carol@example.org", "dave@example.net"}
	if len(jobs) != len(want) {
		t.Fatalf("%d jobs, want %d (duplicates merged)", len(jobs), len(want))
	}
	for i, j := range jobs {
		if len(j.Message.To) != 1 || j.Message.To[0] != want[i] {
			t.Fatalf("job %d To = %v", i, j.Message.To)
		}
		if j.TenantID != "ten_a" || j.Template != mail.TemplateTransferNotification || j.Message.Language != "fr" {
			t.Errorf("job %d: %+v", i, j)
		}
		raw := build(t, j)
		for _, other := range want {
			if other != want[i] && strings.Contains(strings.ToLower(raw), other) {
				t.Errorf("job %d leaks recipient %s", i, other)
			}
		}
		for _, s := range []string{
			"alice@entity-a.example.com", testLink, strings.Repeat("ab", 32), strings.Repeat("cd", 32),
			"Non analys", "vault.7z", "archive chiffrée", strings.Repeat("ef", 32), "cid:qr@transteira",
		} {
			if !strings.Contains(j.Message.HTML, s) {
				t.Errorf("job %d HTML lacks %q", i, s)
			}
		}
		if strings.Contains(j.Message.Text, "eicar") || strings.Contains(j.Message.HTML, "eicar") ||
			strings.Contains(j.Message.Text, "locked") || strings.Contains(j.Message.HTML, "locked") {
			t.Errorf("job %d lists the infected or withheld file", i)
		}
		if len(j.Message.Inline) != 1 {
			t.Fatalf("job %d: %d inline parts", i, len(j.Message.Inline))
		}
		p := j.Message.Inline[0]
		if p.ContentID != mail.QRContentID || p.ContentType != "image/png" || p.Filename != "qr.png" {
			t.Errorf("inline part %+v", p)
		}
		img, err := png.Decode(bytes.NewReader(p.Data))
		if err != nil {
			t.Fatal(err)
		}
		if got := decodeQR(t, img); got != testLink {
			t.Errorf("QR decodes to %q", got)
		}
		if j.Settings.Password != "s3cret-pass" || j.Settings.Host != "smtp.entity-a.example.com" ||
			j.Settings.Security != mail.SecurityStartTLS || j.Settings.FromName != "Entity A" {
			t.Errorf("settings %v", j.Settings)
		}
	}
	// One unsealing per build, for the right tenant and secret, wiped after.
	if e.vault.calls != 1 || e.vault.tid != "ten_a" || e.vault.purpose != crypto.PurposeSecret || e.vault.wkID != "wk_01" {
		t.Errorf("vault calls %+v", e.vault)
	}
	for _, b := range e.vault.issued {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error("password buffer not wiped")
		}
	}
	if e.smtp.tid != "ten_a" {
		t.Errorf("smtp read for %q", e.smtp.tid)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "count=3") || strings.Contains(logs, "@") || strings.Contains(logs, "s3cret") {
		t.Errorf("logs: %s", logs)
	}
}

func TestLanguage(t *testing.T) {
	e := newEnv(t)
	tr := testTransfer()
	for lang, want := range map[string]string{"en": "en", "fr": "fr", "": "fr", "de": "fr"} {
		tr.Language = lang
		j, err := e.n.SenderConfirmation(context.Background(), e.t, tr, testLink)
		if err != nil {
			t.Fatal(err)
		}
		if j.Message.Language != want {
			t.Errorf("transfer language %q: mail in %q, want %q", lang, j.Message.Language, want)
		}
	}
	// A tenant default that is not supported falls back to English.
	e.t.DefaultLanguage = "xx"
	tr.Language = ""
	j, err := e.n.SenderConfirmation(context.Background(), e.t, tr, testLink)
	if err != nil || j.Message.Language != "en" {
		t.Errorf("fallback: %v %q", err, j.Message.Language)
	}
}

func TestHostileContentEscaped(t *testing.T) {
	e := newEnv(t)
	tr := testTransfer()
	tr.Language = "en"
	tr.Message = "Hi <script>alert(1)</script>\r\nGo to https://phishing.example.com/login <a href=\"https://evil.example\">here</a>\u202e\u200bgnp.exe\x00"
	tr.Files[0].Name = "<img src=x onerror=alert(1)>\nBcc: eve@example.com\u202egpj.exe"
	tr.Files[2].Signature = "<b>Evil</b>\r\nInjected: header"
	jobs, err := e.n.RecipientJobs(context.Background(), e.t, tr, testLink)
	if err != nil {
		t.Fatal(err)
	}
	m := jobs[0].Message
	for _, bad := range []string{
		"<script>", "<img src=x", `href="https://evil`, `href="https://phishing`, "\u202e", "\u200b", "\x00", "\r",
	} {
		if strings.Contains(m.HTML, bad) {
			t.Errorf("HTML contains %q", bad)
		}
	}
	// The download link is the only link.
	if n := strings.Count(m.HTML, "<a "); n != 1 || !strings.Contains(m.HTML, `<a href="`+testLink+`"`) {
		t.Errorf("%d links in HTML", n)
	}
	if !strings.Contains(m.HTML, "&lt;script&gt;") || !strings.Contains(m.HTML, "&lt;img src=x onerror=alert(1)&gt; Bcc: eve@example.com") {
		t.Errorf("HTML not escaped:\n%s", m.HTML)
	}
	// In text, the message is quoted line by line and the name is one line.
	if !strings.Contains(m.Text, "> Go to https://phishing.example.com/login") ||
		!strings.Contains(m.Text, "- <img src=x onerror=alert(1)> Bcc: eve@example.com") ||
		strings.Contains(m.Text, "\nBcc:") || strings.ContainsAny(m.Text, "\r\x00\u202e") {
		t.Errorf("text:\n%q", m.Text)
	}

	j, err := e.n.FileProblems(context.Background(), e.t, tr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(j.Message.HTML, "<b>Evil") || strings.Contains(j.Message.Text, "\nInjected") ||
		!strings.Contains(j.Message.Text, "<b>Evil</b> Injected: header") {
		t.Errorf("signature not neutralized:\n%s", j.Message.Text)
	}
}

func TestPasswordSentence(t *testing.T) {
	e := newEnv(t)
	tr := testTransfer()
	sentences := map[string]string{
		"fr": "Le mot de passe vous sera transmis par un autre canal",
		"en": "The password will be sent to you by another channel",
	}
	for lang, s := range sentences {
		tr.Language = lang
		for _, protected := range []bool{true, false} {
			tr.PasswordProtected = protected
			jobs, err := e.n.RecipientJobs(context.Background(), e.t, tr, testLink)
			if err != nil {
				t.Fatal(err)
			}
			m := jobs[0].Message
			if got := strings.Contains(m.Text, s) && strings.Contains(m.HTML, s); got != protected {
				t.Errorf("%s protected=%v: sentence present=%v", lang, protected, got)
			}
		}
	}
}

func TestSenderMails(t *testing.T) {
	e := newEnv(t)
	tr := testTransfer()
	tr.Language = "en"
	ctx := context.Background()

	j, err := e.n.SenderConfirmation(ctx, e.t, tr, testLink)
	if err != nil {
		t.Fatal(err)
	}
	if j.Message.To[0] != "alice@entity-a.example.com" || j.Template != mail.TemplateTransferConfirmation || len(j.Message.Inline) != 0 {
		t.Errorf("confirmation %+v", j)
	}
	for _, s := range []string{"bob@example.com", "carol@example.org", "dave@example.net", testLink, strings.Repeat("ab", 32), "October 28, 2026 at 10:00 UTC"} {
		if !strings.Contains(j.Message.Text, s) {
			t.Errorf("confirmation lacks %q", s)
		}
	}
	if strings.Count(j.Message.Text, "bob@example.com") != 1 || strings.Contains(j.Message.Text, "eicar") ||
		!strings.Contains(j.Message.Text, "Withheld files:\n- locked.zip (5.0\u00a0MB)") ||
		!strings.Contains(j.Message.Text, "withheld for safety") || !strings.Contains(j.Message.HTML, "locked.zip") {
		t.Errorf("confirmation recipients or files:\n%s", j.Message.Text)
	}
	build(t, j)
	// Without a withheld file, the confirmation has no such section.
	clean := tr
	clean.Files = tr.Files[:3]
	if j, err = e.n.SenderConfirmation(ctx, e.t, clean, testLink); err != nil || strings.Contains(j.Message.Text, "Withheld") {
		t.Errorf("confirmation without withheld file: %v\n%s", err, j.Message.Text)
	}

	j, err = e.n.FileProblems(ctx, e.t, tr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(j.Message.Text, "eicar.com") || !strings.Contains(j.Message.Text, "Win.Test.EICAR_HDB-1") ||
		!strings.Contains(j.Message.Text, "- locked.zip (5.0\u00a0MB)") || !strings.HasPrefix(j.Message.Subject, "Infected file") ||
		!strings.Contains(j.Message.Text, "The other files of the transfer have been sent") || strings.Contains(j.Message.Text, "report.pdf") ||
		j.Template != mail.TemplateFileProblems || j.Message.To[0] != "alice@entity-a.example.com" {
		t.Errorf("problems mail:\n%s", j.Message.Text)
	}
	build(t, j)

	// Every file infected or withheld: the transfer was not sent.
	all := tr
	all.Files = []FileView{tr.Files[2], {Name: "b.exe", Scan: ScanInfected, Signature: "X"}, tr.Files[3]}
	j, err = e.n.FileProblems(ctx, e.t, all)
	if err != nil || !strings.Contains(j.Message.Text, "the transfer was not sent") || !strings.Contains(j.Message.Text, "b.exe") ||
		!strings.Contains(j.Message.Text, "locked.zip") {
		t.Errorf("rejected: %v\n%s", err, j.Message.Text)
	}

	// Withheld files only, nothing delivered: one mail, without virus wording.
	withheld := tr
	withheld.Files = []FileView{tr.Files[3], {Name: "second.bin", Size: 10, Scan: ScanWithheld}}
	j, err = e.n.FileProblems(ctx, e.t, withheld)
	if err != nil || !strings.HasPrefix(j.Message.Subject, "File withheld") || !strings.Contains(j.Message.Text, "the transfer was not sent") ||
		!strings.Contains(j.Message.Text, "second.bin (10\u00a0B)") || strings.Contains(j.Message.Text, "threat") {
		t.Errorf("withheld only: %v\n%s\n%s", err, j.Message.Subject, j.Message.Text)
	}
	build(t, j)

	// Withheld files beside delivered ones.
	withheld.Files = []FileView{tr.Files[0], tr.Files[3]}
	j, err = e.n.FileProblems(ctx, e.t, withheld)
	if err != nil || !strings.Contains(j.Message.Text, "The other files of the transfer have been sent") {
		t.Errorf("withheld with delivered: %v\n%s", err, j.Message.Text)
	}

	j, err = e.n.FileNotScanned(ctx, e.t, tr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(j.Message.Text, "big.iso (3.0\u00a0GB)") || strings.Contains(j.Message.Text, "report.pdf") ||
		!strings.Contains(j.Message.Text, "Reason: the file is too large") || !strings.Contains(j.Message.Text, "vault.7z (1.0") ||
		!strings.Contains(j.Message.Text, "Reason: encrypted archive") || j.Template != mail.TemplateFileNotScanned {
		t.Errorf("not scanned mail:\n%s", j.Message.Text)
	}
	// Only an encrypted archive: the mail still goes, with its reason.
	enc := tr
	enc.Files = tr.Files[4:]
	j, err = e.n.FileNotScanned(ctx, e.t, enc)
	if err != nil || !strings.Contains(j.Message.Text, "Reason: encrypted archive") || strings.Contains(j.Message.Text, "too large") {
		t.Errorf("encrypted only: %v\n%s", err, j.Message.Text)
	}
	// Recipients are told, per file, which reason applies.
	enc.Files = tr.Files[:2]
	enc.Files = append(enc.Files, tr.Files[4])
	jobs, err := e.n.RecipientJobs(ctx, e.t, enc, testLink)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"- big.iso (3.0\u00a0GB)\n  SHA-256: " + strings.Repeat("cd", 32) + "\n  Not scanned by the antivirus: the file is too large or too complex to be fully analyzed.",
		"- vault.7z (1.0\u00a0MB)\n  SHA-256: " + strings.Repeat("ef", 32) + "\n  Could not be analyzed by the antivirus: encrypted archive.",
	} {
		if !strings.Contains(jobs[0].Message.Text, s) {
			t.Errorf("recipient mail lacks %q:\n%s", s, jobs[0].Message.Text)
		}
	}
	if strings.Count(jobs[0].Message.Text, "Could not be analyzed") != 1 || strings.Count(jobs[0].Message.Text, "Not scanned by") != 1 {
		t.Errorf("reasons mixed up:\n%s", jobs[0].Message.Text)
	}
	build(t, j)
}

func TestFirstDownload(t *testing.T) {
	e := newEnv(t)
	tr := testTransfer()
	ctx := context.Background()
	at := testNow.Add(90 * time.Minute)

	// Deletion after the first download: the deletion time is shown.
	j, err := e.n.FirstDownload(ctx, e.t, tr, at, at.Add(15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if j.Template != mail.TemplateFirstDownload || j.TenantID != "ten_a" || len(j.Message.To) != 1 ||
		j.Message.To[0] != "alice@entity-a.example.com" || j.Message.Language != "fr" || len(j.Message.Inline) != 0 {
		t.Errorf("first download job %+v", j)
	}
	for _, s := range []string{"21 octobre 2026 à 11:30 UTC", "- report.pdf (2,0\u00a0Mo)", "big.iso", "vault.7z", "effacé le 21 octobre 2026 à 11:45 UTC"} {
		if !strings.Contains(j.Message.Text, s) {
			t.Errorf("first download mail lacks %q:\n%s", s, j.Message.Text)
		}
	}
	// Only delivered files are listed, and no recipient is named.
	for _, s := range []string{"eicar", "locked.zip", "bob@", "carol@", "dave@", testLink} {
		if strings.Contains(j.Message.Text, s) || strings.Contains(j.Message.HTML, s) {
			t.Errorf("first download mail contains %q", s)
		}
	}
	if j.Settings.Password != "s3cret-pass" || e.vault.calls != 1 {
		t.Errorf("settings %+v, vault calls %d", j.Settings, e.vault.calls)
	}
	for _, b := range e.vault.issued {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error("password buffer not wiped")
		}
	}
	build(t, j)

	// A deletion due at once is shown as such.
	tr.Language = "en"
	j, err = e.n.FirstDownload(ctx, e.t, tr, at, at)
	if err != nil || j.Message.Language != "en" || !strings.Contains(j.Message.Text, "erased on October 21, 2026 at 11:30 UTC.") ||
		!strings.Contains(j.Message.Text, "October 21, 2026 at 11:30 UTC") {
		t.Errorf("one minute: %v\n%s", err, j.Message.Text)
	}

	// No deletion: the once-only notice, no deletion time.
	j, err = e.n.FirstDownload(ctx, e.t, tr, at, time.Time{})
	if err != nil || strings.Contains(j.Message.Text, "erased") || !strings.Contains(j.Message.Text, "sent only once") {
		t.Errorf("no deletion: %v\n%s", err, j.Message.Text)
	}

	// File names are reduced to one line and escaped in HTML.
	tr.Files = []FileView{{Name: "<b>x</b>\n\u202eevil.txt", Size: 1, SHA256: strings.Repeat("ab", 32), Scan: ScanClean}}
	j, err = e.n.FirstDownload(ctx, e.t, tr, at, time.Time{})
	if err != nil || !strings.Contains(j.Message.Text, "- <b>x</b> evil.txt (1\u00a0B)") ||
		!strings.Contains(j.Message.HTML, "&lt;b&gt;x&lt;/b&gt; evil.txt") || strings.Contains(j.Message.HTML, "<b>x") {
		t.Errorf("hostile name: %v\n%s\n%s", err, j.Message.Text, j.Message.HTML)
	}
}

func TestNoPasswordKey(t *testing.T) {
	e := newEnv(t)
	e.smtp.cfg = store.SMTPConfig{Host: "relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "transfer@entity-a.example.com"}
	j, err := e.n.SenderConfirmation(context.Background(), e.t, testTransfer(), testLink)
	if err != nil || e.vault.calls != 0 || j.Settings.Password != "" || j.Settings.Security != mail.SecurityNone {
		t.Errorf("relay: %v calls=%d %v", err, e.vault.calls, j.Settings)
	}
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	type call func(e *env, tr TransferView) error
	recipients := func(link string) call {
		return func(e *env, tr TransferView) error { _, err := e.n.RecipientJobs(ctx, e.t, tr, link); return err }
	}
	confirm := func(e *env, tr TransferView) error {
		_, err := e.n.SenderConfirmation(ctx, e.t, tr, testLink)
		return err
	}
	problems := func(e *env, tr TransferView) error { _, err := e.n.FileProblems(ctx, e.t, tr); return err }
	notScanned := func(e *env, tr TransferView) error { _, err := e.n.FileNotScanned(ctx, e.t, tr); return err }
	firstDownload := func(at, deleteAt time.Time) call {
		return func(e *env, tr TransferView) error {
			_, err := e.n.FirstDownload(ctx, e.t, tr, at, deleteAt)
			return err
		}
	}
	first := firstDownload(testNow, time.Time{})
	all := map[string]call{
		"recipients": recipients(testLink), "confirm": confirm, "problems": problems, "notScanned": notScanned,
		"first": first, "firstDelete": firstDownload(testNow, testNow.Add(time.Minute)),
	}

	storeBoom := errors.New("db down")
	cases := []struct {
		name  string
		calls map[string]call
		edit  func(e *env, tr *TransferView)
		want  error
	}{
		{"no smtp", all, func(e *env, _ *TransferView) { e.smtp.err = fmt.Errorf("x: %w", store.ErrNotFound) }, ErrNoSMTP},
		{"smtp error", all, func(e *env, _ *TransferView) { e.smtp.err = storeBoom }, storeBoom},
		{"vault error", all, func(e *env, _ *TransferView) { e.vault.err = storeBoom }, storeBoom},
		{"bad sender", all, func(_ *env, tr *TransferView) { tr.SenderEmail = "alice" }, ErrInvalidTransfer},
		{"unknown scan", all, func(_ *env, tr *TransferView) { tr.Files[0].Scan = 0 }, ErrInvalidTransfer},
		{"scan out of range", all, func(_ *env, tr *TransferView) { tr.Files[1].Scan = 9 }, ErrInvalidTransfer},
		{
			"expired",
			map[string]call{"recipients": recipients(testLink), "confirm": confirm},
			func(_ *env, tr *TransferView) { tr.ExpiresAt = testNow }, ErrTransferExpired,
		},
		{
			"bad digest",
			map[string]call{"recipients": recipients(testLink), "confirm": confirm, "notScanned": notScanned, "first": first},
			func(_ *env, tr *TransferView) { tr.Files[1].SHA256 = strings.Repeat("zz", 32) }, ErrInvalidTransfer,
		},
		{
			"short digest",
			map[string]call{"recipients": recipients(testLink), "confirm": confirm},
			func(_ *env, tr *TransferView) { tr.Files[0].SHA256 = "abcd" }, ErrInvalidTransfer,
		},
		{
			"negative size",
			map[string]call{"recipients": recipients(testLink), "confirm": confirm},
			func(_ *env, tr *TransferView) { tr.Files[0].Size = -1 }, ErrInvalidTransfer,
		},
		{
			"no delivered file",
			map[string]call{"recipients": recipients(testLink), "confirm": confirm, "notScanned": notScanned, "first": first},
			func(_ *env, tr *TransferView) { tr.Files = tr.Files[2:4] }, ErrInvalidTransfer,
		},
		{
			"zero first download time",
			map[string]call{"first": firstDownload(time.Time{}, time.Time{})},
			func(*env, *TransferView) {}, ErrInvalidTransfer,
		},
		{
			"deletion before the first download",
			map[string]call{"first": firstDownload(testNow, testNow.Add(-time.Second))},
			func(*env, *TransferView) {}, ErrInvalidTransfer,
		},
		{
			"no problem file",
			map[string]call{"problems": problems},
			func(_ *env, tr *TransferView) { tr.Files = tr.Files[:2] }, ErrInvalidTransfer,
		},
		{
			"nothing too large",
			map[string]call{"notScanned": notScanned},
			func(_ *env, tr *TransferView) { tr.Files[1].Scan, tr.Files[4].Scan = ScanClean, ScanClean }, ErrInvalidTransfer,
		},
		{
			"no recipient",
			map[string]call{"recipients": recipients(testLink), "confirm": confirm},
			func(_ *env, tr *TransferView) { tr.Recipients = nil }, ErrInvalidTransfer,
		},
		{
			"bad recipient",
			map[string]call{"recipients": recipients(testLink), "confirm": confirm},
			func(_ *env, tr *TransferView) { tr.Recipients = []string{"bob@example.com", "Bob <bob@example.com>"} }, ErrInvalidTransfer,
		},
		{
			"too many recipients",
			map[string]call{"recipients": recipients(testLink), "confirm": confirm},
			func(_ *env, tr *TransferView) {
				tr.Recipients = nil
				for i := range MaxRecipients + 1 {
					tr.Recipients = append(tr.Recipients, fmt.Sprintf("r%d@example.com", i))
				}
			}, ErrInvalidTransfer,
		},
		{"render error", all, func(e *env, _ *TransferView) { e.n.templates = failRenderer{} }, nil},
	}
	for _, c := range cases {
		for name, fn := range c.calls {
			e := newEnv(t)
			tr := testTransfer()
			c.edit(e, &tr)
			err := fn(e, tr)
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Errorf("%s/%s: got %v, want %v", c.name, name, err, c.want)
			}
			if err != nil && strings.Contains(err.Error(), "s3cret") {
				t.Errorf("%s/%s: error leaks the password", c.name, name)
			}
		}
	}

	badLinks := []string{
		"", "javascript:alert(1)", "ftp://example.com/x", "https://", "https:opaque", "/relative/path",
		"https://user:pw@example.com/d/x", "https://example.com/d/x y", "https://example.com/\u202ex",
		"https://example.com/\n", "https://exa%mple.com/", "https://example.com/" + strings.Repeat("a", maxLinkLen),
		"https://example.com/\xff",
	}
	for _, l := range badLinks {
		e := newEnv(t)
		if err := recipients(l)(e, testTransfer()); !errors.Is(err, ErrInvalidLink) {
			t.Errorf("link %q: %v", l, err)
		}
	}
	// A valid link too long for the QR code is refused by QRPNG.
	e := newEnv(t)
	if err := recipients(testLink+"?"+strings.Repeat("q", maxQRText))(e, testTransfer()); !errors.Is(err, ErrQRText) {
		t.Errorf("long link: %v", err)
	}
}

func TestNewDefaults(t *testing.T) {
	n := New(&fakeVault{}, &fakeSMTP{}, nil, Options{})
	if n.templates != mail.DefaultTemplates() || n.now == nil || n.logger == nil {
		t.Errorf("defaults not applied: %+v", n)
	}
	tpl := mail.DefaultTemplates()
	if New(nil, nil, tpl, Options{}).templates != tpl {
		t.Error("templates not kept")
	}
}

func TestOneLine(t *testing.T) {
	cases := map[string]string{
		"  plain.txt  ":          "plain.txt",
		"a\nb\tc\r\x00d":         "a b cd",
		"bad\xffutf8":            "bad\uFFFDutf8",
		"rtl\u202eexe.txt\u200b": "rtlexe.txt",
	}
	for in, want := range cases {
		if got := oneLine(in, 100); got != want {
			t.Errorf("oneLine(%q) = %q, want %q", in, got, want)
		}
	}
	if got := oneLine(strings.Repeat("é", 10), 5); got != "éééé\u2026" {
		t.Errorf("cut: %q", got)
	}
	if got := oneLine("ééééé", 5); got != "ééééé" {
		t.Errorf("exact: %q", got)
	}
}

// TestConfidentialityLabel shows the label of the level of the transfer in
// the language of each mail, and nothing without level.
func TestConfidentialityLabel(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tr := testTransfer()
	tr.ConfidentialityLabels = map[string]string{"fr": "Diffusion restreinte", "en": "Restricted\r\nBcc: x"}
	for lang, want := range map[string]string{"fr": "Diffusion restreinte", "en": "Restricted Bcc: x", "": "Diffusion restreinte"} {
		tr.Language = lang
		jobs, err := e.n.RecipientJobs(ctx, e.t, tr, testLink)
		if err != nil {
			t.Fatal(err)
		}
		conf, err := e.n.SenderConfirmation(ctx, e.t, tr, testLink)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range []mail.Message{jobs[0].Message, conf.Message} {
			if !strings.Contains(m.Text, want) || !strings.Contains(m.HTML, want) {
				t.Errorf("%q: mail lacks %q:\n%s", lang, want, m.Text)
			}
		}
	}
	// A label missing in the mail language falls back to the default
	// language of the templates.
	tr.Language, tr.ConfidentialityLabels = "fr", map[string]string{"en": "Internal only"}
	if got := e.n.levelLabel(e.t, tr); got != "Internal only" {
		t.Errorf("fallback label = %q", got)
	}
	tr.ConfidentialityLabels = nil
	if got := e.n.levelLabel(e.t, tr); got != "" {
		t.Errorf("label without level = %q", got)
	}
	jobs, err := e.n.RecipientJobs(ctx, e.t, tr, testLink)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(jobs[0].Message.Text, "Diffusion restreinte") {
		t.Error("label shown without level")
	}
}

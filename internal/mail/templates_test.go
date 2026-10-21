package mail

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ed-fr/transteira/internal/i18n"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files of the mail templates")

// goldenData returns the data used to render each template in golden tests.
// The invitation message carries HTML and a URL to prove both are escaped
// and never linkified.
func goldenData() map[string]any {
	return map[string]any{
		TemplateVerificationCode: VerificationCodeData{
			TenantName: "Entity A & Co", Code: "123456", ValidityMinutes: 15,
		},
		TemplateInvitation: InvitationData{
			TenantName:   "Entity A & Co",
			InviterEmail: "alice@entity-a.example.com",
			Message:      "Hello <b>Bob</b>,\nplease send the files.\n<script>alert(1)</script> https://phishing.example.com\n",
			Link:         "https://transfer.entity-a.example.com/invitations/inv_abc123",
			ExpiresAt:    time.Date(2027, time.October, 20, 8, 0, 0, 0, time.UTC),
		},
		TemplateTransferNotification: TransferNotificationData{
			TenantName:       "Entity A & Co",
			SenderEmail:      "alice@entity-a.example.com",
			Message:          hostileMessage,
			Link:             goldenLink,
			Files:            goldenFiles(),
			ExpiresAt:        goldenExpiry,
			PasswordRequired: true,
			QR:               true,
		},
		TemplateTransferConfirmation: TransferConfirmationData{
			TenantName:       "Entity A & Co",
			Link:             goldenLink,
			Recipients:       []string{"bob@example.com", "carol@example.org"},
			Files:            goldenFiles(),
			ExpiresAt:        goldenExpiry,
			PasswordRequired: true,
			Withheld:         []FileInfo{{Name: "<i>archive</i>.zip", Size: 3 << 20}},
		},
		TemplateFileProblems: FileProblemsData{
			TenantName: "Entity A & Co",
			Infected: []InfectedFile{
				{Name: "eicar.com", Signature: "Win.Test.EICAR_HDB-1"},
				{Name: "<img src=x onerror=alert(1)>.exe", Signature: "<b>Evil</b>"},
			},
			Withheld: []FileInfo{{Name: "<i>archive</i>.zip", Size: 3 << 20}},
		},
		TemplateFileNotScanned: FileNotScannedData{
			TenantName: "Entity A & Co",
			Files:      goldenFiles()[1:],
		},
		TemplateFirstDownload: FirstDownloadData{
			TenantName:   "Entity A & Co",
			Files:        goldenFiles(),
			DownloadedAt: time.Date(2027, time.October, 14, 16, 5, 0, 0, time.UTC),
			DeleteAt:     time.Date(2027, time.October, 14, 16, 20, 0, 0, time.UTC),
		},
	}
}

// Shared golden values of the transfer templates.
const (
	hostileMessage = "Hello <b>Bob</b>,\nplease see https://phishing.example.com/login\n" +
		`<a href="https://evil.example">click</a>` + "\n"
	goldenLink = "https://transfer.entity-a.example.com/d/dl_abc123"
)

var goldenExpiry = time.Date(2027, time.October, 20, 8, 30, 0, 0, time.UTC)

// goldenFiles returns the files of the transfer golden tests: a hostile
// name, then a file too large or complex to be scanned and an encrypted
// archive.
func goldenFiles() []FileInfo {
	return []FileInfo{
		{Name: "<script>alert(1)</script> report.pdf", Size: 1536, SHA256: strings.Repeat("ab", 32)},
		{Name: "video.mp4", Size: 3 << 30, SHA256: strings.Repeat("0f", 32), NotScanned: NotScannedTooLarge},
		{Name: "secret.zip", Size: 4 << 20, SHA256: strings.Repeat("e1", 32), NotScanned: NotScannedEncrypted},
	}
}

func TestTemplatesGolden(t *testing.T) {
	tpl := DefaultTemplates()
	if got := strings.Join(tpl.Names(), ","); got != "file_not_scanned,file_problems,first_download,invitation,transfer_confirmation,transfer_notification,verification_code" {
		t.Fatalf("Names() = %s", got)
	}
	for name, data := range goldenData() {
		for _, lang := range i18n.Supported() {
			m, err := tpl.Render(name, lang, data)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, lang, err)
			}
			if m.Language != lang || m.To != nil || m.Inline != nil {
				t.Errorf("%s/%s: unexpected fields %+v", name, lang, m)
			}
			for ext, got := range map[string]string{"subject.txt": m.Subject + "\n", "text.txt": m.Text, "html": m.HTML} {
				compareGolden(t, filepath.Join("testdata", "golden", name+"."+lang+"."+ext), got)
			}
			// Every rendered message must be sendable as-is.
			m.To = []string{"bob@example.com"}
			if _, err := Build(buildSettings(), m); err != nil {
				t.Errorf("%s/%s: Build: %v", name, lang, err)
			}
		}
	}
}

// compareGolden compares got with the golden file, or rewrites it with -update.
func compareGolden(t *testing.T, path, got string) {
	t.Helper()
	if *updateGolden {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/mail -run Golden -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden file:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func TestTemplatesEscaping(t *testing.T) {
	data := goldenData()[TemplateInvitation].(InvitationData)
	data.Link = "javascript:alert(1)"
	m, err := Render(TemplateInvitation, "en", data)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script>", "<b>Bob</b>", `href="javascript:`, `href="https://phishing`} {
		if strings.Contains(m.HTML, bad) {
			t.Errorf("HTML contains %q", bad)
		}
	}
	if !strings.Contains(m.HTML, "&lt;script&gt;") || !strings.Contains(m.HTML, "Entity A &amp; Co") {
		t.Error("HTML not escaped as expected")
	}
	if strings.Contains(m.HTML, "http") && strings.Contains(m.HTML, "src=") {
		t.Error("remote resource in HTML")
	}
	if !strings.Contains(m.Text, "> <script>alert(1)</script> https://phishing.example.com") {
		t.Errorf("text message not quoted:\n%s", m.Text)
	}
	// Without a message, the quote block disappears.
	data.Message = ""
	m, err = Render(TemplateInvitation, "fr", data)
	if err != nil || strings.Contains(m.Text, "Son message") || strings.Contains(m.HTML, "blockquote") {
		t.Errorf("empty message: %v\n%s", err, m.Text)
	}
}

func TestTemplatesFirstDownloadVariants(t *testing.T) {
	data := goldenData()[TemplateFirstDownload].(FirstDownloadData)
	// The golden data covers the deletion time; check the transfer kept
	// until its expiry.
	for lang, want := range map[string]string{"en": "erased on October 14, 2027 at 16:20 UTC.", "fr": "effacé le 14 octobre 2027 à 16:20 UTC."} {
		m, err := Render(TemplateFirstDownload, lang, data)
		if err != nil || !strings.Contains(m.Text, want) || !strings.Contains(m.HTML, want) {
			t.Errorf("%s deletion time: %v\n%s", lang, err, m.Text)
		}
	}
	data.DeleteAt = time.Time{}
	for lang, want := range map[string]string{"en": "sent only once", "fr": "envoyé qu'une fois"} {
		m, err := Render(TemplateFirstDownload, lang, data)
		if err != nil || !strings.Contains(m.Text, want) || strings.Contains(m.Text, "16:20") {
			t.Errorf("%s kept: %v\n%s", lang, err, m.Text)
		}
		if !strings.Contains(m.HTML, want) || strings.Contains(m.HTML, "16:20") {
			t.Errorf("%s kept HTML:\n%s", lang, m.HTML)
		}
		// File names are escaped in HTML and no recipient is named.
		if strings.Contains(m.HTML, "<script>") || !strings.Contains(m.HTML, "&lt;script&gt;") || strings.Contains(m.Text, "@") {
			t.Errorf("%s: escaping or recipient:\n%s", lang, m.HTML)
		}
	}
}

func TestTemplatesSubjectNeutralizesNewlines(t *testing.T) {
	m, err := Render(TemplateVerificationCode, "en", VerificationCodeData{TenantName: "Evil\r\nBcc: eve@example.com", Code: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(m.Subject, "\r\n") || m.Subject != "Your verification code for Evil Bcc: eve@example.com" {
		t.Errorf("subject %q", m.Subject)
	}
}

func TestTemplatesRenderErrors(t *testing.T) {
	if _, err := Render("nope", "en", nil); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("unknown: %v", err)
	}
	// Unsupported language falls back to English.
	m, err := Render(TemplateVerificationCode, "de", goldenData()[TemplateVerificationCode])
	if err != nil || m.Language != "en" {
		t.Errorf("fallback: %v %q", err, m.Language)
	}
	// Wrong data type: execution error.
	if _, err := Render(TemplateVerificationCode, "fr", struct{}{}); err == nil {
		t.Error("wrong data: want error")
	}
	cat := i18n.DefaultCatalog()
	tpl, err := NewTemplates(fstest.MapFS{
		"fr/only_fr.subject.tmpl":  {Data: []byte("s")},
		"fr/only_fr.text.tmpl":     {Data: []byte("t")},
		"en/bad_text.subject.tmpl": {Data: []byte("s")},
		"en/bad_text.text.tmpl":    {Data: []byte("{{.Missing}}")},
		"en/bad_html.subject.tmpl": {Data: []byte("s")},
		"en/bad_html.text.tmpl":    {Data: []byte("t")},
		"en/bad_html.html.tmpl":    {Data: []byte("{{.Missing}}")},
		"en/no_html.subject.tmpl":  {Data: []byte("{{t \"mail.footer.ignore\"}}")},
		"en/no_html.text.tmpl":     {Data: []byte("{{quote \"a\\r\\n\\r\\nb \\n\\n\"}}|{{date .}}")},
	}, cat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tpl.Render("only_fr", "en", nil); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("only_fr: %v", err)
	}
	if m, err := tpl.Render("only_fr", "fr", nil); err != nil || m.Subject != "s" || m.HTML != "" {
		t.Errorf("only_fr fr: %+v %v", m, err)
	}
	data := map[string]any{}
	if _, err := tpl.Render("bad_text", "en", data); err == nil {
		t.Error("bad_text: want error")
	}
	if _, err := tpl.Render("bad_html", "en", data); err == nil {
		t.Error("bad_html: want error")
	}
	m, err = tpl.Render("no_html", "en", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil || m.Text != "> a\n>\n> b|January 2, 2026" || m.Subject != i18n.T("en", "mail.footer.ignore") {
		t.Errorf("funcs: %q %q %v", m.Subject, m.Text, err)
	}
}

func TestNewTemplatesErrors(t *testing.T) {
	cat := i18n.DefaultCatalog()
	cases := map[string]fstest.MapFS{
		"unknown language": {"de/x.subject.tmpl": {Data: []byte("s")}},
		"root file":        {"x.subject.tmpl": {Data: []byte("s")}},
		"bad suffix":       {"en/x.subject.txt": {Data: []byte("s")}},
		"no part":          {"en/x.tmpl": {Data: []byte("s")}},
		"bad name":         {"en/X-1.subject.tmpl": {Data: []byte("s")}},
		"empty name":       {"en/.subject.tmpl": {Data: []byte("s")}},
		"unknown part":     {"en/x.footer.tmpl": {Data: []byte("s")}},
		"text parse":       {"en/x.subject.tmpl": {Data: []byte("{{")}},
		"html parse":       {"en/x.html.tmpl": {Data: []byte("{{end}}")}},
		"unknown func":     {"en/x.subject.tmpl": {Data: []byte(`{{exec "rm"}}`)}},
		"missing text": {
			"en/x.subject.tmpl": {Data: []byte("s")},
			"en/x.html.tmpl":    {Data: []byte("h")},
		},
		"nested dir": {"en/sub/x.subject.tmpl": {Data: []byte("s")}},
	}
	for name, fsys := range cases {
		if _, err := NewTemplates(fsys, cat); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

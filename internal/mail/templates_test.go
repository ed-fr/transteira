package mail

import (
	"errors"
	"flag"
	"io/fs"
	"math"
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
		TemplateQuotaWarning: QuotaAlertData{
			TenantName: "Entity A & Co", UsedBytes: 85 << 30, QuotaBytes: 100 << 30, AdminLink: goldenAdminLink,
		},
		TemplateQuotaReached: QuotaAlertData{
			TenantName: "Entity A & Co", UsedBytes: 100<<30 + 1, QuotaBytes: 100 << 30, AdminLink: goldenAdminLink,
		},
		TemplateDiskAlert: DiskAlertData{
			UsedBytes: 4000 << 30 / 100 * 91, TotalBytes: 4000 << 30, ThresholdPercent: 87.5, AdminLink: goldenAdminLink,
		},
	}
}

// Shared golden values of the transfer templates.
const (
	hostileMessage = "Hello <b>Bob</b>,\nplease see https://phishing.example.com/login\n" +
		`<a href="https://evil.example">click</a>` + "\n"
	goldenLink = "https://transfer.entity-a.example.com/d/dl_abc123"
	// goldenAdminLink is the console link of the quota alerts.
	goldenAdminLink = "https://admin.transfer.example.com/admin"
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
	if got := strings.Join(tpl.Names(), ","); got != "disk_alert,file_not_scanned,file_problems,first_download,invitation,quota_reached,quota_warning,transfer_confirmation,transfer_notification,verification_code" {
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

func TestQuotaPercent(t *testing.T) {
	for _, c := range []struct{ used, quota, want int64 }{
		{0, 100, 0},
		{79, 100, 79},
		{799, 1000, 79},
		{80, 100, 80},
		{150, 100, 150},
		{-5, 100, 0},
		{5, 0, 100},
		{5, -1, 100},
		{1 << 62, 1 << 62, 100},
		{math.MaxInt64, math.MaxInt64, 100},
		{math.MaxInt64 - 1, math.MaxInt64, 99}, // exact: a float would round up to 100
		{math.MaxInt64, 50, math.MaxInt64},     // quotient beyond int64: capped
		{math.MaxInt64, 1, math.MaxInt64},      // 128-bit quotient overflow: capped
	} {
		if got := UsagePercent(c.used, c.quota); got != c.want {
			t.Errorf("UsagePercent(%d, %d) = %d, want %d", c.used, c.quota, got, c.want)
		}
	}
	if formatPercent("fr", 80) != "80 %" || formatPercent("en", 80) != "80%" {
		t.Error("formatPercent")
	}
	// The threshold follows the template; the console link is the only link.
	data := goldenData()[TemplateQuotaWarning].(QuotaAlertData)
	for name, want := range map[string]string{TemplateQuotaWarning: "80%", TemplateQuotaReached: "100%"} {
		vals, ok := keyDefs[name].values(labelsFor("en"), "en", data)
		if !ok || vals["threshold_percent"].text != want || vals["usage_percent"].text != "85%" {
			t.Errorf("%s: %+v", name, vals)
		}
		m, err := Render(name, "fr", data)
		if err != nil || strings.Count(m.HTML, "<a ") != 1 || !strings.Contains(m.Subject, "Entity A & Co") {
			t.Errorf("%s: %v %s", name, err, m.Subject)
		}
	}
}

func TestTemplatesDiskAlert(t *testing.T) {
	for _, c := range []struct {
		lang string
		p    float64
		want string
	}{
		{"en", 85, "85%"},
		{"en", 87.5, "87.5%"},
		{"en", 85.004, "85%"},
		{"en", 99.125, "99.13%"},
		{"fr", 85, "85" + nbsp + "%"},
		{"fr", 87.25, "87,25" + nbsp + "%"},
	} {
		if got := formatDecimalPercent(c.lang, c.p); got != c.want {
			t.Errorf("formatDecimalPercent(%s, %v) = %q, want %q", c.lang, c.p, got, c.want)
		}
	}
	data := goldenData()[TemplateDiskAlert].(DiskAlertData)
	vals, ok := keyDefs[TemplateDiskAlert].values(labelsFor("en"), "en", data)
	if !ok || vals["usage_percent"].text != "91%" || vals["threshold_percent"].text != "87.5%" ||
		vals["total_size"].text != FormatSize("en", 4000<<30) {
		t.Errorf("disk alert values: %+v", vals)
	}
	// A system mail: no tenant name, the console link is the only link.
	for _, lang := range i18n.Supported() {
		m, err := Render(TemplateDiskAlert, lang, data)
		if err != nil || strings.Count(m.HTML, "<a ") != 1 || !strings.Contains(m.Subject, "TransTeira") ||
			!strings.Contains(m.Text, goldenAdminLink) {
			t.Errorf("%s: %v %s", lang, err, m.Subject)
		}
	}
	// "disk-alert", the API spelling, names the same built-in template.
	if v, err := Variables("disk-alert"); err != nil || len(v) != 5 || v[0].Name != "usage_percent" || !v[0].Required {
		t.Errorf("Variables(disk-alert) = %+v, %v", v, err)
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
	// Wrong data type.
	if _, err := Render(TemplateVerificationCode, "fr", struct{}{}); err == nil {
		t.Error("wrong data: want error")
	}
	// A template that only exists in French has no fallback in English.
	tpl, err := NewTemplates(fstest.MapFS{
		"fr/verification_code.subject.tmpl": {Data: []byte("s {{code}}")},
		"fr/verification_code.html.tmpl":    {Data: []byte("<p>{{code}}</p>")},
		"fr/verification_code.text.tmpl":    {Data: []byte("{{code}}")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tpl.Render(TemplateVerificationCode, "en", VerificationCodeData{}); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("only fr: %v", err)
	}
	if _, err := tpl.Source(TemplateVerificationCode, "en"); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("only fr source: %v", err)
	}
	m, err = tpl.Render(TemplateVerificationCode, "fr", VerificationCodeData{Code: "1"})
	if err != nil || m.Subject != "s 1" || m.Text != "1\n" || !strings.Contains(m.HTML, "<p>1</p>") {
		t.Errorf("only fr fr: %+v %v", m, err)
	}
	if got := strings.Join(tpl.Names(), ","); got != TemplateVerificationCode {
		t.Errorf("names %s", got)
	}
}

// failFS fails to open one file.
type failFS struct{ fstest.MapFS }

func (f failFS) Open(name string) (fs.File, error) {
	if name == "en/verification_code.text.tmpl" {
		return nil, fs.ErrPermission
	}
	return f.MapFS.Open(name)
}

func (f failFS) ReadFile(name string) ([]byte, error) {
	if name == "en/verification_code.text.tmpl" {
		return nil, fs.ErrPermission
	}
	return f.MapFS.ReadFile(name)
}

// failDirFS fails to list the en directory.
type failDirFS struct{ fstest.MapFS }

func (f failDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "en" {
		return nil, fs.ErrPermission
	}
	return f.MapFS.ReadDir(name)
}

func TestMustTemplates(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	mustTemplates(nil, errors.New("broken"))
}

func TestRenderWrongData(t *testing.T) {
	for _, name := range TemplateNames() {
		if _, err := Render(name, "en", struct{}{}); err == nil || !strings.Contains(err.Error(), "unexpected data type") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewTemplatesErrors(t *testing.T) {
	ok := fstest.MapFS{
		"en/verification_code.subject.tmpl": {Data: []byte("s")},
		"en/verification_code.html.tmpl":    {Data: []byte("<p>{{code}}</p>")},
		"en/verification_code.text.tmpl":    {Data: []byte("{{code}}")},
	}
	with := func(path, data string) fstest.MapFS {
		m := fstest.MapFS{}
		for k, v := range ok {
			m[k] = v
		}
		if data == "" {
			delete(m, path)
		} else {
			m[path] = &fstest.MapFile{Data: []byte(data)}
		}
		return m
	}
	cases := map[string]fs.FS{
		"unknown language": with("de/verification_code.subject.tmpl", "s"),
		"root file":        with("verification_code.subject.tmpl", "s"),
		"bad suffix":       with("en/verification_code.subject.txt", "s"),
		"no part":          with("en/verification_code.tmpl", "s"),
		"unknown key":      with("en/nope.subject.tmpl", "s"),
		"unknown part":     with("en/verification_code.footer.tmpl", "s"),
		"missing part":     with("en/verification_code.html.tmpl", ""),
		"syntax":           with("en/verification_code.text.tmpl", "{{.Code}}"),
		"nested dir":       with("en/sub/verification_code.subject.tmpl", "s"),
		"read error":       failFS{ok},
		"walk error":       failDirFS{ok},
	}
	for name, fsys := range cases {
		if _, err := NewTemplates(fsys); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

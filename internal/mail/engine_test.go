package mail

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/i18n"
)

func TestParsePlaceholders(t *testing.T) {
	pieces, se := parsePlaceholders("a {{x}} b {{ y_2 }}{{z}} { } c")
	if se != nil {
		t.Fatal(se)
	}
	var got []string
	for _, p := range pieces {
		if p.name != "" {
			got = append(got, p.name)
		} else {
			got = append(got, "'"+p.text+"'")
		}
	}
	if strings.Join(got, "|") != "'a '|x|' b '|y_2|z|' { } c'" {
		t.Errorf("pieces %v", got)
	}
	if pieces, se := parsePlaceholders(""); se != nil || len(pieces) != 0 {
		t.Errorf("empty: %v %v", pieces, se)
	}
	errs := map[string]string{
		"a {{x":                               "not closed",
		"a }} b":                              "without a matching",
		"{{x}} }}":                            "without a matching",
		"{{{x}}}":                             "nested braces",
		"{{a{b}}":                             "nested braces",
		"{{}}":                                "empty placeholder",
		"{{   }}":                             "empty placeholder",
		"{{  x}}":                             "one space",
		"{{x\t}}":                             "one space",
		"{{- x -}}":                           "trim markers",
		"{{/* c */}}":                         "comments",
		"{{.Link}}":                           "field and variable",
		"{{$x}}":                              "field and variable",
		"{{x | html}}":                        "pipelines",
		"{{if x}}":                            "template logic",
		"{{ end }}":                           "template logic",
		`{{define "a"}}`:                      "template logic",
		"{{template \"a\"}}":                  "template logic",
		`{{printf "%s" x}}`:                   "functions",
		"{{call(x)}}":                         "functions",
		"{{Name}}":                            "invalid variable name",
		"{{9x}}":                              "invalid variable name",
		"{{x-y}}":                             "invalid variable name",
		"{{" + strings.Repeat("a", 65) + "}}": "invalid variable name",
	}
	for in, want := range errs {
		_, se := parsePlaceholders(in)
		if se == nil || !strings.Contains(se.reason, want) {
			t.Errorf("%q: %v, want %q", in, se, want)
		}
	}
	if _, se := parsePlaceholders("ab\n {{.X}}"); se == nil || se.offset != 4 || !strings.Contains(se.Error(), "at byte 4") {
		t.Errorf("offset: %v", se)
	}
	if l, c := lineCol("é\nab{{", 5); l != 2 || c != 3 {
		t.Errorf("lineCol = %d,%d", l, c)
	}
}

func TestDefaultsAreValidCustomizations(t *testing.T) {
	for _, name := range TemplateNames() {
		for _, lang := range i18n.Supported() {
			src, err := DefaultSource(strings.ReplaceAll(name, "_", "-"), lang)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateTemplate(name, src.Subject, src.HTML, src.Text); err != nil {
				t.Errorf("%s/%s: %v", name, lang, err)
			}
			// Sanitizing a default changes nothing: an administrator who saves
			// it unchanged gets the same mail.
			norm, err := NormalizeTemplate(name, src)
			if err != nil || norm.HTML != strings.TrimRight(src.HTML, "\n") && norm.HTML != src.HTML || norm.Subject != src.Subject {
				t.Errorf("%s/%s: normalized differs: %v\n%s\n---\n%s", name, lang, err, norm.HTML, src.HTML)
			}
			// Rendering the source as an override gives the default mail.
			data := keyDefs[name].sample
			want, _ := Render(name, lang, data)
			got, err := RenderOverride(name, lang, data, &norm)
			if err != nil || got.Subject != want.Subject || got.Text != want.Text || got.HTML != want.HTML {
				t.Errorf("%s/%s: override render differs: %v", name, lang, err)
			}
		}
	}
	if got := strings.Join(TemplateNames(), ","); got != strings.Join(DefaultTemplates().Names(), ",") {
		t.Errorf("names %s", got)
	}
}

// issues returns the issues of a validation error as strings.
func issues(t *testing.T, err error) []string {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) || !errors.Is(err, ErrInvalidTemplate) {
		t.Fatalf("not a validation error: %v", err)
	}
	out := make([]string, len(ve.Issues))
	for i, is := range ve.Issues {
		out[i] = is.String()
	}
	return out
}

func TestValidateTemplate(t *testing.T) {
	const okHTML = `<p>{{code}}</p>`
	if err := ValidateTemplate("verification-code", "Code", okHTML, "{{code}}"); err != nil {
		t.Fatal(err)
	}
	// A required URL variable counts as the href of a link, even when it
	// also appears in a title.
	if err := ValidateTemplate("invitation", "s", `<p><a href="{{invitation_link}}" title="{{invitation_link}}">Open</a></p>`, "{{invitation_link}}"); err != nil {
		t.Errorf("link href: %v", err)
	}
	if err := ValidateTemplate("nope", "s", okHTML, "t"); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("unknown key: %v", err)
	}
	if _, err := NormalizeTemplate("nope", TemplateSource{}); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("normalize unknown key: %v", err)
	}
	if _, err := NormalizeTemplate("verification_code", TemplateSource{Subject: "s"}); !errors.Is(err, ErrInvalidTemplate) {
		t.Errorf("normalize invalid: %v", err)
	}

	cases := []struct {
		key, subject, html, text string
		want                     []string
	}{
		{"verification_code", "", okHTML, "{{code}}", []string{"subject: empty"}},
		{"verification_code", "s", " ", "{{code}}", []string{"html: empty"}},
		{"verification_code", "s", okHTML, "\n", []string{"text: empty"}},
		{"verification_code", "s\xff", okHTML, "{{code}}", []string{"subject: invalid UTF-8"}},
		{"verification_code", strings.Repeat("é", MaxSubjectLen+1), okHTML, "{{code}}", []string{"subject: longer than 255 characters"}},
		{"verification_code", "s", okHTML + strings.Repeat("x", MaxBodyLen), "{{code}}", []string{"html: longer than 100000 characters"}},
		// Syntax errors carry their position, in every part.
		{"verification_code", "Hi {{.TenantName}}", okHTML, "a\n\n  {{if x}}", []string{
			"subject line 1, column 4: field and variable access are not supported; write {{name}}",
			"text line 3, column 3: template logic (if, range, define...) is not supported",
		}},
		{"verification_code", "s", "<p>\n{{code}} {{ nope }}</p>", "{{code}}", []string{"html line 2, column 10: unknown variable {{nope}}"}},
		{"verification_code", "s", "<p>{{code}</p>", "{{code}}", []string{`html line 1, column 4: "{{" is not closed by "}}"`}},
		// Blocks are not allowed in the subject or in an attribute.
		{
			"transfer_notification", "{{files}}", "<p>{{download_link}}{{files}}{{password_notice}}</p>",
			"{{download_link}}{{files}}{{password_notice}}",
			[]string{"subject line 1, column 1: block variable {{files}} is not allowed in the subject"},
		},
		{
			"transfer_notification", "s", `<p title="{{files}}">{{download_link}}{{files}}{{password_notice}}</p>`,
			"{{download_link}}{{files}}{{password_notice}}",
			[]string{"html: block variable {{files}} is not allowed in an attribute"},
		},
		// Only URL variables in href; no placeholder in src or style.
		{
			"invitation", "s", `<a href="{{inviter_email}}">x</a>{{invitation_link}}`, "{{invitation_link}}",
			[]string{"html: variable {{inviter_email}} is not a URL and cannot be used in href"},
		},
		{
			"invitation", "s", `<a href="https://e.example/{{invitation_link}}">x</a>{{invitation_link}}`, "{{invitation_link}}",
			[]string{"html: <a href>: sanitize: placeholder not allowed here: a placeholder must be the whole URL"},
		},
		{
			"invitation", "s", `<img src="{{invitation_link}}"><p style="color:{{tenant_name}}">{{invitation_link}}</p>`, "{{invitation_link}}",
			[]string{"html: <img src>: sanitize: placeholder not allowed here", "html: <p style>: sanitize: placeholder not allowed here"},
		},
		// A placeholder built from entities is still checked.
		{"verification_code", "s", `<p>{{code}} &#123;&#123;nope&#125;&#125;</p>`, "{{code}}", []string{"html: unknown variable {{nope}}"}},
		{"verification_code", "s", `<p>{{code}} &#123;&#123;.X&#125;&#125;</p>`, "{{code}}", []string{"html: field and variable access are not supported; write {{name}}"}},
		{"verification_code", "s", `<p>{{code}}</p>`, "{{code}} {{nope}} {{nope}}", []string{
			"text line 1, column 10: unknown variable {{nope}}", "text line 1, column 19: unknown variable {{nope}}",
		}},
		// Required variables must be in both bodies, outside removed markup.
		{"verification_code", "s", `<p>x</p><script>{{code}}</script>`, "x", []string{
			"html: required variable {{code}} is missing", "text: required variable {{code}} is missing",
		}},
		{"transfer_notification", "s", `<a href="{{download_link}}">x</a>`, "{{download_link}}", []string{
			"html: required variable {{password_notice}} is missing", "text: required variable {{password_notice}} is missing",
			"html: required variable {{files}} is missing", "text: required variable {{files}} is missing",
		}},
		// In the HTML body, a required variable only counts where it is seen:
		// a title or alt attribute is not enough.
		{"verification_code", "s", `<p title="{{code}}">Your code</p>`, "{{code}}", []string{
			"html: required variable {{code}} is missing",
		}},
		{"verification_code", "s", `<p>Your code</p><img src="cid:x@e.example" alt="{{code}}">`, "{{code}}", []string{
			"html: required variable {{code}} is missing",
		}},
		{"invitation", "s", `<p><a href="https://e.example/" title="{{invitation_link}}">Open</a></p>`, "{{invitation_link}}", []string{
			"html: required variable {{invitation_link}} is missing",
		}},
		// Nothing visible once sanitized.
		{"invitation", "s", `<a href="{{invitation_link}}"></a><script>x</script>`, "{{invitation_link}}", []string{"html: empty once sanitized"}},
	}
	for _, c := range cases {
		err := ValidateTemplate(c.key, c.subject, c.html, c.text)
		if err == nil {
			t.Errorf("%s %q %q %q: want error", c.key, c.subject, c.html, c.text)
			continue
		}
		if got := issues(t, err); !slices.Equal(got, c.want) {
			t.Errorf("%s %q %q %q:\n got %q\nwant %q", c.key, c.subject, c.html, c.text, got, c.want)
		}
	}
	err := ValidateTemplate("verification_code", "", "", "")
	if !strings.HasPrefix(err.Error(), "mail: invalid template: subject: empty; html: empty; text: empty") {
		t.Errorf("Error() = %s", err)
	}
}

func TestNormalizeTemplate(t *testing.T) {
	src := TemplateSource{
		Subject: "  Code {{ code }}  ",
		HTML:    `<P onclick="x()" style="color:red;position:fixed">{{code}}</P><script>alert(1)</script><a href="javascript:x">l</a>`,
		Text:    "Code:\r\n{{code}}\r",
	}
	got, err := NormalizeTemplate("verification_code", src)
	if err != nil {
		t.Fatal(err)
	}
	want := TemplateSource{Subject: "Code {{ code }}", HTML: `<p style="color:red;">{{code}}</p><a>l</a>`, Text: "Code:\n{{code}}\n"}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if SanitizeHTML(`<b onclick=x>{{a}}</b>`) != "<b>{{a}}</b>" {
		t.Error("SanitizeHTML")
	}
}

func TestRenderOverride(t *testing.T) {
	data := TransferNotificationData{
		TenantName: `Evil "Co" <b>`, SenderEmail: "alice@entity-a.example.com", Message: "line1\r\nline2",
		Link: "https://transfer.entity-a.example.com/d/x?a=1&b=2", Files: goldenFiles()[:1], ExpiresAt: goldenExpiry,
	}
	ov := &TemplateSource{
		Subject: "{{sender_email}} – {{tenant_name}}",
		HTML: `<p title="{{tenant_name}}">Hi</p>
{{password_notice}}
<p><a href="{{download_link}}" title="{{download_link}}">{{download_link}}</a></p>
{{message}}
{{files}}
<img src="cid:qr@transteira" alt="{{tenant_name}}">`,
		Text: "Hi\n\n{{password_notice}}\n\n{{download_link}}\n\n{{message}}\n\nFiles:\n{{files}}\n\n{{qr_code}}\n\nEnd\n\n\n",
	}
	m, err := RenderOverride(TemplateTransferNotification, "en", data, ov)
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != `alice@entity-a.example.com – Evil "Co" <b>` || m.Language != "en" {
		t.Errorf("subject %q", m.Subject)
	}
	for _, want := range []string{
		`<title>alice@entity-a.example.com – Evil &#34;Co&#34; &lt;b&gt;</title>`,
		`<p title="Evil &#34;Co&#34; &lt;b&gt;">Hi</p>` + "\n<p><a href=",
		`<a href="https://transfer.entity-a.example.com/d/x?a=1&amp;b=2" title="https://transfer.entity-a.example.com/d/x?a=1&amp;b=2">https://transfer.entity-a.example.com/d/x?a=1&amp;b=2</a>`,
		"<blockquote", "line1\r\nline2</blockquote>",
		`<img src="cid:qr@transteira" alt="Evil &#34;Co&#34; &lt;b&gt;">` + "\n</div>",
	} {
		if !strings.Contains(m.HTML, want) {
			t.Errorf("HTML lacks %q:\n%s", want, m.HTML)
		}
	}
	// The empty password notice and QR code leave no blank line; the
	// message keeps LF line breaks; trailing blank lines are trimmed.
	wantText := "Hi\n\nhttps://transfer.entity-a.example.com/d/x?a=1&b=2\n\nTheir message:\n\n> line1\n> line2\n\n" +
		"Files:\n- <script>alert(1)</script> report.pdf (1.5" + nbsp + "KB)\n  SHA-256: " + strings.Repeat("ab", 32) + "\n\nEnd\n"
	if m.Text != wantText {
		t.Errorf("text:\n%q\nwant\n%q", m.Text, wantText)
	}

	// A URL value that is not http(s)/mailto is neutralized in href, and
	// shown as text elsewhere.
	data.Link = "javascript:alert(1)"
	m, err = RenderOverride(TemplateTransferNotification, "en", data, ov)
	if err != nil || !strings.Contains(m.HTML, `<a href="#"`) || strings.Contains(m.HTML, `href="javascript`) {
		t.Errorf("javascript link: %v\n%s", err, m.HTML)
	}
	// An invalid override is refused.
	bad := *ov
	bad.Text = "{{.Link}}"
	if _, err := RenderOverride(TemplateTransferNotification, "en", data, &bad); !errors.Is(err, ErrInvalidTemplate) {
		t.Errorf("invalid override: %v", err)
	}
	if _, err := RenderOverride("nope", "en", data, ov); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("unknown: %v", err)
	}
}

func TestSubjectHeaderInjection(t *testing.T) {
	ov := &TemplateSource{Subject: "Code {{code}} for {{tenant_name}}", HTML: "<p>{{code}}</p>", Text: "{{code}}"}
	data := VerificationCodeData{
		TenantName: "Evil\r\nBcc: eve@example.com\u2028X\u202eY\x00Z\tW\u0085V", Code: "1\n2",
	}
	m, err := RenderOverride(TemplateVerificationCode, "en", data, ov)
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != "Code 1 2 for Evil Bcc: eve@example.com XY Z W V" {
		t.Errorf("subject %q", m.Subject)
	}
	m.To = []string{"bob@example.com"}
	if _, err := Build(buildSettings(), m); err != nil {
		t.Errorf("Build: %v", err)
	}
	// Long subjects are cut to the limit of Build.
	data.TenantName = strings.Repeat("é", 400)
	m, _ = RenderOverride(TemplateVerificationCode, "en", data, ov)
	if r := []rune(m.Subject); len(r) != maxSubjectLen || r[len(r)-1] != '\u2026' {
		t.Errorf("long subject: %d runes", len(r))
	}
}

func TestLinkURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://e.example/a": "https://e.example/a", "HTTP://e.example": "HTTP://e.example",
		"mailto:a@e.example": "mailto:a@e.example", "javascript:alert(1)": "#", "data:text/html,x": "#",
		"https://e.example/a b": "#", "https://e.example/\x7f": "#", "": "#", "//e.example": "#",
	} {
		if got := linkURL(in); got != want {
			t.Errorf("linkURL(%q) = %q", in, got)
		}
	}
}

func TestRenderFor(t *testing.T) {
	ctx := context.Background()
	data := VerificationCodeData{TenantName: "T", Code: "424242", ValidityMinutes: 15}
	custom := &TemplateSource{Subject: "Custom {{code}}", HTML: "<p>C {{code}}</p>", Text: "C {{code}}"}
	var seen []string
	lookup := func(ov *TemplateSource, err error) OverrideLookup {
		return func(_ context.Context, tenantID, name, lang string) (*TemplateSource, error) {
			seen = append(seen, tenantID+"/"+name+"/"+lang)
			return ov, err
		}
	}
	tpl := DefaultTemplates()
	m, err := tpl.RenderFor(ctx, lookup(custom, nil), "ten_a", "verification-code", "de", data)
	if err != nil || m.Subject != "Custom 424242" || m.Language != "en" || seen[0] != "ten_a/verification_code/en" {
		t.Errorf("custom: %v %q %v", err, m.Subject, seen)
	}
	m, err = tpl.RenderFor(ctx, lookup(nil, nil), "ten_a", TemplateVerificationCode, "fr", data)
	if err != nil || !strings.HasPrefix(m.Subject, "Votre code") {
		t.Errorf("default: %v %q", err, m.Subject)
	}
	// A stored customization that no longer validates falls back to the
	// default template.
	m, err = tpl.RenderFor(ctx, lookup(&TemplateSource{Subject: "{{.Code}}"}, nil), "ten_a", TemplateVerificationCode, "en", data)
	if err != nil || !strings.HasPrefix(m.Subject, "Your verification code") {
		t.Errorf("invalid stored: %v %q", err, m.Subject)
	}
	boom := errors.New("boom")
	if _, err := tpl.RenderFor(ctx, lookup(nil, boom), "ten_a", TemplateVerificationCode, "en", data); !errors.Is(err, boom) {
		t.Errorf("lookup error: %v", err)
	}
	if _, err := tpl.RenderFor(ctx, lookup(nil, nil), "ten_a", "nope", "en", data); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("unknown: %v", err)
	}
}

func TestPreviewAndVariables(t *testing.T) {
	for _, name := range TemplateNames() {
		// The disk and antivirus alerts are instance mails: they name the
		// service, not an entity.
		want := sampleTenant
		if name == TemplateDiskAlert || name == TemplateAntivirusAlert {
			want = "TransTeira"
		}
		for _, lang := range i18n.Supported() {
			m, err := Preview(name, lang, nil)
			if err != nil || m.Subject == "" || !strings.Contains(m.HTML, want) || m.Language != lang {
				t.Errorf("%s/%s preview: %v %+v", name, lang, err, m)
			}
			// The administration CSP blocks inline styles and cid:
			// images: the preview has none, the rendered mail keeps them.
			if strings.Contains(m.HTML, "style") || strings.Contains(m.HTML, "<img") {
				t.Errorf("%s/%s preview keeps inline styles: %s", name, lang, m.HTML)
			}
		}
		vars, err := Variables(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vars {
			if v.Description == "" || (v.Sample == "" && v.Name != "qr_code") {
				t.Errorf("%s: variable %+v lacks a description or sample", name, v)
			}
		}
	}
	m, err := Preview("verification-code", "fr", &TemplateSource{Subject: "S {{code}}", HTML: "<p>{{code}}</p>", Text: "{{code}}"})
	if err != nil || m.Subject != "S 123456" || m.Text != "123456\n" {
		t.Errorf("custom preview: %v %+v", err, m)
	}
	styled := &TemplateSource{Subject: "S", HTML: `<p style="color:#123456">{{code}}</p>`, Text: "{{code}}"}
	if m, err := Preview("verification-code", "fr", styled); err != nil || strings.Contains(m.HTML, "style") || !strings.Contains(m.HTML, "<p>123456</p>") {
		t.Errorf("styled preview: %v %s", err, m.HTML)
	}
	if m, err := RenderOverride(TemplateVerificationCode, "fr", keyDefs[TemplateVerificationCode].sample, styled); err != nil || !strings.Contains(m.HTML, `style="color:#123456;"`) {
		t.Errorf("styled render: %v %s", err, m.HTML)
	}
	if _, err := Preview("nope", "fr", nil); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := Preview("verification-code", "fr", &TemplateSource{}); !errors.Is(err, ErrInvalidTemplate) {
		t.Errorf("invalid: %v", err)
	}
	if _, err := Variables("nope"); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("unknown variables: %v", err)
	}

	// Required variables of each key.
	want := map[string]string{
		TemplateVerificationCode:          "code",
		TemplateInvitation:                "invitation_link",
		TemplateTransferNotification:      "download_link,password_notice,files",
		TemplateTransferConfirmation:      "password_notice",
		TemplateFileProblems:              "infected_files,withheld_files,outcome",
		TemplateFileNotScanned:            "files",
		TemplateFirstDownload:             "download_datetime,deletion_notice",
		TemplateExpiryReminder:            "download_link,password_notice",
		TemplateRecipientVerificationCode: "code",
		TemplateQuotaWarning:              "usage_percent",
		TemplateQuotaReached:              "usage_percent",
	}
	for name, w := range want {
		vars, _ := Variables(name)
		var req []string
		for _, v := range vars {
			if v.Required {
				req = append(req, v.Name)
			}
		}
		if strings.Join(req, ",") != w {
			t.Errorf("%s required = %v, want %s", name, req, w)
		}
	}
	if VarText.String() != "text" || VarURL.String() != "url" || VarBlock.String() != "block" {
		t.Error("VarKind.String")
	}
}

func TestEmptyLists(t *testing.T) {
	// Lists without item render nothing.
	for name, data := range map[string]any{
		TemplateFileNotScanned:       FileNotScannedData{TenantName: "T"},
		TemplateTransferConfirmation: TransferConfirmationData{TenantName: "T", Link: goldenLink},
	} {
		m, err := Render(name, "en", data)
		if err != nil || strings.Contains(m.HTML, "<ul") || strings.Contains(m.Text, "\n- ") {
			t.Errorf("%s: %v\n%s", name, err, m.Text)
		}
	}
}

func FuzzParseTemplate(f *testing.F) {
	for _, s := range []string{"a {{x}} b", "{{ y }}", "{{.X}}", "{{if}}", "}}", "{{", "{{{a}}}", "<p title=\"{{a}}\">{{b}}</p>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		pieces, se := parsePlaceholders(s)
		if se != nil {
			if se.offset < 0 || se.offset > len(s) || se.reason == "" {
				t.Fatalf("bad error %+v", se)
			}
			return
		}
		// The pieces cover the input exactly, and names are valid.
		var b strings.Builder
		for _, p := range pieces {
			if p.name == "" {
				if strings.Contains(p.text, "{{") || strings.Contains(p.text, "}}") {
					t.Fatalf("literal %q holds braces", p.text)
				}
				b.WriteString(p.text)
			} else {
				if !isVarName(p.name) {
					t.Fatalf("name %q", p.name)
				}
				b.WriteString(s[p.offset : p.offset+strings.Index(s[p.offset:], "}}")+2])
			}
		}
		if b.String() != s {
			t.Fatalf("pieces %q do not cover %q", b.String(), s)
		}
		// Validation never panics, whatever the part.
		_ = ValidateTemplate(TemplateVerificationCode, s, s, s)
	})
}

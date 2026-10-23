package mail

import (
	"fmt"
	"math"
	"math/bits"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/i18n"
)

// VarKind is the type of a template variable, which decides where it can
// appear.
type VarKind int

// Variable kinds.
const (
	// VarText is plain text (an address, a date, a code): HTML-escaped in
	// the HTML body, raw in the text body, allowed in the subject and in the
	// title and alt attributes.
	VarText VarKind = iota
	// VarURL is an absolute URL built by the server from the registered FQDN
	// of the tenant. Besides the places of a text variable, it is the only
	// kind allowed as the whole value of an href attribute.
	VarURL
	// VarBlock is a pre-rendered block produced by the server (a list of
	// files with their SHA-256, a notice shown only in some cases): trusted
	// HTML in the HTML body, plain text in the text body, empty when it does
	// not apply. A block is only allowed in element content and in the text
	// body, never in the subject or in an attribute.
	VarBlock
)

// String returns "text", "url" or "block".
func (k VarKind) String() string {
	switch k {
	case VarURL:
		return "url"
	case VarBlock:
		return "block"
	default:
		return "text"
	}
}

// Variable describes a variable of a template.
type Variable struct {
	// Name is the placeholder name, written {{name}}.
	Name string
	// Kind is the type of the variable.
	Kind VarKind
	// Required variables must appear in both the HTML and the text body of a
	// customized template.
	Required bool
	// Description explains the variable, in English.
	Description string
	// Sample is the value of the variable in the preview, in English (the
	// text form for a block).
	Sample string
}

// trustedHTML is HTML produced by this package (the HTML form of a block).
// User-provided strings are never converted to it: they go through
// html.EscapeString.
type trustedHTML string

// value is the value of a variable for one rendering.
type value struct {
	kind VarKind
	text string      // text and URL values; text form of a block
	html trustedHTML // HTML form of a block
}

func textValue(s string) value { return value{kind: VarText, text: s} }
func urlValue(s string) value  { return value{kind: VarURL, text: s} }

func blockValue(h trustedHTML, t string) value {
	return value{kind: VarBlock, html: h, text: t}
}

// varSpec declares a variable of a template key.
type varSpec struct {
	name        string
	kind        VarKind
	required    bool
	description string
}

// keyDef declares a template key: its variables, how data becomes values,
// and the sample data of previews.
type keyDef struct {
	vars   []varSpec
	values func(l *labels, lang string, data any) (map[string]value, bool)
	sample any
}

// Common variable declarations.
var (
	tenantVar = varSpec{"tenant_name", VarText, false, "Display name of the entity."}
	filesVar  = func(required bool) varSpec {
		return varSpec{"files", VarBlock, required, "List of the files (name, size, SHA-256 fingerprint and antivirus status)."}
	}
)

// keyDefs declares every template key.
var keyDefs = map[string]keyDef{
	TemplateVerificationCode: {
		vars: []varSpec{
			tenantVar,
			{"code", VarText, true, "One-time verification code (6 digits)."},
			{"validity_minutes", VarText, false, "Lifetime of the code, in minutes."},
		},
		values: verificationValues,
		sample: VerificationCodeData{TenantName: sampleTenant, Code: "123456", ValidityMinutes: 15},
	},
	TemplateInvitation: {
		vars: []varSpec{
			tenantVar,
			{"inviter_email", VarText, false, "Address of the internal user who sends the invitation."},
			{"message", VarBlock, false, "Message of the inviter, quoted; empty when there is none."},
			{"invitation_link", VarURL, true, "Invitation link."},
			{"expiry_date", VarText, false, "Date when the unused invitation expires."},
		},
		values: invitationValues,
		sample: InvitationData{
			TenantName: sampleTenant, InviterEmail: sampleSender, Message: sampleMessage,
			Link: "https://transfer.entity-a.example.com/invitations/inv_sample", ExpiresAt: sampleTime.AddDate(1, 0, 0),
		},
	},
	TemplateTransferNotification: {
		vars: []varSpec{
			tenantVar,
			{"sender_email", VarText, false, "Address of the sender."},
			{"message", VarBlock, false, "Message of the sender, quoted; empty when there is none."},
			{"download_link", VarURL, true, "Download link."},
			{"expiry_datetime", VarText, false, "Date and time when the transfer expires."},
			{"password_notice", VarBlock, true, "Notice that the password comes through another channel; empty without password."},
			{"qr_code", VarBlock, false, "QR code of the download link (HTML only; empty in the text body)."},
			filesVar(true),
			{"file_count", VarText, false, "Number of files."},
		},
		values: notificationValues,
		sample: TransferNotificationData{
			TenantName: sampleTenant, SenderEmail: sampleSender, Message: sampleMessage, Link: sampleLink,
			Files: sampleFiles(), ExpiresAt: sampleTime.AddDate(0, 0, 7), PasswordRequired: true, QR: true,
		},
	},
	TemplateTransferConfirmation: {
		vars: []varSpec{
			tenantVar,
			{"download_link", VarURL, true, "Download link."},
			{"expiry_datetime", VarText, false, "Date and time when the transfer expires."},
			{"password_notice", VarBlock, true, "Reminder to give the password through another channel; empty without password."},
			{"recipients", VarBlock, false, "List of the recipients."},
			filesVar(false),
			{"file_count", VarText, false, "Number of delivered files."},
			{"withheld_files", VarBlock, false, "Files withheld because they could not be analyzed; empty when there is none."},
		},
		values: confirmationValues,
		sample: TransferConfirmationData{
			TenantName: sampleTenant, Link: sampleLink, Recipients: []string{"bob@example.com", "carol@example.org"},
			Files: sampleFiles(), ExpiresAt: sampleTime.AddDate(0, 0, 7), PasswordRequired: true,
			Withheld: []FileInfo{{Name: "archive.zip", Size: 3 << 20}},
		},
	},
	TemplateFileProblems: {
		vars: []varSpec{
			tenantVar,
			{"problem_summary", VarText, false, "Short summary for the subject (infected file deleted, or file withheld)."},
			{"infected_files", VarBlock, true, "Infected files, deleted, with the detected threat; empty when there is none."},
			{"withheld_files", VarBlock, true, "Files withheld because they could not be analyzed; empty when there is none."},
			{"outcome", VarText, true, "Whether the other files were sent or the whole transfer was rejected."},
			{"advice", VarBlock, false, "What to do next."},
		},
		values: problemsValues,
		sample: FileProblemsData{
			TenantName: sampleTenant,
			Infected:   []InfectedFile{{Name: "invoice.exe", Signature: "Win.Test.EICAR_HDB-1"}},
			Withheld:   []FileInfo{{Name: "archive.zip", Size: 3 << 20}},
		},
	},
	TemplateFileNotScanned: {
		vars: []varSpec{
			tenantVar,
			{"files", VarBlock, true, "Files the antivirus could not analyze, with the reason."},
		},
		values: notScannedValues,
		sample: FileNotScannedData{TenantName: sampleTenant, Files: sampleFiles()[1:]},
	},
	TemplateFirstDownload: {
		vars: []varSpec{
			tenantVar,
			{"download_datetime", VarText, true, "Date and time of the first complete download."},
			{"files", VarBlock, false, "List of the files (name and size)."},
			{"deletion_notice", VarBlock, true, "When the transfer will be erased, or that this notice is sent only once."},
		},
		values: firstDownloadValues,
		sample: FirstDownloadData{
			TenantName: sampleTenant, Files: sampleFiles(), DownloadedAt: sampleTime,
			DeleteAt: sampleTime.Add(15 * time.Minute),
		},
	},
	TemplateQuotaWarning: quotaKeyDef(QuotaWarningPercent, 82),
	TemplateQuotaReached: quotaKeyDef(QuotaReachedPercent, 100),
	TemplateDiskAlert: {
		vars: []varSpec{
			{"usage_percent", VarText, true, "Share of the disk used, with the percent sign, rounded down."},
			{"threshold_percent", VarText, false, "Alert threshold, with the percent sign."},
			{"used_size", VarText, false, "Space used on the disk of the data directory."},
			{"total_size", VarText, false, "Size of the disk of the data directory."},
			{"admin_link", VarURL, false, "Link to the administration console."},
		},
		values: diskAlertValues,
		sample: DiskAlertData{
			UsedBytes: 4000 << 30 / 100 * 87, TotalBytes: 4000 << 30, ThresholdPercent: 85,
			AdminLink: "https://admin.transfer.example.com/admin",
		},
	},
}

// Thresholds of the quota alerts, in percent of the quota (CLAUDE.md
// section 8.5), shown by the quota alert mails. Package quota raises the
// alert levels at these same thresholds.
const (
	// QuotaWarningPercent is the threshold of [TemplateQuotaWarning].
	QuotaWarningPercent = 80
	// QuotaReachedPercent is the threshold of [TemplateQuotaReached].
	QuotaReachedPercent = 100
)

// quotaKeyDef declares a quota alert key of the given threshold; the sample
// uses usedPercent of a 500 GB quota.
func quotaKeyDef(threshold, usedPercent int64) keyDef {
	const sampleQuota = 500 << 30
	return keyDef{
		vars: []varSpec{
			tenantVar,
			{"usage_percent", VarText, true, "Share of the storage quota used, with the percent sign, rounded down."},
			{"threshold_percent", VarText, false, "Threshold that triggered the alert, with the percent sign."},
			{"used_size", VarText, false, "Storage used by the entity."},
			{"quota_size", VarText, false, "Storage quota of the entity."},
			{"admin_link", VarURL, false, "Link to the administration console."},
		},
		values: quotaValues(threshold),
		sample: QuotaAlertData{
			TenantName: sampleTenant, UsedBytes: sampleQuota / 100 * usedPercent, QuotaBytes: sampleQuota,
			AdminLink: "https://admin.transfer.example.com/admin",
		},
	}
}

// Sample data of the previews.
const (
	sampleTenant  = "Entity A"
	sampleSender  = "alice@entity-a.example.com"
	sampleLink    = "https://transfer.entity-a.example.com/d/dl_sample"
	sampleMessage = "Hello,\nhere are the documents we talked about."
)

var sampleTime = time.Date(2026, time.October, 21, 14, 30, 0, 0, time.UTC)

func sampleFiles() []FileInfo {
	return []FileInfo{
		{Name: "report.pdf", Size: 1536 << 10, SHA256: strings.Repeat("ab", 32)},
		{Name: "video.mp4", Size: 3 << 30, SHA256: strings.Repeat("0f", 32), NotScanned: NotScannedTooLarge},
		{Name: "secret.zip", Size: 4 << 20, SHA256: strings.Repeat("e1", 32), NotScanned: NotScannedEncrypted},
	}
}

// TemplateNames returns the sorted names of the template keys. The API
// writes the same keys with "-" instead of "_" ("verification-code"); every
// function of this package taking a key accepts both forms.
func TemplateNames() []string {
	names := make([]string, 0, len(keyDefs))
	for n := range keyDefs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// keyName normalizes an API key ("verification-code") to a template name.
func keyName(key string) string { return strings.ReplaceAll(key, "-", "_") }

// lookupKey returns the definition of key.
func lookupKey(key string) (string, keyDef, error) {
	name := keyName(key)
	def, ok := keyDefs[name]
	if !ok {
		return "", keyDef{}, fmt.Errorf("%w: %q", ErrUnknownTemplate, key)
	}
	return name, def, nil
}

// Variables returns the variables of template key, in a stable order, with
// their sample values. Errors wrap [ErrUnknownTemplate].
func Variables(key string) ([]Variable, error) {
	_, def, err := lookupKey(key)
	if err != nil {
		return nil, err
	}
	vals, _ := def.values(labelsFor(i18n.English), i18n.English, def.sample) // sample has the right type
	out := make([]Variable, len(def.vars))
	for i, v := range def.vars {
		out[i] = Variable{Name: v.name, Kind: v.kind, Required: v.required, Description: v.description, Sample: vals[v.name].text}
	}
	return out, nil
}

// specs indexes the variables of a key by name.
func (d keyDef) specs() map[string]varSpec {
	m := make(map[string]varSpec, len(d.vars))
	for _, v := range d.vars {
		m[v.name] = v
	}
	return m
}

// --- Values of each key ---------------------------------------------------

func verificationValues(_ *labels, _ string, data any) (map[string]value, bool) {
	d, ok := data.(VerificationCodeData)
	if !ok {
		return nil, false
	}
	return map[string]value{
		"tenant_name":      textValue(d.TenantName),
		"code":             textValue(d.Code),
		"validity_minutes": textValue(strconv.Itoa(d.ValidityMinutes)),
	}, true
}

func invitationValues(l *labels, lang string, data any) (map[string]value, bool) {
	d, ok := data.(InvitationData)
	if !ok {
		return nil, false
	}
	return map[string]value{
		"tenant_name":     textValue(d.TenantName),
		"inviter_email":   textValue(d.InviterEmail),
		"message":         messageBlock(l, d.Message),
		"invitation_link": urlValue(d.Link),
		"expiry_date":     textValue(i18n.FormatDate(lang, d.ExpiresAt)),
	}, true
}

func notificationValues(l *labels, lang string, data any) (map[string]value, bool) {
	d, ok := data.(TransferNotificationData)
	if !ok {
		return nil, false
	}
	return map[string]value{
		"tenant_name":     textValue(d.TenantName),
		"sender_email":    textValue(d.SenderEmail),
		"message":         messageBlock(l, d.Message),
		"download_link":   urlValue(d.Link),
		"expiry_datetime": textValue(FormatDateTime(lang, d.ExpiresAt)),
		"password_notice": noticeBlock(d.PasswordRequired, l.otherChannelRecipient, true),
		"qr_code":         qrBlock(l, d.QR),
		"files":           filesBlock(l, lang, d.Files),
		"file_count":      textValue(strconv.Itoa(len(d.Files))),
	}, true
}

func confirmationValues(l *labels, lang string, data any) (map[string]value, bool) {
	d, ok := data.(TransferConfirmationData)
	if !ok {
		return nil, false
	}
	return map[string]value{
		"tenant_name":     textValue(d.TenantName),
		"download_link":   urlValue(d.Link),
		"expiry_datetime": textValue(FormatDateTime(lang, d.ExpiresAt)),
		"password_notice": noticeBlock(d.PasswordRequired, l.otherChannelSender, true),
		"recipients":      recipientsBlock(d.Recipients),
		"files":           filesBlock(l, lang, d.Files),
		"file_count":      textValue(strconv.Itoa(len(d.Files))),
		"withheld_files":  withheldConfirmationBlock(l, lang, d.Withheld),
	}, true
}

func problemsValues(l *labels, lang string, data any) (map[string]value, bool) {
	d, ok := data.(FileProblemsData)
	if !ok {
		return nil, false
	}
	summary, outcome := l.summaryWithheld, l.outcomeSent
	if len(d.Infected) > 0 {
		summary = l.summaryInfected
	}
	if d.Rejected {
		outcome = l.outcomeRejected
	}
	var advice []string
	if len(d.Infected) > 0 {
		advice = append(advice, l.adviceInfected)
	}
	if len(d.Withheld) > 0 {
		advice = append(advice, l.adviceWithheld)
	}
	return map[string]value{
		"tenant_name":     textValue(d.TenantName),
		"problem_summary": textValue(summary),
		"infected_files":  infectedBlock(l, d.Infected),
		"withheld_files":  withheldProblemsBlock(l, lang, d.Withheld),
		"outcome":         textValue(outcome),
		"advice":          paragraphsBlock(advice),
	}, true
}

func notScannedValues(l *labels, lang string, data any) (map[string]value, bool) {
	d, ok := data.(FileNotScannedData)
	if !ok {
		return nil, false
	}
	return map[string]value{
		"tenant_name": textValue(d.TenantName),
		"files":       notScannedBlock(l, lang, d.Files),
	}, true
}

func firstDownloadValues(l *labels, lang string, data any) (map[string]value, bool) {
	d, ok := data.(FirstDownloadData)
	if !ok {
		return nil, false
	}
	deletion := noticeBlock(true, l.deletionOnce, false)
	if !d.DeleteAt.IsZero() {
		deletion = noticeBlock(true, fmt.Sprintf(l.deletionScheduled, FormatDateTime(lang, d.DeleteAt)), true)
	}
	return map[string]value{
		"tenant_name":       textValue(d.TenantName),
		"download_datetime": textValue(FormatDateTime(lang, d.DownloadedAt)),
		"files":             simpleFilesBlock(lang, d.Files),
		"deletion_notice":   deletion,
	}, true
}

func quotaValues(threshold int64) func(*labels, string, any) (map[string]value, bool) {
	return func(_ *labels, lang string, data any) (map[string]value, bool) {
		d, ok := data.(QuotaAlertData)
		if !ok {
			return nil, false
		}
		return map[string]value{
			"tenant_name":       textValue(d.TenantName),
			"usage_percent":     textValue(formatPercent(lang, UsagePercent(d.UsedBytes, d.QuotaBytes))),
			"threshold_percent": textValue(formatPercent(lang, threshold)),
			"used_size":         textValue(FormatSize(lang, d.UsedBytes)),
			"quota_size":        textValue(FormatSize(lang, d.QuotaBytes)),
			"admin_link":        urlValue(d.AdminLink),
		}, true
	}
}

// diskAlertValues returns the variables of the disk_alert template from a DiskAlertData.
func diskAlertValues(_ *labels, lang string, data any) (map[string]value, bool) {
	d, ok := data.(DiskAlertData)
	if !ok {
		return nil, false
	}
	return map[string]value{
		"usage_percent":     textValue(formatPercent(lang, UsagePercent(d.UsedBytes, d.TotalBytes))),
		"threshold_percent": textValue(formatDecimalPercent(lang, d.ThresholdPercent)),
		"used_size":         textValue(FormatSize(lang, d.UsedBytes)),
		"total_size":        textValue(FormatSize(lang, d.TotalBytes)),
		"admin_link":        urlValue(d.AdminLink),
	}, true
}

// UsagePercent is the share of quota that used represents, in percent,
// rounded down, computed exactly (128-bit product, no float rounding); a
// quota of 0 or less counts as fully used (100), a negative use as none.
// A share beyond the int64 range, which no real size reaches, is capped
// at math.MaxInt64. The quota alert mails and the audit events of package
// quota share it.
func UsagePercent(used, quota int64) int64 {
	if quota <= 0 {
		return 100
	}
	hi, lo := bits.Mul64(uint64(max(used, 0)), 100)
	if hi >= uint64(quota) {
		return math.MaxInt64
	}
	q, _ := bits.Div64(hi, lo, uint64(quota))
	return int64(min(q, math.MaxInt64))
}

// formatPercent writes a percentage the way lang does: "82%" in English,
// "82 %" with a non-breaking space in French.
func formatPercent(lang string, p int64) string {
	if lang == i18n.French {
		return strconv.FormatInt(p, 10) + nbsp + "%"
	}
	return strconv.FormatInt(p, 10) + "%"
}

// formatDecimalPercent writes a percentage with at most two decimals the
// way lang does: "87.5%" in English, "87,5 %" in French.
func formatDecimalPercent(lang string, p float64) string {
	n := strconv.FormatFloat(math.Round(p*100)/100, 'f', -1, 64)
	if lang == i18n.French {
		return strings.Replace(n, ".", ",", 1) + nbsp + "%"
	}
	return n + "%"
}

// --- Blocks ------------------------------------------------------------------

// Inline styles of the blocks, shared with the default templates.
const (
	styleList     = `padding-left:20px;margin:0 0 16px;`
	styleItem     = `margin:0 0 12px;`
	styleName     = `word-break:break-all;`
	styleSmall    = `font-size:14px;`
	styleCode     = `font-family:Consolas,Menlo,monospace;word-break:break-all;`
	styleH2       = `font-size:18px;margin:24px 0 8px;`
	styleQuote    = `margin:0 0 16px;padding:8px 16px;border-left:4px solid #767676;white-space:pre-wrap;`
	styleQRImage  = `margin-top:8px;border:0;`
	qrImageWidth  = "180"
	ulOpen        = `<ul style="` + styleList + `">` + "\n"
	ulClose       = "\n</ul>"
	itemOpen      = `<li style="` + styleItem + `">`
	smallSpanOpen = `<span style="` + styleSmall + `">`
)

// esc escapes a string for HTML text or a double-quoted attribute (the only
// quoting this package and package sanitize produce): &, <, > and ". The
// apostrophe stays readable.
func esc(s string) string { return escaper.Replace(s) }

var escaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;")

// messageBlock quotes the optional free text of a sender or inviter.
func messageBlock(l *labels, msg string) value {
	if msg == "" {
		return blockValue("", "")
	}
	h := "<p>" + esc(l.messageIntro) + "</p>\n" +
		`<blockquote style="` + styleQuote + `">` + esc(msg) + "</blockquote>"
	return blockValue(trustedHTML(h), l.messageIntro+"\n\n"+quoteLines(msg))
}

// quoteLines prefixes every line of s with "> ", as mail clients quote a
// message, so that free text stands apart from the text of the service.
func quoteLines(s string) string {
	lines := strings.Split(strings.TrimRight(normalizeNewlines(s), "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight("> "+l, " ")
	}
	return strings.Join(lines, "\n")
}

// noticeBlock is a paragraph shown when on is set, in bold when strong.
func noticeBlock(on bool, text string, strong bool) value {
	if !on {
		return blockValue("", "")
	}
	h := esc(text)
	if strong {
		h = "<strong>" + h + "</strong>"
	}
	return blockValue(trustedHTML("<p>"+h+"</p>"), text)
}

// paragraphsBlock renders paragraphs, or nothing.
func paragraphsBlock(ps []string) value {
	hs := make([]string, len(ps))
	for i, p := range ps {
		hs[i] = "<p>" + esc(p) + "</p>"
	}
	return blockValue(trustedHTML(strings.Join(hs, "\n")), strings.Join(ps, "\n\n"))
}

// qrBlock shows the inline QR code of the download link (HTML only).
func qrBlock(l *labels, on bool) value {
	if !on {
		return blockValue("", "")
	}
	h := "<p>" + esc(l.qrIntro) + `<br><img src="cid:` + QRContentID + `" alt="` + esc(l.qrAlt) +
		`" width="` + qrImageWidth + `" height="` + qrImageWidth + `" style="` + styleQRImage + `"></p>`
	return blockValue(trustedHTML(h), "")
}

// recipientsBlock lists addresses.
func recipientsBlock(rs []string) value {
	hs := make([]string, len(rs))
	ts := make([]string, len(rs))
	for i, r := range rs {
		hs[i] = `<li style="` + styleName + `">` + esc(r) + "</li>"
		ts[i] = "- " + r
	}
	return listBlock(hs, ts)
}

// listBlock wraps list items, or renders nothing without item.
func listBlock(hs, ts []string) value {
	if len(hs) == 0 {
		return blockValue("", "")
	}
	return blockValue(trustedHTML(ulOpen+strings.Join(hs, "\n")+ulClose), strings.Join(ts, "\n"))
}

// fileTitle is the name and size of a file.
func fileTitle(lang string, f FileInfo) (h, t string) {
	size := FormatSize(lang, f.Size)
	return `<strong style="` + styleName + `">` + esc(f.Name) + "</strong> (" + esc(size) + ")",
		"- " + f.Name + " (" + size + ")"
}

// fileDigest is the SHA-256 line of a file.
func fileDigest(l *labels, f FileInfo) (h, t string) {
	return smallSpanOpen + esc(l.sha) + `<code style="` + styleCode + `">` + esc(f.SHA256) + "</code></span>",
		"  " + l.sha + f.SHA256
}

// filesBlock lists delivered files with their digest and antivirus status.
func filesBlock(l *labels, lang string, files []FileInfo) value {
	hs := make([]string, len(files))
	ts := make([]string, len(files))
	for i, f := range files {
		th, tt := fileTitle(lang, f)
		dh, dt := fileDigest(l, f)
		h := itemOpen + th + "<br>\n" + dh
		t := tt + "\n" + dt
		label, reason := l.statusFor(f.NotScanned)
		if label != "" {
			h += "<br>\n" + smallSpanOpen + "<strong>" + esc(label) + "</strong>" + esc(reason) + "</span>"
			t += "\n  " + label + reason
		}
		hs[i], ts[i] = h+"</li>", t
	}
	return listBlock(hs, ts)
}

// notScannedBlock lists files the antivirus could not analyze, with the
// reason.
func notScannedBlock(l *labels, lang string, files []FileInfo) value {
	hs := make([]string, len(files))
	ts := make([]string, len(files))
	for i, f := range files {
		th, tt := fileTitle(lang, f)
		dh, dt := fileDigest(l, f)
		reason := l.reasonTooLarge
		if f.NotScanned == NotScannedEncrypted {
			reason = l.reasonEncrypted
		}
		hs[i] = itemOpen + th + "<br>\n" + dh + "<br>\n" + smallSpanOpen + esc(reason) + "</span></li>"
		ts[i] = tt + "\n" + dt + "\n  " + reason
	}
	return listBlock(hs, ts)
}

// simpleFilesBlock lists files with their name and size only.
func simpleFilesBlock(lang string, files []FileInfo) value {
	hs := make([]string, len(files))
	ts := make([]string, len(files))
	for i, f := range files {
		th, tt := fileTitle(lang, f)
		hs[i], ts[i] = itemOpen+th+"</li>", tt
	}
	return listBlock(hs, ts)
}

// infectedBlock explains and lists the infected files, deleted.
func infectedBlock(l *labels, files []InfectedFile) value {
	if len(files) == 0 {
		return blockValue("", "")
	}
	hs := make([]string, len(files))
	ts := make([]string, len(files))
	for i, f := range files {
		hs[i] = itemOpen + `<strong style="` + styleName + `">` + esc(f.Name) + "</strong><br>\n" +
			smallSpanOpen + esc(l.threat) + `<code style="` + styleCode + `">` + esc(f.Signature) + "</code></span></li>"
		ts[i] = "- " + f.Name + "\n  " + l.threat + f.Signature
	}
	list := listBlock(hs, ts)
	return blockValue("<p>"+trustedHTML(esc(l.infectedIntro))+"</p>\n"+list.html, l.infectedIntro+"\n\n"+list.text)
}

// withheldProblemsBlock explains and lists the withheld files in the
// file_problems mail.
func withheldProblemsBlock(l *labels, lang string, files []FileInfo) value {
	if len(files) == 0 {
		return blockValue("", "")
	}
	list := simpleFilesBlock(lang, files)
	return blockValue("<p>"+trustedHTML(esc(l.withheldIntro))+"</p>\n"+list.html, l.withheldIntro+"\n\n"+list.text)
}

// withheldConfirmationBlock lists the withheld files in the confirmation
// sent to the sender.
func withheldConfirmationBlock(l *labels, lang string, files []FileInfo) value {
	if len(files) == 0 {
		return blockValue("", "")
	}
	list := simpleFilesBlock(lang, files)
	h := `<h2 style="` + styleH2 + `">` + esc(l.withheldHeading) + "</h2>\n" + string(list.html) +
		"\n<p>" + esc(l.withheldNote) + "</p>"
	return blockValue(trustedHTML(h), l.withheldHeading+l.colon+"\n"+list.text+"\n\n"+l.withheldNote)
}

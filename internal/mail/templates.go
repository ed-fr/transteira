package mail

import (
	"bytes"
	"embed"
	"fmt"
	htmltemplate "html/template"
	"io/fs"
	"path"
	"sort"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/ed-fr/transteira/internal/i18n"
)

// Names of the built-in templates.
const (
	// TemplateVerificationCode is the e-mail verification code mail
	// (CLAUDE.md section 7); data: [VerificationCodeData].
	TemplateVerificationCode = "verification_code"
	// TemplateInvitation is the external invitation mail (CLAUDE.md
	// section 9); data: [InvitationData].
	TemplateInvitation = "invitation"
	// TemplateTransferNotification is the mail sent to each recipient of an
	// available transfer (CLAUDE.md section 12.2); data:
	// [TransferNotificationData].
	TemplateTransferNotification = "transfer_notification"
	// TemplateTransferConfirmation is the confirmation sent to the sender of
	// an available transfer; data: [TransferConfirmationData].
	TemplateTransferConfirmation = "transfer_confirmation"
	// TemplateFileProblems warns the sender about the files that were not
	// delivered: infected files, deleted (CLAUDE.md section 11), and files
	// that could not be analyzed, withheld under fail-closed; data:
	// [FileProblemsData].
	TemplateFileProblems = "file_problems"
	// TemplateFileNotScanned warns the sender that the antivirus could not
	// analyze files (too large or too complex, or encrypted archives),
	// delivered anyway;
	// data: [FileNotScannedData].
	TemplateFileNotScanned = "file_not_scanned"
	// TemplateFirstDownload tells the sender that the transfer has been
	// downloaded in full for the first time (CLAUDE.md section 12.2), sent
	// once per transfer; data: [FirstDownloadData].
	TemplateFirstDownload = "first_download"
)

// QRContentID is the Content-ID of the QR code of the download link, the
// inline part referenced by the transfer_notification template as
// <img src="cid:qr@transteira"> (threat T-87: no remote image). It is written
// literally in the templates, since html/template neutralizes "cid:" URLs
// built from data.
const QRContentID = "qr@transteira"

// VerificationCodeData is the data of [TemplateVerificationCode].
type VerificationCodeData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Code is the one-time code (6 digits). It is never logged.
	Code string
	// ValidityMinutes is the lifetime of the code (15).
	ValidityMinutes int
}

// InvitationData is the data of [TemplateInvitation].
type InvitationData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// InviterEmail is the verified address of the internal user who invites.
	InviterEmail string
	// Message is the optional free text of the inviter, as plain text. It is
	// HTML-escaped and never turned into links by the templates; the caller
	// limits its length (threat T-18).
	Message string
	// Link is the absolute invitation URL, built from the registered FQDN of
	// the tenant, never from the request Host (threat T-03).
	Link string
	// ExpiresAt is when the unused invitation expires.
	ExpiresAt time.Time
}

// NotScannedReason is why the antivirus could not analyze a delivered
// file. The templates compare it with the constant values below.
type NotScannedReason string

// Reasons for a file not to be scanned.
const (
	// NotScannedTooLarge is a file above the antivirus limits: too large,
	// or too complex (number of files, recursion depth) to be fully
	// analyzed.
	NotScannedTooLarge NotScannedReason = "too_large"
	// NotScannedEncrypted is an encrypted archive, whose content the
	// antivirus cannot read.
	NotScannedEncrypted NotScannedReason = "encrypted"
)

// FileInfo describes one file of a transfer in the transfer mails.
type FileInfo struct {
	// Name is the original file name, as plain text: the templates escape it
	// and the caller removes control and hidden characters.
	Name string
	// Size is the size in bytes, formatted by the templates ("size").
	Size int64
	// SHA256 is the hexadecimal SHA-256 digest of the clear content.
	SHA256 string
	// NotScanned is why the antivirus could not analyze the delivered file,
	// "" when it was scanned.
	NotScanned NotScannedReason
}

// TransferNotificationData is the data of [TemplateTransferNotification].
type TransferNotificationData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// SenderEmail is the verified address of the sender.
	SenderEmail string
	// Message is the optional free text of the sender, as plain text. It is
	// HTML-escaped and never turned into links by the templates (T-81).
	Message string
	// Link is the absolute download URL, built from the registered FQDN of
	// the tenant. It is the only link of the mail.
	Link string
	// Files lists the files available for download.
	Files []FileInfo
	// ExpiresAt is when the transfer expires.
	ExpiresAt time.Time
	// PasswordRequired tells the recipient that a password protects the
	// transfer and will come through another channel (T-88).
	PasswordRequired bool
	// QR shows the QR code of Link, an inline part of Content-ID
	// [QRContentID] that the caller attaches.
	QR bool
}

// TransferConfirmationData is the data of [TemplateTransferConfirmation].
type TransferConfirmationData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Link is the absolute download URL.
	Link string
	// Recipients lists the addresses the transfer was sent to.
	Recipients []string
	// Files lists the files available for download.
	Files []FileInfo
	// ExpiresAt is when the transfer expires.
	ExpiresAt time.Time
	// PasswordRequired reminds the sender to give the password to the
	// recipients through another channel.
	PasswordRequired bool
	// Withheld lists the files that could not be analyzed and are withheld
	// (never downloadable); SHA256 is not shown.
	Withheld []FileInfo
}

// InfectedFile is a file deleted because the antivirus found it infected.
type InfectedFile struct {
	// Name is the original file name, as plain text.
	Name string
	// Signature is the name of the detected threat, as reported by the
	// antivirus (plain text, bounded by the caller).
	Signature string
}

// FileProblemsData is the data of [TemplateFileProblems]. At least one of
// Infected and Withheld is expected; the subject names the infection when
// there is one.
type FileProblemsData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Infected lists the infected files, deleted.
	Infected []InfectedFile
	// Withheld lists the files that could not be analyzed, withheld for
	// safety (name and size only).
	Withheld []FileInfo
	// Rejected is set when no file could be delivered: the transfer was not
	// sent and no recipient was notified. Otherwise the remaining files were
	// sent.
	Rejected bool
}

// FileNotScannedData is the data of [TemplateFileNotScanned]: every file
// listed has a NotScanned reason.
type FileNotScannedData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Files lists the files the antivirus could not analyze.
	Files []FileInfo
}

// FirstDownloadData is the data of [TemplateFirstDownload]. It names no
// recipient: in V1 a transfer has a single download link, so the download
// cannot be attributed to one recipient.
type FirstDownloadData struct {
	// TenantName is the display name of the entity.
	TenantName string
	// Files lists the files of the transfer (name and size; SHA256 and
	// NotScanned are not shown).
	Files []FileInfo
	// DownloadedAt is when the transfer was first downloaded in full,
	// formatted by the templates ("datetime").
	DownloadedAt time.Time
	// DeleteAt is when the transfer is erased, formatted like DownloadedAt,
	// when the sender asked for deletion after the first download; zero
	// when the transfer stays until its expiry.
	DeleteAt time.Time
}

//go:embed templates
var defaultTemplateFS embed.FS

// Template file layout: <lang>/<name>.<part>.tmpl, part being subject, text
// or html. subject and text are mandatory, html is optional.
const (
	partSubject = "subject"
	partText    = "text"
	partHTML    = "html"
	tmplSuffix  = ".tmpl"
)

// templateSet is one template in one language.
type templateSet struct {
	subject *texttemplate.Template
	text    *texttemplate.Template
	html    *htmltemplate.Template // nil when the template has no HTML body
}

// Templates renders mail templates in the supported languages. Templates
// are parsed once, at construction. A Templates is read-only afterwards and
// safe for concurrent use.
//
// The template engine is restricted (threat T-82): besides the builtins of
// text/template and html/template, templates only get "t" (catalog lookup
// in the template language), "date" (locale date), "datetime" (locale date
// and time, UTC; see [FormatDateTime]), "size" (locale binary size; see
// [FormatSize]) and "quote" (prefixes every line with "> "). Later steps add
// per-tenant templates on top of the defaults, with the same restricted
// function set.
type Templates struct {
	sets map[string]map[string]*templateSet // name -> lang -> set
}

// defaultTemplates is the set embedded in the binary.
var defaultTemplates = mustDefaultTemplates()

// mustDefaultTemplates parses the embedded templates; a broken embedded
// template is a build defect, caught by the tests.
func mustDefaultTemplates() *Templates {
	sub, _ := fs.Sub(defaultTemplateFS, "templates") // constant, valid path
	t, err := NewTemplates(sub, i18n.DefaultCatalog())
	if err != nil {
		panic(err)
	}
	return t
}

// DefaultTemplates returns the built-in French and English templates.
func DefaultTemplates() *Templates {
	return defaultTemplates
}

// Render renders a built-in template; see [Templates.Render].
func Render(name, lang string, data any) (Message, error) {
	return defaultTemplates.Render(name, lang, data)
}

// funcs returns the restricted function set of templates written in lang.
func funcs(lang string, catalog *i18n.Catalog) map[string]any {
	return map[string]any{
		"t":        func(key string, pairs ...string) string { return catalog.T(lang, key, pairs...) },
		"date":     func(t time.Time) string { return i18n.FormatDate(lang, t) },
		"datetime": func(t time.Time) string { return FormatDateTime(lang, t) },
		"size":     func(n int64) string { return FormatSize(lang, n) },
		"quote":    quoteLines,
	}
}

// quoteLines prefixes every line of s with "> ", as mail clients quote a
// message, so that free text stands apart from the text of the service.
func quoteLines(s string) string {
	lines := strings.Split(strings.ReplaceAll(strings.TrimRight(s, "\r\n"), "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight("> "+l, " ")
	}
	return strings.Join(lines, "\n")
}

// NewTemplates parses every <lang>/<name>.<part>.tmpl file of fsys. Unknown
// languages, unknown parts and files outside that layout are errors, as is a
// template without subject or text part. Strings looked up with "t" come from
// catalog.
func NewTemplates(fsys fs.FS, catalog *i18n.Catalog) (*Templates, error) {
	t := &Templates{sets: map[string]map[string]*templateSet{}}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		return t.parseFile(fsys, p, catalog)
	})
	if err != nil {
		return nil, fmt.Errorf("mail: templates: %w", err)
	}
	for name, langs := range t.sets {
		for lang, set := range langs {
			if set.subject == nil || set.text == nil {
				return nil, fmt.Errorf("mail: templates: %s/%s lacks a subject or text part", lang, name)
			}
		}
	}
	return t, nil
}

// parseFile parses one template file into its set.
func (t *Templates) parseFile(fsys fs.FS, p string, catalog *i18n.Catalog) error {
	lang, file := path.Split(p)
	lang = strings.TrimSuffix(lang, "/")
	if !i18n.IsSupported(lang) || !strings.HasSuffix(file, tmplSuffix) {
		return fmt.Errorf("unexpected file %q", p)
	}
	name, part, ok := strings.Cut(strings.TrimSuffix(file, tmplSuffix), ".")
	if !ok || !isTemplateName(name) {
		return fmt.Errorf("unexpected file %q", p)
	}
	raw, err := fs.ReadFile(fsys, p)
	if err != nil {
		return err
	}
	if t.sets[name] == nil {
		t.sets[name] = map[string]*templateSet{}
	}
	set := t.sets[name][lang]
	if set == nil {
		set = &templateSet{}
		t.sets[name][lang] = set
	}
	fm := funcs(lang, catalog)
	switch part {
	case partSubject, partText:
		tt, err := texttemplate.New(p).Option("missingkey=error").Funcs(fm).Parse(string(raw))
		if err != nil {
			return err
		}
		if part == partSubject {
			set.subject = tt
		} else {
			set.text = tt
		}
	case partHTML:
		ht, err := htmltemplate.New(p).Option("missingkey=error").Funcs(fm).Parse(string(raw))
		if err != nil {
			return err
		}
		set.html = ht
	default:
		return fmt.Errorf("unexpected file %q", p)
	}
	return nil
}

// isTemplateName accepts [a-z_]+.
func isTemplateName(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if (s[i] < 'a' || s[i] > 'z') && s[i] != '_' {
			return false
		}
	}
	return true
}

// Names returns the sorted template names.
func (t *Templates) Names() []string {
	names := make([]string, 0, len(t.sets))
	for n := range t.sets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Render renders template name in lang with data, falling back to
// [i18n.Default] when the template does not exist in lang. The returned
// [Message] has Subject (whitespace collapsed to one line), Text, HTML and
// Language (the language actually used) set; the caller sets To and any
// inline part. Errors wrap [ErrUnknownTemplate] or report a template
// execution failure (for example a missing field).
func (t *Templates) Render(name, lang string, data any) (Message, error) {
	langs, ok := t.sets[name]
	if !ok {
		return Message{}, fmt.Errorf("%w: %q", ErrUnknownTemplate, name)
	}
	set, ok := langs[lang]
	if !ok {
		lang = i18n.Default
		if set, ok = langs[lang]; !ok {
			return Message{}, fmt.Errorf("%w: %q has no %q version", ErrUnknownTemplate, name, lang)
		}
	}
	var subject, text, html bytes.Buffer
	if err := set.subject.Execute(&subject, data); err != nil {
		return Message{}, fmt.Errorf("mail: render %s: %w", name, err)
	}
	if err := set.text.Execute(&text, data); err != nil {
		return Message{}, fmt.Errorf("mail: render %s: %w", name, err)
	}
	if set.html != nil {
		if err := set.html.Execute(&html, data); err != nil {
			return Message{}, fmt.Errorf("mail: render %s: %w", name, err)
		}
	}
	return Message{
		// strings.Fields also drops any CR or LF a value may have carried.
		Subject:  strings.Join(strings.Fields(subject.String()), " "),
		Text:     text.String(),
		HTML:     html.String(),
		Language: lang,
	}, nil
}

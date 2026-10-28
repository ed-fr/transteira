package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// Limits applied to a [TransferView].
const (
	// MaxRecipients is a backstop on the number of recipient mails built for
	// one transfer (threat T-84). The deposit already enforces the
	// configured limit (TT_MAX_RECIPIENTS, at most 100).
	MaxRecipients = 100
	// maxNameRunes bounds a file name in the mails.
	maxNameRunes = 255
	// maxSignatureRunes bounds a threat name in the mails.
	maxSignatureRunes = 200
	// maxLinkLen bounds the download link.
	maxLinkLen = 2048
	// sha256HexLen is the length of a hexadecimal SHA-256 digest.
	sha256HexLen = 64
	// qrFilename is the file name of the QR code inline part.
	qrFilename = "qr.png"
)

// Errors of the notifier. The others wrap a store, vault, QR or template
// failure.
var (
	// ErrNoSMTP is returned when the tenant has no SMTP settings: no mail
	// can be sent for it.
	ErrNoSMTP = errors.New("notify: the tenant has no SMTP settings")
	// ErrInvalidTransfer is returned when the view of a transfer is not
	// usable: invalid address, digest or scan result, too many recipients,
	// or no file for the mail asked.
	ErrInvalidTransfer = errors.New("notify: invalid transfer view")
	// ErrInvalidLink is returned for a download link that is not an
	// absolute http or https URL.
	ErrInvalidLink = errors.New("notify: invalid download link")
	// ErrTransferExpired is returned when a download mail is asked for a
	// transfer already expired: its link would be dead.
	ErrTransferExpired = errors.New("notify: transfer expired")
)

// ScanResult is the antivirus outcome of one file, as the mails need it.
// The zero value is invalid, so that a file whose result was not filled is
// refused rather than presented as scanned.
type ScanResult int

// Scan results.
const (
	// ScanClean is a file scanned and found clean.
	ScanClean ScanResult = iota + 1
	// ScanTooLarge is a file above the antivirus limits (size, or
	// complexity: number of files, recursion depth): delivered, flagged as
	// not scanned (CLAUDE.md section 11).
	ScanTooLarge
	// ScanInfected is a file found infected and deleted: never delivered.
	ScanInfected
	// ScanWithheld is a file that could not be analyzed after the retries:
	// withheld under fail-closed, never delivered.
	ScanWithheld
	// ScanEncrypted is an encrypted archive the antivirus could not look
	// into: delivered, flagged as not analyzed.
	ScanEncrypted
)

// Delivered reports whether a file with this result is downloadable.
//
// It matches store.ScanStatus.Deliverable: clean, too large or encrypted.
func (r ScanResult) Delivered() bool {
	return r == ScanClean || r == ScanTooLarge || r == ScanEncrypted
}

// notScanned returns why the antivirus could not analyze a delivered file,
// "" when it was scanned.
func (r ScanResult) notScanned() mail.NotScannedReason {
	switch r {
	case ScanTooLarge:
		return mail.NotScannedTooLarge
	case ScanEncrypted:
		return mail.NotScannedEncrypted
	}
	return ""
}

// FileView is one file of a [TransferView].
type FileView struct {
	// Name is the original file name.
	Name string
	// Size is the size in bytes.
	Size int64
	// SHA256 is the hexadecimal SHA-256 digest of the clear content
	// (mandatory for a delivered file).
	SHA256 string
	// Scan is the antivirus outcome.
	Scan ScanResult
	// Signature is the threat name reported for an infected file.
	Signature string
}

// TransferView is what the mails show of a transfer. It is a plain struct
// filled by the caller, so that this package depends neither on the scan
// package nor on the transfer row layout.
type TransferView struct {
	// ID identifies the transfer in logs; it is never shown in mails.
	ID string
	// Language is the language of the mails, "" (or an unsupported value)
	// for the tenant default.
	Language string
	// SenderEmail is the verified address of the sender.
	SenderEmail string
	// Recipients lists the recipient addresses.
	Recipients []string
	// Message is the optional free text of the sender, plain text.
	Message string
	// ExpiresAt is when the transfer expires.
	ExpiresAt time.Time
	// PasswordProtected is set when a password protects the download.
	PasswordProtected bool
	// Files lists every file of the transfer, infected and withheld ones
	// included.
	Files []FileView
	// ConfidentialityLabels are the labels, by language, of the
	// confidentiality level snapshotted on the transfer; nil without level.
	// The notification and confirmation mails show the label in their
	// language.
	ConfidentialityLabels map[string]string
}

// Vault unseals the wrapped secrets of a tenant. *masterkey.Vault
// implements it.
type Vault interface {
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
}

// SMTPSource reads the SMTP settings of a tenant; it returns an error
// wrapping store.ErrNotFound when there are none. *store.SMTPSettings
// implements it.
type SMTPSource interface {
	Get(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error)
}

// Renderer renders a mail template of a tenant, with its customization
// when lookup returns one. *mail.Templates implements it.
type Renderer interface {
	RenderFor(ctx context.Context, lookup mail.OverrideLookup, tenantID, name, lang string, data any) (mail.Message, error)
}

// TemplateStore reads the customized mail templates of a tenant; it returns
// an error wrapping store.ErrNotFound when the tenant uses the default
// template. *store.TenantEmailTemplates implements it.
type TemplateStore interface {
	Get(ctx context.Context, tid tenant.ID, key, lang string) (store.EmailTemplate, error)
}

// StoreOverrides adapts the customized templates of src to a
// [mail.OverrideLookup]: a template that is not customized (store.ErrNotFound)
// gives no override, any other failure is returned. The template name is
// accepted in the internal form (verification_code) and read under its API
// key (verification-code).
func StoreOverrides(src TemplateStore) mail.OverrideLookup {
	return func(ctx context.Context, tenantID, name, lang string) (*mail.TemplateSource, error) {
		tid, err := tenant.ParseID(tenantID)
		if err != nil {
			return nil, fmt.Errorf("notify: template lookup: %w", err)
		}
		t, err := src.Get(ctx, tid, strings.ReplaceAll(name, "_", "-"), lang)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil, nil // no customization: the default template applies
		case err != nil:
			return nil, fmt.Errorf("notify: template lookup: %w", err)
		}
		return &mail.TemplateSource{Subject: t.Subject, HTML: t.BodyHTML, Text: t.BodyText}, nil
	}
}

// NoOverrides is a [mail.OverrideLookup] for which every tenant uses the
// default templates.
func NoOverrides(context.Context, string, string, string) (*mail.TemplateSource, error) {
	return nil, nil // no customization: the default template applies
}

// TolerantOverrides wraps lookup so that a lookup failure never stops a
// mail: the failure is logged at WARN level, with the tenant ID and the
// template name (never an address), and no override is returned, so the
// default template is used. A customized template only changes the
// wording; the default carries the same mandatory content (link, code,
// files), and losing the mail (a scan notification is not retried, a
// verification code would fail the request) is worse than sending it with
// the default wording. A nil lookup is [NoOverrides].
func TolerantOverrides(lookup mail.OverrideLookup, logger *slog.Logger) mail.OverrideLookup {
	if lookup == nil {
		return NoOverrides
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return func(ctx context.Context, tenantID, name, lang string) (*mail.TemplateSource, error) {
		src, err := lookup(ctx, tenantID, name, lang)
		if err != nil {
			logger.WarnContext(ctx, "customized mail template unreadable, the default template is used",
				slog.String("tenant", tenantID), slog.String("template", name), slog.String("language", lang),
				slog.Any("error", err))
			return nil, nil // the default template applies
		}
		return src, nil
	}
}

// Options tunes a [Notifier].
type Options struct {
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Logger receives one debug line per batch of mails built, without any
	// address, and the template lookup failures (nil discards).
	Logger *slog.Logger
	// Overrides returns the customized templates of the tenants, usually
	// StoreOverrides(db.TenantEmailTemplates()); nil uses the default
	// templates for every tenant. Its failures are tolerated (see
	// [TolerantOverrides]).
	Overrides mail.OverrideLookup
}

// Notifier builds the transfer notification mails (CLAUDE.md section 12.2)
// as [mail.Job] values, ready for the mail queue: the caller enqueues them
// and handles a full queue or an open circuit. A Notifier is safe for
// concurrent use.
//
// Each build reads the SMTP settings of the tenant and unseals its password
// with the vault; the clear-text bytes are wiped once copied into the job
// settings, which only live in memory (see [mail.Job]).
type Notifier struct {
	vault     Vault
	smtp      SMTPSource
	templates Renderer
	overrides mail.OverrideLookup
	now       func() time.Time
	logger    *slog.Logger
}

// New returns a notifier reading SMTP settings from smtp, unsealing their
// passwords with vault and rendering with templates
// (mail.DefaultTemplates() when nil).
func New(vault Vault, smtp SMTPSource, templates Renderer, opts Options) *Notifier {
	if templates == nil {
		templates = mail.DefaultTemplates()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &Notifier{
		vault: vault, smtp: smtp, templates: templates, overrides: TolerantOverrides(opts.Overrides, opts.Logger),
		now: opts.Now, logger: opts.Logger,
	}
}

// RecipientJobs builds the transfer_notification mail of every recipient:
// one job per recipient, whose message names only that recipient, so that
// no recipient learns the others. Each mail carries the download link, the
// delivered files with their size, SHA-256 digest and "not scanned" flag
// (too large or too complex, or encrypted archive), the expiry, the password
// notice when the transfer is protected, and the QR code of link as an
// inline PNG. Duplicate recipients (ignoring case) get a single mail.
func (n *Notifier) RecipientJobs(ctx context.Context, t *tenant.Tenant, tr TransferView, link string) ([]mail.Job, error) {
	v, err := n.prepareDownload(tr, link)
	if err != nil {
		return nil, err
	}
	recipients, err := normalizeRecipients(tr.Recipients)
	if err != nil {
		return nil, err
	}
	png, err := QRPNG(link)
	if err != nil {
		return nil, err
	}
	data := mail.TransferNotificationData{
		TenantName: t.Name, SenderEmail: v.sender, Message: v.message, Link: link,
		Files: v.files, ExpiresAt: tr.ExpiresAt, PasswordRequired: tr.PasswordProtected, QR: true,
		ConfidentialityLabel: n.levelLabel(t, tr),
	}
	msg, err := n.render(ctx, t, tr, mail.TemplateTransferNotification, data)
	if err != nil {
		return nil, err
	}
	settings, err := n.settings(ctx, t)
	if err != nil {
		return nil, err
	}
	qrPart := mail.InlinePart{ContentID: mail.QRContentID, ContentType: "image/png", Filename: qrFilename, Data: png}
	jobs := make([]mail.Job, 0, len(recipients))
	for _, r := range recipients {
		m := msg
		m.To = []string{r}
		m.Inline = []mail.InlinePart{qrPart}
		jobs = append(jobs, n.job(t, mail.TemplateTransferNotification, settings, m))
	}
	n.logBuilt(ctx, t, tr, mail.TemplateTransferNotification, len(jobs))
	return jobs, nil
}

// SenderConfirmation builds the transfer_confirmation mail to the sender:
// the download link, the recipients, the delivered files with their SHA-256
// digest, the expiry, and the withheld files with a short explanation.
func (n *Notifier) SenderConfirmation(ctx context.Context, t *tenant.Tenant, tr TransferView, link string) (mail.Job, error) {
	v, err := n.prepareDownload(tr, link)
	if err != nil {
		return mail.Job{}, err
	}
	recipients, err := normalizeRecipients(tr.Recipients)
	if err != nil {
		return mail.Job{}, err
	}
	data := mail.TransferConfirmationData{
		TenantName: t.Name, Link: link, Recipients: recipients, Files: v.files,
		ExpiresAt: tr.ExpiresAt, PasswordRequired: tr.PasswordProtected, Withheld: withheldFiles(tr.Files),
		ConfidentialityLabel: n.levelLabel(t, tr),
	}
	return n.senderJob(ctx, t, tr, v.sender, mail.TemplateTransferConfirmation, data)
}

// FileProblems builds the file_problems mail to the sender, about the
// files that were not delivered: the infected files with their threat names
// (deleted), the files that could not be analyzed (withheld), and whether
// the transfer was not sent at all (no file delivered) or the remaining
// files were sent. A single mail covers both kinds, so that a transfer
// rejected for mixed reasons states it once. It fails with
// ErrInvalidTransfer when every file was delivered.
func (n *Notifier) FileProblems(ctx context.Context, t *tenant.Tenant, tr TransferView) (mail.Job, error) {
	sender, err := mail.ParseAddress(tr.SenderEmail)
	if err != nil {
		return mail.Job{}, fmt.Errorf("%w: sender: %w", ErrInvalidTransfer, err)
	}
	if err := checkScans(tr.Files); err != nil {
		return mail.Job{}, err
	}
	data := mail.FileProblemsData{TenantName: t.Name, Rejected: true, Withheld: withheldFiles(tr.Files)}
	for _, f := range tr.Files {
		switch {
		case f.Scan.Delivered():
			data.Rejected = false
		case f.Scan == ScanInfected:
			data.Infected = append(data.Infected, mail.InfectedFile{
				Name:      oneLine(f.Name, maxNameRunes),
				Signature: oneLine(f.Signature, maxSignatureRunes),
			})
		}
	}
	if len(data.Infected) == 0 && len(data.Withheld) == 0 {
		return mail.Job{}, fmt.Errorf("%w: no infected or withheld file", ErrInvalidTransfer)
	}
	return n.senderJob(ctx, t, tr, sender, mail.TemplateFileProblems, data)
}

// FileNotScanned builds the file_not_scanned mail to the sender, listing the
// delivered files the antivirus could not analyze, each with its reason (too
// large, or encrypted archive). It fails with ErrInvalidTransfer when there
// is none.
func (n *Notifier) FileNotScanned(ctx context.Context, t *tenant.Tenant, tr TransferView) (mail.Job, error) {
	sender, err := mail.ParseAddress(tr.SenderEmail)
	if err != nil {
		return mail.Job{}, fmt.Errorf("%w: sender: %w", ErrInvalidTransfer, err)
	}
	files, err := deliveredFiles(tr.Files)
	if err != nil {
		return mail.Job{}, err
	}
	var notScanned []mail.FileInfo
	for _, f := range files {
		if f.NotScanned != "" {
			notScanned = append(notScanned, f)
		}
	}
	if len(notScanned) == 0 {
		return mail.Job{}, fmt.Errorf("%w: no file left unscanned", ErrInvalidTransfer)
	}
	data := mail.FileNotScannedData{TenantName: t.Name, Files: notScanned}
	return n.senderJob(ctx, t, tr, sender, mail.TemplateFileNotScanned, data)
}

// FirstDownload builds the first_download mail to the sender: the transfer
// was downloaded in full for the first time at at (CLAUDE.md section 12.2,
// sent once per transfer; the caller guarantees the once). It lists the
// delivered files and, when deleteAt is set (deletion after the first
// download), tells when the transfer is erased; deleteAt is zero when the
// transfer stays until its expiry. No recipient is named: in V1 the single
// download link of a transfer does not identify who downloaded. It fails
// with ErrInvalidTransfer for an invalid sender, a zero time, a deletion
// time before at or a transfer without a delivered file.
func (n *Notifier) FirstDownload(ctx context.Context, t *tenant.Tenant, tr TransferView, at, deleteAt time.Time) (mail.Job, error) {
	sender, err := mail.ParseAddress(tr.SenderEmail)
	if err != nil {
		return mail.Job{}, fmt.Errorf("%w: sender: %w", ErrInvalidTransfer, err)
	}
	if at.IsZero() || (!deleteAt.IsZero() && deleteAt.Before(at)) {
		return mail.Job{}, fmt.Errorf("%w: first download or deletion time", ErrInvalidTransfer)
	}
	files, err := deliveredFiles(tr.Files)
	if err != nil {
		return mail.Job{}, err
	}
	if len(files) == 0 {
		return mail.Job{}, fmt.Errorf("%w: no delivered file", ErrInvalidTransfer)
	}
	data := mail.FirstDownloadData{TenantName: t.Name, Files: files, DownloadedAt: at, DeleteAt: deleteAt}
	return n.senderJob(ctx, t, tr, sender, mail.TemplateFirstDownload, data)
}

// downloadView is the validated part of a transfer shared by the download
// mails.
type downloadView struct {
	sender  string
	message string
	files   []mail.FileInfo
}

// prepareDownload validates what the download mails need: an unexpired
// transfer, a valid link and sender, and at least one delivered file.
func (n *Notifier) prepareDownload(tr TransferView, link string) (downloadView, error) {
	if !tr.ExpiresAt.After(n.now()) {
		return downloadView{}, ErrTransferExpired
	}
	if err := checkLink(link); err != nil {
		return downloadView{}, err
	}
	sender, err := mail.ParseAddress(tr.SenderEmail)
	if err != nil {
		return downloadView{}, fmt.Errorf("%w: sender: %w", ErrInvalidTransfer, err)
	}
	files, err := deliveredFiles(tr.Files)
	if err != nil {
		return downloadView{}, err
	}
	if len(files) == 0 {
		return downloadView{}, fmt.Errorf("%w: no delivered file", ErrInvalidTransfer)
	}
	msg := textsafe.SanitizeMessage(strings.ToValidUTF8(tr.Message, "\uFFFD"))
	return downloadView{sender: sender, message: msg, files: files}, nil
}

// senderJob renders a mail to the sender and wraps it in a job.
func (n *Notifier) senderJob(ctx context.Context, t *tenant.Tenant, tr TransferView, sender, name string, data any) (mail.Job, error) {
	msg, err := n.render(ctx, t, tr, name, data)
	if err != nil {
		return mail.Job{}, err
	}
	settings, err := n.settings(ctx, t)
	if err != nil {
		return mail.Job{}, err
	}
	msg.To = []string{sender}
	n.logBuilt(ctx, t, tr, name, 1)
	return n.job(t, name, settings, msg), nil
}

// render renders template name of tenant t in the language of tr, with the
// customization of the tenant when there is one.
func (n *Notifier) render(ctx context.Context, t *tenant.Tenant, tr TransferView, name string, data any) (mail.Message, error) {
	msg, err := n.templates.RenderFor(ctx, n.overrides, t.ID.String(), name, n.language(t, tr), data)
	if err != nil {
		return mail.Message{}, fmt.Errorf("notify: render %s: %w", name, err)
	}
	return msg, nil
}

// job assembles a mail job of tenant t.
func (*Notifier) job(t *tenant.Tenant, name string, s mail.Settings, m mail.Message) mail.Job {
	return mail.Job{TenantID: t.ID.String(), Template: name, Settings: s, Message: m}
}

// language returns the language of the transfer, else the tenant default.
// Rendering falls back to i18n.Default when neither is supported.
func (*Notifier) language(t *tenant.Tenant, tr TransferView) string {
	if i18n.IsSupported(tr.Language) {
		return tr.Language
	}
	return t.DefaultLanguage
}

// levelLabel returns the label of the confidentiality level of tr in the
// language of its mails (see language), else in the default language of
// the templates, else "" (no level, or no label in either language: the
// mail then shows no level rather than a label in another language). The
// label is reduced to one line of at most maxNameRunes characters.
func (n *Notifier) levelLabel(t *tenant.Tenant, tr TransferView) string {
	l, ok := tr.ConfidentialityLabels[n.language(t, tr)]
	if !ok {
		l = tr.ConfidentialityLabels[i18n.Default]
	}
	return oneLine(l, maxNameRunes)
}

// settings loads the SMTP settings of t and unseals their password, wiping
// the clear-text bytes once copied.
func (n *Notifier) settings(ctx context.Context, t *tenant.Tenant) (mail.Settings, error) {
	cfg, err := n.smtp.Get(ctx, t.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return mail.Settings{}, ErrNoSMTP
	case err != nil:
		return mail.Settings{}, fmt.Errorf("notify: read smtp settings: %w", err)
	}
	s := mail.Settings{
		Host: cfg.Host, Port: cfg.Port, Security: mail.Security(cfg.Security), Username: cfg.Username,
		FromAddress: cfg.FromAddress, FromName: cfg.FromName,
	}
	if cfg.PasswordKeyID != "" {
		pw, err := n.vault.Open(ctx, t.ID, crypto.PurposeSecret, cfg.PasswordKeyID)
		if err != nil {
			return mail.Settings{}, fmt.Errorf("notify: unseal smtp password: %w", err)
		}
		s.Password = string(pw)
		clear(pw)
	}
	return s, nil
}

// logBuilt logs a batch of built mails, without any address.
func (n *Notifier) logBuilt(ctx context.Context, t *tenant.Tenant, tr TransferView, name string, count int) {
	n.logger.LogAttrs(ctx, slog.LevelDebug, "notification mails built",
		slog.String("tenant", t.ID.String()),
		slog.String("transfer", tr.ID),
		slog.String("template", name),
		slog.Int("count", count))
}

// checkLink accepts an absolute http or https URL with a host, no user
// information, no whitespace or control character, of bounded length.
func checkLink(link string) error {
	if link == "" || len(link) > maxLinkLen || !utf8.ValidString(link) ||
		strings.ContainsFunc(link, func(r rune) bool { return r <= ' ' || r == 0x7f || textsafe.IsHidden(r) }) {
		return ErrInvalidLink
	}
	u, err := url.Parse(link)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Opaque != "" {
		return ErrInvalidLink
	}
	return nil
}

// normalizeRecipients validates and normalizes the recipient addresses and
// drops duplicates, ignoring case.
func normalizeRecipients(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("%w: no recipient", ErrInvalidTransfer)
	}
	if len(in) > MaxRecipients {
		return nil, fmt.Errorf("%w: more than %d recipients", ErrInvalidTransfer, MaxRecipients)
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, a := range in {
		addr, err := mail.ParseAddress(a)
		if err != nil {
			return nil, fmt.Errorf("%w: recipient: %w", ErrInvalidTransfer, err)
		}
		key := strings.ToLower(addr)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, addr)
	}
	return out, nil
}

// checkScans refuses a file without a known scan result.
func checkScans(files []FileView) error {
	for _, f := range files {
		if f.Scan < ScanClean || f.Scan > ScanEncrypted {
			return fmt.Errorf("%w: file without a scan result", ErrInvalidTransfer)
		}
	}
	return nil
}

// deliveredFiles returns the downloadable files, as the templates show
// them: sanitized names and lowercase digests.
func deliveredFiles(files []FileView) ([]mail.FileInfo, error) {
	if err := checkScans(files); err != nil {
		return nil, err
	}
	var out []mail.FileInfo
	for _, f := range files {
		if !f.Scan.Delivered() {
			continue
		}
		sum := strings.ToLower(f.SHA256)
		if !isHex(sum, sha256HexLen) || f.Size < 0 {
			return nil, fmt.Errorf("%w: file digest or size", ErrInvalidTransfer)
		}
		out = append(out, mail.FileInfo{
			Name: oneLine(f.Name, maxNameRunes), Size: f.Size, SHA256: sum, NotScanned: f.Scan.notScanned(),
		})
	}
	return out, nil
}

// withheldFiles returns the withheld files, name and size only. The scan
// results are checked by the caller.
func withheldFiles(files []FileView) []mail.FileInfo {
	var out []mail.FileInfo
	for _, f := range files {
		if f.Scan == ScanWithheld {
			out = append(out, mail.FileInfo{Name: oneLine(f.Name, maxNameRunes), Size: max(f.Size, 0)})
		}
	}
	return out
}

// isHex reports whether s is n lowercase hexadecimal digits.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// oneLine makes s safe for a single line of a mail: invalid UTF-8 is
// replaced, line breaks and tabs become spaces, the other hidden characters
// (controls, bidirectional and zero-width characters...) are removed, and
// the result is cut to max runes, with an ellipsis when cut.
func oneLine(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case textsafe.IsHidden(r):
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	r := []rune(s)
	return string(r[:maxRunes-1]) + "\u2026"
}

// ViewOf returns what the mails show of the transfer d: every file, with
// its antivirus outcome. A file in scan_error, or in any status without a
// verdict (pending, scanning), is withheld under fail-closed: never
// delivered, left out of the recipient mails and reported to the sender.
// The signature of an infected file is kept for the sender's alert only.
// It is the single mapping shared by the antivirus worker and the download
// service.
func ViewOf(d store.TransferDetails) TransferView {
	v := TransferView{
		ID: d.ID, Language: d.Language, SenderEmail: d.SenderEmail, Recipients: d.Recipients,
		Message: d.Message, ExpiresAt: d.ExpiresAt, PasswordProtected: d.PasswordProtected(),
	}
	if d.ConfidentialityLevel != "" {
		v.ConfidentialityLabels = maps.Clone(d.ConfidentialityLabel)
	}
	for _, f := range d.Files {
		fv := FileView{Name: f.Name, Size: f.Size, SHA256: f.SHA256}
		switch f.ScanStatus {
		case store.ScanClean:
			fv.Scan = ScanClean
		case store.ScanNotScannedTooLarge:
			fv.Scan = ScanTooLarge
		case store.ScanNotScannedEncrypted:
			fv.Scan = ScanEncrypted
		case store.ScanInfected:
			fv.Scan, fv.Signature = ScanInfected, f.ScanSignature
		default:
			fv.Scan = ScanWithheld
		}
		v.Files = append(v.Files, fv)
	}
	return v
}

package proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/pdf"
	"github.com/ed-fr/transteira/internal/store"
)

// Names of the files attached to a proof PDF.
const (
	// StatementName is the attached signed statement (canonical JSON).
	StatementName = "statement.json"
	// SignatureName is the attached Ed25519 signature of StatementName.
	SignatureName = "statement.sig"
)

// Bounds of the visible content of a proof PDF (T-303). The attached
// statement always holds every file.
const (
	// MaxVisibleFiles is the number of files listed in the visible text;
	// the others are counted with a pointer to statement.json.
	MaxVisibleFiles = 300
	// MaxPages bounds the pages of a proof PDF.
	MaxPages = 40
)

// keysPath is the path of the public keys on a tenant host.
const keysPath = "/api/v1/proof-keys"

// KeysURL returns the URL of the public keys on the host fqdn, printed in
// the PDF for the verification.
func KeysURL(fqdn string) string { return "https://" + fqdn + keysPath }

// pdfWrite is [pdf.Write]; a test seam, since the attachments of a proof
// have fixed valid names and a buffer never fails, so it cannot fail here.
var pdfWrite = pdf.Write

// Render returns the PDF of the proof whose statement is st, encoded as
// statementJSON (the exact signed bytes) and signed by sig, with its
// visible text in lang (the default language when unsupported). The PDF
// embeds statementJSON as StatementName and sig as SignatureName, prints
// the SHA-256 of statementJSON, and tells that only the attached statement
// is authoritative, to be checked with transteira proof verify and the
// keys published at keysURL. Its creation date is the latest fact of the
// statement, so that the PDF of a proof is always the same. It returns an
// error when statementJSON is not the encoding of st or sig is not an
// Ed25519 signature.
func Render(st Statement, statementJSON, sig []byte, lang, keysURL string) ([]byte, error) {
	if enc, err := st.Marshal(); err != nil || !bytes.Equal(enc, statementJSON) {
		return nil, errors.New("proof: statement does not match its encoding")
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("proof: malformed signature")
	}
	if !i18n.IsSupported(lang) {
		lang = i18n.Default
	}
	r := renderer{lang: lang}
	sum := sha256.Sum256(statementJSON)
	doc := pdf.Document{
		Title: r.t("proof.title." + string(st.Kind)), Author: st.Tenant.Name, Subject: st.TransferID, Lang: lang,
		Created: st.FactTime(),
		Footer:  r.t("proof.footer", "tenant", st.Tenant.Name, "transfer", st.TransferID),
		Attachments: []pdf.Attachment{
			{Name: StatementName, MIMEType: "application/json", Description: r.t("proof.attachment.statement"), Data: statementJSON},
			{Name: SignatureName, MIMEType: "application/octet-stream", Description: r.t("proof.attachment.signature"), Data: sig},
		},
		MaxPages: MaxPages, TruncatedNotice: r.t("proof.truncated"),
	}
	r.add(pdf.Heading, "", r.t("proof.title."+string(st.Kind)))
	r.add(pdf.Paragraph, "", r.t("proof.intro", "tenant", st.Tenant.Name))
	r.add(pdf.Paragraph, "", r.t("proof.authority", "url", keysURL))
	r.add(pdf.Spacer, "", "")
	r.field("proof.field.tenant", st.Tenant.Name+" ("+st.Tenant.FQDN+")")
	r.field("proof.field.transfer", st.TransferID)
	r.field("proof.field.sender", st.SenderEmail)
	r.field("proof.field.recipients", strings.Join(st.Recipients, "\n"))
	if st.LinkOnly {
		r.field("proof.field.linkOnly", r.t("proof.linkOnly.notice"))
	}
	if st.ConfidentialityLevel != "" {
		r.field("proof.field.level", st.ConfidentialityLevel)
	}
	if st.EndToEndEncrypted {
		r.field("proof.field.e2e", r.t("proof.e2e.notice"))
	}
	r.field("proof.field.deposited", r.time(st.DepositedAt))
	r.field("proof.field.expires", r.time(st.ExpiresAt))
	if st.FirstDownloadedAt != nil {
		r.field("proof.field.firstDownload", r.time(*st.FirstDownloadedAt))
	}
	if len(st.RecipientDownloads) > 0 {
		lines := make([]string, len(st.RecipientDownloads))
		for i, d := range st.RecipientDownloads {
			lines[i] = d.Email + r.colon() + r.time(d.FirstDownloadedAt)
		}
		r.field("proof.field.recipientDownloads", strings.Join(lines, "\n"))
	}
	// The signature block comes before the file list, which the page
	// bound may truncate.
	r.add(pdf.Spacer, "", "")
	r.add(pdf.Heading, "", r.t("proof.heading.signature"))
	r.field("proof.field.statementHash", "")
	r.add(pdf.Mono, "", hex.EncodeToString(sum[:]))
	r.field("proof.field.keyId", st.KeyID)
	r.field("proof.field.instance", st.InstanceVersion)
	r.add(pdf.Spacer, "", "")
	r.add(pdf.Heading, "", r.t("proof.heading.files", "count", strconv.Itoa(len(st.Files))))
	for i, f := range st.Files {
		if i == MaxVisibleFiles {
			r.add(pdf.Paragraph, "", r.t("proof.files.more", "count", strconv.Itoa(len(st.Files)-MaxVisibleFiles)))
			break
		}
		name := f.Name
		if f.Path != "" {
			name = f.Path + "/" + f.Name
		}
		r.add(pdf.Spacer, "", "")
		r.add(pdf.Field, name, "")
		r.add(pdf.Paragraph, "", r.t("proof.file.details", "size", r.size(f.Size), "scan", r.scan(f.ScanStatus)))
		r.add(pdf.Mono, "", f.SHA256)
	}
	doc.Blocks = r.blocks
	var buf bytes.Buffer
	if err := pdfWrite(&buf, doc); err != nil {
		return nil, fmt.Errorf("proof: write pdf: %w", err)
	}
	return buf.Bytes(), nil
}

// FileName returns the download file name of a proof of kind kind of the
// transfer transferID, in ASCII ("transteira-proof-deposit-trf_....pdf"):
// characters outside letters, digits, "_" and "-" are dropped.
func FileName(kind store.ProofKind, transferID string) string {
	keep := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
				return r
			}
			return -1
		}, s)
	}
	return "transteira-proof-" + keep(string(kind)) + "-" + keep(transferID) + ".pdf"
}

// renderer accumulates the blocks of a proof in one language.
type renderer struct {
	lang   string
	blocks []pdf.Block
}

// t translates key with its placeholders.
func (r *renderer) t(key string, pairs ...string) string { return i18n.T(r.lang, key, pairs...) }

// add appends a block.
func (r *renderer) add(kind pdf.BlockKind, label, text string) {
	r.blocks = append(r.blocks, pdf.Block{Kind: kind, Label: label, Text: text})
}

// field appends a labeled value.
func (r *renderer) field(key, value string) {
	r.add(pdf.Field, r.t(key)+r.colon(), value)
}

// colon returns the separator between a label and its value: French puts
// a (non-breaking) space before the colon.
func (r *renderer) colon() string {
	if r.lang == i18n.French {
		return "\u00a0: "
	}
	return ": "
}

// time formats a statement date for reading, falling back to the raw
// value.
func (r *renderer) time(s string) string {
	t, err := parseTime(s)
	if err != nil {
		return s
	}
	return r.t("proof.time", "date", i18n.FormatDate(r.lang, t), "time", t.Format("15:04:05"))
}

// size formats a byte count with grouped digits.
func (r *renderer) size(n int64) string {
	sep := ","
	if r.lang == i18n.French {
		sep = "\u00a0"
	}
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteString(sep)
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// scan translates a scan status, falling back to the raw value.
func (r *renderer) scan(status string) string {
	if s, ok := i18n.DefaultCatalog().Lookup(r.lang, "proof.scan."+status); ok {
		return s
	}
	return status
}

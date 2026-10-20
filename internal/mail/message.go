package mail

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/i18n"
)

// Message limits.
const (
	maxRecipients  = 100
	maxSubjectLen  = 250 // runes
	maxBodyLen     = 1 << 20
	maxInlineParts = 10
	maxInlineSize  = 1 << 20
	maxContentID   = 100
	maxFilenameLen = 100
	// encodedWordBytes is the UTF-8 payload of one RFC 2047 encoded word:
	// 45 bytes give 60 base64 characters, a 72-character word.
	encodedWordBytes = 45
	// base64LineLen is the line length of base64 bodies (RFC 2045).
	base64LineLen = 76
)

// Message is an e-mail to send. Every field is validated by [Build]: no
// header value can carry CR or LF, so no header can be injected.
type Message struct {
	// To lists the recipients, as bare addresses (see [ParseAddress]).
	To []string
	// Subject is a single line, encoded with RFC 2047 when needed.
	Subject string
	// Text is the plain-text body (mandatory).
	Text string
	// HTML is the optional HTML body. It is sent as the preferred
	// alternative to Text.
	HTML string
	// Language is the language of the content ("fr", "en"), written as the
	// Content-Language header when supported.
	Language string
	// Inline lists the parts referenced from HTML by "cid:" URLs (the QR code
	// of the transfer link, CLAUDE.md section 12.2). They require HTML.
	Inline []InlinePart
}

// InlinePart is an image embedded in the message and referenced from the
// HTML body as <img src="cid:ContentID">. Remote images are never used.
type InlinePart struct {
	// ContentID identifies the part, without angle brackets, for example
	// "qr@transteira". Letters, digits, ".", "_", "-" and one "@".
	ContentID string
	// ContentType is an image media type, for example "image/png".
	ContentType string
	// Filename is an optional ASCII file name ([A-Za-z0-9._-]).
	Filename string
	// Data is the raw content (at most 1 MiB).
	Data []byte
}

// validate checks the message and returns the normalized recipients.
func (m Message) validate() ([]string, error) {
	if len(m.To) == 0 || len(m.To) > maxRecipients {
		return nil, fmt.Errorf("%w: between 1 and %d recipients required", ErrInvalidMessage, maxRecipients)
	}
	to := make([]string, 0, len(m.To))
	for _, a := range m.To {
		addr, err := ParseAddress(a)
		if err != nil {
			return nil, fmt.Errorf("%w: recipient: %w", ErrInvalidMessage, err)
		}
		to = append(to, addr)
	}
	if !utf8.ValidString(m.Subject) || hasControl(m.Subject) {
		return nil, fmt.Errorf("%w: subject must be a single line of valid UTF-8", ErrInvalidMessage)
	}
	if strings.TrimSpace(m.Subject) == "" || utf8.RuneCountInString(m.Subject) > maxSubjectLen {
		return nil, fmt.Errorf("%w: subject empty or too long", ErrInvalidMessage)
	}
	if m.Text == "" || len(m.Text) > maxBodyLen || len(m.HTML) > maxBodyLen {
		return nil, fmt.Errorf("%w: text body required, bodies limited to %d bytes", ErrInvalidMessage, maxBodyLen)
	}
	if !utf8.ValidString(m.Text) || !utf8.ValidString(m.HTML) {
		return nil, fmt.Errorf("%w: bodies must be valid UTF-8", ErrInvalidMessage)
	}
	if len(m.Inline) > 0 && m.HTML == "" {
		return nil, fmt.Errorf("%w: inline parts require an HTML body", ErrInvalidMessage)
	}
	if len(m.Inline) > maxInlineParts {
		return nil, fmt.Errorf("%w: too many inline parts", ErrInvalidMessage)
	}
	seen := make(map[string]bool, len(m.Inline))
	for _, p := range m.Inline {
		if err := p.validate(); err != nil {
			return nil, err
		}
		if seen[p.ContentID] {
			return nil, fmt.Errorf("%w: duplicate inline content ID", ErrInvalidMessage)
		}
		seen[p.ContentID] = true
	}
	return to, nil
}

// validate checks an inline part.
func (p InlinePart) validate() error {
	if !validContentID(p.ContentID) {
		return fmt.Errorf("%w: inline content ID", ErrInvalidMessage)
	}
	mt, params, err := mime.ParseMediaType(p.ContentType)
	if err != nil || len(params) != 0 || !strings.HasPrefix(mt, "image/") || hasControl(p.ContentType) {
		return fmt.Errorf("%w: inline content type must be image/*", ErrInvalidMessage)
	}
	if len(p.Filename) > maxFilenameLen || !isSafeToken(p.Filename, false) {
		return fmt.Errorf("%w: inline file name", ErrInvalidMessage)
	}
	if len(p.Data) == 0 || len(p.Data) > maxInlineSize {
		return fmt.Errorf("%w: inline data empty or larger than %d bytes", ErrInvalidMessage, maxInlineSize)
	}
	return nil
}

// validContentID accepts token@token, or a single token, of safe characters.
func validContentID(id string) bool {
	if id == "" || len(id) > maxContentID || strings.Count(id, "@") > 1 {
		return false
	}
	left, right, found := strings.Cut(id, "@")
	return isSafeToken(left, true) && (!found || isSafeToken(right, true))
}

// isSafeToken reports whether s only holds [A-Za-z0-9._-] characters (and is
// non-empty when nonEmpty is set).
func isSafeToken(s string, nonEmpty bool) bool {
	if s == "" {
		return !nonEmpty
	}
	for i := range len(s) {
		c := s[i]
		if !isAlnum(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// Build validates settings and message and returns the RFC 5322 message,
// with CRLF line endings, ready for the SMTP DATA command:
//
//   - multipart/alternative of a quoted-printable text/plain and text/html,
//     or a single text/plain part when there is no HTML;
//   - wrapped in multipart/related with base64 inline parts when there are
//     any;
//   - From, To, Subject, Date, Message-ID (random, at the From domain),
//     MIME-Version, Content-Language and Auto-Submitted headers, in a fixed
//     order; only their values come from the caller, all validated.
func Build(s Settings, m Message) ([]byte, error) {
	return build(s, m, time.Now())
}

// build is [Build] with an injectable clock.
func build(s Settings, m Message, now time.Time) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	to, err := m.validate()
	if err != nil {
		return nil, err
	}
	from, _ := ParseAddress(s.FromAddress) // validated above
	msgID, err := newMessageID(domainOf(from))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writeHeader(&buf, "From", formatMailbox(s.FromName, from))
	writeHeader(&buf, "To", strings.Join(to, ",\r\n "))
	writeHeader(&buf, "Subject", encodeHeaderText(strings.TrimSpace(m.Subject)))
	writeHeader(&buf, "Date", now.Format(time.RFC1123Z))
	writeHeader(&buf, "Message-ID", msgID)
	writeHeader(&buf, "MIME-Version", "1.0")
	if i18n.IsSupported(m.Language) {
		writeHeader(&buf, "Content-Language", m.Language)
	}
	// RFC 3834: tells auto-responders not to reply to these automated mails.
	writeHeader(&buf, "Auto-Submitted", "auto-generated")

	if m.HTML == "" {
		writeHeader(&buf, "Content-Type", "text/plain; charset=utf-8")
		writeHeader(&buf, "Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		writeQP(&buf, m.Text)
		return buf.Bytes(), nil
	}

	if len(m.Inline) == 0 {
		writeAlternative(&buf, nil, m)
		return buf.Bytes(), nil
	}

	related := multipart.NewWriter(&buf)
	writeHeader(&buf, "Content-Type", `multipart/related; type="multipart/alternative"; boundary=`+related.Boundary())
	buf.WriteString("\r\n")
	writeAlternative(&buf, related, m)
	for _, p := range m.Inline {
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", p.ContentType)
		h.Set("Content-Transfer-Encoding", "base64")
		h.Set("Content-ID", "<"+p.ContentID+">")
		if p.Filename != "" {
			h.Set("Content-Disposition", `inline; filename="`+p.Filename+`"`)
		} else {
			h.Set("Content-Disposition", "inline")
		}
		writeBase64(createPart(related, h), p.Data)
	}
	_ = related.Close() // writes to a bytes.Buffer cannot fail
	return buf.Bytes(), nil
}

// writeAlternative writes the multipart/alternative text + HTML entity:
// as the top-level body when parent is nil, else as a part of parent.
func writeAlternative(buf *bytes.Buffer, parent *multipart.Writer, m Message) {
	var alt *multipart.Writer
	if parent == nil {
		alt = multipart.NewWriter(buf)
		writeHeader(buf, "Content-Type", "multipart/alternative; boundary="+alt.Boundary())
		buf.WriteString("\r\n")
	} else {
		// The boundary must appear in the part header, written before the
		// writer of the part exists: draw a random one, then reuse it.
		boundary := multipart.NewWriter(io.Discard).Boundary()
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", "multipart/alternative; boundary="+boundary)
		alt = multipart.NewWriter(createPart(parent, h))
		_ = alt.SetBoundary(boundary) // a boundary drawn by multipart is always valid
	}
	for _, part := range []struct{ ctype, body string }{
		{"text/plain; charset=utf-8", m.Text},
		{"text/html; charset=utf-8", m.HTML},
	} {
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", part.ctype)
		h.Set("Content-Transfer-Encoding", "quoted-printable")
		writeQP(createPart(alt, h), part.body)
	}
	_ = alt.Close() // writes to a bytes.Buffer cannot fail
}

// createPart starts a part of mw. Every multipart writer of this file
// writes, directly or through its parent, to a bytes.Buffer, whose writes
// cannot fail: the error is always nil.
func createPart(mw *multipart.Writer, h textproto.MIMEHeader) io.Writer {
	w, _ := mw.CreatePart(h)
	return w
}

// writeHeader writes one header line. Names are constants of this package
// and values have been validated or encoded, so neither can hold a bare CR
// or LF; folding uses CRLF followed by a space.
func writeHeader(buf *bytes.Buffer, name, value string) {
	buf.WriteString(name)
	buf.WriteString(": ")
	buf.WriteString(value)
	buf.WriteString("\r\n")
}

// writeQP writes body as quoted-printable with CRLF line endings.
func writeQP(w io.Writer, body string) {
	qp := quotedprintable.NewWriter(w)
	_, _ = io.WriteString(qp, body)
	_ = qp.Close()
}

// writeBase64 writes data as base64 lines of base64LineLen characters.
func writeBase64(w io.Writer, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > base64LineLen {
		_, _ = io.WriteString(w, enc[:base64LineLen]+"\r\n")
		enc = enc[base64LineLen:]
	}
	_, _ = io.WriteString(w, enc+"\r\n")
}

// newMessageID returns <32 random hex digits@domain>.
func newMessageID(domain string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mail: message ID: %w", err)
	}
	return "<" + hex.EncodeToString(b[:]) + "@" + domain + ">", nil
}

// formatMailbox formats "Display Name <addr>", or the bare address when
// there is no name. An ASCII name is written as a quoted string, any other
// as RFC 2047 encoded words.
func formatMailbox(name, addr string) string {
	if name == "" {
		return addr
	}
	if isPrintableASCII(name) && !strings.Contains(name, "=?") {
		r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
		return `"` + r.Replace(name) + `" <` + addr + ">"
	}
	return encodeWords(name) + " <" + addr + ">"
}

// encodeHeaderText returns an unstructured header value (RFC 5322 section
// 3.2.5): printable ASCII as-is, anything else as folded RFC 2047 encoded
// words. Text that merely looks like an encoded word ("=?") is encoded too,
// so that readers decode exactly what the caller wrote.
func encodeHeaderText(s string) string {
	if isPrintableASCII(s) && !strings.Contains(s, "=?") {
		return s
	}
	return encodeWords(s)
}

// encodeWords encodes s as UTF-8 "B" encoded words of at most 75
// characters, never splitting a character, folded with CRLF + space.
func encodeWords(s string) string {
	var words []string
	for s != "" {
		n := 0
		for n < len(s) {
			_, size := utf8.DecodeRuneInString(s[n:])
			if n+size > encodedWordBytes {
				break
			}
			n += size
		}
		words = append(words, "=?utf-8?b?"+base64.StdEncoding.EncodeToString([]byte(s[:n]))+"?=")
		s = s[n:]
	}
	return strings.Join(words, "\r\n ")
}

// isPrintableASCII reports whether s only holds characters from space to "~".
func isPrintableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

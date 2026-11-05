package pdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/textsafe"
)

const maxAttachmentName = 1024

// hexUTF16 encodes s as a PDF hexadecimal text string (UTF-16BE with byte
// order mark). A hex string cannot carry any syntax.
func hexUTF16(s string) string {
	u := utf16.Encode([]rune(s))
	var sb strings.Builder
	sb.WriteString("<FEFF")
	for _, c := range u {
		fmt.Fprintf(&sb, "%04X", c)
	}
	sb.WriteByte('>')
	return sb.String()
}

// cleanText prepares a metadata string: valid UTF-8, no hidden character,
// single line.
func cleanText(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case textsafe.IsHidden(r):
			return -1
		}
		return r
	}, s)
}

// asciiFallback returns a conservative ASCII version of s (letters, digits, dot,
// hyphen, underscore; anything else becomes '_') for the /F entry.
func asciiFallback(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
	}
	return sb.String()
}

// nameObject escapes s as a PDF name (#XX for everything but a safe set).
func nameObject(s string) string {
	var sb strings.Builder
	sb.WriteByte('/')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '+' {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "#%02X", c)
		}
	}
	return sb.String()
}

// pdfDate formats t as a PDF date in UTC.
func pdfDate(t time.Time) string {
	return "(D:" + t.UTC().Format("20060102150405") + "Z)"
}

// validLang reports whether s looks like a BCP 47 tag (letters, digits and
// hyphens, at most 16 characters).
func validLang(s string) bool {
	if s == "" || len(s) > 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// checkAttachments validates names and returns the attachments sorted by
// name (UTF-16BE order of the stored form).
func checkAttachments(in []Attachment) ([]Attachment, error) {
	out := append([]Attachment(nil), in...)
	seen := map[string]bool{}
	for _, a := range out {
		if a.Name == "" || len(a.Name) > maxAttachmentName || !utf8.ValidString(a.Name) {
			return nil, fmt.Errorf("%w: invalid attachment name", ErrMalformed)
		}
		if seen[a.Name] {
			return nil, fmt.Errorf("%w: duplicate attachment name", ErrMalformed)
		}
		seen[a.Name] = true
	}
	sort.Slice(out, func(i, j int) bool { return hexUTF16(out[i].Name) < hexUTF16(out[j].Name) })
	return out, nil
}

// Write renders d as a PDF 1.7 document on w. The output is deterministic.
// It returns ErrMalformed for an empty, invalid or duplicate attachment name.
func Write(w io.Writer, d Document) error {
	atts, err := checkAttachments(d.Attachments)
	if err != nil {
		return err
	}
	maxPages := d.MaxPages
	if maxPages <= 0 {
		maxPages = DefaultMaxPages
	}
	pages, _ := layout(d, maxPages)
	np := len(pages)

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n")
	nObjs := 6 + 2*np + 2*len(atts)
	offsets := make([]int, nObjs+1)
	begin := func(n int) {
		offsets[n] = buf.Len()
		buf.WriteString(strconv.Itoa(n) + " 0 obj\n")
	}
	end := func() { buf.WriteString("endobj\n") }
	stream := func(dict string, data []byte) {
		buf.WriteString("<< " + dict + " /Length " + strconv.Itoa(len(data)) + " >>\nstream\n")
		buf.Write(data)
		buf.WriteString("\nendstream\n")
	}

	attBase := 7 + 2*np
	afRefs := make([]string, len(atts))
	nameTree := make([]string, len(atts))
	for i, a := range atts {
		afRefs[i] = strconv.Itoa(attBase+2*i+1) + " 0 R"
		nameTree[i] = hexUTF16(a.Name) + " " + afRefs[i]
	}

	begin(1)
	buf.WriteString("<< /Type /Catalog /Pages 2 0 R /PageMode /UseAttachments /ViewerPreferences << /DisplayDocTitle true >>")
	if validLang(d.Lang) {
		buf.WriteString(" /Lang " + escapeLiteral([]byte(d.Lang)))
	}
	if len(atts) > 0 {
		buf.WriteString(" /Names << /EmbeddedFiles << /Names [" + strings.Join(nameTree, " ") + "] >> >>")
		buf.WriteString(" /AF [" + strings.Join(afRefs, " ") + "]")
	}
	buf.WriteString(" >>\n")
	end()

	begin(2)
	kids := make([]string, np)
	for i := range kids {
		kids[i] = strconv.Itoa(7+2*i) + " 0 R"
	}
	buf.WriteString("<< /Type /Pages /Kids [" + strings.Join(kids, " ") + "] /Count " + strconv.Itoa(np) + " >>\n")
	end()

	begin(3)
	buf.WriteString("<< /Producer (TransTeira) /Title " + hexUTF16(cleanText(d.Title)) +
		" /Author " + hexUTF16(cleanText(d.Author)) + " /Subject " + hexUTF16(cleanText(d.Subject)))
	if !d.Created.IsZero() {
		buf.WriteString(" /CreationDate " + pdfDate(d.Created))
	}
	buf.WriteString(" >>\n")
	end()

	for i, name := range []string{"Helvetica", "Helvetica-Bold", "Courier"} {
		begin(4 + i)
		buf.WriteString("<< /Type /Font /Subtype /Type1 /BaseFont /" + name + " /Encoding /WinAnsiEncoding >>\n")
		end()
	}

	for i, content := range pages {
		begin(7 + 2*i)
		buf.WriteString("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents " + strconv.Itoa(8+2*i) +
			" 0 R /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >> >> >>\n")
		end()
		begin(8 + 2*i)
		stream("", []byte(content))
		end()
	}

	for i, a := range atts {
		mime := a.MIMEType
		if mime == "" {
			mime = "application/octet-stream"
		}
		begin(attBase + 2*i)
		stream("/Type /EmbeddedFile /Subtype "+nameObject(mime)+" /Params << /Size "+strconv.Itoa(len(a.Data))+" >>", a.Data)
		end()
		begin(attBase + 2*i + 1)
		buf.WriteString("<< /Type /Filespec /F " + escapeLiteral([]byte(asciiFallback(a.Name))) + " /UF " + hexUTF16(a.Name) +
			" /Desc " + hexUTF16(cleanText(a.Description)) + " /AFRelationship /Data /EF << /F " +
			strconv.Itoa(attBase+2*i) + " 0 R /UF " + strconv.Itoa(attBase+2*i) + " 0 R >> >>\n")
		end()
	}

	sum := sha256.Sum256(buf.Bytes())
	id := "<" + strings.ToUpper(hex.EncodeToString(sum[:16])) + ">"
	xref := buf.Len()
	buf.WriteString("xref\n0 " + strconv.Itoa(nObjs+1) + "\n0000000000 65535 f \n")
	for n := 1; n <= nObjs; n++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[n])
	}
	buf.WriteString("trailer\n<< /Size " + strconv.Itoa(nObjs+1) + " /Root 1 0 R /Info 3 0 R /ID [" + id + id + "] >>\n")
	buf.WriteString("startxref\n" + strconv.Itoa(xref) + "\n%%EOF\n")
	_, err = w.Write(buf.Bytes())
	return err
}

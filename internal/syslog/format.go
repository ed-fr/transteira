package syslog

import (
	"bytes"
	"math"
	"net/netip"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/events"
)

// timeLayout is the RFC 5424 TIMESTAMP layout: RFC 3339, UTC, microseconds.
const timeLayout = "2006-01-02T15:04:05.000000Z"

// Escaping modes of appendEscaped.
const (
	// escapeQuote escapes the backslash and the double quote.
	escapeQuote = 1 << iota
	// escapeBracket escapes the closing bracket (structured data values).
	escapeBracket
	// escapeSD is the escaping of a structured data PARAM-VALUE.
	escapeSD = escapeQuote | escapeBracket
)

// fixedParams are the names of the parameters written from the fields of
// the record; a security field with one of these names is skipped, so that
// no parameter is ambiguous.
var fixedParams = map[string]bool{
	"stream": true, "tenant": true, "action": true, "actor_kind": true, "actor": true,
	"ip": true, "object_kind": true, "object_id": true, "audit_id": true,
}

// keptParams are the parameters removed last when a message must be
// shortened (formatter.maxLen).
var keptParams = map[string]bool{"stream": true, "tenant": true, "action": true, "ip": true}

// formatter builds the RFC 5424 messages of the exporter.
type formatter struct {
	facility int
	hostname string
	procID   string
	// maxLen, when positive, is the maximum length of a message (MaxDatagram
	// for udp): see format.
	maxLen int
}

// sdParam is one rendered structured data parameter, ` name="value"`.
type sdParam struct {
	text []byte
	keep bool // one of keptParams
}

// format returns the RFC 5424 message of rec, without framing. The
// timestamp is rec.Time, or fallback when it is zero. The message holds a
// single line whatever the content of rec.
//
// When f.maxLen is positive the message never exceeds it and stays well
// formed: the MSG part is cut first, between two escaped characters; when
// the header and the structured data alone are still too long, whole
// parameters are removed from the end, those of keptParams last, so that no
// value is ever cut and the element is always closed. The header alone
// (under 400 bytes) always fits in MaxDatagram.
func (f formatter) format(rec *events.LogRecord, fallback time.Time) []byte {
	var b bytes.Buffer
	severity := severityNotice
	if rec.Stream == events.StreamSecurity {
		severity = severityWarning
	}
	t := rec.Time
	if t.IsZero() {
		t = fallback
	}
	b.WriteByte('<')
	b.WriteString(strconv.Itoa(f.facility*8 + severity))
	b.WriteString(">1 ")
	b.WriteString(t.UTC().Format(timeLayout))
	b.WriteByte(' ')
	b.WriteString(f.hostname)
	b.WriteString(" " + AppName + " ")
	b.WriteString(f.procID)
	b.WriteByte(' ')
	b.WriteString(msgID(rec))
	b.WriteByte(' ')
	params := sdParams(rec)
	total := b.Len() + len("["+SDID+"]")
	for _, p := range params {
		total += len(p.text)
	}
	limit := math.MaxInt
	if f.maxLen > 0 {
		params, total = fitParams(params, total, f.maxLen)
		limit = max(f.maxLen-total, 0)
	}
	b.WriteString("[" + SDID)
	for _, p := range params {
		b.Write(p.text)
	}
	b.WriteByte(']')
	appendMessage(&b, rec, limit)
	return b.Bytes()
}

// sdParams returns the rendered parameters of rec, in their order: the
// fields of the record, then the security fields whose names are valid and
// not taken. Empty values are left out.
func sdParams(rec *events.LogRecord) []sdParam {
	params := make([]sdParam, 0, len(fixedParams)+len(rec.Fields))
	add := func(name, value string) {
		var pb bytes.Buffer
		if appendParam(&pb, name, value); pb.Len() > 0 {
			params = append(params, sdParam{text: pb.Bytes(), keep: keptParams[name]})
		}
	}
	add("stream", string(rec.Stream))
	add("tenant", rec.Tenant)
	add("action", rec.Action)
	add("actor_kind", rec.ActorKind)
	add("actor", rec.Actor)
	add("ip", formatIP(rec.IP))
	add("object_kind", rec.ObjectKind)
	add("object_id", rec.ObjectID)
	add("audit_id", rec.AuditID)
	for _, fd := range rec.Fields {
		if name := sdName(fd.Key); name != "" && !fixedParams[name] {
			add(name, fd.Value)
		}
	}
	return params
}

// fitParams removes whole parameters from the end of params, those not
// kept first, while total (the length of the message without its MSG part)
// exceeds maxLen. It returns the parameters left and the new total.
func fitParams(params []sdParam, total, maxLen int) ([]sdParam, int) {
	for _, keep := range []bool{false, true} {
		for i := len(params) - 1; i >= 0 && total > maxLen; i-- {
			if params[i].keep == keep {
				total -= len(params[i].text)
				params = append(params[:i], params[i+1:]...)
			}
		}
	}
	return params, total
}

// appendMessage writes the MSG part, preceded by a space, in at most limit
// bytes: the security log line as written locally (already escaped, only
// its control characters would be escaped again), or the action, object
// kind and object ID of an audit line, with the same escaping plus \\ and
// \" (escapeQuote), so that a backslash of the audit values cannot be read
// as the start of an escape. The text is cut between two escaped
// characters; nothing is written when the message is empty or limit too
// small.
func appendMessage(b *bytes.Buffer, rec *events.LogRecord, limit int) {
	parts, mode := []string{rec.Line}, 0
	if rec.Line == "" {
		mode = escapeQuote
		parts = []string{
			truncateString(rec.Action, MaxValueLen), truncateString(rec.ObjectKind, MaxValueLen),
			truncateString(rec.ObjectID, MaxValueLen),
		}
	}
	for _, s := range parts {
		if s == "" {
			continue
		}
		if limit < 2 { // a space and at least one byte
			return
		}
		b.WriteByte(' ')
		n, complete := appendEscapedMax(b, s, mode, limit-1)
		if n == 0 { // not even the first character fits
			b.Truncate(b.Len() - 1)
		}
		if !complete {
			return
		}
		limit -= n + 1
	}
}

// msgID returns the MSGID of rec: its action reduced to printable US-ASCII
// (other bytes become "_") and 32 bytes, or its stream when the action is
// empty.
func msgID(rec *events.LogRecord) string {
	s := rec.Action
	if s == "" {
		s = string(rec.Stream)
	}
	if s == "" {
		return "-"
	}
	b := []byte(s[:min(len(s), maxMsgIDLen)])
	for i, c := range b {
		if !isPrintASCII(c) {
			b[i] = '_'
		}
	}
	return string(b)
}

// sdName returns key reduced to an RFC 5424 SD-NAME: printable US-ASCII
// except '=', space, ']' and '"', at most 32 bytes; "" when nothing is
// left.
func sdName(key string) string {
	b := make([]byte, 0, min(len(key), maxSDNameLen))
	for i := 0; i < len(key) && len(b) < maxSDNameLen; i++ {
		if c := key[i]; isPrintASCII(c) && c != '=' && c != ']' && c != '"' {
			b = append(b, c)
		}
	}
	return string(b)
}

// appendParam writes ` name="value"`, value truncated to MaxValueLen bytes
// and escaped; nothing when value is empty.
func appendParam(b *bytes.Buffer, name, value string) {
	if value == "" {
		return
	}
	b.WriteByte(' ')
	b.WriteString(name)
	b.WriteString(`="`)
	appendEscaped(b, truncateString(value, MaxValueLen), escapeSD)
	b.WriteByte('"')
}

// formatIP returns the unmapped, zone-less form of addr, "" when invalid.
func formatIP(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	// The zone is free text (WithZone accepts any string): never write it.
	return addr.Unmap().WithZone("").String()
}

// isPrintASCII reports whether c is printable US-ASCII (RFC 5424
// PRINTUSASCII, 33 to 126).
func isPrintASCII(c byte) bool { return c >= 33 && c <= 126 }

// truncateString keeps at most n bytes of s, cutting on a rune boundary
// when s is valid UTF-8 there.
func truncateString(s string, n int) string {
	return string(truncate([]byte(s), n))
}

// appendEscaped writes s with the escapes of the security log (P22): \n \r
// \t, \xNN for the other ASCII control bytes and for the invalid UTF-8
// bytes, \uNNNN or \UNNNNNNNN for the non-printable runes (C1 controls,
// line and paragraph separators, bidi controls...). mode adds \\ and \"
// (escapeQuote) and \] (escapeBracket).
func appendEscaped(b *bytes.Buffer, s string, mode int) {
	appendEscapedMax(b, s, mode, math.MaxInt)
}

// appendEscapedMax writes s escaped as appendEscaped does, in at most n
// bytes: it stops before the first character whose escaped form would go
// beyond, so that no escape sequence and no rune is ever cut. It returns
// the number of bytes written and whether all of s was written.
func appendEscapedMax(b *bytes.Buffer, s string, mode, n int) (written int, complete bool) {
	var scratch [16]byte
	for i := 0; i < len(s); {
		piece, size := escapeRune(scratch[:0], s, i, mode)
		if written+len(piece) > n {
			return written, false
		}
		b.Write(piece)
		written += len(piece)
		i += size
	}
	return written, true
}

// escapeRune appends to dst the escaped form of the character of s at byte
// i (see appendEscaped) and returns it with the number of bytes of s
// consumed.
func escapeRune(dst []byte, s string, i, mode int) ([]byte, int) {
	const hex = "0123456789abcdef"
	r, size := utf8.DecodeRuneInString(s[i:])
	switch {
	case r == utf8.RuneError && size == 1:
		dst = append(dst, '\\', 'x', hex[s[i]>>4], hex[s[i]&0xf])
	case (r == '\\' || r == '"') && mode&escapeQuote != 0,
		r == ']' && mode&escapeBracket != 0:
		dst = append(dst, '\\', s[i]) // an ASCII byte
	case r == '\n':
		dst = append(dst, `\n`...)
	case r == '\r':
		dst = append(dst, `\r`...)
	case r == '\t':
		dst = append(dst, `\t`...)
	case r < 0x20 || r == 0x7f:
		dst = append(dst, '\\', 'x', hex[r>>4], hex[r&0xf])
	case r >= utf8.RuneSelf && !unicode.IsPrint(r):
		q := strconv.QuoteRuneToASCII(r) // e.g. backslash-u2028 or backslash-U000e0001
		dst = append(dst, q[1:len(q)-1]...)
	default:
		dst = append(dst, s[i:i+size]...)
	}
	return dst, size
}

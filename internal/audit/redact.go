package audit

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// redactedAddress replaces each address removed by [RedactAddresses].
const redactedAddress = "[address]"

// isAt reports whether r is an at sign: the ASCII one and its full-width
// and small compatibility forms, which a reader takes for the same sign.
func isAt(r rune) bool {
	return r == '@' || r == '＠' || r == '﹫'
}

// containsAt reports whether s holds an at sign (see isAt).
func containsAt(s string) bool {
	return strings.ContainsFunc(s, isAt)
}

// isLocalRune reports whether r may be part of the unquoted local part of
// an address: letters and digits of any script, combining marks, and the
// RFC 5322 atext symbols except those that usually delimit a URL query
// ("/", "=", "?", "&"), so that "?to=a@example.com" keeps its "?to=".
func isLocalRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) ||
		strings.ContainsRune("!#$%'*+-^_`{|}~.", r)
}

// isDomainRune reports whether r may be part of the domain of an address,
// internationalized names included.
func isDomainRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) ||
		r == '-' || r == '.' || r == '_'
}

// RedactAddresses returns s with every mail address replaced by
// "[address]", for free text (an administrator's reason, an error message)
// that is about to be recorded or logged.
//
// It errs on the side of redaction: every at sign (ASCII, full-width or
// small form) is replaced together with the local part before it and the
// domain after it, even when one of them is empty or malformed, so the
// result never contains an at sign and passes the [ErrPersonalDetail]
// check. Local parts may be quoted ("john doe"@example.com) and use any
// script; domains may be internationalized or address literals
// ([192.0.2.1]). A trailing dot or hyphen ends the sentence, not the
// domain, and is kept. It never panics, and invalid UTF-8 is kept as is
// outside the redacted spans.
func RedactAddresses(s string) string {
	if !containsAt(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0 // end of the text already written
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !isAt(r) {
			i += size
			continue
		}
		start := localStart(s, last, i)
		end := domainEnd(s, i+size)
		b.WriteString(s[last:start])
		b.WriteString(redactedAddress)
		last, i = end, end
	}
	b.WriteString(s[last:])
	return b.String()
}

// localStart returns the start of the local part ending at at (the index of
// the at sign), not before floor.
func localStart(s string, floor, at int) int {
	if at > floor && s[at-1] == '"' {
		if q := quoteStart(s, floor, at-1); q >= 0 {
			return q
		}
	}
	start := at
	for start > floor {
		r, size := utf8.DecodeLastRuneInString(s[floor:start])
		if !isLocalRune(r) {
			break
		}
		start -= size
	}
	return start
}

// quoteStart returns the index of the double quote opening the quoted
// string closed by the quote at end, not before floor, skipping quotes
// escaped by a backslash; -1 when there is none.
func quoteStart(s string, floor, end int) int {
	for j := end - 1; j >= floor; j-- {
		if s[j] == '"' && (j == floor || s[j-1] != '\\') {
			return j
		}
	}
	return -1
}

// domainEnd returns the end of the domain starting at from: an address
// literal in brackets, or a run of domain runes without its trailing dots
// and hyphens.
func domainEnd(s string, from int) int {
	if from < len(s) && s[from] == '[' {
		if k := strings.IndexByte(s[from:], ']'); k > 0 && literal(s[from+1:from+k]) {
			return from + k + 1
		}
	}
	end := from
	for end < len(s) {
		r, size := utf8.DecodeRuneInString(s[end:])
		if !isDomainRune(r) {
			break
		}
		end += size
	}
	for end > from && (s[end-1] == '.' || s[end-1] == '-') {
		end--
	}
	return end
}

// literal reports whether lit is a plausible address literal body: IPv4,
// or "IPv6:" followed by hexadecimal groups.
func literal(lit string) bool {
	if lit == "" {
		return false
	}
	for _, c := range []byte(lit) {
		ok := c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' ||
			c == '.' || c == ':' || c == 'v' || c == 'V' || c == 'I' || c == 'P'
		if !ok {
			return false
		}
	}
	return true
}

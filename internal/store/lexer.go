package store

import (
	"strconv"
	"strings"
)

// tokenKind classifies the tokens produced by lexSQL.
type tokenKind int

// Token kinds.
const (
	// tokWord is an identifier or keyword, possibly qualified ("t.tenant_id").
	tokWord tokenKind = iota
	// tokPlaceholder is a "?" bind placeholder.
	tokPlaceholder
	// tokString is a single-quoted string literal.
	tokString
	// tokQuotedIdent is a double-quoted identifier.
	tokQuotedIdent
	// tokPunct is any other single character (operator, parenthesis, comma...).
	tokPunct
)

// token is one lexical unit of an SQL statement. Whitespace and comments are
// not tokens.
type token struct {
	kind tokenKind
	text string
	// pos is the byte offset of the token in the statement.
	pos int
}

// end returns the byte offset just after the token.
func (t token) end() int { return t.pos + len(t.text) }

// is reports whether the token is the given keyword or punctuation,
// compared case-insensitively.
func (t token) is(s string) bool {
	return (t.kind == tokWord || t.kind == tokPunct) && strings.EqualFold(t.text, s)
}

// isWordChar reports whether c may appear inside an identifier.
func isWordChar(c byte) bool {
	return c == '_' || c == '.' || c == '$' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isSpace reports whether c is SQL whitespace.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// skipQuoted returns the index just after the quoted section starting at
// s[i] (a quote character q). A doubled quote inside the section is an
// escaped quote. An unterminated section ends at len(s); ok is false then.
func skipQuoted(s string, i int, q byte) (end int, ok bool) {
	for j := i + 1; j < len(s); j++ {
		if s[j] != q {
			continue
		}
		if j+1 < len(s) && s[j+1] == q {
			j++
			continue
		}
		return j + 1, true
	}
	return len(s), false
}

// skipComment returns the index just after the comment starting at s[i], or
// i when no comment starts there. ok is false for an unterminated block
// comment and for a nested one ("/*" inside a block comment): PostgreSQL
// nests block comments while SQLite does not, so the two engines would not
// agree on where it ends.
func skipComment(s string, i int) (end int, ok bool) {
	switch {
	case strings.HasPrefix(s[i:], "--"):
		if nl := strings.IndexByte(s[i:], '\n'); nl >= 0 {
			return i + nl + 1, true
		}
		return len(s), true
	case strings.HasPrefix(s[i:], "/*"):
		if e := strings.Index(s[i+2:], "*/"); e >= 0 {
			return i + 2 + e + 2, !strings.Contains(s[i+2:i+2+e], "/*")
		}
		return len(s), false
	}
	return i, true
}

// lexSQL splits an SQL statement into tokens, skipping whitespace and
// comments. It reports ok=false when a string literal, quoted identifier or
// block comment is not terminated.
func lexSQL(s string) (toks []token, ok bool) {
	ok = true
	for i := 0; i < len(s); {
		c := s[i]
		if isSpace(c) {
			i++
			continue
		}
		if end, cok := skipComment(s, i); end != i {
			ok = ok && cok
			i = end
			continue
		}
		switch {
		case c == '\'' || c == '"':
			end, qok := skipQuoted(s, i, c)
			ok = ok && qok
			kind := tokString
			if c == '"' {
				kind = tokQuotedIdent
			}
			toks = append(toks, token{kind: kind, text: s[i:end], pos: i})
			i = end
		case c == '?':
			toks = append(toks, token{kind: tokPlaceholder, text: "?", pos: i})
			i++
		case isWordChar(c):
			j := i
			for j < len(s) && isWordChar(s[j]) {
				j++
			}
			toks = append(toks, token{kind: tokWord, text: s[i:j], pos: i})
			i = j
		default:
			toks = append(toks, token{kind: tokPunct, text: s[i : i+1], pos: i})
			i++
		}
	}
	return toks, ok
}

// rebindNumbered rewrites each "?" placeholder of s into PostgreSQL's
// numbered form ("$1", "$2", ...). Question marks inside string literals,
// quoted identifiers and comments are left untouched; the rest of the text,
// including whitespace and comments, is preserved byte for byte.
func rebindNumbered(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	n := 0
	for i := 0; i < len(s); {
		c := s[i]
		if end, _ := skipComment(s, i); end != i {
			b.WriteString(s[i:end])
			i = end
			continue
		}
		switch c {
		case '\'', '"':
			end, _ := skipQuoted(s, i, c)
			b.WriteString(s[i:end])
			i = end
		case '?':
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

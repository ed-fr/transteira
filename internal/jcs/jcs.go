// Package jcs implements the JSON Canonicalization Scheme of RFC 8785,
// restricted to the subset used by the signed proof statements (threat
// T-298). The canonical bytes it produces are signed with Ed25519, so the
// canonicalizer is strict and deterministic: any input that could have two
// readings is rejected instead of being normalized.
//
// The output follows RFC 8785:
//
//   - no whitespace between tokens;
//   - object members sorted by their names compared as arrays of UTF-16
//     code units (RFC 8785 section 3.2.3), not as UTF-8 bytes;
//   - strings serialized as ECMAScript JSON.stringify does (RFC 8785
//     section 3.2.2.2): '"' and '\' escaped, \b \f \n \r \t in their short
//     form, the other characters U+0000 to U+001F as \u00xx in lowercase
//     hexadecimal, every other character written as literal UTF-8 (no
//     escaping of '/', '<', '>', '&', U+2028, U+2029 or non-ASCII text);
//   - literals true, false and null; arrays keep their order.
//
// Restrictions compared with RFC 8785 (all rejected with an error, never
// silently rewritten):
//
//   - Numbers must be integer literals: an optional minus sign followed by
//     "0" or by a digit 1-9 and more digits. A fraction or an exponent is
//     rejected with [ErrNumber] even when its value is an integer (for
//     example 1.0 or 1E2), so the canonical form of a number is always the
//     input literal itself. The magnitude must not exceed 2^53-1
//     ([MaxSafeInteger]), the largest integer an IEEE 754 double holds
//     exactly, and "-0" is rejected. RFC 8785 accepts any IEEE 754 double;
//     the statements contain no floating-point value, so this subset avoids
//     the number serialization algorithm entirely.
//   - Object member names must be unique ([ErrDuplicateKey]); RFC 8785
//     relies on I-JSON (RFC 7493), which forbids them too.
//   - Strings must be valid UTF-8 and must not contain lone surrogate
//     escapes such as "\ud800" ([ErrUTF8]), as I-JSON requires.
//   - Nesting is limited to [MaxDepth] levels ([ErrDepth]) and the input to
//     [MaxSize] bytes ([ErrTooLarge]), the bound of the database CHECK on
//     transfer_proofs.statement.
//
// The package depends only on the standard library.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxSize is the largest input accepted by [Canonicalize], in bytes (4 MiB).
// The canonical form is never longer than its input, so it fits the same
// bound.
const MaxSize = 4 << 20

// MaxDepth is the deepest nesting of arrays and objects accepted. A top
// level array or object is at depth 1.
const MaxDepth = 64

// MaxSafeInteger is the largest magnitude accepted for a number, 2^53-1.
const MaxSafeInteger = 1<<53 - 1

// Sentinel errors returned (wrapped with context) by [Canonicalize] and
// [Marshal]. Test them with errors.Is.
var (
	// ErrSyntax reports invalid JSON or data after the top-level value.
	ErrSyntax = errors.New("jcs: invalid JSON")
	// ErrNumber reports a number outside the accepted subset: fraction,
	// exponent, leading zero, negative zero or magnitude above 2^53-1.
	ErrNumber = errors.New("jcs: unsupported number")
	// ErrDuplicateKey reports an object with two members of the same name.
	ErrDuplicateKey = errors.New("jcs: duplicate object member name")
	// ErrUTF8 reports invalid UTF-8 or a lone surrogate escape.
	ErrUTF8 = errors.New("jcs: invalid UTF-8 or lone surrogate")
	// ErrDepth reports nesting deeper than MaxDepth.
	ErrDepth = errors.New("jcs: nesting too deep")
	// ErrTooLarge reports an input longer than MaxSize bytes.
	ErrTooLarge = errors.New("jcs: input too large")
)

// Canonicalize parses exactly one JSON value from data (surrounding JSON
// whitespace allowed, nothing else) and returns its RFC 8785 canonical
// form, within the subset described in the package documentation.
func Canonicalize(data []byte) ([]byte, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(data), MaxSize)
	}
	p := &parser{data: data}
	out := make([]byte, 0, len(data))
	p.skipSpace()
	out, err := p.value(out, 0)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.data) {
		return nil, p.errorf(ErrSyntax, "data after the top-level value")
	}
	return out, nil
}

// Marshal encodes v with encoding/json and returns the canonical form of the
// result. Values outside the subset (for example a float64 with a fraction
// or an integer above 2^53-1) make it fail with [ErrNumber].
func Marshal(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jcs: marshal: %w", err)
	}
	return Canonicalize(data)
}

// parser is a single-use recursive descent parser that writes the canonical
// form while it reads.
type parser struct {
	data []byte
	pos  int
}

// errorf wraps sentinel with the current offset and a description.
func (p *parser) errorf(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w at offset %d: %s", sentinel, p.pos, fmt.Sprintf(format, args...))
}

// skipSpace advances over the four JSON whitespace characters.
func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

// value parses one value at p.pos, the caller having skipped the leading
// whitespace, and appends its canonical form to out. depth is the number of
// enclosing containers.
func (p *parser) value(out []byte, depth int) ([]byte, error) {
	if p.pos >= len(p.data) {
		return nil, p.errorf(ErrSyntax, "unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(out, depth+1)
	case c == '[':
		return p.array(out, depth+1)
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return appendString(out, s), nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number(out)
	default:
		for _, lit := range [...]string{"true", "false", "null"} {
			if bytes.HasPrefix(p.data[p.pos:], []byte(lit)) {
				p.pos += len(lit)
				return append(out, lit...), nil
			}
		}
		return nil, p.errorf(ErrSyntax, "unexpected character %q", c)
	}
}

// member is a parsed object member: its decoded name and the canonical form
// of its value.
type member struct {
	name  string
	key   []uint16
	value []byte
}

// object parses an object at p.pos and appends its canonical form.
func (p *parser) object(out []byte, depth int) ([]byte, error) {
	if depth > MaxDepth {
		return nil, p.errorf(ErrDepth, "more than %d levels", MaxDepth)
	}
	p.pos++ // '{'
	p.skipSpace()
	var members []member
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return append(out, '{', '}'), nil
	}
	for {
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.errorf(ErrSyntax, "expected a member name")
		}
		name, err := p.str()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.errorf(ErrSyntax, "expected ':'")
		}
		p.pos++
		p.skipSpace()
		val, err := p.value(nil, depth)
		if err != nil {
			return nil, err
		}
		members = append(members, member{name: name, key: utf16.Encode([]rune(name)), value: val})
		p.skipSpace()
		if p.pos < len(p.data) && p.data[p.pos] == ',' {
			p.pos++
			p.skipSpace()
			continue
		}
		if p.pos < len(p.data) && p.data[p.pos] == '}' {
			p.pos++
			break
		}
		return nil, p.errorf(ErrSyntax, "expected ',' or '}'")
	}
	slices.SortFunc(members, func(a, b member) int { return slices.Compare(a.key, b.key) })
	out = append(out, '{')
	for i, m := range members {
		if i > 0 {
			if m.name == members[i-1].name {
				return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, m.name)
			}
			out = append(out, ',')
		}
		out = appendString(out, m.name)
		out = append(out, ':')
		out = append(out, m.value...)
	}
	return append(out, '}'), nil
}

// array parses an array at p.pos and appends its canonical form.
func (p *parser) array(out []byte, depth int) ([]byte, error) {
	if depth > MaxDepth {
		return nil, p.errorf(ErrDepth, "more than %d levels", MaxDepth)
	}
	p.pos++ // '['
	p.skipSpace()
	out = append(out, '[')
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return append(out, ']'), nil
	}
	for first := true; ; first = false {
		if !first {
			out = append(out, ',')
		}
		var err error
		out, err = p.value(out, depth)
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.pos < len(p.data) && p.data[p.pos] == ',' {
			p.pos++
			p.skipSpace()
			continue
		}
		if p.pos < len(p.data) && p.data[p.pos] == ']' {
			p.pos++
			return append(out, ']'), nil
		}
		return nil, p.errorf(ErrSyntax, "expected ',' or ']'")
	}
}

// number parses an integer literal at p.pos and appends it unchanged: the
// accepted grammar admits a single spelling per value.
func (p *parser) number(out []byte) ([]byte, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	digits := p.pos
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
	}
	lit := p.data[start:p.pos]
	n := p.pos - digits
	switch {
	case n == 0:
		return nil, p.errorf(ErrSyntax, "expected a digit")
	case n > 1 && p.data[digits] == '0':
		return nil, p.errorf(ErrNumber, "leading zero in %q", lit)
	case string(lit) == "-0":
		return nil, p.errorf(ErrNumber, "negative zero")
	}
	if p.pos < len(p.data) {
		switch p.data[p.pos] {
		case '.', 'e', 'E':
			return nil, p.errorf(ErrNumber, "fraction or exponent after %q, only integer literals are accepted", lit)
		}
	}
	// 2^53-1 has 16 digits; a 16-digit value fits an int64 easily.
	if n > 16 || parseDigits(p.data[digits:p.pos]) > MaxSafeInteger {
		return nil, p.errorf(ErrNumber, "magnitude of %q above 2^53-1", lit)
	}
	return append(out, lit...), nil
}

// parseDigits returns the value of at most 16 ASCII decimal digits.
func parseDigits(d []byte) int64 {
	var v int64
	for _, c := range d {
		v = v*10 + int64(c-'0')
	}
	return v
}

// str parses a string at p.pos (on its opening quote) and returns its
// decoded value, which is valid UTF-8 without surrogate code points.
func (p *parser) str() (string, error) {
	p.pos++ // '"'
	var b []byte
	for {
		if p.pos >= len(p.data) {
			return "", p.errorf(ErrSyntax, "unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(b), nil
		case c == '\\':
			r, err := p.escape()
			if err != nil {
				return "", err
			}
			b = utf8.AppendRune(b, r)
		case c < 0x20:
			return "", p.errorf(ErrSyntax, "unescaped control character %#02x in string", c)
		case c < utf8.RuneSelf:
			b = append(b, c)
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size == 1 {
				return "", p.errorf(ErrUTF8, "invalid UTF-8 byte %#02x", c)
			}
			b = append(b, p.data[p.pos:p.pos+size]...)
			p.pos += size
		}
	}
}

// escape decodes the escape sequence at p.pos (on its backslash) and
// returns the character it stands for. A \u high surrogate must be followed
// by a \u low surrogate; any other surrogate is rejected.
func (p *parser) escape() (rune, error) {
	if p.pos+1 >= len(p.data) {
		p.pos++
		return 0, p.errorf(ErrSyntax, "unterminated escape")
	}
	c := p.data[p.pos+1]
	if r, ok := shortEscapes[c]; ok {
		p.pos += 2
		return r, nil
	}
	if c != 'u' {
		p.pos++
		return 0, p.errorf(ErrSyntax, "invalid escape \\%c", c)
	}
	r1, err := p.hex4()
	if err != nil {
		return 0, err
	}
	if !utf16.IsSurrogate(r1) {
		return r1, nil
	}
	if r1 >= 0xDC00 {
		return 0, p.errorf(ErrUTF8, "lone low surrogate \\u%04x", r1)
	}
	if !bytes.HasPrefix(p.data[p.pos:], []byte(`\u`)) {
		return 0, p.errorf(ErrUTF8, "lone high surrogate \\u%04x", r1)
	}
	r2, err := p.hex4()
	if err != nil {
		return 0, err
	}
	r := utf16.DecodeRune(r1, r2)
	if r == utf8.RuneError {
		return 0, p.errorf(ErrUTF8, "high surrogate \\u%04x followed by \\u%04x", r1, r2)
	}
	return r, nil
}

// shortEscapes maps the character after a backslash to its value, for every
// escape except \u.
var shortEscapes = map[byte]rune{
	'"': '"', '\\': '\\', '/': '/',
	'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t',
}

// hex4 decodes a \uXXXX sequence at p.pos (on its backslash).
func (p *parser) hex4() (rune, error) {
	p.pos += 2 // `\u`
	if p.pos+4 > len(p.data) {
		return 0, p.errorf(ErrSyntax, "truncated \\u escape")
	}
	var r rune
	for _, c := range p.data[p.pos : p.pos+4] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, p.errorf(ErrSyntax, "invalid hexadecimal digit %q in \\u escape", c)
		}
		r = r<<4 | rune(d)
	}
	p.pos += 4
	return r, nil
}

// appendString appends the RFC 8785 serialization of s, a valid UTF-8
// string, to out.
func appendString(out []byte, s string) []byte {
	const hex = "0123456789abcdef"
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			out = append(out, '\\', c)
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if c < 0x20 {
				out = append(out, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xF])
			} else {
				out = append(out, c)
			}
		}
	}
	return append(out, '"')
}

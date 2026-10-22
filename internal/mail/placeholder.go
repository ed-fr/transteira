package mail

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ed-fr/transteira/internal/mail/sanitize"
)

// The variable syntax of mail templates (decision of step 11, threat T-82):
// a template is literal text with {{name}} placeholders, where name matches
// [a-z][a-z0-9_]* (at most 64 characters), optionally surrounded by one space
// on each side inside the braces ("{{ name }}"). There is no logic at all: no
// field access, no function, no pipeline, no condition, no loop, no comment.
// Everything else that looks like template syntax ("{{" or "}}" outside a
// valid placeholder) is refused with its position. As a consequence, a
// literal "{{" or "}}" cannot be written in a template; a single brace can.

// maxVarName bounds the length of a variable name.
const maxVarName = 64

// tpiece is a part of a template: literal text, or a placeholder.
type tpiece struct {
	text   string // literal text, when name is empty
	name   string // placeholder name
	offset int    // byte offset of the piece in the source
}

// syntaxError is a template syntax error at a byte offset.
type syntaxError struct {
	offset int
	reason string
}

func (e *syntaxError) Error() string {
	return fmt.Sprintf("at byte %d: %s", e.offset, e.reason)
}

// parsePlaceholders splits s into literal text and placeholders.
func parsePlaceholders(s string) ([]tpiece, *syntaxError) {
	var out []tpiece
	pos := 0
	for pos < len(s) {
		open := strings.Index(s[pos:], "{{")
		closeAt := strings.Index(s[pos:], "}}")
		if closeAt >= 0 && (open < 0 || closeAt < open) {
			return nil, &syntaxError{offset: pos + closeAt, reason: `"}}" without a matching "{{"`}
		}
		if open < 0 {
			out = append(out, tpiece{text: s[pos:], offset: pos})
			break
		}
		start := pos + open
		if open > 0 {
			out = append(out, tpiece{text: s[pos:start], offset: pos})
		}
		end := strings.Index(s[start+2:], "}}")
		if end < 0 {
			return nil, &syntaxError{offset: start, reason: `"{{" is not closed by "}}"`}
		}
		content := s[start+2 : start+2+end]
		name, reason := placeholderName(content)
		if reason != "" {
			return nil, &syntaxError{offset: start, reason: reason}
		}
		out = append(out, tpiece{name: name, offset: start})
		pos = start + 2 + end + 2
	}
	return out, nil
}

// templateKeywords are the actions of Go templates, refused explicitly.
var templateKeywords = map[string]bool{
	"if": true, "else": true, "end": true, "range": true, "with": true, "define": true,
	"template": true, "block": true, "break": true, "continue": true, "nil": true,
}

// placeholderName returns the variable name of the content of a
// placeholder (between the braces), or why it is refused.
func placeholderName(content string) (name, reason string) {
	n := strings.TrimPrefix(content, " ")
	n = strings.TrimSuffix(n, " ")
	if isVarName(n) && !templateKeywords[n] {
		return n, ""
	}
	t := strings.TrimSpace(content)
	first, _, _ := strings.Cut(t, " ")
	switch {
	case strings.Contains(content, "{"):
		return "", "nested braces are not allowed"
	case t == "":
		return "", "empty placeholder"
	case isVarName(t) && !templateKeywords[t]:
		return "", "at most one space is allowed on each side of the name"
	case strings.HasPrefix(t, "-") || strings.HasSuffix(t, "-"):
		return "", "trim markers are not supported; write {{name}}"
	case strings.HasPrefix(t, "/*"):
		return "", "comments are not supported"
	case strings.HasPrefix(t, ".") || strings.HasPrefix(t, "$"):
		return "", "field and variable access are not supported; write {{name}}"
	case strings.Contains(t, "|"):
		return "", "pipelines are not supported"
	case templateKeywords[first]:
		return "", "template logic (if, range, define...) is not supported"
	case strings.ContainsAny(t, " \t\r\n(\"'`"):
		return "", "functions and arguments are not supported"
	}
	return "", fmt.Sprintf("invalid variable name %q: use lowercase letters, digits and underscores, starting with a letter", t)
}

// isVarName reports whether s matches [a-z][a-z0-9_]{0,63}.
func isVarName(s string) bool {
	if s == "" || len(s) > maxVarName || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// splitter adapts parsePlaceholders to the sanitizer.
func splitter(s string) ([]sanitize.Piece, error) {
	pieces, se := parsePlaceholders(s)
	if se != nil {
		return nil, errors.New(se.reason)
	}
	out := make([]sanitize.Piece, len(pieces))
	for i, p := range pieces {
		out[i] = sanitize.Piece{Text: p.text, Placeholder: p.name}
	}
	return out, nil
}

// lineCol converts a byte offset of s into a 1-based line and column (in
// runes).
func lineCol(s string, offset int) (line, col int) {
	line, col = 1, 1
	for _, r := range s[:offset] {
		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

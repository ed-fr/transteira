package mail

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/mail/sanitize"
)

// ErrInvalidTemplate is wrapped by the [*ValidationError] of a template that
// cannot be used.
var ErrInvalidTemplate = errors.New("mail: invalid template")

// Template parts, as reported in an [Issue].
const (
	PartSubject = "subject"
	PartHTML    = "html"
	PartText    = "text"
)

// Issue is one problem of a template.
type Issue struct {
	// Part is the part of the template: [PartSubject], [PartHTML] or
	// [PartText].
	Part string
	// Line and Column locate the problem in the part (1-based, the column
	// counted in characters); both are 0 when the problem has no position
	// (a missing variable, an attribute found after HTML decoding...).
	Line, Column int
	// Message explains the problem, in English.
	Message string
}

// String formats the issue as "part line L, column C: message".
func (i Issue) String() string {
	if i.Line == 0 {
		return i.Part + ": " + i.Message
	}
	return fmt.Sprintf("%s line %d, column %d: %s", i.Part, i.Line, i.Column, i.Message)
}

// ValidationError lists the problems of a template. It wraps
// [ErrInvalidTemplate].
type ValidationError struct {
	// Issues lists the problems, in the order subject, HTML, text.
	Issues []Issue
}

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		parts[i] = is.String()
	}
	return "mail: invalid template: " + strings.Join(parts, "; ")
}

// Unwrap returns [ErrInvalidTemplate].
func (*ValidationError) Unwrap() error { return ErrInvalidTemplate }

// SanitizeHTML filters HTML through the allowlist of package sanitize (see
// its documentation for the exact policy). Braces are plain text: use
// [NormalizeTemplate] for a template body.
func SanitizeHTML(s string) string { return sanitize.HTML(s) }

// ValidateTemplate checks a customization of template key: sizes (subject
// of 1 to [MaxSubjectLen] characters, bodies of at most [MaxBodyLen]
// characters, valid UTF-8), the {{name}} syntax, unknown variables, blocks
// in the subject or in an attribute, non-URL variables in href,
// placeholders in other attributes, required variables (in both bodies,
// and in the HTML body as text or as a link, not only in a title or alt),
// and bodies that are empty once sanitized. The error is a
// [*ValidationError], or wraps [ErrUnknownTemplate].
func ValidateTemplate(key, subject, html, text string) error {
	name, _, err := lookupKey(key)
	if err != nil {
		return err
	}
	_, err = compileTemplate(name, TemplateSource{Subject: subject, HTML: html, Text: text})
	return err
}

// NormalizeTemplate validates a customization like [ValidateTemplate] and
// returns the form to store: the HTML body sanitized (re-serialized, with
// its placeholders), the text body with LF line breaks, the subject
// trimmed.
func NormalizeTemplate(key string, src TemplateSource) (TemplateSource, error) {
	name, _, err := lookupKey(key)
	if err != nil {
		return TemplateSource{}, err
	}
	c, err := compileTemplate(name, src)
	if err != nil {
		return TemplateSource{}, err
	}
	return TemplateSource{
		Subject: strings.TrimSpace(src.Subject),
		HTML:    sanitize.Join(c.html),
		Text:    normalizeNewlines(src.Text),
	}, nil
}

// checker accumulates the issues of a template.
type checker struct {
	vars    []varSpec
	specs   map[string]varSpec
	issues  []Issue
	unknown map[string]bool // unknown names already reported
}

// add records an issue.
func (c *checker) add(part string, line, col int, format string, args ...any) {
	c.issues = append(c.issues, Issue{Part: part, Line: line, Column: col, Message: fmt.Sprintf(format, args...)})
}

// compileTemplate validates src as a template of name (a known key) and
// compiles it.
func compileTemplate(name string, src TemplateSource) (*compiled, error) {
	def := keyDefs[name]
	c := &checker{vars: def.vars, specs: def.specs(), unknown: map[string]bool{}}
	out := &compiled{}
	c.sizes(src)
	if len(c.issues) > 0 {
		return nil, &ValidationError{Issues: c.issues}
	}
	out.subject = c.pieces(PartSubject, src.Subject)
	html := c.pieces(PartHTML, src.HTML)
	out.text = c.pieces(PartText, src.Text)
	if html != nil {
		out.html = c.sanitized(src.HTML)
	}
	if len(c.issues) > 0 {
		return nil, &ValidationError{Issues: c.issues}
	}
	c.required(out)
	if len(c.issues) > 0 {
		return nil, &ValidationError{Issues: c.issues}
	}
	return out, nil
}

// sizes checks the sizes and encoding of the parts.
func (c *checker) sizes(src TemplateSource) {
	for _, p := range []struct {
		part, s  string
		max      int
		required bool
	}{
		{PartSubject, src.Subject, MaxSubjectLen, true},
		{PartHTML, src.HTML, MaxBodyLen, true},
		{PartText, src.Text, MaxBodyLen, true},
	} {
		switch {
		case !utf8.ValidString(p.s):
			c.add(p.part, 0, 0, "invalid UTF-8")
		case utf8.RuneCountInString(p.s) > p.max:
			c.add(p.part, 0, 0, "longer than %d characters", p.max)
		case p.required && strings.TrimSpace(p.s) == "":
			c.add(p.part, 0, 0, "empty")
		}
	}
}

// pieces parses a part and checks its variables; it returns nil after a
// syntax error.
func (c *checker) pieces(part, s string) []tpiece {
	pieces, se := parsePlaceholders(s)
	if se != nil {
		line, col := lineCol(s, se.offset)
		c.add(part, line, col, "%s", se.reason)
		return nil
	}
	for _, p := range pieces {
		if p.name == "" {
			continue
		}
		spec, ok := c.specs[p.name]
		line, col := lineCol(s, p.offset)
		switch {
		case !ok:
			c.unknown[p.name] = true
			c.add(part, line, col, "unknown variable {{%s}}", p.name)
		case part == PartSubject && spec.kind == VarBlock:
			c.add(part, line, col, "block variable {{%s}} is not allowed in the subject", p.name)
		}
	}
	return pieces // not nil: sizes rejected empty parts
}

// sanitized sanitizes the HTML body and checks where its placeholders are.
func (c *checker) sanitized(s string) []sanitize.Segment {
	segs, err := sanitize.Template(s, splitter)
	if err != nil {
		for _, e := range strings.Split(err.Error(), "\n") {
			c.add(PartHTML, 0, 0, "%s", e)
		}
		return nil
	}
	visible := false
	for _, seg := range segs {
		if seg.Placeholder == "" {
			continue
		}
		spec, ok := c.specs[seg.Placeholder]
		switch {
		case !ok:
			if !c.unknown[seg.Placeholder] {
				c.unknown[seg.Placeholder] = true
				c.add(PartHTML, 0, 0, "unknown variable {{%s}}", seg.Placeholder)
			}
		case seg.Context == sanitize.Attr && spec.kind == VarBlock:
			c.add(PartHTML, 0, 0, "block variable {{%s}} is not allowed in an attribute", seg.Placeholder)
		case seg.Context == sanitize.URL && spec.kind != VarURL:
			c.add(PartHTML, 0, 0, "variable {{%s}} is not a URL and cannot be used in href", seg.Placeholder)
		case seg.Context == sanitize.Text:
			visible = true
		}
	}
	if !visible && !sanitize.HasContent(sanitize.Join(segs)) {
		c.add(PartHTML, 0, 0, "empty once sanitized")
	}
	return segs
}

// required checks that every required variable appears in both bodies. In
// the HTML body only visible occurrences count: in element content, or as
// the href of a link (URL variables); one in a title or alt attribute does
// not, since the recipient may never see it.
func (c *checker) required(out *compiled) {
	inHTML := map[string]bool{}
	for _, seg := range out.html {
		if seg.Context == sanitize.Text || seg.Context == sanitize.URL {
			inHTML[seg.Placeholder] = true
		}
	}
	inText := map[string]bool{}
	for _, p := range out.text {
		inText[p.name] = true
	}
	for _, v := range c.vars {
		if !v.required {
			continue
		}
		if !inHTML[v.name] {
			c.add(PartHTML, 0, 0, "required variable {{%s}} is missing", v.name)
		}
		if !inText[v.name] {
			c.add(PartText, 0, 0, "required variable {{%s}} is missing", v.name)
		}
	}
}

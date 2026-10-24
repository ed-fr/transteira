package mail

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/mail/sanitize"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// Every mail is rendered through the variable engine (approach A of step
// 11): the default templates are written in the same {{name}} syntax as the
// tenant customizations, they are the single source of truth, and a
// customization replaces them as a whole. A template has three parts:
//
//   - the subject, a single line: values are inserted raw, then control,
//     line-separator and format characters are removed or turned into
//     spaces and whitespace is collapsed, so that no header can be injected;
//   - the HTML body, the content of the mail page: it is sanitized by the
//     allowlist of package sanitize, then values are HTML-escaped in text,
//     escaped for attributes in title and alt, and URL values are checked
//     (http, https or mailto, else "#") in href. Blocks are trusted HTML
//     produced by this package. The page around the content (doctype, head
//     with the subject as title, body and its layout styles) is fixed;
//   - the text body: values are inserted raw, with CR and CRLF turned into
//     LF.
//
// A block that renders empty also removes the line breaks that follow it,
// as many as precede it (at most two), so that a block written alone on its
// line, or as a paragraph of its own in the text body, leaves no blank line.

//go:embed templates
var defaultTemplateFS embed.FS

// Template file layout: <lang>/<name>.<part>.tmpl, part being subject, html
// or text; the three parts are mandatory.
const (
	partSubject = "subject"
	partText    = "text"
	partHTML    = "html"
	tmplSuffix  = ".tmpl"
)

// Size limits of a template, in runes (see the EmailTemplateUpdate schema).
const (
	MaxSubjectLen = 255
	MaxBodyLen    = 100000
)

// TemplateSource is the source of a template, in the {{name}} syntax.
type TemplateSource struct {
	// Subject is the subject line.
	Subject string
	// HTML is the content of the HTML body.
	HTML string
	// Text is the plain-text body.
	Text string
}

// compiled is a validated template.
type compiled struct {
	subject []tpiece
	text    []tpiece
	html    []sanitize.Segment
}

// defaultSet is a default template in one language.
type defaultSet struct {
	src TemplateSource
	c   *compiled
}

// Templates renders mail templates in the supported languages. The default
// templates are parsed and validated once, at construction. A Templates is
// read-only afterwards and safe for concurrent use.
type Templates struct {
	sets map[string]map[string]*defaultSet // name -> lang -> set
}

// defaultTemplates is the set embedded in the binary.
var defaultTemplates = mustDefaultTemplates()

// mustDefaultTemplates parses the embedded templates; a broken embedded
// template is a build defect, caught by the tests.
func mustDefaultTemplates() *Templates {
	sub, _ := fs.Sub(defaultTemplateFS, "templates") // constant, valid path
	return mustTemplates(NewTemplates(sub))
}

// mustTemplates panics on err.
func mustTemplates(t *Templates, err error) *Templates {
	if err != nil {
		panic(err)
	}
	return t
}

// DefaultTemplates returns the built-in French and English templates.
func DefaultTemplates() *Templates {
	return defaultTemplates
}

// Render renders a built-in template; see [Templates.Render].
func Render(name, lang string, data any) (Message, error) {
	return defaultTemplates.Render(name, lang, data)
}

// RenderOverride renders a template with an optional customization; see
// [Templates.RenderOverride].
func RenderOverride(name, lang string, data any, override *TemplateSource) (Message, error) {
	return defaultTemplates.RenderOverride(name, lang, data, override)
}

// Preview renders a template with sample data; see [Templates.Preview].
func Preview(key, lang string, override *TemplateSource) (Message, error) {
	return defaultTemplates.Preview(key, lang, override)
}

// DefaultSource returns the source of a built-in template; see
// [Templates.Source].
func DefaultSource(key, lang string) (TemplateSource, error) {
	return defaultTemplates.Source(key, lang)
}

// NewTemplates reads every <lang>/<name>.<part>.tmpl file of fsys, name
// being a template key ([TemplateNames]). Unknown languages, keys or parts,
// files outside that layout, a template lacking a part and a template that
// fails [ValidateTemplate] are errors.
func NewTemplates(fsys fs.FS) (*Templates, error) {
	raw := map[string]map[string]*TemplateSource{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		return readPart(fsys, p, raw)
	})
	if err != nil {
		return nil, fmt.Errorf("mail: templates: %w", err)
	}
	t := &Templates{sets: map[string]map[string]*defaultSet{}}
	for name, langs := range raw {
		t.sets[name] = map[string]*defaultSet{}
		for lang, src := range langs {
			if src.Subject == "" || src.HTML == "" || src.Text == "" {
				return nil, fmt.Errorf("mail: templates: %s/%s lacks a part", lang, name)
			}
			c, err := compileTemplate(name, *src)
			if err != nil {
				return nil, fmt.Errorf("mail: templates: %s/%s: %w", lang, name, err)
			}
			t.sets[name][lang] = &defaultSet{src: *src, c: c}
		}
	}
	return t, nil
}

// readPart reads one template file into raw.
func readPart(fsys fs.FS, p string, raw map[string]map[string]*TemplateSource) error {
	lang, file := path.Split(p)
	lang = strings.TrimSuffix(lang, "/")
	if !i18n.IsSupported(lang) || !strings.HasSuffix(file, tmplSuffix) {
		return fmt.Errorf("unexpected file %q", p)
	}
	name, part, ok := strings.Cut(strings.TrimSuffix(file, tmplSuffix), ".")
	if _, known := keyDefs[name]; !ok || !known {
		return fmt.Errorf("unexpected file %q", p)
	}
	b, err := fs.ReadFile(fsys, p)
	if err != nil {
		return err
	}
	if raw[name] == nil {
		raw[name] = map[string]*TemplateSource{}
	}
	src := raw[name][lang]
	if src == nil {
		src = &TemplateSource{}
		raw[name][lang] = src
	}
	switch part {
	case partSubject:
		src.Subject = strings.TrimRight(string(b), "\r\n")
	case partHTML:
		src.HTML = string(b)
	case partText:
		src.Text = string(b)
	default:
		return fmt.Errorf("unexpected file %q", p)
	}
	return nil
}

// Names returns the sorted template names.
func (t *Templates) Names() []string {
	names := make([]string, 0, len(t.sets))
	for n := range t.sets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// set returns the default template of key in lang, falling back to
// [i18n.Default], and the language used.
func (t *Templates) set(key, lang string) (string, *defaultSet, string, error) {
	name := keyName(key)
	langs, ok := t.sets[name]
	if !ok {
		return "", nil, "", fmt.Errorf("%w: %q", ErrUnknownTemplate, key)
	}
	set, ok := langs[lang]
	if !ok {
		lang = i18n.Default
		if set, ok = langs[lang]; !ok {
			return "", nil, "", fmt.Errorf("%w: %q has no %q version", ErrUnknownTemplate, key, lang)
		}
	}
	return name, set, lang, nil
}

// Source returns the source of the default template of key in lang (or in
// [i18n.Default] when lang has none): the template an administrator starts
// from, and the one used again after a reset. Errors wrap
// [ErrUnknownTemplate].
func (t *Templates) Source(key, lang string) (TemplateSource, error) {
	_, set, _, err := t.set(key, lang)
	if err != nil {
		return TemplateSource{}, err
	}
	return set.src, nil
}

// Render renders the default template name in lang with data, falling back
// to [i18n.Default] when the template does not exist in lang. data must be
// the data type of the template (for example [VerificationCodeData]). The
// returned [Message] has Subject, Text, HTML and Language (the language
// actually used) set; the caller sets To and any inline part. Errors wrap
// [ErrUnknownTemplate] or report a wrong data type.
func (t *Templates) Render(name, lang string, data any) (Message, error) {
	return t.RenderOverride(name, lang, data, nil)
}

// RenderOverride renders like [Templates.Render], with the customization
// override of the tenant instead of the default template when it is not
// nil. override must be the customization of the language actually used
// (lang when the default template exists in lang). An invalid override is
// an error wrapping [ErrInvalidTemplate].
func (t *Templates) RenderOverride(name, lang string, data any, override *TemplateSource) (Message, error) {
	name, set, lang, err := t.set(name, lang)
	if err != nil {
		return Message{}, err
	}
	c := set.c
	if override != nil {
		if c, err = compileTemplate(name, *override); err != nil {
			return Message{}, err
		}
	}
	def := keyDefs[name]
	vals, ok := def.values(labelsFor(lang), lang, data)
	if !ok {
		return Message{}, fmt.Errorf("mail: render %s: unexpected data type %T", name, data)
	}
	return c.render(lang, vals), nil
}

// OverrideLookup returns the customization of template name in lang for a
// tenant, or nil when the tenant uses the default template.
type OverrideLookup func(ctx context.Context, tenantID, name, lang string) (*TemplateSource, error)

// RenderFor renders template name for a tenant: the customization returned
// by lookup for the language actually used when there is one, the default
// template otherwise. A lookup error is returned. A stored customization
// that no longer validates (validation rules made stricter after it was
// saved) is ignored and the default template is used, so that the mails of
// the tenant keep working.
func (t *Templates) RenderFor(ctx context.Context, lookup OverrideLookup, tenantID, name, lang string, data any) (Message, error) {
	name, _, effective, err := t.set(name, lang)
	if err != nil {
		return Message{}, err
	}
	override, err := lookup(ctx, tenantID, name, effective)
	if err != nil {
		return Message{}, fmt.Errorf("mail: render %s: template lookup: %w", name, err)
	}
	if override != nil {
		if m, err := t.RenderOverride(name, effective, data, override); err == nil {
			return m, nil
		}
	}
	return t.Render(name, effective, data)
}

// Preview renders template key in lang with the sample data of the key
// (see [Variables]): override when not nil, else the default template.
// The HTML of a preview is shown inside the administration, whose CSP
// blocks inline styles and "cid:" images: its style attributes and style
// elements are removed and its images replaced by their alt text
// ([sanitize.ForPreview]), so a preview shows the structure and content of
// the mail without its styles; the mails sent keep them.
// Errors wrap [ErrUnknownTemplate] or [ErrInvalidTemplate].
func (t *Templates) Preview(key, lang string, override *TemplateSource) (Message, error) {
	name, _, err := lookupKey(key)
	if err != nil {
		return Message{}, err
	}
	m, err := t.RenderOverride(name, lang, keyDefs[name].sample, override)
	if err != nil {
		return Message{}, err
	}
	m.HTML = sanitize.ForPreview(m.HTML)
	return m, nil
}

// --- Rendering ---------------------------------------------------------------

// HTML page around the content of the HTML body.
const (
	htmlPageStart = "<!DOCTYPE html>\n<html lang=\"%s\">\n<head>\n<meta charset=\"utf-8\">\n" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>%s</title>\n</head>\n" +
		"<body style=\"margin:0;padding:24px;background-color:#ffffff;color:#1a1a1a;" +
		"font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:1.5;\">\n" +
		"<div role=\"main\" style=\"max-width:560px;margin:0 auto;\">\n"
	htmlPageEnd = "\n</div>\n</body>\n</html>\n"
)

// render renders a compiled template with vals.
func (c *compiled) render(lang string, vals map[string]value) Message {
	var subject strings.Builder
	for _, p := range c.subject {
		if p.name == "" {
			subject.WriteString(p.text)
		} else {
			subject.WriteString(vals[p.name].text)
		}
	}
	s := subjectLine(subject.String())

	var text writer
	for _, p := range c.text {
		if p.name == "" {
			text.literal(p.text)
		} else {
			text.value(normalizeNewlines(vals[p.name].text))
		}
	}

	var body writer
	for _, seg := range c.html {
		if seg.Placeholder == "" {
			body.literal(seg.Literal)
			continue
		}
		v := vals[seg.Placeholder]
		switch {
		case seg.Context == sanitize.URL:
			body.value(esc(linkURL(v.text)))
		case v.kind == VarBlock:
			body.value(string(v.html))
		default:
			body.value(esc(v.text))
		}
	}
	page := fmt.Sprintf(htmlPageStart, lang, esc(s)) + strings.Trim(body.b.String(), " \t\r\n") + htmlPageEnd
	return Message{
		Subject:  s,
		Text:     strings.TrimRight(text.b.String(), " \t\r\n") + "\n",
		HTML:     page,
		Language: lang,
	}
}

// writer assembles a body, removing the line breaks after an empty value.
type writer struct {
	b    strings.Builder
	skip int // line breaks to remove at the start of the next literal
}

// literal writes template text.
func (w *writer) literal(s string) {
	if w.skip > 0 {
		n := 0
		for n < w.skip && n < len(s) && s[n] == '\n' {
			n++
		}
		s = s[n:]
		w.skip = 0
	}
	w.b.WriteString(s)
}

// value writes a value; an empty one schedules the removal of as many line
// breaks as precede it (at most two).
func (w *writer) value(s string) {
	if s != "" {
		w.skip = 0
		w.b.WriteString(s)
		return
	}
	cur := w.b.String()
	n := 0
	for n < 2 && n < len(cur) && cur[len(cur)-1-n] == '\n' {
		n++
	}
	w.skip = n
}

// normalizeNewlines turns CRLF and CR into LF.
func normalizeNewlines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// subjectLine makes a header-safe subject: control and line-separator
// characters become spaces, format and invisible characters (bidirectional
// controls...) are removed, whitespace is collapsed and the line is cut to
// the limit of [Build].
func subjectLine(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case textsafe.IsControl(r) || textsafe.IsLineSeparator(r):
			return ' '
		case textsafe.IsFormat(r) || textsafe.IsInvisible(r):
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxSubjectLen {
		s = strings.TrimRight(string(r[:maxSubjectLen-1]), " ") + "…"
	}
	return s
}

// linkURL returns u when it is an http, https or mailto URL without
// whitespace or control character, else "#". URL values are built by the
// server; the check is a last line of defense (threat T-87).
func linkURL(u string) string {
	lower := strings.ToLower(u)
	if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "mailto:") {
		return "#"
	}
	for _, r := range u {
		if r <= ' ' || r == 0x7f {
			return "#"
		}
	}
	return u
}

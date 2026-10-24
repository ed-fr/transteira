// Package sanitize filters HTML written by administrators (mail templates,
// legal documents) through a strict allowlist (threats T-82 and T-87).
//
// The input is parsed with golang.org/x/net/html as a fragment of a <div>,
// and the output is always re-serialized from the parsed tree, never copied
// from the input. The policy is:
//
//   - allowed elements: p, br, strong, b, em, i, u, ul, ol, li, h1 to h4, a,
//     table, thead, tbody, tfoot, tr, td, th, blockquote, hr, span, div and
//     img (tfoot is kept so that unwrapping it can never leave stray content
//     inside a table);
//   - removed with their content: script, style, iframe, frame, frameset,
//     object, embed, applet, form, input, button, select, option, textarea,
//     link, meta, base, svg, math, noscript, template, title, head, xmp,
//     plaintext, noembed, noframes, marquee, audio, video, canvas, caption,
//     colgroup and col;
//   - any other element is unwrapped: it disappears and its content stays;
//   - comments (conditional comments included) and doctypes are removed;
//   - allowed attributes: title and style on every allowed element, href on
//     a (https: or mailto: only), src on img ("cid:" only: an img without
//     such a source is removed, so no remote image survives), alt, width and
//     height on img, align, width and height on table, td and th. Every
//     other attribute, on* handlers included, is removed;
//   - URLs are checked after entity decoding, with ASCII whitespace and
//     control characters removed, so "jav&#x09;ascript:" is refused;
//   - style keeps only declarations whose property is in a small allowlist
//     (colors, text alignment and decoration, fonts, spacing, borders, sizes,
//     white-space, word-break, vertical-align; not display, so that content
//     cannot be hidden) and whose value only
//     uses letters, digits, spaces and the characters # . , % ' -; there is
//     no parenthesis, slash, backslash, colon or semicolon in a value, so
//     url(), expression(), comments and escapes are impossible.
//
// Templates use the same filter through [Template], which also recognizes
// {{name}} placeholders: in text, in title and alt attributes, and as the
// whole value of href (a URL produced by the server, typed [URL]).
//
// [ForPreview] removes the inline styles and images of a rendered mail for
// the administration preview, whose CSP would block them.
package sanitize

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Context is where a placeholder appears in the sanitized HTML, which
// decides how its value must be escaped.
type Context int

// Placeholder contexts.
const (
	// Text is element content: the value is HTML-escaped, or trusted HTML.
	Text Context = iota
	// Attr is a quoted attribute value (title, alt): the value is escaped
	// for an attribute.
	Attr
	// URL is the whole value of an href attribute: the value must be a URL
	// whose scheme the caller checks, then escaped for an attribute.
	URL
)

// Piece is a part of a text split by a [Splitter]: literal text when
// Placeholder is empty, otherwise the name of a placeholder.
type Piece struct {
	// Text is the literal text (when Placeholder is empty).
	Text string
	// Placeholder is the placeholder name.
	Placeholder string
}

// Splitter splits a decoded text or attribute value into literal text and
// placeholders, or reports a syntax error.
type Splitter func(s string) ([]Piece, error)

// Segment is a part of a sanitized template: serialized HTML when
// Placeholder is empty, otherwise a placeholder and its context.
type Segment struct {
	// Literal is safe, serialized HTML.
	Literal string
	// Placeholder is the placeholder name.
	Placeholder string
	// Context is where the placeholder appears.
	Context Context
}

// ErrPlaceholder reports a placeholder at a place where it is not allowed.
var ErrPlaceholder = errors.New("sanitize: placeholder not allowed here")

// maxPasses bounds the passes that bring the output to a fixed point.
const maxPasses = 4

// HTML returns the sanitized form of src, without placeholder support:
// braces are plain text. The result is stable: HTML(HTML(s)) == HTML(s).
func HTML(src string) string {
	segs, _ := Template(src, nil) // no splitter: no error is possible
	return Join(segs)
}

// Template sanitizes src and returns it as segments. When split is not nil,
// text nodes, title and alt values and href values are split into
// placeholders; a placeholder elsewhere (style, src, width...), or an href
// mixing a placeholder with other text, is reported as an error wrapping
// [ErrPlaceholder], and errors of split are returned as well (joined). The
// segments are computed on a fixed point of the sanitizer, so that the
// result does not change when sanitized again.
func Template(src string, split Splitter) ([]Segment, error) {
	cur := src
	for range maxPasses {
		segs, err := pass(cur, split)
		if err != nil {
			return nil, err
		}
		next := Join(segs)
		if next == cur {
			return segs, nil
		}
		cur = next
	}
	return pass(cur, split)
}

// Join serializes segments, writing each placeholder as {{name}}.
func Join(segs []Segment) string {
	var b strings.Builder
	for _, s := range segs {
		if s.Placeholder != "" {
			b.WriteString("{{" + s.Placeholder + "}}")
		} else {
			b.WriteString(s.Literal)
		}
	}
	return b.String()
}

// pass runs the sanitizer once.
func pass(src string, split Splitter) ([]Segment, error) {
	ctx := &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div}
	// ParseFragment only fails on a reader error; strings.Reader never fails.
	nodes, _ := html.ParseFragment(strings.NewReader(src), ctx)
	w := &writer{split: split}
	for _, n := range nodes {
		w.node(n)
	}
	w.flush()
	return w.segs, errors.Join(w.errs...)
}

// writer accumulates the segments of a sanitized tree.
type writer struct {
	split Splitter
	segs  []Segment
	buf   strings.Builder
	errs  []error
}

// flush moves the pending literal into a segment.
func (w *writer) flush() {
	if w.buf.Len() > 0 {
		w.segs = append(w.segs, Segment{Literal: w.buf.String()})
		w.buf.Reset()
	}
}

// placeholder appends a placeholder segment.
func (w *writer) placeholder(name string, c Context) {
	w.flush()
	w.segs = append(w.segs, Segment{Placeholder: name, Context: c})
}

// allowed lists the elements kept.
var allowed = map[atom.Atom]bool{
	atom.P: true, atom.Br: true, atom.Strong: true, atom.B: true, atom.Em: true, atom.I: true, atom.U: true,
	atom.Ul: true, atom.Ol: true, atom.Li: true, atom.H1: true, atom.H2: true, atom.H3: true, atom.H4: true,
	atom.A: true, atom.Table: true, atom.Thead: true, atom.Tbody: true, atom.Tfoot: true, atom.Tr: true,
	atom.Td: true, atom.Th: true, atom.Blockquote: true, atom.Hr: true, atom.Span: true, atom.Div: true,
	atom.Img: true,
}

// dropped lists the elements removed with their content.
var dropped = map[string]bool{
	"script": true, "style": true, "iframe": true, "frame": true, "frameset": true, "object": true,
	"embed": true, "applet": true, "form": true, "input": true, "button": true, "select": true,
	"option": true, "optgroup": true, "textarea": true, "link": true, "meta": true, "base": true,
	"svg": true, "math": true, "noscript": true, "template": true, "title": true, "head": true,
	"xmp": true, "plaintext": true, "noembed": true, "noframes": true, "marquee": true, "audio": true,
	"video": true, "canvas": true, "caption": true, "colgroup": true, "col": true,
}

// void lists the allowed elements without end tag.
var void = map[atom.Atom]bool{atom.Br: true, atom.Hr: true, atom.Img: true}

// node writes one node and its subtree.
func (w *writer) node(n *html.Node) {
	switch n.Type {
	case html.TextNode:
		w.text(n.Data)
	case html.ElementNode:
		w.element(n)
	default: // comments, doctypes: removed
	}
}

// children writes the children of n.
func (w *writer) children(n *html.Node) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		w.node(c)
	}
}

// element writes an element according to the policy.
func (w *writer) element(n *html.Node) {
	if n.Namespace != "" || dropped[strings.ToLower(n.Data)] {
		return
	}
	if !allowed[n.DataAtom] {
		w.children(n)
		return
	}
	attrs, ok := w.attributes(n)
	if !ok {
		return // img without an allowed source
	}
	w.buf.WriteString("<" + n.Data)
	for _, a := range attrs {
		w.buf.WriteString(" " + a.key + `="`)
		for _, p := range a.parts {
			if p.Placeholder != "" {
				w.placeholder(p.Placeholder, a.ctx)
			} else {
				w.buf.WriteString(escapeAttr(p.Text))
			}
		}
		w.buf.WriteString(`"`)
	}
	w.buf.WriteString(">")
	if void[n.DataAtom] {
		return
	}
	w.children(n)
	w.buf.WriteString("</" + n.Data + ">")
}

// text writes a text node, split into placeholders when supported.
func (w *writer) text(s string) {
	s = strings.ReplaceAll(s, "\x00", "")
	if w.split == nil {
		w.buf.WriteString(escapeText(s))
		return
	}
	pieces, err := w.split(s)
	if err != nil {
		w.errs = append(w.errs, err)
		return
	}
	for _, p := range pieces {
		if p.Placeholder != "" {
			w.placeholder(p.Placeholder, Text)
		} else {
			w.buf.WriteString(escapeText(p.Text))
		}
	}
}

// attr is a kept attribute.
type attr struct {
	key   string
	parts []Piece
	ctx   Context
}

// attributes filters the attributes of n. ok is false for an img without an
// allowed source, which must be removed.
func (w *writer) attributes(n *html.Node) (out []attr, ok bool) {
	hasSrc := false
	// Only HTML elements get here: their attributes have no namespace.
	for _, a := range n.Attr {
		key := a.Key
		switch {
		case key == "title" || (key == "alt" && n.DataAtom == atom.Img):
			if parts, ok := w.splitValue(n, key, a.Val); ok {
				out = append(out, attr{key: key, parts: parts, ctx: Attr})
			}
		case key == "style":
			if w.noPlaceholder(n, key, a.Val) {
				if v := Style(a.Val); v != "" {
					out = append(out, attr{key: key, parts: []Piece{{Text: v}}})
				}
			}
		case key == "href" && n.DataAtom == atom.A:
			if a2, ok := w.href(n, a.Val); ok {
				out = append(out, a2)
			}
		case key == "src" && n.DataAtom == atom.Img:
			if !w.noPlaceholder(n, key, a.Val) {
				continue
			}
			if v, ok := cidURL(a.Val); ok {
				out = append(out, attr{key: key, parts: []Piece{{Text: v}}})
				hasSrc = true
			}
		case (key == "width" || key == "height") && sized[n.DataAtom]:
			if w.noPlaceholder(n, key, a.Val) && dimension.MatchString(a.Val) {
				out = append(out, attr{key: key, parts: []Piece{{Text: a.Val}}})
			}
		case key == "align" && aligned[n.DataAtom]:
			if v := strings.ToLower(strings.TrimSpace(a.Val)); w.noPlaceholder(n, key, a.Val) && alignments[v] {
				out = append(out, attr{key: key, parts: []Piece{{Text: v}}})
			}
		}
	}
	return out, n.DataAtom != atom.Img || hasSrc
}

// Attribute value rules.
var (
	sized      = map[atom.Atom]bool{atom.Img: true, atom.Table: true, atom.Td: true, atom.Th: true}
	aligned    = map[atom.Atom]bool{atom.Table: true, atom.Td: true, atom.Th: true}
	alignments = map[string]bool{"left": true, "center": true, "right": true, "justify": true}
	dimension  = regexp.MustCompile(`^[0-9]{1,4}%?$`)
	cidValue   = regexp.MustCompile(`^[A-Za-z0-9@._-]{1,100}$`)
)

// splitValue splits an attribute value into placeholders when supported.
func (w *writer) splitValue(n *html.Node, key, v string) ([]Piece, bool) {
	if w.split == nil {
		return []Piece{{Text: v}}, true
	}
	parts, err := w.split(v)
	if err != nil {
		w.errs = append(w.errs, fmt.Errorf("<%s %s>: %w", n.Data, key, err))
		return nil, false
	}
	return parts, true
}

// noPlaceholder reports whether v holds no placeholder; with a splitter, a
// placeholder is an error.
func (w *writer) noPlaceholder(n *html.Node, key, v string) bool {
	if w.split == nil {
		return true
	}
	parts, err := w.split(v)
	if err == nil {
		for _, p := range parts {
			if p.Placeholder != "" {
				err = ErrPlaceholder
				break
			}
		}
	}
	if err != nil {
		w.errs = append(w.errs, fmt.Errorf("<%s %s>: %w", n.Data, key, err))
		return false
	}
	return true
}

// href checks the href of a link: an https: or mailto: URL, or, in a
// template, a single placeholder (context [URL]).
func (w *writer) href(n *html.Node, v string) (attr, bool) {
	if w.split != nil {
		parts, err := w.split(strings.TrimSpace(v))
		if err != nil {
			w.errs = append(w.errs, fmt.Errorf("<%s href>: %w", n.Data, err))
			return attr{}, false
		}
		hasPlaceholder := false
		for _, p := range parts {
			hasPlaceholder = hasPlaceholder || p.Placeholder != ""
		}
		if hasPlaceholder {
			if len(parts) != 1 {
				w.errs = append(w.errs, fmt.Errorf("<%s href>: %w: a placeholder must be the whole URL", n.Data, ErrPlaceholder))
				return attr{}, false
			}
			return attr{key: "href", parts: parts, ctx: URL}, true
		}
	}
	u, ok := SafeURL(v)
	if !ok {
		return attr{}, false
	}
	return attr{key: "href", parts: []Piece{{Text: u}}}, true
}

// cleanURL removes ASCII whitespace and control characters, which browsers
// ignore inside URLs.
func cleanURL(v string) string {
	return strings.Map(func(r rune) rune {
		if r <= ' ' || r == 0x7f {
			return -1
		}
		return r
	}, v)
}

// SafeURL returns v without whitespace or control characters when it is an
// https: URL with a host ("https://...") or a mailto: URL, else false.
func SafeURL(v string) (string, bool) {
	u := cleanURL(v)
	lower := strings.ToLower(u)
	switch {
	case strings.HasPrefix(lower, "https://") && len(u) > len("https://") && len(u) <= 2048:
		return u, true
	case strings.HasPrefix(lower, "mailto:") && len(u) > len("mailto:") && len(u) <= 2048:
		return u, true
	}
	return "", false
}

// cidURL accepts a "cid:" URL of an inline part.
func cidURL(v string) (string, bool) {
	u := cleanURL(v)
	if len(u) < 4 || !strings.EqualFold(u[:4], "cid:") || !cidValue.MatchString(u[4:]) {
		return "", false
	}
	return "cid:" + u[4:], true
}

// styleProps lists the CSS properties kept in style attributes.
var styleProps = map[string]bool{
	"color": true, "background-color": true, "text-align": true, "text-decoration": true,
	"font-weight": true, "font-style": true, "font-size": true, "font-family": true,
	"line-height": true, "letter-spacing": true, "vertical-align": true, "white-space": true,
	"word-break": true, "width": true, "height": true, "max-width": true,
	"padding": true, "padding-top": true, "padding-right": true, "padding-bottom": true, "padding-left": true,
	"margin": true, "margin-top": true, "margin-right": true, "margin-bottom": true, "margin-left": true,
	"border": true, "border-top": true, "border-right": true, "border-bottom": true, "border-left": true,
	"border-color": true, "border-style": true, "border-width": true, "border-radius": true,
}

// styleValue is the only character set allowed in a CSS value.
var styleValue = regexp.MustCompile(`^[A-Za-z0-9#.,%' -]{1,200}$`)

// Style filters a style attribute: it keeps the declarations of allowed
// properties whose value matches the safe character set, serialized as
// "property:value;" with whitespace collapsed, or "" when none is left.
func Style(v string) string {
	var b strings.Builder
	for decl := range strings.SplitSeq(v, ";") {
		prop, val, ok := strings.Cut(decl, ":")
		if !ok {
			continue
		}
		prop = strings.ToLower(strings.TrimSpace(prop))
		val = strings.Join(strings.Fields(val), " ")
		if styleProps[prop] && styleValue.MatchString(val) {
			b.WriteString(prop + ":" + val + ";")
		}
	}
	return b.String()
}

// escapeText escapes element content.
func escapeText(s string) string {
	return textEscaper.Replace(s)
}

// escapeAttr escapes a double-quoted attribute value.
func escapeAttr(s string) string {
	return attrEscaper.Replace(s)
}

var (
	textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	attrEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;")
)

// EscapeAttr escapes a value for a double-quoted attribute, the way the
// sanitizer does.
func EscapeAttr(s string) string { return escapeAttr(s) }

// ForPreview returns the HTML document doc, a rendered mail, made fit for
// the administration preview of mail templates (threats T-91 and T-163),
// re-serialized from the parsed tree: style attributes and style elements
// are removed, and each image is replaced by its alt text in brackets (an
// image without alt text is removed). The strict CSP of the administration
// (style-src 'self', img-src 'self' data:) would block every inline style
// and every "cid:" image anyway, logging a CSP violation in the browser for
// each; a preview therefore shows the structure and content of the mail
// without its styles. The mails sent are not affected.
func ForPreview(doc string) string {
	root, _ := html.Parse(strings.NewReader(doc)) // strings.Reader never fails
	forPreview(root)
	var b strings.Builder
	// Render only fails on a writer error, or on a tree that the parser
	// never builds (a void element with children); strings.Builder never
	// fails.
	_ = html.Render(&b, root)
	return b.String()
}

// forPreview applies [ForPreview] to the subtree of n.
func forPreview(n *html.Node) {
	n.Attr = slices.DeleteFunc(n.Attr, func(a html.Attribute) bool {
		return a.Namespace == "" && strings.EqualFold(a.Key, "style")
	})
	for c := n.FirstChild; c != nil; {
		next := c.NextSibling
		switch {
		case c.Type != html.ElementNode:
		case c.DataAtom == atom.Style:
			n.RemoveChild(c)
		case c.DataAtom == atom.Img:
			if alt := strings.TrimSpace(attrValue(c, "alt")); alt != "" {
				n.InsertBefore(&html.Node{Type: html.TextNode, Data: "[" + alt + "]"}, c)
			}
			n.RemoveChild(c)
		default:
			forPreview(c)
		}
		c = next
	}
}

// attrValue returns the value of the attribute key of n, or "".
func attrValue(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Namespace == "" && a.Key == key {
			return a.Val
		}
	}
	return ""
}

// HasContent reports whether sanitized HTML shows something: text other
// than whitespace, or an image.
func HasContent(s string) bool {
	ctx := &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, _ := html.ParseFragment(strings.NewReader(s), ctx) // strings.Reader never fails
	var visit func(n *html.Node) bool
	visit = func(n *html.Node) bool {
		if (n.Type == html.TextNode && strings.TrimSpace(n.Data) != "") ||
			(n.Type == html.ElementNode && n.DataAtom == atom.Img) {
			return true
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if visit(c) {
				return true
			}
		}
		return false
	}
	for _, n := range nodes {
		if visit(n) {
			return true
		}
	}
	return false
}

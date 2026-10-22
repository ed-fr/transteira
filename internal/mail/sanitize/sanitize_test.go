package sanitize

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// xssVectors are classic payloads (OWASP XSS filter evasion cheat sheet
// style); none may survive sanitization.
var xssVectors = []string{
	`<script>alert(1)</script>`,
	`<SCRIPT SRC=https://xss.example/xss.js></SCRIPT>`,
	`<img src=x onerror=alert(1)>`,
	`<img src="javascript:alert('XSS');">`,
	`<IMG SRC=JaVaScRiPt:alert('XSS')>`,
	`<img src=https://evil.example/pixel.gif>`,
	`<img src="cid:qr@transteira" onerror="alert(1)">`,
	`<a href="javascript:alert(1)">x</a>`,
	`<a href="jav&#x09;ascript:alert(1)">x</a>`,
	`<a href="jav&#x0A;ascript:alert(1)">x</a>`,
	`<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">x</a>`,
	`<a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A;alert(1)">x</a>`,
	`<a href=" &#14;  javascript:alert(1)">x</a>`,
	`<a href="vbscript:msgbox(1)">x</a>`,
	`<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">x</a>`,
	`<a href="DATA:text/html,<script>alert(1)</script>">x</a>`,
	`<svg onload=alert(1)>`,
	`<svg><script>alert(1)</script></svg>`,
	`<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`,
	`<body onload=alert(1)>`,
	`<iframe src="https://evil.example"></iframe>`,
	`<iframe srcdoc="<script>alert(1)</script>"></iframe>`,
	`<object data="https://evil.example/x.swf"></object>`,
	`<embed src="https://evil.example/x.swf">`,
	`<form action="https://evil.example"><input name=p><button>go</button></form>`,
	`<link rel=stylesheet href="https://evil.example/x.css">`,
	`<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`,
	`<base href="javascript:alert(1)//">`,
	`<style>@import 'https://evil.example/x.css';</style>`,
	`<div style="background:url(javascript:alert(1))">x</div>`,
	`<div style="width:expression(alert(1))">x</div>`,
	`<div style="background-image:url('https://evil.example/t.gif')">x</div>`,
	`<div style="color:red;behavior:url(x.htc)">x</div>`,
	`<p style="color:\72 ed">x</p>`,
	`<div style="color:red/**/;position:fixed">x</div>`,
	`<p onclick="alert(1)" onmouseover=alert(1)>x</p>`,
	`<scr<script>ipt>alert(1)</scr</script>ipt>`,
	`<<script>alert(1)//<</script>`,
	`<img """><script>alert(1)</script>">`,
	`<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>`,
	`<template><script>alert(1)</script></template>`,
	`<!--[if gte IE 4]><script>alert(1)</script><![endif]-->`,
	`<![if !mso]><script>alert(1)</script><![endif]>`,
	`<!-- <script>alert(1)</script> -->`,
	`<textarea><script>alert(1)</script></textarea>`,
	`<xmp><script>alert(1)</script></xmp>`,
	`<title><script>alert(1)</script></title>`,
	`<marquee onstart=alert(1)>x</marquee>`,
	`<video><source onerror=alert(1)></video>`,
	`<details open ontoggle=alert(1)>`,
	`<a href="https://ok.example" target=_blank rel=opener>ok</a>`,
	`<table background="javascript:alert(1)"><tr><td background=x>y</td></tr></table>`,
	`<div><p><b><i><u><a href=javascript:alert(1)>deep</a></u></i></b></p></div>`,
	"<a href=\"java\x00script:alert(1)\">x</a>",
	`<img src="cid:x" srcset="https://evil.example/a.png 1x">`,
}

// unsafe checks the invariants of a sanitized output, on its parsed tree:
// only allowlisted elements (so no script), no on* attribute, href only
// https: or mailto:, img src only cid:, style only simple declarations
// without CSS function. Text may contain anything: it is escaped.
func unsafe(out string) string {
	ctx := &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, err := html.ParseFragment(strings.NewReader(out), ctx)
	if err != nil {
		return err.Error()
	}
	var why string
	var visit func(n *html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if !allowedName[n.Data] || n.Namespace != "" {
				why = "element " + n.Data
			}
			for _, a := range n.Attr {
				v := strings.ToLower(a.Val)
				switch {
				case strings.HasPrefix(a.Key, "on"):
					why = "attribute " + a.Key
				case a.Key == "href" && !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "mailto:"):
					why = "href " + v
				case a.Key == "src" && !strings.HasPrefix(v, "cid:"):
					why = "src " + v
				case a.Key == "style" && !styleDecls.MatchString(v):
					why = "style " + v
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	for _, n := range nodes {
		visit(n)
	}
	return why
}

var (
	styleDecls  = regexp.MustCompile(`^([a-z-]+:[a-z0-9#.,%' -]+;)+$`)
	allowedName = map[string]bool{
		"p": true, "br": true, "strong": true, "b": true, "em": true, "i": true, "u": true, "ul": true,
		"ol": true, "li": true, "h1": true, "h2": true, "h3": true, "h4": true, "a": true, "table": true,
		"thead": true, "tbody": true, "tfoot": true, "tr": true, "td": true, "th": true, "blockquote": true,
		"hr": true, "span": true, "div": true, "img": true,
	}
)

func TestXSSVectors(t *testing.T) {
	for _, v := range xssVectors {
		out := HTML(v)
		if why := unsafe(out); why != "" {
			t.Errorf("%s\n  -> %s\n  %s", v, out, why)
		}
		if again := HTML(out); again != out {
			t.Errorf("not idempotent: %q -> %q", out, again)
		}
	}
}

func TestPolicy(t *testing.T) {
	cases := map[string]string{
		// Allowed structure is kept and re-serialized.
		`<p>Hello <strong>world</strong><br/>bye</p>`: `<p>Hello <strong>world</strong><br>bye</p>`,
		`<P CLASS=x ID=y>a</P>`:                       `<p>a</p>`,
		`<h1>a</h1><h4>b</h4><h5>c</h5>`:              `<h1>a</h1><h4>b</h4>c`,
		`<ul><li>a<li>b</ul><ol><li>c</ol>`:           `<ul><li>a</li><li>b</li></ul><ol><li>c</li></ol>`,
		`<blockquote>q</blockquote><hr><span>s</span><div>d</div><em>e</em><i>i</i><b>b</b><u>u</u>`: `<blockquote>q</blockquote><hr><span>s</span><div>d</div><em>e</em><i>i</i><b>b</b><u>u</u>`,
		// Tables, with align, width and height.
		`<table align=CENTER width=600 height="10%" border=1><thead><tr><th align=left>h</th></tr></thead><tbody><tr><td width=50% valign=top>c</td></tr></tbody><tfoot><tr><td>f</td></tr></tfoot></table>`: `<table align="center" width="600" height="10%"><thead><tr><th align="left">h</th></tr></thead><tbody><tr><td width="50%">c</td></tr></tbody><tfoot><tr><td>f</td></tr></tfoot></table>`,
		`<table width=600px align=middle><tr><td>x</td></tr></table>`:                        `<table><tbody><tr><td>x</td></tr></tbody></table>`,
		`<table><caption>cap</caption><colgroup><col></colgroup><tr><td>x</td></tr></table>`: `<table><tbody><tr><td>x</td></tr></tbody></table>`,
		`<p align=center width=3>a</p>`:                                                      `<p>a</p>`,
		// Links.
		`<a href="https://example.com/a?b=1&amp;c=2" title="T &quot;q&quot;">x</a>`: `<a href="https://example.com/a?b=1&amp;c=2" title="T &#34;q&#34;">x</a>`,
		`<a href="mailto:a@example.com">m</a>`:                                      `<a href="mailto:a@example.com">m</a>`,
		`<a href="  HTTPS://Example.com ">x</a>`:                                    `<a href="HTTPS://Example.com">x</a>`,
		`<a href="http://example.com">x</a>`:                                        `<a>x</a>`,
		`<a href="/relative">x</a><a href="#top">y</a><a href="https://">z</a>`:     `<a>x</a><a>y</a><a>z</a>`,
		// Images: cid only, alt/title/size kept.
		`<img src="cid:qr@transteira" alt="QR" title="t" width="180" height="180" style="display:block;border:0">`: `<img src="cid:qr@transteira" alt="QR" title="t" width="180" height="180" style="border:0;">`,
		`<img src="CID:a.b-c_d@e">`:     `<img src="cid:a.b-c_d@e">`,
		`<img src="cid:a b">x`:          `<img src="cid:ab">x`,
		`<img src="cid:a/b">x`:          `x`,
		`<img src="cid:">x`:             `x`,
		`<img alt="no source">`:         ``,
		`<img src="https://e.example">`: ``,
		// Unknown elements are unwrapped; dropped ones lose their content.
		`<custom><code>c</code><font color=red>f</font></custom>`: `cf`,
		`<p>a<script>b</script>c<style>d</style>e</p>`:            `<p>ace</p>`,
		// Comments, doctype and the document structure disappear.
		`<!DOCTYPE html><html><head><title>t</title></head><body><p>x</p></body></html>`: `<p>x</p>`,
		`a<!-- c -->b`: `ab`,
		// Text is escaped; entities are decoded then re-escaped.
		`1 &lt; 2 &amp;&amp; "q" 'a' &nbsp;`: "1 &lt; 2 &amp;&amp; \"q\" 'a'  ",
		"nul\x00byte":                        "nulbyte",
		// Style: allowed properties and safe values only.
		`<p style="COLOR: Red ;  margin : 0  0 16px; position:fixed; font-family:'Courier New',monospace; color:#fff !important; width:calc(1px)">x</p>`: `<p style="color:Red;margin:0 0 16px;font-family:'Courier New',monospace;">x</p>`,
		`<p style="position:absolute">x</p>`:  `<p>x</p>`,
		`<p style="color">x</p>`:              `<p>x</p>`,
		`<p style="color:&quot;red&quot;">x`:  `<p>x</p>`,
		`<span style="color:red;" foo=bar>s`:  `<span style="color:red;">s</span>`,
		`<p title="a&#10;b">x</p>`:            "<p title=\"a\nb\">x</p>",
		`<a xlink:href="https://e.example">x`: `<a>x</a>`,
	}
	for in, want := range cases {
		if got := HTML(in); got != want {
			t.Errorf("HTML(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// splitBraces is a test splitter: {{name}} placeholders, "{{!" is an error.
func splitBraces(s string) ([]Piece, error) {
	var out []Piece
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			if s != "" {
				out = append(out, Piece{Text: s})
			}
			return out, nil
		}
		j := strings.Index(s[i:], "}}")
		if j < 0 || s[i+2] == '!' {
			return nil, errors.New("bad placeholder")
		}
		if i > 0 {
			out = append(out, Piece{Text: s[:i]})
		}
		out = append(out, Piece{Placeholder: s[i+2 : i+j]})
		s = s[i+j+2:]
	}
}

func TestTemplatePlaceholders(t *testing.T) {
	src := `<p title="T {{t}}">Hi {{name}}<a href=" {{link}} ">go</a><img src="cid:qr" alt="{{alt}}"></p>`
	segs, err := Template(src, splitBraces)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range segs {
		if s.Placeholder != "" {
			got = append(got, s.Placeholder+":"+[]string{"text", "attr", "url"}[s.Context])
		}
	}
	if strings.Join(got, ",") != "t:attr,name:text,link:url,alt:attr" {
		t.Errorf("placeholders %v", got)
	}
	if j := Join(segs); j != `<p title="T {{t}}">Hi {{name}}<a href="{{link}}">go</a><img src="cid:qr" alt="{{alt}}"></p>` {
		t.Errorf("Join = %s", j)
	}
	// Without splitter, braces are plain text and a placeholder href is
	// not a URL.
	if got := HTML(src); got != `<p title="T {{t}}">Hi {{name}}<a>go</a><img src="cid:qr" alt="{{alt}}"></p>` {
		t.Errorf("HTML = %s", got)
	}
	// A literal URL still works with a splitter.
	if segs, err := Template(`<a href="https://e.example">x</a><a href="javascript:x">y</a>`, splitBraces); err != nil ||
		Join(segs) != `<a href="https://e.example">x</a><a>y</a>` {
		t.Errorf("literal href: %v %s", err, Join(segs))
	}

	bad := map[string]string{
		`<a href="https://e.example/{{x}}">x</a>`:          "whole URL",
		`<img src="{{x}}">`:                                "not allowed",
		`<img src="cid:{{x}}">`:                            "not allowed",
		`<p style="color:{{x}}">x</p>`:                     "not allowed",
		`<table width="{{x}}"></table>`:                    "not allowed",
		`<table><tr><td align="{{x}}">x</td></tr></table>`: "not allowed",
		`<p>{{!x}}</p>`:                                    "bad placeholder",
		`<p title="{{!x}}">x</p>`:                          "bad placeholder",
		`<a href="{{!x}}">x</a>`:                           "bad placeholder",
		`<p style="{{!x}}">x</p>`:                          "bad placeholder",
	}
	for in, want := range bad {
		if _, err := Template(in, splitBraces); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want %q", in, err, want)
		}
	}
	if _, err := Template(`<img src="{{x}}">`, splitBraces); !errors.Is(err, ErrPlaceholder) {
		t.Errorf("not ErrPlaceholder: %v", err)
	}
}

func TestFixedPoint(t *testing.T) {
	// Unwrapping a marquee would leave a heading inside a paragraph, which
	// a parser restructures; marquee is dropped. Check that nested
	// constructs reach a fixed point anyway.
	for _, in := range []string{
		`<p><marquee><h1>x</h1></marquee></p>`,
		`<p><custom><h1>x</h1></custom></p>`,
		`<a href="https://a.example"><div><a href="https://b.example">x</a></div></a>`,
		`<table><tr><custom>text</custom><td>x</td></tr></table>`,
		`<ul><li><p>a<li>b</ul>`,
		`<b><p>x</b>y</p>`,
	} {
		out := HTML(in)
		if HTML(out) != out {
			t.Errorf("%s -> %s -> %s", in, out, HTML(out))
		}
	}
	// A splitter error on a later pass is reported: the first pass sees
	// "&#123;&#123;!" as text and outputs "{{!" ... which is parsed again.
	if _, err := Template(`<p>&#123;&#123;!x}}</p>`, splitBraces); err == nil {
		t.Error("entity-built placeholder: want error")
	}
}

func TestTemplateMaxPasses(t *testing.T) {
	// Each pass of this splitter reveals new content: the loop stops after
	// maxPasses and returns the last pass.
	n := 0
	grow := func(s string) ([]Piece, error) {
		n++
		return []Piece{{Text: s + "x"}}, nil
	}
	segs, err := Template("a", grow)
	if err != nil || n != maxPasses+1 || Join(segs) != "a"+strings.Repeat("x", maxPasses+1) {
		t.Errorf("passes %d, %v, %q", n, err, Join(segs))
	}
}

func TestSafeURLAndStyle(t *testing.T) {
	for in, want := range map[string]string{
		"https://e.example": "https://e.example", "\x20https://e.ex\tample\n": "https://e.example",
		"mailto:a@e.example": "mailto:a@e.example", "https://": "", "mailto:": "", "ftp://e": "",
		"https://" + strings.Repeat("a", 2048): "",
	} {
		got, ok := SafeURL(in)
		if got != want || ok != (want != "") {
			t.Errorf("SafeURL(%q) = %q %v", in, got, ok)
		}
	}
	if got := Style("color:red;;:x;font-size:"); got != "color:red;" {
		t.Errorf("Style = %q", got)
	}
	// display is not allowed: display:none would hide required content.
	if got := Style("display:none;color:red;DISPLAY: inline-block"); got != "color:red;" {
		t.Errorf("Style with display = %q", got)
	}
	if got := EscapeAttr(`a"<&>`); got != "a&#34;&lt;&amp;&gt;" {
		t.Errorf("EscapeAttr = %q", got)
	}
}

func TestHasContent(t *testing.T) {
	for in, want := range map[string]bool{
		"": false, "  \n": false, "<p> </p><br>": false, "<p>x</p>": true, `<div><img src="cid:a"></div>`: true,
	} {
		if HasContent(in) != want {
			t.Errorf("HasContent(%q) != %v", in, want)
		}
	}
}

func FuzzSanitizeHTML(f *testing.F) {
	for _, v := range xssVectors {
		f.Add(v)
	}
	f.Add(`<p style="color:red">a <b>b</b> <a href="https://e.example">c</a></p>`)
	f.Add(`<table><tr><td>x</td></tr></table><img src="cid:qr@transteira">`)
	f.Fuzz(func(t *testing.T, in string) {
		out := HTML(in)
		if why := unsafe(out); why != "" {
			t.Fatalf("%q -> %q: %s", in, out, why)
		}
		if again := HTML(out); again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, out, again)
		}
		// The output parses back without any dropped element.
		if _, err := html.Parse(strings.NewReader(out)); err != nil {
			t.Fatal(err)
		}
	})
}

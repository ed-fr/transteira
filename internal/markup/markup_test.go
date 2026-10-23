package markup

import (
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/mail/sanitize"
)

func TestMarkdown(t *testing.T) {
	cases := map[string]string{
		"":                 "",
		"\n\n  \n":         "",
		"Hello":            "<p>Hello</p>",
		"a\nb\r\nc\rd":     "<p>a<br>\nb<br>\nc<br>\nd</p>",
		"p1\n\np2":         "<p>p1</p>\n<p>p2</p>",
		"  indented":       "<p>indented</p>",
		"# Title":          "<h2>Title</h2>",
		"## Sub ##":        "<h3>Sub</h3>",
		"### Third":        "<h4>Third</h4>",
		"#### Fourth":      "<p>#### Fourth</p>",
		"#NoSpace":         "<p>#NoSpace</p>",
		"intro\n# H\nnext": "<p>intro</p>\n<h2>H</h2>\n<p>next</p>",
		// Lists.
		"- a\n* b\n+ c":                "<ul>\n<li>a</li>\n<li>b</li>\n<li>c</li>\n</ul>",
		"1. a\n2) b":                   "<ol>\n<li>a</li>\n<li>b</li>\n</ol>",
		"- a\n  continued\n- b":        "<ul>\n<li>a<br>\ncontinued</li>\n<li>b</li>\n</ul>",
		"- a\n1. b":                    "<ul>\n<li>a</li>\n</ul>\n<ol>\n<li>b</li>\n</ol>",
		"- a\nafter":                   "<ul>\n<li>a</li>\n</ul>\n<p>after</p>",
		"para\n- item":                 "<p>para</p>\n<ul>\n<li>item</li>\n</ul>",
		"-not a list\n---":             "<p>-not a list<br>\n---</p>",
		"- a\n\n- b":                   "<ul>\n<li>a</li>\n</ul>\n<ul>\n<li>b</li>\n</ul>",
		"1234567890. too long numeral": "<p>1234567890. too long numeral</p>",
		// Emphasis.
		"**bold** and __bold__":       "<p><strong>bold</strong> and <strong>bold</strong></p>",
		"*it* and _it_":               "<p><em>it</em> and <em>it</em></p>",
		"***both***":                  "<p><em><strong>both</strong></em></p>",
		"**a** *b* ***":               "<p><strong>a</strong> <em>b</em> ***</p>",
		"snake_case_name and 2*3*4":   "<p>snake_case_name and 2<em>3</em>4</p>",
		"a * b * c":                   "<p>a * b * c</p>",
		"**unclosed and *open":        "<p>**unclosed and *open</p>",
		"**a *b** c*":                 "<p><strong>a *b</strong> c*</p>",
		"\\*not\\* \\_em\\_ \\\\ \\x": "<p>*not* _em_ \\ \\x</p>",
		// Links.
		"[site](https://example.com/a?b=1&c=2)":    `<p><a href="https://example.com/a?b=1&amp;c=2">site</a></p>`,
		"[**bold** link](mailto:dpo@example.com)":  `<p><a href="mailto:dpo@example.com"><strong>bold</strong> link</a></p>`,
		"[x](javascript:alert(1))":                 "<p>x)</p>",
		"[x](http://example.com)":                  "<p>x</p>",
		"[x]( https://example.com )":               `<p><a href="https://example.com">x</a></p>`,
		"[x](https://exa mple.com)":                "<p>x</p>",
		"[[nested](https://a.example)](https://b)": `<p><a href="https://a.example">[nested</a>](https://b)</p>`,
		"[no url] and [x] (y)":                     "<p>[no url] and [x] (y)</p>",
		"[unclosed](https://example.com":           "<p>[unclosed](https://example.com</p>",
		"<https://example.com/x>":                  `<p><a href="https://example.com/x">https://example.com/x</a></p>`,
		"<mailto:a@example.com>":                   `<p><a href="mailto:a@example.com">mailto:a@example.com</a></p>`,
		"<javascript:alert(1)> <a b> <https://x":   "<p>&lt;javascript:alert(1)&gt; &lt;a b&gt; &lt;https://x</p>",
		"[x](data:text/html;base64,PHNjcmlwdD4=)":  "<p>x</p>",
		"[x](https://e.example/\"onclick=\"alert)": `<p><a href="https://e.example/&#34;onclick=&#34;alert">x</a></p>`,
		// No raw HTML.
		`<script>alert(1)</script><b onclick="x">b</b> & 'q'`: "<p>&lt;script&gt;alert(1)&lt;/script&gt;&lt;b onclick=\"x\"&gt;b&lt;/b&gt; &amp; 'q'</p>",
		"# <img src=x onerror=alert(1)>":                      "<h2>&lt;img src=x onerror=alert(1)&gt;</h2>",
	}
	for in, want := range cases {
		if got := Markdown(in); got != want {
			t.Errorf("Markdown(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestMarkdownLinear(t *testing.T) {
	// Many unmatched openers and brackets stay fast and literal.
	src := strings.Repeat("[", 20000) + strings.Repeat("<", 20000) + strings.Repeat("* _ ", 20000)
	if out := Markdown(src); !strings.HasPrefix(out, "<p>[[[[") || !strings.HasSuffix(out, "* _</p>") {
		t.Errorf("unexpected %q", out[:20])
	}
	// Deep nesting beyond the delimiter depth leaves the outer ones literal.
	deep := strings.Repeat("*a ", maxDelimDepth+5) + "x" + strings.Repeat(" a*", maxDelimDepth+5)
	if out := Markdown(deep); strings.Count(out, "<em>") != strings.Count(out, "</em>") {
		t.Errorf("unbalanced: %s", out)
	}
}

func FuzzMarkdown(f *testing.F) {
	for _, s := range []string{"# T\n\n- a\n- **b**\n\n1. [x](https://e.example)", "<script>x</script>", "*a _b* c_", "[a](javascript:x)", "<https://e.example>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Markdown(s)
		// The output is already sanitized: sanitizing it changes nothing,
		// so no raw HTML of the source can survive.
		if again := sanitize.HTML(out); again != out {
			t.Fatalf("not sanitized: %q -> %q\n%q", s, out, again)
		}
		lower := strings.ToLower(out)
		if strings.Contains(lower, "<script") || strings.Contains(lower, "href=\"javascript") || strings.Contains(lower, "<img") {
			t.Fatalf("unsafe: %q -> %q", s, out)
		}
	})
}

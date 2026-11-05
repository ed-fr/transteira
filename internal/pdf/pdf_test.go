package pdf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func sampleDoc() Document {
	sig := bytes.Repeat([]byte{0xAB}, 64)
	blocks := []Block{
		{Kind: Heading, Text: "Proof of deposit and delivery"},
		{Kind: Field, Label: "Sender:", Text: "alice@entity-a.example.com"},
		{Kind: Field, Label: "Message:", Text: "Line one\nLine two (with parens) and \\ backslash"},
		{Kind: Spacer},
		{Kind: Heading, Text: "Files"},
	}
	for i := 0; i < 3; i++ {
		blocks = append(blocks,
			Block{Kind: Field, Label: fmt.Sprintf("File %d:", i+1), Text: "report (final) \\ v2 é€ – 日本.pdf"},
			Block{Kind: Mono, Text: strings.Repeat("0123456789abcdef", 4)})
	}
	return Document{
		Title: "Proof", Author: "TransTeira", Subject: "Statement", Lang: "en",
		Created: time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC),
		Blocks:  blocks,
		Attachments: []Attachment{
			{Name: "statement.sig", MIMEType: "application/octet-stream", Description: "Signature", Data: sig},
			{Name: "statement.json", MIMEType: "application/json", Description: "Statement", Data: []byte(`{"a":"endstream\nendobj 5 0 obj"}`)},
		},
		Footer: "Entity A", TruncatedNotice: "Truncated: see statement.json",
	}
}

func render(t testing.TB, d Document) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := Write(&b, d); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return b.Bytes()
}

func TestRoundTrip(t *testing.T) {
	d := sampleDoc()
	out := render(t, d)
	got, err := ReadAttachments(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d attachments", len(got))
	}
	for _, a := range d.Attachments {
		if !bytes.Equal(got[a.Name], a.Data) {
			t.Errorf("%s differs", a.Name)
		}
	}
}

func TestHeaderTrailerAndForbiddenKeys(t *testing.T) {
	out := render(t, sampleDoc())
	if !bytes.HasPrefix(out, []byte("%PDF-1.7")) {
		t.Fatal("bad header")
	}
	if !bytes.HasSuffix(out, []byte("%%EOF\n")) {
		t.Fatal("bad trailer")
	}
	for _, k := range []string{"/JavaScript", "/JS", "/OpenAction", "/URI", "/Launch", "/AA", "/Annots", "/AcroForm", "/Action"} {
		if bytes.Contains(out, []byte(k)) {
			t.Errorf("output contains %s", k)
		}
	}
	for _, k := range []string{"/PageMode /UseAttachments", "/AFRelationship /Data", "/Lang (en)", "/WinAnsiEncoding"} {
		if !bytes.Contains(out, []byte(k)) {
			t.Errorf("output lacks %s", k)
		}
	}
}

func TestDeterministic(t *testing.T) {
	a, b := render(t, sampleDoc()), render(t, sampleDoc())
	if !bytes.Equal(a, b) {
		t.Fatal("output not deterministic")
	}
	d := sampleDoc()
	d.Created = time.Time{}
	if bytes.Contains(render(t, d), []byte("CreationDate")) {
		t.Fatal("zero Created must be omitted")
	}
	d.Blocks = append(d.Blocks, Block{Kind: Paragraph, Text: "x"})
	if bytes.Equal(render(t, d), a) {
		t.Fatal("different documents give the same output")
	}
}

func TestXrefOffsets(t *testing.T) {
	out := render(t, sampleDoc())
	i := bytes.LastIndex(out, []byte("startxref\n"))
	var off int
	if _, err := fmt.Sscanf(string(out[i+len("startxref\n"):]), "%d", &off); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out[off:], []byte("xref\n0 ")) {
		t.Fatal("startxref does not point at the table")
	}
	lines := strings.Split(string(out[off:]), "\n")
	for n := 1; strings.HasSuffix(lines[2+n-1+0], " n "); n++ {
		var o int
		if _, err := fmt.Sscanf(lines[2+n-1], "%d", &o); err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(out[o:], []byte(fmt.Sprintf("%d 0 obj\n", n))) {
			t.Fatalf("object %d offset wrong", n)
		}
	}
}

func TestInjection(t *testing.T) {
	evil := "a) Tj ET /JavaScript (x) endstream endobj %%EOF \\ ( \n\r\x00\x1b \u202e\u2066 \U0001F600"
	d := Document{
		Title: evil, Author: evil, Subject: evil, Lang: "en) /JS (", Footer: evil, TruncatedNotice: evil,
		Blocks: []Block{
			{Kind: Heading, Label: evil, Text: evil},
			{Kind: Field, Label: evil, Text: evil},
			{Kind: Mono, Label: evil, Text: evil},
			{Kind: Paragraph, Label: evil, Text: evil},
		},
		Attachments: []Attachment{{Name: evil, MIMEType: "x/y) /JS (" + evil, Description: evil, Data: []byte("d")}},
	}
	out := render(t, d)
	if bytes.Contains(out, []byte("\u202e")) {
		t.Error("bidi override in output")
	}
	// The hostile words only appear inside string literals: exactly one line
	// of the file is the real end-of-file marker.
	eof := 0
	for _, line := range bytes.Split(out, []byte("\n")) {
		if string(line) == "%%EOF" {
			eof++
		}
	}
	if eof != 1 {
		t.Errorf("%d EOF lines", eof)
	}
	d.Title, d.Author, d.Subject, d.Footer, d.TruncatedNotice = "t", "a", "s", "f", "n"
	d.Blocks, d.Lang = nil, "en"
	d.Attachments[0].MIMEType, d.Attachments[0].Description = "x/y) /JS (", "/JS ( /JavaScript"
	clean := render(t, d)
	for _, k := range []string{"/JavaScript", "/JS"} {
		if bytes.Contains(clean, []byte(k)) {
			t.Errorf("attachment metadata produced %s", k)
		}
	}
	if n := bytes.Count(out, []byte("\nendstream\n")); n != 2 { // one page + one attachment
		t.Errorf("unexpected endstream count %d", n)
	}
	got, err := ReadAttachments(bytes.NewReader(out), int64(len(out)))
	if err != nil || string(got[evil]) != "d" {
		t.Fatalf("round trip: %v %v", err, got)
	}
}

func TestEmojiAndRTLReplaced(t *testing.T) {
	d := Document{Blocks: []Block{{Kind: Paragraph, Text: "a\U0001F600b\u202ec"}}}
	out := string(render(t, d))
	if !strings.Contains(out, "(a?b?c)") && !strings.Contains(out, "(a?bc)") {
		t.Fatalf("unexpected content: %s", out)
	}
	if strings.Contains(out, "(a?b?c)") {
		t.Fatal("bidi override must be removed, not replaced")
	}
}

func TestToWinAnsi(t *testing.T) {
	cases := map[string]string{
		"abc":        "abc",
		"é":          "\xe9",
		"€":          "\x80",
		"–—":         "\x96\x97",
		"😀":          "?",
		"a\tb":       "a b",
		"a b":        "a b",
		"a\u202eb":   "ab",
		"a\x00b\x7f": "ab",
		"a\nb":       "a\nb",
		"\u0081":     "",
		"日":          "?",
	}
	for in, want := range cases {
		if got := string(toWinAnsi(in)); got != want {
			t.Errorf("toWinAnsi(%q) = %q, want %q", in, got, want)
		}
	}
	if string(toWinAnsi("a\xffb")) != "a?b" {
		t.Error("invalid UTF-8 must become ?")
	}
}

func TestEscapeLiteral(t *testing.T) {
	if got := escapeLiteral([]byte("a(b)c\\d\n\xe9")); got != `(a\(b\)c\\d\012\351)` {
		t.Fatal(got)
	}
}

func TestWidths(t *testing.T) {
	if len(accentBase) != 64 {
		t.Fatalf("accentBase has %d entries", len(accentBase))
	}
	checks := []struct {
		f    font
		c    byte
		want int
	}{
		{fontHelvetica, 'A', 667},
		{fontHelvetica, ' ', 278},
		{fontHelvetica, '~', 584},
		{fontHelvetica, 'i', 222},
		{fontBold, 'a', 556},
		{fontBold, '~', 584},
		{fontBold, 'W', 944},
		{fontHelvetica, 0xE9, 556},
		{fontBold, 0xC9, 667},
		{fontMono, 'x', 600},
		{fontHelvetica, 0x80, 556},
		{fontHelvetica, 0xC6, 1000},
		{fontHelvetica, 0x81, 278},
	}
	for _, c := range checks {
		if got := widths[c.f][c.c]; got != c.want {
			t.Errorf("font %d code %#x width %d, want %d", c.f, c.c, got, c.want)
		}
	}
	if measure(fontHelvetica, []byte("AA")) != 1334 {
		t.Error("measure")
	}
	if fontBold.resourceName() != "F2" {
		t.Error("resourceName")
	}
}

func TestWrap(t *testing.T) {
	words := wordsOf(fontHelvetica, []byte("aaa bbb ccc ddd eee"))
	w := measure(fontHelvetica, []byte("aaa bbb"))
	lines := wrap(words, w)
	if len(lines) != 3 || string(lines[0][0].b) != "aaa bbb" || string(lines[2][0].b) != "eee" {
		t.Fatalf("lines: %v", lines)
	}
	// Long unbreakable token broken by characters.
	long := wordsOf(fontMono, []byte("x"+strings.Repeat("0123456789", 20)))
	lines = wrap(long, 600*30)
	total := ""
	for _, l := range lines {
		if measure(fontMono, l[0].b) > 600*30 {
			t.Fatal("line too wide")
		}
		total += string(l[0].b)
	}
	if total != string(long[0].b) || len(lines) != 7 {
		t.Fatalf("broken token: %d lines", len(lines))
	}
	// A character wider than the line still makes progress.
	if got := wrap(wordsOf(fontHelvetica, []byte("WW")), 10); len(got) != 2 {
		t.Fatalf("tiny width: %v", got)
	}
	// Mixed fonts on one line, the long word after short ones.
	mixed := wrap([]word{{fontBold, []byte("Label:")}, {fontHelvetica, []byte("value")}, {fontHelvetica, []byte(strings.Repeat("z", 200))}}, 20000)
	if len(mixed) < 2 || len(mixed[0]) != 2 {
		t.Fatalf("mixed: %v", mixed)
	}
	if got := wrap(nil, 100); got != nil {
		t.Fatal("empty input")
	}
}

func TestBlockLines(t *testing.T) {
	l := blockLines(fontHelvetica, bodySize, []byte("Label:"), []byte("a\n\nb"))
	if len(l) != 3 || l[1] != nil || l[0][0].f != fontBold {
		t.Fatalf("lines: %v", l)
	}
	if got := blockLines(fontHelvetica, bodySize, nil, nil); len(got) != 1 {
		t.Fatal("empty text must give one empty line")
	}
}

func pageCount(out []byte) int { return bytes.Count(out, []byte("/Type /Page /Parent")) }

func TestPaginationAndTruncation(t *testing.T) {
	var blocks []Block
	for i := 0; i < 400; i++ {
		blocks = append(blocks, Block{Kind: Field, Label: "n:", Text: fmt.Sprintf("line %d", i)})
	}
	d := Document{Blocks: blocks, Footer: "F", MaxPages: 3, TruncatedNotice: "CUT-NOTICE"}
	out := render(t, d)
	if pageCount(out) != 3 {
		t.Fatalf("pages = %d", pageCount(out))
	}
	if !bytes.Contains(out, []byte("(CUT-NOTICE)")) {
		t.Fatal("notice missing")
	}
	if !bytes.Contains(out, []byte("(F - page 3/3)")) || !bytes.Contains(out, []byte("(F - page 1/3)")) {
		t.Fatal("footer missing")
	}
	// Not truncated: no notice.
	small := Document{Blocks: blocks[:5], TruncatedNotice: "CUT-NOTICE"}
	out = render(t, small)
	if pageCount(out) != 1 || bytes.Contains(out, []byte("CUT-NOTICE")) || !bytes.Contains(out, []byte("(page 1/1)")) {
		t.Fatal("unexpected output for short document")
	}
	// Default bound.
	big := append(append([]Block(nil), blocks...), blocks...)
	big = append(big, big...)
	big = append(big, big...)
	if pageCount(render(t, Document{Blocks: big, TruncatedNotice: "x"})) != DefaultMaxPages {
		t.Fatal("default bound")
	}
	// One page, notice reserve, no notice, long notice, long footer.
	one := render(t, Document{Blocks: blocks, MaxPages: 1, TruncatedNotice: strings.Repeat("word ", 400), Footer: strings.Repeat("f", 500)})
	if pageCount(one) != 1 {
		t.Fatal("one page expected")
	}
	if pageCount(render(t, Document{Blocks: blocks, MaxPages: 1})) != 1 {
		t.Fatal("no notice")
	}
}

func TestEmptyDocument(t *testing.T) {
	out := render(t, Document{})
	if pageCount(out) != 1 {
		t.Fatal("empty document must have one page")
	}
	if _, err := ReadAttachments(bytes.NewReader(out), int64(len(out))); !errors.Is(err, ErrNoAttachments) {
		t.Fatalf("err = %v", err)
	}
}

func TestBlockKinds(t *testing.T) {
	d := Document{Blocks: []Block{
		{Kind: Heading, Text: "H"},
		{Kind: Spacer},
		{Kind: Paragraph, Text: "P"},
		{Kind: BlockKind(99), Label: "L", Text: "U"},
		{Kind: Mono, Label: "m:", Text: "M"},
		{Kind: Heading, Text: "H2"},
	}}
	out := string(render(t, d))
	for _, s := range []string{"/F2 16.00 Tf", "/F1 10.00 Tf", "/F3 9.00 Tf", "(H)"} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %s", s)
		}
	}
}

func TestAttachmentErrors(t *testing.T) {
	for name, atts := range map[string][]Attachment{
		"empty":     {{Name: ""}},
		"utf8":      {{Name: "a\xff"}},
		"long":      {{Name: strings.Repeat("a", 2000)}},
		"duplicate": {{Name: "a"}, {Name: "a"}},
	} {
		if err := Write(&bytes.Buffer{}, Document{Attachments: atts}); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestWriteError(t *testing.T) {
	if err := Write(failWriter{}, Document{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestAttachmentDefaultsAndNames(t *testing.T) {
	d := Document{Lang: "bad lang!", Attachments: []Attachment{
		{Name: "ünï/çødé 😀.bin", Data: nil}, {Name: "a", MIMEType: "a/b c#"},
	}}
	out := render(t, d)
	if !bytes.Contains(out, []byte("/Subtype /application#2Foctet-stream")) || !bytes.Contains(out, []byte("/Subtype /a#2Fb#20c#23")) {
		t.Fatal("subtype escaping")
	}
	if bytes.Contains(out, []byte("/Lang")) {
		t.Fatal("invalid lang must be omitted")
	}
	got, err := ReadAttachments(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := got["ünï/çødé 😀.bin"]; !ok || len(v) != 0 {
		t.Fatalf("unicode name: %v", got)
	}
	if validLang("") || validLang(strings.Repeat("a", 17)) || !validLang("fr-CA") {
		t.Fatal("validLang")
	}
}

func TestCleanText(t *testing.T) {
	if got := cleanText("a\nb\tc\u202ed\xff"); got != "a b cd�" {
		t.Fatalf("%q", got)
	}
}

func TestReaderLimits(t *testing.T) {
	out := render(t, sampleDoc())
	if _, err := ReadAttachments(bytes.NewReader(out), int64(len(out))-1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, err := ReadAttachments(bytes.NewReader(out), 0); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, err := ReadAttachments(iotest.ErrReader(errors.New("io")), 100); err == nil {
		t.Fatal("read error expected")
	}
}

func TestReaderTruncatedEverywhere(t *testing.T) {
	out := render(t, sampleDoc())
	for n := 0; n < len(out); n += 7 {
		// Must never panic; truncations before the end of the objects must fail.
		got, err := ReadAttachments(bytes.NewReader(out[:n]), int64(len(out)))
		if err == nil && len(got) != 2 {
			t.Fatalf("truncated at %d: %v", n, got)
		}
	}
}

func replaceOnce(t *testing.T, in []byte, old, repl string) []byte {
	t.Helper()
	if !bytes.Contains(in, []byte(old)) {
		t.Fatalf("pattern %q not found", old)
	}
	return bytes.Replace(in, []byte(old), []byte(repl), 1)
}

func TestReaderMalformed(t *testing.T) {
	base := render(t, Document{Attachments: []Attachment{{Name: "a", Data: []byte("abc")}}})
	hdr := "%PDF-1.7\n"
	cases := map[string][]byte{
		"no header":        []byte("hello"),
		"junk":             []byte(hdr + "garbage"),
		"no gen":           []byte(hdr + "1 x"),
		"no obj":           []byte(hdr + "1 0 foo"),
		"dup object":       []byte(hdr + "1 0 obj\n1\nendobj\n1 0 obj\n2\nendobj\n"),
		"no endobj":        []byte(hdr + "1 0 obj\n1\n"),
		"unterminated arr": []byte(hdr + "1 0 obj\n[1 2\n"),
		"unterminated dic": []byte(hdr + "1 0 obj\n<< /A 1\n"),
		"dict key":         []byte(hdr + "1 0 obj\n<< 1 2 >>\nendobj\n"),
		"dup key":          []byte(hdr + "1 0 obj\n<< /A 1 /A 2 >>\nendobj\n"),
		"dict bad key":     []byte(hdr + "1 0 obj\n<< /A#4 1 >>\nendobj\n"),
		"unterminated str": []byte(hdr + "1 0 obj\n(abc\n"),
		"unterminated hex": []byte(hdr + "1 0 obj\n<41\n"),
		"bad hex":          []byte(hdr + "1 0 obj\n<4G>\nendobj\n"),
		"bad name escape":  []byte(hdr + "1 0 obj\n/A#4\nendobj\n"),
		"bad name hex":     []byte(hdr + "1 0 obj\n/A#GG\nendobj\n"),
		"unknown token":    []byte(hdr + "1 0 obj\nfoo\nendobj\n"),
		"delimiter":        []byte(hdr + "1 0 obj\n)\nendobj\n"),
		"long number":      []byte(hdr + "1 0 obj\n" + strings.Repeat("9", 40) + "\nendobj\n"),
		"deep":             []byte(hdr + "1 0 obj\n" + strings.Repeat("[", 100) + "\nendobj\n"),
		"deep dict":        []byte(hdr + "1 0 obj\n" + strings.Repeat("<</A ", 100) + "\nendobj\n"),
		"stream no eol":    []byte(hdr + "1 0 obj\n<< /Length 1 >>\nstreamX"),
		"stream no length": []byte(hdr + "1 0 obj\n<< >>\nstream\nabc\nendstream\nendobj\n"),
		"stream too long":  []byte(hdr + "1 0 obj\n<< /Length 99 >>\nstream\nabc\nendstream\nendobj\n"),
		"stream neg":       []byte(hdr + "1 0 obj\n<< /Length -1 >>\nstream\nabc\nendstream\nendobj\n"),
		"stream ref late":  []byte(hdr + "1 0 obj\n<< /Length 2 0 R >>\nstream\nabc\nendstream\nendobj\n"),
		"no endstream":     []byte(hdr + "1 0 obj\n<< /Length 3 >>\nstream\nabcXYZ\nendobj\n"),
		"huge generation":  []byte(hdr + "1 " + strings.Repeat("9", 40) + " obj\n"),
		"cut name":         replaceOnce(t, base, "/UF <FEFF0061>", "/UF <FEFF00>"),
	}
	for name, in := range cases {
		if _, err := ReadAttachments(bytes.NewReader(in), int64(len(in))+1); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// build assembles a PDF from object bodies (numbered from 1; object 1 is
// the catalog) with a correct cross-reference table and trailer.
func build(objs ...string) []byte {
	var b strings.Builder
	b.WriteString("%PDF-1.7\n")
	offs := make([]int, len(objs))
	for i, o := range objs {
		offs[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return []byte(b.String())
}

const (
	testStream = "<< /Type /EmbeddedFile /Length 3 >>\nstream\nabc\nendstream"
	testCat    = "<< /Type /Catalog /Names << /EmbeddedFiles << /Names [(a.txt) 3 0 R] >> >> /AF [3 0 R] >>"
	testSpec   = "<< /Type /Filespec /F (a.txt) /UF (a.txt) /EF << /F 2 0 R /UF 2 0 R >> >>"
)

func catalog(names, af string) string {
	return "<< /Type /Catalog /Names << /EmbeddedFiles << /Names [" + names + "] >> >> /AF [" + af + "] >>"
}

func readErr(in []byte) error {
	_, err := ReadAttachments(bytes.NewReader(in), int64(len(in))+1)
	return err
}

func TestReaderStructure(t *testing.T) {
	good := build(testCat, testStream, testSpec)
	got, err := ReadAttachments(bytes.NewReader(good), 10000)
	if err != nil || string(got["a.txt"]) != "abc" || len(got) != 1 {
		t.Fatalf("good: %v %v", got, err)
	}
	// Trailing end of line characters after %%EOF are fine.
	if err := readErr(append(bytes.Clone(good), "\r\n \n"...)); err != nil {
		t.Fatalf("trailing EOL: %v", err)
	}
	// UTF-16 name, escapes in other strings, other value kinds in unrelated objects.
	utf := build(catalog("<FEFF00E9> 3 0 R", "3 0 R"), testStream,
		"<< /Type /Filespec /F (a\\n\\101\\(\\)\\\n(x)b) /UF <FEFF00E9> /X /A#42 /Y [1 -2 3.5 true false null (s) <41 4> 1 0 R] /EF << /F 2 0 R >> >>")
	if got, err := ReadAttachments(bytes.NewReader(utf), 10000); err != nil || string(got["\u00e9"]) != "abc" {
		t.Fatalf("utf16: %q %v", got, err)
	}
	// Streams hide object-looking text: it must not be parsed as objects.
	hidden := build(testCat, "<< /Type /EmbeddedFile /Length 22 >>\nstream\n9 0 obj << /Foo >> end\nendstream", testSpec)
	if got, err := ReadAttachments(bytes.NewReader(hidden), 10000); err != nil || len(got["a.txt"]) != 22 {
		t.Fatalf("hidden: %v %v", got, err)
	}
	// Indirect stream length, CRLF after the stream keyword.
	ind := build(catalog("(a.txt) 4 0 R", "4 0 R"), "3", "<< /Type /EmbeddedFile /Length 2 0 R >>\nstream\r\nabc\nendstream",
		"<< /Type /Filespec /UF (a.txt) /EF << /F 3 0 R >> >>")
	if got, err := ReadAttachments(bytes.NewReader(ind), 10000); err != nil || string(got["a.txt"]) != "abc" {
		t.Fatalf("indirect length: %v %v", got, err)
	}
	// No attachment at all.
	if err := readErr(build("<< /Type /Catalog >>")); !errors.Is(err, ErrNoAttachments) {
		t.Fatalf("err = %v", err)
	}
}

func TestReaderRejectsForgeries(t *testing.T) {
	good := build(testCat, testStream, testSpec)
	other := "<< /Type /Filespec /F (b.txt) /UF (b.txt) /EF << /F 2 0 R >> >>"
	cases := map[string][]byte{
		"incremental update": append(bytes.Clone(good), "4 0 obj\n<< /Type /Filespec >>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 5 /Root 1 0 R /Prev 1 >>\nstartxref\n0\n%%EOF\n"...),
		"second header":      append(bytes.Clone(good), "%PDF-1.7\n"...),
		"data after EOF":     append(bytes.Clone(good), "x"...),
		"nul after EOF":      append(bytes.Clone(good), 0),
		"bad startxref":      replaceOnce(t, good, "startxref\n", "startxref\n1"),
		"missing startxref":  bytes.TrimSuffix(good, []byte("startxref\n"+strconv.Itoa(bytes.Index(good, []byte("xref\n0")))+"\n%%EOF\n")),
		"xref offset":        replaceOnce(t, good, "0000000009 00000 n", "0000000010 00000 n"),
		"xref count":         replaceOnce(t, good, "xref\n0 4\n", "xref\n0 5\n"),
		"no xref":            bytes.Replace(good, []byte("xref\n0 4"), []byte("xrex\n0 4"), 1),
		"trailer size":       replaceOnce(t, good, "/Size 4", "/Size 9"),
		"trailer no root":    replaceOnce(t, good, "/Root 1 0 R", "/Root 1"),
		"trailer prev":       replaceOnce(t, good, "/Root 1 0 R", "/Root 1 0 R /Prev 0"),
		"trailer encrypt":    replaceOnce(t, good, "/Root 1 0 R", "/Root 1 0 R /Encrypt 1 0 R"),
		"trailer garbage":    replaceOnce(t, good, "trailer\n<<", "trailer\n(("),
		"trailer keyword":    replaceOnce(t, good, "trailer\n", "trailex\n"),
		"root missing":       replaceOnce(t, good, "/Root 1 0 R", "/Root 9 0 R"),
		"root not catalog":   build("<< /Type /Pages >>", testStream, testSpec),
		"root not dict":      build("5", testStream, testSpec),
		"generation":         replaceOnce(t, good, "2 0 obj", "2 1 obj"),
		"gap in numbers":     replaceOnce(t, good, "3 0 obj", "7 0 obj"),
		"names not dict":     build("<< /Type /Catalog /Names 5 >>"),
		"names extra key":    build("<< /Type /Catalog /Names << /EmbeddedFiles << /Names [] >> /JavaScript << >> >> >>"),
		"tree not dict":      build("<< /Type /Catalog /Names << /EmbeddedFiles 5 >> >>"),
		"tree kids":          build("<< /Type /Catalog /Names << /EmbeddedFiles << /Kids [] >> >> >>"),
		"tree extra key":     build("<< /Type /Catalog /Names << /EmbeddedFiles << /Names [] /Limits [] >> >> >>"),
		"tree odd array":     build(catalog("(a.txt)", "3 0 R"), testStream, testSpec),
		"AF without names":   build("<< /Type /Catalog /AF [3 0 R] >>", testStream, testSpec),
		"AF missing":         build("<< /Type /Catalog /Names << /EmbeddedFiles << /Names [(a.txt) 3 0 R] >> >> >>", testStream, testSpec),
		"AF not array":       build("<< /Type /Catalog /Names << /EmbeddedFiles << /Names [(a.txt) 3 0 R] >> >> /AF 3 0 R >>", testStream, testSpec),
		"AF longer":          build(catalog("(a.txt) 3 0 R", "3 0 R 4 0 R"), testStream, testSpec, other),
		"AF other":           build(catalog("(a.txt) 3 0 R", "4 0 R"), testStream, testSpec, other),
		"AF direct":          build(catalog("(a.txt) 3 0 R", "5"), testStream, testSpec),
		"key not string":     build(catalog("/a.txt 3 0 R", "3 0 R"), testStream, testSpec),
		"empty name":         build(catalog("() 3 0 R", "3 0 R"), testStream, testSpec),
		"odd utf16 name":     build(catalog("<FEFF00> 3 0 R", "3 0 R"), testStream, testSpec),
		"inline filespec":    build(catalog("(a.txt) << /Type /Filespec /UF (a.txt) /EF << /F 2 0 R >> >>", "3 0 R"), testStream, testSpec),
		"duplicate name":     build(catalog("(a.txt) 3 0 R (a.txt) 4 0 R", "3 0 R 4 0 R"), testStream, testSpec, other),
		"listed twice":       build(catalog("(a.txt) 3 0 R (b.txt) 3 0 R", "3 0 R 3 0 R"), testStream, testSpec),
		"extra filespec":     build(testCat, testStream, testSpec, other),
		"extra no type":      build(testCat, testStream, testSpec, "<< /EF << /F 2 0 R >> >>"),
		"inline in array":    build(testCat, testStream, testSpec, "[ << /Type /Filespec >> ]"),
		"inline in dict":     build(testCat, testStream, testSpec, "<< /A << /B [ << /EF 1 >> ] >> >>"),
		"inline in catalog":  build("<< /Type /Catalog /X << /Type /Filespec >> /Names << /EmbeddedFiles << /Names [(a.txt) 3 0 R] >> >> /AF [3 0 R] >>", testStream, testSpec),
		"value not filespec": build(testCat, testStream, "<< /Type /Pages >>"),
		"value missing":      build(testCat, testStream),
		"value not dict":     build(testCat, testStream, "5"),
		"UF differs":         build(testCat, testStream, "<< /Type /Filespec /UF (b.txt) /EF << /F 2 0 R >> >>"),
		"no UF":              build(testCat, testStream, "<< /Type /Filespec /F (a.txt) /EF << /F 2 0 R >> >>"),
		"UF odd utf16":       build(testCat, testStream, "<< /Type /Filespec /UF <FEFF00> /EF << /F 2 0 R >> >>"),
		"no EF":              build(testCat, testStream, "<< /Type /Filespec /UF (a.txt) >>"),
		"EF not dict":        build(testCat, testStream, "<< /Type /Filespec /UF (a.txt) /EF 5 >>"),
		"EF indirect":        build(testCat, testStream, "<< /Type /Filespec /UF (a.txt) /EF 4 0 R >>", "<< /F 2 0 R >>"),
		"EF no F":            build(testCat, testStream, "<< /Type /Filespec /UF (a.txt) /EF << >> >>"),
		"EF F direct":        build(testCat, testStream, "<< /Type /Filespec /UF (a.txt) /EF << /F 5 >> >>"),
		"EF UF differs":      build(testCat, testStream, "<< /Type /Filespec /UF (a.txt) /EF << /F 2 0 R /UF 3 0 R >> >>"),
		"EF missing obj":     build(testCat, testStream, "<< /Type /Filespec /UF (a.txt) /EF << /F 9 0 R >> >>"),
		"EF not stream":      build(testCat, testStream, "<< /Type /Filespec /UF (a.txt) /EF << /F 1 0 R >> >>"),
		"stream no type":     build(testCat, "<< /Length 3 >>\nstream\nabc\nendstream", testSpec),
		"stream filter":      build(testCat, "<< /Type /EmbeddedFile /Length 3 /Filter /FlateDecode >>\nstream\nabc\nendstream", testSpec),
		"stream length late": build(testCat, "<< /Type /EmbeddedFile /Length 4 0 R >>\nstream\nabc\nendstream", testSpec, "3"),
	}
	for name, in := range cases {
		if err := readErr(in); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestReaderObjectCountBound(t *testing.T) {
	var b strings.Builder
	b.WriteString("%PDF-1.7\n")
	for i := 1; i <= maxObjects+1; i++ {
		fmt.Fprintf(&b, "%d 0 obj 1 endobj\n", i)
	}
	if _, err := ReadAttachments(strings.NewReader(b.String()), int64(b.Len())); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v", err)
	}
}

func TestReaderMemoryProportional(t *testing.T) {
	// A hostile array of one million elements must be handled without error
	// other than the declared ones and without panic.
	in := "%PDF-1.7\n1 0 obj [" + strings.Repeat("1 ", 1000000) + "] endobj\n"
	if _, err := ReadAttachments(strings.NewReader(in), int64(len(in))); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v", err)
	}
}

func TestExternalTools(t *testing.T) {
	out := render(t, sampleDoc())
	dir := t.TempDir()
	file := filepath.Join(dir, "p.pdf")
	if err := os.WriteFile(file, out, 0o600); err != nil {
		t.Fatal(err)
	}
	ran := false
	for _, c := range [][]string{{"qpdf", "--check", file}, {"pdfinfo", file}, {"pdfdetach", "-list", file}} {
		path, err := exec.LookPath(c[0])
		if err != nil {
			continue
		}
		ran = true
		if o, err := exec.Command(path, c[1:]...).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", c[0], err, o)
		}
	}
	if !ran {
		t.Skip("no PDF tool installed (qpdf, pdfinfo, pdfdetach)")
	}
}

// TestWriteSample writes a sample file for manual inspection when
// TRANSTEIRA_PDF_SAMPLE names the destination.
func TestWriteSample(t *testing.T) {
	dst := os.Getenv("TRANSTEIRA_PDF_SAMPLE")
	if dst == "" {
		t.Skip("TRANSTEIRA_PDF_SAMPLE not set")
	}
	d := sampleDoc()
	for i := 0; i < 40; i++ {
		d.Blocks = append(d.Blocks, Block{Kind: Field, Label: fmt.Sprintf("File %d:", i+4), Text: "a long file name with spaces and (parentheses) that has to wrap over several lines of the page.pdf"},
			Block{Kind: Mono, Text: "SHA-256 " + strings.Repeat("0123456789abcdef", 4)})
	}
	if err := os.WriteFile(dst, render(t, d), 0o600); err != nil {
		t.Fatal(err)
	}
}

func FuzzWrite(f *testing.F) {
	f.Add("title", "label", "text (x) \\ \n é 😀", "name.json", "application/json", []byte("data"))
	f.Add("", "", "", "a", "", []byte{})
	f.Add("\u202e", "endstream", "%%EOF", "n)", "a/b)", []byte("endstream\nendobj"))
	f.Fuzz(func(t *testing.T, title, label, text, name, mime string, data []byte) {
		d := Document{
			Title: title, Author: label, Subject: text, Lang: mime, Footer: text, TruncatedNotice: label, MaxPages: 2,
			Blocks: []Block{
				{Kind: Heading, Text: title},
				{Kind: Field, Label: label, Text: text},
				{Kind: Mono, Text: text},
				{Kind: Paragraph, Text: text},
			},
			Attachments: []Attachment{{Name: name, MIMEType: mime, Description: text, Data: data}, {Name: "fixed", Data: []byte("f")}},
		}
		var b bytes.Buffer
		err := Write(&b, d)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatal(err)
			}
			return
		}
		got, err := ReadAttachments(bytes.NewReader(b.Bytes()), int64(b.Len()))
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if !bytes.Equal(got[name], data) || string(got["fixed"]) != "f" || len(got) != 2 {
			t.Fatalf("round trip mismatch for name %q", name)
		}
		for _, k := range []string{"/JavaScript", "/JS", "/OpenAction", "/URI", "/Launch"} {
			if bytes.Contains(b.Bytes(), []byte(k)) && !bytes.Contains(data, []byte(k)) {
				t.Fatalf("forbidden key %s", k)
			}
		}
	})
}

func FuzzReadAttachments(f *testing.F) {
	f.Add(render(f, sampleDoc()))
	f.Add(render(f, Document{}))
	f.Add([]byte("%PDF-1.7\n1 0 obj << /Length 2 0 R >> stream\nab\nendstream endobj\n"))
	f.Add(build(testCat, testStream, testSpec))
	f.Add(build(testCat, testStream, testSpec, "<< /Type /Filespec >>"))
	f.Add(append(render(f, sampleDoc()), "x"...))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := ReadAttachments(bytes.NewReader(in), int64(len(in))+1)
		if err == nil {
			total := 0
			for _, v := range got {
				total += len(v)
			}
			if total > len(in) {
				t.Fatal("output larger than input")
			}
		}
	})
}

func TestParserLiteralsAndNames(t *testing.T) {
	p := &parser{b: []byte("(a\\r\\t\\b\\f\\q\\\r\nb\\\nc\\7\\1x\\0053 (n))")}
	v, err := p.literal()
	if err != nil || string(v.([]byte)) != "a\r\t\b\fq"+"bc\x07\x01x\x053 (n)" {
		t.Fatalf("%q %v", v, err)
	}
	if _, err := (&parser{b: []byte("(a\\")}).literal(); err == nil {
		t.Fatal("dangling backslash")
	}
	if v, err := (&parser{b: []byte("<4a 6b 7>")}).hexString(); err != nil || string(v.([]byte)) != "Jkp" {
		t.Fatalf("%q %v", v, err)
	}
	if v, err := (&parser{b: []byte("/A#2fB")}).name(); err != nil || v != pname("A/B") {
		t.Fatalf("%v %v", v, err)
	}
	if _, err := (&parser{b: []byte("/" + strings.Repeat("a", maxName+1))}).name(); err == nil {
		t.Fatal("long name")
	}
}

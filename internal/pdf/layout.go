package pdf

import (
	"bytes"
	"strconv"
	"strings"
)

// Page geometry and typography, in PDF points.
const (
	pageW      = 595
	pageH      = 842
	margin     = 56
	bodySize   = 10.0
	monoSize   = 9.0
	headSize   = 16.0
	footerSize = 8.0
	leadFactor = 1.35
	spacerH    = 8.0
	headGap    = 10.0
	maxNotice  = 8 // longest truncation notice, in lines
	maxFooter  = 120
)

// layouter places lines on pages and produces one content stream per page.
type layouter struct {
	pages    []*strings.Builder
	y        float64 // top of the next line
	maxPages int
	reserve  float64 // room kept on the last page for the truncation notice
}

func (l *layouter) newPage() {
	l.pages = append(l.pages, &strings.Builder{})
	l.y = pageH - margin
}

func (l *layouter) limit() float64 {
	if len(l.pages) == l.maxPages {
		return margin + l.reserve
	}
	return margin
}

// emit writes one line of runs at the current position.
func (l *layouter) emit(runs []run, size, lead float64) {
	if len(runs) == 0 {
		return
	}
	sb := l.pages[len(l.pages)-1]
	sb.WriteString("BT\n")
	sb.WriteString(num(margin) + " " + num(l.y+lead*0.25) + " Td\n")
	for _, r := range runs {
		sb.WriteString("/" + r.f.resourceName() + " " + num(size) + " Tf\n")
		sb.WriteString(escapeLiteral(r.b) + " Tj\n")
	}
	sb.WriteString("ET\n")
}

// place puts one line on the current page, starting a new one when needed.
// It reports false when the page bound prevents it.
func (l *layouter) place(runs []run, size, space float64) bool {
	lead := size * leadFactor
	if len(l.pages) > 0 && l.y >= pageH-margin {
		space = 0
	}
	need := lead + space
	if len(l.pages) == 0 || l.y-need < l.limit() {
		if len(l.pages) >= l.maxPages {
			return false
		}
		l.newPage()
		need = lead
	}
	l.y -= need
	l.emit(runs, size, lead)
	return true
}

// num formats a coordinate or size.
func num(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }

// segments splits text on line feeds; each segment is wrapped on its own.
func segments(b []byte) [][]byte {
	var out [][]byte
	for {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			return append(out, b)
		}
		out = append(out, b[:i])
		b = b[i+1:]
	}
}

// blockLines wraps the text of a block into lines.
func blockLines(f font, size float64, label, text []byte) [][]run {
	maxW := int(float64(pageW-2*margin) * 1000 / size)
	var lines [][]run
	for i, seg := range segments(text) {
		var words []word
		if i == 0 && len(label) > 0 {
			words = wordsOf(fontBold, label)
		}
		words = append(words, wordsOf(f, seg)...)
		w := wrap(words, maxW)
		if len(w) == 0 {
			w = [][]run{nil}
		}
		lines = append(lines, w...)
	}
	return lines
}

// layout lays the blocks out on pages and reports whether content was
// dropped to respect the page bound. It always returns at least one page.
func layout(d Document, maxPages int) (pages []string, truncated bool) {
	l := &layouter{maxPages: maxPages}
	notice := blockLines(fontHelvetica, bodySize, nil, toWinAnsi(d.TruncatedNotice))
	if strings.TrimSpace(d.TruncatedNotice) == "" {
		notice = nil
	}
	if len(notice) > maxNotice {
		notice = notice[:maxNotice]
	}
	if len(notice) > 0 {
		l.reserve = float64(len(notice))*bodySize*leadFactor + spacerH
	}
	l.newPage()
blocks:
	for _, b := range d.Blocks {
		var (
			f     = fontHelvetica
			size  = bodySize
			space = 0.0
			lines [][]run
		)
		label, text := toWinAnsi(b.Label), toWinAnsi(b.Text)
		switch b.Kind {
		case Spacer:
			l.y -= spacerH
			continue
		case Heading:
			f, size, space = fontBold, headSize, headGap
			lines = blockLines(f, size, nil, append(append(label, ' '), text...))
		case Mono:
			f, size = fontMono, monoSize
			lines = blockLines(f, size, label, text)
		case Field:
			lines = blockLines(f, size, label, text)
		default:
			lines = blockLines(f, size, nil, append(append(label, ' '), text...))
		}
		for _, ln := range lines {
			if !l.place(ln, size, space) {
				truncated = true
				break blocks
			}
			space = 0
		}
	}
	if truncated && len(notice) > 0 {
		l.y -= spacerH
		lead := bodySize * leadFactor
		for _, ln := range notice {
			l.y -= lead
			l.emit(ln, bodySize, lead)
		}
	}
	footer := toWinAnsi(d.Footer)
	if len(footer) > maxFooter {
		footer = footer[:maxFooter]
	}
	for i, sb := range l.pages {
		text := "page " + strconv.Itoa(i+1) + "/" + strconv.Itoa(len(l.pages))
		if len(footer) > 0 {
			text = string(footer) + " - " + text
		}
		sb.WriteString("BT\n" + num(margin) + " 30.00 Td\n/F1 " + num(footerSize) + " Tf\n" +
			escapeLiteral([]byte(text)) + " Tj\nET\n")
		pages = append(pages, sb.String())
	}
	return pages, truncated
}

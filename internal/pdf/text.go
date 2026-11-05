package pdf

import (
	"strings"

	"github.com/ed-fr/transteira/internal/textsafe"
)

// font identifies one of the three standard fonts used by the writer.
type font int

const (
	fontHelvetica font = iota
	fontBold
	fontMono
)

// resourceName is the name of the font in the page resources.
func (f font) resourceName() string { return [...]string{"F1", "F2", "F3"}[f] }

// winAnsiHigh maps the Unicode characters of the cp1252 range 0x80-0x9F to
// their WinAnsi code.
var winAnsiHigh = map[rune]byte{
	0x20AC: 0x80, 0x201A: 0x82, 0x0192: 0x83, 0x201E: 0x84, 0x2026: 0x85, 0x2020: 0x86,
	0x2021: 0x87, 0x02C6: 0x88, 0x2030: 0x89, 0x0160: 0x8A, 0x2039: 0x8B, 0x0152: 0x8C,
	0x017D: 0x8E, 0x2018: 0x91, 0x2019: 0x92, 0x201C: 0x93, 0x201D: 0x94, 0x2022: 0x95,
	0x2013: 0x96, 0x2014: 0x97, 0x02DC: 0x98, 0x2122: 0x99, 0x0161: 0x9A, 0x203A: 0x9B,
	0x0153: 0x9C, 0x017E: 0x9E, 0x0178: 0x9F,
}

// toWinAnsi converts s to WinAnsi bytes. Control, bidirectional, format and
// invisible characters are removed, tabs and no-break spaces become spaces,
// line feeds are kept, and any other character outside WinAnsi becomes '?'.
func toWinAnsi(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			out = append(out, '\n')
		case r == '\t' || r == 0xA0:
			out = append(out, ' ')
		case textsafe.IsHidden(r):
			// dropped
		case r >= 0x20 && r <= 0x7E, r >= 0xA1 && r <= 0xFF:
			out = append(out, byte(r)) //nolint:gosec // r is between 0x20 and 0xFF here
		default:
			if b, ok := winAnsiHigh[r]; ok {
				out = append(out, b)
			} else {
				out = append(out, '?')
			}
		}
	}
	return out
}

// escapeLiteral returns b as a PDF literal string, with parentheses and
// backslash escaped and every non-printable-ASCII byte written as an octal
// escape, so the result is plain ASCII with balanced delimiters.
func escapeLiteral(b []byte) string {
	var sb strings.Builder
	sb.WriteByte('(')
	for _, c := range b {
		switch {
		case c == '(' || c == ')' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 0x20 || c > 0x7E:
			sb.WriteByte('\\')
			sb.WriteByte('0' + c>>6)
			sb.WriteByte('0' + (c>>3)&7)
			sb.WriteByte('0' + c&7)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte(')')
	return sb.String()
}

// Helvetica and Helvetica-Bold widths (AFM, 1/1000 em) for 0x20-0x7E.
var helveticaASCII = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
	1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
	333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
	556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
}

var boldASCII = [95]int{
	278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
	975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
	333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
	611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
}

// accentBase gives, for 0xC0-0xFF, the base letter whose width an accented
// letter shares; '.' marks the characters listed in the special tables.
const accentBase = "AAAAAA.CEEEEIIII.NOOOOO..UUUUY..aaaaaa.ceeeeiiii.nooooo..uuuuy.y"

var helveticaSpecial = map[byte]int{
	0x80: 556, 0x82: 222, 0x83: 556, 0x84: 333, 0x85: 1000, 0x86: 556, 0x87: 556, 0x88: 333,
	0x89: 1000, 0x8A: 667, 0x8B: 333, 0x8C: 1000, 0x8E: 611, 0x91: 222, 0x92: 222, 0x93: 333,
	0x94: 333, 0x95: 350, 0x96: 556, 0x97: 1000, 0x98: 333, 0x99: 1000, 0x9A: 500, 0x9B: 333,
	0x9C: 944, 0x9E: 500, 0x9F: 667,
	0xA0: 278, 0xA1: 333, 0xA2: 556, 0xA3: 556, 0xA4: 556, 0xA5: 556, 0xA6: 260, 0xA7: 556,
	0xA8: 333, 0xA9: 737, 0xAA: 370, 0xAB: 556, 0xAC: 584, 0xAD: 333, 0xAE: 737, 0xAF: 333,
	0xB0: 400, 0xB1: 584, 0xB2: 333, 0xB3: 333, 0xB4: 333, 0xB5: 556, 0xB6: 537, 0xB7: 278,
	0xB8: 333, 0xB9: 333, 0xBA: 365, 0xBB: 556, 0xBC: 834, 0xBD: 834, 0xBE: 834, 0xBF: 611,
	0xC6: 1000, 0xD0: 722, 0xD7: 584, 0xD8: 778, 0xDE: 667, 0xDF: 611, 0xE6: 889, 0xF0: 556,
	0xF7: 584, 0xF8: 611, 0xFE: 556,
}

var boldSpecial = map[byte]int{
	0x80: 556, 0x82: 278, 0x83: 556, 0x84: 500, 0x85: 1000, 0x86: 556, 0x87: 556, 0x88: 333,
	0x89: 1000, 0x8A: 667, 0x8B: 333, 0x8C: 1000, 0x8E: 611, 0x91: 278, 0x92: 278, 0x93: 500,
	0x94: 500, 0x95: 350, 0x96: 556, 0x97: 1000, 0x98: 333, 0x99: 1000, 0x9A: 556, 0x9B: 333,
	0x9C: 944, 0x9E: 500, 0x9F: 667,
	0xA0: 278, 0xA1: 333, 0xA2: 556, 0xA3: 556, 0xA4: 556, 0xA5: 556, 0xA6: 280, 0xA7: 556,
	0xA8: 333, 0xA9: 737, 0xAA: 370, 0xAB: 556, 0xAC: 584, 0xAD: 333, 0xAE: 737, 0xAF: 333,
	0xB0: 400, 0xB1: 584, 0xB2: 333, 0xB3: 333, 0xB4: 333, 0xB5: 611, 0xB6: 556, 0xB7: 278,
	0xB8: 333, 0xB9: 333, 0xBA: 365, 0xBB: 556, 0xBC: 834, 0xBD: 834, 0xBE: 834, 0xBF: 611,
	0xC6: 1000, 0xD0: 722, 0xD7: 584, 0xD8: 778, 0xDE: 667, 0xDF: 611, 0xE6: 889, 0xF0: 611,
	0xF7: 584, 0xF8: 611, 0xFE: 611,
}

// widths holds, per font, the advance width (1/1000 em) of every WinAnsi
// code. Codes undefined in WinAnsi get the width of a space.
var widths = buildWidths()

func buildWidths() [3][256]int {
	var w [3][256]int
	for f, spec := range []struct {
		ascii   *[95]int
		special map[byte]int
	}{{&helveticaASCII, helveticaSpecial}, {&boldASCII, boldSpecial}} {
		for c := 0; c < 256; c++ {
			w[f][c] = helveticaASCII[0]
		}
		for i, v := range spec.ascii {
			w[f][0x20+i] = v
		}
		for c, v := range spec.special {
			w[f][c] = v
		}
		for i := 0; i < len(accentBase); i++ {
			if base := accentBase[i]; base != '.' {
				w[f][0xC0+i] = spec.ascii[base-0x20]
			}
		}
	}
	for c := 0; c < 256; c++ {
		w[fontMono][c] = 600
	}
	return w
}

// measure returns the width of b in 1/1000 em.
func measure(f font, b []byte) int {
	n := 0
	for _, c := range b {
		n += widths[f][c]
	}
	return n
}

// run is a piece of a line in one font.
type run struct {
	f font
	b []byte
}

// word is an unbreakable token in one font.
type word struct {
	f font
	b []byte
}

// wordsOf splits b on spaces into words of font f.
func wordsOf(f font, b []byte) []word {
	var out []word
	for _, p := range strings.Fields(string(b)) {
		out = append(out, word{f, []byte(p)})
	}
	return out
}

// wrap breaks words into lines no wider than maxW (1/1000 em). A word wider
// than a line is broken by characters. It never returns an empty result for
// non-empty input.
func wrap(words []word, maxW int) [][]run {
	var lines [][]run
	var cur []run
	curW := 0
	flush := func() {
		if len(cur) > 0 {
			lines = append(lines, cur)
		}
		cur, curW = nil, 0
	}
	add := func(wd word, w int) {
		if len(cur) == 0 {
			cur = []run{{wd.f, append([]byte(nil), wd.b...)}}
			curW = w
			return
		}
		last := &cur[len(cur)-1]
		curW += widths[last.f][' '] + w
		last.b = append(last.b, ' ')
		if last.f == wd.f {
			last.b = append(last.b, wd.b...)
		} else {
			cur = append(cur, run{wd.f, append([]byte(nil), wd.b...)})
		}
	}
	for _, wd := range words {
		w := measure(wd.f, wd.b)
		switch {
		case w > maxW:
			flush()
			rest := wd.b
			for len(rest) > 0 {
				n, acc := 0, 0
				for n < len(rest) && (n == 0 || acc+widths[wd.f][rest[n]] <= maxW) {
					acc += widths[wd.f][rest[n]]
					n++
				}
				chunk := append([]byte(nil), rest[:n]...)
				rest = rest[n:]
				if len(rest) == 0 {
					cur, curW = []run{{wd.f, chunk}}, acc
				} else {
					lines = append(lines, []run{{wd.f, chunk}})
				}
			}
		case len(cur) == 0:
			add(wd, w)
		case curW+widths[cur[len(cur)-1].f][' ']+w <= maxW:
			add(wd, w)
		default:
			flush()
			add(wd, w)
		}
	}
	flush()
	return lines
}

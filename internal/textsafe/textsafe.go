// Package textsafe classifies the Unicode characters that can hide or
// disguise text, and removes them from free text written by users (threats
// T-18, T-50, T-52 and T-81). It is the single definition shared by the
// sanitization of messages (invitations, transfers) and the file name
// policy of package filename (decision P8). It has no dependency outside the
// standard library.
//
// A character is hidden when it is one of:
//
//   - a control character (category Cc: C0, DEL and C1);
//   - a Unicode line or paragraph separator (U+2028, U+2029);
//   - a format character (category Cf), which includes every bidirectional
//     control (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to
//     U+2069), the zero-width characters, the soft hyphen, the byte order
//     mark and the tag characters;
//   - an invisible character outside Cf (see [IsInvisible]): the Hangul
//     fillers, the combining grapheme joiner, the variation selectors, the
//     Mongolian free variation selectors and the braille blank.
package textsafe

import (
	"strings"
	"unicode"
)

// IsControl reports whether r is a control character (category Cc).
func IsControl(r rune) bool { return unicode.Is(unicode.Cc, r) }

// IsLineSeparator reports whether r is the Unicode line or paragraph
// separator (U+2028, U+2029), which mail clients and browsers may render as
// line breaks.
func IsLineSeparator(r rune) bool { return r == '\u2028' || r == '\u2029' }

// IsBidiControl reports whether r is a bidirectional formatting character:
// U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069. They all
// belong to category Cf.
func IsBidiControl(r rune) bool {
	return r == '\u061c' || r == '\u200e' || r == '\u200f' ||
		(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}

// IsFormat reports whether r is a format character (category Cf).
func IsFormat(r rune) bool { return unicode.Is(unicode.Cf, r) }

// IsInvisible reports whether r is an invisible character outside category
// Cf: the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), the combining
// grapheme joiner (U+034F), the variation selectors (U+FE00 to U+FE0F and
// U+E0100 to U+E01EF), the Mongolian free variation selectors (U+180B to
// U+180D) and the braille pattern blank (U+2800). They render as nothing or
// as blank space, so that they can make two different strings look alike.
func IsInvisible(r rune) bool {
	switch {
	case r == '\u115f', r == '\u1160', r == '\u3164', r == '\uffa0', r == '\u034f', r == '\u2800',
		r >= '\ufe00' && r <= '\ufe0f', r >= '\U000E0100' && r <= '\U000E01EF', r >= '\u180b' && r <= '\u180d':
		return true
	}
	return false
}

// IsHidden reports whether r is a character SanitizeMessage removes: a
// control character other than line feed and tab, a line or paragraph
// separator, a format character or an invisible character.
func IsHidden(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	return IsControl(r) || IsLineSeparator(r) || IsFormat(r) || IsInvisible(r)
}

// SanitizeMessage removes from a free-text message (plain text shown in
// mails and pages) every hidden character ([IsHidden]): the control
// characters except line feed and tab (CR included, so that line breaks are
// always LF), the line and paragraph separators, the format characters
// (bidirectional controls, zero-width characters...) and the invisible
// characters. s must be valid UTF-8; callers check it first, since an
// invalid byte would be replaced by U+FFFD.
func SanitizeMessage(s string) string {
	return strings.Map(func(r rune) rune {
		if IsHidden(r) {
			return -1
		}
		return r
	}, s)
}

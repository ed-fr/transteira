// Package filename validates the names of deposited files (threat model
// decision P8) and derives the entry names of the download archive.
//
// The original name of a file is only stored in the database and displayed
// escaped; it never reaches the file system of the server, where files have
// random names. The rules below protect the recipients instead: a name must
// be safe to display (no control, bidirectional or invisible characters that
// could disguise an extension or inject a header, threats T-50 and T-52) and
// safe to save on Windows, macOS and Linux (no path separator nor drive
// letter, no Windows reserved device name, no leading space, no trailing
// space or dot, at most 255 bytes). A leading dot is allowed (".env").
//
// Validate rejects a non-conforming name with a *ValidationError rather than
// silently altering it, so that an API client knows exactly what was
// refused. The only transformation is the Unicode NFC normalization.
package filename

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/ed-fr/transteira/internal/textsafe"
)

// MaxBytes is the maximum length of a name, in bytes, after NFC
// normalization.
const MaxBytes = 255

// MaxSpaceRun is the longest run of consecutive white space characters
// (unicode.IsSpace) a name may hold. Two spaces in a row are common enough
// in real names to be kept; three or more are refused, since a long run of
// blanks is the classic way to hide the real extension of a file.
const MaxSpaceRun = 2

// Reason is the machine-readable reason why a name is rejected.
type Reason string

// Reasons returned in a ValidationError.
const (
	// ReasonEmpty: the name is empty.
	ReasonEmpty Reason = "empty"
	// ReasonInvalidUTF8: the name is not valid UTF-8.
	ReasonInvalidUTF8 Reason = "invalid-utf8"
	// ReasonTooLong: the name exceeds MaxBytes after NFC normalization.
	ReasonTooLong Reason = "too-long"
	// ReasonControlCharacter: the name contains a C0 or C1 control character,
	// DEL, or a Unicode line or paragraph separator.
	ReasonControlCharacter Reason = "control-character"
	// ReasonBidiControl: the name contains a bidirectional control character.
	ReasonBidiControl Reason = "bidi-control"
	// ReasonInvisibleCharacter: the name contains a zero-width, invisible or
	// other format character (Unicode category Cf, or an invisible character
	// of textsafe.IsInvisible such as a Hangul filler).
	ReasonInvisibleCharacter Reason = "invisible-character"
	// ReasonPathSeparator: the name contains "/", "\" or ":", or a
	// look-alike of one of them (see Validate).
	ReasonPathSeparator Reason = "path-separator"
	// ReasonSpaceRun: the name contains more than MaxSpaceRun consecutive
	// white space characters, which can push a real extension out of sight.
	ReasonSpaceRun Reason = "space-run"
	// ReasonDotName: the name is made of dots only (".", "..", "...").
	ReasonDotName Reason = "dot-name"
	// ReasonLeadingTrailing: the name starts with a space, or ends with a
	// space or a dot. A leading dot is allowed.
	ReasonLeadingTrailing Reason = "leading-or-trailing-space-or-dot"
	// ReasonReservedName: the name is a Windows reserved device name, with or
	// without an extension.
	ReasonReservedName Reason = "reserved-name"
)

// ValidationError reports why a name was rejected. Its message never contains
// the name itself, which may hold characters unsafe for logs.
type ValidationError struct {
	// Reason is the machine-readable cause.
	Reason Reason
}

// Error implements error.
func (e *ValidationError) Error() string {
	return "filename: invalid name: " + string(e.Reason)
}

// reject returns a ValidationError for reason.
func reject(reason Reason) (string, error) {
	return "", &ValidationError{Reason: reason}
}

// Validate checks a file name and returns it normalized to NFC, or a
// *ValidationError. The checks are, in order:
//
//  1. the name is not empty and is valid UTF-8; it is then normalized to NFC;
//  2. it is at most MaxBytes bytes long;
//  3. it contains no control character (C0, DEL, C1), no Unicode line or
//     paragraph separator, no bidirectional control (U+061C, U+200E, U+200F,
//     U+202A to U+202E, U+2066 to U+2069), no format character (U+00AD,
//     U+200B to U+200D, U+2060, U+FEFF and the rest of Unicode category Cf)
//     and no other invisible character (Hangul fillers, combining grapheme
//     joiner, variation selectors, braille blank: textsafe.IsInvisible);
//  4. it contains no "/", "\" or ":", nor their look-alikes U+2215
//     (division slash), U+2044 (fraction slash), U+FF0F (fullwidth
//     solidus), U+29F8 (big solidus), U+FF3C (fullwidth reverse solidus),
//     U+FF1A (fullwidth colon), U+A789 (modifier letter colon), U+FE55
//     (small colon), U+2236 (ratio), U+FE68 (small reverse solidus) and
//     U+2216 (set minus), which could fake a path in a listing (the list
//     covers the common look-alikes; it is not exhaustive); it holds no run of more than
//     MaxSpaceRun consecutive white space characters; and it is not made of
//     dots only (".", "..", "...");
//  5. it neither starts with a space (any Unicode white space) nor ends with
//     a space or a dot: Windows silently strips trailing ones. Such names are
//     rejected rather than trimmed, so that the stored name is exactly the
//     one the client sent. A leading dot is allowed: ".env", ".gitignore" or
//     ".htaccess" are legitimate files to transfer;
//  6. it is not a Windows reserved device name (CON, PRN, AUX, NUL, CONIN$,
//     CONOUT$, COM0 to COM9, LPT0 to LPT9, and COM or LPT followed by a
//     superscript digit ¹, ² or ³), compared case-insensitively on the part
//     before the first dot, trailing spaces ignored ("nul.txt", "Com1.tar.gz"
//     and "AUX .log" are reserved).
func Validate(name string) (string, error) {
	if name == "" {
		return reject(ReasonEmpty)
	}
	if !utf8.ValidString(name) {
		return reject(ReasonInvalidUTF8)
	}
	name = norm.NFC.String(name)
	if len(name) > MaxBytes {
		return reject(ReasonTooLong)
	}
	spaces := 0
	for _, r := range name {
		if reason, bad := forbiddenRune(r); bad {
			return reject(reason)
		}
		if spaces = spaceRun(spaces, r); spaces > MaxSpaceRun {
			return reject(ReasonSpaceRun)
		}
	}
	if strings.Trim(name, ".") == "" {
		return reject(ReasonDotName)
	}
	first, _ := utf8.DecodeRuneInString(name)
	last, _ := utf8.DecodeLastRuneInString(name)
	if unicode.IsSpace(first) || isTrailingForbidden(last) {
		return reject(ReasonLeadingTrailing)
	}
	if isReserved(name) {
		return reject(ReasonReservedName)
	}
	return name, nil
}

// forbiddenRune reports whether r may never appear in a name, and why.
func forbiddenRune(r rune) (Reason, bool) {
	switch {
	case isSeparator(r):
		return ReasonPathSeparator, true
	case textsafe.IsControl(r), textsafe.IsLineSeparator(r):
		// Cc covers C0, DEL and C1 (including U+0085 NEL).
		return ReasonControlCharacter, true
	case textsafe.IsBidiControl(r):
		return ReasonBidiControl, true
	case textsafe.IsFormat(r), textsafe.IsInvisible(r):
		// Cf covers U+00AD, U+200B to U+200D, U+2060, U+FEFF, the invisible
		// operators, the interlinear annotation and tag characters, and more.
		return ReasonInvisibleCharacter, true
	}
	return "", false
}

// isSeparator reports whether r is a path separator or one of the common
// look-alikes of one (not an exhaustive list).
func isSeparator(r rune) bool {
	switch r {
	case '/', '\\', ':', '\u2215', '\u2044', '\uff0f', '\u29f8', '\uff3c', '\uff1a', '\ua789',
		'\ufe55', '\u2236', '\ufe68', '\u2216':
		return true
	}
	return false
}

// spaceRun returns the length of the run of white space ending at r, given
// the length n of the run before it.
func spaceRun(n int, r rune) int {
	if unicode.IsSpace(r) {
		return n + 1
	}
	return 0
}

// isTrailingForbidden reports whether r may not end a name.
func isTrailingForbidden(r rune) bool {
	return r == '.' || unicode.IsSpace(r)
}

// reservedNames are the Windows reserved device names, upper case.
var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"CONIN$": true, "CONOUT$": true,
}

// isReserved reports whether name is a Windows reserved device name, with or
// without an extension.
func isReserved(name string) bool {
	stem, _, _ := strings.Cut(name, ".")
	stem = strings.TrimRight(stem, " ")
	upper := asciiUpper(stem)
	if reservedNames[upper] {
		return true
	}
	if len(upper) < 4 || (upper[:3] != "COM" && upper[:3] != "LPT") {
		return false
	}
	switch suffix := upper[3:]; suffix {
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
		return true
	}
	return false
}

// asciiUpper upper-cases the ASCII letters of s only, as Windows does for
// device names; other characters are kept as is.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// Limits of a folder path (since 1.1, folders dropped in the browser).
const (
	// MaxPathBytes is the maximum length of a path, in bytes, after NFC
	// normalization.
	MaxPathBytes = 1024
	// MaxPathSegments is the maximum number of folders in a path.
	MaxPathSegments = 16
)

// Reasons returned by ValidatePath, on top of the reasons of a segment.
const (
	// ReasonPathEmptySegment: the path starts or ends with "/", or holds
	// two "/" in a row.
	ReasonPathEmptySegment Reason = "empty-segment"
	// ReasonPathTooDeep: the path has more than MaxPathSegments segments.
	ReasonPathTooDeep Reason = "too-deep"
	// ReasonPathTooLong: the path exceeds MaxPathBytes after NFC
	// normalization.
	ReasonPathTooLong Reason = "path-too-long"
)

// ValidatePath checks the relative folder of a file (threat T-226) and
// returns it normalized to NFC, or a *ValidationError. The empty path is
// the root and is valid. Otherwise the path is made of 1 to MaxPathSegments
// segments separated by "/" (no leading, trailing or doubled "/"), at most
// MaxPathBytes bytes long, and each segment passes Validate: it holds no
// "\", ":" nor control, bidirectional or invisible character, is not "."
// or "..", and is not a Windows reserved name. Nothing is decoded: "%2e%2e"
// is a literal, harmless name. As with Validate, a non-conforming path is
// rejected, never corrected; the reason of a rejected segment is reported
// as is.
func ValidatePath(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	if !utf8.ValidString(p) {
		return reject(ReasonInvalidUTF8)
	}
	p = norm.NFC.String(p)
	if len(p) > MaxPathBytes {
		return reject(ReasonPathTooLong)
	}
	segments := strings.Split(p, "/")
	if len(segments) > MaxPathSegments {
		return reject(ReasonPathTooDeep)
	}
	for i, s := range segments {
		if s == "" {
			return reject(ReasonPathEmptySegment)
		}
		n, err := Validate(s)
		if err != nil {
			return "", err
		}
		segments[i] = n
	}
	return strings.Join(segments, "/"), nil
}

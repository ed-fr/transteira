package filename

import (
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Fallback is the archive entry name used for a name that does not pass
// Validate.
const Fallback = "file"

// archiveUnsafe are characters that Validate accepts but that Windows refuses
// in a file name; ArchiveName replaces each of them with an underscore so that
// the archive extracts everywhere.
const archiveUnsafe = `<>"|?*`

// ArchiveName returns the name of a file inside the download ZIP archive.
//
// The name is first validated (Validate); a name that does not pass is
// replaced by Fallback. The characters < > " | ? * are replaced with "_".
// Names are then made unique within the archive, case-insensitively: the
// second "a.txt" (or "A.TXT") becomes "a (2).txt", the third "a (3).txt",
// keeping the extension (the part from the last dot) and shortening the stem
// when needed so that the result stays within MaxBytes bytes.
//
// seen holds the state of one archive: pass the same non-nil map for every
// file of the archive, in order. The result always passes Validate.
func ArchiveName(name string, seen map[string]int) string {
	n, err := Validate(name)
	if err != nil {
		n = Fallback
	}
	n = strings.Map(func(r rune) rune {
		if strings.ContainsRune(archiveUnsafe, r) {
			return '_'
		}
		return r
	}, n)
	key := foldKey(n)
	count, taken := seen[key]
	if !taken {
		seen[key] = 1
		return n
	}
	stem, ext := splitExt(n)
	for i := count + 1; ; i++ {
		candidate := numbered(stem, ext, i)
		ck := foldKey(candidate)
		if _, dup := seen[ck]; dup {
			continue
		}
		seen[ck] = 1
		seen[key] = i
		return candidate
	}
}

// foldKey is the case-insensitive comparison key of a name.
func foldKey(s string) string {
	return strings.ToLower(strings.ToUpper(s))
}

// splitExt splits a validated name into stem and extension (from the last
// dot, ignored when it is the first character, as in ".env").
func splitExt(name string) (string, string) {
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		return name[:i], name[i:]
	}
	return name, ""
}

// numbered returns "stem (i)ext", shortening the stem so that the result
// fits in MaxBytes bytes. When the extension alone leaves no room for a stem,
// it is dropped and the whole name is shortened instead.
func numbered(stem, ext string, i int) string {
	suffix := " (" + strconv.Itoa(i) + ")"
	if len(suffix)+len(ext) >= MaxBytes {
		stem, ext = stem+ext, ""
	}
	// Trailing spaces of the stem are dropped, so that the space of the
	// suffix never makes a run longer than MaxSpaceRun ("a  .txt").
	stem = strings.TrimRightFunc(truncate(stem, MaxBytes-len(suffix)-len(ext)), unicode.IsSpace)
	if stem == "" {
		// Nothing usable is left after the cut: the stem starts with a long
		// run of combining marks (no normalization boundary) or with dots or
		// spaces only.
		return Fallback + suffix
	}
	return stem + suffix + ext
}

// truncate shortens s to at most limit bytes on a normalization boundary, so
// that no character nor combining sequence is split and the result stays NFC,
// then removes the trailing spaces and dots left by the cut. The result may
// be empty.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := 0
	var it norm.Iter
	for it.InitString(norm.NFC, s); !it.Done() && it.Pos() <= limit; {
		cut = it.Pos()
		it.Next()
	}
	return strings.TrimRightFunc(s[:cut], isTrailingForbidden)
}

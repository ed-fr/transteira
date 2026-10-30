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
// in a file name; ArchiveEntries replaces each of them with an underscore, in
// the names and in the folders, so that the archive extracts everywhere.
const archiveUnsafe = `<>"|?*`

// ArchiveFile is a file to place in the download ZIP archive.
type ArchiveFile struct {
	// Path is the relative folder of the file as stored ("" for the root,
	// otherwise segments separated by "/", see ValidatePath).
	Path string
	// Name is the original file name.
	Name string
}

// ArchiveEntries returns the entry name of each file inside the download
// ZIP archive, in the order of files (decision D25, threats T-51, T-52 and
// T-227).
//
// A name that does not pass Validate is replaced by Fallback; a path that
// does not pass ValidatePath is replaced by the root. The characters
// < > " | ? * are replaced with "_" in the name and in each folder.
// Folders are then merged case-insensitively (after NFC normalization): the
// first spelling met wins for the whole folder, so that "Plans/a.pdf" and
// "PLANS/b.pdf" land in the same "Plans" folder. Within a folder, names are
// made unique case-insensitively: the second "a.txt" (or "A.TXT") becomes
// "a (2).txt", the third "a (3).txt", keeping the extension (the part from
// the last dot) and shortening the stem when needed so that it stays within
// MaxBytes bytes. A file whose name equals a folder of the same level is
// suffixed the same way, whatever their order: the folder keeps its name.
//
// Every result is a relative path whose segments pass Validate, joined by
// "/"; no two results are equal case-insensitively, and no result equals a
// folder of the archive.
func ArchiveEntries(files []ArchiveFile) []string {
	// First pass: the sanitized folder and name of each file, the spelling
	// of each folder (by folded full path) and the set of folders.
	dirs := make([]string, len(files))
	names := make([]string, len(files))
	folders := map[string]string{}
	for i, f := range files {
		dirs[i] = archiveFolder(f.Path, folders)
		n, err := Validate(f.Name)
		if err != nil {
			n = Fallback
		}
		names[i] = archiveSafe(n)
	}
	// Second pass: unique entry names, never equal to a folder.
	seen := map[string]int{}
	out := make([]string, len(files))
	for i := range files {
		out[i] = uniqueEntry(dirs[i], names[i], folders, seen)
	}
	return out
}

// archiveFolder returns the archive folder of path, "" for the root, with
// the spelling recorded in folders for each of its levels (keyed by the
// folded full path of the level), recording the levels met for the first
// time.
func archiveFolder(path string, folders map[string]string) string {
	p, err := ValidatePath(path)
	if err != nil || p == "" {
		return ""
	}
	dir, key := "", ""
	for seg := range strings.SplitSeq(archiveSafe(p), "/") {
		if key != "" {
			key += "/"
		}
		key += foldKey(seg)
		spelling, known := folders[key]
		if !known {
			spelling = seg
			if dir != "" {
				spelling = dir + "/" + seg
			}
			folders[key] = spelling
		}
		dir = spelling
	}
	return dir
}

// uniqueEntry returns the entry name of the file name in the folder dir,
// numbered when its folded form is taken by an earlier file (seen) or by a
// folder, and records it in seen.
func uniqueEntry(dir, name string, folders map[string]string, seen map[string]int) string {
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	taken := func(n string) bool {
		k := foldKey(prefix + n)
		_, file := seen[k]
		_, folder := folders[k]
		return file || folder
	}
	key := foldKey(prefix + name)
	if !taken(name) {
		seen[key] = 1
		return prefix + name
	}
	stem, ext := splitExt(name)
	for i := max(seen[key], 1) + 1; ; i++ {
		candidate := numbered(stem, ext, i)
		if taken(candidate) {
			continue
		}
		seen[foldKey(prefix+candidate)] = 1
		seen[key] = i
		return prefix + candidate
	}
}

// archiveSafe replaces the characters of archiveUnsafe with "_".
func archiveSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(archiveUnsafe, r) {
			return '_'
		}
		return r
	}, s)
}

// foldKey is the case-insensitive comparison key of a name. Changing the
// case of an NFC string may leave it denormalized ("ǰ" upper-cases to
// "J̌"), so the key is normalized again: names that only match after
// both foldings would otherwise collide on extraction (macOS, threat T-227).
func foldKey(s string) string {
	return norm.NFC.String(strings.ToLower(strings.ToUpper(s)))
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

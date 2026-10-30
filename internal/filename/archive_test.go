package filename

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/zipstream"
)

// rootEntries returns the archive entries of files named names, at the root.
func rootEntries(names ...string) []string {
	files := make([]ArchiveFile, len(names))
	for i, n := range names {
		files[i] = ArchiveFile{Name: n}
	}
	return ArchiveEntries(files)
}

// second returns the archive entry of the second of two files named name.
func second(name string) string { return rootEntries(name, name)[1] }

func TestArchiveEntriesNames(t *testing.T) {
	steps := []struct{ in, want string }{
		{"a.txt", "a.txt"},
		{"a.txt", "a (2).txt"},
		{"A.TXT", "A (3).TXT"},
		{"a (4).txt", "a (4).txt"},
		{"a.txt", "a (5).txt"},
		{"b", "b"},
		{"B", "B (2)"},
		{"archive.tar.gz", "archive.tar.gz"},
		{"archive.tar.gz", "archive.tar (2).gz"},
		{"", Fallback},
		{"../x", Fallback + " (2)"},
		{"CON", Fallback + " (3)"},
		{"Why?.pdf", "Why_.pdf"},
		{`a<b>c"d|e*f`, "a_b_c_d_e_f"},
		{"é.txt", "é.txt"},
		{"É.TXT", "É (2).TXT"},
		{".env", ".env"},
		{".ENV", ".ENV (2)"},
		{"..env", "..env"},
		{"..env", ". (2).env"},
		{".a.b", ".a.b"},
		{".a.b", ".a (2).b"},
		{"q  .txt", "q  .txt"},
		{"q  .txt", "q (2).txt"},
		// Equal only once case-folded and normalized again.
		{"ǰ.txt", "ǰ.txt"},
		{"J̌.txt", "J̌ (2).txt"},
	}
	names := make([]string, len(steps))
	for i, s := range steps {
		names[i] = s.in
	}
	got := rootEntries(names...)
	for i, s := range steps {
		if got[i] != s.want {
			t.Errorf("entry %d of %q = %q, want %q", i, s.in, got[i], s.want)
		}
	}
	if len(ArchiveEntries(nil)) != 0 {
		t.Fatal("entries of no file")
	}
}

func TestArchiveEntriesLength(t *testing.T) {
	long := strings.Repeat("a", 251) + ".txt" // 255 bytes
	if got, want := second(long), strings.Repeat("a", 247)+" (2).txt"; got != want {
		t.Fatalf("got %q (%d bytes)", got, len(got))
	}

	// Multi-byte stem: never split a character.
	multi := strings.Repeat("é", 125) + ".txt" // 254 bytes
	if got := second(multi); len(got) > MaxBytes || !utf8.ValidString(got) || !strings.HasSuffix(got, " (2).txt") {
		t.Fatalf("got %q (%d bytes)", got, len(got))
	}

	// An extension leaving no room for a stem is dropped.
	hugeExt := "a." + strings.Repeat("x", 252) // 254 bytes
	if got, want := second(hugeExt), hugeExt[:251]+" (2)"; got != want {
		t.Fatalf("got %q (%d bytes)", got, len(got))
	}

	// Truncation removes the trailing spaces and dots of the stem.
	spaced := strings.Repeat("a", 245) + "  .  b.txt" // 255 bytes
	if got := second(spaced); got != strings.Repeat("a", 245)+" (2).txt" {
		t.Fatalf("got %q", got)
	}

	// A stem that cannot be cut on a normalization boundary falls back.
	marks := strings.Repeat("́", 12) + "." + strings.Repeat("x", 239) // 24 + 240 = 264 > 255
	marks = marks[:len(marks)-10]                                     // 254 bytes
	if _, err := Validate(marks); err != nil {
		t.Fatalf("Validate(marks): %v", err)
	}
	if got := second(marks); got != Fallback+" (2)" {
		t.Fatalf("got %q", got)
	}
}

func TestArchiveEntriesAlwaysValid(t *testing.T) {
	names := make([]string, 30)
	for i := range names {
		names[i] = strings.Repeat("z", 255)
	}
	for _, got := range rootEntries(names...) {
		if v, err := Validate(got); err != nil || v != got {
			t.Fatalf("ArchiveEntries produced invalid %q: %v", got, err)
		}
	}
}

func TestArchiveEntriesFolders(t *testing.T) {
	files := []ArchiveFile{
		{Path: "Plans/2026", Name: "a.pdf"},
		{Path: "PLANS/2026", Name: "b.pdf"},     // merged into "Plans/2026"
		{Path: "plans/2026", Name: "A.PDF"},     // same folded name as a.pdf
		{Path: "Plans/Site?", Name: "c.pdf"},    // "?" replaced in a folder
		{Path: "plans/site_", Name: "d.pdf"},    // merged with "Site_"
		{Path: "été", Name: "x"},                // NFC spelling first
		{Path: "ÉTÉ", Name: "y"},              // NFD, other case: merged
		{Path: "../etc", Name: "passwd"},        // invalid path: root
		{Path: "a//b", Name: "z"},               // invalid path: root
		{Path: "%2e%2e", Name: "lit"},           // a literal folder
		{Path: "Plans", Name: "2026"},           // file named as a folder: suffixed
		{Path: "", Name: "PLANS.txt"},           // no conflict with "Plans"
		{Path: "Plans/Sub", Name: "x"},          // folder "Sub" seen before the file
		{Path: "", Name: "Docs"},                // file before the folder "docs"
		{Path: "docs", Name: "readme"},          // the folder keeps its name
		{Path: "", Name: "plans"},               // file named as a root folder
		{Path: "", Name: "plans (2)"},           // the name given just above
		{Path: "Plans", Name: "sub"},            // file after the folder "Sub"
		{Path: "Docs (2)", Name: "f"},           // folder named as a suffixed file
		{Path: "Plans/2026", Name: "a (2).pdf"}, // the name taken by A.PDF
	}
	want := []string{
		"Plans/2026/a.pdf",
		"Plans/2026/b.pdf",
		"Plans/2026/A (2).PDF",
		"Plans/Site_/c.pdf",
		"Plans/Site_/d.pdf",
		"été/x",
		"été/y",
		"passwd",
		"z",
		"%2e%2e/lit",
		"Plans/2026 (2)",
		"PLANS.txt",
		"Plans/Sub/x",
		"Docs (3)",
		"docs/readme",
		"plans (2)",
		"plans (2) (2)",
		"Plans/sub (2)",
		"Docs (2)/f",
		"Plans/2026/a (2) (2).pdf",
	}
	got := ArchiveEntries(files)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d (%q, %q) = %q, want %q", i, files[i].Path, files[i].Name, got[i], want[i])
		}
	}
	checkEntries(t, got)
}

func FuzzArchiveEntries(f *testing.F) {
	for _, s := range [][4]string{
		{"", "a.txt", "", "A.TXT"},
		{"plans", "x", "PLANS", "x"},
		{"", "plans", "plans", "a"},
		{"a/b", "c", "A", "B"},
		{"../x", "y", "/x", "y"},
		{"%2e%2e", "a", "é", "É"},
		{"Site?", "a", "site_", "A"},
		{"", "", "con", "nul"},
		{"ǰ", "x", "J̌", "x"},
	} {
		f.Add(s[0], s[1], s[2], s[3])
	}
	f.Fuzz(func(t *testing.T, p1, n1, p2, n2 string) {
		files := []ArchiveFile{{p1, n1}, {p2, n2}, {p1, n2}, {p2, n1}, {p1 + "/" + n1, n2}, {"", p1}, {"", p2}}
		got := ArchiveEntries(files)
		if len(got) != len(files) {
			t.Fatalf("%d entries for %d files", len(got), len(files))
		}
		checkEntries(t, got)
	})
}

// checkEntries asserts the invariants of the entries of one archive: each
// is relative, every segment passes Validate, no two are equal in folded
// form, none equals a folder, and zipstream accepts them.
func checkEntries(t *testing.T, entries []string) {
	t.Helper()
	files := map[string]bool{}
	folders := map[string]bool{}
	for _, e := range entries {
		segments := strings.Split(e, "/")
		for _, s := range segments {
			if v, err := Validate(s); err != nil || v != s {
				t.Fatalf("entry %q: segment %q invalid: %v", e, s, err)
			}
			checkName(t, s)
		}
		k := foldKey(e)
		if files[k] {
			t.Fatalf("entry %q is a duplicate", e)
		}
		files[k] = true
		for i := 1; i < len(segments); i++ {
			folders[foldKey(strings.Join(segments[:i], "/"))] = true
		}
	}
	for k := range files {
		if folders[k] {
			t.Fatalf("entry %q equals a folder", k)
		}
	}
	zentries := make([]zipstream.Entry, len(entries))
	for i, e := range entries {
		zentries[i] = zipstream.Entry{Name: e}
	}
	if _, err := zipstream.Size(zentries); err != nil {
		t.Fatalf("zipstream refuses %q: %v", entries, err)
	}
}

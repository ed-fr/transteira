package web

import (
	"errors"
	"io/fs"
	"testing"
)

// TestDistRoot checks that Dist is rooted at web/dist: the committed .gitkeep is at its root,
// and the entry pages, when built, are at public/index.html and admin/index.html.
func TestDistRoot(t *testing.T) {
	t.Parallel()
	dist := Dist()
	if _, err := fs.Stat(dist, ".gitkeep"); err != nil {
		t.Fatalf(".gitkeep not at the root of Dist: %v", err)
	}
	for _, page := range []string{"public/index.html", "admin/index.html"} {
		_, err := fs.Stat(dist, page)
		switch {
		case err == nil:
		case errors.Is(err, fs.ErrNotExist):
			t.Logf("%s not built (run make web-build)", page)
		default:
			t.Errorf("stat %s: %v", page, err)
		}
	}
	if _, err := fs.Stat(dist, "dist"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Dist is not rooted at dist/: %v", err)
	}
}

// TestMustSubInvalidPath checks that an invalid subtree path panics.
func TestMustSubInvalidPath(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("mustSub(\"../x\") did not panic")
		}
	}()
	mustSub(dist, "../x")
}

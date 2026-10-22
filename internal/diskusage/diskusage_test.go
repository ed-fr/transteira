package diskusage

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMeasure(t *testing.T) {
	total, free, err := Measure(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 || free > total {
		t.Errorf("total = %d, free = %d", total, free)
	}
}

func TestMeasureErrors(t *testing.T) {
	for name, path := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "missing", "dir"),
		"nul":     "a\x00b",
	} {
		total, free, err := Measure(path)
		if err == nil || total != 0 || free != 0 || !strings.HasPrefix(err.Error(), "diskusage: measure ") {
			t.Errorf("%s: %d %d %v", name, total, free, err)
		}
	}
}
